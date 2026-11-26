package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	domainDNSManual             = "manual"
	domainDNSCloudflareAll      = "cloudflare_all"
	domainDNSCloudflareFailover = "cloudflare_failover"

	domainTLSAuto     = "auto"
	domainTLSManual   = "manual"
	domainTLSExternal = "external"

	domainProxiedInherit = "inherit"
	domainProxiedOn      = "on"
	domainProxiedOff     = "off"

	edgeDomainSelectCols = `id,domain,name,note,enabled,public_visible,node_ids_json,
		dns_mode,dns_ip_mode,dns_proxied,dns_active_node_id,dns_last_sync_at,dns_last_error,
		tls_mode,cert_pem,key_pem_enc,cert_issuer,cert_not_after,cert_status,cert_error,cert_updated_at,
		overrides_json,node_limits_json,waf_rule_ids_json,smart_dns_json,created_at,updated_at`
)

type edgeDomainNodeLimit struct {
	MaxDownloadMbitPerIP  *int64 `json:"max_download_mbps_per_ip,omitempty"`
	MaxConcurrentRequests *int   `json:"max_concurrent_requests,omitempty"`
	MaxConcurrentPerIP    *int   `json:"max_concurrent_per_ip,omitempty"`
}

func (l edgeDomainNodeLimit) isEmpty() bool {
	return l.MaxDownloadMbitPerIP == nil && l.MaxConcurrentRequests == nil && l.MaxConcurrentPerIP == nil
}

func (l edgeDomainNodeLimit) applyToOverrides(ov edgeNodeOverrides) edgeNodeOverrides {
	if l.MaxDownloadMbitPerIP != nil {
		v := *l.MaxDownloadMbitPerIP
		ov.MaxDownloadMbitPerIP = &v
	}
	if l.MaxConcurrentRequests != nil {
		v := *l.MaxConcurrentRequests
		ov.MaxConcurrentRequests = &v
	}
	if l.MaxConcurrentPerIP != nil {
		v := *l.MaxConcurrentPerIP
		ov.MaxConcurrentPerIP = &v
	}
	return ov
}

type edgeDomainRecord struct {
	ID              string                         `json:"id"`
	Domain          string                         `json:"domain"`
	Name            string                         `json:"name"`
	Note            string                         `json:"note"`
	Enabled         bool                           `json:"enabled"`
	PublicVisible   bool                           `json:"public_visible"`
	NodeIDs         []string                       `json:"node_ids"`
	DNSMode         string                         `json:"dns_mode"`
	DNSIPMode       string                         `json:"dns_ip_mode"`
	DNSProxied      string                         `json:"dns_proxied"`
	DNSActiveNodeID string                         `json:"dns_active_node_id"`
	DNSLastSyncAt   int64                          `json:"dns_last_sync_at"`
	DNSLastError    string                         `json:"dns_last_error"`
	TLSMode         string                         `json:"tls_mode"`
	CertPEM         string                         `json:"-"`
	KeyPEMEnc       string                         `json:"-"`
	CertIssuer      string                         `json:"cert_issuer"`
	CertNotAfter    int64                          `json:"cert_not_after"`
	CertStatus      string                         `json:"cert_status"`
	CertError       string                         `json:"cert_error"`
	CertUpdatedAt   int64                          `json:"cert_updated_at"`
	Overrides       edgeNodeOverrides              `json:"overrides"`
	NodeLimits      map[string]edgeDomainNodeLimit `json:"node_limits,omitempty"`
	WAFRuleIDs      []string                       `json:"waf_rule_ids"`
	SmartDNS        *edgeDomainSmartDNS            `json:"smart_dns,omitempty"`
	CreatedAt       int64                          `json:"created_at"`
	UpdatedAt       int64                          `json:"updated_at"`
}

type edgeDomainNodeBrief struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Region         string `json:"region"`
	Status         string `json:"status"`
	EffectiveIPv4  string `json:"effective_ipv4,omitempty"`
	EffectiveIPv6  string `json:"effective_ipv6,omitempty"`
	ActiveDNS      bool   `json:"active_dns,omitempty"`
	SpeedLimitMbps *int64 `json:"speed_limit_mbps,omitempty"`
}

type edgeDomainView struct {
	edgeDomainRecord
	HasCertificate    bool                  `json:"has_certificate"`
	CertStrategy      string                `json:"cert_strategy"`
	BoundNodes        []edgeDomainNodeBrief `json:"bound_nodes"`
	BoundWAFRules     []wafRuleBrief        `json:"bound_waf_rules"`
	HealthyNodeCount  int                   `json:"healthy_node_count"`
	TotalNodeCount    int                   `json:"total_node_count"`
	DNSActiveNodeName string                `json:"dns_active_node_name,omitempty"`
}

type edgeDomainsSummary struct {
	Total       int `json:"total"`
	Enabled     int `json:"enabled"`
	CertsReady  int `json:"certs_ready"`
	DNSManaged  int `json:"dns_managed"`
	BoundNodes  int `json:"bound_nodes"`
}

type edgeDomainsListResponse struct {
	CFEnabled           bool                  `json:"cf_enabled"`
	CFRootDomain        string                `json:"cf_root_domain"`
	AxisNowEnabled      bool                  `json:"axisnow_enabled"`
	AxisNowProviderType string                `json:"axisnow_provider_type,omitempty"`
	AxisNowDefaultZone  string                `json:"axisnow_default_zone,omitempty"`
	AxisNowProviders    []axisnowProviderInfo `json:"axisnow_providers,omitempty"`
	Summary             edgeDomainsSummary    `json:"summary"`
	Domains             []edgeDomainView      `json:"domains"`
}

func normalizeDomainDNSMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case domainDNSCloudflareAll:
		return domainDNSCloudflareAll
	case domainDNSCloudflareFailover:
		return domainDNSCloudflareFailover
	case domainDNSAxisNowSmart:
		return domainDNSAxisNowSmart
	default:
		return domainDNSManual
	}
}

func normalizeDomainTLSMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case domainTLSManual:
		return domainTLSManual
	case domainTLSExternal:
		return domainTLSExternal
	default:
		return domainTLSAuto
	}
}

func normalizeDomainProxied(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case domainProxiedOn:
		return domainProxiedOn
	case domainProxiedOff:
		return domainProxiedOff
	default:
		return domainProxiedInherit
	}
}

func normalizeEdgeDomainPattern(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", errors.New("domain is required")
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("invalid domain")
		}
		value = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	}
	value = strings.Trim(value, "/.")
	wildcard := false
	if strings.HasPrefix(value, "*.") {
		wildcard = true
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" || !strings.Contains(value, ".") || net.ParseIP(value) != nil || !validRuleDomain(value) {
		return "", fmt.Errorf("invalid domain %q (example: play.example.com or *.example.com)", raw)
	}
	if wildcard {
		return "*." + value, nil
	}
	return value, nil
}

func edgeDomainBaseHost(pattern string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(pattern)), "*.")
}

func matchEdgeDomainHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = normalizeHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return host == pattern
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(host, suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func normalizeDomainNodeIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeDomainNodeLimits(raw map[string]edgeDomainNodeLimit, allowedNodeIDs []string) map[string]edgeDomainNodeLimit {
	if len(raw) == 0 || len(allowedNodeIDs) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(allowedNodeIDs))
	for _, id := range allowedNodeIDs {
		allowed[id] = struct{}{}
	}
	out := make(map[string]edgeDomainNodeLimit)
	for rawID, lim := range raw {
		id := strings.TrimSpace(rawID)
		if _, ok := allowed[id]; !ok || lim.isEmpty() {
			continue
		}
		out[id] = lim
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateDomainNodeLimits(base runtimeSettings, domainOverrides edgeNodeOverrides, nodeLimits map[string]edgeDomainNodeLimit) error {
	for nodeID, lim := range nodeLimits {
		merged := lim.applyToOverrides(domainOverrides).ApplyTo(base)
		if _, _, err := applyRuntimeSettings(Config{}, merged); err != nil {
			return fmt.Errorf("invalid limit override for node %s: %w", nodeID, err)
		}
	}
	return nil
}

func parseAndValidateCertKeyPair(certPEM, keyPEM string) (issuer string, notAfter int64, err error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return "", 0, errors.New("certificate PEM and private key PEM are required")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return "", 0, fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return "", 0, errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", 0, fmt.Errorf("parse leaf certificate: %w", err)
	}
	issuer = strings.TrimSpace(leaf.Issuer.CommonName)
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = strings.TrimSpace(leaf.Issuer.Organization[0])
	}
	if issuer == "" {
		issuer = "Manual PEM"
	}
	return issuer, leaf.NotAfter.Unix(), nil
}

func scanEdgeDomain(scanner rowScanner) (edgeDomainRecord, error) {
	var rec edgeDomainRecord
	var enabledInt, visibleInt int
	var nodeIDsRaw, overridesRaw, nodeLimitsRaw, wafIDsRaw, smartDNSRaw string
	err := scanner.Scan(
		&rec.ID, &rec.Domain, &rec.Name, &rec.Note, &enabledInt, &visibleInt, &nodeIDsRaw,
		&rec.DNSMode, &rec.DNSIPMode, &rec.DNSProxied, &rec.DNSActiveNodeID, &rec.DNSLastSyncAt, &rec.DNSLastError,
		&rec.TLSMode, &rec.CertPEM, &rec.KeyPEMEnc, &rec.CertIssuer, &rec.CertNotAfter, &rec.CertStatus, &rec.CertError, &rec.CertUpdatedAt,
		&overridesRaw, &nodeLimitsRaw, &wafIDsRaw, &smartDNSRaw, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rec.Enabled = enabledInt == 1
	rec.PublicVisible = visibleInt == 1
	rec.DNSMode = normalizeDomainDNSMode(rec.DNSMode)
	rec.DNSIPMode = normalizeDNSIPMode(rec.DNSIPMode)
	rec.DNSProxied = normalizeDomainProxied(rec.DNSProxied)
	rec.TLSMode = normalizeDomainTLSMode(rec.TLSMode)
	if strings.TrimSpace(nodeIDsRaw) != "" {
		_ = json.Unmarshal([]byte(nodeIDsRaw), &rec.NodeIDs)
	}
	rec.NodeIDs = normalizeDomainNodeIDs(rec.NodeIDs)
	if strings.TrimSpace(overridesRaw) != "" {
		_ = json.Unmarshal([]byte(overridesRaw), &rec.Overrides)
	}
	if strings.TrimSpace(nodeLimitsRaw) != "" {
		var parsed map[string]edgeDomainNodeLimit
		if json.Unmarshal([]byte(nodeLimitsRaw), &parsed) == nil {
			rec.NodeLimits = normalizeDomainNodeLimits(parsed, rec.NodeIDs)
		}
	}
	if strings.TrimSpace(wafIDsRaw) != "" {
		_ = json.Unmarshal([]byte(wafIDsRaw), &rec.WAFRuleIDs)
	}
	rec.WAFRuleIDs = normalizeDomainNodeIDs(rec.WAFRuleIDs)
	if trimmed := strings.TrimSpace(smartDNSRaw); trimmed != "" && trimmed != "{}" && trimmed != "null" {
		var parsed edgeDomainSmartDNS
		if json.Unmarshal([]byte(trimmed), &parsed) == nil {
			rec.SmartDNS = &parsed
		}
	}
	return rec, nil
}

func (s *telemetryStore) ListEdgeDomains(ctx context.Context) ([]edgeDomainRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+edgeDomainSelectCols+` FROM edge_domains ORDER BY created_at DESC, domain COLLATE NOCASE ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]edgeDomainRecord, 0)
	for rows.Next() {
		rec, err := scanEdgeDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *telemetryStore) GetEdgeDomain(ctx context.Context, id string) (edgeDomainRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+edgeDomainSelectCols+` FROM edge_domains WHERE id=?`, strings.TrimSpace(id))
	return scanEdgeDomain(row)
}

func (s *telemetryStore) CreateEdgeDomain(ctx context.Context, rec edgeDomainRecord) (edgeDomainRecord, error) {
	domain, err := normalizeEdgeDomainPattern(rec.Domain)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rec.Domain = domain
	rec.Name = truncateRunes(strings.TrimSpace(rec.Name), 64)
	if rec.Name == "" {
		rec.Name = domain
	}
	rec.Note = truncateRunes(strings.TrimSpace(rec.Note), 160)
	rec.NodeIDs = normalizeDomainNodeIDs(rec.NodeIDs)
	rec.NodeLimits = normalizeDomainNodeLimits(rec.NodeLimits, rec.NodeIDs)
	rec.WAFRuleIDs = normalizeDomainNodeIDs(rec.WAFRuleIDs)
	rec.DNSMode = normalizeDomainDNSMode(rec.DNSMode)
	rec.DNSIPMode = normalizeDNSIPMode(rec.DNSIPMode)
	rec.DNSProxied = normalizeDomainProxied(rec.DNSProxied)
	rec.TLSMode = normalizeDomainTLSMode(rec.TLSMode)
	if rec.CertStatus == "" {
		if rec.TLSMode == domainTLSExternal {
			rec.CertStatus = "external"
		} else {
			rec.CertStatus = "idle"
		}
	}

	rawID, err := generateRandomHex(8)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rec.ID = "dm_" + rawID
	now := time.Now().Unix()
	rec.CreatedAt = now
	rec.UpdatedAt = now

	nodeIDsJSON, _ := json.Marshal(rec.NodeIDs)
	overridesJSON, _ := json.Marshal(rec.Overrides)
	wafIDsJSON, _ := json.Marshal(rec.WAFRuleIDs)
	nodeLimitsJSON := "{}"
	if len(rec.NodeLimits) > 0 {
		if raw, mErr := json.Marshal(rec.NodeLimits); mErr == nil {
			nodeLimitsJSON = string(raw)
		}
	}
	smartDNSJSON := "{}"
	if rec.SmartDNS != nil {
		if raw, mErr := json.Marshal(rec.SmartDNS); mErr == nil {
			smartDNSJSON = string(raw)
		}
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO edge_domains(
			id,domain,name,note,enabled,public_visible,node_ids_json,
			dns_mode,dns_ip_mode,dns_proxied,dns_active_node_id,dns_last_sync_at,dns_last_error,
			tls_mode,cert_pem,key_pem_enc,cert_issuer,cert_not_after,cert_status,cert_error,cert_updated_at,
			overrides_json,node_limits_json,waf_rule_ids_json,smart_dns_json,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,'',?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.ID, rec.Domain, rec.Name, rec.Note, boolToInt(rec.Enabled), boolToInt(rec.PublicVisible), string(nodeIDsJSON),
		rec.DNSMode, rec.DNSIPMode, rec.DNSProxied, "",
		rec.TLSMode, rec.CertPEM, rec.KeyPEMEnc, rec.CertIssuer, rec.CertNotAfter, rec.CertStatus, rec.CertError, rec.CertUpdatedAt,
		string(overridesJSON), nodeLimitsJSON, string(wafIDsJSON), smartDNSJSON, rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return edgeDomainRecord{}, fmt.Errorf("domain %q already exists", rec.Domain)
		}
		return edgeDomainRecord{}, err
	}
	return s.GetEdgeDomain(ctx, rec.ID)
}

func (s *telemetryStore) UpdateEdgeDomain(ctx context.Context, id string, rec edgeDomainRecord) (edgeDomainRecord, error) {
	domain, err := normalizeEdgeDomainPattern(rec.Domain)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rec.Domain = domain
	rec.Name = truncateRunes(strings.TrimSpace(rec.Name), 64)
	if rec.Name == "" {
		rec.Name = domain
	}
	rec.Note = truncateRunes(strings.TrimSpace(rec.Note), 160)
	rec.NodeIDs = normalizeDomainNodeIDs(rec.NodeIDs)
	rec.NodeLimits = normalizeDomainNodeLimits(rec.NodeLimits, rec.NodeIDs)
	rec.WAFRuleIDs = normalizeDomainNodeIDs(rec.WAFRuleIDs)
	rec.DNSMode = normalizeDomainDNSMode(rec.DNSMode)
	rec.DNSIPMode = normalizeDNSIPMode(rec.DNSIPMode)
	rec.DNSProxied = normalizeDomainProxied(rec.DNSProxied)
	rec.TLSMode = normalizeDomainTLSMode(rec.TLSMode)
	now := time.Now().Unix()

	nodeIDsJSON, _ := json.Marshal(rec.NodeIDs)
	overridesJSON, _ := json.Marshal(rec.Overrides)
	wafIDsJSON, _ := json.Marshal(rec.WAFRuleIDs)
	nodeLimitsJSON := "{}"
	if len(rec.NodeLimits) > 0 {
		if raw, mErr := json.Marshal(rec.NodeLimits); mErr == nil {
			nodeLimitsJSON = string(raw)
		}
	}
	smartDNSJSON := "{}"
	if rec.SmartDNS != nil {
		if raw, mErr := json.Marshal(rec.SmartDNS); mErr == nil {
			smartDNSJSON = string(raw)
		}
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET domain=?, name=?, note=?, enabled=?, public_visible=?, node_ids_json=?,
		    dns_mode=?, dns_ip_mode=?, dns_proxied=?, tls_mode=?,
		    cert_pem=?, key_pem_enc=?, cert_issuer=?, cert_not_after=?, cert_status=?, cert_error=?, cert_updated_at=?,
		    overrides_json=?, node_limits_json=?, waf_rule_ids_json=?, smart_dns_json=?, updated_at=?
		WHERE id=?`,
		rec.Domain, rec.Name, rec.Note, boolToInt(rec.Enabled), boolToInt(rec.PublicVisible), string(nodeIDsJSON),
		rec.DNSMode, rec.DNSIPMode, rec.DNSProxied, rec.TLSMode,
		rec.CertPEM, rec.KeyPEMEnc, rec.CertIssuer, rec.CertNotAfter, rec.CertStatus, rec.CertError, rec.CertUpdatedAt,
		string(overridesJSON), nodeLimitsJSON, string(wafIDsJSON), smartDNSJSON, now, id,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return edgeDomainRecord{}, fmt.Errorf("domain %q already exists", rec.Domain)
		}
		return edgeDomainRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return edgeDomainRecord{}, sql.ErrNoRows
	}
	return s.GetEdgeDomain(ctx, id)
}

func (s *telemetryStore) UpdateEdgeDomainPreservingCert(ctx context.Context, id string, rec edgeDomainRecord) (edgeDomainRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return edgeDomainRecord{}, sql.ErrNoRows
	}
	domain, err := normalizeEdgeDomainPattern(rec.Domain)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rec.Domain = domain
	rec.Name = truncateRunes(strings.TrimSpace(rec.Name), 64)
	if rec.Name == "" {
		rec.Name = domain
	}
	rec.Note = truncateRunes(strings.TrimSpace(rec.Note), 160)
	rec.NodeIDs = normalizeDomainNodeIDs(rec.NodeIDs)
	rec.DNSMode = normalizeDomainDNSMode(rec.DNSMode)
	rec.DNSIPMode = normalizeDNSIPMode(rec.DNSIPMode)
	rec.DNSProxied = normalizeDomainProxied(rec.DNSProxied)
	rec.TLSMode = normalizeDomainTLSMode(rec.TLSMode)
	rec.WAFRuleIDs = normalizeDomainNodeIDs(rec.WAFRuleIDs)

	now := time.Now().Unix()
	nodeIDsJSON, _ := json.Marshal(rec.NodeIDs)
	overridesJSON, _ := json.Marshal(rec.Overrides)
	wafIDsJSON, _ := json.Marshal(rec.WAFRuleIDs)
	nodeLimitsJSON := "{}"
	if len(rec.NodeLimits) > 0 {
		if raw, mErr := json.Marshal(rec.NodeLimits); mErr == nil {
			nodeLimitsJSON = string(raw)
		}
	}
	smartDNSJSON := "{}"
	if rec.SmartDNS != nil {
		if raw, mErr := json.Marshal(rec.SmartDNS); mErr == nil {
			smartDNSJSON = string(raw)
		}
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET domain=?, name=?, note=?, enabled=?, public_visible=?, node_ids_json=?,
		    dns_mode=?, dns_ip_mode=?, dns_proxied=?, tls_mode=?,
		    overrides_json=?, node_limits_json=?, waf_rule_ids_json=?, smart_dns_json=?, updated_at=?
		WHERE id=?`,
		rec.Domain, rec.Name, rec.Note, boolToInt(rec.Enabled), boolToInt(rec.PublicVisible), string(nodeIDsJSON),
		rec.DNSMode, rec.DNSIPMode, rec.DNSProxied, rec.TLSMode,
		string(overridesJSON), nodeLimitsJSON, string(wafIDsJSON), smartDNSJSON, now, id,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return edgeDomainRecord{}, fmt.Errorf("domain %q already exists", rec.Domain)
		}
		return edgeDomainRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return edgeDomainRecord{}, sql.ErrNoRows
	}
	return s.GetEdgeDomain(ctx, id)
}

func (s *telemetryStore) UpdateEdgeDomainSmartDNSAndNodes(ctx context.Context, id string, nodeIDs []string, smartDNS *edgeDomainSmartDNS) (edgeDomainRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return edgeDomainRecord{}, sql.ErrNoRows
	}
	nodeIDsJSON, _ := json.Marshal(normalizeDomainNodeIDs(nodeIDs))
	smartJSON := "{}"
	if smartDNS != nil {
		if raw, err := json.Marshal(smartDNS); err == nil {
			smartJSON = string(raw)
		}
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET node_ids_json=?, smart_dns_json=?, updated_at=?
		WHERE id=?`,
		string(nodeIDsJSON), smartJSON, time.Now().Unix(), id,
	)
	if err != nil {
		return edgeDomainRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return edgeDomainRecord{}, sql.ErrNoRows
	}
	return s.GetEdgeDomain(ctx, id)
}

func (s *telemetryStore) UpdateEdgeDomainDNSState(ctx context.Context, id, activeNodeID string, lastSyncAt int64, lastErr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET dns_active_node_id=?, dns_last_sync_at=?, dns_last_error=?
		WHERE id=?`,
		activeNodeID, lastSyncAt, truncateRunes(strings.TrimSpace(lastErr), 200), id,
	)
	return err
}

func (s *telemetryStore) UpdateEdgeDomainSmartDNSState(ctx context.Context, id string, smartDNS *edgeDomainSmartDNS, activeNodeID string, lastSyncAt int64, lastErr string) error {
	smartJSON := "{}"
	if smartDNS != nil {
		if raw, err := json.Marshal(smartDNS); err == nil {
			smartJSON = string(raw)
		}
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET smart_dns_json=?, dns_active_node_id=?, dns_last_sync_at=?, dns_last_error=?
		WHERE id=?`,
		smartJSON, activeNodeID, lastSyncAt, truncateRunes(strings.TrimSpace(lastErr), 200), id,
	)
	return err
}

func (s *telemetryStore) UpdateEdgeDomainCertState(ctx context.Context, id, certPEM, keyPEMEnc, issuer string, notAfter int64, status, certErr string, updatedAt int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET cert_pem=?, key_pem_enc=?, cert_issuer=?, cert_not_after=?, cert_status=?, cert_error=?, cert_updated_at=?, updated_at=?
		WHERE id=?`,
		certPEM, keyPEMEnc, truncateRunes(strings.TrimSpace(issuer), 96), notAfter,
		truncateRunes(strings.TrimSpace(status), 32), truncateRunes(strings.TrimSpace(certErr), 240),
		updatedAt, time.Now().Unix(), id,
	)
	return err
}

func (s *telemetryStore) UpdateEdgeDomainCertStatusOnly(ctx context.Context, id, status, certErr string) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_domains
		SET cert_status=?, cert_error=?, cert_updated_at=?
		WHERE id=?`,
		truncateRunes(strings.TrimSpace(status), 32), truncateRunes(strings.TrimSpace(certErr), 240), now, id,
	)
	return err
}

func (s *telemetryStore) DeleteEdgeDomain(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM edge_domains WHERE id=?`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *telemetryStore) RemoveNodeFromAllDomains(ctx context.Context, nodeID string) ([]string, error) {
	domains, err := s.ListEdgeDomains(ctx)
	if err != nil {
		return nil, err
	}
	affected := make([]string, 0)
	for _, dom := range domains {
		nextIDs := make([]string, 0, len(dom.NodeIDs))
		found := false
		for _, id := range dom.NodeIDs {
			if id == nodeID {
				found = true
				continue
			}
			nextIDs = append(nextIDs, id)
		}
		if !found {
			// Still check if referenced inside SmartDNS lines
			smartChanged := false
			if dom.SmartDNS != nil {
				for idx := range dom.SmartDNS.Lines {
					line := &dom.SmartDNS.Lines[idx]
					filtered := make([]string, 0, len(line.NodeIDs))
					for _, id := range line.NodeIDs {
						if id == nodeID {
							smartChanged = true
							continue
						}
						filtered = append(filtered, id)
					}
					line.NodeIDs = filtered
				}
			}
			if !smartChanged {
				continue
			}
			smartRaw, _ := json.Marshal(dom.SmartDNS)
			if _, err := s.db.ExecContext(ctx, `UPDATE edge_domains SET smart_dns_json=?, updated_at=? WHERE id=?`, string(smartRaw), time.Now().Unix(), dom.ID); err == nil {
				affected = append(affected, dom.ID)
			}
			continue
		}
		if dom.SmartDNS != nil {
			for idx := range dom.SmartDNS.Lines {
				line := &dom.SmartDNS.Lines[idx]
				filtered := make([]string, 0, len(line.NodeIDs))
				for _, id := range line.NodeIDs {
					if id == nodeID {
						continue
					}
					filtered = append(filtered, id)
				}
				line.NodeIDs = filtered
			}
		}
		nextLimits := normalizeDomainNodeLimits(dom.NodeLimits, nextIDs)
		raw, _ := json.Marshal(nextIDs)
		limJSON := "{}"
		if len(nextLimits) > 0 {
			if b, mErr := json.Marshal(nextLimits); mErr == nil {
				limJSON = string(b)
			}
		}
		smartJSON := "{}"
		if dom.SmartDNS != nil {
			if b, mErr := json.Marshal(dom.SmartDNS); mErr == nil {
				smartJSON = string(b)
			}
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE edge_domains SET node_ids_json=?, node_limits_json=?, smart_dns_json=?, updated_at=? WHERE id=?`, string(raw), limJSON, smartJSON, time.Now().Unix(), dom.ID); err == nil {
			affected = append(affected, dom.ID)
		}
	}
	return affected, nil
}

// MigrateLegacyNodeDomains converts existing nodes that already had real HTTPS hostnames
// into edge_domains entries once, preserving backwards compatibility seamlessly.
func (s *telemetryStore) MigrateLegacyNodeDomains(ctx context.Context) {
	if s == nil {
		return
	}
	var marker string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key='edge_domains_migrated_v1'`).Scan(&marker); err == nil && marker == "1" {
		return
	}
	existingDomains, err := s.ListEdgeDomains(ctx)
	if err != nil || len(existingDomains) > 0 {
		_, _ = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO gateway_settings(key,value,updated_at) VALUES('edge_domains_migrated_v1','1',?)`, time.Now().Unix())
		return
	}
	nodes, err := s.ListEdgeNodes(ctx)
	if err == nil {
		for _, node := range nodes {
			parsed, parseErr := parseHTTPURL(node.PublicURL)
			if parseErr != nil || !strings.EqualFold(parsed.Scheme, "https") {
				continue
			}
			host := normalizeHost(parsed.Hostname())
			if !isAutoTLSEligibleHost(host) {
				continue
			}
			dnsMode := domainDNSManual
			if node.DNSSyncEnabled {
				dnsMode = domainDNSCloudflareAll
			}
			_, _ = s.CreateEdgeDomain(ctx, edgeDomainRecord{
				Domain:        host,
				Name:          node.Name,
				Note:          strings.TrimSpace(strings.Join(nonEmptyStrings(node.GroupName, node.Region), " · ")),
				Enabled:       true,
				PublicVisible: node.PublicVisible,
				NodeIDs:       []string{node.ID},
				DNSMode:       dnsMode,
				DNSIPMode:     node.DNSIPMode,
				DNSProxied:    domainProxiedInherit,
				TLSMode:       domainTLSAuto,
				CertStatus:    "idle",
			})
		}
	}
	_, _ = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO gateway_settings(key,value,updated_at) VALUES('edge_domains_migrated_v1','1',?)`, time.Now().Unix())
}

func (c *clusterController) domainCertStrategy(dom edgeDomainRecord, cf cloudflareDNSStored) string {
	switch dom.TLSMode {
	case domainTLSManual:
		return "manual"
	case domainTLSExternal:
		return "external"
	default:
		if cf.Enabled && cf.EncryptedToken != "" && hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), cf.RootDomain) {
			return "controller_dns01"
		}
		if strings.HasPrefix(dom.Domain, "*.") {
			return "controller_dns01" // wildcard requires DNS-01
		}
		return "agent_http01"
	}
}

func (c *clusterController) ListDomainViews(ctx context.Context) (edgeDomainsListResponse, error) {
	domains, err := c.store.ListEdgeDomains(ctx)
	if err != nil {
		return edgeDomainsListResponse{}, err
	}
	nodes, err := c.store.ListEdgeNodes(ctx)
	if err != nil {
		return edgeDomainsListResponse{}, err
	}
	cf := c.store.LoadCloudflareDNS(ctx)
	an := c.store.LoadAxisNowDNS(ctx)
	smartProfiles, _ := c.store.ListSmartDNSProfiles(ctx)
	smartProfByID := make(map[string]smartDNSProfileRecord, len(smartProfiles))
	for _, sp := range smartProfiles {
		smartProfByID[sp.ID] = sp
	}
	wafRules, _ := c.store.ListWAFRules(ctx)
	wafByID := make(map[string]wafRuleRecord, len(wafRules))
	for _, r := range wafRules {
		wafByID[r.ID] = r
	}
	now := time.Now()
	nodeMap := make(map[string]edgeNodeRecord, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	views := make([]edgeDomainView, 0, len(domains))
	var summary edgeDomainsSummary
	summary.Total = len(domains)
	uniqueBound := make(map[string]struct{})

	for _, dom := range domains {
		if dom.Enabled {
			summary.Enabled++
		}
		if dom.DNSMode != domainDNSManual {
			summary.DNSManaged++
		}
		strategy := c.domainCertStrategy(dom, cf)
		hasCert := dom.CertPEM != "" && dom.KeyPEMEnc != ""
		if dom.TLSMode == domainTLSExternal || (hasCert && dom.CertStatus == "ready") || (strategy == "agent_http01" && dom.Enabled && len(dom.NodeIDs) > 0) {
			if hasCert && dom.CertStatus == "ready" {
				summary.CertsReady++
			}
		}

		briefs := make([]edgeDomainNodeBrief, 0, len(dom.NodeIDs))
		healthy := 0
		activeName := ""
		for _, nid := range dom.NodeIDs {
			n, ok := nodeMap[nid]
			if !ok {
				continue
			}
			uniqueBound[nid] = struct{}{}
			status, _ := c.nodeStatus(n, now)
			if status == edgeNodeStatusOnline {
				healthy++
			}
			v4, v6 := effectiveNodeIPs(n)
			isActiveDNS := dom.DNSActiveNodeID != "" && dom.DNSActiveNodeID == nid
			if isActiveDNS {
				activeName = n.Name
			}
			var nodeSpeed *int64
			if nl, ok := dom.NodeLimits[nid]; ok && nl.MaxDownloadMbitPerIP != nil {
				v := *nl.MaxDownloadMbitPerIP
				nodeSpeed = &v
			}
			briefs = append(briefs, edgeDomainNodeBrief{
				ID:             n.ID,
				Name:           n.Name,
				Region:         n.Region,
				Status:         status,
				EffectiveIPv4:  v4,
				EffectiveIPv6:  v6,
				ActiveDNS:      isActiveDNS,
				SpeedLimitMbps: nodeSpeed,
			})
		}

		displayStatus := dom.CertStatus
		if dom.TLSMode == domainTLSExternal {
			displayStatus = "external"
		} else if strategy == "agent_http01" && !hasCert {
			displayStatus = "agent_auto"
		}
		domCopy := dom
		domCopy.CertStatus = displayStatus
		if domCopy.SmartDNS != nil && domCopy.SmartDNS.ProfileID != "" {
			if sp, ok := smartProfByID[domCopy.SmartDNS.ProfileID]; ok {
				cp := *domCopy.SmartDNS
				cp.ProfileName = sp.Name
				domCopy.SmartDNS = &cp
			}
		}

		boundWAF := make([]wafRuleBrief, 0, len(dom.WAFRuleIDs))
		for _, rid := range dom.WAFRuleIDs {
			if wr, ok := wafByID[rid]; ok {
				boundWAF = append(boundWAF, wafRuleBrief{
					ID: wr.ID, Name: wr.Name, Enabled: wr.Enabled, IsGlobal: wr.IsGlobal,
				})
			}
		}

		views = append(views, edgeDomainView{
			edgeDomainRecord:  domCopy,
			HasCertificate:    hasCert,
			CertStrategy:      strategy,
			BoundNodes:        briefs,
			BoundWAFRules:     boundWAF,
			HealthyNodeCount:  healthy,
			TotalNodeCount:    len(briefs),
			DNSActiveNodeName: activeName,
		})
	}
	summary.BoundNodes = len(uniqueBound)

	return edgeDomainsListResponse{
		CFEnabled:           cf.Enabled,
		CFRootDomain:        cf.RootDomain,
		AxisNowEnabled:      an.Enabled && an.EncryptedToken != "",
		AxisNowProviderType: an.DefaultProviderType,
		AxisNowDefaultZone:  an.DefaultZoneName,
		AxisNowProviders:    an.CachedProviders,
		Summary:             summary,
		Domains:             views,
	}, nil
}

func (c *clusterController) notifyNodesList(nodeIDs []string) {
	seen := make(map[string]struct{}, len(nodeIDs))
	for _, nid := range nodeIDs {
		if nid == "" {
			continue
		}
		if _, dup := seen[nid]; dup {
			continue
		}
		seen[nid] = struct{}{}
		c.NotifyConfigChanged(nid)
	}
}

/* -------------------- Admin API (/_admin/api/domains*) -------------------- */

type edgeDomainMutationRequest struct {
	Domain        string                         `json:"domain"`
	Name          string                         `json:"name"`
	Note          string                         `json:"note"`
	Enabled       *bool                          `json:"enabled"`
	PublicVisible *bool                          `json:"public_visible"`
	NodeIDs       []string                       `json:"node_ids"`
	DNSMode       string                         `json:"dns_mode"`
	DNSIPMode     string                         `json:"dns_ip_mode"`
	DNSProxied    string                         `json:"dns_proxied"`
	TLSMode       string                         `json:"tls_mode"`
	CertPEM       string                         `json:"cert_pem"`
	KeyPEM        string                         `json:"key_pem"`
	Overrides     edgeNodeOverrides              `json:"overrides"`
	NodeLimits    map[string]edgeDomainNodeLimit `json:"node_limits,omitempty"`
	WAFRuleIDs    []string                       `json:"waf_rule_ids,omitempty"`
	SmartDNS      *edgeDomainSmartDNS            `json:"smart_dns,omitempty"`
}

func (a *adminServer) handleEdgeDomains(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge controller unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		res, err := a.gateway.cluster.ListDomainViews(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load domains")
			return
		}
		a.writeJSON(w, http.StatusOK, res)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req edgeDomainMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		baseRuntime := a.gateway.cluster.globalRuntimeSettings()
		if err := validateProxyTrustOverrides(&req.Overrides); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid CDN real-IP configuration: "+err.Error())
			return
		}
		merged := req.Overrides.ApplyTo(baseRuntime)
		if _, _, err := applyRuntimeSettings(Config{}, merged); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid domain runtime overrides: "+err.Error())
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		visible := true
		if req.PublicVisible != nil {
			visible = *req.PublicVisible
		}
		tlsMode := normalizeDomainTLSMode(req.TLSMode)
		dnsMode := normalizeDomainDNSMode(req.DNSMode)
		nodeIDs := normalizeDomainNodeIDs(req.NodeIDs)
		var smartCfg *edgeDomainSmartDNS
		if dnsMode == domainDNSAxisNowSmart || req.SmartDNS != nil {
			if req.SmartDNS != nil && strings.TrimSpace(req.SmartDNS.ProfileID) != "" {
				prof, pErr := a.store.GetSmartDNSProfile(r.Context(), req.SmartDNS.ProfileID)
				if pErr != nil {
					a.writeError(w, http.StatusBadRequest, "所选智能分流方案不存在")
					return
				}
				smartCfg = applySmartDNSProfileToDomain(prof, nil, false)
				if host := normalizeDomainHostname(req.SmartDNS.RoutingDomainHost); host != "" {
					smartCfg.RoutingDomainHost = host
				}
			} else {
				smartCfg = normalizeEdgeDomainSmartDNS(req.SmartDNS, nodeIDs, nil)
			}
			if dnsMode == domainDNSAxisNowSmart {
				if smartCfg == nil {
					smartCfg = normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{}, nodeIDs, nil)
				}
				nodeIDs = normalizeDomainNodeIDs(append(nodeIDs, collectSmartDNSNodeIDs(smartCfg)...))
			}
		}
		normNodeLimits := normalizeDomainNodeLimits(req.NodeLimits, nodeIDs)
		if err := validateDomainNodeLimits(baseRuntime, req.Overrides, normNodeLimits); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		rec := edgeDomainRecord{
			Domain:        req.Domain,
			Name:          req.Name,
			Note:          req.Note,
			Enabled:       enabled,
			PublicVisible: visible,
			NodeIDs:       nodeIDs,
			DNSMode:       dnsMode,
			DNSIPMode:     req.DNSIPMode,
			DNSProxied:    req.DNSProxied,
			TLSMode:       tlsMode,
			Overrides:     req.Overrides,
			NodeLimits:    normNodeLimits,
			WAFRuleIDs:    req.WAFRuleIDs,
			SmartDNS:      smartCfg,
		}
		if tlsMode == domainTLSManual {
			issuer, notAfter, err := parseAndValidateCertKeyPair(req.CertPEM, req.KeyPEM)
			if err != nil {
				a.writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			encKey, err := a.gateway.cluster.certCipher.Encrypt(strings.TrimSpace(req.KeyPEM))
			if err != nil {
				a.writeError(w, http.StatusInternalServerError, "failed to encrypt certificate key")
				return
			}
			rec.CertPEM = strings.TrimSpace(req.CertPEM)
			rec.KeyPEMEnc = encKey
			rec.CertIssuer = issuer
			rec.CertNotAfter = notAfter
			rec.CertStatus = "ready"
			rec.CertUpdatedAt = time.Now().Unix()
		} else if tlsMode == domainTLSExternal {
			rec.CertStatus = "external"
		} else {
			rec.CertStatus = "idle"
		}

		created, err := a.store.CreateEdgeDomain(r.Context(), rec)
		if err != nil {
			a.auditRequest(r, "edge_domain.create", req.Domain, err.Error(), false)
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.cluster.notifyNodesList(created.NodeIDs)
		a.gateway.cluster.triggerDomainBackgroundTasks(created, "")
		a.auditRequest(r, "edge_domain.create", created.Domain, fmt.Sprintf("id=%s nodes=%d dns=%s tls=%s", created.ID, len(created.NodeIDs), created.DNSMode, created.TLSMode), true)
		list, _ := a.gateway.cluster.ListDomainViews(r.Context())
		for _, v := range list.Domains {
			if v.ID == created.ID {
				a.writeJSON(w, http.StatusCreated, v)
				return
			}
		}
		a.writeJSON(w, http.StatusCreated, created)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleEdgeDomainItem(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge controller unavailable")
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/domains/")
	parts := strings.Split(remainder, "/")
	domainID := strings.TrimSpace(parts[0])
	if domainID == "" || len(domainID) > 48 {
		a.writeError(w, http.StatusBadRequest, "invalid domain id")
		return
	}

	if len(parts) == 2 && parts[1] == "issue-cert" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		dom, err := a.store.GetEdgeDomain(r.Context(), domainID)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		if dom.TLSMode != domainTLSAuto {
			a.writeError(w, http.StatusBadRequest, "仅自动证书模式（auto）支持主控 ACME DNS-01 自动签发")
			return
		}
		if a.gateway.cluster.acme == nil {
			a.writeError(w, http.StatusServiceUnavailable, "ACME issuer unavailable")
			return
		}
		if err := a.gateway.cluster.acme.StartIssuanceAsync(dom.ID); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.auditRequest(r, "edge_domain.issue_cert", dom.Domain, "triggered DNS-01 issuance", true)
		a.writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "status": "issuing"})
		return
	}

	if len(parts) == 2 && parts[1] == "sync-dns" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		dom, err := a.store.GetEdgeDomain(r.Context(), domainID)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		if dom.DNSMode == domainDNSAxisNowSmart {
			if a.gateway.axisnow == nil {
				a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS unavailable")
				return
			}
			if err := a.gateway.axisnow.SyncEdgeDomainSmartDNS(r.Context(), dom, time.Now()); err != nil {
				a.auditRequest(r, "edge_domain.sync_dns", dom.Domain, err.Error(), false)
				a.writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		} else {
			if a.gateway.cloudflare == nil {
				a.writeError(w, http.StatusServiceUnavailable, "cloudflare DNS unavailable")
				return
			}
			if err := a.gateway.cloudflare.SyncEdgeDomainDNS(r.Context(), dom, "", time.Now()); err != nil {
				a.auditRequest(r, "edge_domain.sync_dns", dom.Domain, err.Error(), false)
				a.writeError(w, http.StatusBadGateway, err.Error())
				return
			}
		}
		a.auditRequest(r, "edge_domain.sync_dns", dom.Domain, "manual DNS sync", true)
		list, _ := a.gateway.cluster.ListDomainViews(r.Context())
		for _, v := range list.Domains {
			if v.ID == dom.ID {
				a.writeJSON(w, http.StatusOK, v)
				return
			}
		}
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}

	if len(parts) == 2 && parts[1] == "certificate" {
		if r.Method != http.MethodPut {
			a.methodNotAllowed(w, http.MethodPut)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		dom, err := a.store.GetEdgeDomain(r.Context(), domainID)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		var req struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		issuer, notAfter, err := parseAndValidateCertKeyPair(req.CertPEM, req.KeyPEM)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		encKey, err := a.gateway.cluster.certCipher.Encrypt(strings.TrimSpace(req.KeyPEM))
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to encrypt private key")
			return
		}
		dom.TLSMode = domainTLSManual
		dom.CertPEM = strings.TrimSpace(req.CertPEM)
		dom.KeyPEMEnc = encKey
		dom.CertIssuer = issuer
		dom.CertNotAfter = notAfter
		dom.CertStatus = "ready"
		dom.CertError = ""
		dom.CertUpdatedAt = time.Now().Unix()
		updated, err := a.store.UpdateEdgeDomain(r.Context(), domainID, dom)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.gateway.cluster.notifyNodesList(updated.NodeIDs)
		a.auditRequest(r, "edge_domain.cert_upload", updated.Domain, "issuer="+issuer, true)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cert_issuer": issuer, "cert_not_after": notAfter})
		return
	}

	if len(parts) != 1 {
		a.writeError(w, http.StatusNotFound, "domain route not found")
		return
	}

	switch r.Method {
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetEdgeDomain(r.Context(), domainID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "domain not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load domain")
			return
		}
		var req edgeDomainMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		baseRuntime := a.gateway.cluster.globalRuntimeSettings()
		if err := validateProxyTrustOverrides(&req.Overrides); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid CDN real-IP configuration: "+err.Error())
			return
		}
		merged := req.Overrides.ApplyTo(baseRuntime)
		if _, _, err := applyRuntimeSettings(Config{}, merged); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid domain runtime overrides: "+err.Error())
			return
		}
		enabled := existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		visible := existing.PublicVisible
		if req.PublicVisible != nil {
			visible = *req.PublicVisible
		}
		tlsMode := normalizeDomainTLSMode(req.TLSMode)
		dnsMode := normalizeDomainDNSMode(req.DNSMode)
		nodeIDs := normalizeDomainNodeIDs(req.NodeIDs)
		smartCfg := existing.SmartDNS
		if req.SmartDNS != nil {
			if strings.TrimSpace(req.SmartDNS.ProfileID) != "" {
				prof, pErr := a.store.GetSmartDNSProfile(r.Context(), req.SmartDNS.ProfileID)
				if pErr != nil {
					a.writeError(w, http.StatusBadRequest, "所选智能分流方案不存在")
					return
				}
				// Apply profile directly on top of existing.SmartDNS so Provider/Zone/RoutingDomainUUID & line state are preserved when provider/zone matches!
				smartCfg = applySmartDNSProfileToDomain(prof, existing.SmartDNS, false)
				if host := normalizeDomainHostname(req.SmartDNS.RoutingDomainHost); host != "" && net.ParseIP(host) == nil && validRuleDomain(host) {
					samePrevProvider := existing.SmartDNS == nil ||
						((prof.ProviderUUID == "" || existing.SmartDNS.ProviderUUID == "" || prof.ProviderUUID == existing.SmartDNS.ProviderUUID) &&
							(prof.ZoneUUID == "" || existing.SmartDNS.ZoneUUID == "" || prof.ZoneUUID == existing.SmartDNS.ZoneUUID))
					if samePrevProvider && !strings.EqualFold(host, smartCfg.RoutingDomainHost) {
						smartCfg.RoutingDomainHost = host
						smartCfg.RoutingDomainUUID = ""
						smartCfg.CFCNAMESynced = false
						smartCfg.CFCNAMEStatus = ""
						smartCfg.CFCNAMEStatusNote = ""
						smartCfg.CFCNAMECheckedAt = 0
						for i := range smartCfg.Lines {
							smartCfg.Lines[i].AxisNowRuleUUID = ""
						}
					}
				}
			} else {
				smartCfg = normalizeEdgeDomainSmartDNS(req.SmartDNS, nodeIDs, existing.SmartDNS)
			}
		} else if dnsMode == domainDNSAxisNowSmart {
			smartCfg = normalizeEdgeDomainSmartDNS(existing.SmartDNS, nodeIDs, existing.SmartDNS)
			if smartCfg == nil {
				smartCfg = normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{}, nodeIDs, nil)
			}
		}
		if dnsMode == domainDNSAxisNowSmart && smartCfg != nil {
			nodeIDs = normalizeDomainNodeIDs(append(nodeIDs, collectSmartDNSNodeIDs(smartCfg)...))
		}
		normNodeLimits := normalizeDomainNodeLimits(req.NodeLimits, nodeIDs)
		if err := validateDomainNodeLimits(baseRuntime, req.Overrides, normNodeLimits); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		normalizedReqDomain, normErr := normalizeEdgeDomainPattern(req.Domain)
		if normErr != nil {
			a.writeError(w, http.StatusBadRequest, normErr.Error())
			return
		}
		domainRenamed := !strings.EqualFold(existing.Domain, normalizedReqDomain)
		if existing.DNSMode == domainDNSAxisNowSmart && dnsMode != domainDNSAxisNowSmart {
			if smartCfg != nil {
				cp := *smartCfg
				cp.RoutingDomainUUID = ""
				cp.RoutingDomainHost = ""
				cp.CFCNAMESynced = false
				cp.CFCNAMEStatus = ""
				cp.CFCNAMEStatusNote = ""
				cp.CFCNAMECheckedAt = 0
				linesCopy := make([]smartDNSLineRule, len(cp.Lines))
				copy(linesCopy, cp.Lines)
				for i := range linesCopy {
					linesCopy[i].AxisNowRuleUUID = ""
				}
				cp.Lines = linesCopy
				smartCfg = &cp
			}
		} else if domainRenamed && dnsMode == domainDNSAxisNowSmart && smartCfg != nil {
			cp := *smartCfg
			cp.CFCNAMESynced = false
			cp.CFCNAMEStatus = ""
			cp.CFCNAMEStatusNote = ""
			cp.CFCNAMECheckedAt = 0
			if cp.ProviderSource == "self-hosted" && strings.EqualFold(cp.RoutingDomainHost, edgeDomainBaseHost(existing.Domain)) {
				cp.RoutingDomainUUID = ""
				cp.RoutingDomainHost = ""
				linesCopy := make([]smartDNSLineRule, len(cp.Lines))
				copy(linesCopy, cp.Lines)
				for i := range linesCopy {
					linesCopy[i].AxisNowRuleUUID = ""
				}
				cp.Lines = linesCopy
			}
			smartCfg = &cp
		}
		next := existing
		next.Domain = normalizedReqDomain
		next.Name = req.Name
		next.Note = req.Note
		next.Enabled = enabled
		next.PublicVisible = visible
		next.NodeIDs = nodeIDs
		next.DNSMode = dnsMode
		next.DNSIPMode = req.DNSIPMode
		next.DNSProxied = req.DNSProxied
		next.TLSMode = tlsMode
		next.Overrides = req.Overrides
		next.NodeLimits = normNodeLimits
		next.WAFRuleIDs = req.WAFRuleIDs
		next.SmartDNS = smartCfg

		preserveCert := false
		if tlsMode == domainTLSManual {
			if strings.TrimSpace(req.CertPEM) != "" || strings.TrimSpace(req.KeyPEM) != "" {
				issuer, notAfter, err := parseAndValidateCertKeyPair(req.CertPEM, req.KeyPEM)
				if err != nil {
					a.writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				encKey, err := a.gateway.cluster.certCipher.Encrypt(strings.TrimSpace(req.KeyPEM))
				if err != nil {
					a.writeError(w, http.StatusInternalServerError, "failed to encrypt certificate key")
					return
				}
				next.CertPEM = strings.TrimSpace(req.CertPEM)
				next.KeyPEMEnc = encKey
				next.CertIssuer = issuer
				next.CertNotAfter = notAfter
				next.CertStatus = "ready"
				next.CertError = ""
				next.CertUpdatedAt = time.Now().Unix()
			} else if existing.CertPEM == "" || existing.KeyPEMEnc == "" {
				a.writeError(w, http.StatusBadRequest, "certificate PEM and private key PEM are required in manual TLS mode")
				return
			} else {
				preserveCert = true
			}
		} else if tlsMode == domainTLSExternal {
			next.CertPEM = ""
			next.KeyPEMEnc = ""
			next.CertIssuer = ""
			next.CertNotAfter = 0
			next.CertStatus = "external"
			next.CertError = ""
		} else if domainRenamed || existing.TLSMode != domainTLSAuto {
			// Domain changed or switched back to auto -> clear stale cert so it re-issues cleanly
			next.CertPEM = ""
			next.KeyPEMEnc = ""
			next.CertIssuer = ""
			next.CertNotAfter = 0
			next.CertStatus = "idle"
			next.CertError = ""
		} else {
			// Keeping auto TLS on unchanged domain: avoid overwriting concurrent ACME cert updates.
			preserveCert = true
		}

		var updated edgeDomainRecord
		if preserveCert {
			updated, err = a.store.UpdateEdgeDomainPreservingCert(r.Context(), domainID, next)
		} else {
			updated, err = a.store.UpdateEdgeDomain(r.Context(), domainID, next)
		}
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if a.gateway.axisnow != nil && (existing.DNSMode != updated.DNSMode || existing.Enabled != updated.Enabled || domainRenamed) {
			a.gateway.axisnow.clearDomainSyncCache(domainID)
		}
		if a.gateway.cloudflare != nil && (existing.DNSMode != updated.DNSMode || existing.Enabled != updated.Enabled || domainRenamed) {
			a.gateway.cloudflare.clearDomainSyncCache(domainID)
		}
		// Only clean up old Cloudflare hostname on rename if the PREVIOUS mode actually managed it in Cloudflare.
		oldDomainForCF := ""
		if domainRenamed {
			if existing.DNSMode == domainDNSCloudflareAll || existing.DNSMode == domainDNSCloudflareFailover ||
				(existing.DNSMode == domainDNSAxisNowSmart && existing.SmartDNS != nil && existing.SmartDNS.AutoCFCNAME && existing.SmartDNS.CFCNAMESynced) {
				oldDomainForCF = existing.Domain
			}
		}
		// Notify union of old and new bound nodes so removed nodes IMMEDIATELY drop the domain & cert!
		notifySet := append(append([]string(nil), existing.NodeIDs...), updated.NodeIDs...)
		a.gateway.cluster.notifyNodesList(notifySet)
		// If this domain stopped using a previously allocated AxisNow routing domain (switched to manual/CF or switched profile),
		// reclaim the old AxisNow routing domain immediately ONLY if no CF CNAME still points at it.
		// Otherwise keep it until background sync finishes cutting over CF CNAME and orphan sweep cleans it up.
		if a.gateway.axisnow != nil && existing.SmartDNS != nil && existing.SmartDNS.RoutingDomainUUID != "" {
			stillUsesSame := updated.DNSMode == domainDNSAxisNowSmart && updated.SmartDNS != nil && updated.SmartDNS.RoutingDomainUUID == existing.SmartDNS.RoutingDomainUUID
			hasCFCNAMEPointing := existing.SmartDNS.AutoCFCNAME && existing.SmartDNS.CFCNAMESynced
			if !stillUsesSame && !hasCFCNAMEPointing {
				oldCopy := existing
				a.gateway.cluster.runTracked(func() {
					cCtx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 15*time.Second)
					defer cancel()
					a.gateway.axisnow.CleanupOrphanedRoutingDomain(cCtx, oldCopy)
				})
			}
		}
		a.gateway.cluster.triggerDomainBackgroundTasks(updated, oldDomainForCF)
		a.auditRequest(r, "edge_domain.update", updated.Domain, fmt.Sprintf("nodes=%d enabled=%t dns=%s tls=%s", len(updated.NodeIDs), updated.Enabled, updated.DNSMode, updated.TLSMode), true)

		list, _ := a.gateway.cluster.ListDomainViews(r.Context())
		for _, v := range list.Domains {
			if v.ID == updated.ID {
				a.writeJSON(w, http.StatusOK, v)
				return
			}
		}
		a.writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetEdgeDomain(r.Context(), domainID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "domain not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load domain")
			return
		}
		if err := a.store.DeleteEdgeDomain(r.Context(), domainID); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete domain")
			return
		}
		a.gateway.cluster.notifyNodesList(existing.NodeIDs)
		hasAxisNowRouting := existing.DNSMode == domainDNSAxisNowSmart || (existing.SmartDNS != nil && existing.SmartDNS.RoutingDomainUUID != "")
		if hasAxisNowRouting && a.gateway.axisnow != nil {
			dCopy := existing
			a.gateway.cluster.runTracked(func() {
				ctx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 20*time.Second)
				defer cancel()
				a.gateway.axisnow.DeleteEdgeDomainSmartDNS(ctx, dCopy)
			})
		}
		if existing.DNSMode != domainDNSAxisNowSmart && existing.DNSMode != domainDNSManual && a.gateway.cloudflare != nil {
			dCopy := existing
			a.gateway.cluster.runTracked(func() {
				ctx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 15*time.Second)
				defer cancel()
				a.gateway.cloudflare.DeleteEdgeDomainDNS(ctx, dCopy)
			})
		}
		a.auditRequest(r, "edge_domain.delete", existing.Domain, "id="+domainID, true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.methodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
	}
}
