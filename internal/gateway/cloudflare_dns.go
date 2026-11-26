package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	cloudflareDNSSettingKey  = "cloudflare_dns_settings_json"
	cloudflareDefaultAPIBase = "https://api.cloudflare.com/client/v4"
)

type dnsFailoverGroup struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Hostname       string   `json:"hostname"`
	NodeIDs        []string `json:"node_ids"`
	IPMode         string   `json:"ip_mode"`
	ActiveNodeID   string   `json:"active_node_id"`
	ActiveNodeName string   `json:"active_node_name,omitempty"`
	LastSwitchedAt int64    `json:"last_switched_at"`
	LastError      string   `json:"last_error,omitempty"`
}

type cloudflareDNSSettings struct {
	Enabled        bool               `json:"enabled"`
	TokenSet       bool               `json:"token_set"`
	ZoneID         string             `json:"zone_id"`
	RootDomain     string             `json:"root_domain"`
	Proxied        bool               `json:"proxied"`
	TTL            int                `json:"ttl"`
	FailoverGroups []dnsFailoverGroup `json:"failover_groups"`
	LastSyncAt     int64              `json:"last_sync_at"`
	LastError      string             `json:"last_error,omitempty"`
}

type cloudflareDNSStored struct {
	cloudflareDNSSettings
	EncryptedToken string `json:"encrypted_token,omitempty"`
}

type cloudflareDNSManager struct {
	store   *telemetryStore
	gateway *Gateway
	cipher  *tokenCipher
	client  *http.Client
	apiBase string
	mu      sync.Mutex
	cfgMu   sync.Mutex

	syncHashMu       sync.Mutex
	lastDomainHash   map[string]string
	lastDomainSyncAt map[string]time.Time
	lastGroupHash    map[string]string
	lastGroupSyncAt  map[string]time.Time
}

func newCloudflareDNSManager(store *telemetryStore, gateway *Gateway, secret []byte) (*cloudflareDNSManager, error) {
	cipher, err := newScopedTokenCipher(secret, "cloudflare-dns")
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &cloudflareDNSManager{
		store:            store,
		gateway:          gateway,
		cipher:           cipher,
		client:           &http.Client{Transport: transport, Timeout: 15 * time.Second},
		apiBase:          cloudflareDefaultAPIBase,
		lastDomainHash:   make(map[string]string),
		lastDomainSyncAt: make(map[string]time.Time),
		lastGroupHash:    make(map[string]string),
		lastGroupSyncAt:  make(map[string]time.Time),
	}, nil
}

func (m *cloudflareDNSManager) clearSyncCache() {
	if m == nil {
		return
	}
	m.syncHashMu.Lock()
	clear(m.lastDomainHash)
	clear(m.lastDomainSyncAt)
	clear(m.lastGroupHash)
	clear(m.lastGroupSyncAt)
	m.syncHashMu.Unlock()
}

func (m *cloudflareDNSManager) updateSyncStatus(ctx context.Context, lastSyncAt int64, lastErr string) {
	if m == nil || m.store == nil {
		return
	}
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	fresh := m.store.LoadCloudflareDNS(ctx)
	if lastSyncAt > 0 {
		fresh.LastSyncAt = lastSyncAt
	}
	fresh.LastError = truncateRunes(lastErr, 200)
	_ = m.store.SaveCloudflareDNS(ctx, fresh)
}

func (m *cloudflareDNSManager) Close() {
	if m != nil && m.client != nil {
		m.client.CloseIdleConnections()
	}
}

func defaultCloudflareDNSStored() cloudflareDNSStored {
	return cloudflareDNSStored{
		cloudflareDNSSettings: cloudflareDNSSettings{
			TTL:            60,
			FailoverGroups: []dnsFailoverGroup{},
		},
	}
}

func (s *telemetryStore) LoadCloudflareDNS(ctx context.Context) cloudflareDNSStored {
	if s == nil {
		return defaultCloudflareDNSStored()
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, cloudflareDNSSettingKey).Scan(&raw)
	if err != nil || strings.TrimSpace(raw) == "" {
		return defaultCloudflareDNSStored()
	}
	var loaded cloudflareDNSStored
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		return defaultCloudflareDNSStored()
	}
	if loaded.FailoverGroups == nil {
		loaded.FailoverGroups = []dnsFailoverGroup{}
	}
	if loaded.TTL <= 0 {
		loaded.TTL = 60
	}
	loaded.TokenSet = loaded.EncryptedToken != ""
	return loaded
}

func (s *telemetryStore) SaveCloudflareDNS(ctx context.Context, stored cloudflareDNSStored) error {
	if stored.FailoverGroups == nil {
		stored.FailoverGroups = []dnsFailoverGroup{}
	}
	stored.TokenSet = stored.EncryptedToken != ""
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		cloudflareDNSSettingKey, string(data), time.Now().Unix(),
	)
	return err
}

func normalizeDomainHostname(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil {
			host = strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		}
	}
	host = strings.Trim(host, ".")
	return host
}

func hostnameBelongsToRoot(hostname, rootDomain string) bool {
	hostname = normalizeDomainHostname(hostname)
	rootDomain = normalizeDomainHostname(rootDomain)
	if hostname == "" || rootDomain == "" {
		return false
	}
	return hostname == rootDomain || strings.HasSuffix(hostname, "."+rootDomain)
}

func normalizeCloudflareDNSTTL(ttl int) int {
	if ttl == 1 {
		return 1 // Cloudflare Auto TTL
	}
	if ttl < 60 {
		return 60
	}
	if ttl > 86400 {
		return 86400
	}
	return ttl
}

func normalizeFailoverGroups(groups []dnsFailoverGroup, rootDomain string, existing map[string]dnsFailoverGroup) ([]dnsFailoverGroup, error) {
	out := make([]dnsFailoverGroup, 0, len(groups))
	seenHosts := make(map[string]struct{}, len(groups))
	for i, g := range groups {
		if len(out) >= 32 {
			return nil, errors.New("too many failover groups (max 32)")
		}
		hostname := normalizeDomainHostname(g.Hostname)
		if hostname == "" || net.ParseIP(hostname) != nil || !validRuleDomain(hostname) {
			return nil, fmt.Errorf("failover group #%d has invalid hostname %q", i+1, g.Hostname)
		}
		if rootDomain != "" && !hostnameBelongsToRoot(hostname, rootDomain) {
			return nil, fmt.Errorf("failover hostname %q must belong to root domain %q", hostname, rootDomain)
		}
		if _, dup := seenHosts[hostname]; dup {
			return nil, fmt.Errorf("duplicate failover hostname %q", hostname)
		}
		seenHosts[hostname] = struct{}{}

		name := truncateRunes(strings.TrimSpace(g.Name), 64)
		if name == "" {
			name = hostname
		}
		id := strings.TrimSpace(g.ID)
		if id == "" {
			if raw, err := generateRandomHex(6); err == nil {
				id = "fg_" + raw
			} else {
				id = fmt.Sprintf("fg_%d", i+1)
			}
		}
		seenNodes := make(map[string]struct{}, len(g.NodeIDs))
		nodeIDs := make([]string, 0, len(g.NodeIDs))
		for _, nid := range g.NodeIDs {
			nid = strings.TrimSpace(nid)
			if nid == "" {
				continue
			}
			if _, dup := seenNodes[nid]; dup {
				continue
			}
			seenNodes[nid] = struct{}{}
			nodeIDs = append(nodeIDs, nid)
		}
		if len(nodeIDs) == 0 {
			return nil, fmt.Errorf("failover group %q must include at least one node", name)
		}
		item := dnsFailoverGroup{
			ID:       id,
			Name:     name,
			Hostname: hostname,
			NodeIDs:  nodeIDs,
			IPMode:   normalizeDNSIPMode(g.IPMode),
		}
		if prev, ok := existing[id]; ok {
			item.ActiveNodeID = prev.ActiveNodeID
			item.ActiveNodeName = prev.ActiveNodeName
			item.LastSwitchedAt = prev.LastSwitchedAt
			item.LastError = prev.LastError
		}
		out = append(out, item)
	}
	return out, nil
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type cfDNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (m *cloudflareDNSManager) cfDo(ctx context.Context, token, method, path string, reqBody any, dst any) error {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(m.apiBase, "/")+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return err
	}
	var env cfAPIResponse
	if err := json.Unmarshal(rawResp, &env); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("cloudflare API HTTP %d", resp.StatusCode)
		}
		return err
	}
	if !env.Success || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(env.Errors) > 0 {
			return fmt.Errorf("cloudflare API: %s (code %d)", env.Errors[0].Message, env.Errors[0].Code)
		}
		return fmt.Errorf("cloudflare API HTTP %d", resp.StatusCode)
	}
	if dst != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, dst); err != nil {
			return err
		}
	}
	return nil
}

func (m *cloudflareDNSManager) resolveZone(ctx context.Context, token, rootDomain, zoneID string) (cfZone, error) {
	zoneID = strings.TrimSpace(zoneID)
	rootDomain = normalizeDomainHostname(rootDomain)
	if zoneID != "" {
		var z cfZone
		if err := m.cfDo(ctx, token, http.MethodGet, "/zones/"+url.PathEscape(zoneID), nil, &z); err != nil {
			return cfZone{}, err
		}
		return z, nil
	}
	if rootDomain == "" {
		return cfZone{}, errors.New("root_domain or zone_id is required")
	}
	var zones []cfZone
	if err := m.cfDo(ctx, token, http.MethodGet, "/zones?name="+url.QueryEscape(rootDomain), nil, &zones); err != nil {
		return cfZone{}, err
	}
	if len(zones) == 0 {
		return cfZone{}, fmt.Errorf("cloudflare zone not found for %q", rootDomain)
	}
	return zones[0], nil
}

func (m *cloudflareDNSManager) listRecords(ctx context.Context, token, zoneID, recordType, name string) ([]cfDNSRecord, error) {
	q := url.Values{}
	q.Set("type", recordType)
	q.Set("name", name)
	var records []cfDNSRecord
	if err := m.cfDo(ctx, token, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records?"+q.Encode(), nil, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (m *cloudflareDNSManager) upsertRecord(ctx context.Context, token, zoneID, recordType, name, content string, ttl int, proxied bool) (bool, error) {
	existing, err := m.listRecords(ctx, token, zoneID, recordType, name)
	if err != nil {
		return false, err
	}
	desired := cfDNSRecord{
		Type:    recordType,
		Name:    name,
		Content: content,
		TTL:     ttl,
		Proxied: proxied,
	}
	if len(existing) == 1 && existing[0].Content == content && existing[0].Proxied == proxied && (proxied || existing[0].TTL == ttl) {
		return false, nil
	}
	if len(existing) > 0 {
		if err := m.cfDo(ctx, token, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(existing[0].ID), desired, nil); err != nil {
			return false, err
		}
		for _, extra := range existing[1:] {
			_ = m.cfDo(ctx, token, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(extra.ID), nil, nil)
		}
		return true, nil
	}
	if err := m.cfDo(ctx, token, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", desired, nil); err != nil {
		return false, err
	}
	return true, nil
}

func (m *cloudflareDNSManager) deleteRecords(ctx context.Context, token, zoneID, recordType, name string) error {
	existing, err := m.listRecords(ctx, token, zoneID, recordType, name)
	if err != nil {
		return err
	}
	for _, rec := range existing {
		if err := m.cfDo(ctx, token, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(rec.ID), nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (m *cloudflareDNSManager) CreateTXTRecord(ctx context.Context, token, zoneID, name, content string) (string, error) {
	desired := cfDNSRecord{
		Type:    "TXT",
		Name:    name,
		Content: fmt.Sprintf("%q", content),
		TTL:     60,
		Proxied: false,
	}
	var created cfDNSRecord
	if err := m.cfDo(ctx, token, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", desired, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

func (m *cloudflareDNSManager) DeleteRecordByID(ctx context.Context, token, zoneID, recordID string) error {
	if strings.TrimSpace(recordID) == "" {
		return nil
	}
	return m.cfDo(ctx, token, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil)
}

func (m *cloudflareDNSManager) syncHostMultiIPs(ctx context.Context, token, zoneID, hostname string, v4s, v6s []string, ipMode string, ttl int, proxied bool) error {
	mode := normalizeDNSIPMode(ipMode)
	if mode == "ipv4" {
		v6s = nil
	} else if mode == "ipv6" {
		v4s = nil
	}
	if len(v4s) == 0 && len(v6s) == 0 {
		return errors.New("no healthy bound node has a usable public IP")
	}
	reconcileType := func(recType string, want []string) error {
		existing, err := m.listRecords(ctx, token, zoneID, recType, hostname)
		if err != nil {
			return err
		}
		wantSet := make(map[string]struct{}, len(want))
		for _, ip := range want {
			wantSet[ip] = struct{}{}
		}
		seen := make(map[string]bool, len(want))
		var toDelete []string
		for _, rec := range existing {
			if _, ok := wantSet[rec.Content]; !ok || seen[rec.Content] {
				toDelete = append(toDelete, rec.ID)
				continue
			}
			seen[rec.Content] = true
			if rec.Proxied != proxied || (!proxied && rec.TTL != ttl) {
				desired := cfDNSRecord{Type: recType, Name: hostname, Content: rec.Content, TTL: ttl, Proxied: proxied}
				if err := m.cfDo(ctx, token, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(rec.ID), desired, nil); err != nil {
					return err
				}
			}
		}
		// Create missing desired records BEFORE removing stale ones to avoid a zero-record DNS blackout.
		for _, ip := range want {
			if seen[ip] {
				continue
			}
			desired := cfDNSRecord{Type: recType, Name: hostname, Content: ip, TTL: ttl, Proxied: proxied}
			if err := m.cfDo(ctx, token, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", desired, nil); err != nil {
				return err
			}
		}
		for _, id := range toDelete {
			if err := m.DeleteRecordByID(ctx, token, zoneID, id); err != nil {
				return err
			}
		}
		return nil
	}
	// Reconcile non-empty desired record types BEFORE clearing emptied record types so switching A <-> AAAA never causes a blackout.
	if len(v4s) > 0 {
		if err := reconcileType("A", v4s); err != nil {
			return err
		}
	}
	if len(v6s) > 0 {
		if err := reconcileType("AAAA", v6s); err != nil {
			return err
		}
	}
	if len(v4s) == 0 {
		if err := reconcileType("A", nil); err != nil {
			return err
		}
	}
	if len(v6s) == 0 {
		if err := reconcileType("AAAA", nil); err != nil {
			return err
		}
	}
	return nil
}

func (m *cloudflareDNSManager) clearDomainSyncCache(domainID string) {
	if m == nil || domainID == "" {
		return
	}
	m.syncHashMu.Lock()
	delete(m.lastDomainHash, domainID)
	delete(m.lastDomainSyncAt, domainID)
	m.syncHashMu.Unlock()
}

func (m *cloudflareDNSManager) SyncEdgeDomainDNS(ctx context.Context, dom edgeDomainRecord, oldDomain string, now time.Time) error {
	return m.syncEdgeDomainDNS(ctx, dom, oldDomain, now, true)
}

func (m *cloudflareDNSManager) syncEdgeDomainDNS(ctx context.Context, dom edgeDomainRecord, oldDomain string, now time.Time, force bool) error {
	if m == nil || m.gateway == nil || m.gateway.cluster == nil {
		return nil
	}
	m.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			m.mu.Unlock()
		}
	}
	defer unlock()
	if latest, getErr := m.store.GetEdgeDomain(ctx, dom.ID); getErr == nil {
		dom = latest
	} else if errors.Is(getErr, sql.ErrNoRows) {
		return nil
	}
	var failoverAlert []string
	stored, token, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return err
	}
	// Never delete Cloudflare records for manual or disabled domains (including on rename).
	if dom.DNSMode == domainDNSManual || !dom.Enabled {
		return nil
	}
	oldHost := strings.ToLower(strings.TrimSpace(oldDomain))
	if oldHost != "" && oldHost != dom.Domain && hostnameBelongsToRoot(edgeDomainBaseHost(oldHost), stored.RootDomain) {
		if dom.DNSMode != domainDNSAxisNowSmart || (dom.SmartDNS != nil && dom.SmartDNS.AutoCFCNAME) {
			_ = m.deleteRecords(ctx, token, stored.ZoneID, "A", oldHost)
			_ = m.deleteRecords(ctx, token, stored.ZoneID, "AAAA", oldHost)
			_ = m.deleteRecords(ctx, token, stored.ZoneID, "CNAME", oldHost)
		}
	}
	if dom.DNSMode == domainDNSAxisNowSmart {
		return nil
	}
	if !hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), stored.RootDomain) {
		err := fmt.Errorf("domain %q does not belong to root domain %q", dom.Domain, stored.RootDomain)
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, dom.DNSActiveNodeID, dom.DNSLastSyncAt, err.Error())
		return err
	}

	nodes, err := m.store.ListEdgeNodes(ctx)
	if err != nil {
		return err
	}
	nodeMap := make(map[string]edgeNodeRecord, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	healthyNodes := make([]edgeNodeRecord, 0, len(dom.NodeIDs))
	for _, nid := range dom.NodeIDs {
		cand, ok := nodeMap[nid]
		if !ok || cand.TokenHash == "" {
			continue
		}
		status, _ := m.gateway.cluster.nodeStatus(cand, now)
		if status != edgeNodeStatusOnline {
			continue
		}
		if cand.MonthlyQuotaGB > 0 && cand.QuotaAutoDrain {
			quotaBytes := monthlyQuotaGBToBytes(cand.MonthlyQuotaGB)
			_, startUnix, _ := billingCycleWindow(now, cand.QuotaResetDay)
			used, uErr := m.store.NodeCycleTrafficUsage(ctx, cand.ID, startUnix, cand.QuotaDirection)
			if uErr == nil && quotaBytes > 0 && used >= quotaBytes {
				continue
			}
		}
		v4, v6 := effectiveNodeIPs(cand)
		wantV4, wantV6 := selectRecordIPs(v4, v6, dom.DNSIPMode)
		if wantV4 == "" && wantV6 == "" {
			continue
		}
		healthyNodes = append(healthyNodes, cand)
	}

	if len(healthyNodes) == 0 {
		msg := "没有满足条件的健康在线绑定节点"
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, "", dom.DNSLastSyncAt, msg)
		return errors.New(msg)
	}

	proxied := stored.Proxied
	if dom.DNSProxied == domainProxiedOn {
		proxied = true
	} else if dom.DNSProxied == domainProxiedOff {
		proxied = false
	}
	ttl := normalizeCloudflareDNSTTL(stored.TTL)

	// Compute desired DNS state fingerprint so idle 15s monitor cycles skip redundant Cloudflare API calls.
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s|%t|%d|", dom.Domain, dom.DNSMode, dom.DNSIPMode, proxied, ttl)
	if dom.DNSMode == domainDNSCloudflareFailover {
		v4, v6 := effectiveNodeIPs(healthyNodes[0])
		_, _ = fmt.Fprintf(h, "%s:%s:%s", healthyNodes[0].ID, v4, v6)
	} else {
		for _, n := range healthyNodes {
			v4, v6 := effectiveNodeIPs(n)
			_, _ = fmt.Fprintf(h, "%s:%s:%s;", n.ID, v4, v6)
		}
	}
	desiredHash := hex.EncodeToString(h.Sum(nil))
	if !force && dom.DNSLastError == "" && oldHost == "" {
		m.syncHashMu.Lock()
		prevHash := m.lastDomainHash[dom.ID]
		prevAt := m.lastDomainSyncAt[dom.ID]
		m.syncHashMu.Unlock()
		if prevHash == desiredHash && !prevAt.IsZero() && now.Sub(prevAt) < dnsReconcileInterval {
			return nil
		}
	}

	// Clear any stale CNAME (e.g. from previous axisnow_smart mode) before writing A/AAAA records
	if err := m.deleteRecords(ctx, token, stored.ZoneID, "CNAME", dom.Domain); err != nil {
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, dom.DNSActiveNodeID, dom.DNSLastSyncAt, err.Error())
		return err
	}

	if dom.DNSMode == domainDNSCloudflareFailover {
		winner := healthyNodes[0]
		v4, v6 := effectiveNodeIPs(winner)
		if _, syncErr := m.syncHostIPs(ctx, token, stored.ZoneID, dom.Domain, v4, v6, dom.DNSIPMode, ttl, proxied); syncErr != nil {
			_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, dom.DNSActiveNodeID, dom.DNSLastSyncAt, syncErr.Error())
			return syncErr
		}
		prevID := dom.DNSActiveNodeID
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, winner.ID, now.Unix(), "")
		if prevID != "" && prevID != winner.ID {
			prevName := prevID
			if prevRec, ok := nodeMap[prevID]; ok {
				prevName = prevRec.Name
			}
			ipLabel := strings.Join(nonEmptyStrings(v4, v6), " / ")
			m.store.RecordAudit(ctx, auditEntry{
				Username: "system",
				Action:   "dns.failover",
				Resource: dom.Domain,
				Detail:   fmt.Sprintf("%s -> %s (%s)", prevName, winner.Name, ipLabel),
				Success:  true,
			})
			if m.gateway.telegram != nil {
				failoverAlert = []string{
					fmt.Sprintf("域名：%s (%s)", dom.Domain, dom.Name),
					fmt.Sprintf("原节点：%s", prevName),
					fmt.Sprintf("新节点：%s", winner.Name),
					fmt.Sprintf("指向 IP：%s", ipLabel),
				}
			}
		}
	} else {
		var v4s, v6s []string
		seenV4 := map[string]struct{}{}
		seenV6 := map[string]struct{}{}
		for _, n := range healthyNodes {
			v4, v6 := effectiveNodeIPs(n)
			if v4 != "" {
				if _, dup := seenV4[v4]; !dup {
					seenV4[v4] = struct{}{}
					v4s = append(v4s, v4)
				}
			}
			if v6 != "" {
				if _, dup := seenV6[v6]; !dup {
					seenV6[v6] = struct{}{}
					v6s = append(v6s, v6)
				}
			}
		}
		if syncErr := m.syncHostMultiIPs(ctx, token, stored.ZoneID, dom.Domain, v4s, v6s, dom.DNSIPMode, ttl, proxied); syncErr != nil {
			_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, "", dom.DNSLastSyncAt, syncErr.Error())
			return syncErr
		}
		activeID := ""
		if len(healthyNodes) == 1 {
			activeID = healthyNodes[0].ID
		}
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, activeID, now.Unix(), "")
	}

	m.syncHashMu.Lock()
	m.lastDomainHash[dom.ID] = desiredHash
	m.lastDomainSyncAt[dom.ID] = now
	m.syncHashMu.Unlock()
	m.updateSyncStatus(ctx, now.Unix(), "")
	unlock()
	if len(failoverAlert) > 0 && m.gateway.telegram != nil {
		alertCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = m.gateway.telegram.SendAlert(alertCtx, "dns_failover", "域名故障自动切线", failoverAlert)
		cancel()
	}
	return nil
}

func (m *cloudflareDNSManager) SyncEdgeDomainCNAME(ctx context.Context, domainID, domainHost, targetHost string) error {
	if m == nil {
		return errors.New("cloudflare DNS manager unavailable")
	}
	targetHost = normalizeDomainHostname(targetHost)
	domainHost = strings.ToLower(strings.TrimSpace(domainHost))
	if domainHost == "" || targetHost == "" {
		return errors.New("domain and CNAME target are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, err := m.activeCredentials(ctx)
	if err != nil {
		return err
	}
	if !stored.Enabled || token == "" {
		return errors.New("Cloudflare DNS 未启用，请先在设置中配置 Cloudflare API Token")
	}
	if !hostnameBelongsToRoot(edgeDomainBaseHost(domainHost), stored.RootDomain) {
		return fmt.Errorf("域名 %q 不属于 Cloudflare 根域名 %q", domainHost, stored.RootDomain)
	}
	ttl := normalizeCloudflareDNSTTL(stored.TTL)
	// Fast path: if the desired gray-cloud CNAME already exists, skip redundant delete/upsert calls.
	if existingCNAMEs, lErr := m.listRecords(ctx, token, stored.ZoneID, "CNAME", domainHost); lErr == nil && len(existingCNAMEs) == 1 {
		rec := existingCNAMEs[0]
		if strings.EqualFold(normalizeDomainHostname(rec.Content), targetHost) && !rec.Proxied && rec.TTL == ttl {
			m.clearDomainSyncCache(domainID)
			return nil
		}
	}
	// DNS forbids CNAME coexisting with A/AAAA on the same hostname
	if err := m.deleteRecords(ctx, token, stored.ZoneID, "A", domainHost); err != nil {
		return err
	}
	if err := m.deleteRecords(ctx, token, stored.ZoneID, "AAAA", domainHost); err != nil {
		return err
	}
	// Always gray-cloud (proxied=false) so AxisNow Geo/ISP routing returns the real edge node IP directly
	_, err = m.upsertRecord(ctx, token, stored.ZoneID, "CNAME", domainHost, targetHost, ttl, false)
	if err == nil {
		m.clearDomainSyncCache(domainID)
	}
	return err
}

func (m *cloudflareDNSManager) DeleteEdgeDomainDNS(ctx context.Context, dom edgeDomainRecord) {
	if m == nil || dom.DNSMode == domainDNSManual {
		return
	}
	m.syncHashMu.Lock()
	delete(m.lastDomainHash, dom.ID)
	delete(m.lastDomainSyncAt, dom.ID)
	m.syncHashMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return
	}
	if !hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), stored.RootDomain) {
		return
	}
	_ = m.deleteRecords(ctx, token, stored.ZoneID, "A", dom.Domain)
	_ = m.deleteRecords(ctx, token, stored.ZoneID, "AAAA", dom.Domain)
	_ = m.deleteRecords(ctx, token, stored.ZoneID, "CNAME", dom.Domain)
}

func (m *cloudflareDNSManager) EvaluateEdgeDomainsDNS(ctx context.Context, now time.Time) (int, error) {
	return m.evaluateEdgeDomainsDNS(ctx, now, false)
}

func (m *cloudflareDNSManager) evaluateEdgeDomainsDNS(ctx context.Context, now time.Time, force bool) (int, error) {
	if m == nil {
		return 0, nil
	}
	stored := m.store.LoadCloudflareDNS(ctx)
	if !stored.Enabled || stored.EncryptedToken == "" {
		return 0, nil
	}
	domains, err := m.store.ListEdgeDomains(ctx)
	if err != nil {
		return 0, err
	}
	synced := 0
	var firstErr error
	for _, dom := range domains {
		if !dom.Enabled || dom.DNSMode == domainDNSManual || dom.DNSMode == domainDNSAxisNowSmart || len(dom.NodeIDs) == 0 {
			continue
		}
		if err := m.syncEdgeDomainDNS(ctx, dom, "", now, force); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			synced++
		}
	}
	return synced, firstErr
}

func selectRecordIPs(ipv4, ipv6, ipMode string) (wantV4, wantV6 string) {
	switch normalizeDNSIPMode(ipMode) {
	case "ipv4":
		return ipv4, ""
	case "ipv6":
		return "", ipv6
	case "dual", "auto":
		return ipv4, ipv6
	default:
		return ipv4, ipv6
	}
}

func (m *cloudflareDNSManager) syncHostIPs(ctx context.Context, token, zoneID, hostname, ipv4, ipv6, ipMode string, ttl int, proxied bool) (bool, error) {
	wantV4, wantV6 := selectRecordIPs(ipv4, ipv6, ipMode)
	if wantV4 == "" && wantV6 == "" {
		return false, errors.New("node has no public IPv4 or IPv6 available")
	}
	changed := false
	// Upsert non-empty desired record types BEFORE deleting emptied types to prevent zero-record blackouts.
	if wantV4 != "" {
		c, err := m.upsertRecord(ctx, token, zoneID, "A", hostname, wantV4, ttl, proxied)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}
	if wantV6 != "" {
		c, err := m.upsertRecord(ctx, token, zoneID, "AAAA", hostname, wantV6, ttl, proxied)
		if err != nil {
			return changed, err
		}
		changed = changed || c
	}
	if wantV4 == "" {
		if err := m.deleteRecords(ctx, token, zoneID, "A", hostname); err != nil {
			return changed, err
		}
	}
	if wantV6 == "" {
		if err := m.deleteRecords(ctx, token, zoneID, "AAAA", hostname); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func (m *cloudflareDNSManager) activeCredentials(ctx context.Context) (cloudflareDNSStored, string, error) {
	m.cfgMu.Lock()
	stored := m.store.LoadCloudflareDNS(ctx)
	m.cfgMu.Unlock()
	if !stored.Enabled {
		return stored, "", nil
	}
	if stored.EncryptedToken == "" {
		return stored, "", errors.New("cloudflare API token not configured")
	}
	token, err := m.cipher.Decrypt(stored.EncryptedToken)
	if err != nil || strings.TrimSpace(token) == "" {
		return stored, "", errors.New("cloudflare API token unavailable")
	}
	if (strings.TrimSpace(stored.ZoneID) == "" && strings.TrimSpace(stored.RootDomain) != "") ||
		(strings.TrimSpace(stored.ZoneID) != "" && strings.TrimSpace(stored.RootDomain) == "") {
		zone, err := m.resolveZone(ctx, token, stored.RootDomain, stored.ZoneID)
		if err != nil {
			return stored, "", err
		}
		m.cfgMu.Lock()
		fresh := m.store.LoadCloudflareDNS(ctx)
		if fresh.ZoneID == "" {
			fresh.ZoneID = zone.ID
		}
		if fresh.RootDomain == "" {
			fresh.RootDomain = normalizeDomainHostname(zone.Name)
		}
		_ = m.store.SaveCloudflareDNS(ctx, fresh)
		stored.ZoneID = fresh.ZoneID
		stored.RootDomain = fresh.RootDomain
		m.cfgMu.Unlock()
	}
	if strings.TrimSpace(stored.ZoneID) == "" {
		return stored, "", errors.New("cloudflare zone_id is required")
	}
	return stored, token, nil
}

func (m *cloudflareDNSManager) SyncNodeDNS(ctx context.Context, node edgeNodeRecord, oldPublicURL string) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return err
	}
	newHost := normalizeDomainHostname(node.PublicURL)
	oldHost := normalizeDomainHostname(oldPublicURL)
	if oldHost != "" && oldHost != newHost && hostnameBelongsToRoot(oldHost, stored.RootDomain) {
		_ = m.deleteRecords(ctx, token, stored.ZoneID, "A", oldHost)
		_ = m.deleteRecords(ctx, token, stored.ZoneID, "AAAA", oldHost)
	}
	if !node.DNSSyncEnabled || newHost == "" || !hostnameBelongsToRoot(newHost, stored.RootDomain) {
		return nil
	}
	ipv4, ipv6 := effectiveNodeIPs(node)
	if ipv4 == "" && ipv6 == "" {
		return nil
	}
	ttl := normalizeCloudflareDNSTTL(stored.TTL)
	_, err = m.syncHostIPs(ctx, token, stored.ZoneID, newHost, ipv4, ipv6, node.DNSIPMode, ttl, stored.Proxied)
	if err != nil {
		m.updateSyncStatus(ctx, 0, err.Error())
		return err
	}
	m.updateSyncStatus(ctx, time.Now().Unix(), "")
	return nil
}

func (m *cloudflareDNSManager) DeleteNodeDNS(ctx context.Context, node edgeNodeRecord) {
	if m == nil || !node.DNSSyncEnabled {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return
	}
	host := normalizeDomainHostname(node.PublicURL)
	if host == "" || !hostnameBelongsToRoot(host, stored.RootDomain) {
		return
	}
	_ = m.deleteRecords(ctx, token, stored.ZoneID, "A", host)
	_ = m.deleteRecords(ctx, token, stored.ZoneID, "AAAA", host)
}

func (m *cloudflareDNSManager) EvaluateFailoverGroups(ctx context.Context, now time.Time) (int, error) {
	return m.evaluateFailoverGroups(ctx, now, false)
}

func (m *cloudflareDNSManager) evaluateFailoverGroups(ctx context.Context, now time.Time, force bool) (int, error) {
	if m == nil || m.gateway == nil || m.gateway.cluster == nil {
		return 0, nil
	}
	m.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			m.mu.Unlock()
		}
	}
	defer unlock()
	var queuedAlerts [][]string

	stored, token, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" || len(stored.FailoverGroups) == 0 {
		return 0, err
	}
	nodes, err := m.store.ListEdgeNodes(ctx)
	if err != nil {
		return 0, err
	}
	nodeMap := make(map[string]edgeNodeRecord, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	ttl := normalizeCloudflareDNSTTL(stored.TTL)
	dirty := false
	synced := 0
	var firstErr error
	groupUpdates := make(map[string]dnsFailoverGroup)

	for idx := range stored.FailoverGroups {
		group := &stored.FailoverGroups[idx]
		var winner *edgeNodeRecord
		for _, candidateID := range group.NodeIDs {
			cand, ok := nodeMap[candidateID]
			if !ok || cand.TokenHash == "" {
				continue
			}
			status, _ := m.gateway.cluster.nodeStatus(cand, now)
			if status != edgeNodeStatusOnline {
				continue
			}
			if cand.MonthlyQuotaGB > 0 && cand.QuotaAutoDrain {
				quotaBytes := monthlyQuotaGBToBytes(cand.MonthlyQuotaGB)
				_, startUnix, _ := billingCycleWindow(now, cand.QuotaResetDay)
				used, usageErr := m.store.NodeCycleTrafficUsage(ctx, cand.ID, startUnix, cand.QuotaDirection)
				if usageErr == nil && quotaBytes > 0 && used >= quotaBytes {
					continue
				}
			}
			ipv4, ipv6 := effectiveNodeIPs(cand)
			wantV4, wantV6 := selectRecordIPs(ipv4, ipv6, group.IPMode)
			if wantV4 == "" && wantV6 == "" {
				continue
			}
			copyCand := cand
			winner = &copyCand
			break
		}

		if winner == nil {
			msg := "没有满足条件的健康在线节点"
			if group.LastError != msg {
				group.LastError = msg
				groupUpdates[group.ID] = *group
				dirty = true
			}
			continue
		}

		ipv4, ipv6 := effectiveNodeIPs(*winner)
		desiredHash := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%d", group.Hostname, group.IPMode, winner.ID, ipv4, ipv6, stored.Proxied, ttl)
		if !force && group.LastError == "" && group.ActiveNodeID == winner.ID {
			m.syncHashMu.Lock()
			prevHash := m.lastGroupHash[group.ID]
			prevAt := m.lastGroupSyncAt[group.ID]
			m.syncHashMu.Unlock()
			if prevHash == desiredHash && !prevAt.IsZero() && now.Sub(prevAt) < dnsReconcileInterval {
				continue
			}
		}

		changed, syncErr := m.syncHostIPs(ctx, token, stored.ZoneID, group.Hostname, ipv4, ipv6, group.IPMode, ttl, stored.Proxied)
		if syncErr != nil {
			errMsg := truncateRunes(syncErr.Error(), 200)
			if group.LastError != errMsg {
				group.LastError = errMsg
				groupUpdates[group.ID] = *group
				dirty = true
			}
			if firstErr == nil {
				firstErr = syncErr
			}
			continue
		}
		m.syncHashMu.Lock()
		m.lastGroupHash[group.ID] = desiredHash
		m.lastGroupSyncAt[group.ID] = now
		m.syncHashMu.Unlock()
		synced++
		prevNodeID := group.ActiveNodeID
		prevNodeName := group.ActiveNodeName
		if prevNodeName == "" && prevNodeID != "" {
			if prevRec, ok := nodeMap[prevNodeID]; ok {
				prevNodeName = prevRec.Name
			} else {
				prevNodeName = prevNodeID
			}
		}

		switched := prevNodeID != winner.ID
		if switched || changed || group.LastError != "" || group.ActiveNodeName != winner.Name {
			group.ActiveNodeID = winner.ID
			group.ActiveNodeName = winner.Name
			group.LastError = ""
			if switched {
				group.LastSwitchedAt = now.Unix()
			}
			groupUpdates[group.ID] = *group
			dirty = true
		}

		if switched {
			ipLabel := strings.TrimSpace(strings.Join(nonEmptyStrings(ipv4, ipv6), " / "))
			detail := fmt.Sprintf("group=%s host=%s %s -> %s (%s)", group.Name, group.Hostname, prevNodeName, winner.Name, ipLabel)
			m.store.RecordAudit(ctx, auditEntry{
				Username: "system",
				Action:   "dns.failover",
				Resource: group.Hostname,
				Detail:   detail,
				Success:  true,
			})
			if prevNodeID != "" && m.gateway.telegram != nil {
				queuedAlerts = append(queuedAlerts, []string{
					fmt.Sprintf("切线组：%s", group.Name),
					fmt.Sprintf("域名：%s", group.Hostname),
					fmt.Sprintf("原节点：%s", prevNodeName),
					fmt.Sprintf("新节点：%s", winner.Name),
					fmt.Sprintf("指向 IP：%s", ipLabel),
				})
			}
		}
	}

	if dirty || synced > 0 {
		// Merge ONLY runtime group status & sync timestamp onto fresh stored config to prevent
		// overwriting concurrent admin token/settings changes.
		m.cfgMu.Lock()
		fresh := m.store.LoadCloudflareDNS(ctx)
		for i := range fresh.FailoverGroups {
			if upd, ok := groupUpdates[fresh.FailoverGroups[i].ID]; ok {
				fresh.FailoverGroups[i].ActiveNodeID = upd.ActiveNodeID
				fresh.FailoverGroups[i].ActiveNodeName = upd.ActiveNodeName
				fresh.FailoverGroups[i].LastSwitchedAt = upd.LastSwitchedAt
				fresh.FailoverGroups[i].LastError = upd.LastError
			}
		}
		fresh.LastSyncAt = now.Unix()
		if firstErr != nil {
			fresh.LastError = truncateRunes(firstErr.Error(), 200)
		} else {
			fresh.LastError = ""
		}
		_ = m.store.SaveCloudflareDNS(ctx, fresh)
		m.cfgMu.Unlock()
	}
	unlock()
	if len(queuedAlerts) > 0 && m.gateway.telegram != nil {
		for _, lines := range queuedAlerts {
			alertCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = m.gateway.telegram.SendAlert(alertCtx, "dns_failover", "DNS 故障自动切线", lines)
			cancel()
		}
	}
	return synced, firstErr
}

func nonEmptyStrings(items ...string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (m *cloudflareDNSManager) SyncAll(ctx context.Context) (syncedNodes int, syncedGroups int, err error) {
	if m == nil {
		return 0, 0, errors.New("cloudflare DNS manager unavailable")
	}
	stored := m.store.LoadCloudflareDNS(ctx)
	if !stored.Enabled {
		return 0, 0, errors.New("cloudflare DNS integration is disabled")
	}
	nodes, err := m.store.ListEdgeNodes(ctx)
	if err != nil {
		return 0, 0, err
	}
	var lastErr error
	for _, node := range nodes {
		if !node.DNSSyncEnabled {
			continue
		}
		if syncErr := m.SyncNodeDNS(ctx, node, ""); syncErr != nil {
			lastErr = syncErr
			log.Printf("cloudflare node dns sync warning node=%s error=%v", node.ID, syncErr)
		} else {
			syncedNodes++
		}
	}
	syncedGroups, groupErr := m.evaluateFailoverGroups(ctx, time.Now(), true)
	if groupErr != nil && lastErr == nil {
		lastErr = groupErr
	}
	syncedDomains, domErr := m.evaluateEdgeDomainsDNS(ctx, time.Now(), true)
	if domErr != nil && lastErr == nil {
		lastErr = domErr
	}
	return syncedNodes + syncedDomains, syncedGroups, lastErr
}

func (m *cloudflareDNSManager) TestConnection(ctx context.Context, rawToken, rootDomain, zoneID string) (cfZone, error) {
	stored := m.store.LoadCloudflareDNS(ctx)
	token := strings.TrimSpace(rawToken)
	if token == "" {
		if stored.EncryptedToken == "" {
			return cfZone{}, errors.New("cloudflare API token is required")
		}
		decrypted, err := m.cipher.Decrypt(stored.EncryptedToken)
		if err != nil {
			return cfZone{}, errors.New("stored cloudflare API token unavailable")
		}
		token = decrypted
	}
	if strings.TrimSpace(rootDomain) == "" {
		rootDomain = stored.RootDomain
	}
	if strings.TrimSpace(zoneID) == "" {
		zoneID = stored.ZoneID
	}
	return m.resolveZone(ctx, token, rootDomain, zoneID)
}

/* -------------------- Admin API (/_admin/api/cloudflare-dns*) -------------------- */

func (a *adminServer) handleCloudflareDNS(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cloudflare == nil {
		a.writeError(w, http.StatusServiceUnavailable, "cloudflare DNS unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		stored := a.store.LoadCloudflareDNS(r.Context())
		a.writeJSON(w, http.StatusOK, stored.cloudflareDNSSettings)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req struct {
			Enabled        bool               `json:"enabled"`
			APIToken       string             `json:"api_token"`
			ZoneID         string             `json:"zone_id"`
			RootDomain     string             `json:"root_domain"`
			Proxied        bool               `json:"proxied"`
			TTL            int                `json:"ttl"`
			FailoverGroups []dnsFailoverGroup `json:"failover_groups"`
		}
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.cloudflare.cfgMu.Lock()
		current := a.store.LoadCloudflareDNS(r.Context())
		token := strings.TrimSpace(req.APIToken)
		rootDomain := normalizeDomainHostname(req.RootDomain)
		zoneID := strings.TrimSpace(req.ZoneID)
		if rootDomain != "" && !validRuleDomain(rootDomain) {
			a.gateway.cloudflare.cfgMu.Unlock()
			a.writeError(w, http.StatusBadRequest, "invalid root domain")
			return
		}
		if req.Enabled && token == "" && current.EncryptedToken == "" {
			a.gateway.cloudflare.cfgMu.Unlock()
			a.writeError(w, http.StatusBadRequest, "cloudflare API token is required when enabled")
			return
		}
		if req.Enabled && rootDomain == "" && zoneID == "" {
			a.gateway.cloudflare.cfgMu.Unlock()
			a.writeError(w, http.StatusBadRequest, "root_domain or zone_id is required when enabled")
			return
		}
		existingGroups := make(map[string]dnsFailoverGroup, len(current.FailoverGroups))
		for _, g := range current.FailoverGroups {
			existingGroups[g.ID] = g
		}
		groups, err := normalizeFailoverGroups(req.FailoverGroups, rootDomain, existingGroups)
		if err != nil {
			a.gateway.cloudflare.cfgMu.Unlock()
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		encrypted := current.EncryptedToken
		if token != "" {
			encrypted, err = a.gateway.cloudflare.cipher.Encrypt(token)
			if err != nil {
				a.gateway.cloudflare.cfgMu.Unlock()
				a.writeError(w, http.StatusInternalServerError, "failed to encrypt cloudflare token")
				return
			}
		}
		next := cloudflareDNSStored{
			cloudflareDNSSettings: cloudflareDNSSettings{
				Enabled:        req.Enabled,
				TokenSet:       encrypted != "",
				ZoneID:         zoneID,
				RootDomain:     rootDomain,
				Proxied:        req.Proxied,
				TTL:            normalizeCloudflareDNSTTL(req.TTL),
				FailoverGroups: groups,
				LastSyncAt:     current.LastSyncAt,
				LastError:      "",
			},
			EncryptedToken: encrypted,
		}
		plainForResolve := token
		if plainForResolve == "" && req.Enabled && zoneID != "" && rootDomain == "" && encrypted != "" {
			plainForResolve, _ = a.gateway.cloudflare.cipher.Decrypt(encrypted)
		}
		a.gateway.cloudflare.cfgMu.Unlock()

		// Resolve root_domain when configured with zone_id only so ACME DNS-01 and domain checks work immediately.
		if req.Enabled && zoneID != "" && rootDomain == "" && plainForResolve != "" {
			if zone, zErr := a.gateway.cloudflare.resolveZone(r.Context(), plainForResolve, "", zoneID); zErr == nil && zone.Name != "" {
				rootDomain = normalizeDomainHostname(zone.Name)
				next.RootDomain = rootDomain
			}
		}

		a.gateway.cloudflare.cfgMu.Lock()
		fresh := a.store.LoadCloudflareDNS(r.Context())
		next.LastSyncAt = fresh.LastSyncAt
		saveErr := a.store.SaveCloudflareDNS(r.Context(), next)
		a.gateway.cloudflare.cfgMu.Unlock()
		if saveErr != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save cloudflare DNS settings")
			return
		}
		a.gateway.cloudflare.clearSyncCache()
		a.auditRequest(r, "dns.settings", rootDomain, fmt.Sprintf("enabled=%t groups=%d proxied=%t", next.Enabled, len(groups), next.Proxied), true)
		a.writeJSON(w, http.StatusOK, next.cloudflareDNSSettings)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleCloudflareDNSTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.cloudflare == nil {
		a.writeError(w, http.StatusServiceUnavailable, "cloudflare DNS unavailable")
		return
	}
	var req struct {
		APIToken   string `json:"api_token"`
		RootDomain string `json:"root_domain"`
		ZoneID     string `json:"zone_id"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req)
	zone, err := a.gateway.cloudflare.TestConnection(r.Context(), req.APIToken, req.RootDomain, req.ZoneID)
	if err != nil {
		a.auditRequest(r, "dns.test", req.RootDomain, err.Error(), false)
		a.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.auditRequest(r, "dns.test", zone.Name, "zone_id="+zone.ID, true)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"zone_id":     zone.ID,
		"root_domain": zone.Name,
		"status":      zone.Status,
	})
}

func (a *adminServer) handleCloudflareDNSSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.cloudflare == nil {
		a.writeError(w, http.StatusServiceUnavailable, "cloudflare DNS unavailable")
		return
	}
	nodesCount, groupsCount, err := a.gateway.cloudflare.SyncAll(r.Context())
	if err != nil {
		a.auditRequest(r, "dns.sync", "", err.Error(), false)
		a.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.auditRequest(r, "dns.sync", "", fmt.Sprintf("nodes=%d groups=%d", nodesCount, groupsCount), true)
	stored := a.store.LoadCloudflareDNS(r.Context())
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"synced_nodes":  nodesCount,
		"synced_groups": groupsCount,
		"settings":      stored.cloudflareDNSSettings,
	})
}
