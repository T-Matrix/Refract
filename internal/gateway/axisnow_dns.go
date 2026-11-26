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
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	axisnowDNSSettingKey     = "axisnow_dns_settings_json"
	axisnowDefaultAPIBase    = "https://api.axisnow.io/client/v1"
	domainDNSAxisNowSmart    = "axisnow_smart"
	axisnowManagedDescPrefix = "Managed by Refract"
	axisnowMetadataCacheTTL  = 6 * time.Hour
	axisnowMetadataFailTTL   = 60 * time.Second
	dnsReconcileInterval     = 10 * time.Minute
)

type axisnowProviderZone struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Zone string `json:"zone"`
	Plan string `json:"plan,omitempty"`
}

type axisnowProviderInfo struct {
	UUID           string                `json:"uuid"`
	Name           string                `json:"name"`
	Type           string                `json:"type"`
	ProviderSource string                `json:"provider_source"` // "platform" | "self-hosted"
	Status         string                `json:"status,omitempty"`
	Zones          []axisnowProviderZone `json:"zones,omitempty"`
}

type axisnowDNSSettings struct {
	Enabled               bool                  `json:"enabled"`
	TokenSet              bool                  `json:"token_set"`
	APIBase               string                `json:"api_base,omitempty"`
	DefaultProviderUUID   string                `json:"default_provider_uuid,omitempty"`
	DefaultProviderSource string                `json:"default_provider_source,omitempty"`
	DefaultProviderType   string                `json:"default_provider_type,omitempty"`
	DefaultZoneUUID       string                `json:"default_zone_uuid,omitempty"`
	DefaultZoneName       string                `json:"default_zone_name,omitempty"`
	DefaultZonePlan       string                `json:"default_zone_plan,omitempty"`
	TokenName             string                `json:"token_name,omitempty"`
	TenantUUID            string                `json:"tenant_uuid,omitempty"`
	CachedProviders       []axisnowProviderInfo `json:"cached_providers,omitempty"`
	LastSyncAt            int64                 `json:"last_sync_at"`
	LastError             string                `json:"last_error,omitempty"`
}

type axisnowDNSStored struct {
	axisnowDNSSettings
	EncryptedToken string `json:"encrypted_token,omitempty"`
}

type smartDNSLineRule struct {
	ID               string   `json:"id"`
	GeoISP           string   `json:"geo_isp"`
	Label            string   `json:"label,omitempty"`
	NodeIDs          []string `json:"node_ids"`
	ElectionStrategy string   `json:"election_strategy"` // "priority_order" | "random"
	IPQuantity       int      `json:"ip_quantity"`
	AutoPauseOnEmpty bool     `json:"auto_pause_on_empty"`
	Enabled          bool     `json:"enabled"`
	AxisNowRuleUUID  string   `json:"axisnow_rule_uuid,omitempty"`
	ActiveNodeIDs    []string `json:"active_node_ids,omitempty"`
	ActiveIPs        []string `json:"active_ips,omitempty"`
	Status           string   `json:"status,omitempty"`
	LastError        string   `json:"last_error,omitempty"`
}

type edgeDomainSmartDNS struct {
	ProfileID         string             `json:"profile_id,omitempty"`
	ProfileName       string             `json:"profile_name,omitempty"`
	ProviderUUID      string             `json:"provider_uuid,omitempty"`
	ProviderSource    string             `json:"provider_source,omitempty"` // "platform" | "self-hosted"
	ProviderType      string             `json:"provider_type,omitempty"`
	ZoneUUID          string             `json:"zone_uuid,omitempty"`
	ZoneName          string             `json:"zone_name,omitempty"`
	ZonePlan          string             `json:"zone_plan,omitempty"`
	RoutingDomainUUID string             `json:"routing_domain_uuid,omitempty"`
	RoutingDomainHost string             `json:"routing_domain_host,omitempty"`
	AutoCFCNAME       bool               `json:"auto_cf_cname"`
	CFCNAMESynced     bool               `json:"cf_cname_synced,omitempty"`
	CFCNAMEStatus     string             `json:"cf_cname_status,omitempty"`      // "" | "pending" | "synced" | "error"
	CFCNAMEStatusNote string             `json:"cf_cname_status_note,omitempty"` // human-readable cutover / probe status
	CFCNAMECheckedAt  int64              `json:"cf_cname_checked_at,omitempty"`
	Lines             []smartDNSLineRule `json:"lines,omitempty"`
}

type smartDNSProfileRecord struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	ProviderUUID   string             `json:"provider_uuid,omitempty"`
	ProviderSource string             `json:"provider_source"`
	ProviderType   string             `json:"provider_type,omitempty"`
	ZoneUUID       string             `json:"zone_uuid,omitempty"`
	ZoneName       string             `json:"zone_name,omitempty"`
	ZonePlan       string             `json:"zone_plan,omitempty"`
	AutoCFCNAME    bool               `json:"auto_cf_cname"`
	Lines          []smartDNSLineRule `json:"lines"`
	CreatedAt      int64              `json:"created_at"`
	UpdatedAt      int64              `json:"updated_at"`
}

type smartDNSBoundDomainBrief struct {
	ID                string `json:"id"`
	Domain            string `json:"domain"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	RoutingDomainHost string `json:"routing_domain_host,omitempty"`
	AutoCFCNAME       bool   `json:"auto_cf_cname,omitempty"`
	CFCNAMESynced     bool   `json:"cf_cname_synced,omitempty"`
	CFCNAMEStatus     string `json:"cf_cname_status,omitempty"`
	CFCNAMEStatusNote string `json:"cf_cname_status_note,omitempty"`
	DNSLastSyncAt     int64  `json:"dns_last_sync_at"`
	DNSLastError      string `json:"dns_last_error,omitempty"`
}

type smartDNSProfileView struct {
	smartDNSProfileRecord
	LineCount    int                        `json:"line_count"`
	BoundDomains []smartDNSBoundDomainBrief `json:"bound_domains"`
}

type smartDNSProfilesListResponse struct {
	AxisNowEnabled      bool                  `json:"axisnow_enabled"`
	AxisNowProviderType string                `json:"axisnow_provider_type,omitempty"`
	AxisNowDefaultZone  string                `json:"axisnow_default_zone,omitempty"`
	AxisNowProviders    []axisnowProviderInfo `json:"axisnow_providers,omitempty"`
	CFEnabled           bool                  `json:"cf_enabled"`
	CFRootDomain        string                `json:"cf_root_domain"`
	Profiles            []smartDNSProfileView `json:"profiles"`
}

type axisnowGeoISPOption struct {
	DisplayName string                `json:"displayName"`
	Value       string                `json:"value"`
	Disabled    bool                  `json:"disabled,omitempty"`
	Children    []axisnowGeoISPOption `json:"children,omitempty"`
}

type axisnowGeoISPPlan struct {
	ProviderPlan string                `json:"provider_plan"`
	Options      []axisnowGeoISPOption `json:"options"`
}

type axisnowGeoISPProviderGroup struct {
	ProviderType string              `json:"provider_type"`
	List         []axisnowGeoISPPlan `json:"list"`
}

type axisnowMetadataResponse struct {
	Source    string                       `json:"source"` // "live" | "fallback"
	FetchedAt int64                        `json:"fetched_at"`
	Providers []axisnowGeoISPProviderGroup `json:"providers"`
	Error     string                       `json:"error,omitempty"`
}

type axisnowTestResult struct {
	OK         bool                  `json:"ok"`
	TokenName  string                `json:"token_name"`
	TenantUUID string                `json:"tenant_uuid"`
	Providers  []axisnowProviderInfo `json:"providers"`
}

type axisnowAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type axisnowAPIEnvelope struct {
	Success  bool              `json:"success"`
	Messages []string          `json:"messages"`
	Errors   []axisnowAPIError `json:"errors"`
	Result   json.RawMessage   `json:"result"`
}

type axisnowTokenVerification struct {
	UUID           string `json:"uuid"`
	TenantUUID     string `json:"tenant_uuid"`
	Name           string `json:"name"`
	ExpirationTime string `json:"expiration_time"`
}

type axisnowRemoteZoneConf struct {
	Plan   string `json:"plan,omitempty"`
	Zone   string `json:"zone,omitempty"`
	ZoneID string `json:"zone_id,omitempty"`
}

type axisnowRemoteRoutingDomain struct {
	UUID           string                 `json:"uuid"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Domain         string                 `json:"domain"`
	DNSProviderID  string                 `json:"dns_provider_uuid"`
	DNSZoneID      string                 `json:"dns_zone_uuid"`
	ZoneConf       *axisnowRemoteZoneConf `json:"zone_conf,omitempty"`
	RecordType     string                 `json:"record_type"`
	ProviderSource string                 `json:"provider_source"`
	ProviderType   string                 `json:"provider_type"`
	Status         string                 `json:"status"`
}

type axisnowRemoteAddressGroup struct {
	Type string   `json:"type"`
	IPs  []string `json:"ips,omitempty"`
}

type axisnowRemoteAddressPool struct {
	Mode   string                      `json:"mode"`
	Groups []axisnowRemoteAddressGroup `json:"groups,omitempty"`
}

type axisnowRemoteResponseStrategy struct {
	ElectionStrategy string `json:"election_strategy"`
	IPQuantity       int    `json:"ip_quantity"`
}

type axisnowRemoteTTLConf struct {
	ProviderType string `json:"provider_type"`
	Plan         string `json:"plan,omitempty"`
	TTL          int    `json:"ttl"`
}

type axisnowRemoteRuleConf struct {
	AddressPool      axisnowRemoteAddressPool      `json:"address_pool"`
	ResponseStrategy axisnowRemoteResponseStrategy `json:"response_strategy"`
	TTLConf          *axisnowRemoteTTLConf         `json:"ttl_conf,omitempty"`
}

type axisnowRemoteRuleAction struct {
	Method string                `json:"method"`
	Conf   axisnowRemoteRuleConf `json:"conf"`
}

type axisnowRemoteRulePayload struct {
	Domain           string                  `json:"domain,omitempty"`
	Type             string                  `json:"type"`
	GeoISP           string                  `json:"geo_isp"`
	Name             string                  `json:"name,omitempty"`
	Description      string                  `json:"description,omitempty"`
	DNSDomainUUID    string                  `json:"dns_domain_uuid"`
	Action           axisnowRemoteRuleAction `json:"action"`
	Status           string                  `json:"status"`
	AutoPauseOnEmpty bool                    `json:"auto_pause_on_empty"`
}

type axisnowRemoteRuleEntity struct {
	UUID             string                  `json:"uuid"`
	Domain           string                  `json:"domain"`
	Type             string                  `json:"type"`
	GeoISP           string                  `json:"geo_isp"`
	Name             string                  `json:"name"`
	Description      string                  `json:"description"`
	DNSDomainUUID    string                  `json:"dns_domain_uuid"`
	Action           axisnowRemoteRuleAction `json:"action"`
	Status           string                  `json:"status"`
	AutoPauseOnEmpty bool                    `json:"auto_pause_on_empty"`
	AutoPaused       bool                    `json:"auto_paused"`
}

type axisnowDNSManager struct {
	store    *telemetryStore
	gateway  *Gateway
	cipher   *tokenCipher
	client   *http.Client
	resolver *safeResolver
	apiBase  string
	mu       sync.Mutex
	cfgMu    sync.Mutex

	domainMu    sync.Mutex
	domainLocks map[string]*sync.Mutex

	syncHashMu     sync.Mutex
	lastSyncedHash map[string]string
	lastSyncedAt   map[string]time.Time

	orphanSweepMu     sync.Mutex
	lastOrphanSweepAt time.Time

	metaMu          sync.RWMutex
	metaFetchMu     sync.Mutex
	metaCached      []axisnowGeoISPProviderGroup
	metaFetchedAt   time.Time
	metaFailedAt    time.Time
	metaFailedError string

	// cnameReadyProbe checks whether an AxisNow routing domain resolves to valid public IP(s)
	// before switching Cloudflare DNS to CNAME (overridable in unit tests).
	cnameReadyProbe func(ctx context.Context, host string) (ready bool, resolvedIPs []string, detail string)
}

func newAxisNowDNSManager(store *telemetryStore, gateway *Gateway, secret []byte) (*axisnowDNSManager, error) {
	cipher, err := newScopedTokenCipher(secret, "axisnow-dns")
	if err != nil {
		return nil, err
	}
	res := newSafeResolver(time.Minute, false)
	m := &axisnowDNSManager{
		store:          store,
		gateway:        gateway,
		cipher:         cipher,
		resolver:       res,
		apiBase:        axisnowDefaultAPIBase,
		domainLocks:    make(map[string]*sync.Mutex),
		lastSyncedHash: make(map[string]string),
		lastSyncedAt:   make(map[string]time.Time),
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		// Enforce SSRF protection for all production endpoints; only skip for unit-test httptest overrides.
		if strings.TrimSpace(m.apiBase) == "" || m.apiBase == axisnowDefaultAPIBase {
			host, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return nil, fmt.Errorf("invalid AxisNow endpoint address")
			}
			u := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port)}
			resolved, rErr := res.Resolve(ctx, u)
			if rErr != nil {
				return nil, fmt.Errorf("AxisNow API endpoint blocked: %w", rErr)
			}
			var lastErr error
			for _, target := range resolved {
				conn, dErr := dialer.DialContext(ctx, network, target)
				if dErr == nil {
					return conn, nil
				}
				lastErr = dErr
			}
			if lastErr == nil {
				lastErr = errors.New("AxisNow API endpoint unreachable")
			}
			return nil, lastErr
		}
		return dialer.DialContext(ctx, network, addr)
	}
	m.client = &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return m, nil
}

func (m *axisnowDNSManager) Close() {
	if m != nil && m.client != nil {
		m.client.CloseIdleConnections()
	}
}

func (m *axisnowDNSManager) lockDomain(domainID string) func() {
	if m == nil || domainID == "" {
		return func() {}
	}
	m.domainMu.Lock()
	if m.domainLocks == nil {
		m.domainLocks = make(map[string]*sync.Mutex)
	}
	l, ok := m.domainLocks[domainID]
	if !ok {
		l = &sync.Mutex{}
		m.domainLocks[domainID] = l
	}
	m.domainMu.Unlock()
	l.Lock()
	return l.Unlock
}

func (m *axisnowDNSManager) clearDomainSyncCache(domainID string) {
	if m == nil || domainID == "" {
		return
	}
	m.syncHashMu.Lock()
	delete(m.lastSyncedHash, domainID)
	delete(m.lastSyncedAt, domainID)
	m.syncHashMu.Unlock()
}

func (m *axisnowDNSManager) clearSyncCache() {
	if m == nil {
		return
	}
	m.syncHashMu.Lock()
	clear(m.lastSyncedHash)
	clear(m.lastSyncedAt)
	m.syncHashMu.Unlock()
}

func defaultAxisNowDNSStored() axisnowDNSStored {
	return axisnowDNSStored{
		axisnowDNSSettings: axisnowDNSSettings{
			APIBase:               axisnowDefaultAPIBase,
			DefaultProviderSource: "platform",
			CachedProviders:       []axisnowProviderInfo{},
		},
	}
}

func validateAxisNowAPIBase(raw string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return axisnowDefaultAPIBase, nil
	}
	parsed, err := parseHTTPURL(trimmed)
	if err != nil {
		return "", fmt.Errorf("AxisNow API 地址格式无效: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", errors.New("AxisNow API 地址仅允许 HTTPS 协议")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("AxisNow API 地址不能包含查询参数或锚点")
	}
	host := normalizeHost(parsed.Hostname())
	if host == "localhost" || host == "host.docker.internal" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", errors.New("AxisNow API 地址不允许指向本机或内网域名")
	}
	if addr, pErr := netip.ParseAddr(strings.Trim(host, "[]")); pErr == nil && isBlockedAddress(addr) {
		return "", errors.New("AxisNow API 地址不允许指向私有或保留 IP")
	}
	return trimmed, nil
}

func normalizeAxisNowAPIBase(raw string) string {
	validated, err := validateAxisNowAPIBase(raw)
	if err != nil {
		return axisnowDefaultAPIBase
	}
	return validated
}

func normalizeAxisNowProviderSource(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), "self-hosted") {
		return "self-hosted"
	}
	return "platform"
}

func normalizeSmartDNSElectionStrategy(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), "random") {
		return "random"
	}
	return "priority_order"
}

func (s *telemetryStore) LoadAxisNowDNS(ctx context.Context) axisnowDNSStored {
	if s == nil {
		return defaultAxisNowDNSStored()
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, axisnowDNSSettingKey).Scan(&raw)
	if err != nil || strings.TrimSpace(raw) == "" {
		return defaultAxisNowDNSStored()
	}
	var loaded axisnowDNSStored
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		return defaultAxisNowDNSStored()
	}
	loaded.APIBase = normalizeAxisNowAPIBase(loaded.APIBase)
	if loaded.DefaultProviderSource != "" {
		loaded.DefaultProviderSource = normalizeAxisNowProviderSource(loaded.DefaultProviderSource)
	}
	if loaded.CachedProviders == nil {
		loaded.CachedProviders = []axisnowProviderInfo{}
	}
	loaded.TokenSet = loaded.EncryptedToken != ""
	return loaded
}

func (s *telemetryStore) SaveAxisNowDNS(ctx context.Context, stored axisnowDNSStored) error {
	stored.APIBase = normalizeAxisNowAPIBase(stored.APIBase)
	if stored.DefaultProviderSource != "" {
		stored.DefaultProviderSource = normalizeAxisNowProviderSource(stored.DefaultProviderSource)
	}
	if stored.CachedProviders == nil {
		stored.CachedProviders = []axisnowProviderInfo{}
	}
	stored.TokenSet = stored.EncryptedToken != ""
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		axisnowDNSSettingKey, string(data), time.Now().Unix(),
	)
	return err
}

func normalizeEdgeDomainSmartDNS(raw *edgeDomainSmartDNS, fallbackNodeIDs []string, existing *edgeDomainSmartDNS) *edgeDomainSmartDNS {
	if raw == nil {
		return nil
	}
	rawSourceEmpty := strings.TrimSpace(raw.ProviderSource) == ""
	routingHost := normalizeDomainHostname(raw.RoutingDomainHost)
	if routingHost != "" && (net.ParseIP(routingHost) != nil || !validRuleDomain(routingHost)) {
		routingHost = ""
	}
	out := &edgeDomainSmartDNS{
		ProfileID:         strings.TrimSpace(raw.ProfileID),
		ProfileName:       truncateRunes(strings.TrimSpace(raw.ProfileName), 64),
		ProviderUUID:      strings.TrimSpace(raw.ProviderUUID),
		ProviderSource:    normalizeAxisNowProviderSource(raw.ProviderSource),
		ProviderType:      strings.TrimSpace(raw.ProviderType),
		ZoneUUID:          strings.TrimSpace(raw.ZoneUUID),
		ZoneName:          normalizeDomainHostname(raw.ZoneName),
		ZonePlan:          strings.TrimSpace(raw.ZonePlan),
		RoutingDomainUUID: strings.TrimSpace(raw.RoutingDomainUUID),
		RoutingDomainHost: routingHost,
		AutoCFCNAME:       raw.AutoCFCNAME,
		CFCNAMESynced:     raw.CFCNAMESynced,
		CFCNAMEStatus:     strings.TrimSpace(raw.CFCNAMEStatus),
		CFCNAMEStatusNote: truncateRunes(strings.TrimSpace(raw.CFCNAMEStatusNote), 200),
		CFCNAMECheckedAt:  raw.CFCNAMECheckedAt,
	}
	inheritRuleState := true
	if existing != nil {
		sameProfile := existing.ProfileID == "" || out.ProfileID == "" || out.ProfileID == existing.ProfileID
		sameSource := rawSourceEmpty || existing.ProviderSource == "" || out.ProviderSource == existing.ProviderSource
		sameProviderID := out.ProviderUUID == "" || existing.ProviderUUID == "" || out.ProviderUUID == existing.ProviderUUID
		sameZone := out.ZoneUUID == "" || existing.ZoneUUID == "" || out.ZoneUUID == existing.ZoneUUID
		sameProvider := sameProfile && sameSource && sameProviderID && sameZone
		if sameProvider {
			if rawSourceEmpty && existing.ProviderSource != "" {
				out.ProviderSource = existing.ProviderSource
			}
			if out.ProviderUUID == "" {
				out.ProviderUUID = existing.ProviderUUID
			}
			if out.ProviderType == "" {
				out.ProviderType = existing.ProviderType
			}
			if out.ZoneUUID == "" {
				out.ZoneUUID = existing.ZoneUUID
			}
			if out.ZoneName == "" {
				out.ZoneName = existing.ZoneName
			}
			if out.ZonePlan == "" {
				out.ZonePlan = existing.ZonePlan
			}
			if out.RoutingDomainHost == "" {
				out.RoutingDomainHost = existing.RoutingDomainHost
			}
			sameHost := out.RoutingDomainHost == existing.RoutingDomainHost
			if sameHost {
				if out.RoutingDomainUUID == "" {
					out.RoutingDomainUUID = existing.RoutingDomainUUID
				}
				out.CFCNAMESynced = existing.CFCNAMESynced
				out.CFCNAMEStatus = existing.CFCNAMEStatus
				out.CFCNAMEStatusNote = existing.CFCNAMEStatusNote
				out.CFCNAMECheckedAt = existing.CFCNAMECheckedAt
			} else {
				out.RoutingDomainUUID = ""
				out.CFCNAMESynced = false
				out.CFCNAMEStatus = ""
				out.CFCNAMEStatusNote = ""
				out.CFCNAMECheckedAt = 0
				inheritRuleState = false
			}
		} else {
			out.RoutingDomainUUID = ""
			out.RoutingDomainHost = ""
			out.CFCNAMESynced = false
			out.CFCNAMEStatus = ""
			out.CFCNAMEStatusNote = ""
			out.CFCNAMECheckedAt = 0
			inheritRuleState = false
		}
	}
	if !out.AutoCFCNAME {
		out.CFCNAMESynced = false
		out.CFCNAMEStatus = ""
		out.CFCNAMEStatusNote = ""
		out.CFCNAMECheckedAt = 0
	}

	existingByGeo := make(map[string]smartDNSLineRule)
	existingByID := make(map[string]smartDNSLineRule)
	if existing != nil && inheritRuleState {
		for _, prev := range existing.Lines {
			if prev.GeoISP != "" {
				existingByGeo[prev.GeoISP] = prev
			}
			if prev.ID != "" {
				existingByID[prev.ID] = prev
			}
		}
	}

	seenGeo := make(map[string]struct{}, len(raw.Lines))
	lines := make([]smartDNSLineRule, 0, len(raw.Lines))
	hasDefault := false
	for i, l := range raw.Lines {
		if len(lines) >= 32 {
			break
		}
		geo := strings.TrimSpace(l.GeoISP)
		if geo == "" {
			continue
		}
		if _, dup := seenGeo[geo]; dup {
			continue
		}
		seenGeo[geo] = struct{}{}
		if geo == "default" {
			hasDefault = true
		}
		id := strings.TrimSpace(l.ID)
		if id == "" {
			if rawID, err := generateRandomHex(5); err == nil {
				id = "ln_" + rawID
			} else {
				id = fmt.Sprintf("ln_%d", i+1)
			}
		}
		strategy := normalizeSmartDNSElectionStrategy(l.ElectionStrategy)
		qty := l.IPQuantity
		if qty < 1 {
			qty = 1
		}
		if qty > 50 {
			qty = 50
		}
		label := truncateRunes(strings.TrimSpace(l.Label), 64)
		if label == "" {
			if geo == "default" {
				label = "默认兜底线路"
			} else {
				label = geo
			}
		}
		nodeIDs := normalizeDomainNodeIDs(l.NodeIDs)
		ruleUUID := ""
		if inheritRuleState {
			ruleUUID = strings.TrimSpace(l.AxisNowRuleUUID)
		}
		item := smartDNSLineRule{
			ID:               id,
			GeoISP:           geo,
			Label:            label,
			NodeIDs:          nodeIDs,
			ElectionStrategy: strategy,
			IPQuantity:       qty,
			AutoPauseOnEmpty: geo != "default" && l.AutoPauseOnEmpty,
			Enabled:          l.Enabled || geo == "default",
			AxisNowRuleUUID:  ruleUUID,
		}
		if prev, ok := existingByID[id]; ok {
			if item.AxisNowRuleUUID == "" && prev.GeoISP == geo {
				item.AxisNowRuleUUID = prev.AxisNowRuleUUID
			}
			item.ActiveNodeIDs = prev.ActiveNodeIDs
			item.ActiveIPs = prev.ActiveIPs
			item.Status = prev.Status
			item.LastError = prev.LastError
		} else if prev, ok := existingByGeo[geo]; ok {
			if item.AxisNowRuleUUID == "" {
				item.AxisNowRuleUUID = prev.AxisNowRuleUUID
			}
			item.ActiveNodeIDs = prev.ActiveNodeIDs
			item.ActiveIPs = prev.ActiveIPs
			item.Status = prev.Status
			item.LastError = prev.LastError
		}
		lines = append(lines, item)
	}
	if !hasDefault {
		defNodes := normalizeDomainNodeIDs(fallbackNodeIDs)
		defLine := smartDNSLineRule{
			ID:               "ln_default",
			GeoISP:           "default",
			Label:            "默认兜底线路",
			NodeIDs:          defNodes,
			ElectionStrategy: "priority_order",
			IPQuantity:       1,
			AutoPauseOnEmpty: false,
			Enabled:          true,
		}
		if prev, ok := existingByGeo["default"]; ok {
			defLine.ID = prev.ID
			defLine.AxisNowRuleUUID = prev.AxisNowRuleUUID
			defLine.ActiveNodeIDs = prev.ActiveNodeIDs
			defLine.ActiveIPs = prev.ActiveIPs
			defLine.Status = prev.Status
			defLine.LastError = prev.LastError
		}
		lines = append([]smartDNSLineRule{defLine}, lines...)
	}
	// Always place default line first for predictable UI & AxisNow sync ordering
	sort.SliceStable(lines, func(i, j int) bool {
		if lines[i].GeoISP == "default" {
			return true
		}
		if lines[j].GeoISP == "default" {
			return false
		}
		return false
	})
	out.Lines = lines
	return out
}

func collectSmartDNSNodeIDs(cfg *edgeDomainSmartDNS) []string {
	if cfg == nil {
		return nil
	}
	var all []string
	for _, l := range cfg.Lines {
		all = append(all, l.NodeIDs...)
	}
	return normalizeDomainNodeIDs(all)
}

func (m *axisnowDNSManager) effectiveAPIBase(stored axisnowDNSStored) string {
	if strings.TrimSpace(m.apiBase) != "" && m.apiBase != axisnowDefaultAPIBase {
		return strings.TrimRight(m.apiBase, "/")
	}
	return normalizeAxisNowAPIBase(stored.APIBase)
}

func (m *axisnowDNSManager) apiDo(ctx context.Context, apiBase, token, method, path string, reqBody any, dst any) (int, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return 0, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(apiBase, "/")+path, bodyReader)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	var env axisnowAPIEnvelope
	if err := json.Unmarshal(rawResp, &env); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resp.StatusCode, fmt.Errorf("AxisNow API HTTP %d", resp.StatusCode)
		}
		return resp.StatusCode, err
	}
	if !env.Success || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(env.Errors) > 0 {
			return resp.StatusCode, fmt.Errorf("AxisNow API 错误 %d: %s", env.Errors[0].Code, env.Errors[0].Message)
		}
		return resp.StatusCode, fmt.Errorf("AxisNow API HTTP %d", resp.StatusCode)
	}
	if dst != nil && len(env.Result) > 0 && string(bytes.TrimSpace(env.Result)) != "null" {
		if err := json.Unmarshal(env.Result, dst); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (m *axisnowDNSManager) activeCredentials(ctx context.Context) (axisnowDNSStored, string, string, error) {
	stored := m.store.LoadAxisNowDNS(ctx)
	apiBase := m.effectiveAPIBase(stored)
	if !stored.Enabled {
		return stored, "", apiBase, nil
	}
	if stored.EncryptedToken == "" {
		return stored, "", apiBase, errors.New("AxisNow API Token 未配置")
	}
	token, err := m.cipher.Decrypt(stored.EncryptedToken)
	if err != nil || strings.TrimSpace(token) == "" {
		return stored, "", apiBase, errors.New("AxisNow API Token 解密失败")
	}
	return stored, strings.TrimSpace(token), apiBase, nil
}

func (m *axisnowDNSManager) verifyToken(ctx context.Context, apiBase, token string) (axisnowTokenVerification, error) {
	var res axisnowTokenVerification
	if _, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/api_tokens_verifications", nil, &res); err != nil {
		return axisnowTokenVerification{}, err
	}
	return res, nil
}

func (m *axisnowDNSManager) listAllProviders(ctx context.Context, apiBase, token string) ([]axisnowProviderInfo, error) {
	providers := make([]axisnowProviderInfo, 0)

	// 1. Platform-hosted (system) DNS providers (free Aliyun & AWS hosted routing domains)
	var sysRaw []struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type"`
		Source      string `json:"source"`
		Zones       []struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
			Zone string `json:"zone"`
			Conf struct {
				ZoneID string `json:"zone_id"`
				Zone   string `json:"zone"`
				Plan   string `json:"plan"`
			} `json:"conf"`
		} `json:"zones"`
	}
	var sysErr, selfErr error
	if _, err := m.apiDo(ctx, apiBase, token, http.MethodPost, "/system_dns_providers", map[string]any{
		"page": 1, "per_page": 100,
	}, &sysRaw); err == nil {
		for _, p := range sysRaw {
			zones := make([]axisnowProviderZone, 0, len(p.Zones))
			for _, z := range p.Zones {
				zName := strings.TrimSpace(z.Zone)
				if zName == "" {
					zName = strings.TrimSpace(z.Conf.Zone)
				}
				if zName == "" {
					zName = strings.TrimSpace(z.Name)
				}
				zones = append(zones, axisnowProviderZone{
					UUID: strings.TrimSpace(z.UUID),
					Name: strings.TrimSpace(z.Name),
					Zone: normalizeDomainHostname(zName),
					Plan: strings.TrimSpace(z.Conf.Plan),
				})
			}
			providers = append(providers, axisnowProviderInfo{
				UUID:           strings.TrimSpace(p.UUID),
				Name:           strings.TrimSpace(p.Name),
				Type:           strings.TrimSpace(p.Type),
				ProviderSource: "platform",
				Status:         "active",
				Zones:          zones,
			})
		}
	} else {
		sysErr = err
	}

	// 2. Self-hosted DNS providers integrated by the user inside AxisNow
	var selfRaw []struct {
		UUID   string `json:"uuid"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	if _, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/dns_providers?page=1&per_page=100", nil, &selfRaw); err == nil {
		for _, p := range selfRaw {
			providers = append(providers, axisnowProviderInfo{
				UUID:           strings.TrimSpace(p.UUID),
				Name:           strings.TrimSpace(p.Name),
				Type:           strings.TrimSpace(p.Type),
				ProviderSource: "self-hosted",
				Status:         strings.TrimSpace(p.Status),
			})
		}
	} else {
		selfErr = err
	}
	if sysErr != nil && selfErr != nil {
		return nil, sysErr
	}
	return providers, nil
}

func (m *axisnowDNSManager) TestConnection(ctx context.Context, rawToken, rawAPIBase string) (axisnowTestResult, error) {
	stored := m.store.LoadAxisNowDNS(ctx)
	apiBase := m.effectiveAPIBase(stored)
	baseChanged := false
	if strings.TrimSpace(rawAPIBase) != "" && (m.apiBase == "" || m.apiBase == axisnowDefaultAPIBase) {
		validated, vErr := validateAxisNowAPIBase(rawAPIBase)
		if vErr != nil {
			return axisnowTestResult{}, vErr
		}
		if !strings.EqualFold(validated, stored.APIBase) {
			baseChanged = true
		}
		apiBase = validated
	}
	token := strings.TrimSpace(rawToken)
	if token == "" {
		if baseChanged {
			return axisnowTestResult{}, errors.New("修改 AxisNow API 地址时必须重新填写 API Token")
		}
		if stored.EncryptedToken == "" {
			return axisnowTestResult{}, errors.New("请先填写 AxisNow API Token")
		}
		decrypted, err := m.cipher.Decrypt(stored.EncryptedToken)
		if err != nil || strings.TrimSpace(decrypted) == "" {
			return axisnowTestResult{}, errors.New("已保存的 AxisNow API Token 解密失败，请重新填写")
		}
		token = strings.TrimSpace(decrypted)
	}

	ver, err := m.verifyToken(ctx, apiBase, token)
	if err != nil {
		return axisnowTestResult{}, err
	}
	providers, pErr := m.listAllProviders(ctx, apiBase, token)
	if pErr != nil {
		providers = stored.CachedProviders
	}
	return axisnowTestResult{
		OK:         true,
		TokenName:  ver.Name,
		TenantUUID: ver.TenantUUID,
		Providers:  providers,
	}, nil
}

func (m *axisnowDNSManager) GetGeoISPMetadata(ctx context.Context, forceRefresh bool) axisnowMetadataResponse {
	m.metaMu.RLock()
	if !forceRefresh && len(m.metaCached) > 0 && time.Since(m.metaFetchedAt) < axisnowMetadataCacheTTL {
		out := axisnowMetadataResponse{
			Source:    "live",
			FetchedAt: m.metaFetchedAt.Unix(),
			Providers: m.metaCached,
		}
		m.metaMu.RUnlock()
		return out
	}
	if !forceRefresh && !m.metaFailedAt.IsZero() && time.Since(m.metaFailedAt) < axisnowMetadataFailTTL {
		errText := m.metaFailedError
		m.metaMu.RUnlock()
		return axisnowMetadataResponse{
			Source:    "fallback",
			FetchedAt: m.metaFailedAt.Unix(),
			Providers: fallbackAxisNowGeoISPMetadata(),
			Error:     errText,
		}
	}
	m.metaMu.RUnlock()

	stored := m.store.LoadAxisNowDNS(ctx)
	isTestOverride := strings.TrimSpace(m.apiBase) != "" && m.apiBase != axisnowDefaultAPIBase
	if !isTestOverride && (!stored.Enabled || stored.EncryptedToken == "") {
		return axisnowMetadataResponse{
			Source:    "fallback",
			FetchedAt: time.Now().Unix(),
			Providers: fallbackAxisNowGeoISPMetadata(),
		}
	}

	m.metaFetchMu.Lock()
	defer m.metaFetchMu.Unlock()
	m.metaMu.RLock()
	if !forceRefresh && len(m.metaCached) > 0 && time.Since(m.metaFetchedAt) < axisnowMetadataCacheTTL {
		out := axisnowMetadataResponse{
			Source:    "live",
			FetchedAt: m.metaFetchedAt.Unix(),
			Providers: m.metaCached,
		}
		m.metaMu.RUnlock()
		return out
	}
	if !forceRefresh && !m.metaFailedAt.IsZero() && time.Since(m.metaFailedAt) < axisnowMetadataFailTTL {
		errText := m.metaFailedError
		m.metaMu.RUnlock()
		return axisnowMetadataResponse{
			Source:    "fallback",
			FetchedAt: m.metaFailedAt.Unix(),
			Providers: fallbackAxisNowGeoISPMetadata(),
			Error:     errText,
		}
	}
	m.metaMu.RUnlock()

	apiBase := m.effectiveAPIBase(stored)
	token := ""
	if stored.Enabled && stored.EncryptedToken != "" {
		if dec, err := m.cipher.Decrypt(stored.EncryptedToken); err == nil {
			token = strings.TrimSpace(dec)
		}
	}

	var live []axisnowGeoISPProviderGroup
	_, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/policy/metadata/geo_isp", nil, &live)
	if err == nil && len(live) > 0 {
		now := time.Now()
		m.metaMu.Lock()
		m.metaCached = live
		m.metaFetchedAt = now
		m.metaFailedAt = time.Time{}
		m.metaFailedError = ""
		m.metaMu.Unlock()
		return axisnowMetadataResponse{
			Source:    "live",
			FetchedAt: now.Unix(),
			Providers: live,
		}
	}

	now := time.Now()
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	m.metaMu.Lock()
	m.metaFailedAt = now
	m.metaFailedError = errText
	m.metaMu.Unlock()
	return axisnowMetadataResponse{
		Source:    "fallback",
		FetchedAt: now.Unix(),
		Providers: fallbackAxisNowGeoISPMetadata(),
		Error:     errText,
	}
}

func fallbackAxisNowGeoISPMetadata() []axisnowGeoISPProviderGroup {
	aliOptions := []axisnowGeoISPOption{
		{DisplayName: "默认兜底线路", Value: "default"},
		{
			DisplayName: "中国大陆运营商",
			Value:       "_cn_isp",
			Disabled:    true,
			Children: []axisnowGeoISPOption{
				{DisplayName: "中国电信", Value: "telecom"},
				{DisplayName: "中国联通", Value: "unicom"},
				{DisplayName: "中国移动", Value: "mobile"},
				{DisplayName: "中国教育网", Value: "edu"},
				{DisplayName: "鹏博士/长城宽带", Value: "drpeng"},
			},
		},
		{
			DisplayName: "中国地区与海外",
			Value:       "_region",
			Disabled:    true,
			Children: []axisnowGeoISPOption{
				{DisplayName: "海外地区", Value: "oversea"},
				{DisplayName: "中国香港", Value: "cn_region_hongkong"},
				{DisplayName: "中国台湾", Value: "cn_region_taiwan"},
				{DisplayName: "中国澳门", Value: "cn_region_macao"},
				{DisplayName: "北京", Value: "cn_region_beijing"},
				{DisplayName: "上海", Value: "cn_region_shanghai"},
				{DisplayName: "广东", Value: "cn_region_guangdong"},
				{DisplayName: "浙江", Value: "cn_region_zhejiang"},
				{DisplayName: "江苏", Value: "cn_region_jiangsu"},
				{DisplayName: "四川", Value: "cn_region_sichuan"},
				{DisplayName: "福建", Value: "cn_region_fujian"},
				{DisplayName: "山东", Value: "cn_region_shandong"},
				{DisplayName: "湖北", Value: "cn_region_hubei"},
				{DisplayName: "河南", Value: "cn_region_henan"},
			},
		},
	}

	awsOptions := []axisnowGeoISPOption{
		{DisplayName: "默认兜底线路 (Global Default)", Value: "default"},
		{
			DisplayName: "大洲",
			Value:       "_continent",
			Disabled:    true,
			Children: []axisnowGeoISPOption{
				{DisplayName: "亚洲 (Asia)", Value: "AS"},
				{DisplayName: "欧洲 (Europe)", Value: "EU"},
				{DisplayName: "北美洲 (North America)", Value: "NA"},
				{DisplayName: "大洋洲 (Oceania)", Value: "OC"},
				{DisplayName: "南美洲 (South America)", Value: "SA"},
				{DisplayName: "非洲 (Africa)", Value: "AF"},
			},
		},
		{
			DisplayName: "热门国家 / 地区",
			Value:       "_country",
			Disabled:    true,
			Children: []axisnowGeoISPOption{
				{DisplayName: "中国大陆 (CN)", Value: "CN"},
				{DisplayName: "中国香港 (HK)", Value: "HK"},
				{DisplayName: "中国台湾 (TW)", Value: "TW"},
				{DisplayName: "日本 (JP)", Value: "JP"},
				{DisplayName: "新加坡 (SG)", Value: "SG"},
				{DisplayName: "韩国 (KR)", Value: "KR"},
				{DisplayName: "美国 (US)", Value: "US"},
				{DisplayName: "德国 (DE)", Value: "DE"},
				{DisplayName: "英国 (GB)", Value: "GB"},
				{DisplayName: "澳大利亚 (AU)", Value: "AU"},
				{DisplayName: "加拿大 (CA)", Value: "CA"},
			},
		},
	}

	dnspodOptions := []axisnowGeoISPOption{
		{DisplayName: "默认兜底线路", Value: "default"},
		{DisplayName: "电信", Value: "电信"},
		{DisplayName: "联通", Value: "联通"},
		{DisplayName: "移动", Value: "移动"},
		{DisplayName: "教育网", Value: "教育网"},
		{DisplayName: "境外", Value: "境外"},
	}

	return []axisnowGeoISPProviderGroup{
		{ProviderType: "alibaba-cloud", List: []axisnowGeoISPPlan{{ProviderPlan: "free", Options: aliOptions}}},
		{ProviderType: "aws-route53", List: []axisnowGeoISPPlan{{ProviderPlan: "default", Options: awsOptions}}},
		{ProviderType: "dnspod", List: []axisnowGeoISPPlan{{ProviderPlan: "free", Options: dnspodOptions}}},
		{ProviderType: "cloudflare", List: []axisnowGeoISPPlan{{ProviderPlan: "default", Options: []axisnowGeoISPOption{{DisplayName: "默认线路（Cloudflare 仅支持默认线路）", Value: "default"}}}}},
	}
}

var dnsLabelSanitizeRe = regexp.MustCompile(`[^a-z0-9-]+`)

func buildPlatformProfileRoutingDomainHost(profileID, zoneName string) string {
	zoneName = normalizeDomainHostname(zoneName)
	if zoneName == "" {
		return ""
	}
	rawID := strings.ToLower(strings.TrimSpace(profileID))
	rawID = strings.TrimPrefix(rawID, "sdp_")
	rawID = strings.Trim(dnsLabelSanitizeRe.ReplaceAllString(rawID, ""), "-")
	if len(rawID) > 10 {
		rawID = rawID[:10]
	}
	if rawID == "" {
		rawID = "pool"
	}
	return "refract-" + rawID + "." + zoneName
}

func axisnowRoutingOwnerKey(dom edgeDomainRecord, cfg *edgeDomainSmartDNS) (string, bool) {
	if cfg != nil && cfg.ProviderSource == "platform" && strings.TrimSpace(cfg.ProfileID) != "" {
		return strings.TrimSpace(cfg.ProfileID), true
	}
	return dom.ID, false
}

func (m *axisnowDNSManager) findSiblingSharedRoutingDomain(ctx context.Context, dom edgeDomainRecord, cfg *edgeDomainSmartDNS) (string, string, map[string]string) {
	if m == nil || m.store == nil || cfg == nil || cfg.ProviderSource != "platform" || strings.TrimSpace(cfg.ProfileID) == "" {
		return "", "", nil
	}
	others, err := m.store.ListEdgeDomains(ctx)
	if err != nil {
		return "", "", nil
	}
	explicitHost := normalizeDomainHostname(cfg.RoutingDomainHost)
	for _, o := range others {
		if o.ID == dom.ID || !o.Enabled || o.DNSMode != domainDNSAxisNowSmart || o.SmartDNS == nil {
			continue
		}
		os := o.SmartDNS
		if os.ProfileID != cfg.ProfileID || os.RoutingDomainUUID == "" {
			continue
		}
		if normalizeAxisNowProviderSource(os.ProviderSource) != "platform" {
			continue
		}
		if cfg.ProviderUUID != "" && os.ProviderUUID != "" && cfg.ProviderUUID != os.ProviderUUID {
			continue
		}
		if cfg.ZoneUUID != "" && os.ZoneUUID != "" && cfg.ZoneUUID != os.ZoneUUID {
			continue
		}
		siblingHost := normalizeDomainHostname(os.RoutingDomainHost)
		if explicitHost != "" && siblingHost != "" && !strings.EqualFold(explicitHost, siblingHost) {
			continue
		}
		ruleMap := make(map[string]string, len(os.Lines))
		for _, ln := range os.Lines {
			if ln.GeoISP != "" && ln.AxisNowRuleUUID != "" {
				ruleMap[ln.GeoISP] = ln.AxisNowRuleUUID
			}
		}
		return os.RoutingDomainUUID, siblingHost, ruleMap
	}
	return "", "", nil
}

func buildPlatformRoutingDomainHost(dom edgeDomainRecord, zoneName string) string {
	zoneName = normalizeDomainHostname(zoneName)
	if zoneName == "" {
		return ""
	}
	base := edgeDomainBaseHost(dom.Domain)
	prefix := strings.Split(base, ".")[0]
	prefix = strings.Trim(dnsLabelSanitizeRe.ReplaceAllString(strings.ToLower(prefix), "-"), "-")
	if prefix == "" {
		prefix = "edge"
	}
	if len(prefix) > 18 {
		prefix = strings.TrimRight(prefix[:18], "-")
	}
	rawID := strings.ToLower(strings.TrimSpace(dom.ID))
	rawID = strings.TrimPrefix(rawID, "dom_")
	rawID = strings.TrimPrefix(rawID, "dm_")
	suffix := strings.Trim(dnsLabelSanitizeRe.ReplaceAllString(rawID, ""), "-")
	if len(suffix) > 8 {
		suffix = suffix[:8]
	}
	label := prefix
	if suffix != "" {
		label = prefix + "-" + suffix
	}
	return label + "." + zoneName
}

func (m *axisnowDNSManager) listRoutingDomains(ctx context.Context, apiBase, token, keyword string) ([]axisnowRemoteRoutingDomain, error) {
	kw := strings.TrimSpace(keyword)
	if kw != "" {
		body := map[string]any{
			"page":     1,
			"per_page": 100,
			"filter": map[string]any{
				"or": []any{
					map[string]any{
						"and": []any{
							map[string]any{
								"field":    "keyword",
								"operator": "contains",
								"value":    kw,
							},
						},
					},
				},
			},
		}
		var filtered []axisnowRemoteRoutingDomain
		if _, fErr := m.apiDo(ctx, apiBase, token, http.MethodPost, "/dns_routing_domains/filter", body, &filtered); fErr == nil {
			return filtered, nil
		}
	}
	var all []axisnowRemoteRoutingDomain
	var lastStatus int
	var lastErr error
	for page := 1; page <= 5; page++ {
		var batch []axisnowRemoteRoutingDomain
		status, err := m.apiDo(ctx, apiBase, token, http.MethodGet, fmt.Sprintf("/dns_routing_domains?page=%d&per_page=100", page), nil, &batch)
		if err != nil {
			lastStatus = status
			lastErr = err
			break
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, nil
		}
	}
	if len(all) > 0 {
		return all, nil
	}
	// Fallback to /dns_routing_domains/filter if GET list is unavailable.
	if lastStatus != http.StatusNotFound && lastStatus != http.StatusMethodNotAllowed {
		if kw == "" {
			return nil, lastErr
		}
	}
	body := map[string]any{"page": 1, "per_page": 100}
	if kw != "" {
		body["filter"] = map[string]any{
			"or": []any{
				map[string]any{
					"and": []any{
						map[string]any{
							"field":    "keyword",
							"operator": "contains",
							"value":    kw,
						},
					},
				},
			},
		}
	}
	var filtered []axisnowRemoteRoutingDomain
	if _, fErr := m.apiDo(ctx, apiBase, token, http.MethodPost, "/dns_routing_domains/filter", body, &filtered); fErr != nil {
		return nil, fErr
	}
	return filtered, nil
}

func (m *axisnowDNSManager) findRoutingDomainByName(ctx context.Context, apiBase, token, targetHost string) (*axisnowRemoteRoutingDomain, error) {
	list, err := m.listRoutingDomains(ctx, apiBase, token, targetHost)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if strings.EqualFold(strings.TrimSpace(list[i].Domain), targetHost) && list[i].Status != "deleted" {
			return &list[i], nil
		}
	}
	return nil, nil
}

type axisnowRemoteDNSRecord struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	Type        string `json:"type"`
	GeoISP      string `json:"geo_isp"`
	Content     string `json:"content"`
	SyncStatus  string `json:"sync_status"`
	ThirdRecID  string `json:"third_record_id"`
	DNSRuleUUID string `json:"dns_rule_uuid"`
}

func (m *axisnowDNSManager) queryRecordSyncStatus(ctx context.Context, apiBase, token, targetHost string) string {
	target := normalizeDomainHostname(targetHost)
	if target == "" {
		return ""
	}
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var records []axisnowRemoteDNSRecord
	if _, err := m.apiDo(qCtx, apiBase, token, http.MethodGet, "/dns_records?page=1&per_page=100", nil, &records); err != nil {
		return ""
	}
	hasFailed := false
	hasSyncing := false
	hasSynced := false
	for _, r := range records {
		nameNorm := normalizeDomainHostname(r.Name)
		domNorm := normalizeDomainHostname(r.Domain)
		if nameNorm != target && domNorm != target {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.SyncStatus)) {
		case "sync_failed", "failed":
			hasFailed = true
		case "syncing", "unsynced", "pending":
			hasSyncing = true
		case "synced":
			hasSynced = true
		}
	}
	if hasFailed {
		return "sync_failed"
	}
	if hasSyncing {
		return "syncing"
	}
	if hasSynced {
		return "synced"
	}
	return ""
}

func buildAxisNowTTLConf(providerType, plan string) *axisnowRemoteTTLConf {
	pt := strings.ToLower(strings.TrimSpace(providerType))
	pl := strings.ToLower(strings.TrimSpace(plan))
	switch pt {
	case "alibaba-cloud":
		switch pl {
		case "personal", "enterprise-standard", "enterprise-ultimate":
			return &axisnowRemoteTTLConf{ProviderType: "alibaba-cloud", Plan: pl, TTL: 60}
		default:
			return &axisnowRemoteTTLConf{ProviderType: "alibaba-cloud", Plan: "free", TTL: 600}
		}
	case "dnspod", "dnspod-intl":
		switch pl {
		case "expert", "ultra", "professional", "enterprise", "ultimate":
			return &axisnowRemoteTTLConf{ProviderType: pt, Plan: pl, TTL: 60}
		case "plus":
			return &axisnowRemoteTTLConf{ProviderType: pt, Plan: "plus", TTL: 120}
		default:
			return &axisnowRemoteTTLConf{ProviderType: pt, Plan: "free", TTL: 600}
		}
	case "cloudflare":
		return &axisnowRemoteTTLConf{ProviderType: "cloudflare", TTL: 60}
	case "aws-route53":
		return &axisnowRemoteTTLConf{ProviderType: "aws-route53", TTL: 60}
	case "huawei-cloud":
		return &axisnowRemoteTTLConf{ProviderType: "huawei-cloud", TTL: 60}
	case "self-hosted":
		return &axisnowRemoteTTLConf{ProviderType: "self-hosted", TTL: 60}
	case "cloudns":
		return &axisnowRemoteTTLConf{ProviderType: "cloudns", TTL: 300}
	default:
		return nil
	}
}

func syncDomainMetaFromRemote(cfg *edgeDomainSmartDNS, remote axisnowRemoteRoutingDomain) {
	if cfg == nil {
		return
	}
	if remote.Domain != "" {
		cfg.RoutingDomainHost = normalizeDomainHostname(remote.Domain)
	}
	if remote.ProviderType != "" {
		cfg.ProviderType = strings.TrimSpace(remote.ProviderType)
	}
	if remote.ZoneConf != nil {
		if remote.ZoneConf.Plan != "" {
			cfg.ZonePlan = strings.TrimSpace(remote.ZoneConf.Plan)
		}
		if remote.ZoneConf.Zone != "" && cfg.ZoneName == "" {
			cfg.ZoneName = normalizeDomainHostname(remote.ZoneConf.Zone)
		}
	}
}

var axisnowDescOwnerTagRe = regexp.MustCompile(`\[([A-Za-z0-9_-]+)\]`)

func axisnowRoutingDomainExactOwner(desc, domID string) bool {
	if domID == "" || !strings.HasPrefix(desc, axisnowManagedDescPrefix) {
		return false
	}
	return strings.Contains(desc, "["+domID+"]")
}

func extractAxisNowManagedOwnerTag(desc string) string {
	if !strings.HasPrefix(desc, axisnowManagedDescPrefix) {
		return ""
	}
	m := axisnowDescOwnerTagRe.FindStringSubmatch(desc)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func extractAxisNowLegacyManagedHost(desc string) string {
	if !strings.HasPrefix(desc, axisnowManagedDescPrefix) || strings.Contains(desc, "[") {
		return ""
	}
	start := strings.LastIndex(desc, "(")
	end := strings.LastIndex(desc, ")")
	if start < 0 || end <= start+1 {
		return ""
	}
	return normalizeDomainHostname(desc[start+1 : end])
}

func (m *axisnowDNSManager) deleteRoutingDomainCascade(ctx context.Context, apiBase, token, routingUUID string) error {
	if routingUUID == "" {
		return nil
	}
	if rules, err := m.listRulesForDomain(ctx, apiBase, token, routingUUID); err == nil {
		for _, rr := range rules {
			if rr.UUID == "" {
				continue
			}
			_, _ = m.apiDo(ctx, apiBase, token, http.MethodDelete, "/dns_routing_rules/"+url.PathEscape(rr.UUID), nil, nil)
		}
	}
	status, err := m.apiDo(ctx, apiBase, token, http.MethodDelete, "/dns_routing_domains/"+url.PathEscape(routingUUID), nil, nil)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}

func axisnowRoutingDomainMatchesProvider(item axisnowRemoteRoutingDomain, cfg *edgeDomainSmartDNS) bool {
	if cfg == nil {
		return false
	}
	if cfg.ProviderSource != "" && item.ProviderSource != "" && !strings.EqualFold(item.ProviderSource, cfg.ProviderSource) {
		return false
	}
	if cfg.ProviderUUID != "" && item.DNSProviderID != "" && item.DNSProviderID != cfg.ProviderUUID {
		return false
	}
	if cfg.ZoneUUID != "" && item.DNSZoneID != "" && item.DNSZoneID != cfg.ZoneUUID {
		return false
	}
	return true
}

func (m *axisnowDNSManager) ensureRoutingDomain(ctx context.Context, apiBase, token string, dom edgeDomainRecord, cfg *edgeDomainSmartDNS) (result axisnowRemoteRoutingDomain, retErr error) {
	prevUUID := cfg.RoutingDomainUUID
	prevHost := normalizeDomainHostname(cfg.RoutingDomainHost)
	ownerKey, isSharedProfile := axisnowRoutingOwnerKey(dom, cfg)
	defer func() {
		if retErr != nil {
			return
		}
		if (prevHost != "" && !strings.EqualFold(prevHost, cfg.RoutingDomainHost)) || (prevUUID != "" && prevUUID != cfg.RoutingDomainUUID) {
			cfg.CFCNAMESynced = false
			cfg.CFCNAMEStatus = ""
			cfg.CFCNAMEStatusNote = ""
			cfg.CFCNAMECheckedAt = 0
		}
		if prevUUID != "" && prevUUID != cfg.RoutingDomainUUID {
			for i := range cfg.Lines {
				cfg.Lines[i].AxisNowRuleUUID = ""
			}
		}
	}()

	// Platform Smart DNS profiles share a single AxisNow routing domain across all bound Edge Domains
	// to preserve free-tier tenant routing domain quota (e.g., 5 domains on AxisNow Managed DNS) and
	// enable instant CNAME cutover for newly bound domains.
	if isSharedProfile && cfg.RoutingDomainUUID == "" {
		if sibUUID, sibHost, sibRules := m.findSiblingSharedRoutingDomain(ctx, dom, cfg); sibUUID != "" {
			var existing axisnowRemoteRoutingDomain
			if _, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/dns_routing_domains/"+url.PathEscape(sibUUID), nil, &existing); err == nil && existing.UUID != "" && existing.Status != "deleted" && axisnowRoutingDomainMatchesProvider(existing, cfg) {
				cfg.RoutingDomainUUID = existing.UUID
				syncDomainMetaFromRemote(cfg, existing)
				if cfg.RoutingDomainHost == "" {
					cfg.RoutingDomainHost = sibHost
				}
				for i := range cfg.Lines {
					if cfg.Lines[i].AxisNowRuleUUID == "" {
						if rUUID, ok := sibRules[cfg.Lines[i].GeoISP]; ok {
							cfg.Lines[i].AxisNowRuleUUID = rUUID
						}
					}
				}
				return existing, nil
			}
		}
	}

	// Auto-migrate legacy Refract-generated platform routing domains that accidentally contained
	// RFC-invalid underscores (e.g. "emby-dom_39.alidns-2.com") to a clean RFC-1123 hostname.
	if cfg.ProviderSource == "platform" && strings.Contains(cfg.RoutingDomainHost, "_") {
		if cfg.RoutingDomainUUID != "" {
			var legacy axisnowRemoteRoutingDomain
			if _, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/dns_routing_domains/"+url.PathEscape(cfg.RoutingDomainUUID), nil, &legacy); err == nil {
				if axisnowRoutingDomainExactOwner(legacy.Description, ownerKey) ||
					axisnowRoutingDomainExactOwner(legacy.Description, dom.ID) ||
					(strings.HasPrefix(legacy.Description, axisnowManagedDescPrefix) && !strings.Contains(legacy.Description, "[dm_")) {
					_ = m.deleteRoutingDomainCascade(ctx, apiBase, token, cfg.RoutingDomainUUID)
				}
			}
		}
		cfg.RoutingDomainUUID = ""
		cfg.RoutingDomainHost = ""
		cfg.CFCNAMESynced = false
		cfg.CFCNAMEStatus = ""
		cfg.CFCNAMEStatusNote = ""
		cfg.CFCNAMECheckedAt = 0
		for i := range cfg.Lines {
			cfg.Lines[i].AxisNowRuleUUID = ""
		}
	}

	// Reconcile any duplicate or legacy-underscore Refract-managed routing domains owned strictly by this ownerKey
	// (either the shared ProfileID in platform mode or dom.ID) so previous sync retries never leave orphaned
	// domains consuming platform quota (100321), while NEVER touching domains owned by other Refract profiles/domains.
	allDomains, listErr := m.listRoutingDomains(ctx, apiBase, token, "")
	if listErr == nil && len(allDomains) > 0 {
		var ownedValid []axisnowRemoteRoutingDomain
		for _, item := range allDomains {
			if item.Status == "deleted" || item.UUID == "" {
				continue
			}
			exactOwned := axisnowRoutingDomainExactOwner(item.Description, ownerKey) ||
				(!isSharedProfile && axisnowRoutingDomainExactOwner(item.Description, dom.ID))
			linkedExisting := cfg.RoutingDomainUUID != "" && item.UUID == cfg.RoutingDomainUUID &&
				strings.HasPrefix(item.Description, axisnowManagedDescPrefix)
			if !exactOwned && !linkedExisting {
				continue
			}
			// Delete any legacy platform routing domains with invalid underscores owned by this exact owner
			if exactOwned && cfg.ProviderSource == "platform" && (item.ProviderSource == "" || item.ProviderSource == "platform") && strings.Contains(item.Domain, "_") {
				_ = m.deleteRoutingDomainCascade(ctx, apiBase, token, item.UUID)
				continue
			}
			if axisnowRoutingDomainMatchesProvider(item, cfg) {
				ownedValid = append(ownedValid, item)
			}
		}
		if len(ownedValid) > 0 {
			// Prefer the currently linked UUID, else the one matching our target host, else the first valid one.
			chosenIdx := 0
			for i, item := range ownedValid {
				if cfg.RoutingDomainUUID != "" && item.UUID == cfg.RoutingDomainUUID {
					chosenIdx = i
					break
				}
				if cfg.RoutingDomainHost != "" && strings.EqualFold(item.Domain, cfg.RoutingDomainHost) {
					chosenIdx = i
				}
			}
			chosen := ownedValid[chosenIdx]
			for i, item := range ownedValid {
				if i == chosenIdx {
					continue
				}
				if axisnowRoutingDomainExactOwner(item.Description, ownerKey) && !m.routingDomainUsedByOtherDomain(ctx, dom.ID, item.UUID) {
					_ = m.deleteRoutingDomainCascade(ctx, apiBase, token, item.UUID)
				}
			}
			cfg.RoutingDomainUUID = chosen.UUID
			syncDomainMetaFromRemote(cfg, chosen)
			return chosen, nil
		}
	}

	if cfg.RoutingDomainUUID != "" {
		var existing axisnowRemoteRoutingDomain
		status, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/dns_routing_domains/"+url.PathEscape(cfg.RoutingDomainUUID), nil, &existing)
		if err == nil && existing.UUID != "" && existing.Status != "deleted" {
			if axisnowRoutingDomainMatchesProvider(existing, cfg) {
				syncDomainMetaFromRemote(cfg, existing)
				return existing, nil
			}
			// Provider or zone changed; provision a fresh routing domain for the new target.
			cfg.RoutingDomainUUID = ""
		} else if status != http.StatusNotFound && existing.Status != "deleted" {
			if err != nil {
				return axisnowRemoteRoutingDomain{}, err
			}
			// Keep existing UUID on unexpected empty response rather than creating duplicates.
			return axisnowRemoteRoutingDomain{UUID: cfg.RoutingDomainUUID, Domain: cfg.RoutingDomainHost}, nil
		} else {
			cfg.RoutingDomainUUID = ""
		}
	}

	explicitHost := normalizeDomainHostname(cfg.RoutingDomainHost) != ""
	targetHost := normalizeDomainHostname(cfg.RoutingDomainHost)
	if targetHost == "" {
		if isSharedProfile {
			targetHost = buildPlatformProfileRoutingDomainHost(cfg.ProfileID, cfg.ZoneName)
		} else if cfg.ProviderSource == "platform" {
			targetHost = buildPlatformRoutingDomainHost(dom, cfg.ZoneName)
		} else {
			targetHost = edgeDomainBaseHost(dom.Domain)
		}
	}
	if targetHost == "" {
		return axisnowRemoteRoutingDomain{}, errors.New("智能 DNS 调度域不能为空，请先在设置或域名中选择托管调度域")
	}

	// Reuse existing routing domain only when it belongs to this owner (or is untagged/explicitly specified and not owned by another domain/profile).
	if found, err := m.findRoutingDomainByName(ctx, apiBase, token, targetHost); err == nil && found != nil {
		ownedByOther := (strings.Contains(found.Description, "[dm_") || strings.Contains(found.Description, "[dom_") || strings.Contains(found.Description, "[sdp_")) &&
			!axisnowRoutingDomainExactOwner(found.Description, ownerKey) &&
			!axisnowRoutingDomainExactOwner(found.Description, dom.ID)
		isManaged := strings.HasPrefix(found.Description, axisnowManagedDescPrefix)
		sameProvider := axisnowRoutingDomainMatchesProvider(*found, cfg)
		if !ownedByOther && (isManaged || explicitHost) && sameProvider {
			cfg.RoutingDomainUUID = found.UUID
			syncDomainMetaFromRemote(cfg, *found)
			if cfg.RoutingDomainHost == "" {
				cfg.RoutingDomainHost = normalizeDomainHostname(found.Domain)
			}
			return *found, nil
		}
	}

	createDomain := func(host string) (axisnowRemoteRoutingDomain, error) {
		displayName := dom.Name
		descTarget := dom.Domain
		if isSharedProfile {
			if strings.TrimSpace(cfg.ProfileName) != "" {
				displayName = cfg.ProfileName
				descTarget = cfg.ProfileName
			}
		}
		payload := map[string]any{
			"name":              truncateRunes("Refract · "+displayName, 64),
			"description":       fmt.Sprintf("%s [%s] (%s)", axisnowManagedDescPrefix, ownerKey, descTarget),
			"domain":            host,
			"dns_provider_uuid": cfg.ProviderUUID,
			"record_type":       "A",
			"provider_source":   cfg.ProviderSource,
		}
		if cfg.ZoneUUID != "" {
			payload["dns_zone_uuid"] = cfg.ZoneUUID
		}
		var created axisnowRemoteRoutingDomain
		_, err := m.apiDo(ctx, apiBase, token, http.MethodPost, "/dns_routing_domains", payload, &created)
		return created, err
	}

	created, err := createDomain(targetHost)
	// If an auto-generated hostname collides on a shared platform zone (100609: domain already in use),
	// retry with a fresh random hex suffix so shared-zone collisions never block provisioning.
	if err != nil && !explicitHost && cfg.ProviderSource == "platform" && strings.Contains(err.Error(), "100609") {
		if randHex, rErr := generateRandomHex(3); rErr == nil && cfg.ZoneName != "" {
			zone := normalizeDomainHostname(cfg.ZoneName)
			label := strings.TrimSuffix(targetHost, "."+zone)
			if len(label) > 24 {
				label = strings.TrimRight(label[:24], "-")
			}
			altHost := label + "-" + randHex + "." + zone
			if altCreated, altErr := createDomain(altHost); altErr == nil {
				created = altCreated
				targetHost = altHost
				err = nil
			}
		}
	}
	if err != nil {
		return axisnowRemoteRoutingDomain{}, err
	}
	cfg.RoutingDomainUUID = created.UUID
	syncDomainMetaFromRemote(cfg, created)
	if cfg.RoutingDomainHost == "" {
		cfg.RoutingDomainHost = targetHost
	}
	return created, nil
}

func (m *axisnowDNSManager) listRulesForDomain(ctx context.Context, apiBase, token, routingDomainUUID string) ([]axisnowRemoteRuleEntity, error) {
	var list []axisnowRemoteRuleEntity
	_, err := m.apiDo(ctx, apiBase, token, http.MethodPost, "/dns_routing_rules/filter", map[string]any{
		"page":     1,
		"per_page": 200,
		"filter": map[string]any{
			"or": []any{
				map[string]any{
					"and": []any{
						map[string]any{
							"field":    "dns_domain_uuid",
							"operator": "in",
							"value":    []string{routingDomainUUID},
						},
					},
				},
			},
		},
	}, &list)
	if err != nil {
		return nil, err
	}
	filtered := make([]axisnowRemoteRuleEntity, 0, len(list))
	for _, rr := range list {
		if rr.DNSDomainUUID != "" && rr.DNSDomainUUID != routingDomainUUID {
			continue
		}
		if rr.Type != "" && !strings.EqualFold(rr.Type, "A") {
			continue
		}
		filtered = append(filtered, rr)
	}
	return filtered, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func remoteRuleMatchesDesired(existing axisnowRemoteRuleEntity, desired axisnowRemoteRulePayload) bool {
	if existing.GeoISP != desired.GeoISP || existing.Status != desired.Status || existing.AutoPauseOnEmpty != desired.AutoPauseOnEmpty {
		return false
	}
	if existing.Action.Method != desired.Action.Method {
		return false
	}
	ec := existing.Action.Conf
	dc := desired.Action.Conf
	if ec.ResponseStrategy.ElectionStrategy != dc.ResponseStrategy.ElectionStrategy ||
		ec.ResponseStrategy.IPQuantity != dc.ResponseStrategy.IPQuantity {
		return false
	}
	if dc.TTLConf != nil {
		if ec.TTLConf == nil || !strings.EqualFold(ec.TTLConf.ProviderType, dc.TTLConf.ProviderType) || ec.TTLConf.TTL != dc.TTLConf.TTL {
			return false
		}
		if dc.TTLConf.Plan != "" && !strings.EqualFold(ec.TTLConf.Plan, dc.TTLConf.Plan) {
			return false
		}
	}
	if ec.AddressPool.Mode != dc.AddressPool.Mode || len(ec.AddressPool.Groups) != 1 || len(dc.AddressPool.Groups) != 1 {
		return false
	}
	eg := ec.AddressPool.Groups[0]
	dg := dc.AddressPool.Groups[0]
	return eg.Type == dg.Type && equalStringSlices(eg.IPs, dg.IPs)
}

func (m *axisnowDNSManager) updateSyncStatus(ctx context.Context, lastSyncAt int64, lastErr string) {
	if m == nil || m.store == nil {
		return
	}
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	fresh := m.store.LoadAxisNowDNS(ctx)
	if lastSyncAt > 0 {
		fresh.LastSyncAt = lastSyncAt
	}
	fresh.LastError = truncateRunes(lastErr, 200)
	_ = m.store.SaveAxisNowDNS(ctx, fresh)
}

func computeSmartDNSDesiredHash(dom edgeDomainRecord, cfg *edgeDomainSmartDNS, healthyIPv4 map[string]string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "d=%s|host=%s|p=%s|src=%s|z=%s|rh=%s|ru=%s|cf=%t|",
		dom.ID, dom.Domain, cfg.ProviderUUID, cfg.ProviderSource, cfg.ZoneUUID,
		cfg.RoutingDomainHost, cfg.RoutingDomainUUID, cfg.AutoCFCNAME)
	for _, l := range cfg.Lines {
		ips := make([]string, 0, len(l.NodeIDs))
		seen := make(map[string]struct{}, len(l.NodeIDs))
		for _, nid := range l.NodeIDs {
			if ip, ok := healthyIPv4[nid]; ok {
				if _, dup := seen[ip]; !dup {
					seen[ip] = struct{}{}
					ips = append(ips, ip)
				}
			}
		}
		_, _ = fmt.Fprintf(h, "%s:%t:%t:%s:%d:%s;", l.GeoISP, l.Enabled, l.AutoPauseOnEmpty, l.ElectionStrategy, l.IPQuantity, strings.Join(ips, ","))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (m *axisnowDNSManager) routingDomainUsedByOtherDomain(ctx context.Context, excludeDomID, routingUUID string) bool {
	if m == nil || m.store == nil || routingUUID == "" {
		return false
	}
	others, err := m.store.ListEdgeDomains(ctx)
	if err != nil {
		return true // Fail closed: never delete if DB list fails
	}
	for _, o := range others {
		if o.ID != excludeDomID && o.DNSMode == domainDNSAxisNowSmart && o.SmartDNS != nil && o.SmartDNS.RoutingDomainUUID == routingUUID {
			return true
		}
	}
	return false
}

func axisnowRuleOwnedByDomain(desc, domID string, sharedProfileID ...string) bool {
	if !strings.HasPrefix(desc, axisnowManagedDescPrefix) {
		return false
	}
	profID := ""
	if len(sharedProfileID) > 0 {
		profID = strings.TrimSpace(sharedProfileID[0])
	}
	// On a shared profile routing domain, any Refract-managed rule under that routing domain
	// (whether tagged with [sdp_...] or an earlier sibling [dm_...]/[dom_...]) belongs to the profile.
	if profID != "" {
		return true
	}
	// If the description contains a scoped domain tag [dm_...], enforce exact domain ownership.
	if idx := strings.Index(desc, "[dm_"); idx >= 0 {
		if end := strings.IndexByte(desc[idx:], ']'); end > 0 {
			tagID := desc[idx+1 : idx+end]
			return tagID == domID
		}
	}
	return true
}

var reservedDNSProbePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // RFC 1122 "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598 CGNAT (common ISP DNS hijack target)
	netip.MustParsePrefix("198.18.0.0/15"),  // RFC 2544 Benchmarking / FakeIP (Clash/Mihomo/Surge)
	netip.MustParsePrefix("240.0.0.0/4"),    // RFC 1112 Reserved
	netip.MustParsePrefix("100::/64"),       // RFC 6666 Discard
	netip.MustParsePrefix("64:ff9b::/96"),   // RFC 6052 NAT64
	netip.MustParsePrefix("2001::/32"),      // RFC 4380 Teredo
	netip.MustParsePrefix("2001:db8::/32"),  // RFC 3849 Documentation
	netip.MustParsePrefix("2002::/16"),      // RFC 3056 6to4
	netip.MustParsePrefix("fec0::/10"),      // Deprecated site-local
}

func isPublicRoutableDNSAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	for _, p := range reservedDNSProbePrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func filterPublicDNSIPs(addrs []net.IPAddr) []string {
	out := make([]string, 0, len(addrs))
	seen := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok || !isPublicRoutableDNSAddr(ip) {
			continue
		}
		s := ip.Unmap().String()
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func filterPublicRawIPs(rawIPs []net.IP) []string {
	addrs := make([]net.IPAddr, 0, len(rawIPs))
	for _, ip := range rawIPs {
		addrs = append(addrs, net.IPAddr{IP: ip})
	}
	return filterPublicDNSIPs(addrs)
}

func lookupNSWithFallback(ctx context.Context, nameFQDN string) []string {
	resolvers := []string{"1.1.1.1:53", "223.5.5.5:53", "8.8.8.8:53"}
	for _, srv := range resolvers {
		if ctx.Err() != nil {
			return nil
		}
		qCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1200 * time.Millisecond}
				return d.DialContext(dialCtx, network, srv)
			},
		}
		nss, err := res.LookupNS(qCtx, nameFQDN)
		cancel()
		if err == nil && len(nss) > 0 {
			out := make([]string, 0, len(nss))
			for _, ns := range nss {
				h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
				if h != "" {
					out = append(out, h)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func lookupNSPublicIPs(ctx context.Context, nsHost string) []string {
	nsFQDN := strings.TrimSuffix(strings.TrimSpace(nsHost), ".") + "."
	resolvers := []string{"1.1.1.1:53", "223.5.5.5:53", "8.8.8.8:53"}
	for _, srv := range resolvers {
		if ctx.Err() != nil {
			return nil
		}
		qCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1200 * time.Millisecond}
				return d.DialContext(dialCtx, network, srv)
			},
		}
		rawIPs, err := res.LookupIPAddr(qCtx, nsFQDN)
		cancel()
		if err != nil || len(rawIPs) == 0 {
			continue
		}
		var v4, v6 []string
		for _, a := range rawIPs {
			addr, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if isBlockedAddress(addr) || !isPublicRoutableDNSAddr(addr) {
				continue
			}
			if addr.Is4() {
				v4 = append(v4, addr.String())
			} else {
				v6 = append(v6, addr.String())
			}
		}
		ordered := append(v4, v6...)
		if len(ordered) > 0 {
			return ordered
		}
	}
	return nil
}

// probeAuthoritativeNS queries the authoritative nameservers of host's zone directly
// so we can verify whether AxisNow has pushed the record WITHOUT triggering negative NXDOMAIN
// caching on public recursive resolvers (1.1.1.1 / 8.8.8.8 / 223.5.5.5).
func probeAuthoritativeNS(ctx context.Context, host string) (checked bool, ips []string) {
	host = normalizeDomainHostname(host)
	if host == "" || net.ParseIP(host) != nil || !validRuleDomain(host) {
		return false, nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false, nil
	}
	fqdn := host + "."

	var nsHosts []string
	if len(parts) == 2 {
		// 2-label apex (e.g. example.com): query NS of the zone directly (never queries A record on recursive DNS).
		nsHosts = lookupNSWithFallback(ctx, fqdn)
	} else {
		// Walk parent labels from direct parent up to registrable zone (e.g. a.b.alidns-2.com -> b.alidns-2.com -> alidns-2.com)
		for i := 1; i <= len(parts)-2; i++ {
			zoneFQDN := strings.Join(parts[i:], ".") + "."
			nsHosts = lookupNSWithFallback(ctx, zoneFQDN)
			if len(nsHosts) > 0 {
				break
			}
		}
	}
	if len(nsHosts) == 0 {
		return false, nil
	}

	queryAgainstNS := func(candidates []string, allowDelegationFollow bool) (bool, []string, []string) {
		if len(candidates) > 2 {
			candidates = candidates[:2]
		}
		var subChecked bool
		seenIP := make(map[string]struct{})
		var foundIPs []string
		for _, nsHost := range candidates {
			if ctx.Err() != nil {
				break
			}
			nsIPs := lookupNSPublicIPs(ctx, nsHost)
			if len(nsIPs) == 0 {
				continue
			}
			maxTry := len(nsIPs)
			if maxTry > 2 {
				maxTry = 2
			}
			for _, nsIP := range nsIPs[:maxTry] {
				if ctx.Err() != nil {
					break
				}
				nsAddr := net.JoinHostPort(nsIP, "53")
				authRes := &net.Resolver{
					PreferGo: true,
					Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
						d := net.Dialer{Timeout: 1200 * time.Millisecond}
						return d.DialContext(dialCtx, network, nsAddr)
					},
				}
				aCtx, aCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
				rawIPs, aErr := authRes.LookupIP(aCtx, "ip4", fqdn)
				aCancel()
				if aErr != nil {
					var dnsErr *net.DNSError
					if errors.As(aErr, &dnsErr) && dnsErr.IsNotFound {
						// If host is a delegated subzone or 3-label 2nd-level TLD (e.g. myzone.co.uk),
						// parent NS returns a NOERROR delegation referral (0 answers). Follow delegation NS directly!
						if allowDelegationFollow {
							dCtx, dCancel := context.WithTimeout(ctx, 1200*time.Millisecond)
							delegNS, dErr := authRes.LookupNS(dCtx, fqdn)
							dCancel()
							if dErr == nil && len(delegNS) > 0 {
								var nextNS []string
								for _, ns := range delegNS {
									h := strings.TrimSuffix(strings.TrimSpace(ns.Host), ".")
									if h != "" {
										nextNS = append(nextNS, h)
									}
								}
								if len(nextNS) > 0 {
									return false, nil, nextNS
								}
							}
						}
						subChecked = true
						break // authoritative NS answered cleanly; no need to try alternate IP of same NS
					}
					continue // network/IPv6 dial error -> try next IP of this NS
				}
				subChecked = true
				for _, ip := range filterPublicRawIPs(rawIPs) {
					if _, ok := seenIP[ip]; !ok {
						seenIP[ip] = struct{}{}
						foundIPs = append(foundIPs, ip)
					}
				}
				if len(foundIPs) > 0 {
					sort.Strings(foundIPs)
					return true, foundIPs, nil
				}
				break
			}
		}
		return subChecked, foundIPs, nil
	}

	subChecked, foundIPs, delegatedNS := queryAgainstNS(nsHosts, true)
	if len(delegatedNS) > 0 {
		subChecked, foundIPs, _ = queryAgainstNS(delegatedNS, false)
	}
	return subChecked, foundIPs
}

// probeAxisNowCNAMEReadiness performs a two-stage readiness check before switching Cloudflare DNS:
//  1. Query the zone's authoritative NS first (never caches NXDOMAIN) so we do NOT poison
//     public recursive resolvers with stale NXDOMAIN while AxisNow is still pushing records.
//  2. Once authoritative NS returns valid public IP(s), confirm across independent public
//     recursive resolvers (1.1.1.1 / 8.8.8.8 / 223.5.5.5) without pinning to a specific node IP
//     so geo/ISP split routing works identically from overseas or mainland controllers.
func probeAxisNowCNAMEReadiness(ctx context.Context, host string) (ready bool, resolvedIPs []string, detail string) {
	host = normalizeDomainHostname(host)
	if host == "" {
		return false, nil, "缺少 AxisNow 调度域名"
	}
	if net.ParseIP(host) != nil || !validRuleDomain(host) {
		return false, nil, "AxisNow 调度域名格式无效，无法执行解析检测"
	}
	// Cap total probe time per domain so slow DNS never exhausts the 12s monitor cycle deadline.
	totalCtx, totalCancel := context.WithTimeout(ctx, 4500*time.Millisecond)
	defer totalCancel()

	authCtx, authCancel := context.WithTimeout(totalCtx, 2500*time.Millisecond)
	authChecked, authIPs := probeAuthoritativeNS(authCtx, host)
	authCancel()
	if authChecked && len(authIPs) == 0 {
		return false, nil, "等待 AxisNow 推送记录至权威 DNS，暂保留原 Cloudflare 记录"
	}

	type probeResult struct {
		reachable bool
		ips       []string
	}
	fqdn := host + "."
	servers := []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"}
	results := make([]probeResult, len(servers))
	var wg sync.WaitGroup
	for i, addr := range servers {
		wg.Add(1)
		go func(idx int, serverAddr string) {
			defer wg.Done()
			probeCtx, cancel := context.WithTimeout(totalCtx, 2*time.Second)
			defer cancel()
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
					d := net.Dialer{Timeout: 1500 * time.Millisecond}
					return d.DialContext(dialCtx, network, serverAddr)
				},
			}
			rawIPs, err := resolver.LookupIP(probeCtx, "ip4", fqdn)
			if err != nil {
				var dnsErr *net.DNSError
				if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
					results[idx] = probeResult{reachable: true}
				}
				return
			}
			results[idx] = probeResult{reachable: true, ips: filterPublicRawIPs(rawIPs)}
		}(i, addr)
	}
	wg.Wait()

	reachableCount := 0
	resolvedCount := 0
	seenIP := make(map[string]struct{})
	ips := make([]string, 0, 4)
	for _, r := range results {
		if r.reachable {
			reachableCount++
		}
		if len(r.ips) > 0 {
			resolvedCount++
			for _, ip := range r.ips {
				if _, ok := seenIP[ip]; !ok {
					seenIP[ip] = struct{}{}
					ips = append(ips, ip)
				}
			}
		}
	}

	if reachableCount == 0 {
		if len(authIPs) > 0 {
			return true, authIPs, fmt.Sprintf("权威 DNS 已解析（%s）", strings.Join(authIPs, ", "))
		}
		probeCtx, cancel := context.WithTimeout(totalCtx, 1500*time.Millisecond)
		defer cancel()
		if rawIPs, err := net.DefaultResolver.LookupIP(probeCtx, "ip4", fqdn); err == nil {
			if valid := filterPublicRawIPs(rawIPs); len(valid) > 0 {
				return true, valid, fmt.Sprintf("系统 DNS 已解析（%s）", strings.Join(valid, ", "))
			}
		}
		return false, nil, "等待 AxisNow 解析生效（公网 DNS 暂未解析出有效 IP），暂保留原 Cloudflare 记录"
	}

	sort.Strings(ips)
	required := 2
	if reachableCount < 2 {
		required = reachableCount
	}
	if resolvedCount >= required && len(ips) > 0 {
		return true, ips, fmt.Sprintf("公网 DNS %d/%d 已解析（%s）", resolvedCount, reachableCount, strings.Join(ips, ", "))
	}
	if len(authIPs) > 0 {
		return false, authIPs, fmt.Sprintf("权威 DNS 已生效（%s），等待公网递归 DNS 刷新（%d/%d），暂保留原 Cloudflare 记录", strings.Join(authIPs, ", "), resolvedCount, reachableCount)
	}
	return false, ips, fmt.Sprintf("等待 AxisNow 解析生效（公网 DNS %d/%d 已解析），暂保留原 Cloudflare 记录", resolvedCount, reachableCount)
}

func (m *axisnowDNSManager) SyncEdgeDomainSmartDNS(ctx context.Context, dom edgeDomainRecord, now time.Time) error {
	return m.syncEdgeDomainSmartDNS(ctx, dom, now, true)
}

func (m *axisnowDNSManager) syncEdgeDomainSmartDNS(ctx context.Context, dom edgeDomainRecord, now time.Time, force bool) error {
	if m == nil || m.gateway == nil || m.gateway.cluster == nil {
		return nil
	}
	if dom.DNSMode != domainDNSAxisNowSmart || !dom.Enabled {
		return nil
	}

	// Serialize concurrent syncs: for platform Smart DNS profiles, serialize on the shared profile key
	// so two newly bound domains never race to provision duplicate AxisNow routing domains.
	lockKey := dom.ID
	if dom.SmartDNS != nil && strings.TrimSpace(dom.SmartDNS.ProfileID) != "" && normalizeAxisNowProviderSource(dom.SmartDNS.ProviderSource) == "platform" {
		lockKey = "prof:" + strings.TrimSpace(dom.SmartDNS.ProfileID)
	}
	unlockDom := m.lockDomain(lockKey)
	defer unlockDom()

	m.mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			m.mu.Unlock()
		}
	}
	defer unlock()

	// Always reload fresh domain record inside the critical section so stale snapshots
	// never overwrite concurrent admin edits or recreate deleted domains.
	if freshDom, err := m.store.GetEdgeDomain(ctx, dom.ID); err == nil {
		dom = freshDom
		if dom.DNSMode != domainDNSAxisNowSmart || !dom.Enabled {
			return nil
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	origUpdatedAt := dom.UpdatedAt
	origDomain := dom.Domain

	stored, token, apiBase, err := m.activeCredentials(ctx)
	if err != nil {
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, dom.DNSActiveNodeID, dom.DNSLastSyncAt, err.Error())
		return err
	}
	if !stored.Enabled || token == "" {
		msg := "AxisNow 智能 DNS 尚未启用或未配置 Token"
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, dom.DNSActiveNodeID, dom.DNSLastSyncAt, msg)
		return errors.New(msg)
	}

	cfg := normalizeEdgeDomainSmartDNS(dom.SmartDNS, dom.NodeIDs, dom.SmartDNS)
	if cfg == nil {
		cfg = normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{}, dom.NodeIDs, nil)
	}
	if cfg.ProfileID != "" {
		if prof, pErr := m.store.GetSmartDNSProfile(ctx, cfg.ProfileID); pErr == nil {
			cfg = applySmartDNSProfileToDomain(prof, cfg, false)
		}
	}
	if cfg.ProviderUUID == "" {
		cfg.ProviderUUID = stored.DefaultProviderUUID
		cfg.ProviderSource = normalizeAxisNowProviderSource(stored.DefaultProviderSource)
		cfg.ProviderType = stored.DefaultProviderType
		cfg.ZoneUUID = stored.DefaultZoneUUID
		cfg.ZoneName = stored.DefaultZoneName
		cfg.ZonePlan = stored.DefaultZonePlan
	} else if cfg.ProviderType == "" || cfg.ZonePlan == "" {
		for _, p := range stored.CachedProviders {
			if p.UUID == cfg.ProviderUUID {
				if cfg.ProviderType == "" {
					cfg.ProviderType = p.Type
				}
				for _, z := range p.Zones {
					if (cfg.ZoneUUID != "" && z.UUID == cfg.ZoneUUID) || (cfg.ZoneName != "" && strings.EqualFold(z.Zone, cfg.ZoneName)) {
						if cfg.ZonePlan == "" {
							cfg.ZonePlan = z.Plan
						}
						if cfg.ZoneName == "" {
							cfg.ZoneName = normalizeDomainHostname(z.Zone)
						}
						break
					}
				}
				break
			}
		}
	}
	if cfg.ProviderUUID == "" {
		msg := "请先在系统设置或域名配置中选择 AxisNow DNS 提供商 / 托管调度域"
		_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, "", dom.DNSLastSyncAt, msg)
		return errors.New(msg)
	}

	nodes, err := m.store.ListEdgeNodes(ctx)
	if err != nil {
		return err
	}
	healthyIPv4 := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if n.TokenHash == "" {
			continue
		}
		status, _ := m.gateway.cluster.nodeStatus(n, now)
		if status != edgeNodeStatusOnline {
			continue
		}
		if n.MonthlyQuotaGB > 0 && n.QuotaAutoDrain {
			quotaBytes := monthlyQuotaGBToBytes(n.MonthlyQuotaGB)
			_, startUnix, _ := billingCycleWindow(now, n.QuotaResetDay)
			used, uErr := m.store.NodeCycleTrafficUsage(ctx, n.ID, startUnix, n.QuotaDirection)
			if uErr == nil && quotaBytes > 0 && used >= quotaBytes {
				continue
			}
		}
		v4, _ := effectiveNodeIPs(n)
		if strings.TrimSpace(v4) != "" {
			healthyIPv4[n.ID] = strings.TrimSpace(v4)
		}
	}

	needsCNAMECutover := cfg.AutoCFCNAME && !cfg.CFCNAMESynced && cfg.RoutingDomainHost != "" && !strings.EqualFold(cfg.RoutingDomainHost, dom.Domain)
	desiredHash := computeSmartDNSDesiredHash(dom, cfg, healthyIPv4)
	skipAxisNowPush := false
	if !force && cfg.RoutingDomainUUID != "" {
		m.syncHashMu.Lock()
		prevHash := m.lastSyncedHash[dom.ID]
		prevAt := m.lastSyncedAt[dom.ID]
		m.syncHashMu.Unlock()
		axisnowHealthy := dom.DNSLastError == "" || cfg.CFCNAMEStatus == "error"
		if axisnowHealthy && prevHash == desiredHash && !prevAt.IsZero() && now.Sub(prevAt) < dnsReconcileInterval {
			if !needsCNAMECutover {
				return nil
			}
			// Back off repeated Cloudflare CNAME failures (e.g. misconfigured CF root_domain) to 60s instead of hammering every 15s.
			if cfg.CFCNAMEStatus == "error" && cfg.CFCNAMECheckedAt > 0 && now.Unix()-cfg.CFCNAMECheckedAt < 60 {
				return nil
			}
			// AxisNow rules are already up to date; only check whether CNAME target has propagated.
			skipAxisNowPush = true
		}
	}

	var firstLineErr error
	var switchLines []string
	defaultPrimaryNode := dom.DNSActiveNodeID

	if !skipAxisNowPush {
		defaultPrimaryNode = ""
		// 1. Ensure AxisNow routing domain exists
		remoteDom, err := m.ensureRoutingDomain(ctx, apiBase, token, dom, cfg)
		if err != nil {
			_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, "", dom.DNSLastSyncAt, err.Error())
			m.updateSyncStatus(ctx, 0, err.Error())
			return err
		}

		// 2. Fetch existing AxisNow rules under this routing domain
		remoteRules, err := m.listRulesForDomain(ctx, apiBase, token, remoteDom.UUID)
		if err != nil {
			_ = m.store.UpdateEdgeDomainDNSState(ctx, dom.ID, "", dom.DNSLastSyncAt, err.Error())
			return err
		}
		remoteByUUID := make(map[string]axisnowRemoteRuleEntity, len(remoteRules))
		remoteByGeo := make(map[string]axisnowRemoteRuleEntity, len(remoteRules))
		for _, rr := range remoteRules {
			remoteByUUID[rr.UUID] = rr
			remoteByGeo[rr.GeoISP] = rr
		}

		// 3. Reconcile lines (default line is guaranteed first by normalizeEdgeDomainSmartDNS)
		desiredGeos := make(map[string]struct{}, len(cfg.Lines))

		for i := range cfg.Lines {
			line := &cfg.Lines[i]
			desiredGeos[line.GeoISP] = struct{}{}

			prevIPs := append([]string(nil), line.ActiveIPs...)
			activeIPs := make([]string, 0, len(line.NodeIDs))
			activeNodeIDs := make([]string, 0, len(line.NodeIDs))
			seenIP := make(map[string]struct{}, len(line.NodeIDs))
			for _, nid := range line.NodeIDs {
				ip, ok := healthyIPv4[nid]
				if !ok {
					continue
				}
				if _, dup := seenIP[ip]; dup {
					continue
				}
				seenIP[ip] = struct{}{}
				activeIPs = append(activeIPs, ip)
				activeNodeIDs = append(activeNodeIDs, nid)
			}

			var existingRule *axisnowRemoteRuleEntity
			if line.AxisNowRuleUUID != "" {
				if r, ok := remoteByUUID[line.AxisNowRuleUUID]; ok {
					cp := r
					existingRule = &cp
				}
			}
			if existingRule == nil {
				if r, ok := remoteByGeo[line.GeoISP]; ok {
					cp := r
					existingRule = &cp
					line.AxisNowRuleUUID = r.UUID
				}
			}

			ownerKey, isSharedProf := axisnowRoutingOwnerKey(dom, cfg)
			descScope := dom.Domain
			if isSharedProf && strings.TrimSpace(cfg.ProfileName) != "" {
				descScope = cfg.ProfileName
			}
			managedDesc := truncateRunes(fmt.Sprintf("%s [%s] (%s · %s)", axisnowManagedDescPrefix, ownerKey, descScope, line.Label), 255)

			// Handle disabled or empty-healthy-pool cases safely
			if !line.Enabled && line.GeoISP != "default" {
				if existingRule != nil && existingRule.Status != "paused" {
					pausePayload := axisnowRemoteRulePayload{
						Domain:           cfg.RoutingDomainHost,
						Type:             "A",
						GeoISP:           line.GeoISP,
						Name:             line.Label,
						Description:      managedDesc,
						DNSDomainUUID:    remoteDom.UUID,
						Action:           existingRule.Action,
						Status:           "paused",
						AutoPauseOnEmpty: line.AutoPauseOnEmpty,
					}
					if _, uErr := m.apiDo(ctx, apiBase, token, http.MethodPut, "/dns_routing_rules/"+url.PathEscape(existingRule.UUID), pausePayload, nil); uErr != nil {
						line.Status = "error"
						line.LastError = truncateRunes("暂停线路失败: "+uErr.Error(), 180)
						if firstLineErr == nil {
							firstLineErr = uErr
						}
						continue
					}
				}
				line.ActiveIPs = nil
				line.ActiveNodeIDs = nil
				line.Status = "paused"
				line.LastError = ""
				continue
			}

			if len(activeIPs) == 0 {
				if line.GeoISP != "default" && line.AutoPauseOnEmpty {
					if existingRule != nil && existingRule.Status != "paused" {
						pausePayload := axisnowRemoteRulePayload{
							Domain:           cfg.RoutingDomainHost,
							Type:             "A",
							GeoISP:           line.GeoISP,
							Name:             line.Label,
							Description:      managedDesc,
							DNSDomainUUID:    remoteDom.UUID,
							Action:           existingRule.Action,
							Status:           "paused",
							AutoPauseOnEmpty: true,
						}
						if _, uErr := m.apiDo(ctx, apiBase, token, http.MethodPut, "/dns_routing_rules/"+url.PathEscape(existingRule.UUID), pausePayload, nil); uErr != nil {
							line.Status = "error"
							line.LastError = truncateRunes("自动暂停失败: "+uErr.Error(), 180)
							if firstLineErr == nil {
								firstLineErr = uErr
							}
							continue
						}
					}
					line.ActiveIPs = nil
					line.ActiveNodeIDs = nil
					line.Status = "paused"
					line.LastError = "无健康在线 IPv4 节点，已自动暂停并回退默认线路"
					continue
				}
				msg := "该线路没有满足条件的健康在线 IPv4 节点"
				line.ActiveIPs = nil
				line.ActiveNodeIDs = nil
				line.Status = "error"
				line.LastError = msg
				if firstLineErr == nil {
					firstLineErr = fmt.Errorf("线路 %s: %s", line.Label, msg)
				}
				continue
			}

			qty := line.IPQuantity
			if qty < 1 {
				qty = 1
			}
			if qty > len(activeIPs) {
				qty = len(activeIPs)
			}
			if qty > 50 {
				qty = 50
			}
			strategy := normalizeSmartDNSElectionStrategy(line.ElectionStrategy)
			ttlConf := buildAxisNowTTLConf(cfg.ProviderType, cfg.ZonePlan)
			payload := axisnowRemoteRulePayload{
				Domain:           cfg.RoutingDomainHost,
				Type:             "A",
				GeoISP:           line.GeoISP,
				Name:             truncateRunes(line.Label, 100),
				Description:      managedDesc,
				DNSDomainUUID:    remoteDom.UUID,
				Status:           "active",
				AutoPauseOnEmpty: line.GeoISP != "default" && line.AutoPauseOnEmpty,
				Action: axisnowRemoteRuleAction{
					Method: "ip_election",
					Conf: axisnowRemoteRuleConf{
						AddressPool: axisnowRemoteAddressPool{
							Mode: "customize",
							Groups: []axisnowRemoteAddressGroup{
								{Type: "ip", IPs: activeIPs},
							},
						},
						ResponseStrategy: axisnowRemoteResponseStrategy{
							ElectionStrategy: strategy,
							IPQuantity:       qty,
						},
						TTLConf: ttlConf,
					},
				},
			}

			if existingRule != nil {
				if !remoteRuleMatchesDesired(*existingRule, payload) {
					var updated axisnowRemoteRuleEntity
					if _, uErr := m.apiDo(ctx, apiBase, token, http.MethodPut, "/dns_routing_rules/"+url.PathEscape(existingRule.UUID), payload, &updated); uErr != nil {
						line.Status = "error"
						line.LastError = truncateRunes(uErr.Error(), 180)
						if firstLineErr == nil {
							firstLineErr = uErr
						}
						continue
					}
				}
				line.AxisNowRuleUUID = existingRule.UUID
			} else {
				var created axisnowRemoteRuleEntity
				if _, cErr := m.apiDo(ctx, apiBase, token, http.MethodPost, "/dns_routing_rules", payload, &created); cErr != nil {
					line.Status = "error"
					line.LastError = truncateRunes(cErr.Error(), 180)
					if firstLineErr == nil {
						firstLineErr = cErr
					}
					continue
				}
				line.AxisNowRuleUUID = created.UUID
			}

			line.ActiveIPs = activeIPs
			line.ActiveNodeIDs = activeNodeIDs
			line.Status = "active"
			line.LastError = ""
			if line.GeoISP == "default" && len(activeNodeIDs) > 0 {
				defaultPrimaryNode = activeNodeIDs[0]
			}
			if len(prevIPs) > 0 && !equalStringSlices(prevIPs, activeIPs) {
				switchLines = append(switchLines, fmt.Sprintf("%s: %s → %s", line.Label, strings.Join(prevIPs, ","), strings.Join(activeIPs, ",")))
			}
		}

		// 4. Clean up removed Refract-managed non-default lines owned by this domain/profile on AxisNow
		sharedProfID := ""
		if _, isShared := axisnowRoutingOwnerKey(dom, cfg); isShared {
			sharedProfID = cfg.ProfileID
		}
		for _, rr := range remoteRules {
			if rr.GeoISP == "default" {
				continue
			}
			if _, keep := desiredGeos[rr.GeoISP]; keep {
				continue
			}
			if axisnowRuleOwnedByDomain(rr.Description, dom.ID, sharedProfID) {
				if _, dErr := m.apiDo(ctx, apiBase, token, http.MethodDelete, "/dns_routing_rules/"+url.PathEscape(rr.UUID), nil, nil); dErr != nil && firstLineErr == nil {
					firstLineErr = dErr
				}
			}
		}
	}

	// Release axisnow.mu BEFORE DNS readiness probing, cloudflare manager, or Telegram alerts.
	axisnowPushErr := firstLineErr
	unlock()

	// 5. Zero-downtime Cloudflare gray-cloud CNAME -> AxisNow RoutingDomainHost
	// Wait until public recursive DNS resolves RoutingDomainHost to valid public IP(s) before
	// replacing existing Cloudflare records; once synced, keep reconciling normally.
	cnameCutoverJustCompleted := false
	if cfg.AutoCFCNAME && cfg.RoutingDomainHost != "" && !strings.EqualFold(cfg.RoutingDomainHost, dom.Domain) {
		if m.gateway.cloudflare != nil && axisnowPushErr == nil {
			readyForCutover := cfg.CFCNAMESynced
			probeDetail := ""
			if !readyForCutover {
				probeFn := m.cnameReadyProbe
				if probeFn == nil {
					probeFn = probeAxisNowCNAMEReadiness
				}
				readyForCutover, _, probeDetail = probeFn(ctx, cfg.RoutingDomainHost)
				cfg.CFCNAMECheckedAt = now.Unix()
				if !readyForCutover {
					if ctx.Err() == nil {
						if recStatus := m.queryRecordSyncStatus(ctx, apiBase, token, cfg.RoutingDomainHost); recStatus != "" {
							switch recStatus {
							case "sync_failed":
								probeDetail = "AxisNow 向 DNS 商同步记录失败（sync_failed），请检查 AxisNow 控制台；暂保留原 Cloudflare 记录"
							case "syncing":
								probeDetail = "AxisNow 正在向 DNS 商推送记录（syncing），" + probeDetail
							case "synced":
								probeDetail = "AxisNow 已推送记录（synced），" + probeDetail
							}
						}
					}
					cfg.CFCNAMESynced = false
					cfg.CFCNAMEStatus = "pending"
					cfg.CFCNAMEStatusNote = truncateRunes(probeDetail, 200)
				}
			}
			if readyForCutover {
				// Re-verify domain still exists, is unchanged, and wants AutoCFCNAME before writing Cloudflare CNAME.
				checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
				curDom, curErr := m.store.GetEdgeDomain(checkCtx, dom.ID)
				checkCancel()
				stillValidForCF := curErr == nil && curDom.DNSMode == domainDNSAxisNowSmart && curDom.Enabled &&
					strings.EqualFold(curDom.Domain, origDomain) && curDom.SmartDNS != nil && curDom.SmartDNS.AutoCFCNAME &&
					(curDom.SmartDNS.RoutingDomainHost == "" || strings.EqualFold(curDom.SmartDNS.RoutingDomainHost, cfg.RoutingDomainHost))
				if stillValidForCF {
					wasSynced := cfg.CFCNAMESynced
					cfCtx, cfCancel := context.WithTimeout(ctx, 8*time.Second)
					if cfCtx.Err() != nil {
						cfCancel()
						cfCtx, cfCancel = context.WithTimeout(context.Background(), 5*time.Second)
					}
					cErr := m.gateway.cloudflare.SyncEdgeDomainCNAME(cfCtx, dom.ID, dom.Domain, cfg.RoutingDomainHost)
					cfCancel()
					cfg.CFCNAMECheckedAt = now.Unix()
					if cErr != nil {
						cfg.CFCNAMESynced = false
						cfg.CFCNAMEStatus = "error"
						cfg.CFCNAMEStatusNote = truncateRunes("Cloudflare CNAME 切换失败: "+cErr.Error(), 200)
						if firstLineErr == nil {
							firstLineErr = fmt.Errorf("Cloudflare CNAME 联动失败: %w", cErr)
						}
					} else {
						cfg.CFCNAMESynced = true
						cfg.CFCNAMEStatus = "synced"
						if !wasSynced {
							cnameCutoverJustCompleted = true
							if probeDetail != "" {
								cfg.CFCNAMEStatusNote = truncateRunes(probeDetail+"，已自动切换 Cloudflare CNAME", 200)
							} else {
								cfg.CFCNAMEStatusNote = "AxisNow 解析已就绪，已自动切换 Cloudflare CNAME"
							}
						} else if cfg.CFCNAMEStatusNote == "" {
							cfg.CFCNAMEStatusNote = "Cloudflare CNAME 已生效"
						}
					}
				}
			}
		}
	} else if !cfg.AutoCFCNAME {
		cfg.CFCNAMESynced = false
		cfg.CFCNAMEStatus = ""
		cfg.CFCNAMEStatusNote = ""
		cfg.CFCNAMECheckedAt = 0
	}

	lastErr := ""
	if firstLineErr != nil {
		lastErr = truncateRunes(firstLineErr.Error(), 200)
	}
	// Always persist DB state using a fresh detached context so an expired monitor cycle ctx never drops state!
	dbCtx, dbCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dbCancel()
	persistedOK := false
	if latestDom, lErr := m.store.GetEdgeDomain(dbCtx, dom.ID); lErr == nil && latestDom.DNSMode == domainDNSAxisNowSmart {
		cfgToSave := cfg
		// If admin edited the domain concurrently while we were probing, merge ONLY safe runtime status onto latestDom.SmartDNS!
		if latestDom.UpdatedAt != origUpdatedAt && latestDom.SmartDNS != nil {
			merged := *latestDom.SmartDNS
			sameProvider := (merged.ProviderUUID == "" || cfg.ProviderUUID == "" || merged.ProviderUUID == cfg.ProviderUUID) &&
				(merged.ZoneUUID == "" || cfg.ZoneUUID == "" || merged.ZoneUUID == cfg.ZoneUUID)
			sameHost := merged.RoutingDomainHost == "" || strings.EqualFold(merged.RoutingDomainHost, cfg.RoutingDomainHost)
			if sameProvider && sameHost && strings.EqualFold(latestDom.Domain, origDomain) {
				if merged.RoutingDomainUUID == "" {
					merged.RoutingDomainUUID = cfg.RoutingDomainUUID
				}
				if merged.RoutingDomainHost == "" {
					merged.RoutingDomainHost = cfg.RoutingDomainHost
				}
				if merged.ProviderType == "" {
					merged.ProviderType = cfg.ProviderType
				}
				if merged.ZonePlan == "" {
					merged.ZonePlan = cfg.ZonePlan
				}
				if merged.AutoCFCNAME {
					merged.CFCNAMESynced = cfg.CFCNAMESynced
					merged.CFCNAMEStatus = cfg.CFCNAMEStatus
					merged.CFCNAMEStatusNote = cfg.CFCNAMEStatusNote
					merged.CFCNAMECheckedAt = cfg.CFCNAMECheckedAt
				}
				byGeo := make(map[string]smartDNSLineRule, len(cfg.Lines))
				for _, l := range cfg.Lines {
					byGeo[l.GeoISP] = l
				}
				mergedLines := make([]smartDNSLineRule, len(merged.Lines))
				copy(mergedLines, merged.Lines)
				for i := range mergedLines {
					if prev, ok := byGeo[mergedLines[i].GeoISP]; ok {
						if mergedLines[i].AxisNowRuleUUID == "" {
							mergedLines[i].AxisNowRuleUUID = prev.AxisNowRuleUUID
						}
						mergedLines[i].ActiveNodeIDs = prev.ActiveNodeIDs
						mergedLines[i].ActiveIPs = prev.ActiveIPs
						mergedLines[i].Status = prev.Status
						mergedLines[i].LastError = prev.LastError
					}
				}
				merged.Lines = mergedLines
			}
			cfgToSave = &merged
		}
		if uErr := m.store.UpdateEdgeDomainSmartDNSState(dbCtx, dom.ID, cfgToSave, defaultPrimaryNode, now.Unix(), lastErr); uErr == nil {
			persistedOK = true
		}
	}
	if !skipAxisNowPush || cnameCutoverJustCompleted || firstLineErr != nil {
		m.updateSyncStatus(dbCtx, now.Unix(), lastErr)
	}

	if axisnowPushErr == nil && !skipAxisNowPush && persistedOK {
		m.syncHashMu.Lock()
		m.lastSyncedHash[dom.ID] = computeSmartDNSDesiredHash(dom, cfg, healthyIPv4)
		m.lastSyncedAt[dom.ID] = now
		m.syncHashMu.Unlock()
	}

	if cnameCutoverJustCompleted {
		m.store.RecordAudit(dbCtx, auditEntry{
			Username: "system",
			Action:   "dns.cname_cutover",
			Resource: dom.Domain,
			Detail:   truncateRunes(fmt.Sprintf("CNAME -> %s (%s)", cfg.RoutingDomainHost, cfg.CFCNAMEStatusNote), 240),
			Success:  true,
		})
		if m.gateway.telegram != nil {
			alertCtx, alertCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = m.gateway.telegram.SendAlert(alertCtx, "dns_failover", "智能 DNS 无中断 CNAME 切换完成", []string{
				fmt.Sprintf("域名：%s (%s)", dom.Domain, dom.Name),
				fmt.Sprintf("CNAME 目标：%s", cfg.RoutingDomainHost),
				fmt.Sprintf("校验结果：%s", cfg.CFCNAMEStatusNote),
			})
			alertCancel()
		}
	}

	if len(switchLines) > 0 {
		m.store.RecordAudit(dbCtx, auditEntry{
			Username: "system",
			Action:   "dns.smart_switch",
			Resource: dom.Domain,
			Detail:   strings.Join(switchLines, "; "),
			Success:  firstLineErr == nil,
		})
		if m.gateway.telegram != nil {
			lines := append([]string{fmt.Sprintf("域名：%s (%s)", dom.Domain, dom.Name)}, switchLines...)
			alertCtx, alertCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = m.gateway.telegram.SendAlert(alertCtx, "dns_failover", "智能 DNS 线路自动调整", lines)
			alertCancel()
		}
	}
	return firstLineErr
}

func (m *axisnowDNSManager) DeleteEdgeDomainSmartDNS(ctx context.Context, dom edgeDomainRecord) {
	if m == nil || dom.SmartDNS == nil {
		return
	}
	m.clearDomainSyncCache(dom.ID)

	// Only delete Cloudflare records if domain was actively in axisnow_smart mode AND had actually cut over CNAME.
	if dom.DNSMode == domainDNSAxisNowSmart && dom.SmartDNS.AutoCFCNAME && dom.SmartDNS.CFCNAMESynced && m.gateway != nil && m.gateway.cloudflare != nil {
		m.gateway.cloudflare.DeleteEdgeDomainDNS(ctx, dom)
	}
	m.CleanupOrphanedRoutingDomain(ctx, dom)
}

// CleanupOrphanedRoutingDomain deletes a Refract-managed AxisNow routing domain ONLY when no remaining
// active axisnow_smart Edge Domain references its UUID, reclaiming free-tier tenant quota safely.
func (m *axisnowDNSManager) CleanupOrphanedRoutingDomain(ctx context.Context, prevDom edgeDomainRecord) {
	if m == nil || prevDom.SmartDNS == nil || prevDom.SmartDNS.RoutingDomainUUID == "" {
		return
	}
	routingUUID := prevDom.SmartDNS.RoutingDomainUUID
	if m.routingDomainUsedByOtherDomain(ctx, prevDom.ID, routingUUID) {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, apiBase, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return
	}
	// Re-check refcount under lock so a concurrent bind cannot lose its newly adopted routing domain.
	if m.routingDomainUsedByOtherDomain(ctx, prevDom.ID, routingUUID) {
		return
	}
	// Verify remote routing domain exists AND is strictly Refract-managed before deleting.
	var existing axisnowRemoteRoutingDomain
	if _, err := m.apiDo(ctx, apiBase, token, http.MethodGet, "/dns_routing_domains/"+url.PathEscape(routingUUID), nil, &existing); err != nil {
		return
	}
	isExactDomOwner := axisnowRoutingDomainExactOwner(existing.Description, prevDom.ID)
	isExactProfOwner := prevDom.SmartDNS.ProfileID != "" && axisnowRoutingDomainExactOwner(existing.Description, prevDom.SmartDNS.ProfileID)
	isLegacyManaged := strings.HasPrefix(existing.Description, axisnowManagedDescPrefix) && !strings.Contains(existing.Description, "[dm_") && !strings.Contains(existing.Description, "[dom_") && !strings.Contains(existing.Description, "[sdp_")
	// Also allow cleaning up a shared routing domain originally tagged with an earlier sibling's [dm_]/[dom_]
	// when prevDom belonged to a shared profile and zero active local domains still reference routingUUID.
	isUnreferencedSharedSibling := prevDom.SmartDNS.ProfileID != "" && strings.HasPrefix(existing.Description, axisnowManagedDescPrefix)
	if !isExactDomOwner && !isExactProfOwner && !isLegacyManaged && !isUnreferencedSharedSibling {
		return
	}
	if err := m.deleteRoutingDomainCascade(ctx, apiBase, token, routingUUID); err != nil {
		log.Printf("axisnow cleanup orphaned routing domain warning uuid=%s host=%s error=%v", routingUUID, existing.Domain, err)
	} else {
		log.Printf("axisnow reclaimed orphaned routing domain uuid=%s host=%s desc=%q", routingUUID, existing.Domain, existing.Description)
	}
}

// ReconcileOrphanedRoutingDomains sweeps orphaned Refract-managed AxisNow routing domains that belong
// strictly to this controller's own Edge Domains or Smart DNS Profiles (e.g., domains switched to manual
// before orphan cleanup existed, or migrated onto a shared profile routing domain), without ever touching
// manually created AxisNow domains or domains managed by other Refract controllers.
func (m *axisnowDNSManager) ReconcileOrphanedRoutingDomains(ctx context.Context, now time.Time, force bool) int {
	if m == nil || m.store == nil {
		return 0
	}
	m.orphanSweepMu.Lock()
	if !force && !m.lastOrphanSweepAt.IsZero() && now.Sub(m.lastOrphanSweepAt) < 10*time.Minute {
		m.orphanSweepMu.Unlock()
		return 0
	}
	m.orphanSweepMu.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	stored, token, apiBase, err := m.activeCredentials(ctx)
	if err != nil || !stored.Enabled || token == "" {
		return 0
	}
	domains, err := m.store.ListEdgeDomains(ctx)
	if err != nil {
		return 0
	}
	profiles, _ := m.store.ListSmartDNSProfiles(ctx)

	activeUUIDs := make(map[string]bool)
	pendingDomains := make(map[string]bool)
	pendingProfiles := make(map[string]bool)
	localDomains := make(map[string]bool, len(domains))
	localHosts := make(map[string]bool, len(domains))
	for _, d := range domains {
		localDomains[d.ID] = true
		baseHost := edgeDomainBaseHost(d.Domain)
		if baseHost != "" {
			localHosts[baseHost] = true
		}
		if d.DNSMode == domainDNSAxisNowSmart {
			if d.SmartDNS != nil && d.SmartDNS.RoutingDomainUUID != "" {
				activeUUIDs[d.SmartDNS.RoutingDomainUUID] = true
			} else if d.Enabled {
				pendingDomains[d.ID] = true
				if baseHost != "" {
					pendingDomains[baseHost] = true
				}
				if d.SmartDNS != nil && d.SmartDNS.ProfileID != "" {
					pendingProfiles[d.SmartDNS.ProfileID] = true
				}
			}
		}
	}
	localProfiles := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		localProfiles[p.ID] = true
	}

	allRemote, err := m.listRoutingDomains(ctx, apiBase, token, "")
	if err != nil {
		return 0
	}
	m.orphanSweepMu.Lock()
	m.lastOrphanSweepAt = now
	m.orphanSweepMu.Unlock()

	deleted := 0
	for _, item := range allRemote {
		if item.Status == "deleted" || item.UUID == "" || !strings.HasPrefix(item.Description, axisnowManagedDescPrefix) {
			continue
		}
		if activeUUIDs[item.UUID] {
			continue
		}
		ownedOrphan := false
		if tag := extractAxisNowManagedOwnerTag(item.Description); tag != "" {
			if localDomains[tag] && !pendingDomains[tag] {
				ownedOrphan = true
			} else if localProfiles[tag] && !pendingProfiles[tag] {
				ownedOrphan = true
			}
		} else if legacyHost := extractAxisNowLegacyManagedHost(item.Description); legacyHost != "" {
			if localHosts[legacyHost] && !pendingDomains[legacyHost] {
				ownedOrphan = true
			}
		}
		if !ownedOrphan {
			continue
		}
		if delErr := m.deleteRoutingDomainCascade(ctx, apiBase, token, item.UUID); delErr != nil {
			log.Printf("axisnow orphan routing domain cleanup warning uuid=%s host=%s error=%v", item.UUID, item.Domain, delErr)
		} else {
			deleted++
			log.Printf("axisnow reclaimed orphaned routing domain uuid=%s host=%s desc=%q", item.UUID, item.Domain, item.Description)
		}
	}
	return deleted
}

func (m *axisnowDNSManager) EvaluateEdgeDomainsSmartDNS(ctx context.Context, now time.Time) (int, error) {
	return m.evaluateEdgeDomainsSmartDNS(ctx, now, false)
}

func (m *axisnowDNSManager) evaluateEdgeDomainsSmartDNS(ctx context.Context, now time.Time, force bool) (int, error) {
	if m == nil {
		return 0, nil
	}
	stored := m.store.LoadAxisNowDNS(ctx)
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
		if !dom.Enabled || dom.DNSMode != domainDNSAxisNowSmart {
			continue
		}
		if err := m.syncEdgeDomainSmartDNS(ctx, dom, now, force); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("axisnow smart dns sync warning domain=%s error=%v", dom.Domain, err)
		} else {
			synced++
		}
	}
	m.ReconcileOrphanedRoutingDomains(ctx, now, force)
	return synced, firstErr
}

/* -------------------- Admin API (/_admin/api/axisnow-dns*) -------------------- */

type axisnowDNSUpdateRequest struct {
	Enabled               bool                  `json:"enabled"`
	Token                 string                `json:"token,omitempty"`
	ClearToken            bool                  `json:"clear_token,omitempty"`
	APIBase               string                `json:"api_base,omitempty"`
	DefaultProviderUUID   string                `json:"default_provider_uuid,omitempty"`
	DefaultProviderSource string                `json:"default_provider_source,omitempty"`
	DefaultProviderType   string                `json:"default_provider_type,omitempty"`
	DefaultZoneUUID       string                `json:"default_zone_uuid,omitempty"`
	DefaultZoneName       string                `json:"default_zone_name,omitempty"`
	DefaultZonePlan       string                `json:"default_zone_plan,omitempty"`
	TokenName             string                `json:"token_name,omitempty"`
	TenantUUID            string                `json:"tenant_uuid,omitempty"`
	CachedProviders       []axisnowProviderInfo `json:"cached_providers,omitempty"`
}

func (a *adminServer) handleAxisNowDNS(w http.ResponseWriter, r *http.Request) {
	if a.gateway.axisnow == nil {
		a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS manager unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		stored := a.store.LoadAxisNowDNS(r.Context())
		a.writeJSON(w, http.StatusOK, stored.axisnowDNSSettings)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req axisnowDNSUpdateRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		validatedBase, baseErr := validateAxisNowAPIBase(req.APIBase)
		if baseErr != nil {
			a.writeError(w, http.StatusBadRequest, baseErr.Error())
			return
		}
		a.gateway.axisnow.cfgMu.Lock()
		stored := a.store.LoadAxisNowDNS(r.Context())
		if !strings.EqualFold(validatedBase, stored.APIBase) && strings.TrimSpace(req.Token) == "" && !req.ClearToken && stored.EncryptedToken != "" {
			a.gateway.axisnow.cfgMu.Unlock()
			a.writeError(w, http.StatusBadRequest, "修改 AxisNow API 地址时请重新填写 API Token")
			return
		}
		stored.Enabled = req.Enabled
		stored.APIBase = validatedBase
		stored.DefaultProviderUUID = strings.TrimSpace(req.DefaultProviderUUID)
		if strings.TrimSpace(req.DefaultProviderSource) != "" {
			stored.DefaultProviderSource = normalizeAxisNowProviderSource(req.DefaultProviderSource)
		}
		stored.DefaultProviderType = strings.TrimSpace(req.DefaultProviderType)
		stored.DefaultZoneUUID = strings.TrimSpace(req.DefaultZoneUUID)
		stored.DefaultZoneName = normalizeDomainHostname(req.DefaultZoneName)
		stored.DefaultZonePlan = strings.TrimSpace(req.DefaultZonePlan)
		if req.TokenName != "" {
			stored.TokenName = strings.TrimSpace(req.TokenName)
		}
		if req.TenantUUID != "" {
			stored.TenantUUID = strings.TrimSpace(req.TenantUUID)
		}
		if len(req.CachedProviders) > 0 {
			stored.CachedProviders = req.CachedProviders
		}

		newPlainToken := ""
		if req.ClearToken {
			stored.EncryptedToken = ""
			stored.TokenName = ""
			stored.TenantUUID = ""
			stored.CachedProviders = []axisnowProviderInfo{}
		} else if strings.TrimSpace(req.Token) != "" {
			newPlainToken = strings.TrimSpace(req.Token)
			enc, err := a.gateway.axisnow.cipher.Encrypt(newPlainToken)
			if err != nil {
				a.gateway.axisnow.cfgMu.Unlock()
				a.writeError(w, http.StatusInternalServerError, "failed to encrypt AxisNow API token")
				return
			}
			stored.EncryptedToken = enc
		}
		a.gateway.axisnow.cfgMu.Unlock()

		// Probe AxisNow outside cfgMu to avoid blocking concurrent config reads
		if newPlainToken != "" {
			if testRes, tErr := a.gateway.axisnow.TestConnection(r.Context(), newPlainToken, stored.APIBase); tErr == nil {
				stored.TokenName = testRes.TokenName
				stored.TenantUUID = testRes.TenantUUID
				if len(testRes.Providers) > 0 {
					stored.CachedProviders = testRes.Providers
				}
				if stored.DefaultProviderUUID == "" && len(testRes.Providers) > 0 {
					for _, p := range testRes.Providers {
						if p.ProviderSource == "platform" && len(p.Zones) > 0 {
							stored.DefaultProviderUUID = p.UUID
							stored.DefaultProviderSource = "platform"
							stored.DefaultProviderType = p.Type
							stored.DefaultZoneUUID = p.Zones[0].UUID
							stored.DefaultZoneName = p.Zones[0].Zone
							stored.DefaultZonePlan = p.Zones[0].Plan
							break
						}
					}
				}
			}
		}

		a.gateway.axisnow.cfgMu.Lock()
		fresh := a.store.LoadAxisNowDNS(r.Context())
		stored.LastSyncAt = fresh.LastSyncAt
		stored.LastError = fresh.LastError
		saveErr := a.store.SaveAxisNowDNS(r.Context(), stored)
		a.gateway.axisnow.cfgMu.Unlock()
		if saveErr != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save AxisNow DNS settings")
			return
		}
		a.gateway.axisnow.clearSyncCache()
		a.auditRequest(r, "axisnow_dns.update", stored.DefaultZoneName, fmt.Sprintf("enabled=%t provider=%s", stored.Enabled, stored.DefaultProviderType), true)
		a.writeJSON(w, http.StatusOK, stored.axisnowDNSSettings)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleAxisNowDNSTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.axisnow == nil {
		a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS manager unavailable")
		return
	}
	var req struct {
		Token   string `json:"token"`
		APIBase string `json:"api_base"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := a.gateway.axisnow.TestConnection(r.Context(), req.Token, req.APIBase)
	if err != nil {
		a.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// Persist freshly discovered providers if token was already saved
	if strings.TrimSpace(req.Token) == "" {
		a.gateway.axisnow.cfgMu.Lock()
		stored := a.store.LoadAxisNowDNS(r.Context())
		if stored.EncryptedToken != "" {
			stored.TokenName = res.TokenName
			stored.TenantUUID = res.TenantUUID
			if len(res.Providers) > 0 {
				stored.CachedProviders = res.Providers
			}
			_ = a.store.SaveAxisNowDNS(r.Context(), stored)
		}
		a.gateway.axisnow.cfgMu.Unlock()
	}
	a.writeJSON(w, http.StatusOK, res)
}

func (a *adminServer) handleAxisNowDNSMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	if a.gateway.axisnow == nil {
		a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS manager unavailable")
		return
	}
	force := r.URL.Query().Get("refresh") == "1"
	meta := a.gateway.axisnow.GetGeoISPMetadata(r.Context(), force)
	a.writeJSON(w, http.StatusOK, meta)
}

func (a *adminServer) handleAxisNowDNSSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.axisnow == nil {
		a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS manager unavailable")
		return
	}
	synced, err := a.gateway.axisnow.evaluateEdgeDomainsSmartDNS(r.Context(), time.Now(), true)
	if err != nil {
		a.auditRequest(r, "axisnow_dns.sync", "all", err.Error(), false)
		a.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.auditRequest(r, "axisnow_dns.sync", "all", fmt.Sprintf("domains=%d", synced), true)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "synced_domains": synced})
}

/* -------------------- Reusable Smart DNS Profiles (smart_dns_profiles) -------------------- */

const smartDNSProfileSelectCols = `id,name,description,provider_uuid,provider_source,provider_type,zone_uuid,zone_name,zone_plan,auto_cf_cname,lines_json,created_at,updated_at`

func scanSmartDNSProfile(scanner rowScanner) (smartDNSProfileRecord, error) {
	var rec smartDNSProfileRecord
	var autoCFInt int
	var linesRaw string
	err := scanner.Scan(
		&rec.ID, &rec.Name, &rec.Description,
		&rec.ProviderUUID, &rec.ProviderSource, &rec.ProviderType,
		&rec.ZoneUUID, &rec.ZoneName, &rec.ZonePlan,
		&autoCFInt, &linesRaw, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	rec.AutoCFCNAME = autoCFInt == 1
	rec.ProviderSource = normalizeAxisNowProviderSource(rec.ProviderSource)
	if strings.TrimSpace(linesRaw) != "" {
		_ = json.Unmarshal([]byte(linesRaw), &rec.Lines)
	}
	norm := normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{Lines: rec.Lines}, nil, nil)
	if norm != nil {
		rec.Lines = norm.Lines
	} else {
		rec.Lines = []smartDNSLineRule{}
	}
	return rec, nil
}

func normalizeSmartDNSProfileInput(rec smartDNSProfileRecord) (smartDNSProfileRecord, error) {
	rec.Name = truncateRunes(strings.TrimSpace(rec.Name), 64)
	if rec.Name == "" {
		return smartDNSProfileRecord{}, errors.New("分流方案名称不能为空")
	}
	rec.Description = truncateRunes(strings.TrimSpace(rec.Description), 200)
	rec.ProviderUUID = strings.TrimSpace(rec.ProviderUUID)
	rec.ProviderSource = normalizeAxisNowProviderSource(rec.ProviderSource)
	rec.ProviderType = strings.TrimSpace(rec.ProviderType)
	rec.ZoneUUID = strings.TrimSpace(rec.ZoneUUID)
	rec.ZoneName = normalizeDomainHostname(rec.ZoneName)
	rec.ZonePlan = strings.TrimSpace(rec.ZonePlan)
	norm := normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{Lines: rec.Lines}, nil, nil)
	if norm == nil || len(norm.Lines) == 0 {
		return smartDNSProfileRecord{}, errors.New("至少需要配置一条默认兜底线路")
	}
	// Strip domain-specific runtime fields before saving reusable profile
	cleanLines := make([]smartDNSLineRule, 0, len(norm.Lines))
	for _, l := range norm.Lines {
		l.AxisNowRuleUUID = ""
		l.ActiveNodeIDs = nil
		l.ActiveIPs = nil
		l.Status = ""
		l.LastError = ""
		cleanLines = append(cleanLines, l)
	}
	rec.Lines = cleanLines
	return rec, nil
}

func applySmartDNSProfileToDomain(prof smartDNSProfileRecord, existing *edgeDomainSmartDNS, preserveAutoCF bool) *edgeDomainSmartDNS {
	autoCF := prof.AutoCFCNAME
	if preserveAutoCF && existing != nil {
		autoCF = existing.AutoCFCNAME
	}
	merged := &edgeDomainSmartDNS{
		ProfileID:      prof.ID,
		ProfileName:    prof.Name,
		ProviderUUID:   prof.ProviderUUID,
		ProviderSource: prof.ProviderSource,
		ProviderType:   prof.ProviderType,
		ZoneUUID:       prof.ZoneUUID,
		ZoneName:       prof.ZoneName,
		ZonePlan:       prof.ZonePlan,
		AutoCFCNAME:    autoCF,
		Lines:          make([]smartDNSLineRule, len(prof.Lines)),
	}
	copy(merged.Lines, prof.Lines)
	return normalizeEdgeDomainSmartDNS(merged, nil, existing)
}

func (s *telemetryStore) ListSmartDNSProfiles(ctx context.Context) ([]smartDNSProfileRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+smartDNSProfileSelectCols+` FROM smart_dns_profiles ORDER BY updated_at DESC, name COLLATE NOCASE ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]smartDNSProfileRecord, 0)
	for rows.Next() {
		rec, err := scanSmartDNSProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *telemetryStore) GetSmartDNSProfile(ctx context.Context, id string) (smartDNSProfileRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+smartDNSProfileSelectCols+` FROM smart_dns_profiles WHERE id=?`, strings.TrimSpace(id))
	return scanSmartDNSProfile(row)
}

func (s *telemetryStore) CreateSmartDNSProfile(ctx context.Context, rec smartDNSProfileRecord) (smartDNSProfileRecord, error) {
	norm, err := normalizeSmartDNSProfileInput(rec)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	rawID, err := generateRandomHex(6)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	norm.ID = "sdp_" + rawID
	now := time.Now().Unix()
	norm.CreatedAt = now
	norm.UpdatedAt = now
	linesJSON, _ := json.Marshal(norm.Lines)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO smart_dns_profiles(
			id,name,description,provider_uuid,provider_source,provider_type,
			zone_uuid,zone_name,zone_plan,auto_cf_cname,lines_json,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		norm.ID, norm.Name, norm.Description,
		norm.ProviderUUID, norm.ProviderSource, norm.ProviderType,
		norm.ZoneUUID, norm.ZoneName, norm.ZonePlan,
		boolToInt(norm.AutoCFCNAME), string(linesJSON), norm.CreatedAt, norm.UpdatedAt,
	)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	return s.GetSmartDNSProfile(ctx, norm.ID)
}

func (s *telemetryStore) UpdateSmartDNSProfile(ctx context.Context, id string, rec smartDNSProfileRecord) (smartDNSProfileRecord, error) {
	norm, err := normalizeSmartDNSProfileInput(rec)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	now := time.Now().Unix()
	linesJSON, _ := json.Marshal(norm.Lines)
	res, err := s.db.ExecContext(ctx, `
		UPDATE smart_dns_profiles
		SET name=?, description=?, provider_uuid=?, provider_source=?, provider_type=?,
		    zone_uuid=?, zone_name=?, zone_plan=?, auto_cf_cname=?, lines_json=?, updated_at=?
		WHERE id=?`,
		norm.Name, norm.Description,
		norm.ProviderUUID, norm.ProviderSource, norm.ProviderType,
		norm.ZoneUUID, norm.ZoneName, norm.ZonePlan,
		boolToInt(norm.AutoCFCNAME), string(linesJSON), now, strings.TrimSpace(id),
	)
	if err != nil {
		return smartDNSProfileRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return smartDNSProfileRecord{}, sql.ErrNoRows
	}
	return s.GetSmartDNSProfile(ctx, id)
}

func (s *telemetryStore) DeleteSmartDNSProfile(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM smart_dns_profiles WHERE id=?`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *telemetryStore) RemoveNodeFromAllSmartDNSProfiles(ctx context.Context, nodeID string) {
	profiles, err := s.ListSmartDNSProfiles(ctx)
	if err != nil {
		return
	}
	for _, prof := range profiles {
		changed := false
		for i := range prof.Lines {
			filtered := make([]string, 0, len(prof.Lines[i].NodeIDs))
			for _, id := range prof.Lines[i].NodeIDs {
				if id == nodeID {
					changed = true
					continue
				}
				filtered = append(filtered, id)
			}
			prof.Lines[i].NodeIDs = filtered
		}
		if changed {
			_, _ = s.UpdateSmartDNSProfile(ctx, prof.ID, prof)
		}
	}
}

func (c *clusterController) ListSmartDNSProfileViews(ctx context.Context) (smartDNSProfilesListResponse, error) {
	profiles, err := c.store.ListSmartDNSProfiles(ctx)
	if err != nil {
		return smartDNSProfilesListResponse{}, err
	}
	domains, _ := c.store.ListEdgeDomains(ctx)
	cf := c.store.LoadCloudflareDNS(ctx)
	an := c.store.LoadAxisNowDNS(ctx)

	boundByProfile := make(map[string][]smartDNSBoundDomainBrief)
	for _, d := range domains {
		if d.DNSMode == domainDNSAxisNowSmart && d.SmartDNS != nil && d.SmartDNS.ProfileID != "" {
			boundByProfile[d.SmartDNS.ProfileID] = append(boundByProfile[d.SmartDNS.ProfileID], smartDNSBoundDomainBrief{
				ID:                d.ID,
				Domain:            d.Domain,
				Name:              d.Name,
				Enabled:           d.Enabled,
				RoutingDomainHost: d.SmartDNS.RoutingDomainHost,
				AutoCFCNAME:       d.SmartDNS.AutoCFCNAME,
				CFCNAMESynced:     d.SmartDNS.CFCNAMESynced,
				CFCNAMEStatus:     d.SmartDNS.CFCNAMEStatus,
				CFCNAMEStatusNote: d.SmartDNS.CFCNAMEStatusNote,
				DNSLastSyncAt:     d.DNSLastSyncAt,
				DNSLastError:      d.DNSLastError,
			})
		}
	}

	views := make([]smartDNSProfileView, 0, len(profiles))
	for _, p := range profiles {
		bound := boundByProfile[p.ID]
		if bound == nil {
			bound = []smartDNSBoundDomainBrief{}
		}
		views = append(views, smartDNSProfileView{
			smartDNSProfileRecord: p,
			LineCount:             len(p.Lines),
			BoundDomains:          bound,
		})
	}
	return smartDNSProfilesListResponse{
		AxisNowEnabled:      an.Enabled && an.EncryptedToken != "",
		AxisNowProviderType: an.DefaultProviderType,
		AxisNowDefaultZone:  an.DefaultZoneName,
		AxisNowProviders:    an.CachedProviders,
		CFEnabled:           cf.Enabled,
		CFRootDomain:        cf.RootDomain,
		Profiles:            views,
	}, nil
}

func (c *clusterController) propagateSmartDNSProfileUpdate(ctx context.Context, prof smartDNSProfileRecord) {
	domains, err := c.store.ListEdgeDomains(ctx)
	if err != nil {
		return
	}
	profNodes := collectSmartDNSNodeIDs(&edgeDomainSmartDNS{Lines: prof.Lines})
	profNodeSet := make(map[string]struct{}, len(profNodes))
	for _, nid := range profNodes {
		profNodeSet[nid] = struct{}{}
	}
	for _, dom := range domains {
		if dom.DNSMode != domainDNSAxisNowSmart || dom.SmartDNS == nil || dom.SmartDNS.ProfileID != prof.ID {
			continue
		}
		prevSmartNodes := collectSmartDNSNodeIDs(dom.SmartDNS)
		removedFromProfile := make(map[string]struct{}, len(prevSmartNodes))
		for _, oldNID := range prevSmartNodes {
			if _, stillInProfile := profNodeSet[oldNID]; !stillInProfile {
				removedFromProfile[oldNID] = struct{}{}
			}
		}
		keptNodes := make([]string, 0, len(dom.NodeIDs)+len(profNodes))
		for _, nid := range dom.NodeIDs {
			if _, removed := removedFromProfile[nid]; !removed {
				keptNodes = append(keptNodes, nid)
			}
		}
		keptNodes = append(keptNodes, profNodes...)
		mergedSmart := applySmartDNSProfileToDomain(prof, dom.SmartDNS, false)
		nextNodes := normalizeDomainNodeIDs(keptNodes)
		updated, uErr := c.store.UpdateEdgeDomainSmartDNSAndNodes(ctx, dom.ID, nextNodes, mergedSmart)
		if uErr != nil {
			continue
		}
		c.notifyNodesList(append(append([]string(nil), dom.NodeIDs...), updated.NodeIDs...))
		if updated.Enabled && c.gateway.axisnow != nil {
			dCopy := updated
			c.runTracked(func() {
				syncCtx, cancel := context.WithTimeout(c.ctx, 25*time.Second)
				defer cancel()
				_ = c.gateway.axisnow.SyncEdgeDomainSmartDNS(syncCtx, dCopy, time.Now())
			})
		}
	}
}

func (a *adminServer) handleSmartDNSProfiles(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge controller unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		res, err := a.gateway.cluster.ListSmartDNSProfileViews(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load smart DNS profiles")
			return
		}
		a.writeJSON(w, http.StatusOK, res)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req smartDNSProfileRecord
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := a.store.CreateSmartDNSProfile(r.Context(), req)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.auditRequest(r, "smart_dns_profile.create", created.Name, fmt.Sprintf("id=%s lines=%d", created.ID, len(created.Lines)), true)
		a.writeJSON(w, http.StatusCreated, created)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleSmartDNSProfileItem(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge controller unavailable")
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/smart-dns-profiles/")
	parts := strings.Split(remainder, "/")
	profileID := strings.TrimSpace(parts[0])
	if profileID == "" || len(profileID) > 48 {
		a.writeError(w, http.StatusBadRequest, "invalid profile id")
		return
	}

	if len(parts) == 2 && parts[1] == "sync" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if a.gateway.axisnow == nil {
			a.writeError(w, http.StatusServiceUnavailable, "AxisNow DNS unavailable")
			return
		}
		prof, err := a.store.GetSmartDNSProfile(r.Context(), profileID)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "smart DNS profile not found")
			return
		}
		domains, _ := a.store.ListEdgeDomains(r.Context())
		synced := 0
		var firstErr error
		now := time.Now()
		for _, dom := range domains {
			if !dom.Enabled || dom.DNSMode != domainDNSAxisNowSmart || dom.SmartDNS == nil || dom.SmartDNS.ProfileID != prof.ID {
				continue
			}
			if sErr := a.gateway.axisnow.SyncEdgeDomainSmartDNS(r.Context(), dom, now); sErr != nil {
				if firstErr == nil {
					firstErr = sErr
				}
			} else {
				synced++
			}
		}
		if firstErr != nil {
			a.writeError(w, http.StatusBadGateway, firstErr.Error())
			return
		}
		a.auditRequest(r, "smart_dns_profile.sync", prof.Name, fmt.Sprintf("domains=%d", synced), true)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "synced_domains": synced})
		return
	}

	if len(parts) == 2 && parts[1] == "bind-domains" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		prof, err := a.store.GetSmartDNSProfile(r.Context(), profileID)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "smart DNS profile not found")
			return
		}
		var req struct {
			DomainIDs []string `json:"domain_ids"`
		}
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		wantSet := make(map[string]struct{}, len(req.DomainIDs))
		for _, id := range req.DomainIDs {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				wantSet[trimmed] = struct{}{}
			}
		}
		domains, err := a.store.ListEdgeDomains(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load domains")
			return
		}
		profNodes := collectSmartDNSNodeIDs(&edgeDomainSmartDNS{Lines: prof.Lines})
		boundCount := 0
		for _, dom := range domains {
			_, shouldBind := wantSet[dom.ID]
			wasBound := dom.DNSMode == domainDNSAxisNowSmart && dom.SmartDNS != nil && dom.SmartDNS.ProfileID == prof.ID
			if shouldBind {
				boundCount++
				if wasBound {
					continue
				}
				next := dom
				next.DNSMode = domainDNSAxisNowSmart
				next.SmartDNS = applySmartDNSProfileToDomain(prof, dom.SmartDNS, false)
				next.NodeIDs = normalizeDomainNodeIDs(append(append([]string(nil), dom.NodeIDs...), profNodes...))
				updated, uErr := a.store.UpdateEdgeDomainPreservingCert(r.Context(), dom.ID, next)
				if uErr == nil {
					a.gateway.cluster.notifyNodesList(updated.NodeIDs)
					if dom.SmartDNS != nil && dom.SmartDNS.RoutingDomainUUID != "" && (updated.SmartDNS == nil || updated.SmartDNS.RoutingDomainUUID != dom.SmartDNS.RoutingDomainUUID) && a.gateway.axisnow != nil {
						oldCopy := dom
						a.gateway.cluster.runTracked(func() {
							cCtx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 15*time.Second)
							defer cancel()
							a.gateway.axisnow.CleanupOrphanedRoutingDomain(cCtx, oldCopy)
						})
					}
					a.gateway.cluster.triggerDomainBackgroundTasks(updated, "")
				}
			} else if wasBound {
				// Detach cleanly: keep current line snapshot, just unlink profile_id so live DNS is never broken
				next := dom
				cp := *dom.SmartDNS
				cp.ProfileID = ""
				cp.ProfileName = ""
				next.SmartDNS = &cp
				_, _ = a.store.UpdateEdgeDomain(r.Context(), dom.ID, next)
			}
		}
		a.auditRequest(r, "smart_dns_profile.bind", prof.Name, fmt.Sprintf("domains=%d", boundCount), true)
		res, _ := a.gateway.cluster.ListSmartDNSProfileViews(r.Context())
		a.writeJSON(w, http.StatusOK, res)
		return
	}

	if len(parts) != 1 {
		a.writeError(w, http.StatusNotFound, "smart DNS profile route not found")
		return
	}

	switch r.Method {
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req smartDNSProfileRecord
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		updated, err := a.store.UpdateSmartDNSProfile(r.Context(), profileID, req)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "smart DNS profile not found")
				return
			}
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.cluster.propagateSmartDNSProfileUpdate(r.Context(), updated)
		a.auditRequest(r, "smart_dns_profile.update", updated.Name, fmt.Sprintf("id=%s lines=%d", updated.ID, len(updated.Lines)), true)
		a.writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetSmartDNSProfile(r.Context(), profileID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "smart DNS profile not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load profile")
			return
		}
		// Safely detach bound domains while keeping their current lines snapshot
		if domains, dErr := a.store.ListEdgeDomains(r.Context()); dErr == nil {
			for _, dom := range domains {
				if dom.SmartDNS != nil && dom.SmartDNS.ProfileID == profileID {
					next := dom
					cp := *dom.SmartDNS
					cp.ProfileID = ""
					cp.ProfileName = ""
					next.SmartDNS = &cp
					_, _ = a.store.UpdateEdgeDomain(r.Context(), dom.ID, next)
				}
			}
		}
		if err := a.store.DeleteSmartDNSProfile(r.Context(), profileID); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete profile")
			return
		}
		a.auditRequest(r, "smart_dns_profile.delete", existing.Name, "id="+profileID, true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.methodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
	}
}
