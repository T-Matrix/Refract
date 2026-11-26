package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

const (
	RoleStandalone = "standalone"
	RoleController = "controller"
	RoleAgent      = "agent"

	edgeNodeStatusPending  = "pending"
	edgeNodeStatusOnline   = "online"
	edgeNodeStatusOffline  = "offline"
	edgeNodeStatusDraining = "draining"

	edgeNodeOnlineThresholdSeconds = 30
)

type edgeNodeOverrides struct {
	DefaultUpstream              *string `json:"default_upstream,omitempty"`
	AllowedUpstreams             *string `json:"allowed_upstreams,omitempty"`
	AllowUnsigned                *bool   `json:"allow_unsigned_targets,omitempty"`
	PassClientIP                 *bool   `json:"pass_client_ip,omitempty"`
	DisableCache                 *bool   `json:"disable_cache,omitempty"`
	RewriteMaxBytes              *int64  `json:"rewrite_max_bytes,omitempty"`
	DNSCacheTTLSeconds           *int64  `json:"dns_cache_ttl_seconds,omitempty"`
	DialTimeoutSeconds           *int64  `json:"dial_timeout_seconds,omitempty"`
	ResponseHeaderTimeoutSeconds *int64  `json:"response_header_timeout_seconds,omitempty"`
	MaxConcurrentRequests        *int    `json:"max_concurrent_requests,omitempty"`
	MaxConcurrentPerIP           *int    `json:"max_concurrent_per_ip,omitempty"`
	MaxDownloadMbitPerIP         *int64  `json:"max_download_mbps_per_ip,omitempty"`
	UpstreamIPMode               *string `json:"upstream_ip_mode,omitempty"`
	TrustProxyHeaders            *bool   `json:"trust_proxy_headers,omitempty"`
	TrustedProxyCIDRs            *string `json:"trusted_proxy_cidrs,omitempty"`
	RealIPHeader                 *string `json:"real_ip_header,omitempty"`
}

func validateProxyTrustOverrides(o *edgeNodeOverrides) error {
	if o == nil {
		return nil
	}
	if o.TrustedProxyCIDRs != nil {
		raw := strings.TrimSpace(*o.TrustedProxyCIDRs)
		if len(raw) > 4096 {
			return errors.New("trusted_proxy_cidrs is too long (max 4096 bytes)")
		}
		if raw == "" {
			empty := ""
			o.TrustedProxyCIDRs = &empty
		} else {
			parts := strings.FieldsFunc(raw, func(r rune) bool {
				return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
			})
			if len(parts) > 128 {
				return errors.New("trusted_proxy_cidrs supports at most 128 IP/CIDR entries")
			}
			normalized := make([]string, 0, len(parts))
			seen := make(map[string]struct{}, len(parts))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				var entry string
				if prefix, err := netip.ParsePrefix(part); err == nil {
					entry = prefix.Masked().String()
				} else if addr, err := netip.ParseAddr(part); err == nil {
					entry = addr.Unmap().String()
				} else {
					return fmt.Errorf("invalid IP or CIDR in trusted_proxy_cidrs: %q", part)
				}
				if _, dup := seen[entry]; !dup {
					seen[entry] = struct{}{}
					normalized = append(normalized, entry)
				}
			}
			joined := strings.Join(normalized, ", ")
			o.TrustedProxyCIDRs = &joined
		}
	}
	if o.RealIPHeader != nil {
		hdr := strings.TrimSpace(*o.RealIPHeader)
		if len(hdr) > 64 {
			return errors.New("real_ip_header is too long")
		}
		for i := 0; i < len(hdr); i++ {
			ch := hdr[i]
			if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return fmt.Errorf("invalid header name in real_ip_header: %q", hdr)
			}
		}
		switch strings.ToLower(hdr) {
		case "host", "cookie", "authorization", "content-length", "transfer-encoding":
			return fmt.Errorf("disallowed header in real_ip_header: %q", hdr)
		}
		o.RealIPHeader = &hdr
	}
	return nil
}

func (o edgeNodeOverrides) ApplyTo(base runtimeSettings) runtimeSettings {
	if o.DefaultUpstream != nil {
		base.DefaultUpstream = strings.TrimSpace(*o.DefaultUpstream)
	}
	if o.AllowedUpstreams != nil {
		base.AllowedUpstreams = strings.TrimSpace(*o.AllowedUpstreams)
	}
	if o.AllowUnsigned != nil {
		base.AllowUnsigned = *o.AllowUnsigned
	}
	if o.PassClientIP != nil {
		base.PassClientIP = *o.PassClientIP
	}
	if o.DisableCache != nil {
		base.DisableCache = *o.DisableCache
	}
	if o.RewriteMaxBytes != nil {
		base.RewriteMaxBytes = *o.RewriteMaxBytes
	}
	if o.DNSCacheTTLSeconds != nil {
		base.DNSCacheTTLSeconds = *o.DNSCacheTTLSeconds
	}
	if o.DialTimeoutSeconds != nil {
		base.DialTimeoutSeconds = *o.DialTimeoutSeconds
	}
	if o.ResponseHeaderTimeoutSeconds != nil {
		base.ResponseHeaderTimeoutSeconds = *o.ResponseHeaderTimeoutSeconds
	}
	if o.MaxConcurrentRequests != nil {
		base.MaxConcurrentRequests = *o.MaxConcurrentRequests
	}
	if o.MaxConcurrentPerIP != nil {
		base.MaxConcurrentPerIP = *o.MaxConcurrentPerIP
	}
	if o.MaxDownloadMbitPerIP != nil {
		base.MaxDownloadMbitPerIP = *o.MaxDownloadMbitPerIP
	}
	if o.UpstreamIPMode != nil && strings.TrimSpace(*o.UpstreamIPMode) != "" {
		base.UpstreamIPMode = strings.TrimSpace(*o.UpstreamIPMode)
	}
	return base
}

type edgeNodeMetrics struct {
	UploadBPS      int64                `json:"upload_bps"`
	DownloadBPS    int64                `json:"download_bps"`
	UploadTotal    int64                `json:"upload_total"`
	DownloadTotal  int64                `json:"download_total"`
	ActiveRequests int64                `json:"active_requests"`
	BlockedTotal   uint64               `json:"blocked_total"`
	DroppedLogs    uint64               `json:"dropped_logs"`
	UptimeSeconds  int64                `json:"uptime_seconds"`
	Goroutines     int                  `json:"goroutines"`
	MemAllocBytes  uint64               `json:"mem_alloc_bytes"`
	PublicIPv4     string               `json:"public_ipv4,omitempty"`
	PublicIPv6     string               `json:"public_ipv6,omitempty"`
	BinarySHA256   string               `json:"binary_sha256,omitempty"`
	NICTraffic     *hostNICTrafficReport `json:"nic_traffic,omitempty"`
	agentTLSStatus
	Connections    []connectionSnapshot      `json:"connections,omitempty"`
	Playbacks      []playbackSessionSnapshot `json:"playbacks,omitempty"`
}

type edgeNodeRecord struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	GroupName        string            `json:"group_name"`
	Region           string            `json:"region"`
	PublicURL        string            `json:"public_url"`
	PublicVisible    bool              `json:"public_visible"`
	Draining         bool              `json:"draining"`
	TokenHash        string            `json:"-"`
	EnrollTokenHash  string            `json:"-"`
	EnrollExpiresAt  int64             `json:"enroll_expires_at"`
	Overrides        edgeNodeOverrides `json:"overrides"`
	AppliedRevision  int64             `json:"applied_revision"`
	AppliedSHA256    string            `json:"applied_sha256"`
	AgentVersion     string            `json:"agent_version"`
	Arch             string            `json:"arch"`
	Hostname         string            `json:"hostname"`
	PublicIPv4       string            `json:"public_ipv4"`
	PublicIPv6       string            `json:"public_ipv6"`
	ManualIPv4       string            `json:"manual_ipv4"`
	ManualIPv6       string            `json:"manual_ipv6"`
	DNSSyncEnabled   bool              `json:"dns_sync_enabled"`
	DNSIPMode        string            `json:"dns_ip_mode"`
	MonthlyQuotaGB   float64           `json:"monthly_quota_gb"`
	QuotaResetDay    int               `json:"quota_reset_day"`
	QuotaDirection   string            `json:"quota_direction"`
	QuotaAutoDrain   bool              `json:"quota_auto_drain"`
	QuotaAutoDrained bool              `json:"quota_auto_drained"`
	QuotaCycleKey    string            `json:"quota_cycle_key"`
	QuotaAlertLevel  int               `json:"quota_alert_level"`
	BinarySHA256     string            `json:"binary_sha256"`
	LastSeenAt       int64             `json:"last_seen_at"`
	CreatedAt        int64             `json:"created_at"`
	UpdatedAt        int64             `json:"updated_at"`
}

func effectiveNodeIPs(node edgeNodeRecord) (ipv4, ipv6 string) {
	ipv4 = strings.TrimSpace(node.ManualIPv4)
	if ipv4 == "" {
		ipv4 = strings.TrimSpace(node.PublicIPv4)
	}
	ipv6 = strings.TrimSpace(node.ManualIPv6)
	if ipv6 == "" {
		ipv6 = strings.TrimSpace(node.PublicIPv6)
	}
	return ipv4, ipv6
}

type edgeNodeView struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	GroupName         string            `json:"group_name"`
	Region            string            `json:"region"`
	PublicURL         string            `json:"public_url"`
	PublicVisible     bool              `json:"public_visible"`
	Draining          bool              `json:"draining"`
	Enrolled          bool              `json:"enrolled"`
	Status            string            `json:"status"`
	Connected         bool              `json:"connected"`
	Synced            bool              `json:"synced"`
	Overrides         edgeNodeOverrides `json:"overrides"`
	Effective         runtimeSettings   `json:"effective"`
	AppliedRevision   int64             `json:"applied_revision"`
	DesiredRevision   int64             `json:"desired_revision"`
	AppliedSHA256     string            `json:"applied_sha256"`
	DesiredSHA256     string            `json:"desired_sha256"`
	AgentVersion      string            `json:"agent_version"`
	Arch              string            `json:"arch"`
	Hostname          string            `json:"hostname"`
	PublicIPv4        string            `json:"public_ipv4"`
	PublicIPv6        string            `json:"public_ipv6"`
	ManualIPv4        string            `json:"manual_ipv4"`
	ManualIPv6        string            `json:"manual_ipv6"`
	EffectiveIPv4     string            `json:"effective_ipv4"`
	EffectiveIPv6     string            `json:"effective_ipv6"`
	DNSSyncEnabled    bool              `json:"dns_sync_enabled"`
	DNSIPMode         string            `json:"dns_ip_mode"`
	MonthlyQuotaGB    float64           `json:"monthly_quota_gb"`
	QuotaResetDay     int               `json:"quota_reset_day"`
	QuotaDirection    string            `json:"quota_direction"`
	QuotaAutoDrain    bool              `json:"quota_auto_drain"`
	QuotaAutoDrained  bool              `json:"quota_auto_drained"`
	MonthlyUsedBytes  int64             `json:"monthly_used_bytes"`
	MonthlyQuotaBytes int64             `json:"monthly_quota_bytes"`
	MonthlyUsagePct   float64           `json:"monthly_usage_pct"`
	QuotaResetAt      int64             `json:"quota_reset_at"`
	QuotaExceeded     bool              `json:"quota_exceeded"`
	NICInterfaces     []string          `json:"nic_interfaces,omitempty"`
	BinarySHA256      string            `json:"binary_sha256"`
	UpgradeAvailable  bool              `json:"upgrade_available"`
	AssignedDomains   []string          `json:"assigned_domains,omitempty"`
	LastSeenAt        int64             `json:"last_seen_at"`
	CreatedAt         int64             `json:"created_at"`
	UpdatedAt         int64             `json:"updated_at"`
	EnrollExpiresAt   int64             `json:"enroll_expires_at"`
	Metrics           edgeNodeMetrics   `json:"metrics"`
}

type edgeNodesSummary struct {
	Total            int   `json:"total"`
	Online           int   `json:"online"`
	Offline          int   `json:"offline"`
	Pending          int   `json:"pending"`
	Draining         int   `json:"draining"`
	Synced           int   `json:"synced"`
	TotalUploadBPS   int64 `json:"total_upload_bps"`
	TotalDownloadBPS int64 `json:"total_download_bps"`
	HasNICMetrics    bool  `json:"has_nic_metrics,omitempty"`
	TotalNICRXBPS    int64 `json:"total_nic_rx_bps,omitempty"`
	TotalNICTXBPS    int64 `json:"total_nic_tx_bps,omitempty"`
	ActiveRequests   int64 `json:"active_requests"`
}

type edgeNodesListResponse struct {
	Role                   string           `json:"role"`
	ControllerURL          string           `json:"controller_url"`
	ControllerVersion      string           `json:"controller_version"`
	ControllerBinarySHA256 string           `json:"controller_binary_sha256,omitempty"`
	Summary                edgeNodesSummary `json:"summary"`
	Nodes                  []edgeNodeView   `json:"nodes"`
}

type publicEdgeNode struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	GroupName          string `json:"group_name"`
	Region             string `json:"region"`
	PublicURL          string `json:"public_url"`
	Online             bool   `json:"online"`
	Draining           bool   `json:"draining"`
	ActiveRequests     int64  `json:"active_requests"`
	HealthyNodes       int    `json:"healthy_nodes,omitempty"`
	TotalNodes         int    `json:"total_nodes,omitempty"`
	Version            string `json:"version,omitempty"`
	LastSeen           int64  `json:"last_seen,omitempty"`
	HasDefaultUpstream bool   `json:"has_default_upstream"`
}

type agentDeployCommands struct {
	EnrollToken     string `json:"enroll_token"`
	EnrollExpiresAt int64  `json:"enroll_expires_at"`
	ControllerURL   string `json:"controller_url"`
	OneClickAutoTLS string `json:"one_click_auto_tls"`
	OneClickProxy   string `json:"one_click_proxy"`
	SystemdScript   string `json:"systemd_command"`
	CaddyBlock      string `json:"caddy_block"`
	DockerCommand   string `json:"docker_command"`
	CLICommand      string `json:"cli_command"`
}

type agentEnrollRequest struct {
	EnrollToken string `json:"enroll_token"`
	Version     string `json:"version"`
	Arch        string `json:"arch"`
	Hostname    string `json:"hostname"`
}

type agentEnrollResponse struct {
	NodeID               string `json:"node_id"`
	NodeName             string `json:"node_name"`
	AgentSecret          string `json:"agent_secret"`
	PublicURL            string `json:"public_url"`
	HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
	TelemetryIntervalSec int    `json:"telemetry_interval_sec"`
}

type agentPolicyBundle struct {
	Mode            string             `json:"mode"`
	Rules           []proxyRule        `json:"rules"`
	PlayerPolicy    playerPolicy       `json:"player_policy"`
	ClientAccess    clientAccessPolicy `json:"client_access"`
	ScheduleEnabled bool               `json:"schedule_enabled"`
	ScheduleStart   string             `json:"schedule_start"`
	ScheduleEnd     string             `json:"schedule_end"`
}

type agentDomainConfig struct {
	ID           string            `json:"id"`
	Domain       string            `json:"domain"`
	TLSMode      string            `json:"tls_mode"` // "managed_pem", "agent_http01", "external"
	CertPEM      string            `json:"cert_pem,omitempty"`
	KeyPEM       string            `json:"key_pem,omitempty"`
	CertNotAfter int64             `json:"cert_not_after,omitempty"`
	Overrides    edgeNodeOverrides `json:"overrides,omitempty"`
	WAFRules     []wafRuleRecord   `json:"waf_rules,omitempty"`
}

type agentConfigPayload struct {
	NodeID              string              `json:"node_id"`
	NodeName            string              `json:"node_name"`
	PublicBaseURL       string              `json:"public_base_url"`
	PublicPortalEnabled *bool               `json:"public_portal_enabled,omitempty"`
	Draining            bool                `json:"draining"`
	SigningSecretHex    string              `json:"signing_secret_hex"`
	SignedURLTTLSeconds int64               `json:"signed_url_ttl_seconds"`
	Runtime             runtimeSettings     `json:"runtime"`
	Policy              agentPolicyBundle   `json:"policy"`
	Domains             []agentDomainConfig `json:"domains,omitempty"`
	GlobalWAFRules      []wafRuleRecord     `json:"global_waf_rules,omitempty"`
	IPCountries         map[string]string   `json:"ip_countries,omitempty"`
}

type agentConfigBundle struct {
	agentConfigPayload
	Revision    int64  `json:"revision"`
	SHA256      string `json:"sha256"`
	GeneratedAt int64  `json:"generated_at"`
}

func computeAgentConfigSHA256(payload agentConfigPayload) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type agentSSEEvent struct {
	Type       string `json:"type"`
	Revision   int64  `json:"revision,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	FlowID     string `json:"flow_id,omitempty"`
	SessionKey string `json:"session_key,omitempty"`
}

type agentHeartbeatRequest struct {
	AppliedRevision int64           `json:"applied_revision"`
	AppliedSHA256   string          `json:"applied_sha256"`
	Version         string          `json:"version"`
	Arch            string          `json:"arch"`
	Hostname        string          `json:"hostname"`
	Metrics         edgeNodeMetrics `json:"metrics"`
}

type agentHeartbeatResponse struct {
	OK              bool            `json:"ok"`
	DesiredRevision int64           `json:"desired_revision"`
	DesiredSHA256   string          `json:"desired_sha256"`
	Draining        bool            `json:"draining"`
	ServerTime      int64           `json:"server_time"`
	Commands        []agentSSEEvent `json:"commands,omitempty"`
}

type agentTelemetryEvent struct {
	FlowID     string `json:"flow_id,omitempty"`
	Timestamp  int64  `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	ClientName string `json:"client_name,omitempty"`
	Host       string `json:"host"`
	Scheme     string `json:"scheme"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Category   string `json:"category"`
	Status     int    `json:"status"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	DurationMS int64  `json:"duration_ms"`
}

type agentClientPeak struct {
	IP        string `json:"ip"`
	PeakBPS   int64  `json:"peak_bps"`
	Timestamp int64  `json:"timestamp"`
}

type agentTelemetryBatch struct {
	Events       []agentTelemetryEvent `json:"events,omitempty"`
	ClientPeaks  []agentClientPeak     `json:"client_peaks,omitempty"`
	QuotaDeltas  map[int64]int64       `json:"quota_deltas,omitempty"`
	BlockedDelta uint64                `json:"blocked_delta,omitempty"`
	DroppedDelta uint64                `json:"dropped_delta,omitempty"`
}

func hashAgentToken(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func normalizeNodePublicURL(raw string) (string, error) {
	parsed, err := parseHTTPURL(raw)
	if err != nil {
		return "", err
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errInvalidNodePublicURL
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

var errInvalidNodePublicURL = &url.Error{Op: "parse", URL: "public_url", Err: errURLOriginOnly}

type staticError string

func (e staticError) Error() string { return string(e) }

const errURLOriginOnly = staticError("public_url must contain only an HTTP/HTTPS origin")

func normalizeGatewayRole(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case RoleController, "server", "master":
		return RoleController
	case RoleAgent, "node", "edge":
		return RoleAgent
	default:
		return RoleStandalone
	}
}
