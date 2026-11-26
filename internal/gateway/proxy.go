package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type runtimeSnapshot struct {
	PublicBaseURL     *url.URL
	DefaultUpstream   *url.URL
	AllowedUpstreams  []TargetPattern
	AllowUnsigned     bool
	PassClientIP      bool
	DisableCache      bool
	RewriteMaxBytes   int64
	DNSCacheTTL       time.Duration
	DialTimeout       time.Duration
	ResponseTimeout   time.Duration
	UpstreamIPMode    string
	TrustProxyHeaders bool
	TrustedProxyCIDRs []netip.Prefix
	RealIPHeader      string
}

func (rt runtimeSnapshot) clientIP(request *http.Request) string {
	return clientIPFromRequest(request, rt.TrustProxyHeaders, rt.TrustedProxyCIDRs, rt.RealIPHeader)
}

func runtimeSnapshotFromConfig(cfg Config) runtimeSnapshot {
	ipMode, ok := normalizeUpstreamIPMode(cfg.UpstreamIPMode)
	if !ok {
		ipMode = upstreamIPAuto
	}
	return runtimeSnapshot{
		PublicBaseURL:     cfg.PublicBaseURL,
		DefaultUpstream:   cfg.DefaultUpstream,
		AllowedUpstreams:  cfg.AllowedUpstreams,
		AllowUnsigned:     cfg.AllowUnsigned,
		PassClientIP:      cfg.PassClientIP,
		DisableCache:      cfg.DisableCache,
		RewriteMaxBytes:   cfg.RewriteMaxBytes,
		DNSCacheTTL:       cfg.DNSCacheTTL,
		DialTimeout:       cfg.DialTimeout,
		ResponseTimeout:   cfg.ResponseTimeout,
		UpstreamIPMode:    ipMode,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
		TrustedProxyCIDRs: append([]netip.Prefix(nil), cfg.TrustedProxyCIDRs...),
	}
}

type dynamicTransport struct {
	current atomic.Pointer[http.Transport]
}

func newDynamicTransport(initial *http.Transport) *dynamicTransport {
	dt := &dynamicTransport{}
	dt.current.Store(initial)
	return dt
}

func (t *dynamicTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.current.Load().RoundTrip(req)
}

func (t *dynamicTransport) Swap(next *http.Transport) *http.Transport {
	return t.current.Swap(next)
}

func (t *dynamicTransport) Load() *http.Transport {
	return t.current.Load()
}

func (t *dynamicTransport) CloseIdleConnections() {
	if current := t.current.Load(); current != nil {
		current.CloseIdleConnections()
	}
}

type Gateway struct {
	cfg          Config
	signer       Signer
	signerState  atomic.Pointer[Signer]
	resolver     *safeResolver
	proxy        *httputil.ReverseProxy
	transport    *dynamicTransport
	telemetry    *telemetryStore
	embyHealth   *embyHealthMonitor
	admin        *adminServer
	telegram     *telegramReporter
	turnstile    *turnstileManager
	backups      *backupManager
	geo          *geoTracker
	updates      *updateManager
	runtime      *runtimeConfigManager
	cloudflare   *cloudflareDNSManager
	axisnow      *axisnowDNSManager
	cluster      *clusterController
	agent        *agentClient
	limiter      *requestLimiter
	bandwidth    *bandwidthLimiter
	quota        *domainQuotaManager
	meter        *rateMeter
	connections  *connectionTracker
	playback     *playbackTracker
	started       time.Time
	active        atomic.Int64
	blocked       atomic.Uint64
	restarting    atomic.Bool
	draining      atomic.Bool
	closing       atomic.Bool
	publicPortal  atomic.Bool
	watchSyncLast atomic.Int64
	watchSyncBusy atomic.Bool
	rewriteSem    chan struct{}
	policy          atomic.Pointer[proxyPolicy]
	runtimeState    atomic.Pointer[runtimeSnapshot]
	ipCountries     atomic.Pointer[map[string]string]
	assignedDomains atomic.Pointer[[]agentDomainRuntime]
	globalWAFRules  atomic.Pointer[[]*compiledWAFRule]
}

type agentDomainRuntime struct {
	ID         string
	Pattern    string
	Runtime    runtimeSnapshot
	Bandwidth  *bandwidthLimiter
	Limiter    *requestLimiter
	WAFRules   []*compiledWAFRule
	WAFUsesGeo bool
}

func (g *Gateway) applyAssignedDomains(domains []agentDomainConfig, baseRuntime runtimeSettings, mergedNodeCfg Config) {
	if len(domains) == 0 {
		empty := []agentDomainRuntime{}
		g.assignedDomains.Store(&empty)
		return
	}
	prevByID := make(map[string]agentDomainRuntime)
	if prev := g.assignedDomains.Load(); prev != nil {
		for _, item := range *prev {
			prevByID[item.ID] = item
		}
	}
	list := make([]agentDomainRuntime, 0, len(domains))
	for _, dom := range domains {
		pattern := strings.ToLower(strings.TrimSpace(dom.Domain))
		if pattern == "" {
			continue
		}
		domSettings := dom.Overrides.ApplyTo(baseRuntime)
		if domSettings.MaxConcurrentRequests > 0 && domSettings.MaxConcurrentPerIP > domSettings.MaxConcurrentRequests {
			domSettings.MaxConcurrentPerIP = domSettings.MaxConcurrentRequests
		}
		domCfg, _, err := applyRuntimeSettings(mergedNodeCfg, domSettings)
		if err != nil {
			log.Printf("edge domain %s overrides warning: %v", pattern, err)
			domCfg = mergedNodeCfg
		}
		if domCfg.MaxConcurrent > 0 && domCfg.MaxConcurrentPerIP > domCfg.MaxConcurrent {
			domCfg.MaxConcurrentPerIP = domCfg.MaxConcurrent
		}
		if !strings.HasPrefix(pattern, "*.") {
			if parsed, pErr := parseHTTPURL("https://" + pattern); pErr == nil {
				parsed.Path = ""
				domCfg.PublicBaseURL = parsed
			}
		}
		var bw *bandwidthLimiter
		if dom.Overrides.MaxDownloadMbitPerIP != nil {
			if prevItem, ok := prevByID[dom.ID]; ok && prevItem.Bandwidth != nil {
				bw = prevItem.Bandwidth
				bw.SetLimit(domCfg.MaxDownloadBPSPerIP)
			} else {
				bw = newBandwidthLimiter(domCfg.MaxDownloadBPSPerIP)
			}
		}
		var lim *requestLimiter
		if dom.Overrides.MaxConcurrentRequests != nil || dom.Overrides.MaxConcurrentPerIP != nil {
			if prevItem, ok := prevByID[dom.ID]; ok && prevItem.Limiter != nil {
				lim = prevItem.Limiter
				lim.UpdateLimits(domCfg.MaxConcurrent, domCfg.MaxConcurrentPerIP)
			} else {
				lim = newRequestLimiter(domCfg.MaxConcurrent, domCfg.MaxConcurrentPerIP)
			}
		}
		if dom.Overrides.TrustProxyHeaders != nil {
			domCfg.TrustProxyHeaders = *dom.Overrides.TrustProxyHeaders
		}
		if dom.Overrides.TrustedProxyCIDRs != nil {
			domCfg.TrustedProxyCIDRs = parseTrustedProxyCIDRs(*dom.Overrides.TrustedProxyCIDRs)
		}
		domRT := runtimeSnapshotFromConfig(domCfg)
		if dom.Overrides.RealIPHeader != nil {
			domRT.RealIPHeader = strings.TrimSpace(*dom.Overrides.RealIPHeader)
		}
		domWAF, domWAFGeo := compileWAFRulesList(dom.WAFRules)
		list = append(list, agentDomainRuntime{
			ID:         dom.ID,
			Pattern:    pattern,
			Runtime:    domRT,
			Bandwidth:  bw,
			Limiter:    lim,
			WAFRules:   domWAF,
			WAFUsesGeo: domWAFGeo,
		})
	}
	g.assignedDomains.Store(&list)
}

func (g *Gateway) matchAssignedDomain(request *http.Request, fallback runtimeSnapshot) (rt runtimeSnapshot, bw *bandwidthLimiter, lim *requestLimiter, domWAF []*compiledWAFRule, matched bool, enforced bool) {
	ptr := g.assignedDomains.Load()
	if ptr == nil || len(*ptr) == 0 {
		return fallback, nil, nil, nil, true, false
	}
	reqHost := normalizeHost(stripHostPort(request.Host))
	// Prefer exact match first, then single-level wildcard match.
	var found *agentDomainRuntime
	for i := range *ptr {
		item := &(*ptr)[i]
		if !strings.HasPrefix(item.Pattern, "*.") && item.Pattern == reqHost {
			found = item
			break
		}
	}
	if found == nil {
		for i := range *ptr {
			item := &(*ptr)[i]
			if strings.HasPrefix(item.Pattern, "*.") && matchEdgeDomainHost(item.Pattern, reqHost) {
				found = item
				break
			}
		}
	}
	if found == nil {
		return fallback, nil, nil, nil, false, true
	}
	resolved := found.Runtime
	if reqHost != "" {
		scheme := "https"
		if request.TLS == nil && !g.AgentAutoTLS() {
			if resolved.TrustProxyHeaders && isTrustedProxyPeer(request.RemoteAddr, resolved.TrustedProxyCIDRs) {
				if proto := lastForwardedValue(request.Header.Values("X-Forwarded-Proto")); proto == "https" || proto == "http" {
					scheme = proto
				} else {
					scheme = "http"
				}
			} else {
				scheme = "http"
			}
		}
		if parsed, err := parseHTTPURL(scheme + "://" + strings.TrimSpace(request.Host)); err == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
			resolved.PublicBaseURL = parsed
		}
	}
	return resolved, found.Bandwidth, found.Limiter, found.WAFRules, true, true
}

func New(cfg Config) *Gateway {
	gateway, err := NewChecked(cfg)
	if err != nil {
		panic(err)
	}
	return gateway
}

func NewChecked(cfg Config) (*Gateway, error) {
	cfg.Role = normalizeGatewayRole(cfg.Role)
	if cfg.Role == RoleAgent {
		cfg.AdminEnabled = false
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 256
	}
	if cfg.MaxConcurrentPerIP <= 0 || cfg.MaxConcurrentPerIP > cfg.MaxConcurrent {
		cfg.MaxConcurrentPerIP = min(64, cfg.MaxConcurrent)
	}
	if cfg.AdminEnabled {
		cfg.RuntimeConfigPath = resolveRuntimeConfigPath(cfg.RuntimeConfigPath, cfg.AdminDatabasePath)
	}
	gateway := &Gateway{
		cfg:     cfg,
		signer:  NewSigner(cfg.SigningSecret, cfg.SignedURLTTL),
		started: time.Now(),
	}
	gateway.publicPortal.Store(true)
	gateway.policy.Store(&proxyPolicy{Rules: []proxyRule{}})

	// Pure controller mode does not proxy data-plane traffic, so skip local
	// proxy/limiter/bandwidth/meter/connection goroutines and pools.
	if cfg.Role != RoleController {
		gateway.resolver = newSafeResolver(cfg.DNSCacheTTL, cfg.AllowPrivateTargets)
		gateway.limiter = newRequestLimiter(cfg.MaxConcurrent, cfg.MaxConcurrentPerIP)
		gateway.bandwidth = newBandwidthLimiter(cfg.MaxDownloadBPSPerIP)
		gateway.meter = newRateMeter()
		gateway.connections = newConnectionTracker()
		gateway.playback = newPlaybackTracker()
		gateway.rewriteSem = make(chan struct{}, 16)
		gateway.transport = newDynamicTransport(gateway.newUpstreamTransport(cfg.ResponseTimeout))
		gateway.proxy = &httputil.ReverseProxy{
			Rewrite:        gateway.rewriteRequest,
			Transport:      gateway.transport,
			ModifyResponse: gateway.modifyResponse,
			ErrorHandler:   gateway.handleProxyError,
			BufferPool:     newByteBufferPool(32 << 10),
			FlushInterval:  100 * time.Millisecond,
		}
	}
	closeDataPlane := func() {
		gateway.connections.Close()
		gateway.meter.Close()
		if gateway.transport != nil {
			gateway.transport.CloseIdleConnections()
		}
	}
	if cfg.AdminEnabled {
		store, err := openTelemetryStore(cfg.AdminDatabasePath, cfg.AdminUsername, cfg.AdminPasswordHash)
		if err != nil {
			closeDataPlane()
			return nil, fmt.Errorf("initialize admin database: %w", err)
		}
		gateway.telemetry = store
		gateway.publicPortal.Store(store.LoadPublicPortalEnabled(context.Background()))
		policy, err := store.LoadProxyPolicy(context.Background())
		if err != nil {
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("load proxy policy: %w", err)
		}
		gateway.policy.Store(policy)
		gateway.reloadWAFRules(context.Background())
		reporter, err := newTelegramReporter(store, gateway, cfg.AdminSessionSecret)
		if err != nil {
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize telegram reporter: %w", err)
		}
		gateway.telegram = reporter
		turnstile, err := newTurnstileManager(store, cfg.AdminSessionSecret)
		if err != nil {
			reporter.Close()
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize Turnstile: %w", err)
		}
		gateway.turnstile = turnstile
		backups, err := newBackupManager(store, cfg)
		if err != nil {
			reporter.Close()
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize backup manager: %w", err)
		}
		gateway.backups = backups
		gateway.updates = newUpdateManager(cfg)
		gateway.runtime = newRuntimeConfigManager(cfg)
		gateway.runtime.onApply = gateway.applyRuntimeConfig
		admin, err := newAdminServer(gateway, store, cfg)
		if err != nil {
			backups.Close()
			reporter.Close()
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize admin panel: %w", err)
		}
		gateway.admin = admin
		gateway.geo = newGeoTracker(store, cfg)
		probeResolver := gateway.resolver
		if probeResolver == nil {
			probeResolver = newSafeResolver(cfg.DNSCacheTTL, cfg.AllowPrivateTargets)
		}
		gateway.embyHealth = newEmbyHealthMonitor(store, probeResolver)
		if cfg.Role != RoleController {
			gateway.meter.SetClientPeakSink(gateway.geo.ObservePeak)
			gateway.quota = newDomainQuotaManager(store)
			gateway.quota.Sync(policy)
		}
		cfManager, err := newCloudflareDNSManager(store, gateway, cfg.AdminSessionSecret)
		if err != nil {
			if gateway.embyHealth != nil {
				gateway.embyHealth.Close()
			}
			if gateway.geo != nil {
				gateway.geo.Close()
			}
			if gateway.quota != nil {
				gateway.quota.Close()
			}
			backups.Close()
			reporter.Close()
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize cloudflare dns: %w", err)
		}
		gateway.cloudflare = cfManager
		anManager, err := newAxisNowDNSManager(store, gateway, cfg.AdminSessionSecret)
		if err != nil {
			cfManager.Close()
			if gateway.embyHealth != nil {
				gateway.embyHealth.Close()
			}
			if gateway.geo != nil {
				gateway.geo.Close()
			}
			if gateway.quota != nil {
				gateway.quota.Close()
			}
			backups.Close()
			reporter.Close()
			store.Close()
			closeDataPlane()
			return nil, fmt.Errorf("initialize axisnow dns: %w", err)
		}
		gateway.axisnow = anManager
		gateway.cluster = newClusterController(gateway, store)
	}
	if cfg.Role == RoleAgent {
		agent, err := newAgentClient(gateway, cfg)
		if err != nil {
			closeDataPlane()
			return nil, fmt.Errorf("initialize edge agent: %w", err)
		}
		gateway.agent = agent
		gateway.quota = newDomainQuotaManagerWithPending(nil, agent.AddQuotaDelta, agent.PendingQuotaDelta)
		gateway.quota.Sync(gateway.policy.Load())
		gateway.meter.SetClientPeakSink(agent.ObserveClientPeak)
		agent.Start()
	}
	return gateway, nil
}

func (g *Gateway) liveSigner() Signer {
	if s := g.signerState.Load(); s != nil {
		return *s
	}
	return g.signer
}

func (g *Gateway) notifyClusterConfigChanged(nodeID string) {
	if g != nil && g.cluster != nil {
		g.cluster.NotifyConfigChanged(nodeID)
	}
}

func (g *Gateway) AgentAutoTLS() bool {
	return g != nil && g.agent != nil && g.agent.autoTLS != nil
}

func (g *Gateway) AgentTLSConfig() *tls.Config {
	if !g.AgentAutoTLS() {
		return nil
	}
	return g.agent.autoTLS.TLSConfig()
}

func (g *Gateway) AgentHTTPHandler() http.Handler {
	if !g.AgentAutoTLS() {
		return g
	}
	return g.agent.autoTLS.HTTPChallengeHandler(g)
}

func (g *Gateway) liveRuntime() runtimeSnapshot {
	if snap := g.runtimeState.Load(); snap != nil {
		return *snap
	}
	return runtimeSnapshotFromConfig(g.cfg)
}

func (g *Gateway) newUpstreamTransport(responseTimeout time.Duration) *http.Transport {
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		MaxConnsPerHost:       256,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: responseTimeout,
		ExpectContinueTimeout: time.Second,
		ReadBufferSize:        32 << 10,
		WriteBufferSize:       32 << 10,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: g.liveRuntime().DialTimeout, KeepAlive: 30 * time.Second}
		info, _ := ctx.Value(targetContextKey{}).(*targetInfo)
		if info == nil || !sameDialAddress(address, targetHostPort(info.URL)) {
			return nil, fmt.Errorf("upstream dial target mismatch")
		}
		var lastErr error
		for _, resolved := range info.DialAddresses {
			connection, err := dialer.DialContext(ctx, network, resolved)
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("target has no resolved addresses")
		}
		return nil, lastErr
	}
	return transport
}

func (g *Gateway) applyRuntimeConfig(next Config) {
	prev := g.liveRuntime()
	if next.PublicBaseURL == nil && g.cfg.Role != RoleAgent {
		next.PublicBaseURL = prev.PublicBaseURL
	}
	if g.cfg.Role != RoleAgent {
		next.TrustProxyHeaders = prev.TrustProxyHeaders
		next.TrustedProxyCIDRs = prev.TrustedProxyCIDRs
	}
	snapshot := runtimeSnapshotFromConfig(next)
	if g.cfg.Role != RoleAgent && prev.RealIPHeader != "" {
		snapshot.RealIPHeader = prev.RealIPHeader
	}
	g.runtimeState.Store(&snapshot)
	g.limiter.UpdateLimits(next.MaxConcurrent, next.MaxConcurrentPerIP)
	g.bandwidth.SetLimit(next.MaxDownloadBPSPerIP)
	g.resolver.SetTTL(next.DNSCacheTTL)
	if g.transport != nil && next.ResponseTimeout != prev.ResponseTimeout {
		old := g.transport.Swap(g.newUpstreamTransport(next.ResponseTimeout))
		if old != nil {
			old.CloseIdleConnections()
		}
	}
}

func (g *Gateway) Close() {
	g.closing.Store(true)
	if g.connections != nil {
		g.connections.Close()
	}
	if g.meter != nil {
		g.meter.Close()
	}
	if g.quota != nil {
		g.quota.Close()
	}
	if g.agent != nil {
		g.agent.Close()
	}
	if g.cluster != nil {
		g.cluster.Close()
	}
	if g.cloudflare != nil {
		g.cloudflare.Close()
	}
	if g.axisnow != nil {
		g.axisnow.Close()
	}
	if g.embyHealth != nil {
		g.embyHealth.Close()
	}
	if g.telegram != nil {
		g.telegram.Close()
	}
	if g.backups != nil {
		g.backups.Close()
	}
	if g.geo != nil {
		g.geo.Close()
	}
	if g.transport != nil {
		g.transport.CloseIdleConnections()
	}
	if g.telemetry != nil {
		g.telemetry.Close()
	}
}

func (g *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if g.cluster != nil && g.cluster.HandleAgentAPI(writer, request) {
		return
	}
	if request.URL.Path == "/_gateway/avatar" || publicFrontendAssets[request.URL.Path].file != "" {
		if g.cfg.Role == RoleAgent {
			rt := g.liveRuntime()
			_, _, _, _, matched, enforced := g.matchAssignedDomain(request, rt)
			if enforced && !matched {
				writeGatewayError(writer, http.StatusMisdirectedRequest, "domain is not assigned to this edge node")
				return
			}
			if !enforced && rt.PublicBaseURL == nil {
				writeGatewayError(writer, http.StatusNotFound, "edge node online; no domain assigned yet")
				return
			}
		}
		if g.serveBrandAvatar(writer, request) {
			return
		}
		if servePublicFrontendAsset(writer, request) {
			return
		}
	}
	if g.cfg.Role != RoleAgent {
		if g.cfg.Role == RoleController && request.URL.Path == "/" && !g.publicPortal.Load() {
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			http.Redirect(writer, request, "/login", http.StatusFound)
			return
		}
		if servePublicFrontendPageWithRole(writer, request, g.cfg.Role) {
			return
		}
		if g.admin != nil && g.admin.Handle(writer, request) {
			return
		}
	}
	if request.URL.Path == "/_gateway/nodes" {
		if g.cfg.Role == RoleAgent {
			rt := g.liveRuntime()
			_, _, _, _, matched, enforced := g.matchAssignedDomain(request, rt)
			if enforced && !matched {
				writeGatewayError(writer, http.StatusMisdirectedRequest, "domain is not assigned to this edge node")
				return
			}
			if !enforced && rt.PublicBaseURL == nil {
				writeGatewayError(writer, http.StatusNotFound, "edge node online; no domain assigned yet")
				return
			}
		}
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeGatewayError(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		nodes := make([]publicEdgeNode, 0)
		if g.cluster != nil && g.cfg.Role != RoleController {
			var err error
			nodes, err = g.cluster.PublicNodes(request.Context())
			if err != nil {
				writeGatewayError(writer, http.StatusInternalServerError, "edge nodes unavailable")
				return
			}
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"role":  g.cfg.Role,
			"nodes": nodes,
		})
		return
	}
	if request.URL.Path == "/_gateway/emby-health" {
		if g.cfg.Role == RoleAgent {
			rt := g.liveRuntime()
			_, _, _, _, matched, enforced := g.matchAssignedDomain(request, rt)
			if enforced && !matched {
				writeGatewayError(writer, http.StatusMisdirectedRequest, "domain is not assigned to this edge node")
				return
			}
			if !enforced && rt.PublicBaseURL == nil {
				writeGatewayError(writer, http.StatusNotFound, "edge node online; no domain assigned yet")
				return
			}
		}
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeGatewayError(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		servers := make([]embyHealthServer, 0)
		if g.cfg.Role == RoleStandalone && g.telemetry != nil {
			var err error
			servers, err = g.telemetry.EmbyHealthServers(request.Context(), false)
			if err != nil {
				writeGatewayError(writer, http.StatusInternalServerError, "health status unavailable")
				return
			}
		}
		writeJSON(writer, http.StatusOK, embyHealthPublicSnapshot(servers))
		return
	}
	if request.URL.Path == "/_gateway/health" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
			writeGatewayError(writer, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		rt := g.liveRuntime()
		agentRestricted := false
		var healthDomainWAF []*compiledWAFRule
		if g.cfg.Role == RoleAgent {
			domRT, _, _, domWAF, matched, enforced := g.matchAssignedDomain(request, rt)
			if enforced {
				if matched {
					rt = domRT
					healthDomainWAF = domWAF
				} else {
					agentRestricted = true
				}
			} else if rt.PublicBaseURL == nil {
				agentRestricted = true
			}
		}
		var payload map[string]any
		if agentRestricted {
			payload = map[string]any{
				"ok":       true,
				"role":     g.cfg.Role,
				"draining": g.draining.Load(),
			}
		} else {
			publicBaseURL := ""
			if rt.PublicBaseURL != nil {
				publicBaseURL = strings.TrimRight(rt.PublicBaseURL.String(), "/")
			}
			payload = map[string]any{
				"ok":                   true,
				"role":                 g.cfg.Role,
				"version":              normalizedVersion(Version),
				"public_base_url":      publicBaseURL,
				"has_default_upstream": rt.DefaultUpstream != nil,
			}
			if g.agent != nil {
				nodeID, nodeName, rev, _ := g.agent.Status()
				payload["node_id"] = nodeID
				payload["node_name"] = nodeName
				payload["applied_revision"] = rev
				payload["draining"] = g.draining.Load()
			}
			if g.cluster != nil {
				if g.cfg.Role == RoleController {
					if g.publicPortal.Load() {
						payload["online_nodes"] = g.cluster.OnlineNodeCount(request.Context())
					}
				} else if nodes, err := g.cluster.PublicNodes(request.Context()); err == nil {
					payload["online_nodes"] = len(nodes)
				}
			}
			if g.cfg.Role != RoleController {
				client := rt.clientIP(request)
				if geoBlocked, geoCountry, geoMessage := g.evaluateHomepageGeoBlock(request, client, healthDomainWAF, rt); geoBlocked {
					payload["geo_blocked"] = true
					if geoCountry != "" {
						payload["geo_country"] = geoCountry
					}
					if geoMessage != "" {
						payload["geo_message"] = geoMessage
					}
				}
			}
		}
		if request.Method == http.MethodHead {
			writer.Header().Set("Content-Type", "application/json; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusOK)
			return
		}
		writeJSON(writer, http.StatusOK, payload)
		return
	}
	if g.cfg.Role == RoleController {
		writeGatewayError(writer, http.StatusNotFound, "controller mode does not proxy traffic; connect via an edge node")
		return
	}
	if request.Method == http.MethodOptions {
		writeCORSPreflight(writer, request)
		return
	}
	if g.draining.Load() {
		writer.Header().Set("Retry-After", "10")
		writeGatewayError(writer, http.StatusServiceUnavailable, "edge node is draining")
		return
	}

	rt := g.liveRuntime()
	activeBandwidth := g.bandwidth
	var domLim *requestLimiter
	var domainWAFRules []*compiledWAFRule
	if g.cfg.Role == RoleAgent {
		domRT, domBW, matchedLim, domWAF, matched, enforced := g.matchAssignedDomain(request, rt)
		if enforced && !matched {
			g.blocked.Add(1)
			writeGatewayError(writer, http.StatusMisdirectedRequest, "domain is not assigned to this edge node")
			return
		}
		if !enforced && rt.PublicBaseURL == nil {
			writeGatewayError(writer, http.StatusNotFound, "edge node online; no domain assigned yet")
			return
		}
		rt = domRT
		domainWAFRules = domWAF
		if domBW != nil {
			activeBandwidth = domBW
		}
		if matchedLim != nil {
			domLim = matchedLim
		}
	}
	var trustedPublicHosts []string
	if rt.PublicBaseURL != nil {
		trustedPublicHosts = append(trustedPublicHosts, rt.PublicBaseURL.Host)
	}
	target, dynamic, expires, signature, err := parseRawTarget(request, trustedPublicHosts...)
	if err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid target URL")
		return
	}
	client := rt.clientIP(request)
	policy := g.policy.Load()
	policyCheckedAt := time.Now()
	var reqDeviceTarget *url.URL
	if dynamic {
		reqDeviceTarget = target
	}
	device := requestDeviceIdentityForTarget(request, reqDeviceTarget)

	if !dynamic {
		defaultUpstream := rt.DefaultUpstream
		if defaultUpstream == nil {
			if g.cfg.Role == RoleAgent && g.publicPortal.Load() && request.URL.Path == "/" && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
				// Only enforce explicit IP-ban rules on Agent GET / so abusive IPs stay blocked,
				// while player, host, path, schedule, and geo rules never lock browsers out of the homepage.
				reqHost := normalizeHost(stripHostPort(request.Host))
				if g.evaluateHomepageIPAccess(writer, request, reqHost, client, policy, device, domainWAFRules) {
					return
				}
				if servePublicFrontendPageWithRole(writer, request, g.cfg.Role) {
					return
				}
			}
			writeGatewayError(writer, http.StatusNotFound, "Gateway Active. No Target.")
			return
		}
		target = defaultTarget(defaultUpstream, request.URL)
	} else if !g.authorizeDynamicTargetWithRuntime(rt, target, expires, signature) {
		g.blocked.Add(1)
		writeGatewayError(writer, http.StatusForbidden, "target is not allowed")
		return
	}

	if g.evaluateIngressAccess(writer, request, target.Hostname(), target.Scheme, target.EscapedPath(), target.RawQuery, client, policy, policyCheckedAt, device, domainWAFRules, rt) {
		return
	}
	if !policy.PlayerPolicy.AllowsClient(device.ClientName) {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: target.Host, Scheme: target.Scheme, Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: target.EscapedPath(), Category: "player-policy", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "player is blocked by proxy player policy")
		return
	}
	allowed, quotaRule := policy.evaluateAt(target, policyCheckedAt)
	if !allowed {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: target.Host, Scheme: target.Scheme, Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: target.EscapedPath(), Category: "policy", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "target is blocked by proxy policy")
		return
	}
	var quota *domainQuotaAccount
	if quotaRule != nil {
		quota = quotaRule.quota
	}
	if quota != nil && quota.Exhausted() {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: target.Host, Scheme: target.Scheme, Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: target.EscapedPath(), Category: "quota", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "domain traffic quota exhausted")
		return
	}
	if !g.limiter.Acquire(client) {
		g.blocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		writeGatewayError(writer, http.StatusTooManyRequests, "proxy concurrency limit reached")
		return
	}
	defer g.limiter.Release(client)
	if domLim != nil {
		if !domLim.Acquire(client) {
			g.blocked.Add(1)
			writer.Header().Set("Retry-After", "5")
			writeGatewayError(writer, http.StatusTooManyRequests, "proxy concurrency limit reached")
			return
		}
		defer domLim.Release(client)
	}
	if g.playback != nil && g.playback.IsRequestBlocked(client, target.Host, target.EscapedPath(), target.RawQuery, device.ID, device.ClientName, time.Now()) {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: target.Host, Scheme: target.Scheme, Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: target.EscapedPath(), Category: "playback-terminated", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "playback session terminated by administrator")
		return
	}
	g.active.Add(1)
	defer g.active.Add(-1)
	var requestContext context.Context
	var cancelRequest context.CancelFunc
	if policy.ScheduleEnabled {
		if open, closesAt := policy.scheduleStatus(policyCheckedAt); open && !closesAt.IsZero() {
			requestContext, cancelRequest = context.WithDeadline(request.Context(), closesAt)
		}
	}
	if requestContext == nil {
		requestContext, cancelRequest = context.WithCancel(request.Context())
	}
	defer cancelRequest()
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	flow := g.connections.StartForIdentity(cancelRequest, client, request.Method, target.Host, normalizeHost(target.Hostname()), path, resourceCategory(path), request.UserAgent(), device.ID, device.ClientName)
	flow.deviceName = device.DeviceName
	defer g.connections.Finish(flow)
	request = request.WithContext(requestContext)

	publicCfg := g.cfg
	publicCfg.PublicBaseURL = rt.PublicBaseURL
	publicCfg.TrustProxyHeaders = rt.TrustProxyHeaders
	publicCfg.TrustedProxyCIDRs = rt.TrustedProxyCIDRs
	publicBase, err := publicBaseForRequest(publicCfg, request)
	if err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid public proxy URL")
		return
	}
	dialAddresses, err := g.resolver.ResolveWithMode(request.Context(), target, rt.UpstreamIPMode)
	if err != nil {
		g.blocked.Add(1)
		log.Printf("target resolve blocked host=%s err=%v", target.Hostname(), err)
		writeGatewayError(writer, http.StatusForbidden, "target resolution blocked")
		return
	}
	passIP := rt.PassClientIP
	disableCache := rt.DisableCache
	embyToken, embyTokenHash, embyUserID := extractEmbyRequestCredentials(request, target)
	pbMeta := playbackRequestMeta{
		ClientIP:      client,
		DeviceID:      device.ID,
		DeviceName:    device.DeviceName,
		ClientName:    device.ClientName,
		UpstreamHost:  target.Host,
		Scheme:        target.Scheme,
		Path:          path,
		RawQuery:      target.RawQuery,
		Token:         embyToken,
		TokenHash:     embyTokenHash,
		UserID:        embyUserID,
		DialAddresses: dialAddresses,
		Flow:          flow,
	}
	var playingReportBody []byte
	if g.playback != nil {
		if request.Method == http.MethodPost && request.Body != nil && request.Body != http.NoBody {
			if _, isReport := isEmbyPlayingReportPath(path); isReport {
				peek, _ := io.ReadAll(io.LimitReader(request.Body, playbackPeekBodyLimit))
				playingReportBody = peek
				request.Body = &combinedReadCloser{
					Reader: io.MultiReader(bytes.NewReader(peek), request.Body),
					Closer: request.Body,
				}
			}
		}
		if request.Method == http.MethodGet {
			streamItemID, needLookup, blocked := g.playback.ObserveStreamStart(pbMeta)
			if blocked {
				g.blocked.Add(1)
				g.recordPolicyBlock(telemetryEvent{
					Timestamp: time.Now(), ClientIP: client, Host: target.Host, Scheme: target.Scheme, Method: request.Method,
					DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
					Path: path, Category: "playback-terminated", Status: http.StatusForbidden,
				})
				writeGatewayError(writer, http.StatusForbidden, "playback session terminated by administrator")
				return
			}
			if needLookup {
				g.playback.FetchItemMetadataAsync(pbMeta, streamItemID)
			}
		}
	}
	info := &targetInfo{
		URL:               target,
		Dynamic:           dynamic,
		PublicBase:        publicBase,
		ClientOrigin:      request.Header.Get("Origin"),
		DialAddresses:     dialAddresses,
		PassClientIP:      &passIP,
		DisableCache:      &disableCache,
		DefaultUpstream:   rt.DefaultUpstream,
		RewriteMaxBytes:   rt.RewriteMaxBytes,
		PlaybackMeta:      pbMeta,
		PlayingReportBody: playingReportBody,
	}

	started := time.Now()
	var uploadCounter *countingReadCloser
	if request.Body != nil && request.Body != http.NoBody {
		uploadCounter = &countingReadCloser{ReadCloser: request.Body, meter: g.meter, flow: flow}
		request.Body = uploadCounter
	}
	loggingWriter := &accessResponseWriter{
		ResponseWriter: writer, meter: g.meter, flow: flow, clientIP: client,
		bandwidth: activeBandwidth, quota: quota, context: request.Context(),
	}
	proxiedRequest := request.WithContext(context.WithValue(request.Context(), targetContextKey{}, info))
	defer g.finalizeProxyRequest(request, target, path, client, started, loggingWriter, flow, pbMeta)
	g.proxy.ServeHTTP(loggingWriter, proxiedRequest)
}

func (g *Gateway) evaluateIngressAccess(
	writer http.ResponseWriter,
	request *http.Request,
	targetHost, targetScheme, targetPath, rawQuery, client string,
	policy *proxyPolicy,
	policyCheckedAt time.Time,
	device deviceIdentity,
	domainWAFRules []*compiledWAFRule,
	rt runtimeSnapshot,
) bool {
	var globalWAF []*compiledWAFRule
	if ptr := g.globalWAFRules.Load(); ptr != nil {
		globalWAF = *ptr
	}
	if len(globalWAF) > 0 || len(domainWAFRules) > 0 {
		needsGeo := false
		for _, r := range globalWAF {
			if r != nil && r.usesGeo {
				needsGeo = true
				break
			}
		}
		if !needsGeo {
			for _, r := range domainWAFRules {
				if r != nil && r.usesGeo {
					needsGeo = true
					break
				}
			}
		}
		country := ""
		if needsGeo {
			country = g.resolveClientCountryWithRuntime(request, client, rt)
		}
		wafCtx := wafEvalContext{
			TargetHost:  targetHost,
			ClientIP:    client,
			CountryCode: country,
			Path:        targetPath,
			RawQuery:    rawQuery,
			UserAgent:   request.UserAgent(),
			ClientName:  device.ClientName,
			Now:         policyCheckedAt,
		}
		decision := evaluateWAFRules(globalWAF, wafCtx)
		if !decision.Blocked && len(domainWAFRules) > 0 {
			decision = evaluateWAFRules(domainWAFRules, wafCtx)
		}
		if decision.Blocked {
			g.blocked.Add(1)
			if needsGeo && country == "" && g.geo != nil {
				g.geo.ObserveClient(client)
			}
			status := decision.StatusCode
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			msg := decision.Message
			if msg == "" {
				msg = "blocked by WAF rule"
			}
			g.recordPolicyBlock(telemetryEvent{
				Timestamp: time.Now(), ClientIP: client, Host: targetHost, Scheme: targetScheme, Method: request.Method,
				DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
				Path: targetPath, Category: "waf", Status: status,
			})
			writeGatewayError(writer, status, msg)
			return true
		}
	}
	if policy == nil {
		return false
	}
	if !policy.ClientAccess.AllowsIP(client) {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: targetHost, Scheme: targetScheme, Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: targetPath, Category: "client-ip-policy", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "client IP is blocked by access policy")
		return true
	}
	if policy.ClientAccess.GeoMode != "" && policy.ClientAccess.GeoMode != proxyModeOff {
		country := g.resolveClientCountryWithRuntime(request, client, rt)
		if !policy.ClientAccess.AllowsCountry(country) {
			g.blocked.Add(1)
			if country == "" && g.geo != nil {
				g.geo.ObserveClient(client)
			}
			g.recordPolicyBlock(telemetryEvent{
				Timestamp: time.Now(), ClientIP: client, Host: targetHost, Scheme: targetScheme, Method: request.Method,
				DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
				Path: targetPath, Category: "geo-policy", Status: http.StatusForbidden,
			})
			writeGatewayError(writer, http.StatusForbidden, "region is blocked by access policy")
			return true
		}
	}
	return false
}

func (g *Gateway) evaluateHomepageIPAccess(
	writer http.ResponseWriter,
	request *http.Request,
	reqHost, client string,
	policy *proxyPolicy,
	device deviceIdentity,
	domainWAFRules []*compiledWAFRule,
) bool {
	var globalWAF []*compiledWAFRule
	if ptr := g.globalWAFRules.Load(); ptr != nil {
		globalWAF = *ptr
	}
	decision := evaluateWAFRulesIPOnly(globalWAF, client)
	if !decision.Blocked && len(domainWAFRules) > 0 {
		decision = evaluateWAFRulesIPOnly(domainWAFRules, client)
	}
	if decision.Blocked {
		g.blocked.Add(1)
		status := decision.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		msg := decision.Message
		if msg == "" {
			msg = "blocked by WAF rule"
		}
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: reqHost, Scheme: "https", Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: "/", Category: "waf", Status: status,
		})
		writeGatewayError(writer, status, msg)
		return true
	}
	if policy != nil && !policy.ClientAccess.AllowsIP(client) {
		g.blocked.Add(1)
		g.recordPolicyBlock(telemetryEvent{
			Timestamp: time.Now(), ClientIP: client, Host: reqHost, Scheme: "https", Method: request.Method,
			DeviceID: device.ID, DeviceName: device.DeviceName, ClientName: device.ClientName,
			Path: "/", Category: "client-ip-policy", Status: http.StatusForbidden,
		})
		writeGatewayError(writer, http.StatusForbidden, "client IP is blocked by access policy")
		return true
	}
	return false
}

func (g *Gateway) evaluateHomepageGeoBlock(
	request *http.Request,
	client string,
	domainWAFRules []*compiledWAFRule,
	rt runtimeSnapshot,
) (bool, string, string) {
	var globalWAF []*compiledWAFRule
	if ptr := g.globalWAFRules.Load(); ptr != nil {
		globalWAF = *ptr
	}
	policy := g.policy.Load()
	hasPolicyGeo := policy != nil && policy.ClientAccess.GeoMode != "" && policy.ClientAccess.GeoMode != proxyModeOff
	needsGeo := hasPolicyGeo
	if !needsGeo {
		for _, r := range globalWAF {
			if r != nil && r.usesGeo {
				needsGeo = true
				break
			}
		}
	}
	if !needsGeo {
		for _, r := range domainWAFRules {
			if r != nil && r.usesGeo {
				needsGeo = true
				break
			}
		}
	}
	if !needsGeo {
		return false, "", ""
	}
	country := g.resolveClientCountryWithRuntime(request, client, rt)
	if country == "" && g.geo != nil {
		g.geo.ObserveClient(client)
	}
	now := time.Now()
	if decision := evaluateWAFRulesGeoOnly(globalWAF, country, client, now); decision.Blocked {
		return true, country, decision.Message
	}
	if decision := evaluateWAFRulesGeoOnly(domainWAFRules, country, client, now); decision.Blocked {
		return true, country, decision.Message
	}
	if hasPolicyGeo && !policy.ClientAccess.AllowsCountry(country) {
		return true, country, "region is blocked by access policy"
	}
	return false, "", ""
}

func (g *Gateway) resolveClientCountry(request *http.Request, clientIP string) string {
	return g.resolveClientCountryWithRuntime(request, clientIP, g.liveRuntime())
}

func (g *Gateway) resolveClientCountryWithRuntime(request *http.Request, clientIP string, rt runtimeSnapshot) string {
	if rt.TrustProxyHeaders && request != nil && isTrustedProxyPeer(request.RemoteAddr, rt.TrustedProxyCIDRs) && (rt.RealIPHeader == "" || strings.EqualFold(rt.RealIPHeader, "CF-Connecting-IP")) {
		if cf := strings.ToUpper(strings.TrimSpace(request.Header.Get("CF-IPCountry"))); len(cf) == 2 && cf != "XX" && cf != "T1" {
			return cf
		}
	}
	normalized := normalizeTelemetryClientIP(clientIP)
	if normalized == "" {
		return ""
	}
	if table := g.ipCountries.Load(); table != nil {
		if code := (*table)[normalized]; code != "" {
			return code
		}
	}
	if g.telemetry != nil {
		ctx := context.Background()
		if request != nil {
			ctx = request.Context()
		}
		if loc, found, err := g.telemetry.cachedGeo(ctx, normalized); err == nil && found && loc.CountryCode != "" {
			return strings.ToUpper(strings.TrimSpace(loc.CountryCode))
		}
	}
	return ""
}

func (g *Gateway) terminatePlaybackSession(sessionKey, flowID string) int {
	var canceled int
	var clientIP, upstreamHost, itemID string
	if g.playback != nil && strings.TrimSpace(sessionKey) != "" {
		canceled, clientIP, upstreamHost, itemID = g.playback.TerminateSession(sessionKey, playbackKickBlockTTL)
	}
	if g.connections != nil {
		if clientIP != "" && upstreamHost != "" && itemID != "" {
			matchIDs := []string{itemID}
			if g.playback != nil {
				matchIDs = append(matchIDs, g.playback.AliasItemIDs(upstreamHost, itemID)...)
			}
			canceled += g.connections.CancelMatchingStream(clientIP, upstreamHost, matchIDs...)
		}
		if flowID != "" && g.connections.Cancel(flowID) {
			canceled++
		}
	}
	return canceled
}

func (g *Gateway) recordPolicyBlock(event telemetryEvent) {
	if g.telemetry != nil {
		g.telemetry.Record(event)
	}
	if g.agent != nil {
		g.agent.EnqueueEvent(event)
	}
}

func (g *Gateway) finalizeProxyRequest(request *http.Request, target *url.URL, path, client string, started time.Time, loggingWriter *accessResponseWriter, flow *connectionFlow, pbMeta playbackRequestMeta) {
	status := loggingWriter.status
	if request.Context().Err() != nil {
		status = 499
	} else if status == 0 {
		status = http.StatusOK
	}
	bytesIn := flow.uploadTotal.Load()
	bytesOut := flow.downloadTotal.Load()
	if g.playback != nil {
		g.playback.ObserveStreamEnd(pbMeta, bytesOut)
		if g.telemetry != nil && g.cfg.Role == RoleStandalone && !g.closing.Load() {
			nowUnix := time.Now().Unix()
			if nowUnix-g.watchSyncLast.Load() >= 5 && g.watchSyncBusy.CompareAndSwap(false, true) {
				g.watchSyncLast.Store(nowUnix)
				active := g.playback.Snapshot()
				if len(active) > 0 {
					for i := range active {
						active[i].NodeID = "local"
						active[i].NodeName = "本机节点"
					}
					go func(items []playbackSessionSnapshot) {
						defer g.watchSyncBusy.Store(false)
						if g.closing.Load() {
							return
						}
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						_ = g.telemetry.UpsertWatchHistory(ctx, items)
					}(active)
				} else {
					g.watchSyncBusy.Store(false)
				}
			}
		}
	}
	duration := time.Since(started)
	log.Printf("method=%s status=%d bytes=%d duration=%s target=%s://%s", request.Method, status, bytesOut, duration.Round(time.Millisecond), target.Scheme, target.Host)
	if len(path) > 512 {
		path = path[:512]
	}
	event := telemetryEvent{
		FlowID:     flow.id,
		Timestamp:  time.Now(),
		ClientIP:   client,
		DeviceID:   flow.deviceID,
		DeviceName: flow.deviceName,
		ClientName: flow.clientName,
		Host:       target.Host,
		Scheme:     target.Scheme,
		Method:     request.Method,
		Path:       path,
		Category:   resourceCategory(path),
		Status:     status,
		BytesIn:    bytesIn,
		BytesOut:   bytesOut,
		DurationMS: duration.Milliseconds(),
	}
	if g.telemetry != nil {
		g.telemetry.RecordCompleted(event, g.connections, flow)
	} else if g.agent != nil {
		g.agent.EnqueueEvent(event)
		g.connections.Finish(flow)
	}
	if g.geo != nil {
		g.geo.ObserveClient(client)
	}
}

func (g *Gateway) authorizeDynamicTarget(target *url.URL, expires, signature string) bool {
	return g.authorizeDynamicTargetWithRuntime(g.liveRuntime(), target, expires, signature)
}

func (g *Gateway) authorizeDynamicTargetWithRuntime(rt runtimeSnapshot, target *url.URL, expires, signature string) bool {
	for _, pattern := range rt.AllowedUpstreams {
		if pattern.Matches(target) {
			return true
		}
	}
	if rt.AllowUnsigned {
		return true
	}
	if expires != "" && signature != "" && g.liveSigner().Verify(target, expires, signature) {
		return true
	}

	// When an administrator explicitly enables a domain policy, that policy is
	// also the source of truth for dynamic targets. Otherwise a panel-managed
	// whitelist could never pass the earlier environment allowlist gate, and a
	// blacklist could not implement its advertised "allow everything else"
	// behavior. Policy-off keeps the closed-by-default behavior above.
	policy := g.policy.Load()
	if policy == nil {
		return false
	}
	switch policy.Mode {
	case proxyModeBlacklist:
		return true
	case proxyModeWhitelist:
		return policy.matchingRule(normalizeHost(target.Hostname()), "allow") != nil
	default:
		return false
	}
}

func (g *Gateway) rewriteRequest(proxyRequest *httputil.ProxyRequest) {
	info, _ := proxyRequest.In.Context().Value(targetContextKey{}).(*targetInfo)
	if info == nil {
		return
	}
	target := *info.URL
	proxyRequest.Out.URL = &target
	proxyRequest.Out.Host = target.Host
	proxyRequest.Out.RequestURI = ""

	headers := proxyRequest.Out.Header
	for _, name := range []string{
		"CF-Connecting-IP", "True-Client-IP", "EO-Connecting-IP", "CF-IPCountry", "CF-Ray", "CF-Visitor", "CDN-Loop",
		"Forwarded", "Via", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host",
		"X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Prefix",
	} {
		headers.Del(name)
	}
	passClientIP := g.liveRuntime().PassClientIP
	if info.PassClientIP != nil {
		passClientIP = *info.PassClientIP
	}
	if passClientIP {
		proxyRequest.SetXForwarded()
		if realIP := strings.TrimSpace(info.PlaybackMeta.ClientIP); realIP != "" && realIP != "unknown" {
			headers.Set("X-Forwarded-For", realIP)
			headers.Set("X-Real-IP", realIP)
		}
	}
	headers.Del("Accept-Encoding")
	stripCookieFromHeader(headers, adminCookieName)
	headers.Set("Host", target.Host)
	if headers.Get("Origin") != "" {
		headers.Set("Origin", target.Scheme+"://"+target.Host)
	}
	if headers.Get("Referer") != "" {
		referer := target
		referer.Fragment = ""
		headers.Set("Referer", referer.String())
	}
}

func stripCookieFromHeader(headers http.Header, bannedName string) {
	values := headers.Values("Cookie")
	if len(values) == 0 {
		return
	}
	headers.Del("Cookie")
	for _, raw := range values {
		parts := strings.Split(raw, ";")
		kept := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			name, _, _ := strings.Cut(trimmed, "=")
			if strings.EqualFold(strings.TrimSpace(name), bannedName) {
				continue
			}
			kept = append(kept, trimmed)
		}
		if len(kept) > 0 {
			headers.Add("Cookie", strings.Join(kept, "; "))
		}
	}
}

func sanitizeProxyLogError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr != nil {
		cleaned := urlErr.URL
		if parsed, parseErr := url.Parse(urlErr.URL); parseErr == nil {
			parsed.RawQuery = ""
			parsed.Fragment = ""
			cleaned = parsed.String()
		}
		return fmt.Sprintf("%s %q: %v", urlErr.Op, cleaned, urlErr.Err)
	}
	return err.Error()
}

func (g *Gateway) handleProxyError(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) ||
		(errors.Is(err, context.DeadlineExceeded) && request.Context().Err() != nil) {
		if loggingWriter, ok := writer.(*accessResponseWriter); ok && loggingWriter.status == 0 {
			loggingWriter.status = 499
		}
		return
	}
	log.Printf("proxy error: %s", sanitizeProxyLogError(err))
	writeGatewayError(writer, http.StatusBadGateway, "upstream request failed")
}

func sameDialAddress(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil {
		return strings.EqualFold(left, right)
	}
	return normalizeHost(leftHost) == normalizeHost(rightHost) && leftPort == rightPort
}

func isSafeCORSHeaderList(raw string) bool {
	if raw == "" || len(raw) > 512 {
		return false
	}
	for _, ch := range raw {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == ',' || ch == ' ') {
			return false
		}
	}
	return true
}

func writeCORSPreflight(writer http.ResponseWriter, request *http.Request) {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	allowedHeaders := strings.TrimSpace(request.Header.Get("Access-Control-Request-Headers"))
	if !isSafeCORSHeaderList(allowedHeaders) {
		allowedHeaders = "Authorization, Content-Type, Range, X-Emby-Authorization, X-Emby-Token, X-MediaBrowser-Authorization, X-MediaBrowser-Token"
	}
	headers := writer.Header()
	if origin != "" && sameOriginRequest(request) {
		headers.Set("Access-Control-Allow-Origin", origin)
		headers.Set("Access-Control-Allow-Credentials", "true")
		headers.Set("Vary", "Origin, Access-Control-Request-Headers")
	} else {
		headers.Set("Access-Control-Allow-Origin", "*")
		headers.Del("Access-Control-Allow-Credentials")
		headers.Set("Vary", "Origin, Access-Control-Request-Headers")
	}
	headers.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	headers.Set("Access-Control-Allow-Headers", allowedHeaders)
	headers.Set("Access-Control-Max-Age", "86400")
	writer.WriteHeader(http.StatusNoContent)
}

func writeGatewayError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"error": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func resourceCategory(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".m3u8"), strings.HasSuffix(lower, ".mpd"):
		return "manifest"
	case strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".m4s"):
		return "segment"
	case strings.Contains(lower, "/videos/"), strings.HasSuffix(lower, ".mp4"), strings.HasSuffix(lower, ".mkv"), strings.HasSuffix(lower, ".webm"):
		return "stream"
	case strings.Contains(lower, "/images/"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".webp"):
		return "image"
	case strings.HasSuffix(lower, ".srt"), strings.HasSuffix(lower, ".ass"), strings.HasSuffix(lower, ".vtt"):
		return "subtitle"
	case strings.Contains(lower, "playbackinfo"):
		return "playback"
	default:
		return "api"
	}
}

type byteBufferPool struct {
	size int
	pool sync.Pool
}

func newByteBufferPool(size int) *byteBufferPool {
	return &byteBufferPool{size: size}
}

func (p *byteBufferPool) Get() []byte {
	if value := p.pool.Get(); value != nil {
		return value.([]byte)
	}
	return make([]byte, p.size)
}

func (p *byteBufferPool) Put(buffer []byte) {
	if cap(buffer) < p.size {
		return
	}
	p.pool.Put(buffer[:p.size])
}

type accessResponseWriter struct {
	http.ResponseWriter
	status    int
	bytes     int64
	meter     *rateMeter
	flow      *connectionFlow
	clientIP  string
	bandwidth *bandwidthLimiter
	quota     *domainQuotaAccount
	context   context.Context
}

func (w *accessResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *accessResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	written, err := writeMeteredPayload(w.context, w.bandwidth, w.quota, w.clientIP, data, w.ResponseWriter.Write)
	w.bytes += int64(written)
	w.meter.AddDownload(int64(written))
	w.meter.AddClientDownload(w.clientIP, int64(written))
	w.flow.AddDownload(int64(written))
	return written, err
}

func (w *accessResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return io.CopyBuffer(struct{ io.Writer }{w}, reader, make([]byte, bandwidthWriteChunk))
}

func (w *accessResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *accessResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	metered := &meteredConn{
		Conn: connection, meter: w.meter, flow: w.flow, clientIP: w.clientIP,
		bandwidth: w.bandwidth, quota: w.quota, context: w.context,
	}
	return metered, bufio.NewReadWriter(buffered.Reader, bufio.NewWriter(metered)), nil
}
