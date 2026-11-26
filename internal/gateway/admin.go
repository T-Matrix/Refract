package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const adminCookieName = "vug_admin_session"

var dummyLoginBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("refract-dummy-constant-time-check"), bcrypt.DefaultCost)

//go:embed web/*
var webAssets embed.FS

type adminSession struct {
	Username string
	Version  int64
	Expires  int64
}

type adminServer struct {
	gateway           *Gateway
	store             *telemetryStore
	username          string
	secret            []byte
	setupToken        string
	sessionTTL        time.Duration
	trustProxy        bool
	trustedProxyCIDRs []netip.Prefix
	assets            http.Handler
	revokedMu         sync.Mutex
	revokedTokens     map[string]int64
}

func newAdminServer(gateway *Gateway, store *telemetryStore, cfg Config) (*adminServer, error) {
	assets, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, err
	}
	return &adminServer{
		gateway:           gateway,
		store:             store,
		username:          cfg.AdminUsername,
		secret:            append([]byte(nil), cfg.AdminSessionSecret...),
		setupToken:        strings.TrimSpace(cfg.AdminSetupToken),
		sessionTTL:        cfg.AdminSessionTTL,
		trustProxy:        cfg.TrustProxyHeaders,
		trustedProxyCIDRs: append([]netip.Prefix(nil), cfg.TrustedProxyCIDRs...),
		assets:            http.FileServer(http.FS(assets)),
		revokedTokens:     make(map[string]int64),
	}, nil
}

func (a *adminServer) Handle(w http.ResponseWriter, r *http.Request) bool {
	if a == nil {
		return false
	}
	switch {
	case r.URL.Path == "/setup":
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet+", "+http.MethodHead)
			return true
		}
		installed, err := a.store.HasAdministrator(r.Context())
		if err != nil {
			http.Error(w, "admin database unavailable", http.StatusInternalServerError)
			return true
		}
		if installed {
			http.Redirect(w, r, "/login", http.StatusFound)
			return true
		}
		a.serveSetupHTML(w, r)
		return true
	case r.URL.Path == "/login":
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet+", "+http.MethodHead)
			return true
		}
		installed, err := a.store.HasAdministrator(r.Context())
		if err != nil {
			http.Error(w, "admin database unavailable", http.StatusInternalServerError)
			return true
		}
		if !installed {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return true
		}
		if _, ok := a.authenticate(r); ok {
			http.Redirect(w, r, "/panel", http.StatusFound)
			return true
		}
		a.serveAsset(w, r, "/login.html", false)
		return true
	case r.URL.Path == "/panel":
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet+", "+http.MethodHead)
			return true
		}
		installed, err := a.store.HasAdministrator(r.Context())
		if err != nil {
			http.Error(w, "admin database unavailable", http.StatusInternalServerError)
			return true
		}
		if !installed {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return true
		}
		if _, ok := a.authenticate(r); !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return true
		}
		a.servePanelHTML(w, r)
		return true
	case strings.HasPrefix(r.URL.Path, "/_admin/assets/"):
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet+", "+http.MethodHead)
			return true
		}
		assetPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/_admin/assets/"))
		if !isPublicAdminAsset(assetPath) {
			http.NotFound(w, r)
			return true
		}
		a.serveAsset(w, r, assetPath, true)
		return true
	case strings.HasPrefix(r.URL.Path, "/_admin/api/"):
		a.secureHeaders(w)
		a.handleAPI(w, r)
		return true
	default:
		return false
	}
}

func isPublicAdminAsset(cleanPath string) bool {
	if cleanPath == "/" || strings.HasSuffix(cleanPath, "/") || strings.Contains(cleanPath, "..") {
		return false
	}
	ext := strings.ToLower(path.Ext(cleanPath))
	switch ext {
	case ".js", ".css", ".json", ".svg", ".png", ".ico", ".jpg", ".jpeg", ".webp", ".woff", ".woff2":
		return true
	default:
		return false
	}
}

func (a *adminServer) serveSetupHTML(w http.ResponseWriter, r *http.Request) {
	data, err := webAssets.ReadFile("web/setup.html")
	if err != nil {
		http.Error(w, "setup page unavailable", http.StatusInternalServerError)
		return
	}
	rendered := string(data)
	if a.setupToken != "" {
		rendered = strings.Replace(rendered, `<body class="auth-page">`, `<body class="auth-page" data-setup-token-required="true">`, 1)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(rendered)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, rendered)
	}
}

func (a *adminServer) servePanelHTML(w http.ResponseWriter, r *http.Request) {
	data, err := webAssets.ReadFile("web/panel.html")
	if err != nil {
		http.Error(w, "admin panel unavailable", http.StatusInternalServerError)
		return
	}
	bodyTag := `<body class="panel-page" data-role="standalone">`
	if a.gateway != nil && a.gateway.cfg.Role == RoleController {
		bodyTag = `<body class="panel-page mode-controller" data-role="controller">`
	}
	rendered := strings.Replace(string(data), `<body class="panel-page">`, bodyTag, 1)
	rendered = strings.Replace(rendered, ">v2.0.0-beta.1<", ">v"+normalizedVersion(Version)+"<", 1)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(rendered)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, rendered)
	}
}

func (a *adminServer) serveAsset(w http.ResponseWriter, r *http.Request, assetPath string, cache bool) {
	clone := r.Clone(r.Context())
	clone.URL.Path = assetPath
	if cache {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	a.assets.ServeHTTP(w, clone)
}

func (a *adminServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	path := r.URL.Path
	if path == "/_admin/api/login" {
		a.handleLogin(w, r)
		return
	}
	if path == "/_admin/api/setup" {
		a.handleSetup(w, r)
		return
	}
	if path == "/_admin/api/turnstile/public" {
		a.handleTurnstilePublic(w, r)
		return
	}
	session, ok := a.authenticate(r)
	if !ok {
		a.writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if path == "/_admin/api/rules/domain" {
		a.handleDomainRule(w, r)
		return
	}
	if path == "/_admin/api/player-policy" || path == "/_admin/api/device-policy" {
		a.handlePlayerPolicy(w, r)
		return
	}
	if path == "/_admin/api/client-access-policy" {
		a.handleClientAccessPolicy(w, r)
		return
	}
	if path == "/_admin/api/nodes" {
		a.handleEdgeNodes(w, r)
		return
	}
	if path == "/_admin/api/nodes/upgrade-all" {
		a.handleEdgeNodesUpgradeAll(w, r)
		return
	}
	if path == "/_admin/api/nodes/discovery" {
		a.handleClusterDiscovery(w, r)
		return
	}
	if path == "/_admin/api/nodes/discovery/rotate" {
		a.handleClusterDiscoveryRotate(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/nodes/") {
		a.handleEdgeNodeItem(w, r)
		return
	}
	if path == "/_admin/api/domains" {
		a.handleEdgeDomains(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/domains/") {
		a.handleEdgeDomainItem(w, r)
		return
	}
	if path == "/_admin/api/waf-rules" {
		a.handleWAFRules(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/waf-rules/") {
		a.handleWAFRuleItem(w, r)
		return
	}
	if path == "/_admin/api/cloudflare-dns" {
		a.handleCloudflareDNS(w, r)
		return
	}
	if path == "/_admin/api/cloudflare-dns/test" {
		a.handleCloudflareDNSTest(w, r)
		return
	}
	if path == "/_admin/api/cloudflare-dns/sync" {
		a.handleCloudflareDNSSync(w, r)
		return
	}
	if path == "/_admin/api/axisnow-dns" {
		a.handleAxisNowDNS(w, r)
		return
	}
	if path == "/_admin/api/axisnow-dns/test" {
		a.handleAxisNowDNSTest(w, r)
		return
	}
	if path == "/_admin/api/axisnow-dns/metadata" {
		a.handleAxisNowDNSMetadata(w, r)
		return
	}
	if path == "/_admin/api/axisnow-dns/sync" {
		a.handleAxisNowDNSSync(w, r)
		return
	}
	if path == "/_admin/api/smart-dns-profiles" {
		a.handleSmartDNSProfiles(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/smart-dns-profiles/") {
		a.handleSmartDNSProfileItem(w, r)
		return
	}
	if path == "/_admin/api/emby-health" {
		a.handleEmbyHealthServers(w, r)
		return
	}
	if path == "/_admin/api/emby-health/settings" {
		a.handleEmbyHealthSettings(w, r)
		return
	}
	if path == "/_admin/api/emby-health/check-all" {
		a.handleEmbyHealthCheckAll(w, r)
		return
	}
	if path == "/_admin/api/emby-health/batch" {
		a.handleEmbyHealthBatchImport(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/emby-health/") {
		a.handleEmbyHealthServerItem(w, r)
		return
	}
	if path == "/_admin/api/player-rules" {
		a.handlePlayerRules(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/player-rules/") {
		a.handlePlayerRuleDelete(w, r)
		return
	}
	if path == "/_admin/api/playbacks/terminate" {
		a.handlePlaybackTerminate(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/connections/") {
		a.handleConnectionCancel(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/backups/") && path != "/_admin/api/backups/config" && path != "/_admin/api/backups/import" {
		a.handleBackupItem(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/rules/") && strings.Contains(strings.TrimPrefix(path, "/_admin/api/rules/"), "/quota") {
		a.handleRuleQuota(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/rules/") {
		a.handleRuleDelete(w, r)
		return
	}
	switch path {
	case "/_admin/api/session":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{
			"username":              session.Username,
			"expires":               session.Expires,
			"version":               normalizedVersion(Version),
			"role":                  a.gateway.cfg.Role,
			"public_portal_enabled": a.gateway.publicPortal.Load(),
		})
	case "/_admin/api/portal":
		a.handlePublicPortal(w, r)
	case "/_admin/api/update":
		a.handleUpdate(w, r, session)
	case "/_admin/api/update/notes":
		a.handleUpdateNotes(w, r)
	case "/_admin/api/branding":
		a.handleBranding(w, r)
	case "/_admin/api/runtime-config":
		a.handleRuntimeConfig(w, r, session)
	case "/_admin/api/dashboard":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		period, ok := parseOverviewPeriod(r.URL.Query().Get("period"))
		if !ok {
			a.writeError(w, http.StatusBadRequest, "period must be 24h, 7d, or 30d")
			return
		}
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		localConns := a.gateway.connections.Snapshot()
		active := a.gateway.active.Load()
		blocked := a.gateway.blocked.Load()
		allConns := localConns
		if a.gateway.cluster != nil {
			active, blocked = a.gateway.cluster.AggregateCounters(active, blocked, nodeID)
			allConns = a.gateway.cluster.AggregateConnections(r.Context(), localConns, nodeID)
		}
		snapshot, err := a.store.SnapshotForNode(r.Context(), period, nodeID, active, blocked, time.Since(a.gateway.started), allConns)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "dashboard unavailable")
			return
		}
		if a.gateway.cfg.Role == RoleStandalone {
			if servers, healthErr := a.store.EmbyHealthTargetLabels(r.Context()); healthErr == nil {
				decorateTargetSummaries(snapshot.Targets, servers)
				decorateRequestLogs(snapshot.Recent, servers)
			}
		}
		if names, namesErr := a.store.EdgeNodeNames(r.Context()); namesErr == nil {
			decorateRequestLogNodes(snapshot.Recent, names)
		}
		a.store.EnrichRequestLogLocations(r.Context(), snapshot.Recent)
		a.writeJSON(w, http.StatusOK, snapshot)
	case "/_admin/api/live":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		localLive := a.gateway.meter.Snapshot(a.gateway.active.Load())
		localConns := a.gateway.connections.Snapshot()
		if a.gateway.cluster != nil {
			live := a.gateway.cluster.AggregateLive(localLive, localConns, nodeID)
			a.writeJSON(w, http.StatusOK, live)
			return
		}
		localLive.ActiveTargets = summarizeActiveTargets(localConns)
		if a.gateway.playback != nil {
			localLive.WatchingCount = len(a.gateway.playback.Snapshot())
		}
		a.writeJSON(w, http.StatusOK, localLive)
	case "/_admin/api/playbacks":
		a.handlePlaybacks(w, r)
	case "/_admin/api/connections":
		a.handleConnections(w, r)
	case "/_admin/api/reports":
		a.handleReports(w, r)
	case "/_admin/api/reports/export":
		a.handleReportExport(w, r)
	case "/_admin/api/audit":
		a.handleAuditLogs(w, r)
	case "/_admin/api/backups":
		a.handleBackups(w, r)
	case "/_admin/api/backups/config":
		a.handleBackupConfig(w, r)
	case "/_admin/api/backups/import":
		a.handleBackupImport(w, r)
	case "/_admin/api/geography":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		period, ok := parseGeographyPeriod(r.URL.Query().Get("period"))
		if !ok {
			a.writeError(w, http.StatusBadRequest, "period must be 24h, 7d, or 30d")
			return
		}
		snapshot, err := a.store.Geography(r.Context(), period)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "geography unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, snapshot)
	case "/_admin/api/requests":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		page := 1
		if raw := r.URL.Query().Get("page"); raw != "" {
			var err error
			page, err = strconv.Atoi(raw)
			if err != nil || page < 1 || page > 1000000 {
				a.writeError(w, http.StatusBadRequest, "page must be between 1 and 1000000")
				return
			}
		}
		pageSize := 20
		rawPageSize := r.URL.Query().Get("page_size")
		if rawPageSize == "" {
			rawPageSize = r.URL.Query().Get("limit")
		}
		if rawPageSize != "" {
			var err error
			pageSize, err = strconv.Atoi(rawPageSize)
			if err != nil || pageSize < 1 || pageSize > 100 {
				a.writeError(w, http.StatusBadRequest, "page_size must be between 1 and 100")
				return
			}
		}
		var status *int
		if raw := r.URL.Query().Get("status"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 100 || value > 599 {
				a.writeError(w, http.StatusBadRequest, "status must be a valid HTTP status code")
				return
			}
			status = &value
		}
		result, err := a.store.requestLogPageForNode(r.Context(), page, pageSize, r.URL.Query().Get("host"), r.URL.Query().Get("node_id"), r.URL.Query().Get("client_ip"), status)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "request logs unavailable")
			return
		}
		if a.gateway.cfg.Role == RoleStandalone {
			if servers, healthErr := a.store.EmbyHealthTargetLabels(r.Context()); healthErr == nil {
				decorateRequestLogs(result.Logs, servers)
			}
		}
		if names, namesErr := a.store.EdgeNodeNames(r.Context()); namesErr == nil {
			decorateRequestLogNodes(result.Logs, names)
		}
		a.store.EnrichRequestLogLocations(r.Context(), result.Logs)
		a.writeJSON(w, http.StatusOK, map[string]any{
			"logs": result.Logs, "statuses": result.Statuses, "total": result.Total,
			"page": result.Page, "page_size": result.PageSize, "total_pages": result.TotalPages,
			"dropped": a.store.dropped.Load(),
		})
	case "/_admin/api/policy":
		a.handlePolicy(w, r)
	case "/_admin/api/policy/schedule":
		a.handlePolicySchedule(w, r)
	case "/_admin/api/rules":
		a.handleRules(w, r)
	case "/_admin/api/telegram":
		a.handleTelegram(w, r)
	case "/_admin/api/telegram/test":
		a.handleTelegramTest(w, r)
	case "/_admin/api/turnstile":
		a.handleTurnstile(w, r)
	case "/_admin/api/turnstile/test":
		a.handleTurnstileTest(w, r)
	case "/_admin/api/password":
		a.handlePasswordChange(w, r, session)
	case "/_admin/api/logout":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if cookie, err := r.Cookie(adminCookieName); err == nil && cookie.Value != "" {
			a.revokeSessionToken(cookie.Value, session.Expires)
		}
		a.auditRequest(r, "session.logout", session.Username, "", true)
		a.clearCookie(w)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.writeError(w, http.StatusNotFound, "admin API route not found")
	}
}

func (a *adminServer) handlePublicPortal(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, map[string]bool{"public_portal_enabled": a.gateway.publicPortal.Load()})
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Enabled bool `json:"public_portal_enabled"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.store.SavePublicPortalEnabled(r.Context(), payload.Enabled); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save portal setting")
			return
		}
		a.gateway.publicPortal.Store(payload.Enabled)
		if a.gateway.cluster != nil {
			a.gateway.cluster.NotifyConfigChanged("")
		}
		a.auditRequest(r, "system.portal", "public_portal", fmt.Sprintf("enabled=%t", payload.Enabled), true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"public_portal_enabled": payload.Enabled})
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleEmbyHealthServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		servers, err := a.store.EmbyHealthServers(r.Context(), true)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "health servers unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, servers)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			GroupName     string `json:"group_name"`
			Name          string `json:"name"`
			LineName      string `json:"line_name"`
			Note          string `json:"note"`
			BaseURL       string `json:"base_url"`
			ProbePath     string `json:"probe_path"`
			RetryCount    *int   `json:"retry_count"`
			RetryDelaySec *int   `json:"retry_delay_sec"`
			Enabled       bool   `json:"enabled"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid health server request")
			return
		}
		server, err := normalizeEmbyHealthServerFull(payload.GroupName, payload.Name, payload.LineName, payload.Note, payload.BaseURL, payload.ProbePath, payload.Enabled)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		probeCfg := a.store.LoadEmbyProbeSettings(r.Context())
		server.RetryCount = probeCfg.DefaultRetryCount
		server.RetryDelaySec = probeCfg.DefaultRetryDelaySec
		if payload.RetryCount != nil {
			server.RetryCount = *payload.RetryCount
		}
		if payload.RetryDelaySec != nil {
			server.RetryDelaySec = *payload.RetryDelaySec
		}
		server.RetryCount, server.RetryDelaySec = clampEmbyRetry(server.RetryCount, server.RetryDelaySec)
		id, err := a.store.SaveEmbyHealthServer(r.Context(), server)
		if errors.Is(err, errEmbyHealthLimit) {
			a.writeError(w, http.StatusConflict, "maximum monitored server count reached")
			return
		}
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "health server creation failed")
			return
		}
		server.ID = id
		a.auditRequest(r, "emby_health.server.create", strconv.FormatInt(id, 10), fmt.Sprintf("group=%q name=%q enabled=%t", server.GroupName, server.Name, server.Enabled), true)
		if server.Enabled && a.gateway.embyHealth != nil {
			a.gateway.embyHealth.Wake()
		}
		a.writeJSON(w, http.StatusCreated, server)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleEmbyHealthSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.store.LoadEmbyProbeSettings(r.Context()))
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			DefaultRetryCount    int  `json:"default_retry_count"`
			DefaultRetryDelaySec int  `json:"default_retry_delay_sec"`
			ProbeTimeoutSec      int  `json:"probe_timeout_sec"`
			ApplyToAll           bool `json:"apply_to_all"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid probe settings request")
			return
		}
		saved, err := a.store.SaveEmbyProbeSettings(r.Context(), embyProbeSettings{
			DefaultRetryCount:    payload.DefaultRetryCount,
			DefaultRetryDelaySec: payload.DefaultRetryDelaySec,
			ProbeTimeoutSec:      payload.ProbeTimeoutSec,
		}, payload.ApplyToAll)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to save probe settings")
			return
		}
		a.auditRequest(r, "emby_health.server.update", "settings", fmt.Sprintf("retry=%d delay=%ds timeout=%ds apply_all=%t", saved.DefaultRetryCount, saved.DefaultRetryDelaySec, saved.ProbeTimeoutSec, payload.ApplyToAll), true)
		a.writeJSON(w, http.StatusOK, saved)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleEmbyHealthCheckAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.embyHealth == nil {
		a.writeError(w, http.StatusServiceUnavailable, "health monitor unavailable")
		return
	}
	if err := a.gateway.embyHealth.CheckAllNow(r.Context()); err != nil && !errors.Is(err, context.Canceled) {
		a.writeError(w, http.StatusInternalServerError, "health check failed")
		return
	}
	servers, err := a.store.EmbyHealthServers(r.Context(), true)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "health status unavailable")
		return
	}
	a.auditRequest(r, "emby_health.server.check", "all", fmt.Sprintf("count=%d", len(servers)), true)
	a.writeJSON(w, http.StatusOK, servers)
}

func deriveEmbyServerDisplayName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "Emby 服务器"
	}
	host := parsed.Hostname()
	sub := strings.Trim(parsed.Path, "/")
	if sub != "" {
		return truncateRunes(host+"/"+sub, 128)
	}
	return truncateRunes(host, 128)
}

func (a *adminServer) handleEmbyHealthBatchImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		GroupName string   `json:"group_name"`
		ProbePath string   `json:"probe_path"`
		Enabled   *bool    `json:"enabled"`
		URLs      []string `json:"urls"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid batch import request")
		return
	}
	groupName := strings.TrimSpace(payload.GroupName)
	if groupName == "" {
		groupName = "Emby 服务器"
	}
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	existing, err := a.store.EmbyHealthServers(r.Context(), true)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "health servers unavailable")
		return
	}
	existingURLs := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		existingURLs[strings.ToLower(strings.TrimRight(s.BaseURL, "/"))] = struct{}{}
	}
	probeCfg := a.store.LoadEmbyProbeSettings(r.Context())
	created := 0
	skipped := 0
	var invalid []string
	for _, rawItem := range payload.URLs {
		candidate := strings.TrimSpace(rawItem)
		if candidate == "" {
			continue
		}
		if !strings.Contains(candidate, "://") {
			candidate = "https://" + candidate
		}
		name := deriveEmbyServerDisplayName(candidate)
		srv, normErr := normalizeEmbyHealthServerFull(groupName, name, "", "", candidate, payload.ProbePath, enabled)
		if normErr != nil {
			invalid = append(invalid, rawItem)
			continue
		}
		srv.RetryCount = probeCfg.DefaultRetryCount
		srv.RetryDelaySec = probeCfg.DefaultRetryDelaySec
		key := strings.ToLower(strings.TrimRight(srv.BaseURL, "/"))
		if _, dup := existingURLs[key]; dup {
			skipped++
			continue
		}
		if _, saveErr := a.store.SaveEmbyHealthServer(r.Context(), srv); saveErr != nil {
			if errors.Is(saveErr, errEmbyHealthLimit) {
				invalid = append(invalid, rawItem)
				break
			}
			invalid = append(invalid, rawItem)
			continue
		}
		existingURLs[key] = struct{}{}
		created++
	}
	if created > 0 && enabled && a.gateway.embyHealth != nil {
		a.gateway.embyHealth.Wake()
	}
	a.auditRequest(r, "emby_health.server.create", "batch", fmt.Sprintf("group=%q created=%d skipped=%d invalid=%d", groupName, created, skipped, len(invalid)), true)
	servers, err := a.store.EmbyHealthServers(r.Context(), true)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "health servers unavailable")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"created": created,
		"skipped": skipped,
		"invalid": invalid,
		"servers": servers,
	})
}

func (a *adminServer) handleEmbyHealthServerItem(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/emby-health/")
	parts := strings.Split(remainder, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id < 1 {
		a.writeError(w, http.StatusBadRequest, "invalid health server id")
		return
	}
	if len(parts) == 2 && parts[1] == "check" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if a.gateway.embyHealth == nil {
			a.writeError(w, http.StatusServiceUnavailable, "health monitor unavailable")
			return
		}
		if err := a.gateway.embyHealth.CheckNow(r.Context(), id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "health server not found")
			} else if errors.Is(err, errEmbyHealthDisabled) {
				a.writeError(w, http.StatusConflict, "health server is disabled")
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				a.writeError(w, http.StatusRequestTimeout, "health check timed out")
			} else {
				a.writeError(w, http.StatusInternalServerError, "health check failed")
			}
			return
		}
		servers, err := a.store.EmbyHealthServers(r.Context(), true)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "health status unavailable")
			return
		}
		for _, server := range servers {
			if server.ID == id {
				a.auditRequest(r, "emby_health.server.check", strconv.FormatInt(id, 10), "", true)
				a.writeJSON(w, http.StatusOK, server)
				return
			}
		}
		a.writeError(w, http.StatusNotFound, "health server not found")
		return
	}
	if len(parts) != 1 || parts[0] == "" {
		a.writeError(w, http.StatusNotFound, "health server route not found")
		return
	}
	switch r.Method {
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			GroupName     string `json:"group_name"`
			Name          string `json:"name"`
			LineName      string `json:"line_name"`
			Note          string `json:"note"`
			BaseURL       string `json:"base_url"`
			ProbePath     string `json:"probe_path"`
			RetryCount    *int   `json:"retry_count"`
			RetryDelaySec *int   `json:"retry_delay_sec"`
			Enabled       bool   `json:"enabled"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid health server request")
			return
		}
		server, err := normalizeEmbyHealthServerFull(payload.GroupName, payload.Name, payload.LineName, payload.Note, payload.BaseURL, payload.ProbePath, payload.Enabled)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		probeCfg := a.store.LoadEmbyProbeSettings(r.Context())
		server.RetryCount = probeCfg.DefaultRetryCount
		server.RetryDelaySec = probeCfg.DefaultRetryDelaySec
		if payload.RetryCount != nil {
			server.RetryCount = *payload.RetryCount
		}
		if payload.RetryDelaySec != nil {
			server.RetryDelaySec = *payload.RetryDelaySec
		}
		server.RetryCount, server.RetryDelaySec = clampEmbyRetry(server.RetryCount, server.RetryDelaySec)
		server.ID = id
		if _, err := a.store.SaveEmbyHealthServer(r.Context(), server); errors.Is(err, sql.ErrNoRows) {
			a.writeError(w, http.StatusNotFound, "health server not found")
			return
		} else if err != nil {
			a.writeError(w, http.StatusInternalServerError, "health server update failed")
			return
		}
		a.auditRequest(r, "emby_health.server.update", strconv.FormatInt(id, 10), fmt.Sprintf("group=%q name=%q enabled=%t", server.GroupName, server.Name, server.Enabled), true)
		if server.Enabled && a.gateway.embyHealth != nil {
			a.gateway.embyHealth.Wake()
		}
		servers, err := a.store.EmbyHealthServers(r.Context(), true)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "health servers unavailable")
			return
		}
		for _, saved := range servers {
			if saved.ID == id {
				a.writeJSON(w, http.StatusOK, saved)
				return
			}
		}
		a.writeError(w, http.StatusNotFound, "health server not found")
	case http.MethodDelete:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if err := a.store.DeleteEmbyHealthServer(r.Context(), id); err != nil {
			a.writeError(w, http.StatusNotFound, "health server not found")
			return
		}
		a.auditRequest(r, "emby_health.server.delete", strconv.FormatInt(id, 10), "", true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.methodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
	}
}

func parseGeographyPeriod(raw string) (time.Duration, bool) {
	switch strings.TrimSpace(raw) {
	case "", "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func parseOverviewPeriod(raw string) (time.Duration, bool) {
	switch strings.TrimSpace(raw) {
	case "", "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func (a *adminServer) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Mode string `json:"mode"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid policy request")
			return
		}
		if !validProxyMode(payload.Mode) {
			a.writeError(w, http.StatusBadRequest, "invalid policy mode")
			return
		}
		if err := a.store.SetProxyPolicyMode(r.Context(), payload.Mode); err != nil || a.gateway.reloadProxyPolicy(r.Context()) != nil {
			a.writeError(w, http.StatusInternalServerError, "policy update failed")
			return
		}
		a.auditRequest(r, "policy.mode", payload.Mode, "", true)
		a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handlePolicySchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		a.methodNotAllowed(w, http.MethodPut)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		Enabled bool   `json:"enabled"`
		Start   string `json:"start"`
		End     string `json:"end"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid schedule request")
		return
	}
	if err := a.store.SetProxyPolicySchedule(r.Context(), payload.Enabled, payload.Start, payload.End); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid proxy schedule")
		return
	}
	if err := a.gateway.reloadProxyPolicy(r.Context()); err != nil {
		a.writeError(w, http.StatusInternalServerError, "proxy schedule update failed")
		return
	}
	disconnected := 0
	if payload.Enabled {
		disconnected = a.gateway.connections.CancelAll()
	}
	detail := fmt.Sprintf("enabled=%t start=%s end=%s disconnected=%d", payload.Enabled, payload.Start, payload.End, disconnected)
	a.auditRequest(r, "policy.schedule", "daily", detail, true)
	a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
}

func (a *adminServer) handlePlayerPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.gateway.policy.Load().PlayerPolicy)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Mode string `json:"mode"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil || !validProxyMode(payload.Mode) {
			a.writeError(w, http.StatusBadRequest, "invalid player policy mode")
			return
		}
		if err := a.store.SetProxyPlayerPolicyMode(r.Context(), payload.Mode); err != nil || a.gateway.reloadProxyPolicy(r.Context()) != nil {
			a.writeError(w, http.StatusInternalServerError, "player policy update failed")
			return
		}
		currentPolicy := a.gateway.policy.Load()
		disconnected := a.gateway.connections.CancelDisallowedPlayers(&currentPolicy.PlayerPolicy)
		a.auditRequest(r, "policy.player.mode", payload.Mode, fmt.Sprintf("disconnected=%d", disconnected), true)
		a.writeJSON(w, http.StatusOK, a.gateway.policy.Load().PlayerPolicy)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handlePlayerRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		PlayerName string `json:"player_name"`
		Note       string `json:"note"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid player rule request")
		return
	}
	rule, err := normalizePlayerRule(payload.PlayerName, payload.Note)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.gateway.policy.Load().PlayerPolicy.Mode == proxyModeOff {
		a.writeError(w, http.StatusConflict, "select blacklist or whitelist mode first")
		return
	}
	if _, err := a.store.UpsertProxyPlayerRule(r.Context(), rule); err != nil || a.gateway.reloadProxyPolicy(r.Context()) != nil {
		a.writeError(w, http.StatusInternalServerError, "player rule creation failed")
		return
	}
	currentPolicy := a.gateway.policy.Load()
	disconnected := a.gateway.connections.CancelDisallowedPlayers(&currentPolicy.PlayerPolicy)
	a.auditRequest(r, "policy.player.rule.create", rule.PlayerName, fmt.Sprintf("note=%s disconnected=%d", rule.Note, disconnected), true)
	a.writeJSON(w, http.StatusCreated, a.gateway.policy.Load().PlayerPolicy)
}

func (a *adminServer) handlePlayerRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		a.methodNotAllowed(w, http.MethodDelete)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	rawID := strings.TrimPrefix(r.URL.Path, "/_admin/api/player-rules/")
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id < 1 || strings.Contains(rawID, "/") {
		a.writeError(w, http.StatusBadRequest, "invalid player rule id")
		return
	}
	if err := a.store.DeleteProxyPlayerRule(r.Context(), id); err != nil {
		a.writeError(w, http.StatusNotFound, "player rule not found")
		return
	}
	if err := a.gateway.reloadProxyPolicy(r.Context()); err != nil {
		a.writeError(w, http.StatusInternalServerError, "player rule update failed")
		return
	}
	currentPolicy := a.gateway.policy.Load()
	disconnected := a.gateway.connections.CancelDisallowedPlayers(&currentPolicy.PlayerPolicy)
	a.auditRequest(r, "policy.player.rule.delete", rawID, fmt.Sprintf("disconnected=%d", disconnected), true)
	a.writeJSON(w, http.StatusOK, a.gateway.policy.Load().PlayerPolicy)
}

func (a *adminServer) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		DomainSuffix string   `json:"domain_suffix"`
		QuotaGB      *float64 `json:"quota_gb"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid rule request")
		return
	}
	mode := a.gateway.policy.Load().Mode
	action := "deny"
	if mode == proxyModeWhitelist {
		action = "allow"
	} else if mode != proxyModeBlacklist {
		a.writeError(w, http.StatusConflict, "select blacklist or whitelist mode first")
		return
	}
	rule, err := normalizeProxyRule(action, payload.DomainSuffix)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if payload.QuotaGB != nil {
		if mode != proxyModeWhitelist {
			a.writeError(w, http.StatusBadRequest, "traffic quota is only available in whitelist mode")
			return
		}
		rule.QuotaBytes, err = domainQuotaBytes(*payload.QuotaGB)
		if err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if _, err := a.store.UpsertProxyRule(r.Context(), rule); err != nil || a.gateway.reloadProxyPolicy(r.Context()) != nil {
		a.writeError(w, http.StatusInternalServerError, "rule creation failed")
		return
	}
	a.auditRequest(r, "policy.rule.create", rule.DomainSuffix, "action="+rule.Action, true)
	a.writeJSON(w, http.StatusCreated, a.gateway.policy.Load())
}

func domainQuotaBytes(gigabytes float64) (int64, error) {
	const maxQuotaGB = 1 << 20
	if math.IsNaN(gigabytes) || math.IsInf(gigabytes, 0) || gigabytes < 0 || gigabytes > maxQuotaGB {
		return 0, errors.New("quota must be between 0 and 1048576 GB")
	}
	if gigabytes == 0 {
		return 0, nil
	}
	bytes := math.Round(gigabytes * float64(int64(1)<<30))
	if bytes < 1 {
		return 0, errors.New("quota is too small")
	}
	return int64(bytes), nil
}

func (a *adminServer) handleRuleQuota(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/rules/")
	parts := strings.Split(remainder, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[1] != "quota" {
		a.writeError(w, http.StatusNotFound, "quota route not found")
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id < 1 {
		a.writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	if len(parts) == 3 {
		if parts[2] != "reset" || r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		var resetErr error
		if a.gateway.quota != nil {
			resetErr = a.gateway.quota.Reset(r.Context(), id)
		} else {
			resetErr = a.store.ResetProxyRuleQuota(r.Context(), id)
		}
		if resetErr != nil {
			a.writeError(w, http.StatusNotFound, "limited whitelist rule not found")
			return
		}
		_ = a.gateway.reloadProxyPolicy(r.Context())
		a.auditRequest(r, "policy.rule.quota.reset", strconv.FormatInt(id, 10), "", true)
		a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
		return
	}
	if r.Method != http.MethodPut {
		a.methodNotAllowed(w, http.MethodPut)
		return
	}
	var payload struct {
		QuotaGB *float64 `json:"quota_gb"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil || payload.QuotaGB == nil {
		a.writeError(w, http.StatusBadRequest, "invalid quota request")
		return
	}
	quotaBytes, err := domainQuotaBytes(*payload.QuotaGB)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.store.SetProxyRuleQuota(r.Context(), id, quotaBytes); err != nil {
		a.writeError(w, http.StatusNotFound, "whitelist rule not found")
		return
	}
	if err := a.gateway.reloadProxyPolicy(r.Context()); err != nil {
		a.writeError(w, http.StatusInternalServerError, "quota update failed")
		return
	}
	a.auditRequest(r, "policy.rule.quota", strconv.FormatInt(id, 10), fmt.Sprintf("quota_bytes=%d", quotaBytes), true)
	a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
}

func (a *adminServer) handleDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		a.methodNotAllowed(w, http.MethodPut)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		Access string `json:"access"`
		Domain string `json:"domain"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid domain rule request")
		return
	}
	if payload.Access != "allow" && payload.Access != "block" {
		a.writeError(w, http.StatusBadRequest, "invalid domain rule request")
		return
	}
	validationAction := "deny"
	if payload.Access == "allow" {
		validationAction = "allow"
	}
	rule, err := normalizeProxyRule(validationAction, payload.Domain)
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid domain rule request")
		return
	}
	policy := a.gateway.policy.Load()
	switch policy.Mode {
	case proxyModeOff:
		if payload.Access == "allow" {
			a.writeJSON(w, http.StatusOK, policy)
			return
		}
		rule.Action = "deny"
		if _, err := a.store.UpsertProxyRule(r.Context(), rule); err != nil || a.store.SetProxyPolicyMode(r.Context(), proxyModeBlacklist) != nil {
			a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
			return
		}
	case proxyModeBlacklist:
		if payload.Access == "block" {
			rule.Action = "deny"
			if _, err := a.store.UpsertProxyRule(r.Context(), rule); err != nil {
				a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
				return
			}
		} else if match := policy.matchingRule(rule.DomainSuffix, "deny"); match != nil {
			if err := a.store.DeleteProxyRule(r.Context(), match.ID); err != nil {
				a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
				return
			}
		}
	case proxyModeWhitelist:
		if payload.Access == "allow" {
			rule.Action = "allow"
			if _, err := a.store.UpsertProxyRule(r.Context(), rule); err != nil {
				a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
				return
			}
		} else if match := policy.matchingRule(rule.DomainSuffix, "allow"); match != nil {
			if err := a.store.DeleteProxyRule(r.Context(), match.ID); err != nil {
				a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
				return
			}
		}
	}
	if a.gateway.reloadProxyPolicy(r.Context()) != nil {
		a.writeError(w, http.StatusInternalServerError, "domain rule update failed")
		return
	}
	a.auditRequest(r, "policy.domain.quick", rule.DomainSuffix, "access="+payload.Access, true)
	a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
}

func (a *adminServer) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		a.methodNotAllowed(w, http.MethodDelete)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	rawID := strings.TrimPrefix(r.URL.Path, "/_admin/api/rules/")
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id < 1 || strings.Contains(rawID, "/") {
		a.writeError(w, http.StatusBadRequest, "invalid rule id")
		return
	}
	if err := a.store.DeleteProxyRule(r.Context(), id); err != nil {
		a.writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := a.gateway.reloadProxyPolicy(r.Context()); err != nil {
		a.writeError(w, http.StatusInternalServerError, "rule update failed")
		return
	}
	a.auditRequest(r, "policy.rule.delete", rawID, "", true)
	a.writeJSON(w, http.StatusOK, a.gateway.policy.Load())
}

func (a *adminServer) handleTelegram(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		record, err := a.store.TelegramRecord(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "telegram settings unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, record.telegramConfig)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Enabled  bool                   `json:"enabled"`
			BotToken string                 `json:"bot_token"`
			ChatID   string                 `json:"chat_id"`
			SendHour int                    `json:"send_hour"`
			Alerts   *telegramAlertSettings `json:"alerts"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid telegram settings")
			return
		}
		payload.BotToken = strings.TrimSpace(payload.BotToken)
		payload.ChatID = strings.TrimSpace(payload.ChatID)
		current, err := a.store.TelegramRecord(r.Context())
		if err != nil || payload.SendHour < 0 || payload.SendHour > 23 ||
			(payload.ChatID != "" && !telegramChatPattern.MatchString(payload.ChatID)) ||
			(payload.BotToken != "" && !telegramTokenPattern.MatchString(payload.BotToken)) ||
			(payload.Enabled && (payload.ChatID == "" || (payload.BotToken == "" && !current.TokenSet))) {
			a.writeError(w, http.StatusBadRequest, "invalid telegram settings")
			return
		}
		encrypted := ""
		if payload.BotToken != "" {
			encrypted, err = a.gateway.telegram.cipher.Encrypt(payload.BotToken)
			if err != nil {
				a.writeError(w, http.StatusInternalServerError, "telegram settings update failed")
				return
			}
		}
		config := telegramConfig{Enabled: payload.Enabled, ChatID: payload.ChatID, SendHour: payload.SendHour}
		if err := a.store.SaveTelegram(r.Context(), config, encrypted); err != nil {
			a.writeError(w, http.StatusInternalServerError, "telegram settings update failed")
			return
		}
		if payload.Alerts != nil {
			if err := a.store.SaveTelegramAlerts(r.Context(), *payload.Alerts); err != nil {
				a.writeError(w, http.StatusInternalServerError, "telegram alert settings update failed")
				return
			}
		}
		a.gateway.telegram.Wake()
		a.auditRequest(r, "telegram.settings", payload.ChatID, fmt.Sprintf("enabled=%t hour=%d token_updated=%t", payload.Enabled, payload.SendHour, payload.BotToken != ""), true)
		updated, err := a.store.TelegramRecord(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "telegram settings unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, updated.telegramConfig)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleTelegramTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if err := a.gateway.telegram.SendTest(r.Context()); err != nil {
		a.auditRequest(r, "telegram.test", "", err.Error(), false)
		a.writeError(w, http.StatusBadGateway, "telegram test failed")
		return
	}
	a.auditRequest(r, "telegram.test", "", "", true)
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) handleTurnstilePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	if a.gateway.turnstile == nil {
		a.writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "site_key": ""})
		return
	}
	config, err := a.gateway.turnstile.Public(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "Turnstile unavailable")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"enabled": config.Enabled, "site_key": config.SiteKey})
}

func (a *adminServer) handleTurnstile(w http.ResponseWriter, r *http.Request) {
	if a.gateway.turnstile == nil {
		a.writeError(w, http.StatusServiceUnavailable, "Turnstile unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		config, err := a.gateway.turnstile.Config(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "Turnstile settings unavailable")
			return
		}
		config.EncryptedSecret = ""
		config.TestedFingerprint = ""
		a.writeJSON(w, http.StatusOK, config)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Enabled bool   `json:"enabled"`
			SiteKey string `json:"site_key"`
			Secret  string `json:"secret"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid Turnstile settings")
			return
		}
		payload.SiteKey = strings.TrimSpace(payload.SiteKey)
		payload.Secret = strings.TrimSpace(payload.Secret)
		hostname := ""
		if payload.Enabled || payload.SiteKey != "" || payload.Secret != "" {
			hostname = turnstileRequestHostname(r)
		}
		updated, err := a.gateway.turnstile.Save(r.Context(), turnstileConfig{Enabled: payload.Enabled, SiteKey: payload.SiteKey, Hostname: hostname}, payload.Secret)
		if errors.Is(err, errTurnstileNotTested) {
			a.writeError(w, http.StatusConflict, err.Error())
			return
		}
		if err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid Turnstile settings")
			return
		}
		updated.EncryptedSecret = ""
		updated.TestedFingerprint = ""
		a.auditRequest(r, "turnstile.settings", hostname, fmt.Sprintf("enabled=%t site_key_updated=%t secret_updated=%t", payload.Enabled, payload.SiteKey != "", payload.Secret != ""), true)
		a.writeJSON(w, http.StatusOK, updated)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleTurnstileTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid Turnstile test request")
		return
	}
	if a.gateway.turnstile == nil {
		a.writeError(w, http.StatusServiceUnavailable, "Turnstile unavailable")
		return
	}
	updated, err := a.gateway.turnstile.Test(r.Context(), payload.Token, adminClientIP(r, a.trustProxy, a.trustedProxyCIDRs...))
	if err != nil {
		if errors.Is(err, errTurnstileStore) {
			a.auditRequest(r, "turnstile.test", "", "database unavailable", false)
			a.writeError(w, http.StatusInternalServerError, "Turnstile database unavailable")
			return
		}
		reason := strings.TrimSpace(err.Error())
		if reason == "" {
			reason = "Turnstile self-test failed"
		}
		a.auditRequest(r, "turnstile.test", "", reason, false)
		if errors.Is(err, errTurnstileMissing) {
			a.writeError(w, http.StatusBadRequest, reason)
			return
		}
		a.writeError(w, http.StatusBadGateway, reason)
		return
	}
	updated.EncryptedSecret = ""
	updated.TestedFingerprint = ""
	a.auditRequest(r, "turnstile.test", updated.Hostname, "", true)
	a.writeJSON(w, http.StatusOK, updated)
}

func (a *adminServer) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	installed, err := a.store.HasAdministrator(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "admin database unavailable")
		return
	}
	if installed {
		a.writeError(w, http.StatusConflict, "administrator already configured")
		return
	}
	var payload struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
		SetupToken      string `json:"setup_token,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid setup request")
		return
	}
	if a.setupToken != "" {
		provided := strings.TrimSpace(payload.SetupToken)
		if provided == "" {
			provided = strings.TrimSpace(r.Header.Get("X-Refract-Setup-Token"))
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(a.setupToken)) != 1 {
			a.writeError(w, http.StatusForbidden, "valid setup token is required")
			return
		}
	}
	payload.Username = strings.TrimSpace(payload.Username)
	if payload.Username == "" || len(payload.Username) > 64 || strings.ContainsAny(payload.Username, "\r\n\x00|") {
		a.writeError(w, http.StatusBadRequest, "username must contain 1-64 safe characters")
		return
	}
	if len(payload.Password) < 12 || len([]byte(payload.Password)) > 72 || payload.Password != payload.ConfirmPassword {
		a.writeError(w, http.StatusBadRequest, "password must be 12-72 bytes and match confirmation")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "administrator setup failed")
		return
	}
	record, err := a.store.CreateFirstAdministrator(r.Context(), payload.Username, string(hash))
	if err != nil {
		if strings.Contains(err.Error(), "already configured") {
			a.writeError(w, http.StatusConflict, "administrator already configured")
			return
		}
		a.writeError(w, http.StatusInternalServerError, "administrator setup failed")
		return
	}
	token, err := a.issueSession(record)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "session unavailable")
		return
	}
	a.setSessionCookie(w, token)
	a.store.RecordAudit(r.Context(), auditEntry{Username: record.Username, ClientIP: adminClientIP(r, a.trustProxy, a.trustedProxyCIDRs...), Action: "account.setup", Resource: record.Username, Success: true})
	a.writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "username": record.Username})
}

func (a *adminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	client := adminClientIP(r, a.trustProxy, a.trustedProxyCIDRs...)
	retry, err := a.store.loginRetryAfter(r.Context(), client, time.Now())
	if err != nil {
		a.writeError(w, http.StatusServiceUnavailable, "login protection unavailable")
		return
	}
	if retry > 0 {
		a.store.RecordAudit(r.Context(), auditEntry{Username: "", ClientIP: client, Action: "session.login", Detail: "rate limited", Success: false})
		a.writeLoginBlocked(w, retry)
		return
	}
	var payload struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		TurnstileToken string `json:"turnstile_token"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	if a.gateway.turnstile != nil {
		if err := a.gateway.turnstile.VerifyLogin(r.Context(), payload.TurnstileToken, client, turnstileRequestHostname(r)); err != nil {
			a.store.RecordAudit(r.Context(), auditEntry{Username: payload.Username, ClientIP: client, Action: "session.login", Detail: "human verification failed", Success: false})
			a.writeError(w, http.StatusForbidden, "human verification failed")
			return
		}
	}
	record, err := a.store.AuthRecord(r.Context(), payload.Username)
	passwordHash := dummyLoginBcryptHash
	userMatch := false
	if err == nil {
		passwordHash = []byte(record.PasswordHash)
		userMatch = subtle.ConstantTimeCompare([]byte(record.Username), []byte(payload.Username)) == 1
	}
	passwordMatch := bcrypt.CompareHashAndPassword(passwordHash, []byte(payload.Password)) == nil
	if err != nil || !userMatch || !passwordMatch {
		retry, protectionErr := a.store.recordLoginFailure(r.Context(), client, time.Now())
		detail := "invalid credentials"
		if retry > 0 {
			detail = "invalid credentials; blocked for 24 hours"
		}
		a.store.RecordAudit(r.Context(), auditEntry{Username: payload.Username, ClientIP: client, Action: "session.login", Detail: detail, Success: false})
		time.Sleep(250 * time.Millisecond)
		if protectionErr != nil {
			a.writeError(w, http.StatusServiceUnavailable, "login protection unavailable")
			return
		}
		if retry > 0 {
			a.writeLoginBlocked(w, retry)
			return
		}
		a.writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err := a.store.resetLoginFailures(r.Context(), client); err != nil {
		a.writeError(w, http.StatusServiceUnavailable, "login protection unavailable")
		return
	}
	token, err := a.issueSession(record)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "session unavailable")
		return
	}
	a.setSessionCookie(w, token)
	a.store.RecordAudit(r.Context(), auditEntry{Username: record.Username, ClientIP: client, Action: "session.login", Resource: record.Username, Success: true})
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "username": record.Username})
}

func (a *adminServer) handlePasswordChange(w http.ResponseWriter, r *http.Request, session adminSession) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var payload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid password request")
		return
	}
	if len(payload.NewPassword) < 12 || len([]byte(payload.NewPassword)) > 72 {
		a.writeError(w, http.StatusBadRequest, "new password must be 12-72 bytes")
		return
	}
	record, err := a.store.AuthRecord(r.Context(), session.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(payload.CurrentPassword)) != nil {
		a.writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	if _, err := a.store.ChangePassword(r.Context(), session.Username, string(hash)); err != nil {
		a.writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	a.store.RecordAudit(r.Context(), auditEntry{Username: session.Username, ClientIP: adminClientIP(r, a.trustProxy, a.trustedProxyCIDRs...), Action: "account.password", Resource: session.Username, Success: true})
	a.clearCookie(w)
	a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *adminServer) issueSession(record authRecord) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := strings.Join([]string{
		record.Username,
		strconv.FormatInt(record.Version, 10),
		strconv.FormatInt(time.Now().Add(a.sessionTTL).Unix(), 10),
		base64.RawURLEncoding.EncodeToString(nonce),
	}, "|")
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(a.sign(encoded)), nil
}

func (a *adminServer) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(a.sessionTTL.Seconds()),
		Expires:  time.Now().Add(a.sessionTTL),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *adminServer) revokeSessionToken(rawToken string, expiresUnix int64) {
	if a == nil || rawToken == "" {
		return
	}
	sum := sha256.Sum256([]byte(rawToken))
	key := base64.RawURLEncoding.EncodeToString(sum[:])
	now := time.Now().Unix()
	if expiresUnix <= now {
		expiresUnix = now + int64(a.sessionTTL.Seconds())
	}
	a.revokedMu.Lock()
	for k, exp := range a.revokedTokens {
		if exp <= now {
			delete(a.revokedTokens, k)
		}
	}
	a.revokedTokens[key] = expiresUnix
	a.revokedMu.Unlock()
}

func (a *adminServer) isSessionTokenRevoked(rawToken string) bool {
	if a == nil || rawToken == "" {
		return false
	}
	sum := sha256.Sum256([]byte(rawToken))
	key := base64.RawURLEncoding.EncodeToString(sum[:])
	now := time.Now().Unix()
	a.revokedMu.Lock()
	exp, exists := a.revokedTokens[key]
	if exists && exp <= now {
		delete(a.revokedTokens, key)
		exists = false
	}
	a.revokedMu.Unlock()
	return exists
}

func (a *adminServer) authenticate(r *http.Request) (adminSession, bool) {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || len(cookie.Value) > 1024 {
		return adminSession{}, false
	}
	if a.isSessionTokenRevoked(cookie.Value) {
		return adminSession{}, false
	}
	encoded, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return adminSession{}, false
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(provided, a.sign(encoded)) {
		return adminSession{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return adminSession{}, false
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 4 || parts[0] == "" || len(parts[0]) > 64 {
		return adminSession{}, false
	}
	version, versionErr := strconv.ParseInt(parts[1], 10, 64)
	expires, expiresErr := strconv.ParseInt(parts[2], 10, 64)
	if versionErr != nil || expiresErr != nil || time.Now().Unix() >= expires {
		return adminSession{}, false
	}
	record, err := a.store.AuthRecord(r.Context(), parts[0])
	if err != nil || record.Version != version {
		return adminSession{}, false
	}
	return adminSession{Username: parts[0], Version: version, Expires: expires}, true
}

func (a *adminServer) sign(value string) []byte {
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (a *adminServer) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: adminCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (a *adminServer) writeLoginBlocked(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
	a.writeError(w, http.StatusTooManyRequests, "too many login attempts")
}

func (a *adminServer) secureHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; img-src 'self'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
}

func (a *adminServer) writeJSON(w http.ResponseWriter, status int, value any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *adminServer) writeError(w http.ResponseWriter, status int, message string) {
	a.writeJSON(w, status, map[string]string{"error": message})
}

func (a *adminServer) methodNotAllowed(w http.ResponseWriter, method string) {
	w.Header().Set("Allow", method)
	a.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func sameOriginRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, r.Host) ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if r.TLS != nil && parsed.Scheme != "https" {
		return false
	}
	return true
}

func turnstileRequestHostname(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, "/\\?#@\r\n\t ") {
		return ""
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	} else {
		host = strings.Trim(host, "[]")
	}
	return normalizeTurnstileHostname(host)
}

func canonicalIPString(raw string) (string, bool) {
	trimmed := strings.Trim(strings.TrimSpace(raw), "[]")
	if trimmed == "" || strings.Contains(trimmed, "%") {
		return "", false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

func isTrustedProxyPeer(remoteAddr string, trustedCIDRs []netip.Prefix) bool {
	host := strings.TrimSpace(remoteAddr)
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if len(trustedCIDRs) > 0 {
		for _, prefix := range trustedCIDRs {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func hasWildcardPrefix(trustedCIDRs []netip.Prefix) bool {
	for _, p := range trustedCIDRs {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

func extractIPFromHeader(r *http.Request, header string, trustedCIDRs []netip.Prefix) (string, bool) {
	values := r.Header.Values(header)
	if len(values) == 0 {
		return "", false
	}
	allowWildcardFallback := hasWildcardPrefix(trustedCIDRs)
	if strings.EqualFold(header, "X-Forwarded-For") {
		fallbackIP := ""
		for i := len(values) - 1; i >= 0; i-- {
			parts := strings.Split(values[i], ",")
			for j := len(parts) - 1; j >= 0; j-- {
				if ip, ok := canonicalIPString(parts[j]); ok {
					// Keep updating fallbackIP while walking right-to-left so if EVERY hop
					// matches a wildcard trusted prefix (e.g. 0.0.0.0/0 / "::/0"),
					// we return the leftmost client IP rather than the rightmost hop.
					if allowWildcardFallback {
						fallbackIP = ip
					}
					if !isTrustedProxyPeer(ip, trustedCIDRs) {
						return ip, true
					}
				}
			}
		}
		if allowWildcardFallback && fallbackIP != "" {
			return fallbackIP, true
		}
		return "", false
	}
	for i := len(values) - 1; i >= 0; i-- {
		raw := values[i]
		if strings.Contains(raw, ",") {
			fallbackIP := ""
			parts := strings.Split(raw, ",")
			for j := len(parts) - 1; j >= 0; j-- {
				if ip, ok := canonicalIPString(parts[j]); ok {
					if allowWildcardFallback {
						fallbackIP = ip
					}
					if !isTrustedProxyPeer(ip, trustedCIDRs) {
						return ip, true
					}
				}
			}
			if allowWildcardFallback && fallbackIP != "" {
				return fallbackIP, true
			}
			continue
		}
		if ip, ok := canonicalIPString(raw); ok {
			return ip, true
		}
	}
	return "", false
}

func clientIPFromRequest(r *http.Request, trustProxy bool, trustedCIDRs []netip.Prefix, preferredHeader string) string {
	if trustProxy && isTrustedProxyPeer(r.RemoteAddr, trustedCIDRs) {
		if hdr := strings.TrimSpace(preferredHeader); hdr != "" {
			if ip, ok := extractIPFromHeader(r, hdr, trustedCIDRs); ok {
				return ip
			}
			if !strings.EqualFold(hdr, "X-Forwarded-For") {
				if ip, ok := extractIPFromHeader(r, "X-Forwarded-For", trustedCIDRs); ok {
					return ip
				}
			}
		} else {
			for _, header := range []string{"CF-Connecting-IP", "True-Client-IP", "EO-Connecting-IP", "X-Real-IP"} {
				if ip, ok := extractIPFromHeader(r, header, trustedCIDRs); ok {
					return ip
				}
			}
			if ip, ok := extractIPFromHeader(r, "X-Forwarded-For", trustedCIDRs); ok {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip, ok := canonicalIPString(host); ok {
			return ip
		}
	} else if ip, ok := canonicalIPString(r.RemoteAddr); ok {
		return ip
	}
	return "unknown"
}

func adminClientIP(r *http.Request, trustProxy bool, trustedCIDRs ...netip.Prefix) string {
	return clientIPFromRequest(r, trustProxy, trustedCIDRs, "")
}
