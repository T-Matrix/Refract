package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const adminCookieName = "vug_admin_session"

//go:embed web/*
var adminAssets embed.FS

type adminSession struct {
	Username string
	Version  int64
	Expires  int64
}

type adminServer struct {
	gateway    *Gateway
	store      *telemetryStore
	username   string
	secret     []byte
	sessionTTL time.Duration
	trustProxy bool
	assets     http.Handler
}

func newAdminServer(gateway *Gateway, store *telemetryStore, cfg Config) (*adminServer, error) {
	assets, err := fs.Sub(adminAssets, "web")
	if err != nil {
		return nil, err
	}
	return &adminServer{
		gateway:    gateway,
		store:      store,
		username:   cfg.AdminUsername,
		secret:     append([]byte(nil), cfg.AdminSessionSecret...),
		sessionTTL: cfg.AdminSessionTTL,
		trustProxy: cfg.TrustProxyHeaders,
		assets:     http.FileServer(http.FS(assets)),
	}, nil
}

func (a *adminServer) Handle(w http.ResponseWriter, r *http.Request) bool {
	if a == nil {
		return false
	}
	switch {
	case r.URL.Path == "/":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return false
		}
		a.secureHeaders(w)
		installed, err := a.store.HasAdministrator(r.Context())
		if err != nil {
			http.Error(w, "admin database unavailable", http.StatusInternalServerError)
			return true
		}
		location := "/login"
		if !installed {
			location = "/setup"
		}
		http.Redirect(w, r, location, http.StatusFound)
		return true
	case r.URL.Path == "/setup":
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet)
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
		a.serveAsset(w, r, "/setup.html", false)
		return true
	case r.URL.Path == "/login":
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet)
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
			a.methodNotAllowed(w, http.MethodGet)
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
		a.serveAsset(w, r, "/panel.html", false)
		return true
	case strings.HasPrefix(r.URL.Path, "/_admin/assets/"):
		a.secureHeaders(w)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.methodNotAllowed(w, http.MethodGet)
			return true
		}
		assetPath := strings.TrimPrefix(r.URL.Path, "/_admin/assets")
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

func (a *adminServer) serveAsset(w http.ResponseWriter, r *http.Request, path string, cache bool) {
	clone := r.Clone(r.Context())
	clone.URL.Path = path
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
	if strings.HasPrefix(path, "/_admin/api/connections/") {
		a.handleConnectionCancel(w, r)
		return
	}
	if strings.HasPrefix(path, "/_admin/api/backups/") && path != "/_admin/api/backups/config" && path != "/_admin/api/backups/import" {
		a.handleBackupItem(w, r)
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
		a.writeJSON(w, http.StatusOK, map[string]any{"username": session.Username, "expires": session.Expires, "version": normalizedVersion(Version)})
	case "/_admin/api/update":
		a.handleUpdate(w, r, session)
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
		snapshot, err := a.store.Snapshot(r.Context(), period, a.gateway.active.Load(), a.gateway.blocked.Load(), time.Since(a.gateway.started), a.gateway.connections)
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "dashboard unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, snapshot)
	case "/_admin/api/live":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		live := a.gateway.meter.Snapshot(a.gateway.active.Load())
		live.ActiveTargets = a.gateway.connections.ActiveTargets()
		a.writeJSON(w, http.StatusOK, live)
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
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		logs, err := a.store.recent(r.Context(), limit, r.URL.Query().Get("host"))
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "request logs unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "dropped": a.store.dropped.Load()})
	case "/_admin/api/policy":
		a.handlePolicy(w, r)
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
		a.auditRequest(r, "session.logout", session.Username, "", true)
		a.clearCookie(w)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.writeError(w, http.StatusNotFound, "admin API route not found")
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
		DomainSuffix string `json:"domain_suffix"`
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
	if _, err := a.store.UpsertProxyRule(r.Context(), rule); err != nil || a.gateway.reloadProxyPolicy(r.Context()) != nil {
		a.writeError(w, http.StatusInternalServerError, "rule creation failed")
		return
	}
	a.auditRequest(r, "policy.rule.create", rule.DomainSuffix, "action="+rule.Action, true)
	a.writeJSON(w, http.StatusCreated, a.gateway.policy.Load())
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
			Enabled  bool   `json:"enabled"`
			BotToken string `json:"bot_token"`
			ChatID   string `json:"chat_id"`
			SendHour int    `json:"send_hour"`
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
	updated, err := a.gateway.turnstile.Test(r.Context(), payload.Token, adminClientIP(r, a.trustProxy))
	if err != nil {
		a.auditRequest(r, "turnstile.test", "", "self-test failed", false)
		if errors.Is(err, errTurnstileMissing) {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.writeError(w, http.StatusBadGateway, "Turnstile self-test failed")
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
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid setup request")
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	if payload.Username == "" || len(payload.Username) > 64 || strings.ContainsAny(payload.Username, "\r\n\x00|") {
		a.writeError(w, http.StatusBadRequest, "username must contain 1-64 safe characters")
		return
	}
	if len(payload.Password) < 12 || len(payload.Password) > 128 || payload.Password != payload.ConfirmPassword {
		a.writeError(w, http.StatusBadRequest, "password must contain 12-128 characters and match confirmation")
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
	a.store.RecordAudit(r.Context(), auditEntry{Username: record.Username, ClientIP: adminClientIP(r, a.trustProxy), Action: "account.setup", Resource: record.Username, Success: true})
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
	client := adminClientIP(r, a.trustProxy)
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
	if err != nil || subtle.ConstantTimeCompare([]byte(record.Username), []byte(payload.Username)) != 1 ||
		bcrypt.CompareHashAndPassword([]byte(record.PasswordHash), []byte(payload.Password)) != nil {
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
	if len(payload.NewPassword) < 12 || len(payload.NewPassword) > 128 {
		a.writeError(w, http.StatusBadRequest, "new password must contain 12-128 characters")
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
	a.store.RecordAudit(r.Context(), auditEntry{Username: session.Username, ClientIP: adminClientIP(r, a.trustProxy), Action: "account.password", Resource: session.Username, Success: true})
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

func (a *adminServer) authenticate(r *http.Request) (adminSession, bool) {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || len(cookie.Value) > 1024 {
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
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
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
	return err == nil && parsed.User == nil && parsed.Host != "" && strings.EqualFold(parsed.Host, r.Host) &&
		(parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
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

func adminClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if candidate := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	if forwarded := r.Header.Values("X-Forwarded-For"); trustProxy && len(forwarded) > 0 {
		parts := strings.Split(forwarded[len(forwarded)-1], ",")
		if candidate := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	return "unknown"
}
