package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestAuditIPv6ZoneAndTransitionSSRFBlocked(t *testing.T) {
	// Blocked IPv6 transition & reserved addresses
	blocked := []string{
		"::1",
		"::ffff:127.0.0.1",
		"::127.0.0.1",
		"64:ff9b::127.0.0.1",
		"64:ff9b:1::1",
		"100::1",
		"2001::1",
		"2002:7f00:1::1",
		"fec0::1",
		"fe80::1%en0",
	}
	for _, raw := range blocked {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", raw, err)
		}
		if !isBlockedAddress(addr) {
			t.Fatalf("expected isBlockedAddress(%q) = true", raw)
		}
	}

	// parseHTTPURL must reject IPv6 zones and unsafe hosts
	badURLs := []string{
		"http://[fe80::1%25en0]:8096",
		"http://[fe80::1%en0]:8096",
		"https://example.com:99999",
		"https://bad host.example.com",
	}
	for _, raw := range badURLs {
		if _, err := parseHTTPURL(raw); err == nil {
			t.Fatalf("expected parseHTTPURL(%q) to fail", raw)
		}
	}

	// safeResolver must block zone-qualified hosts directly
	r := newSafeResolver(time.Minute, false)
	if _, err := r.ResolveWithMode(context.Background(), &url.URL{Scheme: "http", Host: "[fe80::1%en0]:8096"}, "auto"); err == nil {
		t.Fatal("expected safeResolver to reject IPv6 zone host")
	}
}

func TestAuditUpstreamProxyStripsAdminCookieAndSandboxesDynamicHTML(t *testing.T) {
	var upstreamCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCookie = r.Header.Get("Cookie")
		w.Header().Add("Set-Cookie", adminCookieName+"=evil-fixation; Path=/")
		w.Header().Add("Set-Cookie", "user_pref=dark; Path=/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body><script>alert(1)</script></body></html>"))
	}))
	defer upstream.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse-battery-staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.AllowPrivateTargets = true
	cfg.AllowUnsigned = true
	cfg.AdminEnabled = true
	cfg.AdminUsername = "admin"
	cfg.AdminPasswordHash = string(hash)
	cfg.AdminSessionSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.AdminSessionTTL = 12 * time.Hour
	cfg.AdminDatabasePath = filepath.Join(t.TempDir(), "gateway.db")
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	defer gw.Close()

	proxyPath := "/" + upstream.URL + "/index.html"
	req := httptest.NewRequest(http.MethodGet, "https://proxy.test"+proxyPath, nil)
	req.Header.Set("Cookie", adminCookieName+"=super-secret-session; other=ok")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(upstreamCookie, adminCookieName) {
		t.Fatalf("admin session cookie leaked to upstream: %q", upstreamCookie)
	}
	if !strings.Contains(upstreamCookie, "other=ok") {
		t.Fatalf("unrelated cookie should be preserved, got %q", upstreamCookie)
	}
	for _, sc := range rec.Header().Values("Set-Cookie") {
		if strings.Contains(sc, adminCookieName) {
			t.Fatalf("upstream Set-Cookie for admin session was not stripped: %q", sc)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "sandbox") {
		t.Fatalf("expected sandbox CSP on dynamic proxied HTML, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff header, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("expected no Allow-Credentials for cross-origin request, got %q", got)
	}
}

func TestAuditAdminLogoutRevokesSessionImmediately(t *testing.T) {
	gw := newAdminTestGateway(t)
	cookie := loginAdmin(t, gw)

	// Valid before logout
	before := adminRequest(t, gw, http.MethodGet, "/_admin/api/session", nil, cookie, false)
	if before.Code != http.StatusOK {
		t.Fatalf("session before logout status=%d", before.Code)
	}

	// Logout
	out := adminRequest(t, gw, http.MethodPost, "/_admin/api/logout", map[string]any{}, cookie, true)
	if out.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", out.Code, out.Body.String())
	}

	// Replaying the exact same cookie must now be rejected
	after := adminRequest(t, gw, http.MethodGet, "/_admin/api/session", nil, cookie, false)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session replay expected 401, got %d body=%s", after.Code, after.Body.String())
	}
}

func TestAuditAdminSetupTokenAndPasswordByteLimit(t *testing.T) {
	cfg := testConfig()
	cfg.AdminEnabled = true
	cfg.AdminSessionSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.AdminSessionTTL = 12 * time.Hour
	cfg.AdminSetupToken = "init-secret-token-2026"
	cfg.AdminDatabasePath = filepath.Join(t.TempDir(), "gateway.db")
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	defer gw.Close()

	// Missing setup token -> 403
	denied := adminRequest(t, gw, http.MethodPost, "/_admin/api/setup", map[string]any{
		"username":         "admin",
		"password":         "ValidPassword123456",
		"confirm_password": "ValidPassword123456",
	}, nil, true)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("setup without token expected 403, got %d body=%s", denied.Code, denied.Body.String())
	}

	// Password exceeding bcrypt 72-byte limit -> 400 (not 500)
	longPW := strings.Repeat("a", 80)
	tooLong := adminRequest(t, gw, http.MethodPost, "/_admin/api/setup", map[string]any{
		"username":         "admin",
		"password":         longPW,
		"confirm_password": longPW,
		"setup_token":      "init-secret-token-2026",
	}, nil, true)
	if tooLong.Code != http.StatusBadRequest {
		t.Fatalf("setup >72 byte password expected 400, got %d body=%s", tooLong.Code, tooLong.Body.String())
	}

	// Valid setup with setup_token -> 201 Created
	ok := adminRequest(t, gw, http.MethodPost, "/_admin/api/setup", map[string]any{
		"username":         "admin",
		"password":         "ValidPassword123456",
		"confirm_password": "ValidPassword123456",
		"setup_token":      "init-secret-token-2026",
	}, nil, true)
	if ok.Code != http.StatusCreated {
		t.Fatalf("setup with valid token expected 201, got %d body=%s", ok.Code, ok.Body.String())
	}
}

func TestAuditAxisNowAPIBaseSSRFAndTokenExfiltrationBlocked(t *testing.T) {
	gw := newAdminTestGateway(t)
	cookie := loginAdmin(t, gw)

	// Plain HTTP or loopback api_base must be rejected
	for _, badBase := range []string{
		"http://api.axisnow.io/client/v1",
		"https://127.0.0.1/client/v1",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]/client/v1",
	} {
		rec := adminRequest(t, gw, http.MethodPost, "/_admin/api/axisnow-dns/test", map[string]any{
			"token":    "tok-test",
			"api_base": badBase,
		}, cookie, true)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusBadGateway {
			t.Fatalf("test api_base=%q expected 400/502 rejection, got %d body=%s", badBase, rec.Code, rec.Body.String())
		}
		putRec := adminRequest(t, gw, http.MethodPut, "/_admin/api/axisnow-dns", map[string]any{
			"enabled":  false,
			"token":    "tok-test",
			"api_base": badBase,
		}, cookie, true)
		if putRec.Code != http.StatusBadRequest {
			t.Fatalf("PUT api_base=%q expected 400, got %d body=%s", badBase, putRec.Code, putRec.Body.String())
		}
	}

	// Save a token via the admin API under default api_base
	saveRec := adminRequest(t, gw, http.MethodPut, "/_admin/api/axisnow-dns", map[string]any{
		"enabled":  false,
		"token":    "saved-secret-token",
		"api_base": axisnowDefaultAPIBase,
	}, cookie, true)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("save initial axisnow token expected 200, got %d body=%s", saveRec.Code, saveRec.Body.String())
	}

	// Trying to change api_base to another HTTPS host without re-entering token must fail (prevents token exfiltration)
	exfilTest := adminRequest(t, gw, http.MethodPost, "/_admin/api/axisnow-dns/test", map[string]any{
		"token":    "",
		"api_base": "https://attacker.example/client/v1",
	}, cookie, true)
	if (exfilTest.Code != http.StatusBadRequest && exfilTest.Code != http.StatusBadGateway) || !strings.Contains(exfilTest.Body.String(), "重新填写") {
		t.Fatalf("test with changed api_base & empty token expected 400/502 rejection, got %d body=%s", exfilTest.Code, exfilTest.Body.String())
	}
	exfilPut := adminRequest(t, gw, http.MethodPut, "/_admin/api/axisnow-dns", map[string]any{
		"enabled":  true,
		"token":    "",
		"api_base": "https://attacker.example/client/v1",
	}, cookie, true)
	if exfilPut.Code != http.StatusBadRequest {
		t.Fatalf("PUT with changed api_base & empty token expected 400, got %d body=%s", exfilPut.Code, exfilPut.Body.String())
	}
}

func TestAuditWAFPathNormalizationAndIPv6HostMatching(t *testing.T) {
	// 1. Path normalization & decoding prevents bypasses
	pathRule := wafRuleRecord{
		ID:      "r_path",
		Name:    "block-secret",
		Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "p", Type: wafNodePathMatch, Config: wafNodeConfig{
					MatchMode: "prefix",
					Patterns:  []string{"/secret", "/.env"},
				}},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "blocked"}},
				{ID: "ok", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "p"},
				{ID: "e2", Source: "p", SourcePort: "true", Target: "b"},
				{ID: "e3", Source: "p", SourcePort: "false", Target: "ok"},
			},
		},
	}
	_, compiledPath, err := normalizeAndCompileWAFRule(pathRule)
	if err != nil {
		t.Fatalf("compile path rule: %v", err)
	}
	for _, bypassPath := range []string{"/secret", "//secret", "/./secret", "/x/../secret", "/%73ecret", "/.%65nv", "/%2eenv"} {
		res := compiledPath.Evaluate(wafEvalContext{Path: bypassPath}, false)
		if !res.Blocked {
			t.Fatalf("expected path %q to be blocked by normalized WAF path_match", bypassPath)
		}
	}

	// 2. IPv6 host_match must not truncate to "2001"
	hostRule := wafRuleRecord{
		ID:      "r_v6",
		Name:    "block-v6",
		Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "h", Type: wafNodeHostMatch, Config: wafNodeConfig{
					Hosts: []string{"[2001:db8::1]:8096", "emby.example.com.:8096"},
				}},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403}},
				{ID: "ok", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "h"},
				{ID: "e2", Source: "h", SourcePort: "true", Target: "b"},
				{ID: "e3", Source: "h", SourcePort: "false", Target: "ok"},
			},
		},
	}
	_, compiledHost, err := normalizeAndCompileWAFRule(hostRule)
	if err != nil {
		t.Fatalf("compile host rule: %v", err)
	}
	if !compiledHost.Evaluate(wafEvalContext{TargetHost: "2001:db8::1"}, false).Blocked {
		t.Fatal("expected exact IPv6 2001:db8::1 to match")
	}
	if compiledHost.Evaluate(wafEvalContext{TargetHost: "2001:db9::2"}, false).Blocked {
		t.Fatal("unrelated IPv6 2001:db9::2 must NOT match truncated 2001")
	}
	if !compiledHost.Evaluate(wafEvalContext{TargetHost: "emby.example.com"}, false).Blocked {
		t.Fatal("expected trailing-dot+port pattern emby.example.com.:8096 to match emby.example.com")
	}
}

func TestAuditExtractAuthParamUTF8NoPanicAndDevicePolicyParsing(t *testing.T) {
	// Turkish dotted capital I ('İ', U+0130) expands from 2 bytes to 3 bytes under strings.ToLower.
	hdr := `MediaBrowser ` + strings.Repeat("İ", 32) + `, Token="secret-tok-123"`
	got := extractAuthParam(hdr, "Token")
	if got != "secret-tok-123" {
		t.Fatalf("extractAuthParam UTF-8 got %q, want %q", got, "secret-tok-123")
	}
	// Suffix parameter name must not falsely match
	if got := extractAuthParam(`MediaBrowser AccessToken="wrong"`, "Token"); got != "" {
		t.Fatalf("expected AccessToken not to match Token, got %q", got)
	}

	// No-scheme X-Emby-Authorization & query fallback
	req := httptest.NewRequest(http.MethodGet, "https://proxy.test/Users?X-Emby-Client=Infuse", nil)
	req.Header.Add("X-Emby-Authorization", `DeviceId="dev-99", Device="AppleTV"`)
	id := requestDeviceIdentity(req)
	if id.ID != "dev-99" || id.DeviceName != "AppleTV" || id.ClientName != "Infuse" {
		t.Fatalf("unexpected device identity: %#v", id)
	}
}

func TestAuditTelemetryStoreCloseConcurrentRecordNoPanic(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "telemetry.db")
	store, err := openTelemetryStore(dbPath, "", "")
	if err != nil {
		t.Fatalf("openTelemetryStore: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				store.RecordCompleted(telemetryEvent{
					Timestamp:  time.Now(),
					Host:       "emby.example.com",
					Scheme:     "https",
					Method:     "GET",
					Path:       "/test",
					Category:   "api",
					Status:     200,
					BytesOut:   1024,
					DurationMS: 5,
				}, nil, nil)
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	store.Close()
	wg.Wait()
}

func TestAuditBandwidthLimiterWaitDoesNotBlockSetLimitOrCleanup(t *testing.T) {
	limiter := newBandwidthLimiter(1024) // 1 KB/s
	clientKey := "203.0.113.10"

	// Consume burst so next Wait sleeps ~2s
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = limiter.Wait(ctx, clientKey, 4096)

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- limiter.Wait(ctx, clientKey, 4096)
	}()
	time.Sleep(30 * time.Millisecond)

	// SetLimit and cleanup must NOT block on the sleeping Wait()!
	start := time.Now()
	limiter.SetLimit(10 << 20)
	limiter.mu.Lock()
	limiter.cleanup(time.Now().Add(2*time.Minute), nil)
	limiter.mu.Unlock()
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("SetLimit/cleanup blocked for %v while client Wait was sleeping", elapsed)
	}
	cancel()
	<-waitDone
}

func TestAuditBackupValidationRejectsTriggersAndViews(t *testing.T) {
	badPath := filepath.Join(t.TempDir(), "evil.db")
	db, err := sql.Open("sqlite", badPath)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE admin_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, auth_version INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL)`,
		`CREATE TABLE request_logs (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE traffic_minutes (minute INTEGER, host TEXT)`,
		`CREATE TABLE gateway_settings (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)`,
		`CREATE TABLE proxy_rules (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE proxy_device_rules (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE proxy_player_rules (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE telegram_settings (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE turnstile_settings (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE geo_ip_cache (ip TEXT PRIMARY KEY)`,
		`CREATE TABLE geo_ip_stats (ip TEXT PRIMARY KEY)`,
		`CREATE TABLE admin_audit_logs (id INTEGER PRIMARY KEY)`,
		`CREATE TRIGGER evil_trig AFTER INSERT ON gateway_settings BEGIN SELECT 1; END`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	_ = db.Close()

	if err := validateSQLiteBackup(badPath); err == nil {
		t.Fatal("expected validateSQLiteBackup to reject backup containing SQLite trigger")
	}
}

func TestAuditDecodeAdminJSONMalformedReturns400(t *testing.T) {
	gw := newAdminTestGateway(t)
	cookie := loginAdmin(t, gw)

	req := httptest.NewRequest(http.MethodPut, "https://proxy.test/_admin/api/runtime-config", strings.NewReader("{bad-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://proxy.test")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("malformed JSON expected 400, got %d body=%s", rec.Code, string(body))
	}
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp["error"] == "" {
		t.Fatalf("expected structured JSON error response, got %q", rec.Body.String())
	}
}

func TestAuditV2TrustedProxyHeaderSpoofingBlocked(t *testing.T) {
	// 1. Public external peer must NEVER be able to spoof client IP headers even when trustProxy=true.
	req := httptest.NewRequest(http.MethodGet, "https://proxy.test/", nil)
	req.RemoteAddr = "198.51.100.77:54321"
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.Header.Set("True-Client-IP", "1.2.3.5")
	req.Header.Set("EO-Connecting-IP", "1.2.3.6")
	req.Header.Set("X-Real-IP", "1.2.3.7")
	req.Header.Set("X-Forwarded-For", "1.2.3.8, 1.2.3.9")
	if got := adminClientIP(req, true); got != "198.51.100.77" {
		t.Fatalf("public peer spoofed client IP: got %q, want 198.51.100.77", got)
	}

	// 2. Loopback proxy peer IS trusted by default; right-to-left XFF skips private hops and empty trailing tokens.
	localReq := httptest.NewRequest(http.MethodGet, "https://proxy.test/", nil)
	localReq.RemoteAddr = "127.0.0.1:41234"
	localReq.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 10.0.0.5, , ")
	if got := adminClientIP(localReq, true); got != "203.0.113.9" {
		t.Fatalf("loopback proxy XFF parsing got %q, want 203.0.113.9", got)
	}

	// 3. Explicit TRUSTED_PROXY_CIDRS authorizes a specific public edge proxy and rejects others.
	trusted := parseTrustedProxyCIDRs("198.51.100.0/24")
	if len(trusted) != 1 {
		t.Fatalf("parseTrustedProxyCIDRs expected 1 prefix, got %v", trusted)
	}
	if got := adminClientIP(req, true, trusted...); got != "1.2.3.4" {
		t.Fatalf("explicitly trusted proxy peer got %q, want 1.2.3.4", got)
	}
	otherReq := httptest.NewRequest(http.MethodGet, "https://proxy.test/", nil)
	otherReq.RemoteAddr = "203.0.113.88:9999"
	otherReq.Header.Set("CF-Connecting-IP", "9.9.9.9")
	if got := adminClientIP(otherReq, true, trusted...); got != "203.0.113.88" {
		t.Fatalf("unlisted public peer with explicit CIDR got %q, want 203.0.113.88", got)
	}
}

func TestAuditV2AgentPublicFrontendWAFAndDomainIsolation(t *testing.T) {
	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AgentControllerURL = "https://controller.example.test"
	cfg.AgentNodeID = "nd_test_agent"
	cfg.AgentSecret = "agent-test-secret-0123456789abcdef"
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-state.json")
	cfg.AllowUnsigned = true
	cfg.TrustProxyHeaders = true
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	defer gw.Close()

	// Assign a single domain + a global WAF rule blocking 198.51.100.55.
	gw.applyAssignedDomains([]agentDomainConfig{
		{ID: "dom_1", Domain: "edge.example.test"},
	}, runtimeSettingsFromConfig(cfg), cfg)
	wafRule := wafRuleRecord{
		ID:       "r_block_ip",
		Name:     "Block Bad IP",
		Enabled:  true,
		IsGlobal: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "m", Type: wafNodeIPMatch, Config: wafNodeConfig{IPs: []string{"198.51.100.55"}}},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "waf blocked"}},
				{ID: "p", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "m"},
				{ID: "e2", Source: "m", SourcePort: "true", Target: "b"},
				{ID: "e3", Source: "m", SourcePort: "false", Target: "p"},
			},
		},
	}
	_, compiled, err := normalizeAndCompileWAFRule(wafRule)
	if err != nil {
		t.Fatalf("normalizeAndCompileWAFRule: %v", err)
	}
	globalList := []*compiledWAFRule{compiled}
	gw.globalWAFRules.Store(&globalList)

	// 1. Blocked IP hitting Agent GET / must be rejected by WAF (not bypassed).
	blockedReq := httptest.NewRequest(http.MethodGet, "https://edge.example.test/", nil)
	blockedReq.RemoteAddr = "198.51.100.55:4444"
	blockedRec := httptest.NewRecorder()
	gw.ServeHTTP(blockedRec, blockedReq)
	if blockedRec.Code != http.StatusForbidden {
		t.Fatalf("blocked IP on Agent GET / expected 403, got %d", blockedRec.Code)
	}

	// 2. Allowed IP hitting assigned Agent GET / receives public HTML with data-role="agent".
	okReq := httptest.NewRequest(http.MethodGet, "https://edge.example.test/", nil)
	okReq.RemoteAddr = "203.0.113.10:4444"
	okRec := httptest.NewRecorder()
	gw.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK || !strings.Contains(okRec.Body.String(), `data-role="agent"`) {
		t.Fatalf("allowed Agent GET / expected 200 with data-role=agent, got %d", okRec.Code)
	}

	// 3. Disabling public portal hides Agent GET /.
	gw.publicPortal.Store(false)
	hiddenRec := httptest.NewRecorder()
	gw.ServeHTTP(hiddenRec, okReq)
	if hiddenRec.Code != http.StatusNotFound {
		t.Fatalf("Agent GET / with publicPortal=false expected 404, got %d", hiddenRec.Code)
	}
	gw.publicPortal.Store(true)

	// 4. Unmatched host on Agent gateway auxiliary endpoints must return 421.
	for _, p := range []string{"/_gateway/nodes", "/_gateway/avatar", "/_gateway/emby-health", "/_gateway/assets/frontend.js"} {
		uReq := httptest.NewRequest(http.MethodGet, "https://unassigned.example.test"+p, nil)
		uRec := httptest.NewRecorder()
		gw.ServeHTTP(uRec, uReq)
		if uRec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("unmatched Agent host on %s expected 421, got %d", p, uRec.Code)
		}
	}

	// 5. Unmatched host on Agent /_gateway/health omits node_id & node_name; HEAD returns empty body.
	hReq := httptest.NewRequest(http.MethodGet, "https://unassigned.example.test/_gateway/health", nil)
	hRec := httptest.NewRecorder()
	gw.ServeHTTP(hRec, hReq)
	if hRec.Code != http.StatusOK {
		t.Fatalf("health expected 200, got %d", hRec.Code)
	}
	var healthBody map[string]any
	if err := json.Unmarshal(hRec.Body.Bytes(), &healthBody); err != nil {
		t.Fatalf("decode health JSON: %v", err)
	}
	if _, leaked := healthBody["node_id"]; leaked {
		t.Fatalf("unmatched Agent /_gateway/health leaked node_id: %v", healthBody)
	}
	headReq := httptest.NewRequest(http.MethodHead, "https://edge.example.test/_gateway/health", nil)
	headRec := httptest.NewRecorder()
	gw.ServeHTTP(headRec, headReq)
	if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
		t.Fatalf("HEAD /_gateway/health expected 200 empty body, got %d len=%d", headRec.Code, headRec.Body.Len())
	}

	// 6. AutoTLS port-80 redirect must NOT leak AllowedHost() on unmatched Host.
	autoTLS, err := newAgentAutoTLS(t.TempDir(), "")
	if err != nil {
		t.Fatalf("newAgentAutoTLS: %v", err)
	}
	defer autoTLS.Close()
	allowed := "edge.example.test"
	autoTLS.allowedHost.Store(&allowed)
	autoTLS.mu.Lock()
	autoTLS.http01Hosts[allowed] = struct{}{}
	autoTLS.mu.Unlock()
	redirectReq := httptest.NewRequest(http.MethodGet, "http://evil.example.test/", nil)
	redirectRec := httptest.NewRecorder()
	autoTLS.HTTPChallengeHandler(gw).ServeHTTP(redirectRec, redirectReq)
	if redirectRec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("port-80 unmatched host expected 421, got %d location=%q", redirectRec.Code, redirectRec.Header().Get("Location"))
	}
}

func TestAuditV2SetupHTMLSetupTokenAndDiscoveryVerifyNoAutoInit(t *testing.T) {
	cfg := testConfig()
	cfg.AdminEnabled = true
	cfg.AdminSessionSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.AdminSessionTTL = 12 * time.Hour
	cfg.AdminSetupToken = "setup-token-xyz"
	cfg.AdminDatabasePath = filepath.Join(t.TempDir(), "gateway.db")
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	defer gw.Close()

	// GET /setup must inject data-setup-token-required="true"
	setupRec := httptest.NewRecorder()
	gw.ServeHTTP(setupRec, httptest.NewRequest(http.MethodGet, "https://proxy.test/setup", nil))
	if setupRec.Code != http.StatusOK || !strings.Contains(setupRec.Body.String(), `data-setup-token-required="true"`) {
		t.Fatalf("GET /setup expected data-setup-token-required=true, status=%d", setupRec.Code)
	}
	// HEAD /setup returns 200 with no body; POST /setup returns 405 with Allow: GET, HEAD
	headRec := httptest.NewRecorder()
	gw.ServeHTTP(headRec, httptest.NewRequest(http.MethodHead, "https://proxy.test/setup", nil))
	if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
		t.Fatalf("HEAD /setup expected 200 empty, got %d len=%d", headRec.Code, headRec.Body.Len())
	}
	postRec := httptest.NewRecorder()
	gw.ServeHTTP(postRec, httptest.NewRequest(http.MethodPost, "https://proxy.test/setup", nil))
	if postRec.Code != http.StatusMethodNotAllowed || postRec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST /setup expected 405 Allow GET, HEAD; got %d allow=%q", postRec.Code, postRec.Header().Get("Allow"))
	}

	// Unauthenticated discovery Verify must NOT auto-create a cluster_discovery row.
	dm, err := newClusterDiscoveryManager(gw.telemetry, cfg.AdminSessionSecret)
	if err != nil {
		t.Fatalf("newClusterDiscoveryManager: %v", err)
	}
	if _, ok := dm.Verify(context.Background(), "rf_dsc_0000000000000000000000000000"); ok {
		t.Fatal("expected invalid discovery token to fail Verify")
	}
	var cnt int
	if err := gw.telemetry.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM gateway_settings WHERE key=?`, clusterDiscoverySettingKey).Scan(&cnt); err != nil {
		t.Fatalf("query cluster_discovery row count: %v", err)
	}
	if cnt != 0 {
		t.Fatalf("Verify() auto-initialized cluster_discovery setting unexpectedly: count=%d", cnt)
	}
}

func TestAuditV2AxisNowSafetyAndACMEManualGuard(t *testing.T) {
	// 1. filterPublicDNSIPs strips FakeIP, CGNAT, loopback, RFC1918, unspecified, keeping public IPs.
	var probeAddrs []net.IPAddr
	for _, s := range []string{"198.18.0.1", "100.64.1.2", "127.0.0.1", "10.0.0.1", "0.0.0.0", "203.0.113.10", "8.8.8.8", "8.8.8.8"} {
		probeAddrs = append(probeAddrs, net.IPAddr{IP: net.ParseIP(s)})
	}
	filtered := filterPublicDNSIPs(probeAddrs)
	if len(filtered) != 2 || filtered[0] != "203.0.113.10" || filtered[1] != "8.8.8.8" {
		t.Fatalf("filterPublicDNSIPs unexpected result: %v", filtered)
	}

	// 2. buildAxisNowTTLConf provider/plan mapping.
	if got := buildAxisNowTTLConf("dnspod-intl", ""); got == nil || got.ProviderType != "dnspod-intl" || got.TTL != 600 {
		t.Fatalf("dnspod-intl TTL conf unexpected: %+v", got)
	}
	if got := buildAxisNowTTLConf("alibaba-cloud", "enterprise-standard"); got == nil || got.Plan != "enterprise-standard" || got.TTL != 60 {
		t.Fatalf("alibaba-cloud enterprise-standard expected plan=enterprise-standard ttl=60, got %+v", got)
	}
	if got := buildAxisNowTTLConf("alibaba-cloud", ""); got == nil || got.Plan != "free" || got.TTL != 600 {
		t.Fatalf("alibaba-cloud free expected ttl=600, got %+v", got)
	}

	// 3. IP literals rejected in edge domains, failover groups, and smart DNS routing host.
	if _, err := normalizeEdgeDomainPattern("1.2.3.4"); err == nil {
		t.Fatal("expected normalizeEdgeDomainPattern to reject IPv4 literal")
	}
	if _, err := normalizeFailoverGroups([]dnsFailoverGroup{{Name: "g", Hostname: "203.0.113.5", NodeIDs: []string{"n1"}}}, "example.com", nil); err == nil {
		t.Fatal("expected normalizeFailoverGroups to reject IP literal")
	}

	// 4. Switching provider/zone clears stale RoutingDomainUUID/Host & rule UUIDs.
	existing := &edgeDomainSmartDNS{
		ProviderSource:    "platform",
		ProviderUUID:      "prov-old",
		ZoneUUID:          "zone-old",
		RoutingDomainUUID: "rd-old",
		RoutingDomainHost: "old.axisnow.test",
		CFCNAMESynced:     true,
		Lines:             []smartDNSLineRule{{ID: "l1", GeoISP: "default", AxisNowRuleUUID: "rule-old", Enabled: true}},
	}
	switched := normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{
		ProviderSource: "platform",
		ProviderUUID:   "prov-new",
		ZoneUUID:       "zone-new",
		Lines:          []smartDNSLineRule{{ID: "l1", GeoISP: "default", NodeIDs: []string{"n1"}, Enabled: true}},
	}, []string{"n1"}, existing)
	if switched == nil {
		t.Fatal("normalizeEdgeDomainSmartDNS returned nil")
	}
	if switched.RoutingDomainUUID != "" || switched.RoutingDomainHost != "" || switched.CFCNAMESynced || switched.Lines[0].AxisNowRuleUUID != "" {
		t.Fatalf("provider switch did not clear stale AxisNow state: %+v", switched)
	}

	// 5. Strict routing domain ownership protects untagged or foreign domains.
	other := axisnowRemoteRoutingDomain{UUID: "rd-1", Name: "emby.example.com", Description: axisnowManagedDescPrefix + " [dm_other]"}
	untagged := axisnowRemoteRoutingDomain{UUID: "rd-2", Name: "emby.example.com", Description: ""}
	if axisnowRoutingDomainExactOwner(other.Description, "dm_mine") || axisnowRoutingDomainExactOwner(untagged.Description, "dm_mine") {
		t.Fatal("axisnowRoutingDomainExactOwner must reject untagged or foreign-owned routing domains")
	}
	owned := axisnowRemoteRoutingDomain{UUID: "rd-3", Name: "emby.example.com", Description: axisnowManagedDescPrefix + " [dm_mine]"}
	if !axisnowRoutingDomainExactOwner(owned.Description, "dm_mine") {
		t.Fatal("axisnowRoutingDomainExactOwner should accept matching Refract tag")
	}

	// 6. POST /issue-cert must reject non-auto TLS domains.
	gw := newControllerTestGateway(t)
	cookie := loginAdmin(t, gw)
	dom, err := gw.telemetry.CreateEdgeDomain(context.Background(), edgeDomainRecord{
		Domain:  "manual.example.test",
		Name:    "Manual TLS",
		Enabled: true,
		TLSMode: domainTLSManual,
	})
	if err != nil {
		t.Fatalf("CreateEdgeDomain: %v", err)
	}
	rec := adminRequest(t, gw, http.MethodPost, "/_admin/api/domains/"+dom.ID+"/issue-cert", map[string]any{}, cookie, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /issue-cert on manual TLS domain expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	// 7. Controller mode must NOT decorate targets/requests/playbacks with stale monitored_emby_servers rows.
	if _, err := gw.telemetry.SaveEmbyHealthServer(context.Background(), embyHealthServer{
		GroupName: "旧分组",
		Name:      "示例服 A",
		LineName:  "旧线路",
		Note:      "旧备注",
		BaseURL:   "https://legacy-emby.example.test",
		Enabled:   true,
	}); err != nil {
		t.Fatalf("SaveEmbyHealthServer: %v", err)
	}
	if err := gw.telemetry.writeBatch([]telemetryEvent{{
		NodeID:     "local",
		Timestamp:  time.Now(),
		Host:       "legacy-emby.example.test",
		Scheme:     "https",
		Method:     "GET",
		Path:       "/emby/System/Info",
		Category:   "api",
		Status:     200,
		BytesOut:   256,
		DurationMS: 12,
	}}); err != nil {
		t.Fatalf("writeBatch: %v", err)
	}

	dashRec := adminRequest(t, gw, http.MethodGet, "/_admin/api/dashboard?period=24h", nil, cookie, false)
	if dashRec.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d", dashRec.Code)
	}
	if strings.Contains(dashRec.Body.String(), "示例服 A") {
		t.Fatalf("controller dashboard leaked legacy monitored_emby_servers label: %s", dashRec.Body.String())
	}
	reqRec := adminRequest(t, gw, http.MethodGet, "/_admin/api/requests?page=1&page_size=20", nil, cookie, false)
	if reqRec.Code != http.StatusOK {
		t.Fatalf("requests status=%d", reqRec.Code)
	}
	if strings.Contains(reqRec.Body.String(), "示例服 A") {
		t.Fatalf("controller requests leaked legacy monitored_emby_servers label: %s", reqRec.Body.String())
	}
}

func TestAuditHTTPChallengeOpenRedirectAndOpaqueBlocked(t *testing.T) {
	auto, err := newAgentAutoTLS(t.TempDir(), "")
	if err != nil {
		t.Fatalf("newAgentAutoTLS: %v", err)
	}
	defer auto.Close()
	auto.mu.Lock()
	auto.http01Hosts["edge.example.test"] = struct{}{}
	auto.mu.Unlock()
	h := auto.HTTPChallengeHandler(nil)

	reqOpaque := &http.Request{
		Method: http.MethodGet,
		Host:   "edge.example.test",
		URL:    &url.URL{Opaque: "//evil.com/phish"},
	}
	recOpaque := httptest.NewRecorder()
	h.ServeHTTP(recOpaque, reqOpaque)
	if recOpaque.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on opaque URI, got %d location=%q", recOpaque.Code, recOpaque.Header().Get("Location"))
	}

	reqValid := httptest.NewRequest(http.MethodGet, "http://edge.example.test/emby/Items?foo=1", nil)
	recValid := httptest.NewRecorder()
	h.ServeHTTP(recValid, reqValid)
	if recValid.Code != http.StatusPermanentRedirect || recValid.Header().Get("Location") != "https://edge.example.test/emby/Items?foo=1" {
		t.Fatalf("unexpected valid HTTPS redirect: code=%d loc=%q", recValid.Code, recValid.Header().Get("Location"))
	}
}

func TestAuditEmbyHealthPublicSnapshotSanitizesHostnames(t *testing.T) {
	snap := embyHealthPublicSnapshot([]embyHealthServer{
		{ID: 1, GroupName: "Main", Name: "secret-origin.example.com:8920", DetectedName: "我的影视库", Status: "up", Enabled: true},
		{ID: 2, GroupName: "Main", Name: "https://raw.example.net/emby", DetectedName: "raw.example.net", Status: "up", Enabled: true},
		{ID: 3, GroupName: "Main", Name: "友好的线路名", Status: "up", Enabled: true},
	})
	if len(snap.Groups) != 1 || len(snap.Groups[0].Servers) != 3 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	got := snap.Groups[0].Servers
	if got[0].Name != "我的影视库" || got[1].Name != "Emby 节点" || got[2].Name != "友好的线路名" {
		t.Fatalf("unexpected sanitized public Emby names: %+v", got)
	}
}
