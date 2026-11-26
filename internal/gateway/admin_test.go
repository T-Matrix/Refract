package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newAdminTestGateway(t *testing.T) *Gateway {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.AdminEnabled = true
	cfg.AdminUsername = "admin"
	cfg.AdminPasswordHash = string(hash)
	cfg.AdminSessionSecret = []byte("0123456789abcdef0123456789abcdef")
	cfg.AdminSessionTTL = 12 * time.Hour
	cfg.AdminDatabasePath = filepath.Join(t.TempDir(), "gateway.db")
	gateway, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)
	return gateway
}

func adminRequest(t *testing.T, gateway *Gateway, method, path string, body any, cookie *http.Cookie, withOrigin bool) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "https://proxy.test"+path, &encoded)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if withOrigin {
		request.Header.Set("Origin", "https://proxy.test")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	return recorder
}

func loginAdmin(t *testing.T, gateway *Gateway) *http.Cookie {
	t.Helper()
	recorder := adminRequest(t, gateway, http.MethodPost, "/_admin/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery staple",
	}, nil, true)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	response := recorder.Result()
	defer response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Name == adminCookieName {
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("insecure session cookie: %#v", cookie)
			}
			return cookie
		}
	}
	t.Fatal("session cookie not set")
	return nil
}

func loginAdminFromIP(t *testing.T, gateway *Gateway, ip, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": "admin", "password": password})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://proxy.test/_admin/api/login", bytes.NewReader(body))
	request.RemoteAddr = ip + ":12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://proxy.test")
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	return recorder
}

func TestAdminRoutesRequireAuthentication(t *testing.T) {
	gateway := newAdminTestGateway(t)

	login := adminRequest(t, gateway, http.MethodGet, "/login", nil, nil, false)
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "管理员登录") {
		t.Fatalf("login page status=%d body=%q", login.Code, login.Body.String())
	}
	if !strings.Contains(login.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("login page is missing strict CSP")
	}

	panel := adminRequest(t, gateway, http.MethodGet, "/panel", nil, nil, false)
	if panel.Code != http.StatusFound || panel.Header().Get("Location") != "/login" {
		t.Fatalf("unauthenticated panel status=%d location=%q", panel.Code, panel.Header().Get("Location"))
	}

	api := adminRequest(t, gateway, http.MethodGet, "/_admin/api/dashboard", nil, nil, false)
	if api.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status=%d", api.Code)
	}
}

func TestAdminLoginRejectsCrossOriginAndIssuesSecureSession(t *testing.T) {
	gateway := newAdminTestGateway(t)

	withoutOrigin := adminRequest(t, gateway, http.MethodPost, "/_admin/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery staple",
	}, nil, false)
	if withoutOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status=%d", withoutOrigin.Code)
	}

	cookie := loginAdmin(t, gateway)
	panel := adminRequest(t, gateway, http.MethodGet, "/panel", nil, cookie, false)
	if panel.Code != http.StatusOK || !strings.Contains(panel.Body.String(), "运行概览") {
		t.Fatalf("authenticated panel status=%d", panel.Code)
	}
	dashboard := adminRequest(t, gateway, http.MethodGet, "/_admin/api/dashboard", nil, cookie, false)
	if dashboard.Code != http.StatusOK {
		t.Fatalf("dashboard status=%d body=%s", dashboard.Code, dashboard.Body.String())
	}
}

func TestAdminPanelBootDoesNotWaitForOptionalScripts(t *testing.T) {
	gateway := newAdminTestGateway(t)
	panel := adminRequest(t, gateway, http.MethodGet, "/panel", nil, loginAdmin(t, gateway), false)
	if panel.Code != http.StatusOK {
		t.Fatalf("authenticated panel status=%d", panel.Code)
	}
	html := panel.Body.String()
	if strings.Count(html, "<script") != 1 || !strings.Contains(html, `<script defer src="/_admin/assets/panel.js?`) {
		t.Fatal("panel boot must depend only on the local entry script")
	}
	for _, optionalScript := range []string{"challenges.cloudflare.com", "echarts.min.js", "lucide.min.js"} {
		if strings.Contains(html, optionalScript) {
			t.Fatalf("optional resource %q must load independently of panel boot", optionalScript)
		}
	}
}

func TestAdminLoginBlocksOnlyFailingIPFor24Hours(t *testing.T) {
	gateway := newAdminTestGateway(t)
	blockedIP := "198.51.100.10"

	for attempt := 1; attempt <= loginFailureLimit; attempt++ {
		response := loginAdminFromIP(t, gateway, blockedIP, "incorrect password")
		expected := http.StatusUnauthorized
		if attempt == loginFailureLimit {
			expected = http.StatusTooManyRequests
		}
		if response.Code != expected {
			t.Fatalf("attempt %d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}

	blocked := loginAdminFromIP(t, gateway, blockedIP, "correct horse battery staple")
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked IP status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	retryAfter, err := time.ParseDuration(blocked.Header().Get("Retry-After") + "s")
	if err != nil || retryAfter < 23*time.Hour || retryAfter > loginBlockDuration {
		t.Fatalf("unexpected Retry-After %q", blocked.Header().Get("Retry-After"))
	}

	allowed := loginAdminFromIP(t, gateway, "198.51.100.11", "correct horse battery staple")
	if allowed.Code != http.StatusOK {
		t.Fatalf("different IP was blocked: status=%d body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestAdminClientIPUsesCloudflareAddressWhenProxyHeadersAreTrusted(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://proxy.test/panel", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.20, 203.0.113.30")
	request.Header.Set("X-Real-IP", "198.51.100.25")
	request.Header.Set("CF-Connecting-IP", "198.51.100.20")

	if got := adminClientIP(request, true); got != "198.51.100.20" {
		t.Fatalf("client IP=%q", got)
	}
	if got := adminClientIP(request, false); got != "127.0.0.1" {
		t.Fatalf("untrusted client IP=%q", got)
	}

	// Multi-hop X-Real-IP takes precedence over multi-hop X-Forwarded-For CDN peer IP
	openflareReq := httptest.NewRequest(http.MethodGet, "https://proxy.test/panel", nil)
	openflareReq.RemoteAddr = "127.0.0.1:12345"
	openflareReq.Header.Set("X-Forwarded-For", "198.51.100.25, 198.51.100.12")
	openflareReq.Header.Set("X-Real-IP", "198.51.100.25")
	if got := adminClientIP(openflareReq, true); got != "198.51.100.25" {
		t.Fatalf("openflare X-Real-IP=%q want 198.51.100.25", got)
	}
	if got := adminClientIP(openflareReq, false); got != "127.0.0.1" {
		t.Fatalf("untrusted X-Real-IP=%q want 127.0.0.1", got)
	}
}

func TestPanelHTMLInjectsServerRoleClass(t *testing.T) {
	standalone := newAdminTestGateway(t)
	sCookie := loginAdmin(t, standalone)
	sResp := adminRequest(t, standalone, http.MethodGet, "/panel", nil, sCookie, false)
	if sResp.Code != http.StatusOK || !strings.Contains(sResp.Body.String(), `<body class="panel-page" data-role="standalone">`) || strings.Contains(sResp.Body.String(), `mode-controller`) {
		t.Fatalf("unexpected standalone /panel body role tag: status=%d", sResp.Code)
	}

	controller := newControllerTestGateway(t)
	cCookie := loginAdmin(t, controller)
	cResp := adminRequest(t, controller, http.MethodGet, "/panel", nil, cCookie, false)
	if cResp.Code != http.StatusOK || !strings.Contains(cResp.Body.String(), `<body class="panel-page mode-controller" data-role="controller">`) {
		t.Fatalf("expected mode-controller injected into controller /panel HTML, got status=%d", cResp.Code)
	}
}

func TestPasswordChangeInvalidatesExistingSession(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)

	changed := adminRequest(t, gateway, http.MethodPost, "/_admin/api/password", map[string]string{
		"current_password": "correct horse battery staple",
		"new_password":     "a different strong password",
	}, cookie, true)
	if changed.Code != http.StatusOK {
		t.Fatalf("password change status=%d body=%s", changed.Code, changed.Body.String())
	}

	session := adminRequest(t, gateway, http.MethodGet, "/_admin/api/session", nil, cookie, false)
	if session.Code != http.StatusUnauthorized {
		t.Fatalf("old session remained valid after password change: %d", session.Code)
	}
}

func TestTelemetryNeverStoresQueryParameters(t *testing.T) {
	gateway := newAdminTestGateway(t)
	gateway.telemetry.Record(telemetryEvent{
		Timestamp: time.Now(), Host: "emby.example", Scheme: "https", Method: http.MethodGet,
		Path: "/Videos/1/stream.m3u8?api_key=top-secret-token", Category: "manifest", Status: http.StatusOK, BytesOut: 1024, DurationMS: 20,
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		logs, err := gateway.telemetry.recent(context.Background(), 10, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(logs) > 0 {
			if strings.Contains(logs[0].Path, "?") || strings.Contains(logs[0].Path, "token") {
				t.Fatalf("sensitive query was persisted: %q", logs[0].Path)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("telemetry event was not persisted")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRequestLogsClientIPStorageFilterAndGeo(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	now := time.Now()

	gateway.telemetry.Record(telemetryEvent{
		Timestamp: now.Add(-2 * time.Second), ClientIP: "203.0.113.102", Host: "emby.example", Scheme: "https",
		Method: http.MethodGet, Path: "/Videos/1/stream", Category: "stream", Status: http.StatusOK,
		BytesOut: 2048, DurationMS: 18, ClientName: "SenPlayer",
	})
	gateway.telemetry.Record(telemetryEvent{
		Timestamp: now.Add(-1 * time.Second), ClientIP: "198.51.100.12", Host: "emby.example", Scheme: "https",
		Method: http.MethodGet, Path: "/Videos/2/stream", Category: "stream", Status: http.StatusForbidden,
		BytesOut: 128, DurationMS: 4, ClientName: "Chrome",
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		logs, err := gateway.telemetry.recent(context.Background(), 10, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(logs) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("telemetry events were not persisted")
		}
		time.Sleep(50 * time.Millisecond)
	}

	if _, err := gateway.telemetry.db.Exec(
		`INSERT OR REPLACE INTO geo_ip_cache(ip, country, country_code, region, latitude, longitude, looked_up) VALUES(?,?,?,?,?,?,?)`,
		"203.0.113.102", "China", "CN", "湖南", 28.2, 112.9, now.Unix(),
	); err != nil {
		t.Fatal(err)
	}

	// Verify /_admin/api/requests returns client_ip and location
	allRec := adminRequest(t, gateway, http.MethodGet, "/_admin/api/requests?page=1&page_size=20", nil, cookie, false)
	if allRec.Code != http.StatusOK {
		t.Fatalf("GET /_admin/api/requests status=%d body=%s", allRec.Code, allRec.Body.String())
	}
	var allRes struct {
		Logs     []requestLog            `json:"logs"`
		Statuses []requestLogStatusCount `json:"statuses"`
		Total    int64                   `json:"total"`
	}
	if err := json.NewDecoder(allRec.Body).Decode(&allRes); err != nil {
		t.Fatal(err)
	}
	if allRes.Total != 2 || len(allRes.Logs) != 2 {
		t.Fatalf("expected 2 request logs, got total=%d len=%d", allRes.Total, len(allRes.Logs))
	}
	var foundCN bool
	for _, l := range allRes.Logs {
		if l.ClientIP == "203.0.113.102" {
			foundCN = true
			if l.Location == "" {
				t.Fatalf("expected geo location for 203.0.113.102, got %+v", l)
			}
		}
	}
	if !foundCN {
		t.Fatalf("expected 203.0.113.102 in logs, got %+v", allRes.Logs)
	}

	// Verify prefix filtering by ?client_ip=203.0.113.
	filteredRec := adminRequest(t, gateway, http.MethodGet, "/_admin/api/requests?page=1&page_size=20&client_ip=203.0.113.", nil, cookie, false)
	if filteredRec.Code != http.StatusOK {
		t.Fatalf("filtered GET /_admin/api/requests status=%d body=%s", filteredRec.Code, filteredRec.Body.String())
	}
	var filteredRes struct {
		Logs     []requestLog            `json:"logs"`
		Statuses []requestLogStatusCount `json:"statuses"`
		Total    int64                   `json:"total"`
	}
	if err := json.NewDecoder(filteredRec.Body).Decode(&filteredRes); err != nil {
		t.Fatal(err)
	}
	if filteredRes.Total != 1 || len(filteredRes.Logs) != 1 || filteredRes.Logs[0].ClientIP != "203.0.113.102" {
		t.Fatalf("unexpected prefix filtered logs: %+v", filteredRes)
	}
	if len(filteredRes.Statuses) != 1 || filteredRes.Statuses[0].Status != http.StatusOK || filteredRes.Statuses[0].Count != 1 {
		t.Fatalf("unexpected filtered status counts: %+v", filteredRes.Statuses)
	}
}
