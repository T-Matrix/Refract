package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newUnconfiguredAdminTestGateway(t *testing.T) *Gateway {
	t.Helper()
	cfg := testConfig()
	cfg.AdminEnabled = true
	cfg.AdminUsername = "admin"
	cfg.AdminPasswordHash = ""
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

func cookieFromResponse(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == adminCookieName {
			return cookie
		}
	}
	t.Fatal("session cookie not set")
	return nil
}

func TestFirstInstallCreatesOnlyOneAdministrator(t *testing.T) {
	gateway := newUnconfiguredAdminTestGateway(t)
	setupPage := adminRequest(t, gateway, http.MethodGet, "/setup", nil, nil, false)
	if setupPage.Code != http.StatusOK || !strings.Contains(setupPage.Body.String(), "创建管理员") {
		t.Fatalf("setup page status=%d body=%q", setupPage.Code, setupPage.Body.String())
	}
	created := adminRequest(t, gateway, http.MethodPost, "/_admin/api/setup", map[string]string{
		"username": "owner", "password": "a sufficiently long password", "confirm_password": "a sufficiently long password",
	}, nil, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("setup status=%d body=%s", created.Code, created.Body.String())
	}
	cookie := cookieFromResponse(t, created)
	second := adminRequest(t, gateway, http.MethodPost, "/_admin/api/setup", map[string]string{
		"username": "other", "password": "another sufficiently long password", "confirm_password": "another sufficiently long password",
	}, nil, true)
	if second.Code != http.StatusConflict {
		t.Fatalf("second setup status=%d body=%s", second.Code, second.Body.String())
	}
	panel := adminRequest(t, gateway, http.MethodGet, "/panel", nil, cookie, false)
	if panel.Code != http.StatusOK {
		t.Fatalf("panel after setup status=%d", panel.Code)
	}
}

func TestTurnstileRequiresMatchingSelfTestBeforeEnable(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	verification := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("secret") != "turnstile-secret" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		action := "config_test"
		if r.Form.Get("response") == "login-token" {
			action = "login"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "action": action, "hostname": "proxy.test"})
	}))
	defer verification.Close()
	gateway.turnstile.client = verification.Client()
	gateway.turnstile.siteverifyURL = verification.URL

	saved := adminRequest(t, gateway, http.MethodPut, "/_admin/api/turnstile", map[string]any{
		"enabled": false, "site_key": "1x00000000000000000000AA", "secret": "turnstile-secret",
	}, cookie, true)
	if saved.Code != http.StatusOK || strings.Contains(saved.Body.String(), "turnstile-secret") || !strings.Contains(saved.Body.String(), `"hostname":"proxy.test"`) {
		t.Fatalf("turnstile save status=%d body=%s", saved.Code, saved.Body.String())
	}
	tooSoon := adminRequest(t, gateway, http.MethodPut, "/_admin/api/turnstile", map[string]any{
		"enabled": true, "site_key": "1x00000000000000000000AA",
	}, cookie, true)
	if tooSoon.Code != http.StatusConflict {
		t.Fatalf("enable before self-test status=%d body=%s", tooSoon.Code, tooSoon.Body.String())
	}
	tested := adminRequest(t, gateway, http.MethodPost, "/_admin/api/turnstile/test", map[string]string{"token": "config-token"}, cookie, true)
	if tested.Code != http.StatusOK {
		t.Fatalf("turnstile self-test status=%d body=%s", tested.Code, tested.Body.String())
	}
	enabled := adminRequest(t, gateway, http.MethodPut, "/_admin/api/turnstile", map[string]any{
		"enabled": true, "site_key": "1x00000000000000000000AA",
	}, cookie, true)
	if enabled.Code != http.StatusOK {
		t.Fatalf("enable after self-test status=%d body=%s", enabled.Code, enabled.Body.String())
	}
	public := adminRequest(t, gateway, http.MethodGet, "/_admin/api/turnstile/public", nil, nil, false)
	if public.Code != http.StatusOK || !strings.Contains(public.Body.String(), `"enabled":true`) || strings.Contains(public.Body.String(), "secret") {
		t.Fatalf("public Turnstile response=%s", public.Body.String())
	}
	login := adminRequest(t, gateway, http.MethodPost, "/_admin/api/login", map[string]string{
		"username": "admin", "password": "correct horse battery staple", "turnstile_token": "login-token",
	}, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("Turnstile-protected login status=%d body=%s", login.Code, login.Body.String())
	}
	if err := gateway.turnstile.VerifyLogin(context.Background(), "login-token", "127.0.0.1", "other.test"); err == nil {
		t.Fatal("Turnstile login accepted a request from a different hostname")
	}
}

func TestTurnstileRequestHostname(t *testing.T) {
	for _, test := range []struct {
		host string
		want string
	}{
		{host: "Emby.Example.com:443", want: "emby.example.com"},
		{host: "127.0.0.1:8080", want: "127.0.0.1"},
		{host: "bad.example/path", want: ""},
	} {
		request := httptest.NewRequest(http.MethodGet, "https://proxy.test/", nil)
		request.Host = test.host
		if got := turnstileRequestHostname(request); got != test.want {
			t.Fatalf("host %q normalized to %q, want %q", test.host, got, test.want)
		}
	}
}

func TestDashboardPeriodChangesTimeWindow(t *testing.T) {
	gateway := newAdminTestGateway(t)
	now := time.Now().Unix()
	for _, item := range []struct {
		age      time.Duration
		requests int
	}{
		{age: 10 * 24 * time.Hour, requests: 1},
		{age: 3 * 24 * time.Hour, requests: 2},
		{age: 12 * time.Hour, requests: 4},
	} {
		minute := (now - int64(item.age/time.Second)) / 60 * 60
		if _, err := gateway.telemetry.db.Exec(`INSERT INTO traffic_minutes(minute,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?)`, minute, "media.example", item.requests, 0, item.requests, 0, 1); err != nil {
			t.Fatal(err)
		}
	}
	for _, check := range []struct {
		period  time.Duration
		wantSum int64
	}{
		{24 * time.Hour, 4},
		{7 * 24 * time.Hour, 6},
		{30 * 24 * time.Hour, 7},
	} {
		snapshot, err := gateway.telemetry.Snapshot(context.Background(), check.period, 0, 0, time.Minute, gateway.connections)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Requests24H != check.wantSum {
			t.Fatalf("period %s requests=%d want %d", check.period, snapshot.Requests24H, check.wantSum)
		}
	}
}
