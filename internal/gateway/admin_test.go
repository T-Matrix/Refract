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
