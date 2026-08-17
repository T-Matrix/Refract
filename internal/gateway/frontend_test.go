package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPublicFrontendTakesPriorityOverDefaultUpstream(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamRequests.Add(1)
		_, _ = writer.Write([]byte("upstream root"))
	}))
	defer upstream.Close()

	gateway, server := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer server.Close()

	response, err := http.Get(server.URL + "/?source=test")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Refract · 通用反向代理") {
		t.Fatalf("frontend status=%d body=%q", response.StatusCode, body)
	}
	if upstreamRequests.Load() != 0 {
		t.Fatalf("root request reached default upstream %d times", upstreamRequests.Load())
	}
	if response.Header.Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("frontend security headers = %#v", response.Header)
	}
}

func TestPublicFrontendTakesPriorityOverAdminRootRedirect(t *testing.T) {
	gateway := newAdminTestGateway(t)
	response := adminRequest(t, gateway, http.MethodGet, "/", nil, nil, false)
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" || !strings.Contains(response.Body.String(), "Refract") {
		t.Fatalf("admin root status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
	}
}

func TestPublicFrontendAssetsAreCachedAndSupportHead(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()

	getRequest := httptest.NewRequest(http.MethodGet, "https://proxy.test"+publicAssetPrefix+"frontend.css", nil)
	getResponse := httptest.NewRecorder()
	gateway.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.HasPrefix(getResponse.Header().Get("Content-Type"), "text/css") ||
		!strings.Contains(getResponse.Header().Get("Cache-Control"), "immutable") || getResponse.Body.Len() == 0 {
		t.Fatalf("asset status=%d headers=%#v bytes=%d", getResponse.Code, getResponse.Header(), getResponse.Body.Len())
	}

	headRequest := httptest.NewRequest(http.MethodHead, "https://proxy.test/", nil)
	headResponse := httptest.NewRecorder()
	gateway.ServeHTTP(headResponse, headRequest)
	contentLength, err := strconv.Atoi(headResponse.Header().Get("Content-Length"))
	if err != nil || headResponse.Code != http.StatusOK || contentLength <= 0 || headResponse.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d length=%q body=%d", headResponse.Code, headResponse.Header().Get("Content-Length"), headResponse.Body.Len())
	}
}

func TestPublicAvatarUsesEmbeddedDefaultWithoutAdmin(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()
	request := httptest.NewRequest(http.MethodHead, "https://proxy.test/_gateway/avatar", nil)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/png" ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Length") == "" || response.Body.Len() != 0 {
		t.Fatalf("default avatar status=%d headers=%#v body=%d", response.Code, response.Header(), response.Body.Len())
	}
}

func TestPublicFrontendAssetRejectsWrites(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()
	request := httptest.NewRequest(http.MethodPost, "https://proxy.test"+publicAssetPrefix+"frontend.js", strings.NewReader("ignored"))
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("asset write status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}

func TestHealthPublishesConfiguredFrontendEntry(t *testing.T) {
	cfg := testConfig()
	cfg.PublicBaseURL = mustURL(t, "https://proxy.configured.example")
	gateway := New(cfg)
	defer gateway.Close()
	request := httptest.NewRequest(http.MethodGet, "https://internal.example/_gateway/health", nil)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || payload["public_base_url"] != "https://proxy.configured.example" {
		t.Fatalf("health status=%d payload=%#v", response.Code, payload)
	}
}
