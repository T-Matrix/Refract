package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func validRuntimeSettings() runtimeSettings {
	return runtimeSettings{
		DefaultUpstream:              "https://emby.example.com",
		AllowedUpstreams:             "media.example.com,*.cdn.example.com",
		AllowUnsigned:                true,
		PassClientIP:                 false,
		DisableCache:                 true,
		RewriteMaxBytes:              8 << 20,
		DNSCacheTTLSeconds:           60,
		DialTimeoutSeconds:           15,
		ResponseHeaderTimeoutSeconds: 60,
		MaxConcurrentRequests:        256,
		MaxConcurrentPerIP:           64,
		MaxDownloadMbitPerIP:         80,
	}
}

func TestRuntimeConfigAPIIsAuthenticatedValidatedAndPrivate(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)

	unauthenticated := adminRequest(t, gateway, http.MethodGet, "/_admin/api/runtime-config", nil, nil, false)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", unauthenticated.Code)
	}
	status := adminRequest(t, gateway, http.MethodGet, "/_admin/api/runtime-config", nil, cookie, false)
	if status.Code != http.StatusOK || strings.Contains(status.Body.String(), "0123456789abcdef") {
		t.Fatalf("runtime config status=%d body=%s", status.Code, status.Body.String())
	}

	settings := validRuntimeSettings()
	crossOrigin := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", settings, cookie, false)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}
	invalid := settings
	invalid.MaxConcurrentPerIP = invalid.MaxConcurrentRequests + 1
	rejected := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", invalid, cookie, true)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("invalid status=%d body=%s", rejected.Code, rejected.Body.String())
	}

	saved := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", settings, cookie, true)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"default_upstream":"https://emby.example.com"`) || !strings.Contains(saved.Body.String(), `"hot_reload":true`) || !strings.Contains(saved.Body.String(), `"restart_pending":false`) {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
	}
	if gateway.runtime.current.MaxDownloadMbitPerIP != 80 {
		t.Fatalf("saved per-IP speed limit = %d Mbps", gateway.runtime.current.MaxDownloadMbitPerIP)
	}
	info, err := os.Stat(gateway.cfg.RuntimeConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime config mode=%o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(gateway.cfg.RuntimeConfigPath + ".backup"); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeConfigFallsBackToLastKnownGoodFile(t *testing.T) {
	base := testConfig()
	base.MaxConcurrent = 256
	base.MaxConcurrentPerIP = 64
	base.RuntimeConfigPath = filepath.Join(t.TempDir(), "runtime-config.json")
	manager := newRuntimeConfigManager(base)
	first := validRuntimeSettings()
	first.MaxConcurrentRequests = 300
	first.MaxConcurrentPerIP = 50
	if _, err := manager.Save(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.MaxConcurrentRequests = 400
	if _, err := manager.Save(second); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base.RuntimeConfigPath, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded := loadRuntimeConfigWithFallback(base)
	if loaded.MaxConcurrent != 300 || loaded.MaxConcurrentPerIP != 50 {
		t.Fatalf("fallback concurrency=%d/%d, want 300/50", loaded.MaxConcurrent, loaded.MaxConcurrentPerIP)
	}
}

func TestMaintenanceSocketUsesRestrictedUpdateProtocol(t *testing.T) {
	temporary, err := os.CreateTemp("", "rf-maintenance-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	path := temporary.Name()
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		var request maintenanceRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			done <- decodeErr
			return
		}
		if request.Action != "update" || request.Version != "1.9.0" {
			done <- &protocolTestError{request: request}
			return
		}
		done <- json.NewEncoder(connection).Encode(maintenanceResponse{OK: true})
	}()

	manager := &updateManager{maintenanceSocket: path}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := manager.requestMaintenanceUpdate(ctx, "v1.9.0"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type protocolTestError struct {
	request maintenanceRequest
}

func (e *protocolTestError) Error() string {
	return "unexpected maintenance request: " + e.request.Action + " " + e.request.Version
}

func TestRuntimeConfigHotReloadTogglesAndRouting(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Content-Type", "application/json")
		payload := map[string]string{
			"url": upstream.URL + "/video/stream.m3u8",
			"xff": r.Header.Get("X-Forwarded-For"),
		}
		if r.URL.Query().Get("large") == "1" {
			payload["pad"] = strings.Repeat("p", 2048)
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.AllowPrivateTargets = true
	gateway.resolver.allowPrivate = true
	gateway.runtime.restart = true // Even with RESTART_ON_CONFIG_SAVE=true, hot reload must NOT restart.
	cookie := loginAdmin(t, gateway)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseSettings := runtimeSettings{
		DefaultUpstream:              "",
		AllowedUpstreams:             "",
		AllowUnsigned:                false,
		PassClientIP:                 false,
		DisableCache:                 false,
		RewriteMaxBytes:              8 << 20,
		DNSCacheTTLSeconds:           60,
		DialTimeoutSeconds:           15,
		ResponseHeaderTimeoutSeconds: 60,
		MaxConcurrentRequests:        64,
		MaxConcurrentPerIP:           16,
		MaxDownloadMbitPerIP:         0,
	}
	putSettings := func(s runtimeSettings) {
		t.Helper()
		res := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", s, cookie, true)
		if res.Code != http.StatusOK {
			t.Fatalf("PUT runtime-config status=%d body=%s", res.Code, res.Body.String())
		}
		var view runtimeSettingsView
		if err := json.Unmarshal(res.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		if !view.HotReload || view.RestartPending || gateway.restarting.Load() {
			t.Fatalf("expected hot reload without restart: view=%+v restarting=%v", view, gateway.restarting.Load())
		}
	}

	dynamicURL := "https://proxy.test/" + upstream.URL + "/info"

	// 1. AllowUnsigned hot toggle: off -> 403, on -> 200, off -> 403
	putSettings(baseSettings)
	blocked := httptest.NewRecorder()
	gateway.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, dynamicURL, nil))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("unsigned off status=%d, want 403", blocked.Code)
	}

	s := baseSettings
	s.AllowUnsigned = true
	putSettings(s)
	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, dynamicURL, nil)
	req.RemoteAddr = "198.51.100.7:4321"
	gateway.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("unsigned on status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if got := allowed.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("disable_cache=false Cache-Control=%q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(allowed.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["xff"] != "" {
		t.Fatalf("pass_client_ip=false forwarded xff=%q", body["xff"])
	}

	// 2. PassClientIP & DisableCache hot toggle
	s.PassClientIP = true
	s.DisableCache = true
	putSettings(s)
	withHeaders := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, dynamicURL, nil)
	req2.RemoteAddr = "198.51.100.7:4321"
	gateway.ServeHTTP(withHeaders, req2)
	if withHeaders.Code != http.StatusOK {
		t.Fatalf("pass_client_ip=true status=%d body=%s", withHeaders.Code, withHeaders.Body.String())
	}
	if got := withHeaders.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("disable_cache=true Cache-Control=%q, want no-store", got)
	}
	body = nil
	if err := json.Unmarshal(withHeaders.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body["xff"], "198.51.100.7") {
		t.Fatalf("pass_client_ip=true xff=%q, want client IP", body["xff"])
	}

	// 3. AllowedUpstreams hot toggle (with AllowUnsigned=false)
	s.AllowUnsigned = false
	s.AllowedUpstreams = upstreamURL.Host
	putSettings(s)
	byAllowlist := httptest.NewRecorder()
	gateway.ServeHTTP(byAllowlist, httptest.NewRequest(http.MethodGet, dynamicURL, nil))
	if byAllowlist.Code != http.StatusOK {
		t.Fatalf("allowed_upstreams status=%d body=%s", byAllowlist.Code, byAllowlist.Body.String())
	}

	// 4. DefaultUpstream & RewriteMaxBytes hot toggle
	noDefault := httptest.NewRecorder()
	gateway.ServeHTTP(noDefault, httptest.NewRequest(http.MethodGet, "https://proxy.test/direct", nil))
	if noDefault.Code != http.StatusNotFound {
		t.Fatalf("no default_upstream status=%d, want 404", noDefault.Code)
	}

	s.DefaultUpstream = upstream.URL
	s.AllowedUpstreams = ""
	s.RewriteMaxBytes = 1024
	putSettings(s)

	smallDefault := httptest.NewRecorder()
	gateway.ServeHTTP(smallDefault, httptest.NewRequest(http.MethodGet, "https://proxy.test/direct", nil))
	if smallDefault.Code != http.StatusOK {
		t.Fatalf("default_upstream status=%d body=%s", smallDefault.Code, smallDefault.Body.String())
	}
	body = nil
	if err := json.Unmarshal(smallDefault.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["url"] != "https://proxy.test/video/stream.m3u8" {
		t.Fatalf("default_upstream rewrite url=%q, want https://proxy.test/video/stream.m3u8", body["url"])
	}

	largeSkipped := httptest.NewRecorder()
	gateway.ServeHTTP(largeSkipped, httptest.NewRequest(http.MethodGet, "https://proxy.test/direct?large=1", nil))
	body = nil
	if err := json.Unmarshal(largeSkipped.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["url"] != upstream.URL+"/video/stream.m3u8" {
		t.Fatalf("rewrite_max_bytes=1024 should skip large body, got url=%q", body["url"])
	}

	s.RewriteMaxBytes = 1 << 20
	putSettings(s)
	largeRewritten := httptest.NewRecorder()
	gateway.ServeHTTP(largeRewritten, httptest.NewRequest(http.MethodGet, "https://proxy.test/direct?large=1", nil))
	body = nil
	if err := json.Unmarshal(largeRewritten.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["url"] != "https://proxy.test/video/stream.m3u8" {
		t.Fatalf("rewrite_max_bytes=1MiB should rewrite large body, got url=%q", body["url"])
	}
}

func TestRuntimeConfigHotReloadLimitsDNSAndTransport(t *testing.T) {
	holdStarted := make(chan struct{})
	holdRelease := make(chan struct{})
	slowStarted := make(chan struct{})
	slowRelease := make(chan struct{})
	var closeHoldOnce, closeSlowOnce sync.Once
	releaseHold := func() { closeHoldOnce.Do(func() { close(holdRelease) }) }
	releaseSlow := func() { closeSlowOnce.Do(func() { close(slowRelease) }) }
	defer releaseHold()
	defer releaseSlow()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			close(holdStarted)
			select {
			case <-holdRelease:
				_, _ = w.Write([]byte("held"))
			case <-r.Context().Done():
			}
		case "/slow-inflight":
			close(slowStarted)
			select {
			case <-slowRelease:
				_, _ = w.Write([]byte("inflight-ok"))
			case <-r.Context().Done():
			}
		case "/slow-timeout":
			select {
			case <-time.After(1300 * time.Millisecond):
				_, _ = w.Write([]byte("late"))
			case <-r.Context().Done():
			}
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.AllowPrivateTargets = true
	gateway.resolver.allowPrivate = true
	cookie := loginAdmin(t, gateway)

	settings := runtimeSettings{
		DefaultUpstream:              upstream.URL,
		AllowUnsigned:                true,
		DisableCache:                 true,
		RewriteMaxBytes:              8 << 20,
		DNSCacheTTLSeconds:           60,
		DialTimeoutSeconds:           15,
		ResponseHeaderTimeoutSeconds: 30,
		MaxConcurrentRequests:        10,
		MaxConcurrentPerIP:           5,
		MaxDownloadMbitPerIP:         0,
	}
	put := func(s runtimeSettings) {
		t.Helper()
		res := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", s, cookie, true)
		if res.Code != http.StatusOK {
			t.Fatalf("PUT runtime-config status=%d body=%s", res.Code, res.Body.String())
		}
	}
	put(settings)

	// 1. Live concurrency limit hot reload without interrupting active request
	holdDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://proxy.test/hold", nil)
		req.RemoteAddr = "198.51.100.20:1111"
		gateway.ServeHTTP(rec, req)
		holdDone <- rec
	}()
	<-holdStarted

	settings.MaxConcurrentRequests = 1
	settings.MaxConcurrentPerIP = 1
	put(settings)

	limited := httptest.NewRecorder()
	reqLimited := httptest.NewRequest(http.MethodGet, "https://proxy.test/ok", nil)
	reqLimited.RemoteAddr = "198.51.100.20:2222"
	gateway.ServeHTTP(limited, reqLimited)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("tightened concurrency limit status=%d, want 429", limited.Code)
	}

	settings.MaxConcurrentRequests = 4
	settings.MaxConcurrentPerIP = 2
	put(settings)

	admitted := httptest.NewRecorder()
	reqAdmitted := httptest.NewRequest(http.MethodGet, "https://proxy.test/ok", nil)
	reqAdmitted.RemoteAddr = "198.51.100.20:3333"
	gateway.ServeHTTP(admitted, reqAdmitted)
	if admitted.Code != http.StatusOK {
		t.Fatalf("raised concurrency limit status=%d, want 200", admitted.Code)
	}
	releaseHold()
	if holdRec := <-holdDone; holdRec.Code != http.StatusOK || holdRec.Body.String() != "held" {
		t.Fatalf("active request disrupted: status=%d body=%q", holdRec.Code, holdRec.Body.String())
	}

	// 2. Bandwidth limit hot reload (including clamping queued reservations when uncapped)
	settings.MaxDownloadMbitPerIP = 1
	put(settings)
	if gateway.bandwidth.Limit() != megabitsToBytes(1) {
		t.Fatalf("bandwidth limit=%d, want %d", gateway.bandwidth.Limit(), megabitsToBytes(1))
	}
	_ = gateway.bandwidth.reserve("198.51.100.99", 512<<10, time.Now())
	settings.MaxDownloadMbitPerIP = 0
	put(settings)
	if gateway.bandwidth.Limit() != 0 {
		t.Fatalf("bandwidth limit=%d, want 0", gateway.bandwidth.Limit())
	}
	start := time.Now()
	if err := gateway.bandwidth.Wait(context.Background(), "198.51.100.99", 64<<10); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("uncapped bandwidth Wait blocked for %s", time.Since(start))
	}

	// 3. DNS TTL hot reload clamps existing long-lived cache entries
	gateway.resolver.mu.Lock()
	gateway.resolver.cache["media.example"] = dnsCacheEntry{
		addresses: []netip.Addr{netip.MustParseAddr("93.184.216.34")},
		expires:   time.Now().Add(10 * time.Minute),
	}
	gateway.resolver.mu.Unlock()

	settings.DNSCacheTTLSeconds = 2
	put(settings)
	if gateway.resolver.TTL() != 2*time.Second {
		t.Fatalf("resolver TTL=%s, want 2s", gateway.resolver.TTL())
	}
	gateway.resolver.mu.Lock()
	clampedExpiry := gateway.resolver.cache["media.example"].expires
	gateway.resolver.mu.Unlock()
	if time.Until(clampedExpiry) > 3*time.Second {
		t.Fatalf("dns cache entry not clamped: expires in %s", time.Until(clampedExpiry))
	}

	// 4. DialTimeout hot reload does NOT needlessly replace Transport; ResponseTimeout swap preserves in-flight requests
	initialTransport := gateway.transport.Load()
	settings.DialTimeoutSeconds = 7
	put(settings)
	if gateway.transport.Load() != initialTransport {
		t.Fatal("dial timeout change unexpectedly replaced upstream transport")
	}
	if gateway.liveRuntime().DialTimeout != 7*time.Second {
		t.Fatalf("live DialTimeout=%s, want 7s", gateway.liveRuntime().DialTimeout)
	}

	inflightDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		gateway.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://proxy.test/slow-inflight", nil))
		inflightDone <- rec
	}()
	<-slowStarted

	settings.ResponseHeaderTimeoutSeconds = 1
	put(settings)
	swappedTransport := gateway.transport.Load()
	if swappedTransport == initialTransport || swappedTransport.ResponseHeaderTimeout != time.Second {
		t.Fatalf("transport not hot-swapped: same=%v timeout=%s", swappedTransport == initialTransport, swappedTransport.ResponseHeaderTimeout)
	}

	timedOut := httptest.NewRecorder()
	gateway.ServeHTTP(timedOut, httptest.NewRequest(http.MethodGet, "https://proxy.test/slow-timeout", nil))
	if timedOut.Code != http.StatusBadGateway {
		t.Fatalf("new request exceeding hot-reloaded 1s header timeout got status=%d, want 502", timedOut.Code)
	}

	releaseSlow()
	if inflightRec := <-inflightDone; inflightRec.Code != http.StatusOK || inflightRec.Body.String() != "inflight-ok" {
		t.Fatalf("in-flight request disrupted by transport swap: status=%d body=%q", inflightRec.Code, inflightRec.Body.String())
	}
}

func TestRuntimeConfigHotReloadConcurrentAccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.AllowPrivateTargets = true
	gateway.resolver.allowPrivate = true
	cookie := loginAdmin(t, gateway)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				rec := httptest.NewRecorder()
				gateway.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://proxy.test/"+upstream.URL+"/ping", nil))
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				settings := validRuntimeSettings()
				settings.DefaultUpstream = upstream.URL
				settings.AllowUnsigned = (j+worker)%2 == 0
				settings.PassClientIP = j%2 == 0
				settings.DisableCache = j%2 == 1
				settings.DNSCacheTTLSeconds = int64(10 + j)
				settings.DialTimeoutSeconds = int64(5 + j)
				settings.MaxConcurrentRequests = 64 + j
				settings.MaxConcurrentPerIP = 32
				settings.MaxDownloadMbitPerIP = int64(j * 10)
				res := adminRequest(t, gateway, http.MethodPut, "/_admin/api/runtime-config", settings, cookie, true)
				if res.Code != http.StatusOK {
					t.Errorf("concurrent save failed: status=%d body=%s", res.Code, res.Body.String())
				}
			}
		}(i)
	}
	wg.Wait()
}
