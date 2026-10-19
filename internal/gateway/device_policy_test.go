package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRequestDeviceIdentityParsesMediaBrowserAuthorization(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://proxy.test/Items/1", nil)
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Jellyfin Web", Device="Living Room, TV", DeviceId="device-123", Version="10.9"`)
	identity := requestDeviceIdentity(request)
	if identity.ID != "device-123" || identity.DeviceName != "Living Room, TV" || identity.ClientName != "Jellyfin Web" {
		t.Fatalf("identity = %#v", identity)
	}

	request.Header.Del("X-Emby-Authorization")
	request.Header.Set("Authorization", `MediaBrowser Client="Emby Theater", DeviceId="auth-device"`)
	if got := requestDeviceIdentity(request).ID; got != "auth-device" {
		t.Fatalf("Authorization device id = %q", got)
	}

	request.Header.Del("Authorization")
	request.Header.Set("X-Emby-Device-Id", "direct-device")
	if got := requestDeviceIdentity(request).ID; got != "direct-device" {
		t.Fatalf("direct device id = %q", got)
	}
	request.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Infuse", Device="Living Room", DeviceId="auth-device"`)
	identity = requestDeviceIdentity(request)
	if identity.ID != "auth-device" || identity.ClientName != "Infuse" || identity.DeviceName != "Living Room" {
		t.Fatalf("combined identity = %#v", identity)
	}
	request.Header.Del("X-Emby-Authorization")
	request.Header.Set("X-Emby-Client", "Swiftfin")
	request.Header.Set("X-Emby-Device-Name", "iPhone")
	identity = requestDeviceIdentity(request)
	if identity.ID != "direct-device" || identity.ClientName != "Swiftfin" || identity.DeviceName != "iPhone" {
		t.Fatalf("fallback identity = %#v", identity)
	}
}

func TestPlayerPolicyModesAndMissingIdentity(t *testing.T) {
	policy := &playerPolicy{Mode: proxyModeOff}
	if !policy.AllowsClient("") {
		t.Fatal("off mode rejected a request without player identity")
	}
	policy.Mode = proxyModeBlacklist
	policy.Rules = []playerRule{{PlayerName: "Infuse", Enabled: true}}
	if policy.AllowsClient("infuse") || !policy.AllowsClient("Other Player") || !policy.AllowsClient("") {
		t.Fatal("blacklist did not block only the listed player name")
	}
	policy.Mode = proxyModeWhitelist
	if !policy.AllowsClient("infuse") || policy.AllowsClient("unknown") || policy.AllowsClient("") {
		t.Fatal("whitelist did not require a listed player name")
	}
}

func TestLegacyPlayerRulesDefaultToBlacklist(t *testing.T) {
	gateway := newAdminTestGateway(t)
	rule, err := normalizePlayerRule("Infuse", "已有禁用规则")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.telemetry.UpsertProxyPlayerRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}

	loaded, err := gateway.telemetry.LoadProxyPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PlayerPolicy.Mode != proxyModeBlacklist || loaded.PlayerPolicy.AllowsClient("Infuse") {
		t.Fatalf("legacy player rules were not preserved as a blacklist: %#v", loaded.PlayerPolicy)
	}
}

func TestPlayerPolicyAPIAndGatewayEnforcement(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.AllowPrivateTargets = true
	gateway.resolver.allowPrivate = true
	gateway.cfg.AllowUnsigned = true
	cookie := loginAdmin(t, gateway)

	mode := adminRequest(t, gateway, http.MethodPut, "/_admin/api/player-policy", map[string]string{"mode": proxyModeWhitelist}, cookie, true)
	if mode.Code != http.StatusOK || !strings.Contains(mode.Body.String(), `"mode":"whitelist"`) {
		t.Fatalf("enable player whitelist status=%d body=%s", mode.Code, mode.Body.String())
	}
	if gateway.policy.Load().Mode != proxyModeOff {
		t.Fatalf("player policy changed domain mode to %q", gateway.policy.Load().Mode)
	}

	requestURL := "https://proxy.test/" + upstream.URL + "/playback"
	missingID := httptest.NewRequest(http.MethodGet, requestURL, nil)
	missingResult := httptest.NewRecorder()
	gateway.ServeHTTP(missingResult, missingID)
	if missingResult.Code != http.StatusForbidden || upstreamRequests.Load() != 0 {
		t.Fatalf("missing player name status=%d upstream calls=%d body=%s", missingResult.Code, upstreamRequests.Load(), missingResult.Body.String())
	}

	created := adminRequest(t, gateway, http.MethodPost, "/_admin/api/player-rules", map[string]string{
		"player_name": "Infuse", "note": "允许的播放器",
	}, cookie, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"player_name":"Infuse"`) {
		t.Fatalf("create player rule status=%d body=%s", created.Code, created.Body.String())
	}
	if len(gateway.policy.Load().PlayerPolicy.Rules) != 1 {
		t.Fatalf("player rules = %#v", gateway.policy.Load().PlayerPolicy.Rules)
	}

	allowed := httptest.NewRequest(http.MethodGet, requestURL, nil)
	allowed.Header.Set("X-Emby-Authorization", `MediaBrowser Client="infuse", DeviceId="any-device"`)
	allowedResult := httptest.NewRecorder()
	gateway.ServeHTTP(allowedResult, allowed)
	if allowedResult.Code != http.StatusOK || upstreamRequests.Load() != 1 {
		t.Fatalf("listed player status=%d upstream calls=%d body=%s", allowedResult.Code, upstreamRequests.Load(), allowedResult.Body.String())
	}

	blocked := httptest.NewRequest(http.MethodGet, requestURL, nil)
	blocked.Header.Set("Authorization", `MediaBrowser Client="Unknown", DeviceId="any-device"`)
	blockedResult := httptest.NewRecorder()
	gateway.ServeHTTP(blockedResult, blocked)
	if blockedResult.Code != http.StatusForbidden || upstreamRequests.Load() != 1 {
		t.Fatalf("unlisted player status=%d upstream calls=%d", blockedResult.Code, upstreamRequests.Load())
	}

	loaded, err := gateway.telemetry.LoadProxyPolicy(context.Background())
	if err != nil || loaded.PlayerPolicy.Mode != proxyModeWhitelist || len(loaded.PlayerPolicy.Rules) != 1 {
		t.Fatalf("persisted device policy=%#v err=%v", loaded, err)
	}

	deleted := adminRequest(t, gateway, http.MethodDelete, "/_admin/api/player-rules/1", nil, cookie, true)
	if deleted.Code != http.StatusOK || len(gateway.policy.Load().PlayerPolicy.Rules) != 0 {
		t.Fatalf("delete player rule status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestCancelDisallowedPlayerConnections(t *testing.T) {
	tracker := newConnectionTracker()
	defer tracker.Close()
	canceled := map[string]*atomic.Int64{
		"allowed": new(atomic.Int64), "blocked": new(atomic.Int64), "unknown": new(atomic.Int64),
	}
	for _, player := range []string{"allowed", "blocked", "unknown"} {
		clientName := player
		tracker.StartForIdentity(func() { canceled[clientName].Add(1) }, "192.0.2.1", http.MethodGet,
			"media.example", "media.example", "/stream", "stream", "test", "same-device", clientName)
	}
	policy := &playerPolicy{Mode: proxyModeWhitelist, Rules: []playerRule{{PlayerName: "allowed", Enabled: true}}}
	if count := tracker.CancelDisallowedPlayers(policy); count != 2 {
		t.Fatalf("canceled count = %d, want 2", count)
	}
	if canceled["allowed"].Load() != 0 || canceled["blocked"].Load() != 1 || canceled["unknown"].Load() != 1 {
		t.Fatalf("cancellation counts: allowed=%d blocked=%d unknown=%d", canceled["allowed"].Load(), canceled["blocked"].Load(), canceled["unknown"].Load())
	}
}

func TestPlayerRuleAPIAndGatewayEnforcement(t *testing.T) {
	var upstreamRequests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.AllowPrivateTargets = true
	gateway.resolver.allowPrivate = true
	gateway.cfg.AllowUnsigned = true
	cookie := loginAdmin(t, gateway)

	mode := adminRequest(t, gateway, http.MethodPut, "/_admin/api/player-policy", map[string]string{"mode": proxyModeBlacklist}, cookie, true)
	if mode.Code != http.StatusOK {
		t.Fatalf("enable player blacklist status=%d body=%s", mode.Code, mode.Body.String())
	}

	created := adminRequest(t, gateway, http.MethodPost, "/_admin/api/player-rules", map[string]string{
		"player_name": "  Infuse  ", "note": "旧版客户端暂时停用",
	}, cookie, true)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"player_name":"Infuse"`) {
		t.Fatalf("create player rule status=%d body=%s", created.Code, created.Body.String())
	}
	if len(gateway.policy.Load().PlayerPolicy.Rules) != 1 {
		t.Fatalf("player rules = %#v", gateway.policy.Load().PlayerPolicy.Rules)
	}

	requestURL := "https://proxy.test/" + upstream.URL + "/playback"
	blocked := httptest.NewRequest(http.MethodGet, requestURL, nil)
	blocked.Header.Set("X-Emby-Authorization", `MediaBrowser Client="infuse", DeviceId="player-device"`)
	blockedResult := httptest.NewRecorder()
	gateway.ServeHTTP(blockedResult, blocked)
	if blockedResult.Code != http.StatusForbidden || upstreamRequests.Load() != 0 {
		t.Fatalf("blocked player status=%d upstream calls=%d body=%s", blockedResult.Code, upstreamRequests.Load(), blockedResult.Body.String())
	}

	allowed := httptest.NewRequest(http.MethodGet, requestURL, nil)
	allowed.Header.Set("X-Emby-Authorization", `MediaBrowser Client="Other Player", DeviceId="other-device"`)
	allowedResult := httptest.NewRecorder()
	gateway.ServeHTTP(allowedResult, allowed)
	if allowedResult.Code != http.StatusOK || upstreamRequests.Load() != 1 {
		t.Fatalf("allowed player status=%d upstream calls=%d body=%s", allowedResult.Code, upstreamRequests.Load(), allowedResult.Body.String())
	}

	deleted := adminRequest(t, gateway, http.MethodDelete, "/_admin/api/player-rules/1", nil, cookie, true)
	if deleted.Code != http.StatusOK || len(gateway.policy.Load().PlayerPolicy.Rules) != 0 {
		t.Fatalf("delete player rule status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}
