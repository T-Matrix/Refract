package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOrderAddressesByIPMode(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("2001:db8::2"),
		netip.MustParseAddr("203.0.113.11"),
	}

	v4First, err := orderAddressesByIPMode(addrs, upstreamIPIPv4First)
	if err != nil || len(v4First) != 4 || !v4First[0].Is4() || !v4First[1].Is4() || !v4First[2].Is6() {
		t.Fatalf("ipv4_first unexpected result: %v err=%v", v4First, err)
	}
	v4Only, err := orderAddressesByIPMode(addrs, upstreamIPIPv4Only)
	if err != nil || len(v4Only) != 2 || !v4Only[0].Is4() || !v4Only[1].Is4() {
		t.Fatalf("ipv4_only unexpected result: %v err=%v", v4Only, err)
	}
	v6First, err := orderAddressesByIPMode(addrs, upstreamIPIPv6First)
	if err != nil || len(v6First) != 4 || !v6First[0].Is6() || !v6First[1].Is6() || !v6First[2].Is4() {
		t.Fatalf("ipv6_first unexpected result: %v err=%v", v6First, err)
	}
	v6Only, err := orderAddressesByIPMode(addrs, upstreamIPIPv6Only)
	if err != nil || len(v6Only) != 2 || !v6Only[0].Is6() || !v6Only[1].Is6() {
		t.Fatalf("ipv6_only unexpected result: %v err=%v", v6Only, err)
	}

	onlyV4 := []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	if _, err := orderAddressesByIPMode(onlyV4, upstreamIPIPv6Only); err == nil {
		t.Fatal("expected ipv6_only to fail when only IPv4 addresses exist")
	}
}

func TestRuntimeUpstreamIPModeHotReload(t *testing.T) {
	controller, client := newTestClusterController(t, RoleController)
	defer controller.Close()

	// Valid hot reload to ipv4_first
	req := mustAdminJSONRequest(t, http.MethodPut, controller.URL+"/_admin/api/runtime-config", map[string]any{
		"allow_unsigned_targets":          true,
		"pass_client_ip":                  false,
		"disable_cache":                   true,
		"rewrite_max_bytes":               8 << 20,
		"dns_cache_ttl_seconds":           60,
		"dial_timeout_seconds":            15,
		"response_header_timeout_seconds": 60,
		"max_concurrent_requests":         256,
		"max_concurrent_per_ip":           64,
		"max_download_mbps_per_ip":        0,
		"upstream_ip_mode":                "ipv4_first",
	})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT runtime-config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	var view map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decode runtime-config: %v", err)
	}
	if view["upstream_ip_mode"] != "ipv4_first" {
		t.Fatalf("expected upstream_ip_mode=ipv4_first, got %v", view["upstream_ip_mode"])
	}

	// Invalid upstream_ip_mode rejected
	badReq := mustAdminJSONRequest(t, http.MethodPut, controller.URL+"/_admin/api/runtime-config", map[string]any{
		"rewrite_max_bytes":               8 << 20,
		"dns_cache_ttl_seconds":           60,
		"dial_timeout_seconds":            15,
		"response_header_timeout_seconds": 60,
		"max_concurrent_requests":         256,
		"max_concurrent_per_ip":           64,
		"upstream_ip_mode":                "bogus_mode",
	})
	badResp, err := client.Do(badReq)
	if err != nil {
		t.Fatalf("PUT bad runtime-config: %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid upstream_ip_mode, got %d", badResp.StatusCode)
	}
}

func TestClientAccessPolicyEvaluationAndSSESync(t *testing.T) {
	// Direct unit evaluation of IP/CIDR + country rules
	p, err := normalizeClientAccessPolicy(clientAccessPolicy{
		IPMode:          proxyModeBlacklist,
		IPRules:         []string{"203.0.113.0/24", "2001:db8::1"},
		GeoMode:         proxyModeWhitelist,
		Countries:       []string{"cn", "hk"},
		AllowUnknownGeo: false,
	})
	if err != nil {
		t.Fatalf("normalizeClientAccessPolicy: %v", err)
	}
	if p.AllowsIP("203.0.113.42") {
		t.Fatal("expected 203.0.113.42 to be blocked by CIDR blacklist")
	}
	if !p.AllowsIP("198.51.100.7") {
		t.Fatal("expected 198.51.100.7 to be allowed")
	}
	if p.AllowsIP("2001:db8::1") {
		t.Fatal("expected IPv6 2001:db8::1 to be blocked")
	}
	if !p.AllowsCountry("CN") || p.AllowsCountry("US") || p.AllowsCountry("") {
		t.Fatal("unexpected country whitelist behavior")
	}

	// End-to-end SSE push from Controller to Agent + enforcement on Agent proxy
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok-from-origin")
	}))
	defer upstream.Close()

	ctrl, adminClient := newTestClusterController(t, RoleController)
	defer ctrl.Close()

	enrollToken, _ := createTestEdgeNode(t, adminClient, ctrl.URL, "Access Node", "https://edge-access.example.com")

	agentCfg := testConfig()
	agentCfg.Role = RoleAgent
	agentCfg.AdminEnabled = false
	agentCfg.AllowPrivateTargets = true
	agentCfg.TrustProxyHeaders = true
	agentCfg.AgentControllerURL = ctrl.URL
	agentCfg.AgentEnrollToken = enrollToken
	agentCfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-state.json")
	agentCfg.AgentHeartbeatInterval = time.Second
	agentCfg.AgentTelemetryInterval = time.Second
	agentGW := New(agentCfg)
	agentGW.agent.skipIPDetect.Store(true)
	defer agentGW.Close()

	agentSrv := httptest.NewServer(agentGW)
	defer agentSrv.Close()

	// Allow unsigned targets on controller
	allowReq := mustAdminJSONRequest(t, http.MethodPut, ctrl.URL+"/_admin/api/runtime-config", map[string]any{
		"allow_unsigned_targets":          true,
		"rewrite_max_bytes":               8 << 20,
		"dns_cache_ttl_seconds":           60,
		"dial_timeout_seconds":            15,
		"response_header_timeout_seconds": 60,
		"max_concurrent_requests":         256,
		"max_concurrent_per_ip":           64,
		"upstream_ip_mode":                "auto",
	})
	resp, err := adminClient.Do(allowReq)
	if err != nil {
		t.Fatalf("enable unsigned: %v", err)
	}
	resp.Body.Close()

	// Push IP blacklist + Geo whitelist via Admin API
	caReq := mustAdminJSONRequest(t, http.MethodPut, ctrl.URL+"/_admin/api/client-access-policy", map[string]any{
		"ip_mode":           "blacklist",
		"ip_rules":          []string{"198.51.100.0/24"},
		"geo_mode":          "whitelist",
		"countries":         []string{"CN", "HK"},
		"allow_unknown_geo": false,
	})
	caResp, err := adminClient.Do(caReq)
	if err != nil {
		t.Fatalf("PUT client-access-policy: %v", err)
	}
	caResp.Body.Close()
	if caResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 saving client access policy, got %d", caResp.StatusCode)
	}

	// Wait for SSE push to arrive on agent
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pol := agentGW.policy.Load()
		if pol != nil && pol.ClientAccess.IPMode == proxyModeBlacklist && pol.ClientAccess.GeoMode == proxyModeWhitelist {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	targetPath := "/" + upstream.URL + "/hello"
	doProxy := func(ip, country string) int {
		r, _ := http.NewRequest(http.MethodGet, agentSrv.URL+targetPath, nil)
		r.Header.Set("CF-Connecting-IP", ip)
		if country != "" {
			r.Header.Set("CF-IPCountry", country)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatalf("proxy request failed: %v", err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}

	if code := doProxy("198.51.100.99", "CN"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for blacklisted IP, got %d", code)
	}
	if code := doProxy("203.0.113.5", "US"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-whitelisted country US, got %d", code)
	}
	if code := doProxy("203.0.113.5", "CN"); code != http.StatusOK {
		t.Fatalf("expected 200 for allowed IP + CN, got %d", code)
	}
}

func TestBillingCycleWindowAndMonthlyQuotaAutoDrain(t *testing.T) {
	// Verify cycle boundary math in Asia/Shanghai
	t1 := time.Date(2026, 5, 14, 10, 0, 0, 0, applicationLocation)
	key1, _, _ := billingCycleWindow(t1, 15)
	if key1 != "2026-04-15" {
		t.Fatalf("expected 2026-04-15 before reset day, got %s", key1)
	}
	t2 := time.Date(2026, 5, 15, 0, 1, 0, 0, applicationLocation)
	key2, _, _ := billingCycleWindow(t2, 15)
	if key2 != "2026-05-15" {
		t.Fatalf("expected 2026-05-15 on reset day, got %s", key2)
	}

	// Capture Telegram alerts
	var mu sync.Mutex
	var tgMessages []string
	tgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		tgMessages = append(tgMessages, r.FormValue("text"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tgServer.Close()

	gw := newControllerTestGateway(t)
	gw.telegram.apiBase = tgServer.URL

	// Seed Telegram bot token & chat id
	encTok, err := gw.telegram.cipher.Encrypt("123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
	if err != nil {
		t.Fatalf("encrypt telegram token: %v", err)
	}
	if err := gw.telemetry.SaveTelegram(context.Background(), telegramConfig{Enabled: false, ChatID: "-100999", SendHour: 9}, encTok); err != nil {
		t.Fatalf("save telegram: %v", err)
	}

	// Create and enroll a node with 1 GB monthly quota
	node, enrollTok, err := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name:           "JP Quota Node",
		PublicURL:      "https://jp.example.com",
		PublicVisible:  true,
		MonthlyQuotaGB: 1,
		QuotaResetDay:  1,
		QuotaDirection: "out",
		QuotaAutoDrain: true,
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}
	node, _, err = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrollTok, "1.0.0", "linux/amd64", "jp-host")
	if err != nil {
		t.Fatalf("CompleteEdgeNodeEnrollment: %v", err)
	}

	now := time.Date(2026, 6, 10, 12, 0, 0, 0, applicationLocation)
	// Keep node online
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), node.ID, 1, "abc", "1.0.0", "linux/amd64", "jp-host", "203.0.113.10", "", "sha1", now.Unix())

	// Insert 850 MiB (~83%) traffic into node_traffic_minutes
	minute := (now.Unix() / 60) * 60
	_, err = gw.telemetry.db.Exec(`INSERT INTO node_traffic_minutes(minute,node_id,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?,?)`,
		minute, node.ID, "emby.origin", 10, 0, 850<<20, 0, 100)
	if err != nil {
		t.Fatalf("seed traffic 85%%: %v", err)
	}

	gw.cluster.EvaluateMonitorCycle(context.Background(), now)
	// Second run should NOT duplicate 80% alert
	gw.cluster.EvaluateMonitorCycle(context.Background(), now)

	updated, _ := gw.telemetry.GetEdgeNode(context.Background(), node.ID)
	if updated.Draining || updated.QuotaAlertLevel != 80 {
		t.Fatalf("at 83%% expected draining=false alertLevel=80, got draining=%v level=%d", updated.Draining, updated.QuotaAlertLevel)
	}

	// Push traffic past 100% (+250 MiB = 1100 MiB > 1024 MiB)
	_, err = gw.telemetry.db.Exec(`UPDATE node_traffic_minutes SET bytes_out = bytes_out + ? WHERE node_id=?`, 250<<20, node.ID)
	if err != nil {
		t.Fatalf("seed traffic 105%%: %v", err)
	}
	gw.cluster.EvaluateMonitorCycle(context.Background(), now)

	updated, _ = gw.telemetry.GetEdgeNode(context.Background(), node.ID)
	if !updated.Draining || !updated.QuotaAutoDrained || updated.QuotaAlertLevel != 100 {
		t.Fatalf("at 105%% expected auto-drained, got draining=%v autoDrained=%v level=%d", updated.Draining, updated.QuotaAutoDrained, updated.QuotaAlertLevel)
	}

	// Next billing cycle (July 1st) -> auto un-drain!
	nextMonth := time.Date(2026, 7, 1, 0, 5, 0, 0, applicationLocation)
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), node.ID, 1, "abc", "1.0.0", "linux/amd64", "jp-host", "203.0.113.10", "", "sha1", nextMonth.Unix())
	gw.cluster.EvaluateMonitorCycle(context.Background(), nextMonth)

	updated, _ = gw.telemetry.GetEdgeNode(context.Background(), node.ID)
	if updated.Draining || updated.QuotaAutoDrained || updated.QuotaAlertLevel != 0 || updated.QuotaCycleKey != "2026-07-01" {
		t.Fatalf("expected next cycle auto-undrain, got draining=%v autoDrained=%v level=%d cycle=%s",
			updated.Draining, updated.QuotaAutoDrained, updated.QuotaAlertLevel, updated.QuotaCycleKey)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(tgMessages) != 3 {
		t.Fatalf("expected 3 Telegram quota messages (80%%, 100%%, cycle reset), got %d: %v", len(tgMessages), tgMessages)
	}
	if !strings.Contains(tgMessages[0], "80%") || !strings.Contains(tgMessages[1], "100%") || !strings.Contains(tgMessages[2], "重置") {
		t.Fatalf("unexpected Telegram quota message contents: %v", tgMessages)
	}
}

func TestClusterRealtimeOfflineAndTLSAlerts(t *testing.T) {
	var mu sync.Mutex
	var tgMessages []string
	tgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		tgMessages = append(tgMessages, r.FormValue("text"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tgServer.Close()

	gw := newControllerTestGateway(t)
	gw.telegram.apiBase = tgServer.URL

	encTok, _ := gw.telegram.cipher.Encrypt("123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
	_ = gw.telemetry.SaveTelegram(context.Background(), telegramConfig{Enabled: false, ChatID: "-100888", SendHour: 9}, encTok)

	node, enrollTok, _ := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name: "DE Alert Node", PublicURL: "https://de.example.com", PublicVisible: true,
	})
	node, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrollTok, "1.0.0", "linux/amd64", "de-host")

	now := time.Now()
	// Backdate last_seen_at to 2 minutes ago (exceeds 60s threshold)
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), node.ID, 1, "abc", "1.0.0", "linux/amd64", "de-host", "", "", "", now.Add(-2*time.Minute).Unix())

	gw.cluster.EvaluateMonitorCycle(context.Background(), now)
	gw.cluster.EvaluateMonitorCycle(context.Background(), now) // debounced

	// Bring node back online with a TLS error
	gw.cluster.mu.Lock()
	gw.cluster.live[node.ID] = &edgeNodeLiveState{
		lastSeen: now,
		metrics: edgeNodeMetrics{
			agentTLSStatus: agentTLSStatus{
				Mode:   "auto",
				Domain: "de.example.com",
				Status: "error",
				Error:  "acme: authorization failed",
			},
		},
	}
	gw.cluster.mu.Unlock()

	gw.cluster.EvaluateMonitorCycle(context.Background(), now)
	gw.cluster.EvaluateMonitorCycle(context.Background(), now) // TLS alert 24h cooldown

	mu.Lock()
	defer mu.Unlock()
	if len(tgMessages) != 3 {
		t.Fatalf("expected 3 Telegram alerts (offline, recovery, tls error), got %d: %v", len(tgMessages), tgMessages)
	}
	if !strings.Contains(tgMessages[0], "已离线") || !strings.Contains(tgMessages[1], "已恢复在线") || !strings.Contains(tgMessages[2], "证书签发异常") {
		t.Fatalf("unexpected alert sequence: %v", tgMessages)
	}
}

func TestAgentRemoteSelfUpgrade(t *testing.T) {
	binDir := t.TempDir()
	newBinaryBytes := []byte("#!/bin/sh\necho refract-new-version-2026\n")
	newSum := sha256.Sum256(newBinaryBytes)
	newSHA := hex.EncodeToString(newSum[:])
	binName := "refract-" + runtime.GOOS + "-" + runtime.GOARCH
	if err := os.WriteFile(filepath.Join(binDir, binName), newBinaryBytes, 0o755); err != nil {
		t.Fatalf("write controller binary: %v", err)
	}

	ctrlGW := newControllerTestGateway(t)
	ctrlGW.cfg.AgentBinaryDir = binDir
	ctrlSrv := httptest.NewServer(ctrlGW)
	defer ctrlSrv.Close()
	adminClient := loginTestAdmin(t, ctrlSrv.URL)

	enrollToken, nodeID := createTestEdgeNode(t, adminClient, ctrlSrv.URL, "Upgrade Node", "https://up.example.com")

	// Prepare old mock executable for the agent
	agentDir := t.TempDir()
	mockExePath := filepath.Join(agentDir, "refract-agent-mock")
	oldBytes := []byte("old-binary-content")
	if err := os.WriteFile(mockExePath, oldBytes, 0o755); err != nil {
		t.Fatalf("write old mock binary: %v", err)
	}
	oldSum := sha256.Sum256(oldBytes)
	oldSHA := hex.EncodeToString(oldSum[:])

	agentCfg := testConfig()
	agentCfg.Role = RoleAgent
	agentCfg.AdminEnabled = false
	agentCfg.AgentControllerURL = ctrlSrv.URL
	agentCfg.AgentEnrollToken = enrollToken
	agentCfg.AgentStatePath = filepath.Join(agentDir, "state.json")
	agentCfg.AgentHeartbeatInterval = 500 * time.Millisecond
	agentCfg.AgentTelemetryInterval = time.Second
	agentGW := New(agentCfg)
	defer agentGW.Close()

	restarted := make(chan struct{}, 2)
	agentGW.agent.skipIPDetect.Store(true)
	agentGW.agent.mu.Lock()
	agentGW.agent.upgradeExePath = mockExePath
	agentGW.agent.binarySHA256 = oldSHA
	agentGW.agent.onUpgradeRestart = func() {
		select {
		case restarted <- struct{}{}:
		default:
		}
	}
	agentGW.agent.mu.Unlock()

	// Wait until agent SSE is connected to controller
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ctrlGW.cluster.isNodeConnected(nodeID) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ctrlGW.cluster.isNodeConnected(nodeID) {
		t.Fatal("agent failed to connect SSE before upgrade test")
	}

	// Trigger single-node upgrade via Admin API
	upReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes/"+nodeID+"/upgrade", map[string]any{})
	upResp, err := adminClient.Do(upReq)
	if err != nil {
		t.Fatalf("POST upgrade: %v", err)
	}
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on upgrade trigger, got %d", upResp.StatusCode)
	}

	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agent self-upgrade restart hook")
	}

	gotBytes, err := os.ReadFile(mockExePath)
	if err != nil || !bytes.Equal(gotBytes, newBinaryBytes) {
		t.Fatalf("upgraded binary content mismatch: got=%q err=%v", string(gotBytes), err)
	}
	bakBytes, err := os.ReadFile(mockExePath + ".bak")
	if err != nil || !bytes.Equal(bakBytes, oldBytes) {
		t.Fatalf("expected .bak backup of old binary, got=%q err=%v", string(bakBytes), err)
	}

	// Triggering upgrade again when SHA already matches should be a no-op (no restart)
	agentGW.agent.mu.RLock()
	curSHA := agentGW.agent.binarySHA256
	agentGW.agent.mu.RUnlock()
	if curSHA != newSHA {
		t.Fatalf("expected agent binarySHA256=%s, got %s", newSHA, curSHA)
	}
	if err := agentGW.agent.performSelfUpgrade(context.Background()); err != nil {
		t.Fatalf("second performSelfUpgrade failed: %v", err)
	}
	select {
	case <-restarted:
		t.Fatal("expected no restart when binary SHA-256 already matches controller")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestCloudflareDNSSyncAndFailover(t *testing.T) {
	// Stateful mock Cloudflare API v4
	var cfMu sync.Mutex
	records := make(map[string]cfDNSRecord)
	nextRecID := 1
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-secret-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			_, _ = io.WriteString(w, `{"success":true,"result":[{"id":"zone_abc123","name":"emby.test","status":"active"}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone_abc123":
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"zone_abc123","name":"emby.test","status":"active"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone_abc123/dns_records":
			wantType := r.URL.Query().Get("type")
			wantName := r.URL.Query().Get("name")
			cfMu.Lock()
			matched := make([]cfDNSRecord, 0)
			for _, rec := range records {
				if (wantType == "" || rec.Type == wantType) && (wantName == "" || rec.Name == wantName) {
					matched = append(matched, rec)
				}
			}
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": matched})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone_abc123/dns_records":
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			cfMu.Lock()
			rec.ID = "rec_" + string(rune('a'+nextRecID))
			nextRecID++
			records[rec.ID] = rec
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/zones/zone_abc123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone_abc123/dns_records/")
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = id
			cfMu.Lock()
			records[id] = rec
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/zone_abc123/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/zone_abc123/dns_records/")
			cfMu.Lock()
			delete(records, id)
			cfMu.Unlock()
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"`+id+`"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfServer.Close()

	// Mock Telegram for failover alert
	var tgMu sync.Mutex
	var tgAlerts []string
	tgServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		tgMu.Lock()
		tgAlerts = append(tgAlerts, r.FormValue("text"))
		tgMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer tgServer.Close()

	gw := newControllerTestGateway(t)
	gw.cloudflare.apiBase = cfServer.URL
	gw.telegram.apiBase = tgServer.URL

	encTg, _ := gw.telegram.cipher.Encrypt("123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
	_ = gw.telemetry.SaveTelegram(context.Background(), telegramConfig{Enabled: false, ChatID: "-100777", SendHour: 9}, encTg)

	srv := httptest.NewServer(gw)
	defer srv.Close()
	adminClient := loginTestAdmin(t, srv.URL)

	// 1. Test Cloudflare connection & auto-resolve zone ID
	testReq := mustAdminJSONRequest(t, http.MethodPost, srv.URL+"/_admin/api/cloudflare-dns/test", map[string]any{
		"api_token":   "cf-secret-token-123",
		"root_domain": "emby.test",
	})
	testResp, err := adminClient.Do(testReq)
	if err != nil {
		t.Fatalf("POST cloudflare-dns/test: %v", err)
	}
	var testOut map[string]any
	_ = json.NewDecoder(testResp.Body).Decode(&testOut)
	testResp.Body.Close()
	if testResp.StatusCode != http.StatusOK || testOut["zone_id"] != "zone_abc123" {
		t.Fatalf("expected zone_abc123 from test endpoint, got status=%d body=%v", testResp.StatusCode, testOut)
	}

	// 2. Create two nodes and mark both online
	nodeA, enrA, err := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name: "DE Primary", PublicURL: "https://de.emby.test", PublicVisible: true,
		ManualIPv4: "203.0.113.10", DNSSyncEnabled: true, DNSIPMode: "ipv4",
	})
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrA, "1.0.0", "linux/amd64", "de")
	nodeB, enrB, err := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name: "JP Backup", PublicURL: "https://jp.emby.test", PublicVisible: true,
		ManualIPv4: "203.0.113.20", DNSSyncEnabled: true, DNSIPMode: "ipv4",
	})
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	nodeB, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrB, "1.0.0", "linux/amd64", "jp")

	now := time.Now()
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), nodeA.ID, 1, "a", "1.0.0", "linux/amd64", "de", "", "", "", now.Unix())
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), nodeB.ID, 1, "b", "1.0.0", "linux/amd64", "jp", "", "", "", now.Unix())

	// 3. Save Cloudflare DNS settings with a failover group [nodeA, nodeB]
	saveReq := mustAdminJSONRequest(t, http.MethodPut, srv.URL+"/_admin/api/cloudflare-dns", map[string]any{
		"enabled":     true,
		"api_token":   "cf-secret-token-123",
		"root_domain": "emby.test",
		"zone_id":     "zone_abc123",
		"ttl":         60,
		"proxied":     false,
		"failover_groups": []map[string]any{
			{
				"name":     "主播放入口",
				"hostname": "play.emby.test",
				"node_ids": []string{nodeA.ID, nodeB.ID},
				"ip_mode":  "ipv4",
			},
		},
	})
	saveResp, err := adminClient.Do(saveReq)
	if err != nil {
		t.Fatalf("PUT cloudflare-dns: %v", err)
	}
	saveResp.Body.Close()
	if saveResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 saving CF DNS, got %d", saveResp.StatusCode)
	}

	// 4. Sync all -> verify de.emby.test, jp.emby.test, and play.emby.test -> nodeA (203.0.113.10)
	syncedNodes, syncedGroups, err := gw.cloudflare.SyncAll(context.Background())
	if err != nil || syncedNodes != 2 || syncedGroups != 1 {
		t.Fatalf("SyncAll unexpected result: nodes=%d groups=%d err=%v", syncedNodes, syncedGroups, err)
	}

	findRecord := func(name string) (cfDNSRecord, bool) {
		cfMu.Lock()
		defer cfMu.Unlock()
		for _, rec := range records {
			if rec.Name == name && rec.Type == "A" {
				return rec, true
			}
		}
		return cfDNSRecord{}, false
	}
	if rec, ok := findRecord("de.emby.test"); !ok || rec.Content != "203.0.113.10" {
		t.Fatalf("expected de.emby.test -> 203.0.113.10, got %v %v", rec, ok)
	}
	if rec, ok := findRecord("play.emby.test"); !ok || rec.Content != "203.0.113.10" {
		t.Fatalf("expected play.emby.test -> 203.0.113.10 initially, got %v %v", rec, ok)
	}

	// 5. Rename nodeA domain from de.emby.test -> de2.emby.test and verify old record deleted
	nodeA.PublicURL = "https://de2.emby.test"
	if err := gw.cloudflare.SyncNodeDNS(context.Background(), nodeA, "https://de.emby.test"); err != nil {
		t.Fatalf("SyncNodeDNS rename: %v", err)
	}
	if _, ok := findRecord("de.emby.test"); ok {
		t.Fatal("expected stale de.emby.test record to be deleted on domain rename")
	}
	if rec, ok := findRecord("de2.emby.test"); !ok || rec.Content != "203.0.113.10" {
		t.Fatalf("expected de2.emby.test -> 203.0.113.10, got %v %v", rec, ok)
	}

	// 6. Put nodeA into draining -> failover must automatically switch play.emby.test to nodeB (203.0.113.20) + alert Telegram!
	_, err = gw.telemetry.UpdateEdgeNode(context.Background(), nodeA.ID, edgeNodeUpdateInput{
		Name: nodeA.Name, PublicURL: nodeA.PublicURL, PublicVisible: true, Draining: true,
		ManualIPv4: "203.0.113.10", DNSSyncEnabled: true, DNSIPMode: "ipv4",
	})
	if err != nil {
		t.Fatalf("drain nodeA: %v", err)
	}
	if _, err := gw.cloudflare.EvaluateFailoverGroups(context.Background(), time.Now()); err != nil {
		t.Fatalf("EvaluateFailoverGroups after drain: %v", err)
	}
	if rec, ok := findRecord("play.emby.test"); !ok || rec.Content != "203.0.113.20" {
		t.Fatalf("expected play.emby.test to failover to 203.0.113.20, got %v %v", rec, ok)
	}

	tgMu.Lock()
	defer tgMu.Unlock()
	if len(tgAlerts) != 1 || !strings.Contains(tgAlerts[0], "故障自动切线") || !strings.Contains(tgAlerts[0], "JP Backup") {
		t.Fatalf("expected Telegram failover alert mentioning JP Backup, got %v", tgAlerts)
	}
}

/* -------------------- Small Test Helpers -------------------- */

func newTestClusterController(t *testing.T, role string) (*httptest.Server, *http.Client) {
	t.Helper()
	gw := newControllerTestGateway(t)
	srv := httptest.NewServer(gw)
	t.Cleanup(srv.Close)
	return srv, loginTestAdmin(t, srv.URL)
}

func loginTestAdmin(t *testing.T, baseURL string) *http.Client {
	t.Helper()
	jar := newTestCookieJar()
	client := &http.Client{Jar: jar}
	req := mustAdminJSONRequest(t, http.MethodPost, baseURL+"/_admin/api/login", map[string]any{
		"username": "admin",
		"password": "correct horse battery staple",
	})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status=%d", resp.StatusCode)
	}
	return client
}

func createTestEdgeNode(t *testing.T, adminClient *http.Client, baseURL, name, publicURL string) (enrollToken, nodeID string) {
	t.Helper()
	req := mustAdminJSONRequest(t, http.MethodPost, baseURL+"/_admin/api/nodes", map[string]any{
		"name":           name,
		"public_url":     publicURL,
		"public_visible": true,
	})
	resp, err := adminClient.Do(req)
	if err != nil {
		t.Fatalf("create edge node: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create edge node status=%d body=%s", resp.StatusCode, body)
	}
	var out struct {
		Node   edgeNodeRecord      `json:"node"`
		Deploy agentDeployCommands `json:"deploy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode create edge node: %v", err)
	}
	return out.Deploy.EnrollToken, out.Node.ID
}

func mustAdminJSONRequest(t *testing.T, method, rawURL string, body any) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	parsed, _ := url.Parse(rawURL)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	return req
}

type simpleCookieJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func newTestCookieJar() http.CookieJar { return &simpleCookieJar{} }

func (j *simpleCookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = append(j.cookies, cookies...)
}

func (j *simpleCookieJar) Cookies(_ *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]*http.Cookie(nil), j.cookies...)
}
