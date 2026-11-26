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

func TestWAFRuleDAGValidationAndEvaluation(t *testing.T) {
	// 1. Cycle rejection
	_, _, err := normalizeAndCompileWAFRule(wafRuleRecord{
		Name: "循环测试", Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "m1", Type: wafNodeIPMatch, Config: wafNodeConfig{IPs: []string{"1.2.3.4"}}},
				{ID: "p", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "m1"},
				{ID: "e2", Source: "m1", SourcePort: "true", Target: "p"},
				{ID: "e3", Source: "m1", SourcePort: "false", Target: "m1"},
			},
		},
	})
	if err == nil {
		t.Fatalf("expected cycle / self-loop error, got nil")
	}

	// 2. Dangling outlet rejection
	_, _, err = normalizeAndCompileWAFRule(wafRuleRecord{
		Name: "缺口测试", Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "m1", Type: wafNodeGeoMatch, Config: wafNodeConfig{Countries: []string{"CN"}}},
				{ID: "p", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "m1"},
				{ID: "e2", Source: "m1", SourcePort: "true", Target: "p"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "未命中") {
		t.Fatalf("expected dangling false branch error, got %v", err)
	}

	// 3. Valid multi-branch DAG:
	// Start -> IP whitelist (10.0.0.0/8 -> Pass) -> Path scan (.env -> Block 451) -> Geo (CN/HK -> Pass, else Block 403)
	_, compiled, err := normalizeAndCompileWAFRule(wafRuleRecord{
		ID: "waf_1", Name: "复合防护", Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "ip", Type: wafNodeIPMatch, Config: wafNodeConfig{IPs: []string{"10.0.0.0/8"}}},
				{ID: "path", Type: wafNodePathMatch, Config: wafNodeConfig{MatchMode: "contains", Patterns: []string{".env", "wp-admin"}}},
				{ID: "geo", Type: wafNodeGeoMatch, Config: wafNodeConfig{Countries: []string{"CN", "HK"}}},
				{ID: "pass", Type: wafNodePass},
				{ID: "blk_scan", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 451, Message: "scanner blocked"}},
				{ID: "blk_geo", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "geo blocked"}},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "ip"},
				{ID: "e2", Source: "ip", SourcePort: "true", Target: "pass"},
				{ID: "e3", Source: "ip", SourcePort: "false", Target: "path"},
				{ID: "e4", Source: "path", SourcePort: "true", Target: "blk_scan"},
				{ID: "e5", Source: "path", SourcePort: "false", Target: "geo"},
				{ID: "e6", Source: "geo", SourcePort: "true", Target: "pass"},
				{ID: "e7", Source: "geo", SourcePort: "false", Target: "blk_geo"},
			},
		},
	})
	if err != nil {
		t.Fatalf("valid DAG failed to compile: %v", err)
	}

	// Trusted IP bypasses even .env & US
	dec1 := compiled.Evaluate(wafEvalContext{ClientIP: "10.1.2.3", CountryCode: "US", Path: "/.env"}, true)
	if dec1.Blocked || len(dec1.TraceNodes) != 3 {
		t.Fatalf("trusted IP should pass directly via ip->pass, got %+v", dec1)
	}

	// Non-trusted IP hitting /.env -> blocked 451
	dec2 := compiled.Evaluate(wafEvalContext{ClientIP: "8.8.8.8", CountryCode: "CN", Path: "/.env"}, true)
	if !dec2.Blocked || dec2.StatusCode != 451 {
		t.Fatalf("expected scanner block 451, got %+v", dec2)
	}

	// Non-trusted CN normal path -> pass
	dec3 := compiled.Evaluate(wafEvalContext{ClientIP: "8.8.8.8", CountryCode: "CN", Path: "/emby/System/Info"}, true)
	if dec3.Blocked {
		t.Fatalf("expected CN normal path pass, got %+v", dec3)
	}

	// Non-trusted US normal path -> blocked 403
	dec4 := compiled.Evaluate(wafEvalContext{ClientIP: "8.8.8.8", CountryCode: "US", Path: "/emby/System/Info"}, true)
	if !dec4.Blocked || dec4.StatusCode != 403 || dec4.Message != "geo blocked" {
		t.Fatalf("expected US geo block 403, got %+v", dec4)
	}

	// 4. Generic reverse-proxy target host match (exact + subdomain + port stripping)
	_, hostCompiled, err := normalizeAndCompileWAFRule(wafRuleRecord{
		ID: "waf_host", Name: "通用反代上游白名单", Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "h", Type: wafNodeHostMatch, Config: wafNodeConfig{Hosts: []string{"*.emby.example.com", "https://media.test.org:8096/"}}},
				{ID: "p", Type: wafNodePass},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "upstream host denied"}},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "h"},
				{ID: "e2", Source: "h", SourcePort: "true", Target: "p"},
				{ID: "e3", Source: "h", SourcePort: "false", Target: "b"},
			},
		},
	})
	if err != nil {
		t.Fatalf("host_match DAG failed to compile: %v", err)
	}
	if d := hostCompiled.Evaluate(wafEvalContext{TargetHost: "emby.example.com"}, false); d.Blocked {
		t.Fatalf("expected exact host match to pass, got %+v", d)
	}
	if d := hostCompiled.Evaluate(wafEvalContext{TargetHost: "cdn.emby.example.com:443"}, false); d.Blocked {
		t.Fatalf("expected subdomain host match to pass, got %+v", d)
	}
	if d := hostCompiled.Evaluate(wafEvalContext{TargetHost: "media.test.org"}, false); d.Blocked {
		t.Fatalf("expected normalized URL host to pass, got %+v", d)
	}
	if d := hostCompiled.Evaluate(wafEvalContext{TargetHost: "evil-emby.example.com"}, false); !d.Blocked || d.StatusCode != 403 {
		t.Fatalf("expected non-matching sibling host to be blocked 403, got %+v", d)
	}
}

func TestWAFRuleDomainBindingAndAgentEnforcement(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("UPSTREAM_OK"))
	}))
	defer upstream.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Allow unsigned dynamic/default proxy targets
	rtReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/runtime-config", map[string]any{
		"default_upstream":                upstream.URL,
		"allowed_upstreams":               "",
		"allow_unsigned_targets":          true,
		"pass_client_ip":                  false,
		"disable_cache":                   true,
		"rewrite_max_bytes":               4 * 1024 * 1024,
		"dns_cache_ttl_seconds":           30,
		"dial_timeout_seconds":            10,
		"response_header_timeout_seconds": 30,
		"max_concurrent_requests":         128,
		"max_concurrent_per_ip":           32,
		"max_download_mbps_per_ip":        0,
		"upstream_ip_mode":                "auto",
	})
	rtResp, err := adminClient.Do(rtReq)
	if err != nil || rtResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT runtime-config failed: %v", err)
	}
	rtResp.Body.Close()

	// Create & enroll 1 Agent
	nReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
		"name": "WAF Edge", "group_name": "测试", "region": "JP",
	})
	nResp, err := adminClient.Do(nReq)
	if err != nil || nResp.StatusCode != http.StatusCreated {
		t.Fatalf("create node failed: %v", err)
	}
	var nodeOut struct {
		Node   edgeNodeView `json:"node"`
		Deploy struct {
			EnrollToken string `json:"enroll_token"`
		} `json:"deploy"`
	}
	_ = json.NewDecoder(nResp.Body).Decode(&nodeOut)
	nResp.Body.Close()

	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = nodeOut.Deploy.EnrollToken
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "waf-agent.json")
	cfg.AgentHeartbeatInterval = 500 * time.Millisecond
	cfg.AgentTelemetryInterval = time.Second
	agent := New(cfg)
	agent.agent.skipIPDetect.Store(true)
	t.Cleanup(agent.Close)

	// Create domain-scoped WAF rule: block requests matching path "/secret" with 403
	wafReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/waf-rules", map[string]any{
		"name":        "屏蔽敏感路径",
		"description": "拦截 /secret",
		"enabled":     true,
		"is_global":   false,
		"graph": wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "n_start", Type: wafNodeStart, Label: "请求入口"},
				{ID: "n_path", Type: wafNodePathMatch, Label: "敏感路径", Config: wafNodeConfig{MatchMode: "prefix", Patterns: []string{"/secret"}}},
				{ID: "n_block", Type: wafNodeBlock, Label: "拦截", Config: wafNodeConfig{StatusCode: 403, Message: "secret path denied"}},
				{ID: "n_pass", Type: wafNodePass, Label: "放行"},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "n_start", SourcePort: "next", Target: "n_path"},
				{ID: "e2", Source: "n_path", SourcePort: "true", Target: "n_block"},
				{ID: "e3", Source: "n_path", SourcePort: "false", Target: "n_pass"},
			},
		},
	})
	wafResp, err := adminClient.Do(wafReq)
	if err != nil || wafResp.StatusCode != http.StatusCreated {
		t.Fatalf("create WAF rule failed: err=%v status=%v", err, wafResp)
	}
	var createdWAF wafRuleView
	_ = json.NewDecoder(wafResp.Body).Decode(&createdWAF)
	wafResp.Body.Close()

	// Create 2 domains on the SAME agent:
	//   protected.emby.test -> binds createdWAF
	//   open.emby.test      -> NO WAF bound
	for _, item := range []struct {
		host   string
		wafIDs []string
	}{
		{"protected.emby.test", []string{createdWAF.ID}},
		{"open.emby.test", []string{}},
	} {
		dReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
			"domain":       item.host,
			"name":         item.host,
			"enabled":      true,
			"node_ids":     []string{nodeOut.Node.ID},
			"dns_mode":     "manual",
			"tls_mode":     "external",
			"waf_rule_ids": item.wafIDs,
		})
		dResp, err := adminClient.Do(dReq)
		if err != nil || dResp.StatusCode != http.StatusCreated {
			t.Fatalf("create domain %s failed: err=%v status=%v", item.host, err, dResp)
		}
		dResp.Body.Close()
	}

	// Sync agent config
	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("agent syncConfig: %v", err)
	}

	// 1. protected.emby.test/secret -> BLOCKED 403 by domain-bound WAF!
	recBlocked := httptest.NewRecorder()
	reqBlocked := httptest.NewRequest(http.MethodGet, "https://protected.emby.test/secret/key", nil)
	reqBlocked.RemoteAddr = "203.0.113.10:12345"
	agent.ServeHTTP(recBlocked, reqBlocked)
	if recBlocked.Code != http.StatusForbidden || !strings.Contains(recBlocked.Body.String(), "secret path denied") {
		t.Fatalf("expected 403 secret path denied on protected domain, got %d body=%s", recBlocked.Code, recBlocked.Body.String())
	}

	// 2. protected.emby.test/ok -> ALLOWED 200!
	recAllowed := httptest.NewRecorder()
	reqAllowed := httptest.NewRequest(http.MethodGet, "https://protected.emby.test/ok", nil)
	reqAllowed.RemoteAddr = "203.0.113.10:12345"
	agent.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 on protected domain /ok, got %d body=%s", recAllowed.Code, recAllowed.Body.String())
	}

	// 3. open.emby.test/secret -> ALLOWED 200 (rule NOT bound to open.emby.test!)
	recOpen := httptest.NewRecorder()
	reqOpen := httptest.NewRequest(http.MethodGet, "https://open.emby.test/secret/key", nil)
	reqOpen.RemoteAddr = "203.0.113.10:12345"
	agent.ServeHTTP(recOpen, reqOpen)
	if recOpen.Code != http.StatusOK {
		t.Fatalf("expected 200 on unbound open domain /secret, got %d body=%s", recOpen.Code, recOpen.Body.String())
	}

	// 4. Verify Simulate API returns exact trace nodes & edges
	simReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/waf-rules/simulate", map[string]any{
		"name":  "测试",
		"graph": createdWAF.Graph,
		"path":  "/secret/admin",
	})
	simResp, err := adminClient.Do(simReq)
	if err != nil || simResp.StatusCode != http.StatusOK {
		t.Fatalf("simulate failed: %v", err)
	}
	var simOut wafEvalDecision
	_ = json.NewDecoder(simResp.Body).Decode(&simOut)
	simResp.Body.Close()
	if !simOut.Blocked || simOut.StatusCode != 403 || len(simOut.TraceNodes) != 3 || len(simOut.TraceEdges) != 2 {
		t.Fatalf("unexpected simulate decision: %+v", simOut)
	}

	// 5. Delete WAF rule -> automatically detaches from protected.emby.test
	delReq := mustAdminJSONRequest(t, http.MethodDelete, ctrlSrv.URL+"/_admin/api/waf-rules/"+createdWAF.ID, nil)
	delResp, err := adminClient.Do(delReq)
	if err != nil || delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete WAF rule failed: %v", err)
	}
	delResp.Body.Close()

	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("agent resync after WAF delete: %v", err)
	}
	recAfterDel := httptest.NewRecorder()
	reqAfterDel := httptest.NewRequest(http.MethodGet, "https://protected.emby.test/secret/key", nil)
	reqAfterDel.RemoteAddr = "203.0.113.10:12345"
	agent.ServeHTTP(recAfterDel, reqAfterDel)
	if recAfterDel.Code != http.StatusOK {
		t.Fatalf("expected 200 after WAF rule deleted & detached, got %d", recAfterDel.Code)
	}
}

func TestWAFHomepageBypassAndGeoNoticeAndDetectedPlayers(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stream-ok"))
	}))
	defer origin.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Create & enroll 1 Agent
	nReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
		"name": "WAF Homepage Edge", "group_name": "测试", "region": "HK",
	})
	nResp, err := adminClient.Do(nReq)
	if err != nil || nResp.StatusCode != http.StatusCreated {
		t.Fatalf("create node failed: %v", err)
	}
	var nodeOut struct {
		Node   edgeNodeView `json:"node"`
		Deploy struct {
			EnrollToken string `json:"enroll_token"`
		} `json:"deploy"`
	}
	_ = json.NewDecoder(nResp.Body).Decode(&nodeOut)
	nResp.Body.Close()

	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.TrustProxyHeaders = true
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = nodeOut.Deploy.EnrollToken
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "waf-homepage-agent.json")
	cfg.AgentHeartbeatInterval = 500 * time.Millisecond
	cfg.AgentTelemetryInterval = time.Second
	agent := New(cfg)
	agent.agent.skipIPDetect.Store(true)
	t.Cleanup(agent.Close)

	createRule := func(name string, graph wafRuleGraph) string {
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/waf-rules", map[string]any{
			"name": name, "enabled": true, "is_global": false, "graph": graph,
		})
		resp, err := adminClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create rule %s failed: err=%v resp=%v", name, err, resp)
		}
		var out wafRuleView
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		return out.ID
	}

	// Rule 1: Player whitelist (only SenPlayer allowed)
	playerRuleID := createRule("播放器白名单", wafRuleGraph{
		Nodes: []wafGraphNode{
			{ID: "n_start", Type: wafNodeStart, Label: "请求入口"},
			{ID: "n_player", Type: wafNodePlayerMatch, Label: "播放器", Config: wafNodeConfig{Patterns: []string{"SenPlayer"}}},
			{ID: "n_pass", Type: wafNodePass, Label: "放行"},
			{ID: "n_block", Type: wafNodeBlock, Label: "拦截", Config: wafNodeConfig{StatusCode: 403, Message: "player not allowed"}},
		},
		Edges: []wafGraphEdge{
			{ID: "e1", Source: "n_start", SourcePort: "next", Target: "n_player"},
			{ID: "e2", Source: "n_player", SourcePort: "true", Target: "n_pass"},
			{ID: "e3", Source: "n_player", SourcePort: "false", Target: "n_block"},
		},
	})

	// Rule 2: Combined Geo (CN only) -> Player (SenPlayer only)
	geoPlayerRuleID := createRule("仅限中国大陆与白名单播放器", wafRuleGraph{
		Nodes: []wafGraphNode{
			{ID: "n_start", Type: wafNodeStart, Label: "请求入口"},
			{ID: "n_geo", Type: wafNodeGeoMatch, Label: "国家地区", Config: wafNodeConfig{Countries: []string{"CN"}}},
			{ID: "n_player", Type: wafNodePlayerMatch, Label: "播放器", Config: wafNodeConfig{Patterns: []string{"SenPlayer"}}},
			{ID: "n_pass", Type: wafNodePass, Label: "放行"},
			{ID: "n_geo_block", Type: wafNodeBlock, Label: "地区拦截", Config: wafNodeConfig{StatusCode: 403, Message: "仅限中国大陆地区访问"}},
			{ID: "n_player_block", Type: wafNodeBlock, Label: "播放器拦截", Config: wafNodeConfig{StatusCode: 403, Message: "player not allowed"}},
		},
		Edges: []wafGraphEdge{
			{ID: "e1", Source: "n_start", SourcePort: "next", Target: "n_geo"},
			{ID: "e2", Source: "n_geo", SourcePort: "false", Target: "n_geo_block"},
			{ID: "e3", Source: "n_geo", SourcePort: "true", Target: "n_player"},
			{ID: "e4", Source: "n_player", SourcePort: "true", Target: "n_pass"},
			{ID: "e5", Source: "n_player", SourcePort: "false", Target: "n_player_block"},
		},
	})

	for _, dom := range []struct {
		host   string
		wafIDs []string
	}{
		{"player.emby.test", []string{playerRuleID}},
		{"geo.emby.test", []string{geoPlayerRuleID}},
	} {
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
			"domain":       dom.host,
			"name":         dom.host,
			"enabled":      true,
			"node_ids":     []string{nodeOut.Node.ID},
			"dns_mode":     "manual",
			"tls_mode":     "external",
			"waf_rule_ids": dom.wafIDs,
			"overrides":    map[string]any{"allow_unsigned_targets": true},
		})
		resp, err := adminClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create domain %s failed: err=%v resp=%v", dom.host, err, resp)
		}
		resp.Body.Close()
	}

	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("agent syncConfig: %v", err)
	}

	// 1. Browser visiting GET / on player-whitelist domain MUST succeed (200 OK)
	rootRec := httptest.NewRecorder()
	rootReq := httptest.NewRequest(http.MethodGet, "https://player.emby.test/", nil)
	rootReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126.0")
	rootReq.RemoteAddr = "127.0.0.1:40001"
	agent.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK || !strings.Contains(rootRec.Body.String(), "Refract · 通用反向代理") {
		t.Fatalf("expected 200 public homepage on player-whitelist domain, got %d body=%s", rootRec.Code, rootRec.Body.String())
	}

	// 2. Browser proxying stream on player-whitelist domain MUST be blocked (403)
	playBlocked := httptest.NewRecorder()
	playReq := httptest.NewRequest(http.MethodGet, "https://player.emby.test/"+origin.URL+"/Videos/1/stream", nil)
	playReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126.0")
	playReq.RemoteAddr = "127.0.0.1:40002"
	agent.ServeHTTP(playBlocked, playReq)
	if playBlocked.Code != http.StatusForbidden || !strings.Contains(playBlocked.Body.String(), "player not allowed") {
		t.Fatalf("expected 403 for browser playback on player-whitelist domain, got %d body=%s", playBlocked.Code, playBlocked.Body.String())
	}

	// 3. Allowed player proxying stream MUST succeed (200)
	playAllowed := httptest.NewRecorder()
	playOkReq := httptest.NewRequest(http.MethodGet, "https://player.emby.test/"+origin.URL+"/Videos/1/stream", nil)
	playOkReq.Header.Set("User-Agent", "SenPlayer/5.0")
	playOkReq.RemoteAddr = "127.0.0.1:40003"
	agent.ServeHTTP(playAllowed, playOkReq)
	if playAllowed.Code != http.StatusOK || playAllowed.Body.String() != "stream-ok" {
		t.Fatalf("expected 200 for SenPlayer stream, got %d body=%s", playAllowed.Code, playAllowed.Body.String())
	}

	// 4. Geo-blocked visitor (US) can still open GET / (200 OK), AND /_gateway/health reports geo_blocked=true
	geoRoot := httptest.NewRecorder()
	geoRootReq := httptest.NewRequest(http.MethodGet, "https://geo.emby.test/", nil)
	geoRootReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126.0")
	geoRootReq.Header.Set("CF-IPCountry", "US")
	geoRootReq.RemoteAddr = "127.0.0.1:40004"
	agent.ServeHTTP(geoRoot, geoRootReq)
	if geoRoot.Code != http.StatusOK {
		t.Fatalf("expected 200 homepage for US visitor on geo-restricted domain, got %d", geoRoot.Code)
	}

	usHealth := httptest.NewRecorder()
	usHealthReq := httptest.NewRequest(http.MethodGet, "https://geo.emby.test/_gateway/health", nil)
	usHealthReq.Header.Set("CF-IPCountry", "US")
	usHealthReq.RemoteAddr = "127.0.0.1:40005"
	agent.ServeHTTP(usHealth, usHealthReq)
	var usPayload map[string]any
	_ = json.NewDecoder(usHealth.Body).Decode(&usPayload)
	if usHealth.Code != http.StatusOK || usPayload["geo_blocked"] != true || usPayload["geo_country"] != "US" || usPayload["geo_message"] != "仅限中国大陆地区访问" {
		t.Fatalf("expected geo_blocked=true for US health check, got code=%d payload=%#v", usHealth.Code, usPayload)
	}

	// 5. CN browser on combined Geo+Player rule MUST NOT be falsely flagged as geo_blocked on /_gateway/health
	cnHealth := httptest.NewRecorder()
	cnHealthReq := httptest.NewRequest(http.MethodGet, "https://geo.emby.test/_gateway/health", nil)
	cnHealthReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/126.0")
	cnHealthReq.Header.Set("CF-IPCountry", "CN")
	cnHealthReq.RemoteAddr = "127.0.0.1:40006"
	agent.ServeHTTP(cnHealth, cnHealthReq)
	var cnPayload map[string]any
	_ = json.NewDecoder(cnHealth.Body).Decode(&cnPayload)
	if cnHealth.Code != http.StatusOK || cnPayload["geo_blocked"] == true {
		t.Fatalf("expected CN visitor not geo_blocked on combined geo+player rule, got code=%d payload=%#v", cnHealth.Code, cnPayload)
	}

	// 6. US visitor attempting actual proxy playback MUST still be strictly blocked (403)
	usPlay := httptest.NewRecorder()
	usPlayReq := httptest.NewRequest(http.MethodGet, "https://geo.emby.test/"+origin.URL+"/Videos/1/stream", nil)
	usPlayReq.Header.Set("User-Agent", "SenPlayer/5.0")
	usPlayReq.Header.Set("CF-IPCountry", "US")
	usPlayReq.RemoteAddr = "127.0.0.1:40007"
	agent.ServeHTTP(usPlay, usPlayReq)
	if usPlay.Code != http.StatusForbidden || !strings.Contains(usPlay.Body.String(), "仅限中国大陆地区访问") {
		t.Fatalf("expected 403 geo block for US proxy request, got %d body=%s", usPlay.Code, usPlay.Body.String())
	}

	// 7. Detected players API returns live + persisted players merged case-insensitively
	detResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/waf-rules/detected-players")
	if err != nil || detResp.StatusCode != http.StatusOK {
		t.Fatalf("GET detected-players failed: err=%v resp=%v", err, detResp)
	}
	var detPayload struct {
		Players []wafDetectedPlayer `json:"players"`
		Presets []string            `json:"presets"`
	}
	_ = json.NewDecoder(detResp.Body).Decode(&detPayload)
	detResp.Body.Close()
	if len(detPayload.Presets) == 0 {
		t.Fatalf("expected non-empty player presets, got %#v", detPayload)
	}
}

func TestTelemetryStoreListDetectedPlayersMergesSources(t *testing.T) {
	store, err := openTelemetryStore(filepath.Join(t.TempDir(), "players.db"), "admin", "hash")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		_, err := store.db.Exec(
			`INSERT INTO request_logs(node_id,timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms,device_id,device_name,client_name)
			 VALUES('', ?, 'emby.test', 'https', 'GET', '/Videos/1', 'media', 200, 0, 100, 12, '', '', ?)`,
			now-int64(i), "RodelPlayer",
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = store.db.Exec(
		`INSERT INTO request_logs(node_id,timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms,device_id,device_name,client_name)
		 VALUES('', ?, 'emby.test', 'https', 'GET', '/Videos/2', 'media', 200, 0, 100, 12, '', '', ?)`,
		now, "rodelplayer",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertWatchHistory(context.Background(), []playbackSessionSnapshot{
		{SessionKey: "s1", ClientName: "Hills Windows", Title: "Demo Movie", StartedAt: now - 60, LastSeenAt: now},
	}); err != nil {
		t.Fatal(err)
	}

	players, err := store.ListDetectedPlayers(
		context.Background(),
		[]connectionSnapshot{{ClientName: "SenPlayer"}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(players) != 3 {
		t.Fatalf("expected 3 merged players, got %#v", players)
	}
	// Active live player pops first
	if players[0].Name != "SenPlayer" || !players[0].Active {
		t.Fatalf("expected active SenPlayer first, got %#v", players[0])
	}
	// Merged case-insensitive RodelPlayer keeps majority capitalization and summed count (3 + 1 = 4)
	if players[1].Name != "RodelPlayer" || players[1].Requests != 4 {
		t.Fatalf("expected merged RodelPlayer with 4 requests, got %#v", players[1])
	}
	if players[2].Name != "Hills Windows" || players[2].Requests != 1 {
		t.Fatalf("expected Hills Windows from watch_history, got %#v", players[2])
	}
}

func TestWAFPathMatchQueryAndMalformedPercent(t *testing.T) {
	_, compiled, err := normalizeAndCompileWAFRule(wafRuleRecord{
		ID: "waf_q", Name: "Query Bypass Check", Enabled: true,
		Graph: wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "p1", Type: wafNodePathMatch, Config: wafNodeConfig{MatchMode: "regex", Patterns: []string{`^/emby/Items$`, `admin=true`}}},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "blocked"}},
				{ID: "ok", Type: wafNodePass},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "p1"},
				{ID: "e2", Source: "p1", SourcePort: "true", Target: "b"},
				{ID: "e3", Source: "p1", SourcePort: "false", Target: "ok"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile WAF rule: %v", err)
	}
	// Appending ?1 must NOT bypass regex $ anchor on path.
	if dec := compiled.Evaluate(wafEvalContext{Path: "/emby/Items", RawQuery: "1"}, false); !dec.Blocked {
		t.Fatalf("expected ^/emby/Items$ with ?1 query to remain blocked")
	}
	// Malformed %zz in same query must NOT abort decoding of valid %61dmin%3dtrue.
	if dec := compiled.Evaluate(wafEvalContext{Path: "/test", RawQuery: "bad=%zz&%61dmin%3dtrue"}, false); !dec.Blocked {
		t.Fatalf("expected malformed %%zz alongside encoded admin=true to be decoded and blocked")
	}
}

func TestDynamicTargetDeviceIdentityCaseInsensitive(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://proxy.test/direct?x-emby-client=HeaderClient", nil)
	target, _ := req.URL.Parse("https://origin.example.test/Videos/1/stream?DEVICEID=Dev-Uppercase&client=TargetPlayer")
	req2 := httptest.NewRequest(http.MethodGet, "https://proxy.test/direct", nil)
	id := requestDeviceIdentityForTarget(req2, target)
	if id.ID != "Dev-Uppercase" || id.ClientName != "TargetPlayer" {
		t.Fatalf("unexpected target device identity: %+v", id)
	}
}
