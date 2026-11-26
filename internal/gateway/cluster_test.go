package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newControllerTestGateway(t *testing.T) *Gateway {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse battery staple"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.Role = RoleController
	cfg.AdminEnabled = true
	cfg.AdminUsername = "admin"
	cfg.AdminPasswordHash = string(hash)
	cfg.AdminSessionSecret = []byte("fedcba9876543210fedcba9876543210")
	cfg.AdminDatabasePath = filepath.Join(t.TempDir(), "controller.db")
	cfg.AdminSessionTTL = time.Hour
	cfg.AllowUnsigned = false
	cfg.PassClientIP = false
	cfg.DisableCache = true
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gw.Close)
	return gw
}

func TestControllerModeDisablesDataPlaneProxying(t *testing.T) {
	controller := newControllerTestGateway(t)

	// Pure controller mode must not allocate local data-plane pools, while enabling Emby server probe workers
	if controller.proxy != nil || controller.transport != nil || controller.meter != nil ||
		controller.connections != nil || controller.quota != nil {
		t.Fatal("controller mode should not initialize local data-plane pools")
	}
	if controller.embyHealth == nil || controller.embyHealth.resolver == nil {
		t.Fatal("controller mode should initialize Emby health probe monitor with safeResolver")
	}

	// Health reports controller role
	health := httptest.NewRecorder()
	controller.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_gateway/health", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"role":"controller"`) {
		t.Fatalf("controller health status=%d body=%s", health.Code, health.Body.String())
	}

	// Public frontend & nodes endpoint stay available by default
	front := httptest.NewRecorder()
	controller.ServeHTTP(front, httptest.NewRequest(http.MethodGet, "https://ctrl.test/", nil))
	if front.Code != http.StatusOK || !strings.Contains(front.Body.String(), "Refract · 通用反向代理") {
		t.Fatalf("controller frontend status=%d", front.Code)
	}
	nodesRes := httptest.NewRecorder()
	controller.ServeHTTP(nodesRes, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_gateway/nodes", nil))
	if nodesRes.Code != http.StatusOK || !strings.Contains(nodesRes.Body.String(), `"role":"controller"`) {
		t.Fatalf("controller public nodes status=%d body=%s", nodesRes.Code, nodesRes.Body.String())
	}

	// Toggling public portal off immediately redirects / -> /login; toggling back restores /
	cookie := loginAdmin(t, controller)
	disableRes := adminRequest(t, controller, http.MethodPut, "/_admin/api/portal", map[string]bool{"public_portal_enabled": false}, cookie, true)
	if disableRes.Code != http.StatusOK || !strings.Contains(disableRes.Body.String(), `"public_portal_enabled":false`) {
		t.Fatalf("disable portal status=%d body=%s", disableRes.Code, disableRes.Body.String())
	}
	hiddenFront := httptest.NewRecorder()
	controller.ServeHTTP(hiddenFront, httptest.NewRequest(http.MethodGet, "https://ctrl.test/", nil))
	if hiddenFront.Code != http.StatusFound || hiddenFront.Header().Get("Location") != "/login" {
		t.Fatalf("hidden portal status=%d location=%q", hiddenFront.Code, hiddenFront.Header().Get("Location"))
	}
	enableRes := adminRequest(t, controller, http.MethodPut, "/_admin/api/portal", map[string]bool{"public_portal_enabled": true}, cookie, true)
	if enableRes.Code != http.StatusOK {
		t.Fatalf("enable portal status=%d", enableRes.Code)
	}
	restoredFront := httptest.NewRecorder()
	controller.ServeHTTP(restoredFront, httptest.NewRequest(http.MethodGet, "https://ctrl.test/", nil))
	if restoredFront.Code != http.StatusOK {
		t.Fatalf("restored portal status=%d", restoredFront.Code)
	}

	// Data-plane proxy requests MUST be rejected on controller
	proxyReq := httptest.NewRecorder()
	controller.ServeHTTP(proxyReq, httptest.NewRequest(http.MethodGet, "https://ctrl.test/https://emby.example.com/System/Info", nil))
	if proxyReq.Code != http.StatusNotFound || !strings.Contains(proxyReq.Body.String(), "controller mode does not proxy") {
		t.Fatalf("controller proxy path status=%d body=%s", proxyReq.Code, proxyReq.Body.String())
	}
}

func TestClusterEndToEndEnrollHotSyncTelemetryKickAndFailOpen(t *testing.T) {
	holdStarted := make(chan struct{})
	holdRelease := make(chan struct{})
	var closeHoldOnce sync.Once
	releaseHold := func() { closeHoldOnce.Do(func() { close(holdRelease) }) }
	defer releaseHold()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			select {
			case <-holdStarted:
			default:
				close(holdStarted)
			}
			select {
			case <-holdRelease:
				_, _ = w.Write([]byte("released"))
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ok":  "yes",
			"xff": r.Header.Get("X-Forwarded-For"),
		})
	}))
	defer upstream.Close()

	controller := newControllerTestGateway(t)
	ctrlServer := httptest.NewServer(controller)
	defer ctrlServer.Close()

	cookie := loginAdmin(t, controller)

	// Create Node A (overrides AllowUnsigned=true, speed limit 50 Mbps) and Node B (inherits global AllowUnsigned=false)
	allowTrue := true
	speed50 := int64(50)
	createNode := func(body map[string]any) (edgeNodeRecord, agentDeployCommands) {
		t.Helper()
		res := adminRequest(t, controller, http.MethodPost, "/_admin/api/nodes", body, cookie, true)
		if res.Code != http.StatusCreated {
			t.Fatalf("create node status=%d body=%s", res.Code, res.Body.String())
		}
		var out struct {
			Node   edgeNodeRecord      `json:"node"`
			Deploy agentDeployCommands `json:"deploy"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Deploy.EnrollToken == "" || !strings.Contains(out.Deploy.SystemdScript, out.Deploy.EnrollToken) {
			t.Fatalf("missing deploy token/script: %+v", out.Deploy)
		}
		return out.Node, out.Deploy
	}

	nodeA, deployA := createNode(map[string]any{
		"name":           "德国 9929",
		"group_name":     "欧洲直连",
		"region":         "Frankfurt",
		"public_url":     "https://de.emby.test",
		"public_visible": true,
		"overrides": edgeNodeOverrides{
			AllowUnsigned:        &allowTrue,
			MaxDownloadMbitPerIP: &speed50,
		},
	})
	nodeB, deployB := createNode(map[string]any{
		"name":           "日本 IIJ",
		"group_name":     "亚太优化",
		"region":         "Tokyo",
		"public_url":     "https://jp.emby.test",
		"public_visible": true,
	})

	statePathA := filepath.Join(t.TempDir(), "agent-a.json")
	statePathB := filepath.Join(t.TempDir(), "agent-b.json")

	newAgent := func(statePath, enrollToken string) *Gateway {
		t.Helper()
		cfg := testConfig()
		cfg.Role = RoleAgent
		cfg.AdminEnabled = false
		cfg.AllowPrivateTargets = true
		cfg.AgentControllerURL = ctrlServer.URL
		cfg.AgentEnrollToken = enrollToken
		cfg.AgentStatePath = statePath
		cfg.AgentHeartbeatInterval = 300 * time.Millisecond
		cfg.AgentTelemetryInterval = 300 * time.Millisecond
		gw, err := NewChecked(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return gw
	}

	agentA := newAgent(statePathA, deployA.EnrollToken)
	defer agentA.Close()
	agentB := newAgent(statePathB, deployB.EnrollToken)
	defer agentB.Close()

	waitUntil := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for: %s", desc)
	}

	// 1. Both agents enroll, persist 0600 state files, sync config, and appear online
	waitUntil("both agents online and synced", func() bool {
		res := adminRequest(t, controller, http.MethodGet, "/_admin/api/nodes", nil, cookie, false)
		if res.Code != http.StatusOK {
			return false
		}
		var list edgeNodesListResponse
		if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
			return false
		}
		return list.Summary.Online == 2 && list.Summary.Synced == 2
	})

	if info, err := os.Stat(statePathA); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("agent state file mode err=%v info=%v", err, info)
	}

	// Reusing consumed enroll token must be rejected
	replayBody, _ := json.Marshal(agentEnrollRequest{EnrollToken: deployA.EnrollToken})
	replayResp, err := http.Post(ctrlServer.URL+"/_agent/api/v1/enroll", "application/json", bytes.NewReader(replayBody))
	if err != nil {
		t.Fatal(err)
	}
	_ = replayResp.Body.Close()
	if replayResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed enroll token status=%d, want 401", replayResp.StatusCode)
	}

	// Public /_gateway/nodes on Controller always returns empty nodes (privacy), while cluster PublicNodes has both online nodes
	pubNodesRec := httptest.NewRecorder()
	controller.ServeHTTP(pubNodesRec, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_gateway/nodes", nil))
	if pubNodesRec.Code != http.StatusOK || !strings.Contains(pubNodesRec.Body.String(), `"nodes":[]`) {
		t.Fatalf("controller /_gateway/nodes must hide node inventory, got=%s", pubNodesRec.Body.String())
	}
	ctrlPublicNodes, err := controller.cluster.PublicNodes(context.Background())
	if err != nil {
		t.Fatalf("PublicNodes: %v", err)
	}
	ctrlPublicRaw, _ := json.Marshal(ctrlPublicNodes)
	if !strings.Contains(string(ctrlPublicRaw), "德国 9929") || !strings.Contains(string(ctrlPublicRaw), "日本 IIJ") {
		t.Fatalf("cluster PublicNodes=%s", ctrlPublicRaw)
	}

	// 2. Per-node override vs global inheritance: Agent A allows unsigned, Agent B blocks unsigned
	targetURL := "https://de.emby.test/" + upstream.URL + "/ping"
	recA := httptest.NewRecorder()
	reqA := httptest.NewRequest(http.MethodGet, targetURL, nil)
	reqA.RemoteAddr = "198.51.100.11:5001"
	agentA.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("agent A unsigned proxy status=%d body=%s", recA.Code, recA.Body.String())
	}
	if agentA.bandwidth.Limit() != megabitsToBytes(50) {
		t.Fatalf("agent A speed override=%d, want %d", agentA.bandwidth.Limit(), megabitsToBytes(50))
	}

	recB := httptest.NewRecorder()
	agentB.ServeHTTP(recB, httptest.NewRequest(http.MethodGet, "https://jp.emby.test/"+upstream.URL+"/ping", nil))
	if recB.Code != http.StatusForbidden {
		t.Fatalf("agent B global unsigned=false status=%d, want 403", recB.Code)
	}

	// 3. Global hot-reload via Controller pushes to Agent B in real time via SSE
	globalSettings := validRuntimeSettings()
	globalSettings.DefaultUpstream = ""
	globalSettings.AllowedUpstreams = ""
	globalSettings.AllowUnsigned = true
	globalSettings.PassClientIP = true
	saveRes := adminRequest(t, controller, http.MethodPut, "/_admin/api/runtime-config", globalSettings, cookie, true)
	if saveRes.Code != http.StatusOK {
		t.Fatalf("save global runtime config status=%d body=%s", saveRes.Code, saveRes.Body.String())
	}

	waitUntil("agent B hot-reloads global allow_unsigned=true & pass_client_ip=true", func() bool {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://jp.emby.test/"+upstream.URL+"/ping", nil)
		req.RemoteAddr = "198.51.100.22:5002"
		agentB.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return false
		}
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return strings.Contains(body["xff"], "198.51.100.22")
	})

	// 4. Node draining hot-sync + public portal hiding
	drainRes := adminRequest(t, controller, http.MethodPut, "/_admin/api/nodes/"+nodeA.ID, map[string]any{
		"name":           nodeA.Name,
		"group_name":     nodeA.GroupName,
		"region":         nodeA.Region,
		"public_url":     nodeA.PublicURL,
		"public_visible": true,
		"draining":       true,
		"overrides":      edgeNodeOverrides{AllowUnsigned: &allowTrue, MaxDownloadMbitPerIP: &speed50},
	}, cookie, true)
	if drainRes.Code != http.StatusOK {
		t.Fatalf("enable draining status=%d body=%s", drainRes.Code, drainRes.Body.String())
	}
	waitUntil("agent A enters draining mode (503)", func() bool {
		rec := httptest.NewRecorder()
		agentA.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, targetURL, nil))
		return rec.Code == http.StatusServiceUnavailable
	})
	pubAfterDrain, err := controller.cluster.PublicNodes(context.Background())
	if err != nil {
		t.Fatalf("PublicNodes after drain: %v", err)
	}
	pubAfterDrainRaw, _ := json.Marshal(pubAfterDrain)
	if strings.Contains(string(pubAfterDrainRaw), "德国 9929") {
		t.Fatalf("draining node should be hidden from PublicNodes: %s", pubAfterDrainRaw)
	}
	// Restore node A active
	_ = adminRequest(t, controller, http.MethodPut, "/_admin/api/nodes/"+nodeA.ID, map[string]any{
		"name":           nodeA.Name,
		"group_name":     nodeA.GroupName,
		"region":         nodeA.Region,
		"public_url":     nodeA.PublicURL,
		"public_visible": true,
		"draining":       false,
		"overrides":      edgeNodeOverrides{AllowUnsigned: &allowTrue, MaxDownloadMbitPerIP: &speed50},
	}, cookie, true)
	waitUntil("agent A resumes active traffic", func() bool {
		rec := httptest.NewRecorder()
		agentA.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, targetURL, nil))
		return rec.Code == http.StatusOK
	})

	// 5. Telemetry aggregation & per-node filtering on Controller
	waitUntil("controller aggregates telemetry logs from agent A and B", func() bool {
		resA := adminRequest(t, controller, http.MethodGet, "/_admin/api/requests?node_id="+nodeA.ID, nil, cookie, false)
		resB := adminRequest(t, controller, http.MethodGet, "/_admin/api/requests?node_id="+nodeB.ID, nil, cookie, false)
		return resA.Code == http.StatusOK && strings.Contains(resA.Body.String(), `"node_name":"德国 9929"`) &&
			resB.Code == http.StatusOK && strings.Contains(resB.Body.String(), `"node_name":"日本 IIJ"`)
	})

	// 6. Cross-node remote connection termination via Controller SSE cancel_flow
	holdDone := make(chan struct{})
	go func() {
		defer close(holdDone)
		rec := httptest.NewRecorder()
		agentA.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://de.emby.test/"+upstream.URL+"/hold", nil))
	}()
	<-holdStarted

	var flowID string
	waitUntil("live connection from agent A appears on controller", func() bool {
		res := adminRequest(t, controller, http.MethodGet, "/_admin/api/connections?node_id="+nodeA.ID, nil, cookie, false)
		if res.Code != http.StatusOK {
			return false
		}
		var payload struct {
			Connections []connectionSnapshot `json:"connections"`
		}
		_ = json.Unmarshal(res.Body.Bytes(), &payload)
		for _, c := range payload.Connections {
			if c.NodeID == nodeA.ID && c.Path == "/hold" {
				flowID = c.ID
				return true
			}
		}
		return false
	})

	kickRes := adminRequest(t, controller, http.MethodDelete, "/_admin/api/connections/"+flowID+"?node_id="+nodeA.ID, nil, cookie, true)
	if kickRes.Code != http.StatusOK {
		t.Fatalf("remote kick status=%d body=%s", kickRes.Code, kickRes.Body.String())
	}
	select {
	case <-holdDone:
	case <-time.After(3 * time.Second):
		t.Fatal("remote SSE cancel_flow did not terminate active agent connection")
	}

	// 7. Fail-open autonomy: stop Controller completely, restart Agent A from cached state file only
	agentA.Close()
	agentB.Close()
	ctrlServer.Close()

	offlineAgentCfg := testConfig()
	offlineAgentCfg.Role = RoleAgent
	offlineAgentCfg.AdminEnabled = false
	offlineAgentCfg.AllowPrivateTargets = true
	offlineAgentCfg.AgentControllerURL = ctrlServer.URL // unreachable now!
	offlineAgentCfg.AgentStatePath = statePathA
	offlineAgentCfg.AgentHeartbeatInterval = 10 * time.Second
	offlineAgentCfg.AgentTelemetryInterval = 10 * time.Second
	offlineAgent, err := NewChecked(offlineAgentCfg)
	if err != nil {
		t.Fatalf("agent failed to start from cached state while controller offline: %v", err)
	}
	defer offlineAgent.Close()

	recOffline := httptest.NewRecorder()
	offlineAgent.ServeHTTP(recOffline, httptest.NewRequest(http.MethodGet, targetURL, nil))
	if recOffline.Code != http.StatusOK {
		t.Fatalf("fail-open agent proxy while controller offline status=%d body=%s", recOffline.Code, recOffline.Body.String())
	}
}

func TestOneClickInstallScriptBinaryAndDynamicDomainAutoTLS(t *testing.T) {
	controller := newControllerTestGateway(t)
	binDir := t.TempDir()
	controller.cfg.AgentBinaryDir = binDir
	fakeBinary := []byte("#!/bin/sh\necho fake-linux-amd64-binary\n")
	if err := os.WriteFile(filepath.Join(binDir, "refract-linux-amd64"), fakeBinary, 0o755); err != nil {
		t.Fatal(err)
	}

	ctrlServer := httptest.NewServer(controller)
	defer ctrlServer.Close()
	cookie := loginAdmin(t, controller)

	// 1. Create node & verify one-click install command is returned
	res := adminRequest(t, controller, http.MethodPost, "/_admin/api/nodes", map[string]any{
		"name":           "法兰克福 AutoTLS",
		"group_name":     "欧洲直连",
		"region":         "Frankfurt",
		"public_url":     "https://de1.emby.example",
		"public_visible": true,
	}, cookie, true)
	if res.Code != http.StatusCreated {
		t.Fatalf("create node status=%d body=%s", res.Code, res.Body.String())
	}
	var created struct {
		Node   edgeNodeRecord      `json:"node"`
		Deploy agentDeployCommands `json:"deploy"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(created.Deploy.OneClickAutoTLS, "/_agent/api/v1/install.sh?token="+created.Deploy.EnrollToken) ||
		!strings.Contains(created.Deploy.OneClickProxy, "&tls=off") {
		t.Fatalf("unexpected one-click commands: %+v", created.Deploy)
	}

	// 2. Verify install.sh endpoint validates token & generates auto-TLS and behind-proxy scripts
	unauthInstall := httptest.NewRecorder()
	controller.ServeHTTP(unauthInstall, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_agent/api/v1/install.sh?token=rf_enr_invalid000000000000", nil))
	if unauthInstall.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token install.sh status=%d, want 401", unauthInstall.Code)
	}

	autoScript := httptest.NewRecorder()
	controller.ServeHTTP(autoScript, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_agent/api/v1/install.sh?token="+created.Deploy.EnrollToken, nil))
	if autoScript.Code != http.StatusOK ||
		!strings.Contains(autoScript.Body.String(), "REFRACT_AGENT_AUTO_TLS=true") ||
		!strings.Contains(autoScript.Body.String(), "REFRACT_AGENT_TLS_LISTEN_ADDR=:443") ||
		!strings.Contains(autoScript.Body.String(), "sha256sum") {
		t.Fatalf("auto-TLS install script status=%d body=%s", autoScript.Code, autoScript.Body.String())
	}

	proxyScript := httptest.NewRecorder()
	controller.ServeHTTP(proxyScript, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_agent/api/v1/install.sh?token="+created.Deploy.EnrollToken+"&tls=off&port=18090", nil))
	if proxyScript.Code != http.StatusOK ||
		!strings.Contains(proxyScript.Body.String(), "REFRACT_AGENT_AUTO_TLS=false") ||
		!strings.Contains(proxyScript.Body.String(), "LISTEN_ADDR=127.0.0.1:18090") {
		t.Fatalf("proxy install script status=%d body=%s", proxyScript.Code, proxyScript.Body.String())
	}

	// 3. Verify /_agent/api/v1/binary requires auth and returns exact file + X-Refract-SHA256
	unauthBin := httptest.NewRecorder()
	controller.ServeHTTP(unauthBin, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_agent/api/v1/binary?os=linux&arch=amd64", nil))
	if unauthBin.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated binary status=%d, want 401", unauthBin.Code)
	}
	authedBin := httptest.NewRecorder()
	controller.ServeHTTP(authedBin, httptest.NewRequest(http.MethodGet, "https://ctrl.test/_agent/api/v1/binary?os=linux&arch=amd64&token="+created.Deploy.EnrollToken, nil))
	if authedBin.Code != http.StatusOK || authedBin.Header().Get("X-Refract-SHA256") == "" || !bytes.Equal(authedBin.Body.Bytes(), fakeBinary) {
		t.Fatalf("binary download status=%d sha=%q len=%d", authedBin.Code, authedBin.Header().Get("X-Refract-SHA256"), authedBin.Body.Len())
	}

	// 4. Verify dynamic controller-driven domain hot-swap on Agent AutoTLS HostPolicy
	agentCfg := testConfig()
	agentCfg.Role = RoleAgent
	agentCfg.AdminEnabled = false
	agentCfg.AgentControllerURL = ctrlServer.URL
	agentCfg.AgentEnrollToken = created.Deploy.EnrollToken
	agentCfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-autotls.json")
	agentCfg.AgentAutoTLS = true
	agentCfg.AgentCertDir = filepath.Join(t.TempDir(), "certs")
	agentCfg.AgentHeartbeatInterval = 300 * time.Millisecond
	agentCfg.AgentTelemetryInterval = 300 * time.Millisecond

	// Construct agent with skipCertWarm so unit test validates HostPolicy & hot-swap without calling Let's Encrypt
	gw := &Gateway{
		cfg:         agentCfg,
		signer:      NewSigner(agentCfg.SigningSecret, agentCfg.SignedURLTTL),
		resolver:    newSafeResolver(agentCfg.DNSCacheTTL, true),
		limiter:     newRequestLimiter(agentCfg.MaxConcurrent, agentCfg.MaxConcurrentPerIP),
		bandwidth:   newBandwidthLimiter(agentCfg.MaxDownloadBPSPerIP),
		meter:       newRateMeter(),
		connections: newConnectionTracker(),
		started:     time.Now(),
	}
	gw.policy.Store(&proxyPolicy{Rules: []proxyRule{}})
	agent, err := newAgentClient(gw, agentCfg)
	if err != nil {
		t.Fatal(err)
	}
	agent.skipCertWarm = true
	gw.agent = agent
	agent.Start()
	defer func() {
		gw.Close()
	}()

	waitUntil := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for: %s", desc)
	}

	waitUntil("agent receives initial domain de1.emby.example", func() bool {
		return agent.autoTLS.AllowedHost() == "de1.emby.example"
	})
	if err := agent.autoTLS.hostPolicy(t.Context(), "de1.emby.example"); err != nil {
		t.Fatalf("de1 hostPolicy rejected: %v", err)
	}
	if err := agent.autoTLS.hostPolicy(t.Context(), "de2.emby.example"); err == nil {
		t.Fatal("unassigned de2.emby.example should be rejected before controller pushes update")
	}

	// Admin edits the node domain on Controller: de1.emby.example -> de2.emby.example
	updateRes := adminRequest(t, controller, http.MethodPut, "/_admin/api/nodes/"+created.Node.ID, map[string]any{
		"name":           created.Node.Name,
		"group_name":     created.Node.GroupName,
		"region":         created.Node.Region,
		"public_url":     "https://de2.emby.example",
		"public_visible": true,
		"draining":       false,
	}, cookie, true)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("update node domain status=%d body=%s", updateRes.Code, updateRes.Body.String())
	}

	// Agent hot-switches both PublicBaseURL AND AutoTLS HostPolicy via SSE without restart!
	waitUntil("agent hot-swaps AutoTLS domain to de2.emby.example", func() bool {
		rt := gw.liveRuntime()
		return agent.autoTLS.AllowedHost() == "de2.emby.example" &&
			rt.PublicBaseURL != nil && rt.PublicBaseURL.String() == "https://de2.emby.example"
	})
	if err := agent.autoTLS.hostPolicy(t.Context(), "de2.emby.example"); err != nil {
		t.Fatalf("new domain de2 hostPolicy rejected: %v", err)
	}
	if err := agent.autoTLS.hostPolicy(t.Context(), "de1.emby.example"); err == nil {
		t.Fatal("old domain de1 should be rejected after hot-swap")
	}

	// Verify HTTP-01 challenge handler redirects regular HTTP requests to new HTTPS domain
	redirectRec := httptest.NewRecorder()
	gw.AgentHTTPHandler().ServeHTTP(redirectRec, httptest.NewRequest(http.MethodGet, "http://de2.emby.example/System/Info", nil))
	if redirectRec.Code != http.StatusPermanentRedirect || redirectRec.Header().Get("Location") != "https://de2.emby.example/System/Info" {
		t.Fatalf("HTTP redirect status=%d location=%q", redirectRec.Code, redirectRec.Header().Get("Location"))
	}
}
