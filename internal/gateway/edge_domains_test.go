package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func generateTestSelfSignedCert(t *testing.T, dnsNames ...string) (certPEM, keyPEM string, derBytes []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: dnsNames[0], Organization: []string{"Refract Test CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certOut), string(keyOut), der
}

func TestClusterDiscoveryZeroDomainEnrollment(t *testing.T) {
	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// 1. Fetch discovery config & update default group/region
	putReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/nodes/discovery", map[string]any{
		"enabled":        true,
		"default_group":  "自动接入组",
		"default_region": "Global",
	})
	resp, err := adminClient.Do(putReq)
	if err != nil {
		t.Fatalf("PUT discovery: %v", err)
	}
	var disc clusterDiscoveryView
	_ = json.NewDecoder(resp.Body).Decode(&disc)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(disc.Token, "rf_dsc_") {
		t.Fatalf("expected valid discovery token, got status=%d token=%q", resp.StatusCode, disc.Token)
	}
	if !strings.Contains(disc.Commands.OneClickAutoTLS, "discovery="+disc.Token) {
		t.Fatalf("expected discovery install URL, got %q", disc.Commands.OneClickAutoTLS)
	}

	// 2. Verify install.sh accepts ?discovery=...
	shResp, err := http.Get(ctrlSrv.URL + "/_agent/api/v1/install.sh?discovery=" + disc.Token)
	if err != nil {
		t.Fatalf("GET install.sh?discovery: %v", err)
	}
	shBody, _ := io.ReadAll(shResp.Body)
	shResp.Body.Close()
	if shResp.StatusCode != http.StatusOK || !strings.Contains(string(shBody), disc.Token) {
		t.Fatalf("expected 200 install script with discovery token, got %d", shResp.StatusCode)
	}

	// 3. Enroll two independent agents with the SAME discovery token & ZERO domains
	startDiscoveryAgent := func(name string) *Gateway {
		cfg := testConfig()
		cfg.Role = RoleAgent
		cfg.AdminEnabled = false
		cfg.AllowPrivateTargets = true
		cfg.AgentControllerURL = ctrlSrv.URL
		cfg.AgentEnrollToken = disc.Token
		cfg.AgentStatePath = filepath.Join(t.TempDir(), name+".json")
		cfg.AgentHeartbeatInterval = 500 * time.Millisecond
		cfg.AgentTelemetryInterval = time.Second
		gw := New(cfg)
		gw.agent.skipIPDetect.Store(true)
		t.Cleanup(gw.Close)
		return gw
	}
	agentA := startDiscoveryAgent("agent-a")
	agentB := startDiscoveryAgent("agent-b")

	idA, _, _, _ := agentA.agent.Status()
	idB, _, _, _ := agentB.agent.Status()
	if idA == "" || idB == "" || idA == idB {
		t.Fatalf("expected two distinct auto-enrolled node IDs, got idA=%q idB=%q", idA, idB)
	}

	// Unassigned agent returns 404 for proxy requests while /_gateway/health returns 200
	rec := httptest.NewRecorder()
	agentA.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://unassigned.test/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on unassigned agent, got %d body=%s", rec.Code, rec.Body.String())
	}
	hRec := httptest.NewRecorder()
	agentA.ServeHTTP(hRec, httptest.NewRequest(http.MethodGet, "https://unassigned.test/_gateway/health", nil))
	if hRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on health check, got %d", hRec.Code)
	}

	// 4. Rotate discovery token -> old token rejected for new enrollment
	rotReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes/discovery/rotate", map[string]any{})
	rotResp, err := adminClient.Do(rotReq)
	if err != nil {
		t.Fatalf("rotate discovery: %v", err)
	}
	var rotated clusterDiscoveryView
	_ = json.NewDecoder(rotResp.Body).Decode(&rotated)
	rotResp.Body.Close()
	if rotated.Token == disc.Token || !strings.HasPrefix(rotated.Token, "rf_dsc_") {
		t.Fatalf("expected new rotated token, got %q", rotated.Token)
	}

	oldEnrollReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_agent/api/v1/enroll", map[string]any{
		"enroll_token": disc.Token,
		"hostname":     "stale-host",
	})
	oldResp, err := http.DefaultClient.Do(oldEnrollReq)
	if err != nil {
		t.Fatalf("old token enroll check: %v", err)
	}
	oldResp.Body.Close()
	if oldResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for rotated-out discovery token, got %d", oldResp.StatusCode)
	}
}

func TestDomainSelectiveDistributionAndHostIsolation(t *testing.T) {
	originA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin-A")
	}))
	defer originA.Close()
	originB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin-B")
	}))
	defer originB.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Fetch discovery token
	discResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/nodes/discovery")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	var disc clusterDiscoveryView
	_ = json.NewDecoder(discResp.Body).Decode(&disc)
	discResp.Body.Close()

	newAgent := func(name string) (*Gateway, string) {
		cfg := testConfig()
		cfg.Role = RoleAgent
		cfg.AdminEnabled = false
		cfg.AllowPrivateTargets = true
		cfg.AgentAutoTLS = true
		cfg.AgentCertDir = filepath.Join(t.TempDir(), "certs")
		cfg.AgentControllerURL = ctrlSrv.URL
		cfg.AgentEnrollToken = disc.Token
		cfg.AgentStatePath = filepath.Join(t.TempDir(), name+".json")
		cfg.AgentHeartbeatInterval = 300 * time.Millisecond
		cfg.AgentTelemetryInterval = time.Second
		gw := New(cfg)
		gw.agent.skipIPDetect.Store(true)
		gw.agent.skipCertWarm = true
		t.Cleanup(gw.Close)
		nodeID, _, _, _ := gw.agent.Status()
		return gw, nodeID
	}

	agentA, nodeA := newAgent("node-a")
	agentB, nodeB := newAgent("node-b")

	certAlpha, keyAlpha, _ := generateTestSelfSignedCert(t, "alpha.emby.test")
	certWild, keyWild, _ := generateTestSelfSignedCert(t, "*.wild.test")

	// Bind alpha.emby.test ONLY to Node A (with managed manual cert + default_upstream=originA)
	createDom := func(payload map[string]any) edgeDomainView {
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", payload)
		res, err := adminClient.Do(req)
		if err != nil {
			t.Fatalf("POST domain: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("POST domain status=%d body=%s", res.StatusCode, body)
		}
		var view edgeDomainView
		_ = json.NewDecoder(res.Body).Decode(&view)
		return view
	}

	domAlpha := createDom(map[string]any{
		"domain":         "alpha.emby.test",
		"name":           "Alpha Line",
		"enabled":        true,
		"public_visible": true,
		"node_ids":       []string{nodeA},
		"dns_mode":       "manual",
		"tls_mode":       "manual",
		"cert_pem":       certAlpha,
		"key_pem":        keyAlpha,
		"overrides": map[string]any{
			"default_upstream": originA.URL,
		},
	})

	// Bind *.wild.test ONLY to Node B (with wildcard PEM cert + default_upstream=originB)
	_ = createDom(map[string]any{
		"domain":         "*.wild.test",
		"name":           "Wild Line",
		"enabled":        true,
		"public_visible": false,
		"node_ids":       []string{nodeB},
		"dns_mode":       "manual",
		"tls_mode":       "manual",
		"cert_pem":       certWild,
		"key_pem":        keyWild,
		"overrides": map[string]any{
			"default_upstream": originB.URL,
		},
	})

	// Wait for SSE config push to reach both agents
	waitFor := func(cond func() bool, msg string) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatal(msg)
	}

	waitFor(func() bool {
		_, errA := agentA.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.emby.test"})
		_, errB := agentB.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "play.wild.test"})
		return errA == nil && errB == nil
	}, "agents did not receive their assigned domain TLS certificates")

	// Strict TLS isolation: Node B must NOT have alpha.emby.test cert; Node A must NOT have play.wild.test cert
	if _, err := agentB.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.emby.test"}); err == nil {
		t.Fatal("Node B should NOT serve TLS certificate for unassigned domain alpha.emby.test")
	}
	if _, err := agentA.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "play.wild.test"}); err == nil {
		t.Fatal("Node A should NOT serve TLS certificate for unassigned domain play.wild.test")
	}
	// Multi-level subdomain must NOT match *.wild.test
	if _, err := agentB.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "a.b.wild.test"}); err == nil {
		t.Fatal("a.b.wild.test should NOT match single-level wildcard *.wild.test")
	}

	// Strict HTTP Host routing & isolation
	doHost := func(gw *Gateway, host string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "https://"+host+"/ping", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	if code, body := doHost(agentA, "alpha.emby.test"); code != http.StatusOK || body != "origin-A" {
		t.Fatalf("Node A alpha.emby.test expected 200 origin-A, got %d %q", code, body)
	}
	if code, _ := doHost(agentA, "play.wild.test"); code != http.StatusMisdirectedRequest {
		t.Fatalf("Node A unassigned host expected 421, got %d", code)
	}
	if code, body := doHost(agentB, "play.wild.test"); code != http.StatusOK || body != "origin-B" {
		t.Fatalf("Node B play.wild.test expected 200 origin-B, got %d %q", code, body)
	}
	if code, _ := doHost(agentB, "alpha.emby.test"); code != http.StatusMisdirectedRequest {
		t.Fatalf("Node B unassigned host expected 421, got %d", code)
	}

	// Reassign alpha.emby.test from Node A -> Node B!
	updReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/domains/"+domAlpha.ID, map[string]any{
		"domain":         "alpha.emby.test",
		"name":           "Alpha Line",
		"enabled":        true,
		"public_visible": true,
		"node_ids":       []string{nodeB},
		"dns_mode":       "manual",
		"tls_mode":       "manual",
		"overrides": map[string]any{
			"default_upstream": originA.URL,
		},
	})
	updResp, err := adminClient.Do(updReq)
	if err != nil {
		t.Fatalf("PUT domain reassign: %v", err)
	}
	updResp.Body.Close()
	if updResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT domain reassign status=%d", updResp.StatusCode)
	}

	// Wait until Node B serves BOTH alpha.emby.test & play.wild.test AND Node A drops alpha.emby.test!
	waitFor(func() bool {
		_, errA := agentA.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.emby.test"})
		_, errB := agentB.AgentTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "alpha.emby.test"})
		return errA != nil && errB == nil
	}, "domain reassignment did not hot-swap across Node A and Node B")

	if code, body := doHost(agentB, "alpha.emby.test"); code != http.StatusOK || body != "origin-A" {
		t.Fatalf("Node B after reassignment expected 200 origin-A, got %d %q", code, body)
	}
	if code, body := doHost(agentB, "play.wild.test"); code != http.StatusOK || body != "origin-B" {
		t.Fatalf("Node B second domain expected 200 origin-B, got %d %q", code, body)
	}
	if code, _ := doHost(agentA, "alpha.emby.test"); code != http.StatusNotFound {
		t.Fatalf("Node A with zero assigned domains expected 404, got %d", code)
	}
}

func TestEdgeDomainCloudflareAllAndFailover(t *testing.T) {
	var cfMu sync.Mutex
	records := make(map[string]cfDNSRecord)
	nextID := 1
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/z1/dns_records":
			wantType := r.URL.Query().Get("type")
			wantName := r.URL.Query().Get("name")
			cfMu.Lock()
			var list []cfDNSRecord
			for _, rec := range records {
				if (wantType == "" || rec.Type == wantType) && (wantName == "" || rec.Name == wantName) {
					list = append(list, rec)
				}
			}
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/z1/dns_records":
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			cfMu.Lock()
			rec.ID = "r" + string(rune('a'+nextID))
			nextID++
			records[rec.ID] = rec
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = id
			cfMu.Lock()
			records[id] = rec
			cfMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			id := strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/")
			cfMu.Lock()
			delete(records, id)
			cfMu.Unlock()
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"`+id+`"}}`)
		}
	}))
	defer cfServer.Close()

	gw := newControllerTestGateway(t)
	gw.cloudflare.apiBase = cfServer.URL
	encCF, _ := gw.cloudflare.cipher.Encrypt("cf-tok-999")
	_ = gw.telemetry.SaveCloudflareDNS(context.Background(), cloudflareDNSStored{
		cloudflareDNSSettings: cloudflareDNSSettings{
			Enabled: true, ZoneID: "z1", RootDomain: "emby.test", TTL: 60,
		},
		EncryptedToken: encCF,
	})

	nodeA, enrA, _ := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name: "DE", ManualIPv4: "203.0.113.10",
	})
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrA, "1.0", "linux/amd64", "de")
	nodeB, enrB, _ := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{
		Name: "JP", ManualIPv4: "203.0.113.20",
	})
	nodeB, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrB, "1.0", "linux/amd64", "jp")
	now := time.Now()
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), nodeA.ID, 1, "s", "1.0", "linux/amd64", "de", "", "", "", now.Unix())
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(context.Background(), nodeB.ID, 1, "s", "1.0", "linux/amd64", "jp", "", "", "", now.Unix())

	// Mode 1: cloudflare_all -> syncs BOTH IPs
	domAll, err := gw.telemetry.CreateEdgeDomain(context.Background(), edgeDomainRecord{
		Domain: "all.emby.test", Name: "All", Enabled: true, NodeIDs: []string{nodeA.ID, nodeB.ID},
		DNSMode: domainDNSCloudflareAll, DNSIPMode: "ipv4", TLSMode: domainTLSExternal,
	})
	if err != nil {
		t.Fatalf("create domAll: %v", err)
	}
	if err := gw.cloudflare.SyncEdgeDomainDNS(context.Background(), domAll, "", now); err != nil {
		t.Fatalf("SyncEdgeDomainDNS all: %v", err)
	}

	ipsFor := func(name string) map[string]bool {
		cfMu.Lock()
		defer cfMu.Unlock()
		out := map[string]bool{}
		for _, r := range records {
			if r.Name == name && r.Type == "A" {
				out[r.Content] = true
			}
		}
		return out
	}
	gotAll := ipsFor("all.emby.test")
	if !gotAll["203.0.113.10"] || !gotAll["203.0.113.20"] || len(gotAll) != 2 {
		t.Fatalf("expected both A records for cloudflare_all, got %v", gotAll)
	}

	// Mode 2: cloudflare_failover -> points only to Node A, switches to Node B on drain
	domFail, err := gw.telemetry.CreateEdgeDomain(context.Background(), edgeDomainRecord{
		Domain: "play.emby.test", Name: "Play", Enabled: true, NodeIDs: []string{nodeA.ID, nodeB.ID},
		DNSMode: domainDNSCloudflareFailover, DNSIPMode: "ipv4", TLSMode: domainTLSExternal,
	})
	if err != nil {
		t.Fatalf("create domFail: %v", err)
	}
	if err := gw.cloudflare.SyncEdgeDomainDNS(context.Background(), domFail, "", now); err != nil {
		t.Fatalf("SyncEdgeDomainDNS failover #1: %v", err)
	}
	if got := ipsFor("play.emby.test"); !got["203.0.113.10"] || len(got) != 1 {
		t.Fatalf("expected play.emby.test -> 203.0.113.10, got %v", got)
	}

	// Drain Node A -> both all.emby.test and play.emby.test must immediately drop 203.0.113.10!
	_, _ = gw.telemetry.UpdateEdgeNode(context.Background(), nodeA.ID, edgeNodeUpdateInput{
		Name: nodeA.Name, ManualIPv4: "203.0.113.10", Draining: true,
	})
	if _, err := gw.cloudflare.EvaluateEdgeDomainsDNS(context.Background(), now); err != nil {
		t.Fatalf("EvaluateEdgeDomainsDNS after drain: %v", err)
	}
	if got := ipsFor("all.emby.test"); !got["203.0.113.20"] || len(got) != 1 {
		t.Fatalf("expected all.emby.test to drop drained node, got %v", got)
	}
	if got := ipsFor("play.emby.test"); !got["203.0.113.20"] || len(got) != 1 {
		t.Fatalf("expected play.emby.test to failover to 203.0.113.20, got %v", got)
	}
}

func TestControllerACMEDNS01CertificateIssuance(t *testing.T) {
	_, _, certDER := generateTestSelfSignedCert(t, "acme.emby.test")
	certPEMChain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Track Cloudflare TXT create + delete cleanup
	var cfMu sync.Mutex
	var createdTXTName, createdTXTVal string
	var deletedIDs []string
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/zones/z_acme/dns_records" {
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			cfMu.Lock()
			createdTXTName = rec.Name
			createdTXTVal = rec.Content
			cfMu.Unlock()
			rec.ID = "txt_rec_1"
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/zones/z_acme/dns_records/") {
			id := strings.TrimPrefix(r.URL.Path, "/zones/z_acme/dns_records/")
			cfMu.Lock()
			deletedIDs = append(deletedIDs, id)
			cfMu.Unlock()
			_, _ = io.WriteString(w, `{"success":true,"result":{"id":"`+id+`"}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cfServer.Close()

	// Minimal RFC 8555 ACME v2 mock server for DNS-01
	var acmeURL string
	acmeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte("nonce-123456")))
		switch r.URL.Path {
		case "/directory":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   acmeURL + "/nonce",
				"newAccount": acmeURL + "/account",
				"newOrder":   acmeURL + "/order",
			})
		case "/nonce":
			w.WriteHeader(http.StatusOK)
		case "/account":
			w.Header().Set("Location", acmeURL+"/acct/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"valid"}`)
		case "/order":
			w.Header().Set("Location", acmeURL+"/order/1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ready",
				"identifiers":    []map[string]string{{"type": "dns", "value": "acme.emby.test"}},
				"authorizations": []string{acmeURL + "/authz/1"},
				"finalize":       acmeURL + "/finalize/1",
			})
		case "/order/1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      "ready",
				"identifiers": []map[string]string{{"type": "dns", "value": "acme.emby.test"}},
				"finalize":    acmeURL + "/finalize/1",
			})
		case "/authz/1":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "valid",
				"identifier": map[string]string{"type": "dns", "value": "acme.emby.test"},
				"challenges": []map[string]any{
					{"type": "dns-01", "url": acmeURL + "/chal/1", "token": "tok_dns01_abc", "status": "valid"},
				},
			})
		case "/chal/1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"type":"dns-01","status":"valid","token":"tok_dns01_abc"}`)
		case "/finalize/1":
			// Sign the incoming CSR's public key so cert matches the generated key pair!
			var jws struct {
				Payload string `json:"payload"`
			}
			_ = json.NewDecoder(r.Body).Decode(&jws)
			rawPayload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
			var req struct {
				CSR string `json:"csr"`
			}
			_ = json.Unmarshal(rawPayload, &req)
			csrDER, _ := base64.RawURLEncoding.DecodeString(req.CSR)
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err == nil {
				caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(99),
					Subject:      pkix.Name{CommonName: "acme.emby.test", Organization: []string{"Mock LE"}},
					Issuer:       pkix.Name{CommonName: "Mock Let's Encrypt"},
					NotBefore:    time.Now().Add(-time.Hour),
					NotAfter:     time.Now().Add(90 * 24 * time.Hour),
					DNSNames:     csr.DNSNames,
				}
				if signedDER, signErr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, caKey); signErr == nil {
					certPEMChain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedDER})
				}
			}
			w.Header().Set("Location", acmeURL+"/order/1/done")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      "valid",
				"certificate": acmeURL + "/cert/1",
			})
		case "/order/1/done":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      "valid",
				"certificate": acmeURL + "/cert/1",
			})
		case "/cert/1":
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			_, _ = w.Write(certPEMChain)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer acmeServer.Close()
	acmeURL = acmeServer.URL

	// Make first /authz/1 call return pending so DNS-01 TXT creation & cleanup runs!
	var authzCalls int
	var authzMu sync.Mutex
	origHandler := acmeServer.Config.Handler
	acmeServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/authz/1" {
			authzMu.Lock()
			authzCalls++
			callNum := authzCalls
			authzMu.Unlock()
			if callNum == 1 {
				w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte("nonce-authz-1")))
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":     "pending",
					"identifier": map[string]string{"type": "dns", "value": "acme.emby.test"},
					"challenges": []map[string]any{
						{"type": "dns-01", "url": acmeURL + "/chal/1", "token": "tok_dns01_abc", "status": "pending"},
					},
				})
				return
			}
		}
		origHandler.ServeHTTP(w, r)
	})

	gw := newControllerTestGateway(t)
	gw.cloudflare.apiBase = cfServer.URL
	gw.cluster.acme.directoryURL = acmeURL + "/directory"
	gw.cluster.acme.propagationWait = 5 * time.Millisecond
	gw.cluster.acme.skipDNSCheck = true

	encCF, _ := gw.cloudflare.cipher.Encrypt("cf-acme-token")
	_ = gw.telemetry.SaveCloudflareDNS(context.Background(), cloudflareDNSStored{
		cloudflareDNSSettings: cloudflareDNSSettings{Enabled: true, ZoneID: "z_acme", RootDomain: "emby.test", TTL: 60},
		EncryptedToken:        encCF,
	})

	nodeA, enrA, _ := gw.telemetry.CreateEdgeNode(context.Background(), edgeNodeRecord{Name: "Edge 1"})
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(context.Background(), enrA, "1.0", "linux/amd64", "e1")

	dom, err := gw.telemetry.CreateEdgeDomain(context.Background(), edgeDomainRecord{
		Domain: "acme.emby.test", Name: "ACME Test", Enabled: true, NodeIDs: []string{nodeA.ID},
		DNSMode: domainDNSManual, TLSMode: domainTLSAuto,
	})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}

	if err := gw.cluster.acme.IssueDomainCertificate(context.Background(), dom.ID); err != nil {
		t.Fatalf("IssueDomainCertificate: %v", err)
	}

	// Verify Cloudflare TXT record created and cleaned up
	cfMu.Lock()
	if createdTXTName != "_acme-challenge.acme.emby.test" || createdTXTVal == "" {
		t.Fatalf("expected _acme-challenge.acme.emby.test TXT record, got name=%q val=%q", createdTXTName, createdTXTVal)
	}
	if len(deletedIDs) != 1 || deletedIDs[0] != "txt_rec_1" {
		t.Fatalf("expected TXT cleanup for txt_rec_1, got %v", deletedIDs)
	}
	cfMu.Unlock()

	// Verify stored cert state + config bundle contains managed_pem for Node A!
	updated, err := gw.telemetry.GetEdgeDomain(context.Background(), dom.ID)
	if err != nil || updated.CertStatus != "ready" || updated.CertPEM == "" || updated.KeyPEMEnc == "" {
		t.Fatalf("expected stored ready cert, got status=%q err=%v", updated.CertStatus, err)
	}
	bundle, err := gw.cluster.buildConfigBundle(context.Background(), nodeA)
	if err != nil || len(bundle.Domains) != 1 || bundle.Domains[0].TLSMode != "managed_pem" || bundle.Domains[0].CertPEM == "" || bundle.Domains[0].KeyPEM == "" {
		t.Fatalf("expected managed_pem in nodeA config bundle, got %+v err=%v", bundle.Domains, err)
	}
}

func TestEdgeDomainAndPerNodeSpeedLimits(t *testing.T) {
	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Configure global default speed limit = 50 Mbps
	rtReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/runtime-config", map[string]any{
		"default_upstream":                "",
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
		"max_download_mbps_per_ip":        50,
		"upstream_ip_mode":                "auto",
	})
	rtResp, err := adminClient.Do(rtReq)
	if err != nil || rtResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT runtime-config failed: err=%v status=%v", err, rtResp)
	}
	rtResp.Body.Close()

	// Create and enroll 2 agents (Node A + Node B)
	createAndEnroll := func(name string) (string, *Gateway) {
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
			"name": name, "group_name": "测试组", "region": "Test",
		})
		resp, err := adminClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("create node %s failed: err=%v status=%v", name, err, resp)
		}
		var out struct {
			Node   edgeNodeView `json:"node"`
			Deploy struct {
				EnrollToken string `json:"enroll_token"`
			} `json:"deploy"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()

		cfg := testConfig()
		cfg.Role = RoleAgent
		cfg.AdminEnabled = false
		cfg.AllowPrivateTargets = true
		cfg.AgentControllerURL = ctrlSrv.URL
		cfg.AgentEnrollToken = out.Deploy.EnrollToken
		cfg.AgentStatePath = filepath.Join(t.TempDir(), name+".json")
		cfg.AgentHeartbeatInterval = 500 * time.Millisecond
		cfg.AgentTelemetryInterval = time.Second
		gw := New(cfg)
		gw.agent.skipIPDetect.Store(true)
		t.Cleanup(gw.Close)
		return out.Node.ID, gw
	}

	nodeAID, agentA := createAndEnroll("node-a")
	nodeBID, agentB := createAndEnroll("node-b")

	// Domain 1: domain speed = 20 Mbps, per-IP conc = 4, AND nodeB overrides speed = 10 Mbps
	dom1Req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
		"domain":   "free.emby.test",
		"name":     "公益线",
		"enabled":  true,
		"node_ids": []string{nodeAID, nodeBID},
		"dns_mode": "manual",
		"tls_mode": "external",
		"overrides": map[string]any{
			"max_download_mbps_per_ip": 20,
			"max_concurrent_per_ip":    4,
		},
		"node_limits": map[string]any{
			nodeBID: map[string]any{
				"max_download_mbps_per_ip": 10,
			},
		},
	})
	dom1Resp, err := adminClient.Do(dom1Req)
	if err != nil || dom1Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create dom1 failed: err=%v status=%v", err, dom1Resp)
	}
	var dom1 edgeDomainView
	_ = json.NewDecoder(dom1Resp.Body).Decode(&dom1)
	dom1Resp.Body.Close()

	// Domain 2 on nodeA ONLY: explicitly unlimited (0 Mbps) overriding global 50 Mbps!
	dom2Req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
		"domain":   "vip.emby.test",
		"name":     "VIP线",
		"enabled":  true,
		"node_ids": []string{nodeAID},
		"dns_mode": "manual",
		"tls_mode": "external",
		"overrides": map[string]any{
			"max_download_mbps_per_ip": 0,
		},
	})
	dom2Resp, err := adminClient.Do(dom2Req)
	if err != nil || dom2Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create dom2 failed: err=%v status=%v", err, dom2Resp)
	}
	dom2Resp.Body.Close()

	// Verify API view returns per-node speed_limit_mbps on bound_nodes
	foundBOverride := false
	for _, bn := range dom1.BoundNodes {
		if bn.ID == nodeBID && bn.SpeedLimitMbps != nil && *bn.SpeedLimitMbps == 10 {
			foundBOverride = true
		}
		if bn.ID == nodeAID && bn.SpeedLimitMbps != nil {
			t.Fatalf("expected nodeA to inherit domain limit (nil SpeedLimitMbps), got %d", *bn.SpeedLimitMbps)
		}
	}
	if !foundBOverride {
		t.Fatalf("expected nodeB SpeedLimitMbps=10 in domain view, got %+v", dom1.BoundNodes)
	}

	// Sync both agents and assert exact per-domain & per-node bandwidth/concurrency limiters!
	if err := agentA.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("sync agentA: %v", err)
	}
	if err := agentB.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("sync agentB: %v", err)
	}

	want20 := int64(20) * 1_000_000 / 8
	want10 := int64(10) * 1_000_000 / 8

	// Agent A + free.emby.test -> 20 Mbps & per-IP concurrency 4
	_, bwA1, limA1, _, okA1, _ := agentA.matchAssignedDomain(httptest.NewRequest(http.MethodGet, "https://free.emby.test/", nil), agentA.liveRuntime())
	if !okA1 || bwA1 == nil || bwA1.Limit() != want20 {
		t.Fatalf("agentA free.emby.test want bw=%d, got ok=%v bw=%v", want20, okA1, bwA1)
	}
	if limA1 == nil {
		t.Fatalf("agentA free.emby.test expected per-domain concurrency limiter")
	}
	if _, perIP := limA1.Limits(); perIP != 4 {
		t.Fatalf("agentA free.emby.test want perIP=4, got %d", perIP)
	}

	// Agent A + vip.emby.test -> 0 (explicitly unlimited despite 50 Mbps global default!)
	_, bwA2, limA2, _, okA2, _ := agentA.matchAssignedDomain(httptest.NewRequest(http.MethodGet, "https://vip.emby.test/", nil), agentA.liveRuntime())
	if !okA2 || bwA2 == nil || bwA2.Limit() != 0 {
		t.Fatalf("agentA vip.emby.test want unlimited bw=0, got ok=%v bw=%v", okA2, bwA2)
	}
	if limA2 != nil {
		t.Fatalf("agentA vip.emby.test should fall back to default concurrency limiter")
	}

	// Agent B + free.emby.test -> 10 Mbps (per-machine override under domain!)
	_, bwB1, _, _, okB1, _ := agentB.matchAssignedDomain(httptest.NewRequest(http.MethodGet, "https://free.emby.test/", nil), agentB.liveRuntime())
	if !okB1 || bwB1 == nil || bwB1.Limit() != want10 {
		t.Fatalf("agentB free.emby.test want per-node bw=%d, got ok=%v bw=%v", want10, okB1, bwB1)
	}

	// Update dom1 removing nodeB -> node_limits[nodeB] should be pruned cleanly
	updReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/domains/"+dom1.ID, map[string]any{
		"domain":   "free.emby.test",
		"name":     "公益线",
		"enabled":  true,
		"node_ids": []string{nodeAID},
		"dns_mode": "manual",
		"tls_mode": "external",
		"overrides": map[string]any{
			"max_download_mbps_per_ip": 30,
		},
		"node_limits": map[string]any{
			nodeBID: map[string]any{"max_download_mbps_per_ip": 10},
		},
	})
	updResp, err := adminClient.Do(updReq)
	if err != nil || updResp.StatusCode != http.StatusOK {
		t.Fatalf("update dom1 failed: err=%v status=%v", err, updResp)
	}
	var updated edgeDomainView
	_ = json.NewDecoder(updResp.Body).Decode(&updated)
	updResp.Body.Close()
	if len(updated.NodeLimits) != 0 {
		t.Fatalf("expected removed nodeB limit to be pruned, got %+v", updated.NodeLimits)
	}

	// Hot-reload agentA: verify existing limiter instance is updated in place to 30 Mbps
	if err := agentA.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("resync agentA: %v", err)
	}
	_, bwA1After, _, _, _, _ := agentA.matchAssignedDomain(httptest.NewRequest(http.MethodGet, "https://free.emby.test/", nil), agentA.liveRuntime())
	want30 := int64(30) * 1_000_000 / 8
	if bwA1After != bwA1 || bwA1After.Limit() != want30 {
		t.Fatalf("expected in-place hot-reload to %d B/s, got samePtr=%v limit=%d", want30, bwA1After == bwA1, bwA1After.Limit())
	}
}

func TestAgentServesPublicFrontendWithoutDefaultUpstream(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dynamic-origin-ok")
	}))
	defer origin.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)
	discResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/nodes/discovery")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	var disc clusterDiscoveryView
	_ = json.NewDecoder(discResp.Body).Decode(&disc)
	discResp.Body.Close()

	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.TrustProxyHeaders = true
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = disc.Token
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "agent.json")
	cfg.AgentHeartbeatInterval = 300 * time.Millisecond
	cfg.AgentTelemetryInterval = time.Second
	agent := New(cfg)
	agent.agent.skipIPDetect.Store(true)
	t.Cleanup(agent.Close)
	nodeID, _, _, _ := agent.agent.Status()

	createDom := func(domain, defaultUpstream string) {
		overrides := map[string]any{
			"allow_unsigned_targets": true,
		}
		if defaultUpstream != "" {
			overrides["default_upstream"] = defaultUpstream
		}
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
			"domain":    domain,
			"name":      domain,
			"enabled":   true,
			"node_ids":  []string{nodeID},
			"dns_mode":  "manual",
			"tls_mode":  "external",
			"overrides": overrides,
		})
		res, err := adminClient.Do(req)
		if err != nil || res.StatusCode != http.StatusCreated {
			t.Fatalf("POST domain %s failed: err=%v res=%v", domain, err, res)
		}
		res.Body.Close()
	}

	createDom("open.emby.test", "")
	createDom("direct.emby.test", origin.URL)

	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("sync agent config: %v", err)
	}

	// 1. Matched domain WITHOUT default_upstream serves Refract public landing page on GET /
	rootRec := httptest.NewRecorder()
	rootReq := httptest.NewRequest(http.MethodGet, "http://open.emby.test/", nil)
	rootReq.RemoteAddr = "127.0.0.1:41000"
	rootReq.Header.Set("X-Forwarded-Proto", "https")
	agent.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK || !strings.Contains(rootRec.Body.String(), "Refract · 通用反向代理") {
		t.Fatalf("expected 200 public frontend on assigned agent root, got %d body=%q", rootRec.Code, rootRec.Body.String())
	}

	// 2. Public assets, avatar, and health report domain-specific public_base_url cleanly
	for _, assetPath := range []string{"/_gateway/assets/frontend.js", "/_gateway/assets/frontend.css", "/_gateway/avatar", "/_gateway/nodes", "/_gateway/emby-health"} {
		rec := httptest.NewRecorder()
		agent.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://open.emby.test"+assetPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on agent %s, got %d body=%q", assetPath, rec.Code, rec.Body.String())
		}
	}
	hRec := httptest.NewRecorder()
	hReq := httptest.NewRequest(http.MethodGet, "http://open.emby.test/_gateway/health", nil)
	hReq.RemoteAddr = "127.0.0.1:41001"
	hReq.Header.Set("X-Forwarded-Proto", "https")
	agent.ServeHTTP(hRec, hReq)
	var health map[string]any
	_ = json.NewDecoder(hRec.Body).Decode(&health)
	if hRec.Code != http.StatusOK || health["public_base_url"] != "https://open.emby.test" || health["role"] != RoleAgent {
		t.Fatalf("unexpected agent health response: code=%d payload=%#v", hRec.Code, health)
	}
	// Untrusted remote peer spoofing X-Forwarded-Proto must NOT elevate scheme to https
	hSpoofRec := httptest.NewRecorder()
	hSpoofReq := httptest.NewRequest(http.MethodGet, "http://open.emby.test/_gateway/health", nil)
	hSpoofReq.RemoteAddr = "198.51.100.77:41001"
	hSpoofReq.Header.Set("X-Forwarded-Proto", "https")
	agent.ServeHTTP(hSpoofRec, hSpoofReq)
	var healthSpoof map[string]any
	_ = json.NewDecoder(hSpoofRec.Body).Decode(&healthSpoof)
	if hSpoofRec.Code != http.StatusOK || healthSpoof["public_base_url"] != "http://open.emby.test" {
		t.Fatalf("untrusted X-Forwarded-Proto spoof should stay http, got code=%d payload=%#v", hSpoofRec.Code, healthSpoof)
	}

	// 3. Dynamic proxy still works on open.emby.test
	dynRec := httptest.NewRecorder()
	agent.ServeHTTP(dynRec, httptest.NewRequest(http.MethodGet, "https://open.emby.test/"+origin.URL+"/test", nil))
	if dynRec.Code != http.StatusOK || dynRec.Body.String() != "dynamic-origin-ok" {
		t.Fatalf("expected dynamic proxy 200, got %d body=%q", dynRec.Code, dynRec.Body.String())
	}

	// 4. Admin routes remain strictly disabled (404) on agent
	for _, blockedPath := range []string{"/login", "/panel", "/setup", "/_admin/api/overview"} {
		rec := httptest.NewRecorder()
		agent.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://open.emby.test"+blockedPath, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for admin path %s on agent, got %d", blockedPath, rec.Code)
		}
	}

	// 5. Unassigned host still returns 421 Misdirected Request
	rogueRec := httptest.NewRecorder()
	agent.ServeHTTP(rogueRec, httptest.NewRequest(http.MethodGet, "https://rogue.emby.test/", nil))
	if rogueRec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421 on unassigned host, got %d", rogueRec.Code)
	}

	// 6. Matched domain WITH default_upstream still proxies GET / directly to default upstream
	dirRec := httptest.NewRecorder()
	agent.ServeHTTP(dirRec, httptest.NewRequest(http.MethodGet, "https://direct.emby.test/", nil))
	if dirRec.Code != http.StatusOK || dirRec.Body.String() != "dynamic-origin-ok" {
		t.Fatalf("expected default_upstream proxy 200, got %d body=%q", dirRec.Code, dirRec.Body.String())
	}
}

func TestEdgeDomainPerDomainCDNRealIPAndIsolation(t *testing.T) {
	var lastXFF, lastXReal string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastXFF = r.Header.Get("X-Forwarded-For")
		lastXReal = r.Header.Get("X-Real-IP")
		_, _ = io.WriteString(w, "cdn-origin-ok")
	}))
	defer origin.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)
	discResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/nodes/discovery")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	var disc clusterDiscoveryView
	_ = json.NewDecoder(discResp.Body).Decode(&disc)
	discResp.Body.Close()

	// Agent has TRUST_PROXY_HEADERS=false globally (simulating Auto-TLS node with mixed CDN + direct domains).
	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.TrustProxyHeaders = false
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = disc.Token
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-cdn.json")
	cfg.AgentHeartbeatInterval = 300 * time.Millisecond
	cfg.AgentTelemetryInterval = time.Second
	agent := New(cfg)
	agent.agent.skipIPDetect.Store(true)
	t.Cleanup(agent.Close)
	nodeID, _, _, _ := agent.agent.Status()

	// Create WAF Geo rule (CN only) to prove real country detection behind CDN works per domain.
	wafReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/waf-rules", map[string]any{
		"name": "仅允许CN", "enabled": true, "is_global": false,
		"graph": wafRuleGraph{
			Nodes: []wafGraphNode{
				{ID: "s", Type: wafNodeStart},
				{ID: "g", Type: wafNodeGeoMatch, Config: wafNodeConfig{Countries: []string{"CN"}}},
				{ID: "p", Type: wafNodePass},
				{ID: "b", Type: wafNodeBlock, Config: wafNodeConfig{StatusCode: 403, Message: "geo denied"}},
			},
			Edges: []wafGraphEdge{
				{ID: "e1", Source: "s", SourcePort: "next", Target: "g"},
				{ID: "e2", Source: "g", SourcePort: "true", Target: "p"},
				{ID: "e3", Source: "g", SourcePort: "false", Target: "b"},
			},
		},
	})
	wafRes, err := adminClient.Do(wafReq)
	if err != nil || wafRes.StatusCode != http.StatusCreated {
		t.Fatalf("create geo WAF failed: err=%v res=%v", err, wafRes)
	}
	var geoRule wafRuleView
	_ = json.NewDecoder(wafRes.Body).Decode(&geoRule)
	wafRes.Body.Close()

	// Invalid CIDR must be rejected cleanly with 400
	badReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
		"domain": "bad.emby.test", "node_ids": []string{nodeID}, "dns_mode": "manual", "tls_mode": "external",
		"overrides": map[string]any{"trust_proxy_headers": true, "trusted_proxy_cidrs": "not-an-ip"},
	})
	badRes, err := adminClient.Do(badReq)
	if err != nil || badRes.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid trusted_proxy_cidrs, got err=%v res=%v", err, badRes)
	}
	badRes.Body.Close()

	createDom := func(domain string, overrides map[string]any, wafIDs []string) {
		req := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/domains", map[string]any{
			"domain":       domain,
			"name":         domain,
			"enabled":      true,
			"node_ids":     []string{nodeID},
			"dns_mode":     "manual",
			"tls_mode":     "external",
			"overrides":    overrides,
			"waf_rule_ids": wafIDs,
		})
		res, err := adminClient.Do(req)
		if err != nil || res.StatusCode != http.StatusCreated {
			t.Fatalf("POST domain %s failed: err=%v res=%v", domain, err, res)
		}
		res.Body.Close()
	}

	// Domain 1: Trusted specific CDN node IP (CDN-A 198.51.100.12), PassClientIP=true
	createDom("cdn.emby.test", map[string]any{
		"allow_unsigned_targets": true,
		"pass_client_ip":         true,
		"trust_proxy_headers":    true,
		"trusted_proxy_cidrs":    "198.51.100.12, 198.51.100.21",
	}, nil)
	// Domain 2: Direct domain on the SAME agent (no CDN override -> inherits TrustProxyHeaders=false)
	createDom("direct.emby.test", map[string]any{
		"allow_unsigned_targets": true,
		"pass_client_ip":         true,
	}, nil)
	// Domain 3: Wildcard CDN (0.0.0.0/0, ::/0) + custom header Ali-CDN-Real-IP + Geo WAF
	createDom("anycdn.emby.test", map[string]any{
		"allow_unsigned_targets": true,
		"pass_client_ip":         true,
		"trust_proxy_headers":    true,
		"trusted_proxy_cidrs":    "0.0.0.0/0, ::/0",
		"real_ip_header":         "Ali-CDN-Real-IP",
	}, []string{geoRule.ID})
	// Domain 4: Cloudflare CDN + explicit CF-Connecting-IP + Geo WAF
	createDom("cfcdn.emby.test", map[string]any{
		"allow_unsigned_targets": true,
		"pass_client_ip":         true,
		"trust_proxy_headers":    true,
		"trusted_proxy_cidrs":    "198.51.100.12",
		"real_ip_header":         "CF-Connecting-IP",
	}, []string{geoRule.ID})

	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("sync agent config: %v", err)
	}
	geoMap := map[string]string{
		"203.0.113.102": "CN",
		"203.0.113.17":  "CN",
		"203.0.113.99":  "US",
	}
	agent.ipCountries.Store(&geoMap)

	// 1. Trusted CDN peer on cdn.emby.test -> extracts real user IP 203.0.113.102 and forwards it upstream
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://cdn.emby.test/"+origin.URL+"/stream", nil)
	req.RemoteAddr = "198.51.100.12:41001"
	req.Header.Set("X-Real-IP", "203.0.113.102")
	req.Header.Set("X-Forwarded-For", "203.0.113.102, 198.51.100.12")
	agent.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || lastXFF != "203.0.113.102" || lastXReal != "203.0.113.102" {
		t.Fatalf("trusted CDN peer on cdn.emby.test: code=%d xff=%q xreal=%q", rec.Code, lastXFF, lastXReal)
	}

	// 2. Untrusted public IP spoofing X-Real-IP on cdn.emby.test -> spoofed header IGNORED, uses RemoteAddr 198.51.100.77
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "https://cdn.emby.test/"+origin.URL+"/stream", nil)
	req2.RemoteAddr = "198.51.100.77:41002"
	req2.Header.Set("X-Real-IP", "1.1.1.1")
	agent.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || lastXFF != "198.51.100.77" {
		t.Fatalf("untrusted peer spoofing on cdn.emby.test should fall back to RemoteAddr, got code=%d xff=%q", rec2.Code, lastXFF)
	}

	// 3. Direct domain on SAME agent ignores X-Real-IP even from 198.51.100.12 (strict per-domain isolation!)
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "https://direct.emby.test/"+origin.URL+"/stream", nil)
	req3.RemoteAddr = "198.51.100.12:41003"
	req3.Header.Set("X-Real-IP", "203.0.113.102")
	agent.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || lastXFF != "198.51.100.12" {
		t.Fatalf("direct domain must NOT trust CDN headers, got code=%d xff=%q", rec3.Code, lastXFF)
	}

	// 4. Wildcard CDN domain: multi-hop XFF returns leftmost real client IP (not rightmost CDN hop!) + custom header
	rec4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "https://anycdn.emby.test/"+origin.URL+"/stream", nil)
	req4.RemoteAddr = "203.0.113.55:41004"
	req4.Header.Set("X-Forwarded-For", "203.0.113.102, 203.0.113.55")
	agent.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK || lastXFF != "203.0.113.102" {
		t.Fatalf("wildcard CDN multi-hop XFF expected leftmost 203.0.113.102, got code=%d xff=%q", rec4.Code, lastXFF)
	}

	rec5 := httptest.NewRecorder()
	req5 := httptest.NewRequest(http.MethodGet, "https://anycdn.emby.test/"+origin.URL+"/stream", nil)
	req5.RemoteAddr = "203.0.113.55:41005"
	req5.Header.Set("Ali-CDN-Real-IP", "203.0.113.17")
	req5.Header.Set("X-Real-IP", "203.0.113.55")
	agent.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusOK || lastXFF != "203.0.113.17" {
		t.Fatalf("custom real_ip_header Ali-CDN-Real-IP expected 203.0.113.17, got code=%d xff=%q", rec5.Code, lastXFF)
	}

	// 5. Spoofed CF-IPCountry on non-Cloudflare header domain (Ali-CDN-Real-IP) is ignored
	rec6 := httptest.NewRecorder()
	req6 := httptest.NewRequest(http.MethodGet, "https://anycdn.emby.test/"+origin.URL+"/stream", nil)
	req6.RemoteAddr = "203.0.113.55:41006"
	req6.Header.Set("Ali-CDN-Real-IP", "203.0.113.17")
	req6.Header.Set("CF-IPCountry", "US")
	agent.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusOK {
		t.Fatalf("non-Cloudflare real_ip_header Ali-CDN-Real-IP must ignore spoofed CF-IPCountry: US, got %d body=%s", rec6.Code, rec6.Body.String())
	}
	rec7 := httptest.NewRecorder()
	req7 := httptest.NewRequest(http.MethodGet, "https://anycdn.emby.test/"+origin.URL+"/stream", nil)
	req7.RemoteAddr = "203.0.113.55:41007"
	req7.Header.Set("Ali-CDN-Real-IP", "203.0.113.99")
	req7.Header.Set("CF-IPCountry", "CN")
	agent.ServeHTTP(rec7, req7)
	if rec7.Code != http.StatusForbidden {
		t.Fatalf("non-Cloudflare domain must ignore spoofed CF-IPCountry: CN bypass for US IP, got %d body=%s", rec7.Code, rec7.Body.String())
	}

	// 6. Trusted Cloudflare CDN domain honors CF-IPCountry
	rec8 := httptest.NewRecorder()
	req8 := httptest.NewRequest(http.MethodGet, "https://cfcdn.emby.test/"+origin.URL+"/stream", nil)
	req8.RemoteAddr = "198.51.100.12:41008"
	req8.Header.Set("CF-Connecting-IP", "203.0.113.17")
	req8.Header.Set("CF-IPCountry", "US")
	agent.ServeHTTP(rec8, req8)
	if rec8.Code != http.StatusForbidden {
		t.Fatalf("Cloudflare real_ip_header CF-Connecting-IP expected 403 for CF-IPCountry=US, got %d body=%s", rec8.Code, rec8.Body.String())
	}
}
