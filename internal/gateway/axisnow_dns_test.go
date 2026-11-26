package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAxisNowSmartDNSFullLifecycleAndCloudflareCNAME(t *testing.T) {
	t.Parallel()

	// Mock AxisNow API state
	var anMu sync.Mutex
	routingDomains := map[string]axisnowRemoteRoutingDomain{}
	routingRules := map[string]axisnowRemoteRuleEntity{}
	createOrder := []string{}
	rulePutCount := 0
	domainSeq := 0
	ruleSeq := 0

	anServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/policy/metadata/geo_isp" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "messages": []string{}, "errors": []any{},
				"result": []axisnowGeoISPProviderGroup{
					{
						ProviderType: "alibaba-cloud",
						List: []axisnowGeoISPPlan{{
							ProviderPlan: "free",
							Options: []axisnowGeoISPOption{
								{DisplayName: "默认", Value: "default"},
								{DisplayName: "联通", Value: "unicom"},
								{DisplayName: "移动", Value: "mobile"},
							},
						}},
					},
				},
			})
			return
		}
		if r.Header.Get("Authorization") != "Bearer an-secret-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false, "messages": []string{},
				"errors": []axisnowAPIError{{Code: 200201, Message: "invalid_token"}},
			})
			return
		}

		anMu.Lock()
		defer anMu.Unlock()

		switch {
		case r.URL.Path == "/api_tokens_verifications" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "messages": []string{}, "errors": []any{},
				"result": axisnowTokenVerification{
					UUID: "tok-1", TenantUUID: "ten-1", Name: "refract-dns",
				},
			})
		case r.URL.Path == "/system_dns_providers" && r.Method == http.MethodPost:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "messages": []string{}, "errors": []any{},
				"result": []map[string]any{
					{
						"uuid": "sys-ali-1", "name": "阿里云托管调度域", "type": "alibaba-cloud", "source": "platform",
						"zones": []map[string]any{
							{"uuid": "zone-ali-1", "name": "axisnow-edge.io", "zone": "axisnow-edge.io", "conf": map[string]any{"zone_id": "z1", "zone": "axisnow-edge.io", "plan": "free"}},
						},
					},
				},
			})
		case r.URL.Path == "/dns_providers" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true, "messages": []string{}, "errors": []any{},
				"result": []map[string]any{},
			})
		case r.URL.Path == "/dns_routing_domains/filter" && r.Method == http.MethodPost:
			list := make([]axisnowRemoteRoutingDomain, 0, len(routingDomains))
			for _, d := range routingDomains {
				list = append(list, d)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": list})
		case r.URL.Path == "/dns_routing_domains" && r.Method == http.MethodPost:
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			domainSeq++
			id := "dom-" + string(rune('a'+domainSeq))
			desc, _ := req["description"].(string)
			dom := axisnowRemoteRoutingDomain{
				UUID:           id,
				Name:           req["name"].(string),
				Description:    desc,
				Domain:         req["domain"].(string),
				DNSProviderID:  req["dns_provider_uuid"].(string),
				RecordType:     req["record_type"].(string),
				ProviderSource: req["provider_source"].(string),
				Status:         "active",
			}
			routingDomains[id] = dom
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": dom})
		case strings.HasPrefix(r.URL.Path, "/dns_routing_domains/") && r.Method == http.MethodGet:
			id := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			dom, ok := routingDomains[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []axisnowAPIError{{Code: 404, Message: "not found"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": dom})
		case strings.HasPrefix(r.URL.Path, "/dns_routing_domains/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			delete(routingDomains, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}})
		case r.URL.Path == "/dns_routing_rules/filter" && r.Method == http.MethodPost:
			list := make([]axisnowRemoteRuleEntity, 0, len(routingRules))
			for _, rr := range routingRules {
				list = append(list, rr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": list})
		case r.URL.Path == "/dns_routing_rules" && r.Method == http.MethodPost:
			var req axisnowRemoteRulePayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			createOrder = append(createOrder, req.GeoISP)
			ruleSeq++
			id := "rule-" + string(rune('a'+ruleSeq))
			ent := axisnowRemoteRuleEntity{
				UUID: id, Domain: req.Domain, Type: req.Type, GeoISP: req.GeoISP,
				Name: req.Name, Description: req.Description, DNSDomainUUID: req.DNSDomainUUID,
				Action: req.Action, Status: req.Status, AutoPauseOnEmpty: req.AutoPauseOnEmpty,
			}
			routingRules[id] = ent
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": ent})
		case strings.HasPrefix(r.URL.Path, "/dns_routing_rules/") && r.Method == http.MethodPut:
			id := strings.TrimPrefix(r.URL.Path, "/dns_routing_rules/")
			var req axisnowRemoteRulePayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			rulePutCount++
			ent := axisnowRemoteRuleEntity{
				UUID: id, Domain: req.Domain, Type: req.Type, GeoISP: req.GeoISP,
				Name: req.Name, Description: req.Description, DNSDomainUUID: req.DNSDomainUUID,
				Action: req.Action, Status: req.Status, AutoPauseOnEmpty: req.AutoPauseOnEmpty,
			}
			routingRules[id] = ent
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}, "result": ent})
		case strings.HasPrefix(r.URL.Path, "/dns_routing_rules/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/dns_routing_rules/")
			delete(routingRules, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "messages": []string{}, "errors": []any{}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer anServer.Close()

	// Mock Cloudflare API to verify stale A deletion + gray-cloud CNAME upsert
	var cfMu sync.Mutex
	cfRecords := map[string]cfDNSRecord{
		"old-a-1": {ID: "old-a-1", Type: "A", Name: "emby.example.test", Content: "198.51.100.1", TTL: 60, Proxied: false},
	}
	cfSeq := 0
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfMu.Lock()
		defer cfMu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/dns_records"):
			recType := r.URL.Query().Get("type")
			recName := r.URL.Query().Get("name")
			out := []cfDNSRecord{}
			for _, rec := range cfRecords {
				if (recType == "" || rec.Type == recType) && (recName == "" || strings.EqualFold(rec.Name, recName)) {
					out = append(out, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records"):
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			cfSeq++
			rec.ID = "cf-" + string(rune('a'+cfSeq))
			cfRecords[rec.ID] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/dns_records/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			var rec cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = id
			cfRecords[id] = rec
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rec})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/dns_records/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			delete(cfRecords, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": id}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer cfServer.Close()

	gw := newControllerTestGateway(t)
	gw.axisnow.apiBase = anServer.URL
	gw.cloudflare.apiBase = cfServer.URL

	ctx := context.Background()
	encAN, _ := gw.axisnow.cipher.Encrypt("an-secret-token")
	if err := gw.telemetry.SaveAxisNowDNS(ctx, axisnowDNSStored{
		axisnowDNSSettings: axisnowDNSSettings{
			Enabled:               true,
			APIBase:               anServer.URL,
			DefaultProviderUUID:   "sys-ali-1",
			DefaultProviderSource: "platform",
			DefaultProviderType:   "alibaba-cloud",
			DefaultZoneUUID:       "zone-ali-1",
			DefaultZoneName:       "axisnow-edge.io",
			DefaultZonePlan:       "free",
		},
		EncryptedToken: encAN,
	}); err != nil {
		t.Fatalf("SaveAxisNowDNS: %v", err)
	}

	encCF, _ := gw.cloudflare.cipher.Encrypt("cf-tok-test")
	_ = gw.telemetry.SaveCloudflareDNS(ctx, cloudflareDNSStored{
		cloudflareDNSSettings: cloudflareDNSSettings{
			Enabled: true, ZoneID: "z_cf", RootDomain: "example.test", TTL: 60,
		},
		EncryptedToken: encCF,
	})

	// 1. Test connection + metadata fetch
	testRes, err := gw.axisnow.TestConnection(ctx, "", "")
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if testRes.TokenName != "refract-dns" || len(testRes.Providers) != 1 || len(testRes.Providers[0].Zones) != 1 {
		t.Fatalf("unexpected TestConnection result: %+v", testRes)
	}
	meta := gw.axisnow.GetGeoISPMetadata(ctx, true)
	if meta.Source != "live" || len(meta.Providers) != 1 {
		t.Fatalf("expected live metadata, got %+v", meta)
	}

	// 2. Register two online nodes: DE (9929) & JP (IIJ)
	now := time.Now()
	nodeDE, enrDE, err := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{
		Name: "德国 9929", Region: "DE", ManualIPv4: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode DE: %v", err)
	}
	nodeDE, _, err = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrDE, "1.0", "linux/amd64", "de")
	if err != nil {
		t.Fatalf("Enroll DE: %v", err)
	}
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeDE.ID, 1, "s", "1.0", "linux/amd64", "de", "", "", "", now.Unix())

	nodeJP, enrJP, err := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{
		Name: "日本 IIJ", Region: "JP", ManualIPv4: "203.0.113.20",
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode JP: %v", err)
	}
	nodeJP, _, err = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrJP, "1.0", "linux/amd64", "jp")
	if err != nil {
		t.Fatalf("Enroll JP: %v", err)
	}
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeJP.ID, 1, "s", "1.0", "linux/amd64", "jp", "", "", "", now.Unix())

	// 3. Create domain with axisnow_smart (deliberately pass non-default lines first to verify default-first ordering!)
	dom, err := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain:  "emby.example.test",
		Name:    "Emby 主站",
		Enabled: true,
		NodeIDs: []string{nodeDE.ID, nodeJP.ID},
		DNSMode: domainDNSAxisNowSmart,
		SmartDNS: normalizeEdgeDomainSmartDNS(&edgeDomainSmartDNS{
			AutoCFCNAME: true,
			Lines: []smartDNSLineRule{
				{GeoISP: "unicom", Label: "中国联通", NodeIDs: []string{nodeDE.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, AutoPauseOnEmpty: true, Enabled: true},
				{GeoISP: "mobile", Label: "中国移动", NodeIDs: []string{nodeJP.ID, nodeDE.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, AutoPauseOnEmpty: true, Enabled: true},
				{GeoISP: "default", Label: "默认兜底", NodeIDs: []string{nodeJP.ID, nodeDE.ID}, ElectionStrategy: "random", IPQuantity: 2, Enabled: true},
			},
		}, []string{nodeDE.ID, nodeJP.ID}, nil),
	})
	if err != nil {
		t.Fatalf("CreateEdgeDomain: %v", err)
	}

	// 4. First sync while AxisNow CNAME target has NOT yet propagated in public DNS:
	// creates platform routing domain & rules (default FIRST), but MUST keep existing Cloudflare A record untouched!
	var probeReadyMu sync.Mutex
	probeReady := false
	probeCalls := 0
	gw.axisnow.cnameReadyProbe = func(ctx context.Context, host string) (bool, []string, string) {
		probeReadyMu.Lock()
		defer probeReadyMu.Unlock()
		probeCalls++
		if !probeReady {
			return false, nil, "等待 AxisNow 解析生效（公网 DNS 0/3 已解析），暂保留原 Cloudflare 记录"
		}
		return true, []string{"203.0.113.10"}, "公网 DNS 3/3 已解析（203.0.113.10）"
	}

	if err := gw.axisnow.SyncEdgeDomainSmartDNS(ctx, dom, now); err != nil {
		t.Fatalf("SyncEdgeDomainSmartDNS #1 (pending cutover): %v", err)
	}
	if len(createOrder) != 3 || createOrder[0] != "default" {
		t.Fatalf("expected default rule created first, got order %v", createOrder)
	}
	// Verify every AxisNow rule includes valid ttl_conf so AxisNow's backend generates /dns_records
	anMu.Lock()
	for _, rr := range routingRules {
		if rr.Action.Conf.TTLConf == nil || rr.Action.Conf.TTLConf.ProviderType != "alibaba-cloud" || rr.Action.Conf.TTLConf.TTL < 60 {
			anMu.Unlock()
			t.Fatalf("expected valid ttl_conf on AxisNow rule %s, got %+v", rr.GeoISP, rr.Action.Conf.TTLConf)
		}
	}
	anMu.Unlock()
	// Verify Cloudflare STILL has original A record and ZERO CNAME (zero-downtime protection!)
	cfMu.Lock()
	var cnameRec *cfDNSRecord
	aCount := 0
	for _, r := range cfRecords {
		if r.Type == "A" {
			aCount++
		}
		if r.Type == "CNAME" {
			cp := r
			cnameRec = &cp
		}
	}
	cfMu.Unlock()
	if aCount != 1 || cnameRec != nil {
		t.Fatalf("expected original CF A record preserved while AxisNow DNS is not ready, got aCount=%d cname=%+v", aCount, cnameRec)
	}
	pendingDom, err := gw.telemetry.GetEdgeDomain(ctx, dom.ID)
	if err != nil || pendingDom.SmartDNS == nil || pendingDom.SmartDNS.CFCNAMESynced || pendingDom.SmartDNS.CFCNAMEStatus != "pending" {
		t.Fatalf("expected cf_cname_status=pending & cf_cname_synced=false, got %+v err=%v", pendingDom.SmartDNS, err)
	}

	// 4b. Background monitor tick while still not ready -> probes DNS ONLY (zero AxisNow PUTs), still preserves CF A record
	if _, err := gw.axisnow.EvaluateEdgeDomainsSmartDNS(ctx, now.Add(15*time.Second)); err != nil {
		t.Fatalf("EvaluateEdgeDomainsSmartDNS (still pending): %v", err)
	}
	anMu.Lock()
	putsWhilePending := rulePutCount
	anMu.Unlock()
	if putsWhilePending != 0 {
		t.Fatalf("expected 0 redundant AxisNow PUTs while waiting for DNS propagation, got %d", putsWhilePending)
	}

	// 4c. Public DNS now resolves AxisNow CNAME target -> next monitor tick automatically swaps CF A -> gray-cloud CNAME!
	probeReadyMu.Lock()
	probeReady = true
	probeReadyMu.Unlock()
	if _, err := gw.axisnow.EvaluateEdgeDomainsSmartDNS(ctx, now.Add(30*time.Second)); err != nil {
		t.Fatalf("EvaluateEdgeDomainsSmartDNS (ready cutover): %v", err)
	}
	cfMu.Lock()
	cnameRec = nil
	aCount = 0
	for _, r := range cfRecords {
		if r.Type == "A" {
			aCount++
		}
		if r.Type == "CNAME" {
			cp := r
			cnameRec = &cp
		}
	}
	cfMu.Unlock()
	if aCount != 0 || cnameRec == nil || cnameRec.Proxied || !strings.HasSuffix(cnameRec.Content, ".axisnow-edge.io") || strings.Contains(cnameRec.Content, "_") {
		t.Fatalf("expected stale A removed and RFC-valid gray-cloud CNAME to axisnow-edge.io after DNS ready, got aCount=%d cname=%+v", aCount, cnameRec)
	}
	syncedDom, err := gw.telemetry.GetEdgeDomain(ctx, dom.ID)
	if err != nil || syncedDom.SmartDNS == nil || !syncedDom.SmartDNS.CFCNAMESynced || syncedDom.SmartDNS.CFCNAMEStatus != "synced" {
		t.Fatalf("expected cf_cname_status=synced & cf_cname_synced=true, got %+v err=%v", syncedDom.SmartDNS, err)
	}

	// Verify Smart DNS profile inheriting empty default ProviderUUID/ZoneUUID preserves RoutingDomainUUID across syncs!
	prof, err := gw.telemetry.CreateSmartDNSProfile(ctx, smartDNSProfileRecord{
		Name:           "默认托管方案",
		ProviderSource: "platform",
		AutoCFCNAME:    true,
		Lines:          syncedDom.SmartDNS.Lines,
	})
	if err != nil {
		t.Fatalf("CreateSmartDNSProfile: %v", err)
	}
	mergedWithEmptyProvider := applySmartDNSProfileToDomain(prof, syncedDom.SmartDNS, false)
	if mergedWithEmptyProvider.RoutingDomainUUID != syncedDom.SmartDNS.RoutingDomainUUID ||
		mergedWithEmptyProvider.RoutingDomainHost != syncedDom.SmartDNS.RoutingDomainHost ||
		!mergedWithEmptyProvider.CFCNAMESynced {
		t.Fatalf("expected profile with empty default provider to preserve routing domain & CF CNAME state, got %+v vs %+v", mergedWithEmptyProvider, syncedDom.SmartDNS)
	}

	// 5. Idempotent second sync -> zero PUT calls!
	reloaded, err := gw.telemetry.GetEdgeDomain(ctx, dom.ID)
	if err != nil {
		t.Fatalf("GetEdgeDomain: %v", err)
	}
	if err := gw.axisnow.SyncEdgeDomainSmartDNS(ctx, reloaded, now); err != nil {
		t.Fatalf("SyncEdgeDomainSmartDNS #2: %v", err)
	}
	if rulePutCount != 0 {
		t.Fatalf("expected idempotent second sync with 0 PUTs, got %d", rulePutCount)
	}

	// 6. Drain DE node -> unicom auto-pauses (auto_pause_on_empty), mobile & default shrink to JP only!
	if _, err := gw.telemetry.UpdateEdgeNode(ctx, nodeDE.ID, edgeNodeUpdateInput{
		Name: nodeDE.Name, Region: nodeDE.Region, ManualIPv4: nodeDE.ManualIPv4, Draining: true,
	}); err != nil {
		t.Fatalf("UpdateEdgeNode drain: %v", err)
	}
	if _, err := gw.axisnow.EvaluateEdgeDomainsSmartDNS(ctx, now); err != nil {
		t.Fatalf("EvaluateEdgeDomainsSmartDNS after drain: %v", err)
	}
	afterDrain, err := gw.telemetry.GetEdgeDomain(ctx, dom.ID)
	if err != nil {
		t.Fatalf("GetEdgeDomain after drain: %v", err)
	}
	lineByGeo := map[string]smartDNSLineRule{}
	for _, l := range afterDrain.SmartDNS.Lines {
		lineByGeo[l.GeoISP] = l
	}
	if lineByGeo["unicom"].Status != "paused" {
		t.Fatalf("expected unicom line auto-paused when DE drained, got %+v", lineByGeo["unicom"])
	}
	if len(lineByGeo["mobile"].ActiveIPs) != 1 || lineByGeo["mobile"].ActiveIPs[0] != "203.0.113.20" {
		t.Fatalf("expected mobile line shrunk to JP IP, got %+v", lineByGeo["mobile"])
	}

	// 7. Delete domain -> cleans up AxisNow routing domain + Cloudflare CNAME
	gw.axisnow.DeleteEdgeDomainSmartDNS(ctx, afterDrain)
	anMu.Lock()
	remDomains := len(routingDomains)
	anMu.Unlock()
	cfMu.Lock()
	remCF := len(cfRecords)
	cfMu.Unlock()
	if remDomains != 0 || remCF != 0 {
		t.Fatalf("expected cleanup of remote domain and CF CNAME, got remDomains=%d remCF=%d", remDomains, remCF)
	}
}

func TestSmartDNSProfileReusableBindingAndPropagation(t *testing.T) {
	t.Parallel()
	gw := newControllerTestGateway(t)
	ctx := context.Background()
	now := time.Now()

	nodeA, enrA, _ := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{Name: "德国 9929", Region: "DE", ManualIPv4: "203.0.113.11"})
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrA, "1.0", "linux/amd64", "de")
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeA.ID, 1, "s", "1.0", "linux/amd64", "de", "", "", "", now.Unix())

	nodeB, enrB, _ := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{Name: "日本 IIJ", Region: "JP", ManualIPv4: "203.0.113.22"})
	nodeB, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrB, "1.0", "linux/amd64", "jp")
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeB.ID, 1, "s", "1.0", "linux/amd64", "jp", "", "", "", now.Unix())

	// 1. Create reusable Smart DNS profile BEFORE creating/binding domains
	prof, err := gw.telemetry.CreateSmartDNSProfile(ctx, smartDNSProfileRecord{
		Name:           "中国三网优化",
		Description:    "联通走德国 9929，移动走日本 IIJ",
		ProviderSource: "platform",
		ProviderType:   "alibaba-cloud",
		AutoCFCNAME:    true,
		Lines: []smartDNSLineRule{
			{GeoISP: "default", Label: "默认兜底", NodeIDs: []string{nodeB.ID, nodeA.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, Enabled: true},
			{GeoISP: "unicom", Label: "中国联通", NodeIDs: []string{nodeA.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, AutoPauseOnEmpty: true, Enabled: true},
			{GeoISP: "mobile", Label: "中国移动", NodeIDs: []string{nodeB.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, AutoPauseOnEmpty: true, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("CreateSmartDNSProfile: %v", err)
	}

	// 2. Bind domain to the profile
	dom, err := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain:   "media.example.test",
		Name:     "媒体主站",
		Enabled:  true,
		NodeIDs:  []string{nodeA.ID},
		DNSMode:  domainDNSAxisNowSmart,
		SmartDNS: applySmartDNSProfileToDomain(prof, nil, false),
	})
	if err != nil {
		t.Fatalf("CreateEdgeDomain: %v", err)
	}

	views, err := gw.cluster.ListSmartDNSProfileViews(ctx)
	if err != nil || len(views.Profiles) != 1 || len(views.Profiles[0].BoundDomains) != 1 {
		t.Fatalf("expected 1 profile with 1 bound domain, got %+v err=%v", views, err)
	}

	// 3. Update profile -> propagates new node & line config to bound domain
	prof.Name = "三网尊享版"
	prof.Lines = append(prof.Lines, smartDNSLineRule{
		GeoISP: "telecom", Label: "中国电信", NodeIDs: []string{nodeA.ID, nodeB.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, AutoPauseOnEmpty: true, Enabled: true,
	})
	updatedProf, err := gw.telemetry.UpdateSmartDNSProfile(ctx, prof.ID, prof)
	if err != nil {
		t.Fatalf("UpdateSmartDNSProfile: %v", err)
	}
	gw.cluster.propagateSmartDNSProfileUpdate(ctx, updatedProf)

	reloadedDom, err := gw.telemetry.GetEdgeDomain(ctx, dom.ID)
	if err != nil {
		t.Fatalf("GetEdgeDomain: %v", err)
	}
	if reloadedDom.SmartDNS == nil || reloadedDom.SmartDNS.ProfileName != "三网尊享版" || len(reloadedDom.SmartDNS.Lines) != 4 {
		t.Fatalf("expected propagated profile update (4 lines, new name), got %+v", reloadedDom.SmartDNS)
	}
	if len(reloadedDom.NodeIDs) != 2 {
		t.Fatalf("expected node union propagated to domain NodeIDs, got %v", reloadedDom.NodeIDs)
	}
}

func TestAxisNowSmartDNSProfileSharesSingleRoutingDomainAndFreesOrphanedQuota(t *testing.T) {
	t.Parallel()
	gw := newControllerTestGateway(t)
	ctx := context.Background()
	now := time.Now()

	var anMu sync.Mutex
	domainCreateCount := 0
	routingDomains := map[string]axisnowRemoteRoutingDomain{}
	routingRules := map[string]axisnowRemoteRuleEntity{}
	anSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		anMu.Lock()
		defer anMu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/dns_routing_domains":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			domainCreateCount++
			uid := fmt.Sprintf("rd-shared-%d", domainCreateCount)
			host, _ := req["domain"].(string)
			desc, _ := req["description"].(string)
			provID, _ := req["dns_provider_uuid"].(string)
			zoneID, _ := req["dns_zone_uuid"].(string)
			src, _ := req["provider_source"].(string)
			rd := axisnowRemoteRoutingDomain{
				UUID: uid, Domain: host, Description: desc, Status: "active",
				ProviderType: "alibaba-cloud", ProviderSource: src, DNSProviderID: provID, DNSZoneID: zoneID,
			}
			routingDomains[uid] = rd
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rd})
		case r.Method == http.MethodPost && r.URL.Path == "/dns_routing_domains/filter":
			list := make([]axisnowRemoteRoutingDomain, 0, len(routingDomains))
			for _, rd := range routingDomains {
				list = append(list, rd)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns_routing_domains/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			rd, ok := routingDomains[uid]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []axisnowAPIError{{Code: 404, Message: "not found"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": rd})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dns_routing_domains/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			delete(routingDomains, uid)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/dns_routing_rules/filter":
			list := make([]axisnowRemoteRuleEntity, 0, len(routingRules))
			for _, rr := range routingRules {
				list = append(list, rr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodPost && r.URL.Path == "/dns_routing_rules":
			var req axisnowRemoteRulePayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			uid := fmt.Sprintf("rl-%d", len(routingRules)+1)
			ent := axisnowRemoteRuleEntity{
				UUID: uid, Domain: req.Domain, Type: req.Type, GeoISP: req.GeoISP,
				Name: req.Name, Description: req.Description, DNSDomainUUID: req.DNSDomainUUID,
				Action: req.Action, Status: req.Status,
			}
			routingRules[uid] = ent
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": ent})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/dns_routing_rules/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_rules/")
			var req axisnowRemoteRulePayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			ent := routingRules[uid]
			ent.Action = req.Action
			ent.Status = req.Status
			ent.Description = req.Description
			routingRules[uid] = ent
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": ent})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		}
	}))
	defer anSrv.Close()

	var cfMu sync.Mutex
	cfRecords := map[string]cfDNSRecord{}
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfMu.Lock()
		defer cfMu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/dns_records"):
			name := r.URL.Query().Get("name")
			res := []cfDNSRecord{}
			for _, rec := range cfRecords {
				if name == "" || strings.EqualFold(rec.Name, name) {
					res = append(res, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": res})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records"):
			var body cfDNSRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			body.ID = fmt.Sprintf("cf-%d", len(cfRecords)+1)
			cfRecords[body.ID] = body
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": body})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/dns_records/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			delete(cfRecords, id)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": id}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		}
	}))
	defer cfSrv.Close()

	gw.axisnow.apiBase = anSrv.URL
	gw.axisnow.cnameReadyProbe = func(_ context.Context, _ string) (bool, []string, string) {
		return true, []string{"203.0.113.11"}, "公网 DNS 已解析（203.0.113.11）"
	}
	gw.cloudflare.apiBase = cfSrv.URL

	encAn, _ := gw.axisnow.cipher.Encrypt("an-tok")
	_ = gw.telemetry.SaveAxisNowDNS(ctx, axisnowDNSStored{
		axisnowDNSSettings: axisnowDNSSettings{
			Enabled: true, TokenSet: true, APIBase: anSrv.URL, DefaultProviderUUID: "prov-ali", DefaultProviderSource: "platform",
			DefaultProviderType: "alibaba-cloud", DefaultZoneUUID: "zone-1", DefaultZoneName: "alidns-2.com", DefaultZonePlan: "free",
		},
		EncryptedToken: encAn,
	})
	encCF, _ := gw.cloudflare.cipher.Encrypt("cf-tok")
	_ = gw.telemetry.SaveCloudflareDNS(ctx, cloudflareDNSStored{
		cloudflareDNSSettings: cloudflareDNSSettings{Enabled: true, TokenSet: true, ZoneID: "z1", RootDomain: "example.test", TTL: 60},
		EncryptedToken:        encCF,
	})

	nodeA, enrA, _ := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{Name: "德国 9929", Region: "DE", ManualIPv4: "203.0.113.11"})
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrA, "1.0", "linux/amd64", "de")
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeA.ID, 1, "s", "1.0", "linux/amd64", "de", "", "", "", now.Unix())

	prof, err := gw.telemetry.CreateSmartDNSProfile(ctx, smartDNSProfileRecord{
		Name: "三网共享方案", ProviderSource: "platform", ProviderUUID: "prov-ali", ProviderType: "alibaba-cloud",
		ZoneUUID: "zone-1", ZoneName: "alidns-2.com", AutoCFCNAME: true,
		Lines: []smartDNSLineRule{
			{GeoISP: "default", Label: "默认", NodeIDs: []string{nodeA.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("CreateSmartDNSProfile: %v", err)
	}

	dom1, err := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain: "a.example.test", Name: "入口 A", Enabled: true, NodeIDs: []string{nodeA.ID},
		DNSMode: domainDNSAxisNowSmart, SmartDNS: applySmartDNSProfileToDomain(prof, nil, false),
	})
	if err != nil {
		t.Fatalf("create dom1: %v", err)
	}
	dom2, err := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain: "b.example.test", Name: "入口 B", Enabled: true, NodeIDs: []string{nodeA.ID},
		DNSMode: domainDNSAxisNowSmart, SmartDNS: applySmartDNSProfileToDomain(prof, nil, false),
	})
	if err != nil {
		t.Fatalf("create dom2: %v", err)
	}

	// Sync both domains concurrently: MUST create ONLY ONE shared AxisNow routing domain!
	var wg sync.WaitGroup
	wg.Add(2)
	var err1, err2 error
	go func() { defer wg.Done(); err1 = gw.axisnow.SyncEdgeDomainSmartDNS(ctx, dom1, now) }()
	go func() { defer wg.Done(); err2 = gw.axisnow.SyncEdgeDomainSmartDNS(ctx, dom2, now) }()
	wg.Wait()
	if err1 != nil || err2 != nil {
		t.Fatalf("sync errors: err1=%v err2=%v", err1, err2)
	}

	anMu.Lock()
	createdTotal := domainCreateCount
	remoteDomCount := len(routingDomains)
	anMu.Unlock()
	if createdTotal != 1 || remoteDomCount != 1 {
		t.Fatalf("expected exactly 1 shared AxisNow routing domain created, got createdTotal=%d remoteDomCount=%d", createdTotal, remoteDomCount)
	}

	d1After, _ := gw.telemetry.GetEdgeDomain(ctx, dom1.ID)
	d2After, _ := gw.telemetry.GetEdgeDomain(ctx, dom2.ID)
	if d1After.SmartDNS.RoutingDomainUUID == "" || d1After.SmartDNS.RoutingDomainUUID != d2After.SmartDNS.RoutingDomainUUID {
		t.Fatalf("expected dom1 & dom2 to share RoutingDomainUUID, got d1=%q d2=%q", d1After.SmartDNS.RoutingDomainUUID, d2After.SmartDNS.RoutingDomainUUID)
	}
	if !d1After.SmartDNS.CFCNAMESynced || !d2After.SmartDNS.CFCNAMESynced {
		t.Fatalf("expected both dom1 & dom2 CNAMEs synced, got d1=%v d2=%v", d1After.SmartDNS.CFCNAMESynced, d2After.SmartDNS.CFCNAMESynced)
	}

	// Switch dom1 away to manual -> shared routing domain MUST stay alive because dom2 still uses it!
	d1Manual := d1After
	d1Manual.DNSMode = domainDNSManual
	cp := *d1After.SmartDNS
	cp.RoutingDomainUUID = ""
	cp.RoutingDomainHost = ""
	d1Manual.SmartDNS = &cp
	_, _ = gw.telemetry.UpdateEdgeDomain(ctx, dom1.ID, d1Manual)
	gw.axisnow.CleanupOrphanedRoutingDomain(ctx, d1After)
	anMu.Lock()
	remAfterFirstLeave := len(routingDomains)
	anMu.Unlock()
	if remAfterFirstLeave != 1 {
		t.Fatalf("shared routing domain was deleted while dom2 still used it! rem=%d", remAfterFirstLeave)
	}

	// Delete dom2 (last user) -> shared routing domain MUST now be deleted to reclaim quota!
	_ = gw.telemetry.DeleteEdgeDomain(ctx, dom2.ID)
	gw.axisnow.DeleteEdgeDomainSmartDNS(ctx, d2After)
	anMu.Lock()
	remAfterLastDelete := len(routingDomains)
	anMu.Unlock()
	if remAfterLastDelete != 0 {
		t.Fatalf("expected shared routing domain reclaimed after last domain deleted, got rem=%d", remAfterLastDelete)
	}
}

func TestAxisNowReconcileOrphanedRoutingDomainsCascadeAndMultiControllerSafe(t *testing.T) {
	t.Parallel()
	gw := newControllerTestGateway(t)
	ctx := context.Background()
	now := time.Now()

	var mu sync.Mutex
	routingDomains := map[string]axisnowRemoteRoutingDomain{}
	routingRules := map[string]axisnowRemoteRuleEntity{}

	anSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/dns_routing_domains":
			list := make([]axisnowRemoteRoutingDomain, 0, len(routingDomains))
			for _, d := range routingDomains {
				list = append(list, d)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dns_routing_domains/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			if d, ok := routingDomains[uid]; ok {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": d})
			} else {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 404, "message": "not found"}}})
			}
		case r.Method == http.MethodPost && r.URL.Path == "/dns_routing_rules/filter":
			list := make([]axisnowRemoteRuleEntity, 0, len(routingRules))
			for _, rr := range routingRules {
				list = append(list, rr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": list})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dns_routing_rules/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_rules/")
			delete(routingRules, uid)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"uuid": uid}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/dns_routing_domains/"):
			uid := strings.TrimPrefix(r.URL.Path, "/dns_routing_domains/")
			// Simulate strict provider that refuses domain deletion while rules still exist!
			for _, rr := range routingRules {
				if rr.DNSDomainUUID == uid {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 100400, "message": "delete routing rules first"}}})
					return
				}
			}
			delete(routingDomains, uid)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"uuid": uid}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
		}
	}))
	defer anSrv.Close()

	gw.axisnow.apiBase = anSrv.URL
	gw.axisnow.cnameReadyProbe = func(_ context.Context, _ string) (bool, []string, string) {
		return true, []string{"203.0.113.11"}, "ready"
	}
	encAn, _ := gw.axisnow.cipher.Encrypt("an-tok")
	_ = gw.telemetry.SaveAxisNowDNS(ctx, axisnowDNSStored{
		axisnowDNSSettings: axisnowDNSSettings{
			Enabled: true, TokenSet: true, APIBase: anSrv.URL, DefaultProviderUUID: "prov-ali", DefaultProviderSource: "platform",
			DefaultProviderType: "alibaba-cloud", DefaultZoneUUID: "zone-1", DefaultZoneName: "alidns-2.com", DefaultZonePlan: "free",
		},
		EncryptedToken: encAn,
	})

	nodeA, enrA, _ := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{Name: "Node A", Region: "US", ManualIPv4: "203.0.113.11"})
	nodeA, _, _ = gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrA, "1.0", "linux/amd64", "us")
	_ = gw.telemetry.RecordEdgeNodeHeartbeat(ctx, nodeA.ID, 1, "s", "1.0", "linux/amd64", "us", "", "", "", now.Unix())

	prof, _ := gw.telemetry.CreateSmartDNSProfile(ctx, smartDNSProfileRecord{
		Name: "中国三网优化", ProviderSource: "platform", ProviderUUID: "prov-ali", ProviderType: "alibaba-cloud",
		ZoneUUID: "zone-1", ZoneName: "alidns-2.com",
		Lines: []smartDNSLineRule{{GeoISP: "default", Label: "默认", NodeIDs: []string{nodeA.ID}, ElectionStrategy: "priority_order", IPQuantity: 1, Enabled: true}},
	})

	// Domain 1: switched to manual (has no RoutingDomainUUID locally, but left behind an orphaned remote routing domain with 2 rules!)
	domManual, _ := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain: "emby.example.test", Name: "Emby", Enabled: true, NodeIDs: []string{nodeA.ID},
		DNSMode: domainDNSManual,
	})
	// Domain 2: active axisnow_smart domain using rd-active
	activeCfg := applySmartDNSProfileToDomain(prof, nil, false)
	activeCfg.RoutingDomainUUID = "rd-active"
	activeCfg.RoutingDomainHost = "9929-e6b6373c.alidns-2.com"
	domActive, _ := gw.telemetry.CreateEdgeDomain(ctx, edgeDomainRecord{
		Domain: "9929.example.test", Name: "9929", Enabled: true, NodeIDs: []string{nodeA.ID},
		DNSMode: domainDNSAxisNowSmart, SmartDNS: activeCfg,
	})

	mu.Lock()
	routingDomains["rd-active"] = axisnowRemoteRoutingDomain{
		UUID: "rd-active", Domain: "9929-e6b6373c.alidns-2.com", ProviderSource: "platform", DNSProviderID: "prov-ali", DNSZoneID: "zone-1",
		Description: fmt.Sprintf("%s [%s] (9929.example.test)", axisnowManagedDescPrefix, domActive.ID), Status: "active",
	}
	routingDomains["rd-orphan"] = axisnowRemoteRoutingDomain{
		UUID: "rd-orphan", Domain: "emby-39ef175e-eaa0a5.alidns-2.com", ProviderSource: "platform", DNSProviderID: "prov-ali", DNSZoneID: "zone-1",
		Description: fmt.Sprintf("%s [%s] (emby.example.test)", axisnowManagedDescPrefix, domManual.ID), Status: "active",
	}
	routingRules["rl-orphan-1"] = axisnowRemoteRuleEntity{UUID: "rl-orphan-1", DNSDomainUUID: "rd-orphan", Type: "A", GeoISP: "default"}
	routingRules["rl-orphan-2"] = axisnowRemoteRuleEntity{UUID: "rl-orphan-2", DNSDomainUUID: "rd-orphan", Type: "A", GeoISP: "CN_CM"}
	// Foreign controller domain & manually created domain MUST NOT be touched!
	routingDomains["rd-other-ctrl"] = axisnowRemoteRoutingDomain{
		UUID: "rd-other-ctrl", Domain: "other-ctrl.alidns-2.com", ProviderSource: "platform", DNSProviderID: "prov-ali", DNSZoneID: "zone-1",
		Description: axisnowManagedDescPrefix + " [dm_othercontroller] (other.test)", Status: "active",
	}
	routingDomains["rd-unmanaged"] = axisnowRemoteRoutingDomain{
		UUID: "rd-unmanaged", Domain: "manual.alidns-2.com", ProviderSource: "platform", DNSProviderID: "prov-ali", DNSZoneID: "zone-1",
		Description: "User manually created routing domain", Status: "active",
	}
	mu.Unlock()

	reclaimed := gw.axisnow.ReconcileOrphanedRoutingDomains(ctx, now, true)
	if reclaimed != 1 {
		t.Fatalf("expected exactly 1 orphaned routing domain reclaimed, got %d", reclaimed)
	}

	mu.Lock()
	_, hasOrphan := routingDomains["rd-orphan"]
	_, hasActive := routingDomains["rd-active"]
	_, hasOtherCtrl := routingDomains["rd-other-ctrl"]
	_, hasUnmanaged := routingDomains["rd-unmanaged"]
	_, hasRule1 := routingRules["rl-orphan-1"]
	_, hasRule2 := routingRules["rl-orphan-2"]
	mu.Unlock()

	if hasOrphan || hasRule1 || hasRule2 {
		t.Fatalf("expected orphaned routing domain and its rules deleted: orphan=%v r1=%v r2=%v", hasOrphan, hasRule1, hasRule2)
	}
	if !hasActive || !hasOtherCtrl || !hasUnmanaged {
		t.Fatalf("expected active, foreign-controller, and unmanaged domains preserved: active=%v other=%v unmanaged=%v", hasActive, hasOtherCtrl, hasUnmanaged)
	}
}
