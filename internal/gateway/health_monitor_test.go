package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEmbyHealthServer(t *testing.T) {
	server, err := normalizeEmbyHealthServer("  华东线路  ", "  主力节点 ", "https://media.example.com:8920/emby/", true)
	if err != nil {
		t.Fatal(err)
	}
	if server.GroupName != "华东线路" || server.Name != "主力节点" || server.BaseURL != "https://media.example.com:8920/emby" || !server.Enabled {
		t.Fatalf("unexpected normalized server: %#v", server)
	}

	invalid := []struct {
		group string
		name  string
		url   string
	}{
		{"", "node", "https://media.example.com"},
		{"group", "", "https://media.example.com"},
		{"group", "node", "ftp://media.example.com"},
		{"group", "node", "https://user:secret@media.example.com"},
		{"group", "node", "https://media.example.com?token=x"},
		{"group", "node", "https://media.example.com/#fragment"},
		{"group", "node", "https://media.example.com/../admin"},
		{"group", "node", "https://media.example.com:70000"},
		{"bad\nname", "node", "https://media.example.com"},
	}
	for _, input := range invalid {
		t.Run(input.group+"/"+input.name+"/"+input.url, func(t *testing.T) {
			if _, err := normalizeEmbyHealthServer(input.group, input.name, input.url, true); err == nil {
				t.Fatalf("normalizeEmbyHealthServer(%q, %q, %q) unexpectedly succeeded", input.group, input.name, input.url)
			}
		})
	}
}

func TestEmbyHealthAvailabilityAndPublicRedaction(t *testing.T) {
	gateway := newAdminTestGateway(t)
	ctx := context.Background()
	server, err := normalizeEmbyHealthServerDetails("线路 A", "节点 1", "电信主线", "晚高峰观察", "https://secret.example.com:8920/emby", true)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := gateway.telemetry.SaveEmbyHealthServer(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	servers, err := gateway.telemetry.EmbyHealthServers(ctx, true)
	if err != nil || len(servers) != 1 {
		t.Fatalf("load configured server: count=%d err=%v", len(servers), err)
	}
	server = servers[0]
	if server.ID != serverID {
		t.Fatalf("server ID=%d, want %d", server.ID, serverID)
	}

	now := time.Now().Unix()
	samples := []embyHealthSample{
		{CheckedAt: now - 30, Success: true, LatencyMS: 42, StatusCode: http.StatusOK},
		{CheckedAt: now - int64(2*24*time.Hour/time.Second), Success: false, LatencyMS: 5000, StatusCode: http.StatusBadGateway},
		{CheckedAt: now - int64(10*24*time.Hour/time.Second), Success: true, LatencyMS: 63, StatusCode: http.StatusOK},
	}
	for _, sample := range samples {
		if err := gateway.telemetry.RecordEmbyHealthCheck(ctx, server.ID, server.ConfigVersion, sample); err != nil {
			t.Fatal(err)
		}
	}
	servers, err = gateway.telemetry.EmbyHealthServers(ctx, false)
	if err != nil || len(servers) != 1 {
		t.Fatalf("load sampled server: count=%d err=%v", len(servers), err)
	}
	server = servers[0]
	if server.Status != "online" || server.LatencyMS != 42 || server.LastStatusCode != http.StatusOK {
		t.Fatalf("unexpected latest status: %#v", server)
	}
	if server.Availability24H == nil || *server.Availability24H != 100 {
		t.Fatalf("24h availability=%v, want 100%%", server.Availability24H)
	}
	if server.Availability7D == nil || *server.Availability7D != 50 {
		t.Fatalf("7d availability=%v, want 50%%", server.Availability7D)
	}
	if server.Availability30D == nil || *server.Availability30D < 66.6 || *server.Availability30D > 66.7 {
		t.Fatalf("30d availability=%v, want about 66.7%%", server.Availability30D)
	}

	disabled, err := normalizeEmbyHealthServer("线路 A", "隐藏节点", "https://disabled.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.telemetry.SaveEmbyHealthServer(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	publicServers, err := gateway.telemetry.EmbyHealthServers(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(embyHealthPublicSnapshot(publicServers))
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if strings.Contains(body, "secret.example.com") || strings.Contains(body, "disabled.example.com") || strings.Contains(body, "base_url") {
		t.Fatalf("public health payload exposed a probe URL or field: %s", body)
	}
	if !strings.Contains(body, "节点 1") || strings.Contains(body, "隐藏节点") || !strings.Contains(body, "电信主线") || !strings.Contains(body, "晚高峰观察") {
		t.Fatalf("public payload did not include only enabled servers: %s", body)
	}
}

func TestEmbyHealthAdminAPIAuthCRUDAndPublicEndpoint(t *testing.T) {
	gateway := newAdminTestGateway(t)
	unauthorized := adminRequest(t, gateway, http.MethodGet, "/_admin/api/emby-health", nil, nil, false)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated health API status=%d", unauthorized.Code)
	}
	cookie := loginAdmin(t, gateway)

	payload := map[string]any{
		"group_name": "北美",
		"name":       "主节点",
		"line_name":  "电信主线",
		"note":       "晚高峰观察",
		"base_url":   "https://private.example.com:8920/emby",
		"enabled":    true,
	}
	crossOrigin := adminRequest(t, gateway, http.MethodPost, "/_admin/api/emby-health", payload, cookie, false)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin health create status=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}
	created := adminRequest(t, gateway, http.MethodPost, "/_admin/api/emby-health", payload, cookie, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create health server status=%d body=%s", created.Code, created.Body.String())
	}
	var createdServer embyHealthServer
	if err := json.Unmarshal(created.Body.Bytes(), &createdServer); err != nil {
		t.Fatal(err)
	}
	if createdServer.ID == 0 || createdServer.BaseURL != payload["base_url"] || createdServer.LineName != payload["line_name"] || createdServer.Note != payload["note"] {
		t.Fatalf("unexpected created server: %#v", createdServer)
	}

	adminList := adminRequest(t, gateway, http.MethodGet, "/_admin/api/emby-health", nil, cookie, false)
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), "private.example.com") {
		t.Fatalf("admin list status=%d body=%s", adminList.Code, adminList.Body.String())
	}
	public := adminRequest(t, gateway, http.MethodGet, "/_gateway/emby-health", nil, nil, false)
	if public.Code != http.StatusOK || strings.Contains(public.Body.String(), "private.example.com") || strings.Contains(public.Body.String(), "base_url") {
		t.Fatalf("public health endpoint status=%d leaked payload=%s", public.Code, public.Body.String())
	}

	payload["group_name"] = "欧洲"
	payload["name"] = "备用节点"
	payload["line_name"] = "联通备用"
	payload["note"] = "仅夜间启用"
	payload["base_url"] = "https://updated.example.com"
	payload["enabled"] = false
	updated := adminRequest(t, gateway, http.MethodPut, "/_admin/api/emby-health/"+strconv.FormatInt(createdServer.ID, 10), payload, cookie, true)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "备用节点") || !strings.Contains(updated.Body.String(), "联通备用") || !strings.Contains(updated.Body.String(), "仅夜间启用") || !strings.Contains(updated.Body.String(), `"enabled":false`) {
		t.Fatalf("update health server status=%d body=%s", updated.Code, updated.Body.String())
	}

	deleted := adminRequest(t, gateway, http.MethodDelete, "/_admin/api/emby-health/"+strconv.FormatInt(createdServer.ID, 10), nil, cookie, true)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete health server status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	adminList = adminRequest(t, gateway, http.MethodGet, "/_admin/api/emby-health", nil, cookie, false)
	if adminList.Code != http.StatusOK || !strings.Contains(adminList.Body.String(), "[]") {
		t.Fatalf("health list after delete status=%d body=%s", adminList.Code, adminList.Body.String())
	}
}

func TestEmbyHealthManualCheckRecordsProbeResult(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	var checkedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkedPath = r.URL.Path
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected health probe request: method=%s headers=%v", r.Method, r.Header)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer upstream.Close()
	gateway.embyHealth.resolver = newSafeResolver(time.Minute, true)

	server, err := normalizeEmbyHealthServer("测试组", "本机节点", upstream.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := gateway.telemetry.SaveEmbyHealthServer(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	checked := adminRequest(t, gateway, http.MethodPost, "/_admin/api/emby-health/"+strconv.FormatInt(serverID, 10)+"/check", nil, cookie, true)
	if checked.Code != http.StatusOK {
		t.Fatalf("manual check status=%d body=%s", checked.Code, checked.Body.String())
	}
	if checkedPath != "/System/Info/Public" {
		t.Fatalf("probe path=%q", checkedPath)
	}
	var result embyHealthServer
	if err := json.Unmarshal(checked.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "online" || result.LastStatusCode != http.StatusForbidden || result.LastCheckedAt == 0 {
		t.Fatalf("unexpected manual check result: %#v", result)
	}
}

func TestEmbyHealthProbeTreatsServerErrorAsUnavailable(t *testing.T) {
	gateway := newAdminTestGateway(t)
	gateway.embyHealth.resolver = newSafeResolver(time.Minute, true)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer upstream.Close()

	sample := gateway.embyHealth.probe(context.Background(), upstream.URL)
	if sample.Success {
		t.Fatalf("502 response was marked successful: %#v", sample)
	}
	if sample.StatusCode != http.StatusBadGateway {
		t.Fatalf("status code=%d, want %d", sample.StatusCode, http.StatusBadGateway)
	}
}
