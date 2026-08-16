package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"default_upstream":"https://emby.example.com"`) {
		t.Fatalf("save status=%d body=%s", saved.Code, saved.Body.String())
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
