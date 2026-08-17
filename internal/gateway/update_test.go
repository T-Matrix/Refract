package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{"1.8.0", "1.7.5", 1},
		{"v1.8.0", "1.8.0", 0},
		{"1.8.0", "1.8.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"invalid", "1.0.0", 0},
	}
	for _, test := range tests {
		if got := compareVersions(test.left, test.right); got != test.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}

func TestGatewayDefaultsAllowNormalEmbyRequestBursts(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()
	if gateway.limiter.globalMax != 256 || gateway.limiter.perIPMax != 64 {
		t.Fatalf("default concurrency limits = %d/%d, want 256/64", gateway.limiter.globalMax, gateway.limiter.perIPMax)
	}
	for index := 0; index < 64; index++ {
		if !gateway.limiter.Acquire("203.0.113.10") {
			t.Fatalf("normal Emby burst was rejected at request %d", index+1)
		}
	}
	if gateway.limiter.Acquire("203.0.113.10") {
		t.Fatal("per-IP concurrency guard did not stop request 65")
	}
}

func TestUpdateStatusChecksLatestReleaseAndCachesResult(t *testing.T) {
	oldVersion := Version
	Version = "1.8.0"
	t.Cleanup(func() { Version = oldVersion })
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != "/latest" {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(latestRelease{
			TagName: "v1.8.1",
			Assets: []releaseAsset{
				{Name: "refract-linux-" + runtime.GOARCH},
				{Name: "SHA256SUMS.txt"},
			},
		})
	}))
	defer server.Close()
	manager := &updateManager{
		client: server.Client(), apiURL: server.URL + "/latest", releaseBaseURL: server.URL,
		executable: filepath.Join(t.TempDir(), "refract"), service: "refract.service", systemdRun: "/bin/true", healthURL: "http://127.0.0.1:8080/_gateway/health",
	}

	first, err := manager.Status(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Status(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !first.UpdateAvailable || !first.AutoUpdateSupported || first.CurrentVersion != "1.8.0" || first.LatestVersion != "1.8.1" {
		t.Fatalf("unexpected update status: %#v", first)
	}
	if second != first || requests.Load() != 1 {
		t.Fatalf("release status was not cached: second=%#v requests=%d", second, requests.Load())
	}
}

func TestDownloadReleaseVerifiesBinaryChecksum(t *testing.T) {
	binary := []byte("verified Refract release binary")
	digest := sha256.Sum256(binary)
	checksum := hex.EncodeToString(digest[:])
	assetName := "refract-linux-" + runtime.GOARCH
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1.8.1/SHA256SUMS.txt":
			_, _ = writer.Write([]byte(checksum + "  " + assetName + "\n"))
		case "/v1.8.1/" + assetName:
			_, _ = writer.Write(binary)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	manager := &updateManager{
		client: server.Client(), releaseBaseURL: server.URL, executable: filepath.Join(directory, "refract"),
	}
	release := releaseInfo{
		Version: "1.8.1", Tag: "v1.8.1",
		Assets: map[string]releaseAsset{
			assetName:        {Name: assetName, Digest: "sha256:" + checksum},
			"SHA256SUMS.txt": {Name: "SHA256SUMS.txt"},
		},
	}

	staged, err := manager.downloadRelease(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(staged)
	data, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(binary) {
		t.Fatalf("staged binary = %q, want %q", data, binary)
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %o, want 755", info.Mode().Perm())
	}
}

func TestUpdateAPIRequiresAuthenticationAndSameOrigin(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(latestRelease{
			TagName: "v1.11.1",
			Assets:  []releaseAsset{{Name: "refract-linux-" + runtime.GOARCH}, {Name: "SHA256SUMS.txt"}},
		})
	}))
	defer server.Close()
	gateway.updates = &updateManager{
		client: server.Client(), apiURL: server.URL, releaseBaseURL: server.URL,
		executable: filepath.Join(t.TempDir(), "refract"), service: "refract.service", systemdRun: "/bin/true", healthURL: "http://127.0.0.1:8080/_gateway/health",
	}

	unauthenticated := adminRequest(t, gateway, http.MethodGet, "/_admin/api/update", nil, nil, false)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated update status=%d", unauthenticated.Code)
	}
	status := adminRequest(t, gateway, http.MethodGet, "/_admin/api/update", nil, cookie, false)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"update_available":true`) {
		t.Fatalf("update check status=%d body=%s", status.Code, status.Body.String())
	}
	crossOrigin := adminRequest(t, gateway, http.MethodPost, "/_admin/api/update", map[string]string{"version": "1.11.1"}, cookie, false)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin update status=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}
}

func TestUpdateHelperRejectsUnsafeArguments(t *testing.T) {
	_, err := parseUpdateHelperArgs([]string{
		"--service", "../../evil.service",
		"--executable", "/opt/refract/refract",
		"--staged", "/opt/refract/.next",
		"--backup", "/opt/refract/backups/refract",
		"--health-url", "http://127.0.0.1:8080/_gateway/health",
		"--expected-version", "1.8.1",
	})
	if err == nil {
		t.Fatal("unsafe service name was accepted")
	}
}

func TestUpdateHelperAcceptsSafeArguments(t *testing.T) {
	values, err := parseUpdateHelperArgs([]string{
		"--service", "refract.service",
		"--executable", "/opt/refract/refract",
		"--staged", "/opt/refract/.refract-update-next",
		"--backup", "/opt/refract/deploy-backups/refract",
		"--health-url", "http://127.0.0.1:8080/_gateway/health",
		"--expected-version", "1.8.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if values.service != "refract.service" || values.expectedVersion != "1.8.1" {
		t.Fatalf("unexpected helper values: %#v", values)
	}
}

func TestWaitForUpdateHealthRequiresExpectedVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{"ok": true, "version": "1.8.0"})
	}))
	defer server.Close()
	if err := waitForUpdateHealth(server.URL, "1.8.0", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitForUpdateHealth(server.URL, "1.8.1", 20*time.Millisecond); err == nil {
		t.Fatal("health check accepted the wrong running version")
	}
}

func TestLocalUpdateHealthURL(t *testing.T) {
	if got := localUpdateHealthURL(":8080"); got != "http://127.0.0.1:8080/_gateway/health" {
		t.Fatalf("localUpdateHealthURL(:8080) = %q", got)
	}
	if got := localUpdateHealthURL("invalid"); got != "" {
		t.Fatalf("invalid listen address produced %q", got)
	}
}

func TestChecksumForAssetRejectsMalformedManifest(t *testing.T) {
	if _, err := checksumForAsset([]byte("not-a-checksum  refract-linux-amd64\n"), "refract-linux-amd64"); err == nil {
		t.Fatal("malformed checksum manifest was accepted")
	}
	if _, err := checksumForAsset([]byte(strings.Repeat("a", 64)+"  other\n"), "refract-linux-amd64"); err == nil {
		t.Fatal("missing checksum entry was accepted")
	}
}

func TestStatusTimestampUsesCurrentTime(t *testing.T) {
	manager := &updateManager{unsupported: "native_systemd_required"}
	checked := time.Unix(1_800_000_000, 0)
	status := manager.statusForRelease(releaseInfo{Version: "1.8.1", Tag: "v1.8.1", Assets: map[string]releaseAsset{}}, checked)
	if status.CheckedAt != checked.Unix() {
		t.Fatalf("checked_at=%d, want %d", status.CheckedAt, checked.Unix())
	}
}
