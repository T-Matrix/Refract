package gateway

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var Version = "1.11.0"

const (
	defaultReleaseAPI        = "https://api.github.com/repos/T-Matrix/Refract/releases/latest"
	defaultReleaseBase       = "https://github.com/T-Matrix/Refract/releases/download"
	defaultMaintenanceSocket = "/run/refract-maintenance.sock"
	maxReleaseMetadata       = 1 << 20
	maxReleaseBinary         = 128 << 20
)

var (
	versionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)
	servicePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]+\.service$`)
)

type updateStatus struct {
	CurrentVersion      string `json:"current_version"`
	LatestVersion       string `json:"latest_version"`
	UpdateAvailable     bool   `json:"update_available"`
	AutoUpdateSupported bool   `json:"auto_update_supported"`
	AutoUpdateReason    string `json:"auto_update_reason,omitempty"`
	ReleaseURL          string `json:"release_url,omitempty"`
	CheckedAt           int64  `json:"checked_at"`
	Updating            bool   `json:"updating"`
}

type releaseAsset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type latestRelease struct {
	TagName    string         `json:"tag_name"`
	Draft      bool           `json:"draft"`
	Prerelease bool           `json:"prerelease"`
	Assets     []releaseAsset `json:"assets"`
}

type releaseInfo struct {
	Version string
	Tag     string
	Assets  map[string]releaseAsset
}

type maintenanceRequest struct {
	Action  string `json:"action"`
	Version string `json:"version"`
}

type maintenanceResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type updateManager struct {
	client            *http.Client
	apiURL            string
	releaseBaseURL    string
	executable        string
	service           string
	systemdRun        string
	healthURL         string
	maintenanceSocket string
	unsupported       string

	cacheMu    sync.Mutex
	cached     updateStatus
	cacheUntil time.Time
	updating   atomic.Bool
}

func newUpdateManager(cfg Config) *updateManager {
	manager := &updateManager{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many release download redirects")
				}
				if request.URL.Scheme != "https" {
					return errors.New("release download redirected to a non-HTTPS URL")
				}
				return nil
			},
		},
		apiURL:            defaultReleaseAPI,
		releaseBaseURL:    defaultReleaseBase,
		maintenanceSocket: envString("REFRACT_MAINTENANCE_SOCKET", defaultMaintenanceSocket),
	}
	manager.executable, _ = os.Executable()
	manager.executable, _ = filepath.Abs(manager.executable)
	manager.healthURL = localUpdateHealthURL(cfg.ListenAddr)
	manager.service = detectSystemdService()
	manager.systemdRun, _ = exec.LookPath("systemd-run")
	manager.unsupported = manager.autoUpdateUnsupportedReason()
	return manager
}

func (a *adminServer) handleUpdate(w http.ResponseWriter, r *http.Request, session adminSession) {
	if a.gateway.updates == nil {
		a.writeError(w, http.StatusServiceUnavailable, "update service unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		status, err := a.gateway.updates.Status(r.Context(), r.URL.Query().Get("force") == "1")
		if err != nil {
			a.writeError(w, http.StatusBadGateway, "update check unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, status)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			Version string `json:"version"`
		}
		if err := decodeAdminJSON(w, r, &payload); err != nil || len(payload.Version) > 32 {
			a.writeError(w, http.StatusBadRequest, "invalid update request")
			return
		}
		status, err := a.gateway.updates.Start(r.Context(), payload.Version)
		if err != nil {
			a.auditRequest(r, "system.update", normalizedVersion(payload.Version), err.Error(), false)
			a.writeError(w, http.StatusConflict, "update could not be started")
			return
		}
		a.auditRequest(r, "system.update", status.LatestVersion, "requested_by="+session.Username, true)
		a.writeJSON(w, http.StatusAccepted, status)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (m *updateManager) autoUpdateUnsupportedReason() string {
	switch {
	case runtime.GOOS != "linux":
		return "linux_required"
	case runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64":
		return "unsupported_architecture"
	case m.executable == "" || !filepath.IsAbs(m.executable):
		return "executable_unavailable"
	case m.service == "":
		return "native_systemd_required"
	case m.healthURL == "":
		return "health_check_unavailable"
	case os.Geteuid() != 0 && !maintenanceSocketAvailable(m.maintenanceSocket):
		return "maintenance_service_required"
	case os.Geteuid() == 0 && m.systemdRun == "":
		return "systemd_run_required"
	default:
		return ""
	}
}

func (m *updateManager) Status(ctx context.Context, force bool) (updateStatus, error) {
	now := time.Now()
	m.cacheMu.Lock()
	if !force && now.Before(m.cacheUntil) && m.cached.CurrentVersion != "" {
		cached := m.cached
		cached.Updating = m.updating.Load()
		m.cacheMu.Unlock()
		return cached, nil
	}
	m.cacheMu.Unlock()

	release, err := m.fetchLatest(ctx)
	if err != nil {
		return updateStatus{}, err
	}
	status := m.statusForRelease(release, now)
	m.cacheMu.Lock()
	m.cached = status
	m.cacheUntil = now.Add(10 * time.Minute)
	m.cacheMu.Unlock()
	return status, nil
}

func (m *updateManager) statusForRelease(release releaseInfo, now time.Time) updateStatus {
	assetName := releaseAssetName()
	_, hasBinary := release.Assets[assetName]
	_, hasChecksums := release.Assets["SHA256SUMS.txt"]
	autoSupported := m.unsupported == "" && hasBinary && hasChecksums
	reason := m.unsupported
	if reason == "" && (!hasBinary || !hasChecksums) {
		reason = "release_assets_missing"
	}
	return updateStatus{
		CurrentVersion:      normalizedVersion(Version),
		LatestVersion:       release.Version,
		UpdateAvailable:     compareVersions(release.Version, Version) > 0,
		AutoUpdateSupported: autoSupported,
		AutoUpdateReason:    reason,
		ReleaseURL:          "https://github.com/T-Matrix/Refract/releases/tag/" + url.PathEscape(release.Tag),
		CheckedAt:           now.Unix(),
		Updating:            m.updating.Load(),
	}
}

func (m *updateManager) fetchLatest(ctx context.Context) (releaseInfo, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.apiURL, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "Refract/"+normalizedVersion(Version))
	response, err := m.client.Do(request)
	if err != nil {
		return releaseInfo{}, fmt.Errorf("check release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("check release: unexpected status %d", response.StatusCode)
	}
	var payload latestRelease
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxReleaseMetadata))
	if err := decoder.Decode(&payload); err != nil {
		return releaseInfo{}, fmt.Errorf("decode release: %w", err)
	}
	if payload.Draft || payload.Prerelease {
		return releaseInfo{}, errors.New("latest release is not stable")
	}
	version, ok := parseVersion(payload.TagName)
	if !ok {
		return releaseInfo{}, errors.New("latest release has an invalid version")
	}
	assets := make(map[string]releaseAsset, len(payload.Assets))
	for _, asset := range payload.Assets {
		if asset.Name != "" {
			assets[asset.Name] = asset
		}
	}
	return releaseInfo{Version: version.String(), Tag: strings.TrimSpace(payload.TagName), Assets: assets}, nil
}

func (m *updateManager) Start(ctx context.Context, requestedVersion string) (updateStatus, error) {
	if !m.updating.CompareAndSwap(false, true) {
		return updateStatus{}, errors.New("an update is already running")
	}
	started := false
	defer func() {
		if !started {
			m.updating.Store(false)
		}
	}()

	release, err := m.fetchLatest(ctx)
	if err != nil {
		return updateStatus{}, err
	}
	status := m.statusForRelease(release, time.Now())
	if normalizedVersion(requestedVersion) != release.Version {
		return updateStatus{}, errors.New("requested version is no longer the latest release")
	}
	if !status.UpdateAvailable {
		return updateStatus{}, errors.New("Refract is already up to date")
	}
	if !status.AutoUpdateSupported {
		return updateStatus{}, errors.New("automatic update is not supported by this deployment")
	}
	if os.Geteuid() != 0 {
		if err := m.requestMaintenanceUpdate(ctx, release.Version); err != nil {
			return updateStatus{}, err
		}
		started = true
		status.Updating = true
		return status, nil
	}

	staged, err := m.downloadRelease(ctx, release)
	if err != nil {
		return updateStatus{}, err
	}
	removeStaged := true
	defer func() {
		if removeStaged {
			_ = os.Remove(staged)
		}
	}()

	stamp := time.Now().UTC().Format("20060102-150405")
	backupDir := filepath.Join(filepath.Dir(m.executable), "deploy-backups", "panel-"+release.Version+"-"+stamp)
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return updateStatus{}, fmt.Errorf("create update backup directory: %w", err)
	}
	backup := filepath.Join(backupDir, filepath.Base(m.executable))
	unit := "refract-update-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	command := exec.CommandContext(ctx, m.systemdRun,
		"--unit="+unit,
		"--collect",
		"--no-block",
		"--service-type=oneshot",
		m.executable,
		"_self-update-helper",
		"--service", m.service,
		"--executable", m.executable,
		"--staged", staged,
		"--backup", backup,
		"--health-url", m.healthURL,
		"--expected-version", release.Version,
	)
	if output, err := command.CombinedOutput(); err != nil {
		return updateStatus{}, fmt.Errorf("start update task: %w: %s", err, strings.TrimSpace(string(output)))
	}
	started = true
	removeStaged = false
	status.Updating = true
	return status, nil
}

func maintenanceSocketAvailable(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

func (m *updateManager) requestMaintenanceUpdate(ctx context.Context, version string) error {
	if !maintenanceSocketAvailable(m.maintenanceSocket) {
		return errors.New("maintenance service is unavailable")
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", m.maintenanceSocket)
	if err != nil {
		return fmt.Errorf("connect maintenance service: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := json.NewEncoder(connection).Encode(maintenanceRequest{Action: "update", Version: normalizedVersion(version)}); err != nil {
		return fmt.Errorf("request maintenance update: %w", err)
	}
	var response maintenanceResponse
	if err := json.NewDecoder(io.LimitReader(connection, maxReleaseMetadata)).Decode(&response); err != nil {
		return fmt.Errorf("read maintenance response: %w", err)
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "maintenance update was rejected"
		}
		return errors.New(response.Error)
	}
	return nil
}

// RunMaintenanceRequest is the root-only side of the systemd socket. Its
// protocol intentionally exposes no command, URL, service, or filesystem path.
func RunMaintenanceRequest(input io.Reader, output io.Writer) error {
	respond := func(response maintenanceResponse) error {
		return json.NewEncoder(output).Encode(response)
	}
	if os.Geteuid() != 0 {
		return respond(maintenanceResponse{Error: "maintenance helper requires root"})
	}
	var request maintenanceRequest
	decoder := json.NewDecoder(io.LimitReader(input, maxReleaseMetadata))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return respond(maintenanceResponse{Error: "invalid maintenance request"})
	}
	version, ok := parseVersion(request.Version)
	if request.Action != "update" || !ok || version.String() != normalizedVersion(request.Version) {
		return respond(maintenanceResponse{Error: "unsupported maintenance request"})
	}
	cfg, err := LoadConfig()
	if err != nil {
		return respond(maintenanceResponse{Error: "service configuration is invalid"})
	}
	manager := newUpdateManager(cfg)
	manager.maintenanceSocket = ""
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := manager.Start(ctx, version.String()); err != nil {
		log.Printf("maintenance update rejected version=%s error=%v", version.String(), err)
		return respond(maintenanceResponse{Error: "verified update could not be started"})
	}
	return respond(maintenanceResponse{OK: true})
}

func (m *updateManager) downloadRelease(ctx context.Context, release releaseInfo) (string, error) {
	assetName := releaseAssetName()
	asset, ok := release.Assets[assetName]
	if !ok {
		return "", errors.New("release binary is missing")
	}
	if _, ok := release.Assets["SHA256SUMS.txt"]; !ok {
		return "", errors.New("release checksum manifest is missing")
	}
	checksumURL := m.releaseAssetURL(release.Tag, "SHA256SUMS.txt")
	manifest, err := m.readURL(ctx, checksumURL, maxReleaseMetadata)
	if err != nil {
		return "", fmt.Errorf("download release checksums: %w", err)
	}
	expected, err := checksumForAsset(manifest, assetName)
	if err != nil {
		return "", err
	}
	if asset.Digest != "" {
		digest := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(asset.Digest)), "sha256:")
		if digest != expected {
			return "", errors.New("release digest does not match checksum manifest")
		}
	}

	binaryURL := m.releaseAssetURL(release.Tag, assetName)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "Refract/"+normalizedVersion(Version))
	response, err := m.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download release binary: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download release binary: unexpected status %d", response.StatusCode)
	}

	file, err := os.CreateTemp(filepath.Dir(m.executable), ".refract-update-*")
	if err != nil {
		return "", fmt.Errorf("create staged update: %w", err)
	}
	staged := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(staged)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, maxReleaseBinary+1))
	if err != nil {
		return "", fmt.Errorf("write staged update: %w", err)
	}
	if written > maxReleaseBinary {
		return "", errors.New("release binary exceeds size limit")
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != expected {
		return "", errors.New("release binary checksum verification failed")
	}
	if err := file.Chmod(0o755); err != nil {
		return "", fmt.Errorf("set staged update permissions: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync staged update: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close staged update: %w", err)
	}
	keep = true
	return staged, nil
}

func (m *updateManager) readURL(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Refract/"+normalizedVersion(Version))
	response, err := m.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response exceeds size limit")
	}
	return data, nil
}

func (m *updateManager) releaseAssetURL(tag, asset string) string {
	return strings.TrimRight(m.releaseBaseURL, "/") + "/" + url.PathEscape(tag) + "/" + url.PathEscape(asset)
}

func releaseAssetName() string {
	return "refract-linux-" + runtime.GOARCH
}

func checksumForAsset(manifest []byte, asset string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(manifest)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		checksum := strings.ToLower(fields[0])
		if len(checksum) != sha256.Size*2 {
			break
		}
		if _, err := hex.DecodeString(checksum); err != nil {
			break
		}
		return checksum, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("release checksum is missing or invalid")
}

type semanticVersion struct {
	major int
	minor int
	patch int
}

func (v semanticVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func parseVersion(raw string) (semanticVersion, bool) {
	matches := versionPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if len(matches) != 4 {
		return semanticVersion{}, false
	}
	values := make([]int, 3)
	for index := range values {
		value, err := strconv.Atoi(matches[index+1])
		if err != nil || value < 0 {
			return semanticVersion{}, false
		}
		values[index] = value
	}
	return semanticVersion{major: values[0], minor: values[1], patch: values[2]}, true
}

func normalizedVersion(raw string) string {
	version, ok := parseVersion(raw)
	if !ok {
		return strings.TrimPrefix(strings.TrimSpace(raw), "v")
	}
	return version.String()
}

func compareVersions(left, right string) int {
	a, aOK := parseVersion(left)
	b, bOK := parseVersion(right)
	if !aOK || !bOK {
		return 0
	}
	for _, pair := range [][2]int{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

func detectSystemdService() string {
	if configured := strings.TrimSpace(os.Getenv("REFRACT_SYSTEMD_SERVICE")); servicePattern.MatchString(configured) {
		return configured
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		_, path, ok := strings.Cut(line, "::")
		if !ok {
			continue
		}
		service := filepath.Base(strings.TrimSpace(path))
		if servicePattern.MatchString(service) {
			return service
		}
	}
	return ""
}

func localUpdateHealthURL(listenAddr string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return ""
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return ""
	}
	return "http://127.0.0.1:" + strconv.Itoa(portNumber) + "/_gateway/health"
}

func RunSelfUpdateHelper(args []string) error {
	values, err := parseUpdateHelperArgs(args)
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	defer os.Remove(values.staged)
	if err := copyUpdateFile(values.executable, values.backup, 0o755); err != nil {
		return fmt.Errorf("backup current executable: %w", err)
	}
	if err := os.Rename(values.staged, values.executable); err != nil {
		return fmt.Errorf("activate staged update: %w", err)
	}
	if err := syncUpdateDirectory(filepath.Dir(values.executable)); err != nil {
		return fmt.Errorf("sync executable directory: %w", err)
	}
	if output, err := exec.Command("systemctl", "restart", values.service).CombinedOutput(); err != nil {
		return rollbackUpdate(values, fmt.Errorf("restart service: %w: %s", err, strings.TrimSpace(string(output))))
	}
	if err := waitForUpdateHealth(values.healthURL, values.expectedVersion, 45*time.Second); err != nil {
		return rollbackUpdate(values, err)
	}
	log.Printf("Refract update completed service=%s executable=%s", values.service, values.executable)
	return nil
}

type updateHelperValues struct {
	service         string
	executable      string
	staged          string
	backup          string
	healthURL       string
	expectedVersion string
}

func parseUpdateHelperArgs(args []string) (updateHelperValues, error) {
	values := updateHelperValues{}
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) {
			return values, errors.New("invalid self-update helper arguments")
		}
		switch args[index] {
		case "--service":
			values.service = args[index+1]
		case "--executable":
			values.executable = args[index+1]
		case "--staged":
			values.staged = args[index+1]
		case "--backup":
			values.backup = args[index+1]
		case "--health-url":
			values.healthURL = args[index+1]
		case "--expected-version":
			values.expectedVersion = args[index+1]
		default:
			return values, errors.New("unknown self-update helper argument")
		}
	}
	if !servicePattern.MatchString(values.service) {
		return values, errors.New("invalid self-update service")
	}
	for _, path := range []string{values.executable, values.staged, values.backup} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return values, errors.New("invalid self-update path")
		}
	}
	if filepath.Dir(values.executable) != filepath.Dir(values.staged) || values.executable == values.staged || values.executable == values.backup {
		return values, errors.New("invalid self-update file layout")
	}
	health, err := url.Parse(values.healthURL)
	if err != nil || health.Scheme != "http" || health.User != nil || health.Hostname() != "127.0.0.1" || health.Path != "/_gateway/health" || health.RawQuery != "" || health.Fragment != "" {
		return values, errors.New("invalid self-update health URL")
	}
	port, portErr := strconv.Atoi(health.Port())
	if health.Port() == "" || portErr != nil || port < 1 || port > 65535 {
		return values, errors.New("invalid self-update health port")
	}
	if expected, ok := parseVersion(values.expectedVersion); !ok || expected.String() != values.expectedVersion {
		return values, errors.New("invalid expected self-update version")
	}
	return values, nil
}

func rollbackUpdate(values updateHelperValues, cause error) error {
	_, _ = exec.Command("systemctl", "stop", values.service).CombinedOutput()
	rollbackPath := values.executable + ".rollback"
	if err := copyUpdateFile(values.backup, rollbackPath, 0o755); err != nil {
		return fmt.Errorf("%v; rollback copy failed: %w", cause, err)
	}
	if err := os.Rename(rollbackPath, values.executable); err != nil {
		return fmt.Errorf("%v; rollback activation failed: %w", cause, err)
	}
	_ = syncUpdateDirectory(filepath.Dir(values.executable))
	output, err := exec.Command("systemctl", "start", values.service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v; rollback restart failed: %w: %s", cause, err, strings.TrimSpace(string(output)))
	}
	return fmt.Errorf("%v; previous version restored", cause)
}

func copyUpdateFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary := destination + ".next"
	output, err := os.OpenFile(temporary, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		_ = output.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	removeTemporary = false
	return syncUpdateDirectory(filepath.Dir(destination))
}

func syncUpdateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func waitForUpdateHealth(healthURL, expectedVersion string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := client.Get(healthURL)
		if err == nil {
			var health struct {
				OK      bool   `json:"ok"`
				Version string `json:"version"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&health)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && health.OK && health.Version == expectedVersion {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return errors.New("updated service failed its health check")
}
