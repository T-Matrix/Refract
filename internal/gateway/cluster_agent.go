package gateway

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	agentTelemetryQueueCap  = 4096
	agentTelemetryBatchSize = 128
)

type agentPersistedState struct {
	ControllerURL string             `json:"controller_url"`
	NodeID        string             `json:"node_id"`
	NodeName      string             `json:"node_name"`
	AgentSecret   string             `json:"agent_secret"`
	LastBundle    *agentConfigBundle `json:"last_bundle,omitempty"`
}

type agentClient struct {
	gateway *Gateway

	statePath         string
	enrollToken       string
	heartbeatInterval time.Duration
	telemetryInterval time.Duration
	httpClient        *http.Client
	sseClient         *http.Client
	autoTLS           *agentAutoTLS
	skipCertWarm      bool
	skipIPDetect      atomic.Bool
	ipCheckV4URLs     []string
	ipCheckV6URLs     []string
	upgradeExePath    string
	onUpgradeRestart  func()

	mu              sync.RWMutex
	enrollMu        sync.Mutex
	controllerURL   string
	nodeID          string
	nodeName        string
	agentSecret     string
	appliedRevision int64
	appliedSHA256   string
	publicIPv4      string
	publicIPv6      string
	binarySHA256    string
	bootID          string
	nicSampler      *hostNICSampler
	lastBundle      *agentConfigBundle
	lastReenrollAt  time.Time

	upgrading atomic.Bool

	events      chan agentTelemetryEvent
	dropped     atomic.Uint64
	lastBlocked atomic.Uint64
	lastDropped atomic.Uint64

	auxMu       sync.Mutex
	clientPeaks map[string]agentClientPeak
	quotaDeltas map[int64]int64

	syncCh    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newAgentClient(gateway *Gateway, cfg Config) (*agentClient, error) {
	statePath := strings.TrimSpace(cfg.AgentStatePath)
	if statePath == "" {
		statePath = "refract-agent-state.json"
	}
	if !filepath.IsAbs(statePath) {
		if abs, err := filepath.Abs(statePath); err == nil {
			statePath = abs
		}
	}
	hb := cfg.AgentHeartbeatInterval
	if hb < time.Second {
		hb = 5 * time.Second
	}
	tel := cfg.AgentTelemetryInterval
	if tel < time.Second {
		tel = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	noRedirect := func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	bootID := readHostBootID()
	client := &agentClient{
		gateway:           gateway,
		statePath:         statePath,
		enrollToken:       strings.TrimSpace(cfg.AgentEnrollToken),
		controllerURL:     strings.TrimRight(strings.TrimSpace(cfg.AgentControllerURL), "/"),
		nodeID:            strings.TrimSpace(cfg.AgentNodeID),
		agentSecret:       strings.TrimSpace(cfg.AgentSecret),
		heartbeatInterval: hb,
		telemetryInterval: tel,
		httpClient:        &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect},
		sseClient:         &http.Client{CheckRedirect: noRedirect},
		events:            make(chan agentTelemetryEvent, agentTelemetryQueueCap),
		clientPeaks:       make(map[string]agentClientPeak),
		quotaDeltas:       make(map[int64]int64),
		syncCh:            make(chan struct{}, 1),
		ipCheckV4URLs:     []string{"https://api4.ipify.org", "https://ipv4.icanhazip.com"},
		ipCheckV6URLs:     []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"},
		bootID:            bootID,
		nicSampler:        newHostNICSampler(bootID),
		ctx:               ctx,
		cancel:            cancel,
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		if resolved, evalErr := filepath.EvalSymlinks(exe); evalErr == nil {
			exe = resolved
		}
		if digest, _, hashErr := fileSHA256Cached(exe); hashErr == nil {
			client.binarySHA256 = digest
		}
	}
	if cfg.AgentAutoTLS {
		certDir := cfg.AgentCertDir
		if certDir == "" {
			certDir = filepath.Join(filepath.Dir(statePath), "certs")
		}
		autoTLS, err := newAgentAutoTLS(certDir, cfg.AgentACMEEmail)
		if err != nil {
			cancel()
			return nil, err
		}
		client.autoTLS = autoTLS
	}
	if err := client.loadPersistedState(); err != nil {
		log.Printf("agent state load warning path=%s error=%v", statePath, err)
	}
	if client.controllerURL == "" && client.lastBundle == nil {
		cancel()
		return nil, errors.New("REFRACT_CONTROLLER_URL is required in agent mode")
	}
	if client.agentSecret == "" && client.enrollToken == "" && client.lastBundle == nil {
		cancel()
		return nil, errors.New("REFRACT_ENROLL_TOKEN or REFRACT_AGENT_SECRET is required in agent mode")
	}
	return client, nil
}

func (a *agentClient) loadPersistedState() error {
	data, err := os.ReadFile(a.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var persisted agentPersistedState
	if err := json.Unmarshal(data, &persisted); err != nil {
		return err
	}
	a.mu.Lock()
	if a.controllerURL == "" {
		a.controllerURL = strings.TrimRight(strings.TrimSpace(persisted.ControllerURL), "/")
	}
	if a.nodeID == "" {
		a.nodeID = strings.TrimSpace(persisted.NodeID)
	}
	if a.nodeName == "" {
		a.nodeName = strings.TrimSpace(persisted.NodeName)
	}
	if a.agentSecret == "" {
		a.agentSecret = strings.TrimSpace(persisted.AgentSecret)
	}
	bundle := persisted.LastBundle
	a.mu.Unlock()

	if bundle != nil {
		if err := a.applyBundle(*bundle, false); err != nil {
			return fmt.Errorf("apply cached bundle: %w", err)
		}
		log.Printf("agent loaded cached fail-open config node=%s revision=%d", bundle.NodeID, bundle.Revision)
	}
	return nil
}

func (a *agentClient) persistState() error {
	a.mu.RLock()
	snapshot := agentPersistedState{
		ControllerURL: a.controllerURL,
		NodeID:        a.nodeID,
		NodeName:      a.nodeName,
		AgentSecret:   a.agentSecret,
		LastBundle:    a.lastBundle,
	}
	a.mu.RUnlock()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFileAtomic(a.statePath, append(data, '\n'))
}

func (a *agentClient) Start() {
	if a == nil {
		return
	}
	// Best-effort immediate bootstrap on startup; background loops continue retrying if offline.
	if a.hasCredentials() || a.enrollToken != "" {
		bootCtx, cancel := context.WithTimeout(a.ctx, 8*time.Second)
		if a.ensureEnrolled(bootCtx) == nil {
			_ = a.syncConfig(bootCtx)
			_ = a.sendHeartbeat(bootCtx)
		}
		cancel()
	}

	a.wg.Add(4)
	go a.runSSELoop()
	go a.runHeartbeatLoop()
	go a.runTelemetryLoop()
	go a.runPublicIPRefreshLoop()
}

func (a *agentClient) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		if a.autoTLS != nil {
			a.autoTLS.Close()
		}
		a.cancel()
		a.wg.Wait()
	})
}

func (a *agentClient) Status() (nodeID, nodeName string, rev int64, sha string) {
	if a == nil {
		return "", "", 0, ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodeID, a.nodeName, a.appliedRevision, a.appliedSHA256
}

func (a *agentClient) hasCredentials() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.agentSecret != "" && a.controllerURL != ""
}

func (a *agentClient) triggerSync() {
	select {
	case a.syncCh <- struct{}{}:
	default:
	}
}

func (a *agentClient) EnqueueEvent(event telemetryEvent) {
	if a == nil {
		return
	}
	ts := event.Timestamp.Unix()
	if event.Timestamp.IsZero() {
		ts = time.Now().Unix()
	}
	path := event.Path
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	if path == "" {
		path = "/"
	}
	if len(path) > 512 {
		path = path[:512]
	}
	item := agentTelemetryEvent{
		FlowID:     event.FlowID,
		Timestamp:  ts,
		ClientIP:   normalizeTelemetryClientIP(event.ClientIP),
		DeviceID:   truncateRunes(strings.TrimSpace(event.DeviceID), 256),
		DeviceName: truncateRunes(strings.TrimSpace(event.DeviceName), 128),
		ClientName: truncateRunes(strings.TrimSpace(event.ClientName), 128),
		Host:       strings.TrimSpace(event.Host),
		Scheme:     event.Scheme,
		Method:     event.Method,
		Path:       path,
		Category:   event.Category,
		Status:     event.Status,
		BytesIn:    event.BytesIn,
		BytesOut:   event.BytesOut,
		DurationMS: event.DurationMS,
	}
	select {
	case a.events <- item:
	default:
		a.dropped.Add(1)
	}
}

func (a *agentClient) ObserveClientPeak(ip string, bps int64) {
	if a == nil || ip == "" || bps <= 0 {
		return
	}
	normalized := normalizeTelemetryClientIP(ip)
	if normalized == "" {
		return
	}
	a.auxMu.Lock()
	existing := a.clientPeaks[normalized]
	if bps > existing.PeakBPS {
		a.clientPeaks[normalized] = agentClientPeak{IP: normalized, PeakBPS: bps, Timestamp: time.Now().Unix()}
	}
	a.auxMu.Unlock()
}

func (a *agentClient) AddQuotaDelta(ruleID, delta int64) error {
	if a == nil || ruleID <= 0 || delta == 0 {
		return nil
	}
	a.auxMu.Lock()
	next := a.quotaDeltas[ruleID] + delta
	if next <= 0 {
		delete(a.quotaDeltas, ruleID)
	} else {
		a.quotaDeltas[ruleID] = next
	}
	a.auxMu.Unlock()
	return nil
}

func (a *agentClient) PendingQuotaDelta(ruleID int64) int64 {
	if a == nil || ruleID <= 0 {
		return 0
	}
	a.auxMu.Lock()
	v := a.quotaDeltas[ruleID]
	a.auxMu.Unlock()
	return v
}

func (a *agentClient) ensureEnrolled(ctx context.Context) error {
	if a.hasCredentials() {
		return nil
	}
	a.enrollMu.Lock()
	defer a.enrollMu.Unlock()
	if a.hasCredentials() {
		return nil
	}
	a.mu.RLock()
	ctrlURL := a.controllerURL
	a.mu.RUnlock()
	if ctrlURL == "" || a.enrollToken == "" {
		return errors.New("missing controller URL or enroll token")
	}
	hostname, _ := os.Hostname()
	payload := agentEnrollRequest{
		EnrollToken: a.enrollToken,
		Version:     normalizedVersion(Version),
		Arch:        runtime.GOOS + "/" + runtime.GOARCH,
		Hostname:    hostname,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ctrlURL+"/_agent/api/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("enroll failed status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var enrolled agentEnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&enrolled); err != nil {
		return err
	}
	if enrolled.AgentSecret == "" || enrolled.NodeID == "" {
		return errors.New("controller returned empty agent credentials")
	}
	a.mu.Lock()
	a.nodeID = enrolled.NodeID
	a.nodeName = enrolled.NodeName
	a.agentSecret = enrolled.AgentSecret
	a.mu.Unlock()
	if err := a.persistState(); err != nil {
		log.Printf("agent persist credentials failed: %v", err)
	}
	log.Printf("agent enrolled successfully node=%s (%s)", enrolled.NodeID, enrolled.NodeName)
	return nil
}

func (a *agentClient) recoverUnauthorized(ctx context.Context) bool {
	if a.enrollToken == "" {
		return false
	}
	a.mu.Lock()
	existingNodeID := a.nodeID
	if existingNodeID != "" && strings.HasPrefix(a.enrollToken, "rf_dsc_") {
		a.mu.Unlock()
		log.Printf("agent credentials revoked for node=%s; refusing automatic re-enrollment with discovery token", existingNodeID)
		return false
	}
	if !a.lastReenrollAt.IsZero() && time.Since(a.lastReenrollAt) < 30*time.Second {
		a.mu.Unlock()
		return false
	}
	a.lastReenrollAt = time.Now()
	a.agentSecret = ""
	a.appliedSHA256 = ""
	a.mu.Unlock()
	if err := a.ensureEnrolled(ctx); err != nil {
		log.Printf("agent 401 re-enrollment failed: %v", err)
		return false
	}
	return true
}

func (a *agentClient) syncConfig(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.mu.RLock()
	ctrlURL := a.controllerURL
	secret := a.agentSecret
	currentSHA := a.appliedSHA256
	a.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ctrlURL+"/_agent/api/v1/config", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	if currentSHA != "" {
		req.Header.Set("If-None-Match", `"`+currentSHA+`"`)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		if a.recoverUnauthorized(ctx) {
			return a.syncConfig(ctx)
		}
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("config sync status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var bundle agentConfigBundle
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&bundle); err != nil {
		return err
	}
	return a.applyBundle(bundle, true)
}

func (a *agentClient) applyBundle(bundle agentConfigBundle, persist bool) error {
	computed, err := computeAgentConfigSHA256(bundle.agentConfigPayload)
	if err != nil {
		return err
	}
	if persist && bundle.SHA256 != "" && computed != bundle.SHA256 {
		return fmt.Errorf("config bundle digest mismatch got=%s want=%s", computed, bundle.SHA256)
	}
	bundle.SHA256 = computed

	merged, _, err := applyRuntimeSettings(a.gateway.cfg, bundle.Runtime)
	if err != nil {
		return fmt.Errorf("invalid runtime settings in bundle: %w", err)
	}
	if strings.TrimSpace(bundle.PublicBaseURL) != "" {
		parsed, parseErr := parseHTTPURL(bundle.PublicBaseURL)
		if parseErr == nil {
			parsed.Path = ""
			merged.PublicBaseURL = parsed
		}
	} else {
		merged.PublicBaseURL = nil
	}
	if bundle.PublicPortalEnabled != nil {
		a.gateway.publicPortal.Store(*bundle.PublicPortalEnabled)
	}
	if bundle.SigningSecretHex != "" {
		if rawSecret, decErr := hex.DecodeString(bundle.SigningSecretHex); decErr == nil && len(rawSecret) >= 32 {
			ttl := time.Duration(bundle.SignedURLTTLSeconds) * time.Second
			if ttl <= 0 {
				ttl = 24 * time.Hour
			}
			signer := NewSigner(rawSecret, ttl)
			a.gateway.signerState.Store(&signer)
		}
	}

	a.gateway.applyRuntimeConfig(merged)
	a.gateway.draining.Store(bundle.Draining)
	a.gateway.applyAssignedDomains(bundle.Domains, bundle.Runtime, merged)
	compiledGlobalWAF, _ := compileWAFRulesList(bundle.GlobalWAFRules)
	a.gateway.globalWAFRules.Store(&compiledGlobalWAF)
	if a.autoTLS != nil {
		a.autoTLS.SetDomains(bundle.Domains, bundle.PublicBaseURL, !a.skipCertWarm)
	}

	clientAccess := bundle.Policy.ClientAccess
	clientAccess.compile()
	policy := &proxyPolicy{
		Mode:            bundle.Policy.Mode,
		Rules:           append([]proxyRule(nil), bundle.Policy.Rules...),
		PlayerPolicy:    playerPolicy{Mode: bundle.Policy.PlayerPolicy.Mode, Rules: append([]playerRule(nil), bundle.Policy.PlayerPolicy.Rules...)},
		ClientAccess:    clientAccess,
		ScheduleEnabled: bundle.Policy.ScheduleEnabled,
		ScheduleStart:   bundle.Policy.ScheduleStart,
		ScheduleEnd:     bundle.Policy.ScheduleEnd,
	}
	if len(bundle.IPCountries) > 0 {
		copied := make(map[string]string, len(bundle.IPCountries))
		for ip, code := range bundle.IPCountries {
			copied[ip] = code
		}
		a.gateway.ipCountries.Store(&copied)
	} else {
		empty := map[string]string{}
		a.gateway.ipCountries.Store(&empty)
	}
	if a.gateway.quota != nil {
		a.gateway.quota.Sync(policy)
	}
	a.gateway.policy.Store(policy)
	a.gateway.connections.CancelDisallowedPlayers(&policy.PlayerPolicy)

	copyBundle := bundle
	a.mu.Lock()
	a.nodeID = bundle.NodeID
	a.nodeName = bundle.NodeName
	a.appliedRevision = bundle.Revision
	a.appliedSHA256 = bundle.SHA256
	a.lastBundle = &copyBundle
	a.mu.Unlock()

	if persist {
		if err := a.persistState(); err != nil {
			log.Printf("agent persist state warning: %v", err)
		}
	}
	return nil
}

func (a *agentClient) handleCommand(event agentSSEEvent) {
	switch event.Type {
	case "config_changed":
		a.triggerSync()
	case "cancel_flow":
		if event.FlowID != "" {
			a.gateway.connections.Cancel(event.FlowID)
		}
	case "cancel_playback":
		a.gateway.terminatePlaybackSession(event.SessionKey, event.FlowID)
	case "cancel_all":
		a.gateway.connections.CancelAll()
	case "upgrade":
		if a.ctx.Err() == nil {
			a.wg.Add(1)
			go func() {
				defer a.wg.Done()
				if err := a.performSelfUpgrade(a.ctx); err != nil {
					log.Printf("agent remote upgrade failed: %v", err)
				}
			}()
		}
	}
}

func (a *agentClient) currentExecutablePath() (string, error) {
	a.mu.RLock()
	override := strings.TrimSpace(a.upgradeExePath)
	a.mu.RUnlock()
	if override != "" {
		return override, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, evalErr := filepath.EvalSymlinks(exe); evalErr == nil {
		exe = resolved
	}
	return exe, nil
}

func (a *agentClient) performSelfUpgrade(ctx context.Context) error {
	if !a.upgrading.CompareAndSwap(false, true) {
		return nil
	}
	defer a.upgrading.Store(false)

	a.mu.RLock()
	ctrlURL := a.controllerURL
	secret := a.agentSecret
	currentSHA := a.binarySHA256
	a.mu.RUnlock()
	if ctrlURL == "" || secret == "" {
		return errors.New("agent is not enrolled")
	}

	exePath, err := a.currentExecutablePath()
	if err != nil || exePath == "" {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if currentSHA == "" {
		if digest, _, hashErr := fileSHA256Cached(exePath); hashErr == nil {
			currentSHA = digest
		}
	}

	upgradeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	endpoint := fmt.Sprintf("%s/_agent/api/v1/binary?os=%s&arch=%s", ctrlURL, runtime.GOOS, runtime.GOARCH)
	req, err := http.NewRequestWithContext(upgradeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("download binary HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	expectedSHA := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Refract-SHA256")))
	if len(expectedSHA) != 64 {
		return errors.New("controller response missing valid X-Refract-SHA256 header")
	}
	if currentSHA != "" && strings.EqualFold(expectedSHA, currentSHA) {
		log.Printf("agent remote upgrade skipped: binary already matches controller (%s)", expectedSHA[:12])
		return nil
	}

	dir := filepath.Dir(exePath)
	tmpFile, err := os.CreateTemp(dir, ".refract-upgrade-*")
	if err != nil {
		return fmt.Errorf("create temp binary: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, 128<<20)
	if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), limited); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp binary: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return fmt.Errorf("binary SHA-256 mismatch: expected=%s actual=%s", expectedSHA, actualSHA)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	// Best-effort backup of previous binary before atomic swap.
	backupPath := exePath + ".bak"
	if prevBytes, readErr := os.ReadFile(exePath); readErr == nil && len(prevBytes) > 0 {
		_ = os.WriteFile(backupPath, prevBytes, 0o755)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	cleanupTmp = false

	a.mu.Lock()
	a.binarySHA256 = actualSHA
	restartHook := a.onUpgradeRestart
	a.mu.Unlock()

	log.Printf("agent upgraded binary to sha256=%s, triggering restart", actualSHA[:12])
	if restartHook != nil {
		restartHook()
	} else {
		go func() {
			time.Sleep(300 * time.Millisecond)
			requestSelfTerminate()
		}()
	}
	return nil
}

func (a *agentClient) runPublicIPRefreshLoop() {
	defer a.wg.Done()
	initial := time.NewTimer(250 * time.Millisecond)
	select {
	case <-initial.C:
	case <-a.ctx.Done():
		initial.Stop()
		return
	}
	if a.skipIPDetect.Load() {
		return
	}
	a.refreshPublicIPs()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if !a.skipIPDetect.Load() {
				a.refreshPublicIPs()
			}
		}
	}
}

func (a *agentClient) refreshPublicIPs() {
	detectCtx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	var v4, v6 string
	var wg sync.WaitGroup
	if len(a.ipCheckV4URLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v4 = probePublicIP(detectCtx, "tcp4", a.ipCheckV4URLs, false)
		}()
	}
	if len(a.ipCheckV6URLs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v6 = probePublicIP(detectCtx, "tcp6", a.ipCheckV6URLs, true)
		}()
	}
	wg.Wait()
	if v4 == "" && v6 == "" {
		return
	}
	a.mu.Lock()
	if v4 != "" {
		a.publicIPv4 = v4
	}
	if v6 != "" {
		a.publicIPv6 = v6
	}
	a.mu.Unlock()
}

func probePublicIP(ctx context.Context, network string, urls []string, wantV6 bool) string {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DialContext: func(c context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(c, network, addr)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	for _, endpoint := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Refract-Agent/"+normalizedVersion(Version))
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		candidate := strings.TrimSpace(string(raw))
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if wantV6 && !addr.Is6() {
			continue
		}
		if !wantV6 && !addr.Is4() {
			continue
		}
		return addr.String()
	}
	return ""
}

func (a *agentClient) runSSELoop() {
	defer a.wg.Done()
	backoff := time.Second
	for {
		if a.ctx.Err() != nil {
			return
		}
		if err := a.ensureEnrolled(a.ctx); err != nil {
			a.sleepBackoff(&backoff)
			continue
		}
		if err := a.streamSSE(); err != nil && a.ctx.Err() == nil {
			log.Printf("agent SSE disconnected: %v", err)
			a.sleepBackoff(&backoff)
		} else {
			backoff = time.Second
		}
	}
}

func (a *agentClient) streamSSE() error {
	a.mu.RLock()
	ctrlURL := a.controllerURL
	secret := a.agentSecret
	a.mu.RUnlock()

	req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, ctrlURL+"/_agent/api/v1/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := a.sseClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sse status=%d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 16<<10), 256<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "" {
			continue
		}
		var event agentSSEEvent
		if err := json.Unmarshal([]byte(raw), &event); err == nil {
			a.handleCommand(event)
		}
	}
	return scanner.Err()
}

func (a *agentClient) runHeartbeatLoop() {
	defer a.wg.Done()
	fastInterval := 2 * time.Second
	if a.heartbeatInterval < fastInterval {
		fastInterval = a.heartbeatInterval
	}
	ticker := time.NewTicker(fastInterval)
	defer ticker.Stop()
	var lastSent time.Time
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.syncCh:
			syncCtx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
			if err := a.syncConfig(syncCtx); err != nil && a.ctx.Err() == nil {
				log.Printf("agent config sync error: %v", err)
			} else {
				_ = a.sendHeartbeat(syncCtx)
				lastSent = time.Now()
			}
			cancel()
		case <-ticker.C:
			hasLiveActivity := a.gateway.active.Load() > 0 || (a.gateway.playback != nil && len(a.gateway.playback.Snapshot()) > 0)
			if !hasLiveActivity && !lastSent.IsZero() && time.Since(lastSent) < a.heartbeatInterval {
				continue
			}
			hbCtx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
			if err := a.sendHeartbeat(hbCtx); err != nil && a.ctx.Err() == nil {
				log.Printf("agent heartbeat warning: %v", err)
			} else {
				lastSent = time.Now()
			}
			cancel()
		}
	}
}

func (a *agentClient) sendHeartbeat(ctx context.Context) error {
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	a.mu.RLock()
	ctrlURL := a.controllerURL
	secret := a.agentSecret
	appliedRev := a.appliedRevision
	appliedSHA := a.appliedSHA256
	pubV4 := a.publicIPv4
	pubV6 := a.publicIPv6
	binSHA := a.binarySHA256
	a.mu.RUnlock()

	live := a.gateway.meter.Snapshot(a.gateway.active.Load())
	conns := a.gateway.connections.Snapshot()
	playbacks := a.gateway.playback.Snapshot()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	hostname, _ := os.Hostname()

	payload := agentHeartbeatRequest{
		AppliedRevision: appliedRev,
		AppliedSHA256:   appliedSHA,
		Version:         normalizedVersion(Version),
		Arch:            runtime.GOOS + "/" + runtime.GOARCH,
		Hostname:        hostname,
		Metrics: edgeNodeMetrics{
			UploadBPS:      live.UploadBPS,
			DownloadBPS:    live.DownloadBPS,
			UploadTotal:    live.UploadTotal,
			DownloadTotal:  live.DownloadTotal,
			ActiveRequests: live.ActiveRequests,
			BlockedTotal:   a.gateway.blocked.Load(),
			DroppedLogs:    a.dropped.Load(),
			UptimeSeconds:  int64(time.Since(a.gateway.started).Seconds()),
			Goroutines:     runtime.NumGoroutine(),
			MemAllocBytes:  mem.Alloc,
			PublicIPv4:     pubV4,
			PublicIPv6:     pubV6,
			BinarySHA256:   binSHA,
			NICTraffic:     a.nicSampler.Sample(),
			agentTLSStatus: a.autoTLS.Status(),
			Connections:    conns,
			Playbacks:      playbacks,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ctrlURL+"/_agent/api/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		if a.recoverUnauthorized(ctx) {
			a.triggerSync()
		}
		return fmt.Errorf("heartbeat status=%d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat status=%d", resp.StatusCode)
	}
	var reply agentHeartbeatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 128<<10)).Decode(&reply); err != nil {
		return err
	}
	for _, cmd := range reply.Commands {
		a.handleCommand(cmd)
	}
	if reply.DesiredSHA256 != "" && reply.DesiredSHA256 != appliedSHA {
		a.triggerSync()
	}
	return nil
}

func (a *agentClient) runTelemetryLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.telemetryInterval)
	defer ticker.Stop()
	buffer := make([]agentTelemetryEvent, 0, agentTelemetryBatchSize)

	flush := func(flushParent context.Context, final bool) bool {
		peaks, quotas := a.drainAuxTelemetry()
		blockedCur := a.gateway.blocked.Load()
		blockedPrev := a.lastBlocked.Swap(blockedCur)
		droppedCur := a.dropped.Load()
		droppedPrev := a.lastDropped.Swap(droppedCur)

		if len(buffer) == 0 && len(peaks) == 0 && len(quotas) == 0 {
			return true
		}
		batch := agentTelemetryBatch{
			Events:       append([]agentTelemetryEvent(nil), buffer...),
			ClientPeaks:  peaks,
			QuotaDeltas:  quotas,
			BlockedDelta: max(uint64(0), blockedCur-blockedPrev),
			DroppedDelta: max(uint64(0), droppedCur-droppedPrev),
		}
		buffer = buffer[:0]

		flushCtx, cancel := context.WithTimeout(flushParent, 8*time.Second)
		err := a.sendTelemetry(flushCtx, batch)
		cancel()
		if err != nil {
			a.dropped.Add(uint64(len(batch.Events)))
			if len(batch.QuotaDeltas) > 0 {
				a.auxMu.Lock()
				for ruleID, delta := range batch.QuotaDeltas {
					a.quotaDeltas[ruleID] += delta
				}
				a.auxMu.Unlock()
			}
			if !final && a.ctx.Err() == nil {
				log.Printf("agent telemetry flush warning: %v", err)
			}
			return false
		}
		return true
	}

	for {
		select {
		case <-a.ctx.Done():
			drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer drainCancel()
			for drainCtx.Err() == nil {
				select {
				case ev := <-a.events:
					buffer = append(buffer, ev)
					if len(buffer) >= agentTelemetryBatchSize {
						if !flush(drainCtx, true) {
							return
						}
					}
				default:
					flush(drainCtx, true)
					return
				}
			}
			return
		case ev := <-a.events:
			buffer = append(buffer, ev)
			if len(buffer) >= agentTelemetryBatchSize {
				flush(a.ctx, false)
			}
		case <-ticker.C:
			flush(a.ctx, false)
		}
	}
}

func (a *agentClient) drainAuxTelemetry() ([]agentClientPeak, map[int64]int64) {
	a.auxMu.Lock()
	defer a.auxMu.Unlock()
	var peaks []agentClientPeak
	if len(a.clientPeaks) > 0 {
		peaks = make([]agentClientPeak, 0, len(a.clientPeaks))
		for _, p := range a.clientPeaks {
			peaks = append(peaks, p)
		}
		a.clientPeaks = make(map[string]agentClientPeak)
	}
	var quotas map[int64]int64
	if len(a.quotaDeltas) > 0 {
		quotas = a.quotaDeltas
		a.quotaDeltas = make(map[int64]int64)
	}
	return peaks, quotas
}

func (a *agentClient) sendTelemetry(ctx context.Context, batch agentTelemetryBatch) error {
	if !a.hasCredentials() {
		return errors.New("agent not enrolled")
	}
	a.mu.RLock()
	ctrlURL := a.controllerURL
	secret := a.agentSecret
	a.mu.RUnlock()

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if err := json.NewEncoder(gz).Encode(batch); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ctrlURL+"/_agent/api/v1/telemetry", &compressed)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telemetry status=%d", resp.StatusCode)
	}
	return nil
}

func (a *agentClient) sleepBackoff(backoff *time.Duration) {
	timer := time.NewTimer(*backoff)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-a.ctx.Done():
	}
	*backoff = min(*backoff*2, 15*time.Second)
}
