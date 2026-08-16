package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxRuntimeConfigBytes = 64 << 10

type runtimeSettings struct {
	DefaultUpstream              string `json:"default_upstream"`
	AllowedUpstreams             string `json:"allowed_upstreams"`
	AllowUnsigned                bool   `json:"allow_unsigned_targets"`
	PassClientIP                 bool   `json:"pass_client_ip"`
	DisableCache                 bool   `json:"disable_cache"`
	RewriteMaxBytes              int64  `json:"rewrite_max_bytes"`
	DNSCacheTTLSeconds           int64  `json:"dns_cache_ttl_seconds"`
	DialTimeoutSeconds           int64  `json:"dial_timeout_seconds"`
	ResponseHeaderTimeoutSeconds int64  `json:"response_header_timeout_seconds"`
	MaxConcurrentRequests        int    `json:"max_concurrent_requests"`
	MaxConcurrentPerIP           int    `json:"max_concurrent_per_ip"`
}

type runtimeSettingsView struct {
	runtimeSettings
	PublicBaseURL  string `json:"public_base_url"`
	RestartOnSave  bool   `json:"restart_on_save"`
	RestartPending bool   `json:"restart_pending"`
}

type runtimeConfigManager struct {
	mu      sync.Mutex
	path    string
	current runtimeSettings
	public  string
	restart bool
}

func resolveRuntimeConfigPath(configured, databasePath string) string {
	path := strings.TrimSpace(configured)
	if path == "" && databasePath != "" && databasePath != ":memory:" {
		path = filepath.Join(filepath.Dir(databasePath), "runtime-config.json")
	}
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return absolute
}

func (a *adminServer) handleRuntimeConfig(w http.ResponseWriter, r *http.Request, session adminSession) {
	if a.gateway.runtime == nil {
		a.writeError(w, http.StatusServiceUnavailable, "runtime configuration unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.gateway.runtime.View(a.gateway.restarting.Load()))
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if a.gateway.restarting.Load() {
			a.writeError(w, http.StatusConflict, "configuration restart is already pending")
			return
		}
		var settings runtimeSettings
		if err := decodeAdminJSON(w, r, &settings); err != nil {
			return
		}
		view, err := a.gateway.runtime.Save(settings)
		if err != nil {
			a.auditRequest(r, "system.configuration", "runtime", err.Error(), false)
			a.writeError(w, http.StatusBadRequest, "invalid runtime configuration")
			return
		}
		detail := fmt.Sprintf("requested_by=%s public_proxy=%t concurrency=%d/%d", session.Username, view.AllowUnsigned, view.MaxConcurrentRequests, view.MaxConcurrentPerIP)
		a.auditRequest(r, "system.configuration", "runtime", detail, true)
		if view.RestartOnSave && a.gateway.restarting.CompareAndSwap(false, true) {
			view.RestartPending = true
			a.writeJSON(w, http.StatusAccepted, view)
			go func() {
				time.Sleep(900 * time.Millisecond)
				os.Exit(75)
			}()
			return
		}
		a.writeJSON(w, http.StatusOK, view)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func newRuntimeConfigManager(cfg Config) *runtimeConfigManager {
	public := ""
	if cfg.PublicBaseURL != nil {
		public = cfg.PublicBaseURL.String()
	}
	return &runtimeConfigManager{
		path: cfg.RuntimeConfigPath, current: runtimeSettingsFromConfig(cfg), public: public, restart: cfg.RestartOnConfigSave,
	}
}

func (m *runtimeConfigManager) View(restartPending bool) runtimeSettingsView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return runtimeSettingsView{
		runtimeSettings: m.current, PublicBaseURL: m.public, RestartOnSave: m.restart, RestartPending: restartPending,
	}
}

func (m *runtimeConfigManager) Save(settings runtimeSettings) (runtimeSettingsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.path == "" || !filepath.IsAbs(m.path) {
		return runtimeSettingsView{}, errors.New("runtime configuration path is unavailable")
	}
	normalized, _, err := applyRuntimeSettings(Config{}, settings)
	if err != nil {
		return runtimeSettingsView{}, err
	}
	settings = runtimeSettingsFromConfig(normalized)
	currentData, err := json.MarshalIndent(m.current, "", "  ")
	if err != nil {
		return runtimeSettingsView{}, err
	}
	nextData, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return runtimeSettingsView{}, err
	}
	if err := writePrivateFileAtomic(m.path+".backup", append(currentData, '\n')); err != nil {
		return runtimeSettingsView{}, fmt.Errorf("backup runtime configuration: %w", err)
	}
	if err := writePrivateFileAtomic(m.path, append(nextData, '\n')); err != nil {
		return runtimeSettingsView{}, fmt.Errorf("save runtime configuration: %w", err)
	}
	m.current = settings
	return runtimeSettingsView{runtimeSettings: settings, PublicBaseURL: m.public, RestartOnSave: m.restart}, nil
}

func runtimeSettingsFromConfig(cfg Config) runtimeSettings {
	defaultUpstream := ""
	if cfg.DefaultUpstream != nil {
		defaultUpstream = cfg.DefaultUpstream.String()
	}
	allowed := strings.TrimSpace(cfg.AllowedUpstreamsRaw)
	if allowed == "" && len(cfg.AllowedUpstreams) > 0 {
		allowed = formatTargetPatterns(cfg.AllowedUpstreams, cfg.DefaultUpstream)
	}
	return runtimeSettings{
		DefaultUpstream:              defaultUpstream,
		AllowedUpstreams:             allowed,
		AllowUnsigned:                cfg.AllowUnsigned,
		PassClientIP:                 cfg.PassClientIP,
		DisableCache:                 cfg.DisableCache,
		RewriteMaxBytes:              cfg.RewriteMaxBytes,
		DNSCacheTTLSeconds:           int64(cfg.DNSCacheTTL / time.Second),
		DialTimeoutSeconds:           int64(cfg.DialTimeout / time.Second),
		ResponseHeaderTimeoutSeconds: int64(cfg.ResponseTimeout / time.Second),
		MaxConcurrentRequests:        cfg.MaxConcurrent,
		MaxConcurrentPerIP:           cfg.MaxConcurrentPerIP,
	}
}

func applyRuntimeSettings(base Config, settings runtimeSettings) (Config, runtimeSettings, error) {
	settings.DefaultUpstream = strings.TrimSpace(settings.DefaultUpstream)
	settings.AllowedUpstreams = strings.TrimSpace(settings.AllowedUpstreams)
	if len(settings.DefaultUpstream) > 2048 || len(settings.AllowedUpstreams) > 8192 {
		return Config{}, runtimeSettings{}, errors.New("upstream configuration is too long")
	}
	var defaultUpstream *url.URL
	var err error
	if settings.DefaultUpstream != "" {
		defaultUpstream, err = parseHTTPURL(settings.DefaultUpstream)
		if err != nil || (defaultUpstream.Path != "" && defaultUpstream.Path != "/") || defaultUpstream.RawQuery != "" || defaultUpstream.Fragment != "" {
			return Config{}, runtimeSettings{}, errors.New("default upstream must contain only an HTTP/HTTPS origin")
		}
		defaultUpstream.Path = ""
		settings.DefaultUpstream = defaultUpstream.String()
	}
	patterns, err := parseTargetPatterns(settings.AllowedUpstreams)
	if err != nil {
		return Config{}, runtimeSettings{}, fmt.Errorf("allowed upstreams: %w", err)
	}
	if defaultUpstream != nil {
		patterns = append(patterns, patternFromURL(defaultUpstream))
	}
	if settings.RewriteMaxBytes < 1024 || settings.RewriteMaxBytes > 64<<20 {
		return Config{}, runtimeSettings{}, errors.New("rewrite limit must be between 1 KiB and 64 MiB")
	}
	if settings.DNSCacheTTLSeconds < 1 || settings.DNSCacheTTLSeconds > 3600 {
		return Config{}, runtimeSettings{}, errors.New("DNS cache TTL must be between 1 and 3600 seconds")
	}
	if settings.DialTimeoutSeconds < 1 || settings.DialTimeoutSeconds > 120 {
		return Config{}, runtimeSettings{}, errors.New("dial timeout must be between 1 and 120 seconds")
	}
	if settings.ResponseHeaderTimeoutSeconds < 1 || settings.ResponseHeaderTimeoutSeconds > 600 {
		return Config{}, runtimeSettings{}, errors.New("response timeout must be between 1 and 600 seconds")
	}
	if settings.MaxConcurrentRequests < 1 || settings.MaxConcurrentRequests > 4096 {
		return Config{}, runtimeSettings{}, errors.New("global concurrency must be between 1 and 4096")
	}
	if settings.MaxConcurrentPerIP < 1 || settings.MaxConcurrentPerIP > settings.MaxConcurrentRequests {
		return Config{}, runtimeSettings{}, errors.New("per-IP concurrency must not exceed global concurrency")
	}
	base.DefaultUpstream = defaultUpstream
	base.AllowedUpstreamsRaw = settings.AllowedUpstreams
	base.AllowedUpstreams = patterns
	base.AllowUnsigned = settings.AllowUnsigned
	base.PassClientIP = settings.PassClientIP
	base.DisableCache = settings.DisableCache
	base.RewriteMaxBytes = settings.RewriteMaxBytes
	base.DNSCacheTTL = time.Duration(settings.DNSCacheTTLSeconds) * time.Second
	base.DialTimeout = time.Duration(settings.DialTimeoutSeconds) * time.Second
	base.ResponseTimeout = time.Duration(settings.ResponseHeaderTimeoutSeconds) * time.Second
	base.MaxConcurrent = settings.MaxConcurrentRequests
	base.MaxConcurrentPerIP = settings.MaxConcurrentPerIP
	return base, runtimeSettingsFromConfig(base), nil
}

func loadRuntimeConfigWithFallback(base Config) Config {
	if base.RuntimeConfigPath == "" || !filepath.IsAbs(base.RuntimeConfigPath) {
		return base
	}
	for _, candidate := range []string{base.RuntimeConfigPath, base.RuntimeConfigPath + ".backup"} {
		settings, err := readRuntimeSettings(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Printf("runtime configuration ignored path=%s error=%v", candidate, err)
			continue
		}
		configured, _, err := applyRuntimeSettings(base, settings)
		if err != nil {
			log.Printf("runtime configuration rejected path=%s error=%v", candidate, err)
			continue
		}
		if candidate != base.RuntimeConfigPath {
			log.Printf("runtime configuration rolled back to %s", candidate)
		}
		return configured
	}
	return base
}

func readRuntimeSettings(path string) (runtimeSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeSettings{}, err
	}
	if len(data) > maxRuntimeConfigBytes {
		return runtimeSettings{}, errors.New("runtime configuration exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var settings runtimeSettings
	if err := decoder.Decode(&settings); err != nil {
		return runtimeSettings{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return runtimeSettings{}, errors.New("runtime configuration contains trailing data")
	}
	return settings, nil
}

func writePrivateFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".runtime-config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	keep = true
	return nil
}

func formatTargetPatterns(patterns []TargetPattern, defaultUpstream *url.URL) string {
	defaultPattern := TargetPattern{}
	if defaultUpstream != nil {
		defaultPattern = patternFromURL(defaultUpstream)
	}
	values := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if defaultUpstream != nil && pattern == defaultPattern {
			continue
		}
		host := pattern.Host
		if pattern.Wildcard {
			host = "*." + host
		}
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if pattern.Port != "" {
			host += ":" + pattern.Port
		}
		values = append(values, host)
	}
	return strings.Join(values, ",")
}
