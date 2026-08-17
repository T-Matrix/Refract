package gateway

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr          string
	PublicBaseURL       *url.URL
	DefaultUpstream     *url.URL
	AllowedUpstreams    []TargetPattern
	AllowedUpstreamsRaw string
	SigningSecret       []byte
	SignedURLTTL        time.Duration
	AllowUnsigned       bool
	AllowPrivateTargets bool
	TrustProxyHeaders   bool
	PassClientIP        bool
	DisableCache        bool
	RewriteMaxBytes     int64
	DNSCacheTTL         time.Duration
	DialTimeout         time.Duration
	ResponseTimeout     time.Duration
	AdminEnabled        bool
	AdminUsername       string
	AdminPasswordHash   string
	AdminSessionSecret  []byte
	AdminDatabasePath   string
	AdminBackupDir      string
	AdminSessionTTL     time.Duration
	GeoIPLookupURL      string
	GeoIPLookupTimeout  time.Duration
	GeoIPLookupInterval time.Duration
	MaxConcurrent       int
	MaxConcurrentPerIP  int
	MaxDownloadBPSPerIP int64
	RuntimeConfigPath   string
	RestartOnConfigSave bool
}

type TargetPattern struct {
	Host     string
	Port     string
	Wildcard bool
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:          envString("LISTEN_ADDR", ":8080"),
		SignedURLTTL:        envDuration("SIGNED_URL_TTL", 24*time.Hour),
		AllowUnsigned:       envBool("ALLOW_UNSIGNED_TARGETS", false),
		AllowPrivateTargets: envBool("ALLOW_PRIVATE_TARGETS", false),
		TrustProxyHeaders:   envBool("TRUST_PROXY_HEADERS", false),
		PassClientIP:        envBool("PASS_CLIENT_IP", false),
		DisableCache:        envBool("DISABLE_CACHE", true),
		RewriteMaxBytes:     envInt64("REWRITE_MAX_BYTES", 8<<20),
		DNSCacheTTL:         envDuration("DNS_CACHE_TTL", time.Minute),
		DialTimeout:         envDuration("DIAL_TIMEOUT", 15*time.Second),
		ResponseTimeout:     envDuration("RESPONSE_HEADER_TIMEOUT", 60*time.Second),
		AdminEnabled:        envBool("ADMIN_ENABLED", false),
		AdminUsername:       envString("ADMIN_USERNAME", "admin"),
		AdminPasswordHash:   strings.TrimSpace(os.Getenv("ADMIN_PASSWORD_HASH")),
		AdminSessionSecret:  []byte(os.Getenv("ADMIN_SESSION_SECRET")),
		AdminDatabasePath:   envString("ADMIN_DATABASE_PATH", "gateway.db"),
		AdminBackupDir:      strings.TrimSpace(os.Getenv("ADMIN_BACKUP_DIR")),
		AdminSessionTTL:     envDuration("ADMIN_SESSION_TTL", 12*time.Hour),
		GeoIPLookupURL:      envString("GEOIP_LOOKUP_URL", "https://ipwho.is/{ip}?fields=success,ip,country,country_code,region,latitude,longitude"),
		GeoIPLookupTimeout:  envDuration("GEOIP_LOOKUP_TIMEOUT", 8*time.Second),
		GeoIPLookupInterval: envDuration("GEOIP_LOOKUP_INTERVAL", 1100*time.Millisecond),
		MaxConcurrent:       envInt("MAX_CONCURRENT_REQUESTS", 256),
		MaxConcurrentPerIP:  envInt("MAX_CONCURRENT_PER_IP", 64),
		MaxDownloadBPSPerIP: megabitsToBytes(envInt64("MAX_DOWNLOAD_MBIT_PER_IP", 0)),
		RuntimeConfigPath:   strings.TrimSpace(os.Getenv("RUNTIME_CONFIG_PATH")),
		RestartOnConfigSave: envBool("RESTART_ON_CONFIG_SAVE", false),
	}
	if cfg.AdminEnabled {
		cfg.RuntimeConfigPath = resolveRuntimeConfigPath(cfg.RuntimeConfigPath, cfg.AdminDatabasePath)
	}

	var err error
	if raw := strings.TrimSpace(os.Getenv("PUBLIC_BASE_URL")); raw != "" {
		cfg.PublicBaseURL, err = parseHTTPURL(raw)
		if err != nil {
			return Config{}, fmt.Errorf("PUBLIC_BASE_URL: %w", err)
		}
		if cfg.PublicBaseURL.Path != "" && cfg.PublicBaseURL.Path != "/" {
			return Config{}, fmt.Errorf("PUBLIC_BASE_URL must not contain a path")
		}
		if cfg.PublicBaseURL.RawQuery != "" || cfg.PublicBaseURL.Fragment != "" {
			return Config{}, fmt.Errorf("PUBLIC_BASE_URL must not contain a query or fragment")
		}
		cfg.PublicBaseURL.Path = ""
	}

	if raw := strings.TrimSpace(os.Getenv("DEFAULT_UPSTREAM")); raw != "" {
		cfg.DefaultUpstream, err = parseHTTPURL(raw)
		if err != nil {
			return Config{}, fmt.Errorf("DEFAULT_UPSTREAM: %w", err)
		}
		cfg.DefaultUpstream.RawQuery = ""
		cfg.DefaultUpstream.Fragment = ""
	}

	cfg.AllowedUpstreamsRaw = strings.TrimSpace(os.Getenv("ALLOWED_UPSTREAMS"))
	patterns, err := parseTargetPatterns(cfg.AllowedUpstreamsRaw)
	if err != nil {
		return Config{}, fmt.Errorf("ALLOWED_UPSTREAMS: %w", err)
	}
	if cfg.DefaultUpstream != nil {
		patterns = append(patterns, patternFromURL(cfg.DefaultUpstream))
	}
	cfg.AllowedUpstreams = patterns

	secret := os.Getenv("SIGNING_SECRET")
	if len(secret) < 32 {
		return Config{}, fmt.Errorf("SIGNING_SECRET must contain at least 32 characters")
	}
	cfg.SigningSecret = []byte(secret)

	if cfg.AdminEnabled {
		cfg = loadRuntimeConfigWithFallback(cfg)
	}

	if cfg.SignedURLTTL <= 0 {
		return Config{}, fmt.Errorf("SIGNED_URL_TTL must be positive")
	}
	if cfg.RewriteMaxBytes < 1024 {
		return Config{}, fmt.Errorf("REWRITE_MAX_BYTES must be at least 1024")
	}
	if cfg.MaxConcurrent < 1 {
		return Config{}, fmt.Errorf("MAX_CONCURRENT_REQUESTS must be positive")
	}
	if cfg.MaxConcurrentPerIP < 1 || cfg.MaxConcurrentPerIP > cfg.MaxConcurrent {
		return Config{}, fmt.Errorf("MAX_CONCURRENT_PER_IP must be positive and no greater than MAX_CONCURRENT_REQUESTS")
	}
	if cfg.MaxDownloadBPSPerIP < 0 || cfg.MaxDownloadBPSPerIP > megabitsToBytes(100000) {
		return Config{}, fmt.Errorf("MAX_DOWNLOAD_MBIT_PER_IP must be between 0 and 100000")
	}
	if cfg.GeoIPLookupURL != "" {
		lookupURL, parseErr := url.Parse(cfg.GeoIPLookupURL)
		if parseErr != nil || lookupURL.Scheme != "https" || lookupURL.Hostname() == "" || !strings.Contains(cfg.GeoIPLookupURL, "{ip}") {
			return Config{}, fmt.Errorf("GEOIP_LOOKUP_URL must be an HTTPS URL containing {ip}")
		}
		if cfg.GeoIPLookupTimeout < time.Second || cfg.GeoIPLookupTimeout > 30*time.Second {
			return Config{}, fmt.Errorf("GEOIP_LOOKUP_TIMEOUT must be between 1s and 30s")
		}
		if cfg.GeoIPLookupInterval < 100*time.Millisecond || cfg.GeoIPLookupInterval > time.Minute {
			return Config{}, fmt.Errorf("GEOIP_LOOKUP_INTERVAL must be between 100ms and 1m")
		}
	}
	if cfg.AdminEnabled {
		if cfg.AdminUsername == "" || len(cfg.AdminUsername) > 64 || strings.ContainsAny(cfg.AdminUsername, "\r\n\x00|") {
			return Config{}, fmt.Errorf("ADMIN_USERNAME must contain 1-64 safe characters")
		}
		if cfg.AdminPasswordHash != "" && !strings.HasPrefix(cfg.AdminPasswordHash, "$2") {
			return Config{}, fmt.Errorf("ADMIN_PASSWORD_HASH must be a bcrypt hash")
		}
		if len(cfg.AdminSessionSecret) < 32 {
			return Config{}, fmt.Errorf("ADMIN_SESSION_SECRET must contain at least 32 characters")
		}
		if cfg.AdminSessionTTL < 5*time.Minute || cfg.AdminSessionTTL > 7*24*time.Hour {
			return Config{}, fmt.Errorf("ADMIN_SESSION_TTL must be between 5m and 168h")
		}
	}
	return cfg, nil
}

func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("host is required")
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials in URLs are not supported")
	}
	return u, nil
}

func parseTargetPatterns(raw string) ([]TargetPattern, error) {
	var patterns []TargetPattern
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		pattern, err := parseTargetPattern(item)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func parseTargetPattern(raw string) (TargetPattern, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	wildcard := strings.HasPrefix(raw, "*.")
	if wildcard {
		raw = strings.TrimPrefix(raw, "*.")
	}
	if strings.Contains(raw, "://") {
		u, err := parseHTTPURL(raw)
		if err != nil {
			return TargetPattern{}, err
		}
		return TargetPattern{Host: normalizeHost(u.Hostname()), Port: effectivePort(u), Wildcard: wildcard}, nil
	}

	host, port := raw, ""
	if splitHost, splitPort, err := net.SplitHostPort(raw); err == nil {
		host, port = splitHost, splitPort
	} else if strings.Count(raw, ":") == 1 {
		parts := strings.SplitN(raw, ":", 2)
		if _, convErr := strconv.Atoi(parts[1]); convErr == nil {
			host, port = parts[0], parts[1]
		}
	}
	host = normalizeHost(strings.Trim(host, "[]"))
	if host == "" || strings.ContainsAny(host, "/\\ 	\r\n") {
		return TargetPattern{}, fmt.Errorf("invalid target pattern %q", raw)
	}
	return TargetPattern{Host: host, Port: port, Wildcard: wildcard}, nil
}

func patternFromURL(u *url.URL) TargetPattern {
	return TargetPattern{Host: normalizeHost(u.Hostname()), Port: effectivePort(u)}
}

func (p TargetPattern) Matches(u *url.URL) bool {
	host := normalizeHost(u.Hostname())
	if p.Wildcard {
		if host == p.Host || !strings.HasSuffix(host, "."+p.Host) {
			return false
		}
	} else if host != p.Host {
		return false
	}
	return p.Port == "" || p.Port == effectivePort(u)
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func effectivePort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func targetHostPort(u *url.URL) string {
	return net.JoinHostPort(u.Hostname(), effectivePort(u))
}

func megabitsToBytes(megabits int64) int64 {
	if megabits > 100000 {
		return 100000*125000 + 1
	}
	return megabits * 125000
}

func bytesToMegabits(bytes int64) int64 {
	return bytes * 8 / (1000 * 1000)
}

func envString(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
