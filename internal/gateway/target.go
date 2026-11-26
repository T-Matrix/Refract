package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

type targetInfo struct {
	URL               *url.URL
	Dynamic           bool
	PublicBase        string
	ClientOrigin      string
	DialAddresses     []string
	PassClientIP      *bool
	DisableCache      *bool
	DefaultUpstream   *url.URL
	RewriteMaxBytes   int64
	PlaybackMeta      playbackRequestMeta
	PlayingReportBody []byte
}

type targetContextKey struct{}

type dnsCacheEntry struct {
	addresses []netip.Addr
	expires   time.Time
}

type safeResolver struct {
	resolver     *net.Resolver
	ttl          time.Duration
	allowPrivate bool
	mu           sync.Mutex
	cache        map[string]dnsCacheEntry
}

func newSafeResolver(ttl time.Duration, allowPrivate bool) *safeResolver {
	return &safeResolver{
		resolver:     net.DefaultResolver,
		ttl:          ttl,
		allowPrivate: allowPrivate,
		cache:        make(map[string]dnsCacheEntry),
	}
}

func (r *safeResolver) TTL() time.Duration {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ttl
}

func (r *safeResolver) SetTTL(ttl time.Duration) {
	if r == nil || ttl <= 0 {
		return
	}
	now := time.Now()
	maxExpires := now.Add(ttl)
	r.mu.Lock()
	r.ttl = ttl
	for host, entry := range r.cache {
		if !now.Before(entry.expires) {
			delete(r.cache, host)
		} else if entry.expires.After(maxExpires) {
			entry.expires = maxExpires
			r.cache[host] = entry
		}
	}
	r.mu.Unlock()
}

const (
	upstreamIPAuto      = "auto"
	upstreamIPIPv4First = "ipv4_first"
	upstreamIPIPv4Only  = "ipv4_only"
	upstreamIPIPv6First = "ipv6_first"
	upstreamIPIPv6Only  = "ipv6_only"
)

func normalizeUpstreamIPMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", upstreamIPAuto:
		return upstreamIPAuto, true
	case upstreamIPIPv4First:
		return upstreamIPIPv4First, true
	case upstreamIPIPv4Only:
		return upstreamIPIPv4Only, true
	case upstreamIPIPv6First:
		return upstreamIPIPv6First, true
	case upstreamIPIPv6Only:
		return upstreamIPIPv6Only, true
	default:
		return "", false
	}
}

func orderAddressesByIPMode(addresses []netip.Addr, mode string) ([]netip.Addr, error) {
	normalized, ok := normalizeUpstreamIPMode(mode)
	if !ok || normalized == upstreamIPAuto {
		return addresses, nil
	}
	v4 := make([]netip.Addr, 0, len(addresses))
	v6 := make([]netip.Addr, 0, len(addresses))
	for _, addr := range addresses {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	switch normalized {
	case upstreamIPIPv4Only:
		if len(v4) == 0 {
			return nil, fmt.Errorf("target host has no IPv4 addresses")
		}
		return v4, nil
	case upstreamIPIPv6Only:
		if len(v6) == 0 {
			return nil, fmt.Errorf("target host has no IPv6 addresses")
		}
		return v6, nil
	case upstreamIPIPv4First:
		return append(v4, v6...), nil
	case upstreamIPIPv6First:
		return append(v6, v4...), nil
	default:
		return addresses, nil
	}
}

func (r *safeResolver) Resolve(ctx context.Context, target *url.URL) ([]string, error) {
	return r.ResolveWithMode(ctx, target, upstreamIPAuto)
}

func (r *safeResolver) ResolveWithMode(ctx context.Context, target *url.URL, ipMode string) ([]string, error) {
	host := normalizeHost(target.Hostname())
	if host == "" {
		return nil, fmt.Errorf("target host is required")
	}
	if host == "localhost" || host == "host.docker.internal" {
		if !r.allowPrivate {
			return nil, fmt.Errorf("private target is blocked")
		}
	}

	addresses, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("target host has no addresses")
	}
	ordered, err := orderAddressesByIPMode(addresses, ipMode)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(ordered))
	for _, address := range ordered {
		if !r.allowPrivate && isBlockedAddress(address) {
			return nil, fmt.Errorf("private or reserved target is blocked")
		}
		result = append(result, net.JoinHostPort(address.String(), effectivePort(target)))
	}
	return result, nil
}

const safeResolverMaxCacheEntries = 4096

func (r *safeResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	trimmed := strings.Trim(host, "[]")
	if strings.Contains(trimmed, "%") {
		return nil, fmt.Errorf("scoped IPv6 zone targets are not allowed")
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		if address.Zone() != "" {
			return nil, fmt.Errorf("scoped IPv6 zone targets are not allowed")
		}
		return []netip.Addr{address.Unmap()}, nil
	}

	now := time.Now()
	r.mu.Lock()
	entry, ok := r.cache[host]
	if ok && now.Before(entry.expires) {
		addresses := append([]netip.Addr(nil), entry.addresses...)
		r.mu.Unlock()
		return addresses, nil
	}
	r.mu.Unlock()

	resolved, err := r.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve target %s: %w", host, err)
	}
	addresses := make([]netip.Addr, 0, len(resolved))
	for _, address := range resolved {
		if address.Zone() != "" {
			address = address.WithZone("")
		}
		addresses = append(addresses, address.Unmap())
	}
	now = time.Now()
	r.mu.Lock()
	if len(r.cache) >= safeResolverMaxCacheEntries {
		for cachedHost, cachedEntry := range r.cache {
			if !now.Before(cachedEntry.expires) {
				delete(r.cache, cachedHost)
			}
		}
		if len(r.cache) >= safeResolverMaxCacheEntries {
			// Evict oldest quarter to bound memory deterministically under random-subdomain floods.
			toEvict := len(r.cache) - (safeResolverMaxCacheEntries * 3 / 4)
			for cachedHost := range r.cache {
				delete(r.cache, cachedHost)
				toEvict--
				if toEvict <= 0 {
					break
				}
			}
		}
	}
	r.cache[host] = dnsCacheEntry{addresses: append([]netip.Addr(nil), addresses...), expires: now.Add(r.ttl)}
	r.mu.Unlock()
	return addresses, nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isBlockedAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return true
	}
	address = address.Unmap()
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRawTarget(r *http.Request, trustedPublicHosts ...string) (*url.URL, bool, string, string, error) {
	escapedPath := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	candidate := escapedPath
	if unwrapped, ok := unwrapEmbyClientTarget(r, candidate, trustedPublicHosts...); ok {
		candidate = unwrapped
	}
	if !hasHTTPPrefix(candidate) {
		decoded, err := url.PathUnescape(candidate)
		if err != nil || !hasHTTPPrefix(decoded) {
			return nil, false, "", "", nil
		}
		candidate = decoded
	}

	cleanQuery, expires, signature, err := stripGatewaySignature(r.URL.RawQuery)
	if err != nil {
		return nil, true, "", "", err
	}
	if cleanQuery != "" {
		candidate += "?" + cleanQuery
	}
	target, err := parseHTTPURL(candidate)
	if err != nil {
		return nil, true, "", "", err
	}
	if nested, ok := unwrapEmbyClientTarget(r, strings.TrimPrefix(target.EscapedPath(), "/"), trustedPublicHosts...); ok {
		if cleanQuery != "" {
			nested += "?" + cleanQuery
		}
		target, err = parseHTTPURL(nested)
		if err != nil {
			return nil, true, "", "", err
		}
	}
	return target, true, expires, signature, nil
}

// Some Emby clients prepend their configured /emby base path even when a
// playback field contains an absolute proxy URL. Accept that exact same-origin
// form while leaving authorization and signature verification unchanged.
func unwrapEmbyClientTarget(r *http.Request, escapedPath string, trustedPublicHosts ...string) (string, bool) {
	decoded, err := url.PathUnescape(escapedPath)
	if err != nil {
		return escapedPath, false
	}

	var outerRaw string
	lowerDecoded := strings.ToLower(decoded)
	switch {
	case strings.HasPrefix(lowerDecoded, "embyhttps://"):
		outerRaw = decoded[len("emby"):]
	case strings.HasPrefix(lowerDecoded, "embyhttp://"):
		outerRaw = decoded[len("emby"):]
	case strings.HasPrefix(lowerDecoded, "emby/https://"):
		outerRaw = decoded[len("emby/"):]
	case strings.HasPrefix(lowerDecoded, "emby/http://"):
		outerRaw = decoded[len("emby/"):]
	default:
		return escapedPath, false
	}

	outer, err := url.Parse(outerRaw)
	if err != nil || outer.User != nil || !matchesPublicHost(outer, r.Host, trustedPublicHosts) {
		return escapedPath, false
	}
	inner := strings.TrimPrefix(outer.EscapedPath(), "/")
	if !hasHTTPPrefix(inner) {
		decodedInner, decodeErr := url.PathUnescape(inner)
		if decodeErr != nil || !hasHTTPPrefix(decodedInner) {
			return escapedPath, false
		}
		inner = decodedInner
	}
	return inner, true
}

func matchesPublicHost(target *url.URL, requestHost string, trustedPublicHosts []string) bool {
	if sameRequestHost(target, requestHost) {
		return true
	}
	for _, trustedHost := range trustedPublicHosts {
		if sameRequestHost(target, trustedHost) {
			return true
		}
	}
	return false
}

func sameRequestHost(target *url.URL, requestHost string) bool {
	requestURL, err := url.Parse("//" + requestHost)
	if err != nil || requestURL.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(target.Hostname(), requestURL.Hostname()) {
		return false
	}
	requestPort := requestURL.Port()
	targetPort := target.Port()
	if requestPort == "" {
		return targetPort == "" || targetPort == effectivePort(target)
	}
	if targetPort == "" {
		return requestPort == effectivePort(target)
	}
	return requestPort == targetPort
}

func hasHTTPPrefix(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func defaultTarget(base *url.URL, requestURL *url.URL) *url.URL {
	target := *base
	target.Path = joinURLPath(base.Path, requestURL.Path)
	target.RawPath = ""
	target.RawQuery = requestURL.RawQuery
	target.ForceQuery = requestURL.ForceQuery
	target.Fragment = ""
	return &target
}

func joinURLPath(basePath, requestPath string) string {
	basePath = strings.TrimSuffix(basePath, "/")
	if requestPath == "" {
		requestPath = "/"
	}
	if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	if basePath == "" || basePath == "/" {
		return requestPath
	}
	return basePath + requestPath
}

func publicBaseForRequest(cfg Config, r *http.Request) (string, error) {
	if cfg.PublicBaseURL != nil {
		return strings.TrimRight(cfg.PublicBaseURL.String(), "/"), nil
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Host)
	if cfg.TrustProxyHeaders && isTrustedProxyPeer(r.RemoteAddr, cfg.TrustedProxyCIDRs) {
		if forwardedScheme := lastForwardedValue(r.Header.Values("X-Forwarded-Proto")); forwardedScheme == "http" || forwardedScheme == "https" {
			scheme = forwardedScheme
		}
		if forwardedHost := lastForwardedValue(r.Header.Values("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	parsed, err := parseHTTPURL(scheme + "://" + host)
	if err != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(host, "/\\?#\"'@,; \t\r\n") {
		return "", fmt.Errorf("invalid public host")
	}
	return scheme + "://" + parsed.Host, nil
}

func lastForwardedValue(values []string) string {
	for i := len(values) - 1; i >= 0; i-- {
		parts := strings.Split(values[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			if candidate := strings.ToLower(strings.TrimSpace(parts[j])); candidate != "" {
				return candidate
			}
		}
	}
	return ""
}
