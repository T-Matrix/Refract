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
	URL           *url.URL
	Dynamic       bool
	PublicBase    string
	ClientOrigin  string
	DialAddresses []string
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

func (r *safeResolver) Resolve(ctx context.Context, target *url.URL) ([]string, error) {
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
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if !r.allowPrivate && isBlockedAddress(address) {
			return nil, fmt.Errorf("private or reserved target is blocked")
		}
		result = append(result, net.JoinHostPort(address.String(), effectivePort(target)))
	}
	return result, nil
}

func (r *safeResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
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
		addresses = append(addresses, address.Unmap())
	}
	r.mu.Lock()
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
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isBlockedAddress(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRawTarget(r *http.Request) (*url.URL, bool, string, string, error) {
	escapedPath := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	candidate := escapedPath
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
	return target, true, expires, signature, nil
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
	host := r.Host
	if cfg.TrustProxyHeaders {
		if forwardedScheme := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); forwardedScheme == "http" || forwardedScheme == "https" {
			scheme = forwardedScheme
		}
		if forwardedHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if host == "" || strings.ContainsAny(host, "/\\ 	\r\n") {
		return "", fmt.Errorf("invalid public host")
	}
	return scheme + "://" + host, nil
}

func firstForwardedValue(value string) string {
	value, _, _ = strings.Cut(value, ",")
	return strings.ToLower(strings.TrimSpace(value))
}
