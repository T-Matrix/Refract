package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type agentTLSStatus struct {
	Mode     string `json:"tls_mode,omitempty"`
	Domain   string `json:"tls_domain,omitempty"`
	Status   string `json:"tls_status,omitempty"`
	NotAfter int64  `json:"tls_not_after,omitempty"`
	Error    string `json:"tls_error,omitempty"`
}

type agentAutoTLS struct {
	manager     *autocert.Manager
	allowedHost atomic.Pointer[string]

	mu              sync.RWMutex
	domain          string
	status          string
	notAfter        int64
	lastErr         string
	managedExact    map[string]*tls.Certificate
	managedWildcard map[string]*tls.Certificate // key: ".example.com" for "*.example.com"
	http01Hosts     map[string]struct{}
	http01NotAfter  map[string]int64
	http01Errors    map[string]string
	warmCancels     map[string]context.CancelFunc

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func newAgentAutoTLS(certDir, email string) (*agentAutoTLS, error) {
	certDir = strings.TrimSpace(certDir)
	if certDir == "" {
		certDir = "certs"
	}
	if !filepath.IsAbs(certDir) {
		if abs, err := filepath.Abs(certDir); err == nil {
			certDir = abs
		}
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return nil, fmt.Errorf("create agent cert cache dir: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &agentAutoTLS{
		status:          "idle",
		managedExact:    make(map[string]*tls.Certificate),
		managedWildcard: make(map[string]*tls.Certificate),
		http01Hosts:     make(map[string]struct{}),
		http01NotAfter:  make(map[string]int64),
		http01Errors:    make(map[string]string),
		warmCancels:     make(map[string]context.CancelFunc),
		ctx:             ctx,
		cancel:          cancel,
	}
	a.manager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certDir),
		Email:      strings.TrimSpace(email),
		HostPolicy: a.hostPolicy,
	}
	return a, nil
}

func (a *agentAutoTLS) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.mu.Lock()
		for host, cancel := range a.warmCancels {
			cancel()
			delete(a.warmCancels, host)
		}
		a.mu.Unlock()
		a.cancel()
	})
}

func (a *agentAutoTLS) hostPolicy(_ context.Context, host string) error {
	normalized := normalizeHost(host)
	a.mu.RLock()
	_, ok := a.http01Hosts[normalized]
	totalHTTP01 := len(a.http01Hosts)
	a.mu.RUnlock()
	if totalHTTP01 == 0 {
		return errors.New("agent domain is not configured yet")
	}
	if !ok {
		return fmt.Errorf("host %q is not assigned to this edge node", normalized)
	}
	return nil
}

func (a *agentAutoTLS) AllowedHost() string {
	if a == nil {
		return ""
	}
	if ptr := a.allowedHost.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (a *agentAutoTLS) lookupManagedCert(host string) (*tls.Certificate, bool) {
	normalized := normalizeHost(host)
	if normalized == "" {
		return nil, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if cert, ok := a.managedExact[normalized]; ok {
		return cert, true
	}
	if dot := strings.IndexByte(normalized, '.'); dot > 0 && dot < len(normalized)-1 {
		suffix := normalized[dot:]
		if cert, ok := a.managedWildcard[suffix]; ok {
			return cert, true
		}
	}
	return nil, false
}

func (a *agentAutoTLS) allowsTLSForHost(host string) bool {
	if _, ok := a.lookupManagedCert(host); ok {
		return true
	}
	normalized := normalizeHost(host)
	a.mu.RLock()
	_, ok := a.http01Hosts[normalized]
	a.mu.RUnlock()
	return ok
}

func isAutoTLSEligibleHost(host string) bool {
	host = normalizeHost(host)
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || !strings.Contains(host, ".") {
		return false
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return false
	}
	return true
}

// SetPublicURL updates the single legacy ACME certificate hostname (backwards compatible).
func (a *agentAutoTLS) SetPublicURL(rawURL string, triggerWarm bool) {
	a.SetDomains(nil, rawURL, triggerWarm)
}

// SetDomains hot-swaps all controller-managed PEM certificates and ACME HTTP-01 hosts
// assigned to this edge node. Domains not assigned to this node are immediately removed.
func (a *agentAutoTLS) SetDomains(domains []agentDomainConfig, legacyPublicURL string, triggerWarm bool) {
	if a == nil {
		return
	}
	nextExact := make(map[string]*tls.Certificate)
	nextWildcard := make(map[string]*tls.Certificate)
	nextHTTP01 := make(map[string]struct{})
	var allNames []string
	var earliestManagedNotAfter int64
	var managedErr string

	if len(domains) > 0 {
		for _, dom := range domains {
			pattern := strings.ToLower(strings.TrimSpace(dom.Domain))
			if pattern == "" {
				continue
			}
			switch dom.TLSMode {
			case "managed_pem":
				if dom.CertPEM == "" || dom.KeyPEM == "" {
					continue
				}
				pair, err := tls.X509KeyPair([]byte(dom.CertPEM), []byte(dom.KeyPEM))
				if err != nil {
					managedErr = truncateRunes(err.Error(), 200)
					continue
				}
				if len(pair.Certificate) > 0 {
					if leaf, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil {
						pair.Leaf = leaf
						exp := leaf.NotAfter.Unix()
						if earliestManagedNotAfter == 0 || exp < earliestManagedNotAfter {
							earliestManagedNotAfter = exp
						}
					}
				}
				certCopy := pair
				if strings.HasPrefix(pattern, "*.") {
					nextWildcard[pattern[1:]] = &certCopy
				} else {
					nextExact[pattern] = &certCopy
				}
				allNames = append(allNames, pattern)
			case "agent_http01":
				if !strings.HasPrefix(pattern, "*.") && isAutoTLSEligibleHost(pattern) {
					nextHTTP01[pattern] = struct{}{}
					allNames = append(allNames, pattern)
				}
			}
		}
	} else if strings.TrimSpace(legacyPublicURL) != "" {
		if parsed, err := parseHTTPURL(legacyPublicURL); err == nil && strings.EqualFold(parsed.Scheme, "https") {
			candidate := normalizeHost(parsed.Hostname())
			if isAutoTLSEligibleHost(candidate) {
				nextHTTP01[candidate] = struct{}{}
				allNames = append(allNames, candidate)
			}
		}
	}

	sort.Strings(allNames)
	primary := ""
	for _, candidate := range allNames {
		if !strings.HasPrefix(candidate, "*.") {
			primary = candidate
			break
		}
	}
	primaryCopy := primary
	a.allowedHost.Store(&primaryCopy)

	a.mu.Lock()
	a.managedExact = nextExact
	a.managedWildcard = nextWildcard

	// Cancel warm loops for removed HTTP-01 hosts
	for host, cancel := range a.warmCancels {
		if _, still := nextHTTP01[host]; !still {
			cancel()
			delete(a.warmCancels, host)
			delete(a.http01NotAfter, host)
			delete(a.http01Errors, host)
		}
	}
	a.http01Hosts = nextHTTP01

	// Start warm loops for newly added HTTP-01 hosts
	if triggerWarm {
		for host := range nextHTTP01 {
			if _, exists := a.warmCancels[host]; !exists {
				warmCtx, cancel := context.WithCancel(a.ctx)
				a.warmCancels[host] = cancel
				go a.warmCertificateLoop(warmCtx, host)
			}
		}
	}

	a.domain = strings.Join(allNames, ", ")
	a.recomputeSummaryLocked(earliestManagedNotAfter, managedErr)
	a.mu.Unlock()
}

func (a *agentAutoTLS) recomputeSummaryLocked(managedNotAfter int64, managedErr string) {
	managedCount := len(a.managedExact) + len(a.managedWildcard)
	http01Count := len(a.http01Hosts)
	if managedCount == 0 && http01Count == 0 {
		a.status = "idle"
		a.notAfter = 0
		a.lastErr = managedErr
		return
	}
	earliest := managedNotAfter
	if earliest == 0 {
		for _, cert := range a.managedExact {
			if cert.Leaf != nil {
				exp := cert.Leaf.NotAfter.Unix()
				if earliest == 0 || exp < earliest {
					earliest = exp
				}
			}
		}
		for _, cert := range a.managedWildcard {
			if cert.Leaf != nil {
				exp := cert.Leaf.NotAfter.Unix()
				if earliest == 0 || exp < earliest {
					earliest = exp
				}
			}
		}
	}
	http01Ready := 0
	var firstErr string
	if managedErr != "" {
		firstErr = managedErr
	}
	for host := range a.http01Hosts {
		if exp := a.http01NotAfter[host]; exp > 0 {
			http01Ready++
			if earliest == 0 || exp < earliest {
				earliest = exp
			}
		}
		if e := a.http01Errors[host]; e != "" && firstErr == "" {
			firstErr = e
		}
	}

	a.notAfter = earliest
	a.lastErr = firstErr
	switch {
	case firstErr != "":
		a.status = "error"
	case http01Count == 0 || http01Ready == http01Count:
		a.status = "ready"
	default:
		a.status = "issuing"
	}
}

func (a *agentAutoTLS) warmCertificateLoop(ctx context.Context, host string) {
	defer func() {
		a.mu.Lock()
		delete(a.warmCancels, host)
		a.mu.Unlock()
	}()
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		cert, err := a.manager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: host,
		})
		if err == nil && cert != nil {
			a.recordCertSuccess(host, cert)
			log.Printf("agent auto-TLS certificate ready domain=%s", host)
			return
		}
		if ctx.Err() != nil {
			return
		}
		errMsg := "certificate issuance pending"
		if err != nil {
			errMsg = truncateRunes(err.Error(), 200)
		}
		a.recordCertError(host, errMsg)
		log.Printf("agent auto-TLS retry domain=%s next=%s error=%s", host, backoff, errMsg)
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		backoff = min(backoff*2, 2*time.Minute)
	}
}

func (a *agentAutoTLS) recordCertSuccess(host string, cert *tls.Certificate) {
	var notAfter int64
	if cert != nil {
		leaf := cert.Leaf
		if leaf == nil && len(cert.Certificate) > 0 {
			leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}
		if leaf != nil {
			notAfter = leaf.NotAfter.Unix()
		}
	}
	a.mu.RLock()
	_, tracked := a.http01Hosts[host]
	if !tracked || (a.http01NotAfter[host] == notAfter && a.http01Errors[host] == "") {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()
	a.mu.Lock()
	if _, ok := a.http01Hosts[host]; ok {
		a.http01NotAfter[host] = notAfter
		delete(a.http01Errors, host)
		a.recomputeSummaryLocked(0, "")
	}
	a.mu.Unlock()
}

func (a *agentAutoTLS) recordCertError(host, message string) {
	a.mu.Lock()
	if _, ok := a.http01Hosts[host]; ok {
		a.http01Errors[host] = message
		a.recomputeSummaryLocked(0, "")
	}
	a.mu.Unlock()
}

func (a *agentAutoTLS) Status() agentTLSStatus {
	if a == nil {
		return agentTLSStatus{Mode: "external", Status: "disabled"}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return agentTLSStatus{
		Mode:     "auto",
		Domain:   a.domain,
		Status:   a.status,
		NotAfter: a.notAfter,
		Error:    a.lastErr,
	}
}

func (a *agentAutoTLS) TLSConfig() *tls.Config {
	if a == nil {
		return nil
	}
	cfg := a.manager.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	baseGetCert := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		serverName := ""
		if hello != nil {
			serverName = normalizeHost(hello.ServerName)
		}
		if cert, ok := a.lookupManagedCert(serverName); ok {
			return cert, nil
		}
		cert, err := baseGetCert(hello)
		if err == nil && cert != nil && serverName != "" {
			a.recordCertSuccess(serverName, cert)
		}
		return cert, err
	}
	return cfg
}

// HTTPChallengeHandler handles Let's Encrypt HTTP-01 challenges on :80,
// exposes /_gateway/health for probes, and redirects assigned HTTP hosts to HTTPS.
func (a *agentAutoTLS) HTTPChallengeHandler(gatewayHandler http.Handler) http.Handler {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_gateway/health" && gatewayHandler != nil {
			gatewayHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Opaque != "" {
			http.Error(w, "invalid request URI", http.StatusBadRequest)
			return
		}
		reqHost := normalizeHost(stripHostPort(r.Host))
		if reqHost != "" && a.allowsTLSForHost(reqHost) {
			escPath := r.URL.EscapedPath()
			if !strings.HasPrefix(escPath, "/") {
				escPath = "/" + escPath
			}
			target := "https://" + reqHost + escPath
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		if a.AllowedHost() != "" {
			http.Error(w, "domain is not assigned to this edge node", http.StatusMisdirectedRequest)
			return
		}
		http.Error(w, "no HTTPS domain assigned to this edge node", http.StatusNotFound)
	})
	return a.manager.HTTPHandler(fallback)
}

func stripHostPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return strings.Trim(hostport, "[]")
}
