package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Gateway struct {
	cfg         Config
	signer      Signer
	resolver    *safeResolver
	proxy       *httputil.ReverseProxy
	transport   *http.Transport
	telemetry   *telemetryStore
	admin       *adminServer
	telegram    *telegramReporter
	turnstile   *turnstileManager
	backups     *backupManager
	geo         *geoTracker
	limiter     *requestLimiter
	meter       *rateMeter
	connections *connectionTracker
	started     time.Time
	active      atomic.Int64
	blocked     atomic.Uint64
	policy      atomic.Pointer[proxyPolicy]
}

func New(cfg Config) *Gateway {
	gateway, err := NewChecked(cfg)
	if err != nil {
		panic(err)
	}
	return gateway
}

func NewChecked(cfg Config) (*Gateway, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 64
	}
	if cfg.MaxConcurrentPerIP <= 0 || cfg.MaxConcurrentPerIP > cfg.MaxConcurrent {
		cfg.MaxConcurrentPerIP = min(12, cfg.MaxConcurrent)
	}
	gateway := &Gateway{
		cfg:         cfg,
		signer:      NewSigner(cfg.SigningSecret, cfg.SignedURLTTL),
		resolver:    newSafeResolver(cfg.DNSCacheTTL, cfg.AllowPrivateTargets),
		limiter:     newRequestLimiter(cfg.MaxConcurrent, cfg.MaxConcurrentPerIP),
		meter:       newRateMeter(),
		connections: newConnectionTracker(),
		started:     time.Now(),
	}
	gateway.policy.Store(&proxyPolicy{Rules: []proxyRule{}})
	dialer := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   128,
		MaxConnsPerHost:       256,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseTimeout,
		ExpectContinueTimeout: time.Second,
		ReadBufferSize:        32 << 10,
		WriteBufferSize:       32 << 10,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		info, _ := ctx.Value(targetContextKey{}).(*targetInfo)
		if info == nil || !sameDialAddress(address, targetHostPort(info.URL)) {
			return dialer.DialContext(ctx, network, address)
		}
		var lastErr error
		for _, resolved := range info.DialAddresses {
			connection, err := dialer.DialContext(ctx, network, resolved)
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("target has no resolved addresses")
		}
		return nil, lastErr
	}
	gateway.transport = transport

	gateway.proxy = &httputil.ReverseProxy{
		Rewrite:        gateway.rewriteRequest,
		Transport:      transport,
		ModifyResponse: gateway.modifyResponse,
		ErrorHandler:   gateway.handleProxyError,
		BufferPool:     newByteBufferPool(32 << 10),
		FlushInterval:  100 * time.Millisecond,
	}
	if cfg.AdminEnabled {
		store, err := openTelemetryStore(cfg.AdminDatabasePath, cfg.AdminUsername, cfg.AdminPasswordHash)
		if err != nil {
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("initialize admin database: %w", err)
		}
		gateway.telemetry = store
		policy, err := store.LoadProxyPolicy(context.Background())
		if err != nil {
			store.Close()
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("load proxy policy: %w", err)
		}
		gateway.policy.Store(policy)
		reporter, err := newTelegramReporter(store, gateway, cfg.AdminSessionSecret)
		if err != nil {
			store.Close()
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("initialize telegram reporter: %w", err)
		}
		gateway.telegram = reporter
		turnstile, err := newTurnstileManager(store, cfg.AdminSessionSecret)
		if err != nil {
			reporter.Close()
			store.Close()
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("initialize Turnstile: %w", err)
		}
		gateway.turnstile = turnstile
		backups, err := newBackupManager(store, cfg)
		if err != nil {
			reporter.Close()
			store.Close()
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("initialize backup manager: %w", err)
		}
		gateway.backups = backups
		admin, err := newAdminServer(gateway, store, cfg)
		if err != nil {
			backups.Close()
			reporter.Close()
			store.Close()
			gateway.connections.Close()
			gateway.meter.Close()
			gateway.transport.CloseIdleConnections()
			return nil, fmt.Errorf("initialize admin panel: %w", err)
		}
		gateway.admin = admin
		gateway.geo = newGeoTracker(store, cfg)
		gateway.meter.SetClientPeakSink(gateway.geo.ObservePeak)
	}
	return gateway, nil
}

func (g *Gateway) Close() {
	if g.telegram != nil {
		g.telegram.Close()
	}
	if g.backups != nil {
		g.backups.Close()
	}
	if g.connections != nil {
		g.connections.Close()
	}
	if g.meter != nil {
		g.meter.Close()
	}
	if g.geo != nil {
		g.geo.Close()
	}
	if g.transport != nil {
		g.transport.CloseIdleConnections()
	}
	if g.telemetry != nil {
		g.telemetry.Close()
	}
}

func (g *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if g.admin != nil && g.admin.Handle(writer, request) {
		return
	}
	if request.URL.Path == "/_gateway/health" {
		writeJSON(writer, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if request.Method == http.MethodOptions {
		writeCORSPreflight(writer, request)
		return
	}

	target, dynamic, expires, signature, err := parseRawTarget(request)
	if err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid target URL")
		return
	}
	if !dynamic {
		if g.cfg.DefaultUpstream == nil {
			writeGatewayError(writer, http.StatusNotFound, "Gateway Active. No Target.")
			return
		}
		target = defaultTarget(g.cfg.DefaultUpstream, request.URL)
	} else if !g.authorizeDynamicTarget(target, expires, signature) {
		g.blocked.Add(1)
		writeGatewayError(writer, http.StatusForbidden, "target is not allowed")
		return
	}
	if !g.policy.Load().Allows(target) {
		g.blocked.Add(1)
		if g.telemetry != nil {
			g.telemetry.Record(telemetryEvent{
				Timestamp: time.Now(), Host: target.Host, Scheme: target.Scheme, Method: request.Method,
				Path: target.EscapedPath(), Category: "policy", Status: http.StatusForbidden,
			})
		}
		writeGatewayError(writer, http.StatusForbidden, "target is blocked by proxy policy")
		return
	}
	client := adminClientIP(request, g.cfg.TrustProxyHeaders)
	if !g.limiter.Acquire(client) {
		g.blocked.Add(1)
		writer.Header().Set("Retry-After", "5")
		writeGatewayError(writer, http.StatusTooManyRequests, "proxy concurrency limit reached")
		return
	}
	defer g.limiter.Release(client)
	g.active.Add(1)
	defer g.active.Add(-1)
	requestContext, cancelRequest := context.WithCancel(request.Context())
	defer cancelRequest()
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	flow := g.connections.Start(cancelRequest, client, request.Method, target.Host, normalizeHost(target.Hostname()), path, resourceCategory(path), request.UserAgent())
	defer g.connections.Finish(flow)
	request = request.WithContext(requestContext)

	publicBase, err := publicBaseForRequest(g.cfg, request)
	if err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid public proxy URL")
		return
	}
	dialAddresses, err := g.resolver.Resolve(request.Context(), target)
	if err != nil {
		g.blocked.Add(1)
		writeGatewayError(writer, http.StatusForbidden, err.Error())
		return
	}
	info := &targetInfo{
		URL:           target,
		Dynamic:       dynamic,
		PublicBase:    publicBase,
		ClientOrigin:  request.Header.Get("Origin"),
		DialAddresses: dialAddresses,
	}

	started := time.Now()
	var uploadCounter *countingReadCloser
	if request.Body != nil && request.Body != http.NoBody {
		uploadCounter = &countingReadCloser{ReadCloser: request.Body, meter: g.meter, flow: flow}
		request.Body = uploadCounter
	}
	loggingWriter := &accessResponseWriter{ResponseWriter: writer, meter: g.meter, flow: flow, clientIP: client}
	proxiedRequest := request.WithContext(context.WithValue(request.Context(), targetContextKey{}, info))
	defer g.finalizeProxyRequest(request, target, path, client, started, loggingWriter, flow)
	g.proxy.ServeHTTP(loggingWriter, proxiedRequest)
}

func (g *Gateway) finalizeProxyRequest(request *http.Request, target *url.URL, path, client string, started time.Time, loggingWriter *accessResponseWriter, flow *connectionFlow) {
	status := loggingWriter.status
	if request.Context().Err() != nil {
		status = 499
	} else if status == 0 {
		status = http.StatusOK
	}
	bytesIn := flow.uploadTotal.Load()
	bytesOut := flow.downloadTotal.Load()
	duration := time.Since(started)
	log.Printf("method=%s status=%d bytes=%d duration=%s target=%s://%s", request.Method, status, bytesOut, duration.Round(time.Millisecond), target.Scheme, target.Host)
	if g.telemetry != nil {
		if len(path) > 512 {
			path = path[:512]
		}
		g.telemetry.RecordCompleted(telemetryEvent{
			FlowID:     flow.id,
			Timestamp:  time.Now(),
			Host:       target.Host,
			Scheme:     target.Scheme,
			Method:     request.Method,
			Path:       path,
			Category:   resourceCategory(path),
			Status:     status,
			BytesIn:    bytesIn,
			BytesOut:   bytesOut,
			DurationMS: duration.Milliseconds(),
		}, g.connections, flow)
	}
	if g.geo != nil {
		g.geo.ObserveRequest(client, bytesOut)
	}
}

func (g *Gateway) authorizeDynamicTarget(target *url.URL, expires, signature string) bool {
	for _, pattern := range g.cfg.AllowedUpstreams {
		if pattern.Matches(target) {
			return true
		}
	}
	if g.cfg.AllowUnsigned {
		return true
	}
	return expires != "" && signature != "" && g.signer.Verify(target, expires, signature)
}

func (g *Gateway) rewriteRequest(proxyRequest *httputil.ProxyRequest) {
	info, _ := proxyRequest.In.Context().Value(targetContextKey{}).(*targetInfo)
	if info == nil {
		return
	}
	target := *info.URL
	proxyRequest.Out.URL = &target
	proxyRequest.Out.Host = target.Host
	proxyRequest.Out.RequestURI = ""

	headers := proxyRequest.Out.Header
	for _, name := range []string{
		"CF-Connecting-IP", "CF-IPCountry", "CF-Ray", "CF-Visitor", "CDN-Loop",
		"Forwarded", "Via", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host",
		"X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Prefix",
	} {
		headers.Del(name)
	}
	if g.cfg.PassClientIP {
		proxyRequest.SetXForwarded()
	}
	headers.Del("Accept-Encoding")
	headers.Set("Host", target.Host)
	if headers.Get("Origin") != "" {
		headers.Set("Origin", target.Scheme+"://"+target.Host)
	}
	if headers.Get("Referer") != "" {
		referer := target
		referer.Fragment = ""
		headers.Set("Referer", referer.String())
	}
}

func (g *Gateway) handleProxyError(writer http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		if loggingWriter, ok := writer.(*accessResponseWriter); ok && loggingWriter.status == 0 {
			loggingWriter.status = 499
		}
		return
	}
	log.Printf("proxy error: %v", err)
	writeGatewayError(writer, http.StatusBadGateway, "upstream request failed")
}

func sameDialAddress(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil {
		return strings.EqualFold(left, right)
	}
	return normalizeHost(leftHost) == normalizeHost(rightHost) && leftPort == rightPort
}

func writeCORSPreflight(writer http.ResponseWriter, request *http.Request) {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		origin = "*"
	}
	allowedHeaders := strings.TrimSpace(request.Header.Get("Access-Control-Request-Headers"))
	if allowedHeaders == "" {
		allowedHeaders = "Authorization, Content-Type, Range, X-Emby-Authorization, X-Emby-Token, X-MediaBrowser-Authorization, X-MediaBrowser-Token"
	}
	headers := writer.Header()
	headers.Set("Access-Control-Allow-Origin", origin)
	headers.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
	headers.Set("Access-Control-Allow-Headers", allowedHeaders)
	headers.Set("Access-Control-Max-Age", "86400")
	if origin != "*" {
		headers.Set("Access-Control-Allow-Credentials", "true")
		headers.Set("Vary", "Origin, Access-Control-Request-Headers")
	}
	writer.WriteHeader(http.StatusNoContent)
}

func writeGatewayError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]any{"error": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func resourceCategory(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".m3u8"), strings.HasSuffix(lower, ".mpd"):
		return "manifest"
	case strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".m4s"):
		return "segment"
	case strings.Contains(lower, "/videos/"), strings.HasSuffix(lower, ".mp4"), strings.HasSuffix(lower, ".mkv"), strings.HasSuffix(lower, ".webm"):
		return "stream"
	case strings.Contains(lower, "/images/"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"), strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".webp"):
		return "image"
	case strings.HasSuffix(lower, ".srt"), strings.HasSuffix(lower, ".ass"), strings.HasSuffix(lower, ".vtt"):
		return "subtitle"
	case strings.Contains(lower, "playbackinfo"):
		return "playback"
	default:
		return "api"
	}
}

type byteBufferPool struct {
	size int
	pool sync.Pool
}

func newByteBufferPool(size int) *byteBufferPool {
	return &byteBufferPool{size: size}
}

func (p *byteBufferPool) Get() []byte {
	if value := p.pool.Get(); value != nil {
		return value.([]byte)
	}
	return make([]byte, p.size)
}

func (p *byteBufferPool) Put(buffer []byte) {
	if cap(buffer) < p.size {
		return
	}
	p.pool.Put(buffer[:p.size])
}

type accessResponseWriter struct {
	http.ResponseWriter
	status   int
	bytes    int64
	meter    *rateMeter
	flow     *connectionFlow
	clientIP string
}

func (w *accessResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *accessResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytes += int64(written)
	w.meter.AddDownload(int64(written))
	w.meter.AddClientDownload(w.clientIP, int64(written))
	w.flow.AddDownload(int64(written))
	return written, err
}

func (w *accessResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		written, err := readerFrom.ReadFrom(reader)
		w.bytes += written
		w.meter.AddDownload(written)
		w.meter.AddClientDownload(w.clientIP, written)
		w.flow.AddDownload(written)
		return written, err
	}
	written, err := io.Copy(struct{ io.Writer }{w.ResponseWriter}, reader)
	w.bytes += written
	w.meter.AddDownload(written)
	w.meter.AddClientDownload(w.clientIP, written)
	w.flow.AddDownload(written)
	return written, err
}

func (w *accessResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *accessResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &meteredConn{Conn: connection, meter: w.meter, flow: w.flow, clientIP: w.clientIP}, buffered, nil
}
