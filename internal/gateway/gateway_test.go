package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseRawTargetPreservesOriginalQuery(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://proxy.test/https://cdn.example/video.m3u8?token=a%2Fb&quality=4k", nil)
	target, dynamic, expires, signature, err := parseRawTarget(request)
	if err != nil {
		t.Fatalf("parseRawTarget() error = %v", err)
	}
	if !dynamic || expires != "" || signature != "" {
		t.Fatalf("unexpected dynamic metadata: dynamic=%v expires=%q signature=%q", dynamic, expires, signature)
	}
	if got, want := target.String(), "https://cdn.example/video.m3u8?token=a%2Fb&quality=4k"; got != want {
		t.Fatalf("target = %q, want %q", got, want)
	}
}

func TestParseRawTargetAcceptsWholeURLPercentEncoding(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://proxy.test/https%3A%2F%2Fcdn.example%2Fvideo.m3u8", nil)
	target, dynamic, _, _, err := parseRawTarget(request)
	if err != nil {
		t.Fatalf("parseRawTarget() error = %v", err)
	}
	if !dynamic || target.String() != "https://cdn.example/video.m3u8" {
		t.Fatalf("target = %v dynamic=%v", target, dynamic)
	}
}

func TestParseRawTargetAcceptsEmbyPrefixedSameOriginProxyURL(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()
	gateway.signer.now = func() time.Time { return time.Unix(1_800_000_000, 0) }

	target := mustURL(t, "https://media.example:443/Videos/1/stream.mkv?token=abc")
	publicURL := gateway.signedDynamicURL(target, "https://proxy.example")
	mangledURL := strings.Replace(publicURL, "https://proxy.example/", "https://proxy.example/embyhttps://proxy.example/", 1)
	request := httptest.NewRequest(http.MethodGet, mangledURL, nil)
	request.Host = "127.0.0.1:8080"

	parsed, dynamic, expires, signature, err := parseRawTarget(request, "proxy.example")
	if err != nil {
		t.Fatalf("parseRawTarget() error = %v", err)
	}
	if !dynamic || parsed.String() != target.String() {
		t.Fatalf("target = %v dynamic=%v", parsed, dynamic)
	}
	if !gateway.signer.Verify(parsed, expires, signature) {
		t.Fatal("signature did not verify after Emby client URL normalization")
	}
}

func TestParseRawTargetRejectsEmbyPrefixedForeignProxyURL(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "https://proxy.example/embyhttps://attacker.example/https://media.example/video.mkv", nil)
	target, dynamic, _, _, err := parseRawTarget(request, "proxy.example")
	if err != nil {
		t.Fatalf("parseRawTarget() error = %v", err)
	}
	if dynamic || target != nil {
		t.Fatalf("foreign proxy wrapper was accepted: target=%v dynamic=%v", target, dynamic)
	}
}

func TestSignedURLPreservesQueryAndRejectsTampering(t *testing.T) {
	cfg := testConfig()
	gateway := New(cfg)
	defer gateway.Close()
	gateway.signer.now = func() time.Time { return time.Unix(1_800_000_000, 0) }

	target := mustURL(t, "https://cdn.example/video?token=a%2Fb&x=1&x=2")
	publicURL := gateway.signedDynamicURL(target, "https://proxy.example")
	request := httptest.NewRequest(http.MethodGet, publicURL, nil)
	parsed, dynamic, expires, signature, err := parseRawTarget(request)
	if err != nil {
		t.Fatalf("parseRawTarget() error = %v", err)
	}
	if !dynamic || parsed.RawQuery != "token=a%2Fb&x=1&x=2" {
		t.Fatalf("parsed target = %q", parsed.String())
	}
	if !gateway.signer.Verify(parsed, expires, signature) {
		t.Fatal("generated signature did not verify")
	}
	parsed.Path = "/other"
	if gateway.signer.Verify(parsed, expires, signature) {
		t.Fatal("tampered target signature verified")
	}
}

func TestGatewayRewritesAndAuthorizesExternalRedirect(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "token=a%2Fb&x=1&x=2" {
			t.Errorf("CDN query = %q", request.URL.RawQuery)
		}
		_, _ = writer.Write([]byte("stream-data"))
	}))
	defer cdn.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", cdn.URL+"/video?token=a%2Fb&x=1&x=2")
		writer.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	gateway, gatewayServer := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(gatewayServer.URL + "/redirect")
	if err != nil {
		t.Fatalf("gateway redirect request: %v", err)
	}
	_ = response.Body.Close()
	location := response.Header.Get("Location")
	if !strings.HasPrefix(location, gatewayServer.URL+"/http://") || !strings.Contains(location, signatureParam+"=") {
		t.Fatalf("rewritten Location = %q", location)
	}

	streamResponse, err := http.Get(location)
	if err != nil {
		t.Fatalf("signed CDN request: %v", err)
	}
	body, _ := io.ReadAll(streamResponse.Body)
	_ = streamResponse.Body.Close()
	if streamResponse.StatusCode != http.StatusOK || string(body) != "stream-data" {
		t.Fatalf("CDN response status=%d body=%q", streamResponse.StatusCode, body)
	}
}

func TestGatewayProxiesEmbyPrefixedSignedStreamURL(t *testing.T) {
	stream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/Videos/1/stream.mkv" || request.URL.Query().Get("token") != "abc" {
			t.Errorf("stream URL = %q", request.URL.String())
		}
		_, _ = writer.Write([]byte("stream-data"))
	}))
	defer stream.Close()

	gateway, gatewayServer := newTestGateway(t, stream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	target := mustURL(t, stream.URL+"/Videos/1/stream.mkv?token=abc")
	signedURL := gateway.signedDynamicURL(target, gatewayServer.URL)
	mangledURL := gatewayServer.URL + "/emby" + signedURL
	response, err := http.Get(mangledURL)
	if err != nil {
		t.Fatalf("Emby-prefixed stream request: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "stream-data" {
		t.Fatalf("stream response status=%d body=%q", response.StatusCode, body)
	}
}

func TestGatewayProxiesNestedEmbyPrefixedSignedStreamURL(t *testing.T) {
	stream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/Videos/1/stream.mkv" || request.URL.Query().Get("token") != "abc" {
			t.Errorf("stream URL = %q", request.URL.String())
		}
		_, _ = writer.Write([]byte("stream-data"))
	}))
	defer stream.Close()

	gateway, gatewayServer := newTestGateway(t, stream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	target := mustURL(t, stream.URL+"/Videos/1/stream.mkv?token=abc")
	signedURL := gateway.signedDynamicURL(target, gatewayServer.URL)
	configuredBase := gatewayServer.URL + "/" + stream.URL
	mangledURL := configuredBase + "/emby" + signedURL
	response, err := http.Get(mangledURL)
	if err != nil {
		t.Fatalf("nested Emby-prefixed stream request: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "stream-data" {
		t.Fatalf("stream response status=%d body=%q", response.StatusCode, body)
	}
}

func TestGatewayRewritesJSONAndHLSBackends(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("cdn:" + request.URL.Path))
	}))
	defer cdn.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/playback":
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"MediaUrl":  cdn.URL + "/movie.mp4?token=abc",
				"LocalPath": "/Videos/1/stream.mp4",
			})
		case "/master.m3u8":
			writer.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			_, _ = fmt.Fprintf(writer, "#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"key.bin\"\n%s/segment.ts?token=abc\nrelative.ts\n", cdn.URL)
		case "/key.bin", "/relative.ts", "/Videos/1/stream.mp4":
			_, _ = writer.Write([]byte("origin:" + request.URL.Path))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer upstream.Close()

	gateway, gatewayServer := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	jsonResponse, err := http.Get(gatewayServer.URL + "/playback")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.NewDecoder(jsonResponse.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	_ = jsonResponse.Body.Close()
	if !strings.HasPrefix(payload["MediaUrl"], gatewayServer.URL+"/http://") || !strings.Contains(payload["MediaUrl"], signatureParam+"=") {
		t.Fatalf("MediaUrl = %q", payload["MediaUrl"])
	}
	if payload["LocalPath"] != "/Videos/1/stream.mp4" {
		t.Fatalf("default upstream path unexpectedly changed: %q", payload["LocalPath"])
	}

	hlsResponse, err := http.Get(gatewayServer.URL + "/master.m3u8")
	if err != nil {
		t.Fatal(err)
	}
	hlsBody, _ := io.ReadAll(hlsResponse.Body)
	_ = hlsResponse.Body.Close()
	hls := string(hlsBody)
	if !strings.Contains(hls, gatewayServer.URL+"/http://") || !strings.Contains(hls, gatewayServer.URL+"/key.bin") || !strings.Contains(hls, gatewayServer.URL+"/relative.ts") {
		t.Fatalf("rewritten HLS = %q", hls)
	}
}

func TestGatewayPreservesRelativePlaybackURLsForDynamicTarget(t *testing.T) {
	cdn := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("cdn:" + request.URL.Path))
	}))
	defer cdn.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/emby/Items/1/PlaybackInfo" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"MediaSources": []any{map[string]any{
				"DirectStreamUrl": "/videos/1/stream.mkv?MediaSourceId=1",
				"TranscodingUrl":  cdn.URL + "/videos/1/master.m3u8?MediaSourceId=1",
			}},
		})
	}))
	defer upstream.Close()

	gateway, gatewayServer := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	playbackTarget := mustURL(t, upstream.URL+"/emby/Items/1/PlaybackInfo")
	response, err := http.Get(gateway.signedDynamicURL(playbackTarget, gatewayServer.URL))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		MediaSources []struct {
			DirectStreamURL string `json:"DirectStreamUrl"`
			TranscodingURL  string `json:"TranscodingUrl"`
		} `json:"MediaSources"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if len(payload.MediaSources) != 1 {
		t.Fatalf("media sources = %#v", payload.MediaSources)
	}
	media := payload.MediaSources[0]
	if media.DirectStreamURL != "/videos/1/stream.mkv?MediaSourceId=1" {
		t.Fatalf("relative DirectStreamUrl was rewritten: %q", media.DirectStreamURL)
	}
	if !strings.HasPrefix(media.TranscodingURL, gatewayServer.URL+"/http://") || !strings.Contains(media.TranscodingURL, signatureParam+"=") {
		t.Fatalf("absolute TranscodingUrl was not signed: %q", media.TranscodingURL)
	}
}

func TestGatewayPreservesRangeResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Range") != "bytes=10-19" {
			t.Errorf("Range = %q", request.Header.Get("Range"))
		}
		writer.Header().Set("Accept-Ranges", "bytes")
		writer.Header().Set("Content-Range", "bytes 10-19/100")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("0123456789"))
	}))
	defer upstream.Close()

	gateway, gatewayServer := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	request, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/video", nil)
	request.Header.Set("Range", "bytes=10-19")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusPartialContent || response.Header.Get("Content-Range") != "bytes 10-19/100" {
		t.Fatalf("range response status=%d content-range=%q", response.StatusCode, response.Header.Get("Content-Range"))
	}
}

func TestGatewayProxiesWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
			http.Error(writer, "missing upgrade", http.StatusBadRequest)
			return
		}
		connection, buffered, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer connection.Close()
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffered.Flush()
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(buffered, buffer); err == nil {
			_, _ = connection.Write(buffer)
		}
	}))
	defer upstream.Close()

	gateway, gatewayServer := newTestGateway(t, upstream.URL)
	defer gateway.Close()
	defer gatewayServer.Close()

	gatewayAddress := strings.TrimPrefix(gatewayServer.URL, "http://")
	connection, err := net.DialTimeout("tcp", gatewayAddress, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_, _ = fmt.Fprintf(connection, "GET /socket HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", gatewayAddress)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d", response.StatusCode)
	}
	_, _ = connection.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q", echo)
	}
}

func TestGatewayBlocksPrivateAndUnauthorizedTargets(t *testing.T) {
	cfg := testConfig()
	cfg.AllowPrivateTargets = false
	cfg.AllowedUpstreams = []TargetPattern{{Host: "127.0.0.1"}}
	gateway := New(cfg)
	defer gateway.Close()
	server := httptest.NewServer(gateway)
	defer server.Close()

	response, err := http.Get(server.URL + "/http://127.0.0.1:8096/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("private target status = %d", response.StatusCode)
	}

	cfg = testConfig()
	gateway2 := New(cfg)
	defer gateway2.Close()
	server2 := httptest.NewServer(gateway2)
	defer server2.Close()
	response, err = http.Get(server2.URL + "/https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized target status = %d", response.StatusCode)
	}
}

func TestCanceledProxyRequestIsRecordedAs499(t *testing.T) {
	gateway := New(testConfig())
	defer gateway.Close()
	writer := &accessResponseWriter{ResponseWriter: httptest.NewRecorder()}
	gateway.handleProxyError(writer, httptest.NewRequest(http.MethodGet, "http://proxy.test/", nil), context.Canceled)
	if writer.status != 499 {
		t.Fatalf("canceled request status=%d, want 499", writer.status)
	}
}

func TestTargetPatternWildcardDoesNotMatchApex(t *testing.T) {
	pattern, err := parseTargetPattern("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if pattern.Matches(mustURL(t, "https://example.com")) {
		t.Fatal("wildcard unexpectedly matched apex")
	}
	if !pattern.Matches(mustURL(t, "https://cdn.example.com")) {
		t.Fatal("wildcard did not match subdomain")
	}
}

func newTestGateway(t *testing.T, upstream string) (*Gateway, *httptest.Server) {
	t.Helper()
	cfg := testConfig()
	cfg.DefaultUpstream = mustURL(t, upstream)
	cfg.AllowedUpstreams = []TargetPattern{patternFromURL(cfg.DefaultUpstream)}
	cfg.AllowPrivateTargets = true
	gateway := New(cfg)
	return gateway, httptest.NewServer(gateway)
}

func testConfig() Config {
	return Config{
		SigningSecret:   []byte("0123456789abcdef0123456789abcdef"),
		SignedURLTTL:    24 * time.Hour,
		RewriteMaxBytes: 8 << 20,
		DNSCacheTTL:     time.Minute,
		DialTimeout:     5 * time.Second,
		ResponseTimeout: 5 * time.Second,
		DisableCache:    true,
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
