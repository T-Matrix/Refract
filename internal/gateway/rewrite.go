package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var hlsURIAttribute = regexp.MustCompile(`(?i)(URI=)("[^"]*"|[^,\r\n]*)`)

func (g *Gateway) modifyResponse(response *http.Response) error {
	info, ok := response.Request.Context().Value(targetContextKey{}).(*targetInfo)
	if !ok || info == nil {
		return fmt.Errorf("missing proxy target context")
	}

	g.rewriteResponseHeaders(response, info)
	if g.playback != nil && info != nil {
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices && len(info.PlayingReportBody) > 0 {
			if reportItemID, needLookup := g.playback.ObservePlayingReport(info.PlaybackMeta, info.PlayingReportBody); needLookup {
				g.playback.FetchItemMetadataAsync(info.PlaybackMeta, reportItemID)
			}
		}
		g.playback.ObserveStreamResponseHeaders(info.PlaybackMeta, response.Header)
	}
	if !responseHasBody(response.StatusCode, response.Request.Method) {
		return nil
	}
	if strings.TrimSpace(response.Header.Get("Content-Encoding")) != "" {
		return nil
	}

	kind := rewriteKind(response.Header.Get("Content-Type"), info.URL.Path)
	if kind == "" || response.Body == nil {
		return nil
	}
	if g.rewriteSem != nil {
		select {
		case g.rewriteSem <- struct{}{}:
			defer func() { <-g.rewriteSem }()
		case <-response.Request.Context().Done():
			return response.Request.Context().Err()
		}
	}
	maxBytes := g.liveRuntime().RewriteMaxBytes
	if info.RewriteMaxBytes > 0 {
		maxBytes = info.RewriteMaxBytes
	}
	body, tooLarge, err := readLimitedBody(response.Body, maxBytes)
	if err != nil {
		return err
	}
	if tooLarge {
		response.Body = &combinedReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), response.Body),
			Closer: response.Body,
		}
		return nil
	}
	_ = response.Body.Close()

	var rewritten []byte
	switch kind {
	case "json":
		rewritten, err = g.rewriteJSON(body, info)
	case "hls":
		rewritten = []byte(g.rewriteHLS(string(body), info))
	}
	if err != nil {
		response.Body = io.NopCloser(bytes.NewReader(body))
		response.ContentLength = int64(len(body))
		response.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		return nil
	}
	if rewritten == nil {
		rewritten = body
	}
	response.Body = io.NopCloser(bytes.NewReader(rewritten))
	response.ContentLength = int64(len(rewritten))
	response.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	response.Header.Del("Content-Encoding")
	response.Header.Del("ETag")
	return nil
}

func isActiveDocumentContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	mediaType = strings.ToLower(mediaType)
	switch mediaType {
	case "", "text/html", "application/xhtml+xml", "image/svg+xml", "text/xml", "application/xml", "text/javascript", "application/javascript":
		return true
	default:
		return strings.HasSuffix(mediaType, "+xml")
	}
}

func (g *Gateway) rewriteResponseHeaders(response *http.Response, info *targetInfo) {
	headers := response.Header
	headers.Del("Server")
	headers.Del("X-Powered-By")
	headers.Set("X-Content-Type-Options", "nosniff")
	if g.cfg.AdminEnabled && info != nil && info.Dynamic && isActiveDocumentContentType(headers.Get("Content-Type")) {
		// Prevent active content proxied from dynamic/arbitrary third-party origins from
		// executing scripts in the same origin as the standalone admin panel.
		headers.Set("Content-Security-Policy", "sandbox")
	}
	disableCache := g.liveRuntime().DisableCache
	if info != nil && info.DisableCache != nil {
		disableCache = *info.DisableCache
	}
	if disableCache {
		headers.Set("Cache-Control", "no-store")
	}
	headers.Set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Location, Content-Location, X-Emby-Auth-Token, X-MediaBrowser-Auth-Token")

	requestOrigin := strings.TrimSpace(info.ClientOrigin)
	publicOrigin := strings.TrimRight(strings.TrimSpace(info.PublicBase), "/")
	if requestOrigin != "" && publicOrigin != "" && strings.EqualFold(requestOrigin, publicOrigin) {
		headers.Set("Access-Control-Allow-Origin", requestOrigin)
		headers.Set("Access-Control-Allow-Credentials", "true")
		headers.Add("Vary", "Origin")
	} else {
		headers.Set("Access-Control-Allow-Origin", "*")
		headers.Del("Access-Control-Allow-Credentials")
		if requestOrigin != "" {
			headers.Add("Vary", "Origin")
		}
	}

	for _, name := range []string{"Location", "Content-Location"} {
		if value := headers.Get(name); value != "" {
			if rewritten, resolvedTarget, ok := g.rewriteReferenceWithTarget(value, info.URL, info); ok {
				headers.Set(name, rewritten)
				if name == "Location" && isRedirectStatus(response.StatusCode) && g.playback != nil && info != nil {
					g.playback.ObserveStreamRedirect(info.PlaybackMeta, resolvedTarget)
				}
			}
		}
	}
	if refresh := headers.Get("Refresh"); refresh != "" {
		if rewritten, ok := g.rewriteRefresh(refresh, info); ok {
			headers.Set("Refresh", rewritten)
		}
	}
	g.rewriteCookies(headers)
}

func isRedirectStatus(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

func (g *Gateway) rewriteReference(raw string, base *url.URL, info *targetInfo) (string, bool) {
	rewritten, _, ok := g.rewriteReferenceWithTarget(raw, base, info)
	return rewritten, ok
}

func (g *Gateway) rewriteReferenceWithTarget(raw string, base *url.URL, info *targetInfo) (string, *url.URL, bool) {
	reference, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw, nil, false
	}
	target := base.ResolveReference(reference)
	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil {
		return raw, nil, false
	}
	if info != nil && info.PublicBase != "" {
		if pub, pErr := url.Parse(info.PublicBase); pErr == nil && sameOrigin(target, pub) {
			return raw, nil, false
		}
	}
	if !g.cfg.AllowPrivateTargets {
		if addr, parseErr := netip.ParseAddr(strings.Trim(target.Hostname(), "[]")); parseErr == nil && isBlockedAddress(addr) {
			return raw, nil, false
		}
	}
	return g.publicURLForTarget(target, info), target, true
}

func (g *Gateway) publicURLForTarget(target *url.URL, info *targetInfo) string {
	defaultUpstream := g.liveRuntime().DefaultUpstream
	if info != nil && info.DefaultUpstream != nil {
		defaultUpstream = info.DefaultUpstream
	}
	if defaultUpstream != nil && sameOrigin(target, defaultUpstream) {
		if path, ok := stripBasePath(target.EscapedPath(), defaultUpstream.EscapedPath()); ok {
			publicURL := strings.TrimRight(info.PublicBase, "/") + path
			if target.RawQuery != "" {
				publicURL += "?" + target.RawQuery
			}
			if target.Fragment != "" {
				publicURL += "#" + target.EscapedFragment()
			}
			return publicURL
		}
	}
	return g.signedDynamicURL(target, info.PublicBase)
}

func (g *Gateway) signedDynamicURL(target *url.URL, publicBase string) string {
	copyURL := *target
	copyURL.Fragment = ""
	expires, signature := g.liveSigner().Sign(&copyURL)
	path := copyURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	rawTarget := copyURL.Scheme + "://" + copyURL.Host + path
	query := appendGatewaySignature(copyURL.RawQuery, expires, signature)
	publicURL := strings.TrimRight(publicBase, "/") + "/" + rawTarget + "?" + query
	if target.Fragment != "" {
		publicURL += "#" + target.EscapedFragment()
	}
	return publicURL
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func stripBasePath(targetPath, basePath string) (string, bool) {
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		basePath = "/"
	}
	if targetPath == "" {
		targetPath = "/"
	}
	if basePath == "/" {
		return targetPath, true
	}
	if targetPath == basePath {
		return "/", true
	}
	if strings.HasPrefix(targetPath, basePath+"/") {
		return strings.TrimPrefix(targetPath, basePath), true
	}
	return "", false
}

func (g *Gateway) rewriteRefresh(raw string, info *targetInfo) (string, bool) {
	parts := strings.SplitN(raw, ";", 2)
	if len(parts) != 2 {
		return raw, false
	}
	assignment := strings.TrimSpace(parts[1])
	name, value, ok := strings.Cut(assignment, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "url") {
		return raw, false
	}
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	rewritten, ok := g.rewriteReference(value, info.URL, info)
	if !ok {
		return raw, false
	}
	return strings.TrimSpace(parts[0]) + "; url=" + rewritten, true
}

func (g *Gateway) rewriteCookies(headers http.Header) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	headers.Del("Set-Cookie")
	for _, cookie := range cookies {
		parts := strings.Split(cookie, ";")
		if len(parts) == 0 {
			continue
		}
		cookiePair := strings.TrimSpace(parts[0])
		cookieName, _, _ := strings.Cut(cookiePair, "=")
		if strings.EqualFold(strings.TrimSpace(cookieName), adminCookieName) {
			continue
		}
		rewritten := []string{cookiePair}
		hasPath := false
		for _, part := range parts[1:] {
			part = strings.TrimSpace(part)
			lower := strings.ToLower(part)
			switch {
			case strings.HasPrefix(lower, "domain="):
				continue
			case strings.HasPrefix(lower, "path="):
				rewritten = append(rewritten, "Path=/")
				hasPath = true
			default:
				rewritten = append(rewritten, part)
			}
		}
		if !hasPath {
			rewritten = append(rewritten, "Path=/")
		}
		headers.Add("Set-Cookie", strings.Join(rewritten, "; "))
	}
}

func rewriteKind(contentType, path string) string {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	mediaType = strings.ToLower(mediaType)
	path = strings.ToLower(path)
	switch {
	case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"), mediaType == "text/json":
		return "json"
	case mediaType == "application/vnd.apple.mpegurl", mediaType == "application/x-mpegurl", strings.HasSuffix(path, ".m3u8"):
		return "hls"
	default:
		return ""
	}
}

func (g *Gateway) rewriteJSON(body []byte, info *targetInfo) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if g.playback != nil && info != nil {
		g.playback.ObserveJSONResponse(info.PlaybackMeta, value)
	}
	rewritten, _ := g.rewriteJSONValue(value, "", info)
	return json.Marshal(rewritten)
}

func (g *Gateway) rewriteJSONValue(value any, key string, info *targetInfo) (any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		changed := false
		for childKey, child := range typed {
			rewritten, childChanged := g.rewriteJSONValue(child, childKey, info)
			typed[childKey] = rewritten
			changed = changed || childChanged
		}
		return typed, changed
	case []any:
		changed := false
		for index, child := range typed {
			rewritten, childChanged := g.rewriteJSONValue(child, key, info)
			typed[index] = rewritten
			changed = changed || childChanged
		}
		return typed, changed
	case string:
		if rewritten, ok := g.rewriteJSONString(typed, key, info); ok {
			return rewritten, true
		}
	}
	return value, false
}

func (g *Gateway) rewriteJSONString(value, _ string, info *targetInfo) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if hasHTTPPrefix(trimmed) || strings.HasPrefix(trimmed, "//") {
		return g.rewriteReference(trimmed, info.URL, info)
	}
	return value, false
}

func (g *Gateway) rewriteHLS(body string, info *targetInfo) string {
	lines := strings.SplitAfter(body, "\n")
	for index, line := range lines {
		ending := ""
		content := line
		if strings.HasSuffix(content, "\n") {
			ending = "\n"
			content = strings.TrimSuffix(content, "\n")
		}
		if strings.HasSuffix(content, "\r") {
			content = strings.TrimSuffix(content, "\r")
			ending = "\r" + ending
		}
		trimmed := strings.TrimSpace(content)
		switch {
		case trimmed == "":
		case strings.HasPrefix(trimmed, "#"):
			content = hlsURIAttribute.ReplaceAllStringFunc(content, func(match string) string {
				parts := strings.SplitN(match, "=", 2)
				if len(parts) != 2 {
					return match
				}
				quoted := strings.HasPrefix(strings.TrimSpace(parts[1]), `"`)
				value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				rewritten, resolvedTarget, ok := g.rewriteReferenceWithTarget(value, info.URL, info)
				if !ok {
					return match
				}
				if g.playback != nil && info != nil {
					if _, isDirectStream, _ := extractEmbyItemIDFromPath(resolvedTarget.EscapedPath()); !(isDirectStream && sameOrigin(resolvedTarget, info.URL)) {
						g.playback.ObserveStreamRedirect(info.PlaybackMeta, resolvedTarget)
					}
				}
				if quoted {
					return parts[0] + `="` + rewritten + `"`
				}
				return parts[0] + "=" + rewritten
			})
		default:
			if rewritten, resolvedTarget, ok := g.rewriteReferenceWithTarget(trimmed, info.URL, info); ok {
				if g.playback != nil && info != nil {
					if _, isDirectStream, _ := extractEmbyItemIDFromPath(resolvedTarget.EscapedPath()); !(isDirectStream && sameOrigin(resolvedTarget, info.URL)) {
						g.playback.ObserveStreamRedirect(info.PlaybackMeta, resolvedTarget)
					}
				}
				content = rewritten
			}
		}
		lines[index] = content + ending
	}
	return strings.Join(lines, "")
}

func responseHasBody(status int, method string) bool {
	if method == http.MethodHead {
		return false
	}
	return status >= 200 && status != http.StatusNoContent && status != http.StatusResetContent && status != http.StatusNotModified
}

func readLimitedBody(body io.Reader, max int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, false, err
	}
	return data, int64(len(data)) > max, nil
}

type combinedReadCloser struct {
	io.Reader
	io.Closer
}
