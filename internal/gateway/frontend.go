package gateway

import (
	"fmt"
	"net/http"
	"path"
	"strings"
)

const publicAssetPrefix = "/_gateway/assets/"

var publicFrontendAssets = map[string]struct {
	file        string
	contentType string
}{
	publicAssetPrefix + "frontend.css":     {file: "frontend.css", contentType: "text/css; charset=utf-8"},
	publicAssetPrefix + "frontend.js":      {file: "frontend.js", contentType: "text/javascript; charset=utf-8"},
	publicAssetPrefix + "refract-icon.png": {file: "refract-icon.png", contentType: "image/png"},
}

func servePublicFrontend(writer http.ResponseWriter, request *http.Request) bool {
	if servePublicFrontendAsset(writer, request) {
		return true
	}
	return servePublicFrontendPage(writer, request)
}

func servePublicFrontendAsset(writer http.ResponseWriter, request *http.Request) bool {
	asset, isAsset := publicFrontendAssets[request.URL.Path]
	if !isAsset {
		return false
	}
	return writePublicFrontendResponse(writer, request, asset.file, asset.contentType, "public, max-age=604800, immutable")
}

func servePublicFrontendPage(writer http.ResponseWriter, request *http.Request) bool {
	return servePublicFrontendPageWithRole(writer, request, "")
}

func servePublicFrontendPageWithRole(writer http.ResponseWriter, request *http.Request, role string) bool {
	if request.URL.Path != "/" || (request.Method != http.MethodGet && request.Method != http.MethodHead) {
		return false
	}
	publicFrontendHeaders(writer)
	writer.Header().Set("Cache-Control", "no-store")
	data, err := webAssets.ReadFile(path.Join("web", "frontend.html"))
	if err != nil {
		http.Error(writer, "public frontend unavailable", http.StatusInternalServerError)
		return true
	}
	rendered := strings.Replace(string(data), ">v2.0.0-beta.1<", ">v"+normalizedVersion(Version)+"<", 1)
	if role != "" {
		rendered = strings.Replace(rendered, "<body>", fmt.Sprintf(`<body data-role="%s">`, role), 1)
	}
	data = []byte(rendered)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(data)
	}
	return true
}

func writePublicFrontendResponse(writer http.ResponseWriter, request *http.Request, fileName, contentType, cacheControl string) bool {
	publicFrontendHeaders(writer)
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeGatewayError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return true
	}
	writer.Header().Set("Cache-Control", cacheControl)
	data, err := webAssets.ReadFile(path.Join("web", fileName))
	if err != nil {
		http.Error(writer, "public frontend unavailable", http.StatusInternalServerError)
		return true
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(data)
	}
	return true
}

func publicFrontendHeaders(writer http.ResponseWriter) {
	headers := writer.Header()
	headers.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'", "img-src 'self'", "style-src 'self'", "script-src 'self'",
		"connect-src 'self'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'",
	}, "; "))
	headers.Set("Cross-Origin-Resource-Policy", "same-origin")
	headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
}
