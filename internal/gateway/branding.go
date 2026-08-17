package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	brandingAvatarSetting = "branding_avatar_v1"
	maxBrandAvatarBytes   = 512 << 10
)

type brandingAvatar struct {
	MIME      string `json:"mime"`
	Data      string `json:"data"`
	UpdatedAt int64  `json:"updated_at"`
}

type brandingView struct {
	Custom    bool  `json:"custom"`
	UpdatedAt int64 `json:"updated_at"`
}

func (s *telemetryStore) loadBrandingAvatar(ctx context.Context) (brandingAvatar, bool, error) {
	stored, err := s.setting(ctx, brandingAvatarSetting)
	if err != nil || stored == "" {
		return brandingAvatar{}, false, err
	}
	var avatar brandingAvatar
	if err := json.Unmarshal([]byte(stored), &avatar); err != nil {
		return brandingAvatar{}, false, err
	}
	data, err := base64.StdEncoding.DecodeString(avatar.Data)
	if err != nil || len(data) == 0 || len(data) > maxBrandAvatarBytes || !validBrandAvatar(data, avatar.MIME) {
		return brandingAvatar{}, false, errors.New("stored avatar is invalid")
	}
	return avatar, true, nil
}

func (s *telemetryStore) saveBrandingAvatar(ctx context.Context, mime string, data []byte) (brandingView, error) {
	avatar := brandingAvatar{
		MIME:      mime,
		Data:      base64.StdEncoding.EncodeToString(data),
		UpdatedAt: time.Now().UnixMilli(),
	}
	encoded, err := json.Marshal(avatar)
	if err != nil {
		return brandingView{}, err
	}
	if err := s.setSetting(ctx, brandingAvatarSetting, string(encoded)); err != nil {
		return brandingView{}, err
	}
	return brandingView{Custom: true, UpdatedAt: avatar.UpdatedAt}, nil
}

func (s *telemetryStore) clearBrandingAvatar(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM gateway_settings WHERE key=?`, brandingAvatarSetting)
	return err
}

func (s *telemetryStore) brandingView(ctx context.Context) (brandingView, error) {
	avatar, custom, err := s.loadBrandingAvatar(ctx)
	if err != nil {
		return brandingView{}, err
	}
	return brandingView{Custom: custom, UpdatedAt: avatar.UpdatedAt}, nil
}

func validBrandAvatar(data []byte, mime string) bool {
	if len(data) == 0 || len(data) > maxBrandAvatarBytes || http.DetectContentType(data) != mime {
		return false
	}
	switch mime {
	case "image/png":
		if len(data) < 8 || string(data[:8]) != "\x89PNG\r\n\x1a\n" {
			return false
		}
		return validRasterDimensions(data)
	case "image/jpeg":
		if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 || data[len(data)-2] != 0xff || data[len(data)-1] != 0xd9 {
			return false
		}
		return validRasterDimensions(data)
	case "image/webp":
		return validWebPDimensions(data)
	default:
		return false
	}
}

func validWebPDimensions(data []byte) bool {
	if len(data) < 16 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" || int64(binary.LittleEndian.Uint32(data[4:8]))+8 > int64(len(data)) {
		return false
	}
	width, height := 0, 0
	switch string(data[12:16]) {
	case "VP8 ":
		if len(data) < 30 || string(data[23:26]) != "\x9d\x01\x2a" {
			return false
		}
		width = int(binary.LittleEndian.Uint16(data[26:28]) & 0x3fff)
		height = int(binary.LittleEndian.Uint16(data[28:30]) & 0x3fff)
	case "VP8L":
		if len(data) < 25 || data[20] != 0x2f {
			return false
		}
		bits := binary.LittleEndian.Uint32(data[21:25])
		width = int(bits&0x3fff) + 1
		height = int((bits>>14)&0x3fff) + 1
	case "VP8X":
		if len(data) < 30 {
			return false
		}
		width = int(data[24]) | int(data[25])<<8 | int(data[26])<<16
		height = int(data[27]) | int(data[28])<<8 | int(data[29])<<16
		width++
		height++
	default:
		return false
	}
	return width > 0 && height > 0 && width <= 4096 && height <= 4096
}

func validRasterDimensions(data []byte) bool {
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	return err == nil && config.Width > 0 && config.Height > 0 && config.Width <= 4096 && config.Height <= 4096
}

func (g *Gateway) serveBrandAvatar(writer http.ResponseWriter, request *http.Request) bool {
	if request.URL.Path != "/_gateway/avatar" {
		return false
	}
	publicFrontendHeaders(writer)
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		writeGatewayError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return true
	}

	data, mime := []byte(nil), ""
	if g.telemetry != nil {
		if avatar, custom, err := g.telemetry.loadBrandingAvatar(request.Context()); err == nil && custom {
			data, mime = decodeBrandAvatar(avatar)
		}
	}
	if len(data) == 0 {
		data, _ = webAssets.ReadFile(path.Join("web", "refract-icon.png"))
		mime = "image/png"
	}
	if len(data) == 0 {
		http.Error(writer, "avatar unavailable", http.StatusInternalServerError)
		return true
	}
	writer.Header().Set("Content-Type", mime)
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	writer.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(data)
	}
	return true
}

func decodeBrandAvatar(avatar brandingAvatar) ([]byte, string) {
	data, err := base64.StdEncoding.DecodeString(avatar.Data)
	if err != nil || !validBrandAvatar(data, avatar.MIME) {
		return nil, ""
	}
	return data, avatar.MIME
}

func (a *adminServer) handleBranding(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		view, err := a.store.brandingView(request.Context())
		if err != nil {
			a.writeError(writer, http.StatusInternalServerError, "branding settings unavailable")
			return
		}
		a.writeJSON(writer, http.StatusOK, view)
	case http.MethodPost:
		if !sameOriginRequest(request) {
			a.writeError(writer, http.StatusForbidden, "same-origin request required")
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxBrandAvatarBytes+(64<<10))
		if err := request.ParseMultipartForm(maxBrandAvatarBytes); err != nil {
			a.writeError(writer, http.StatusBadRequest, "invalid avatar upload")
			return
		}
		file, _, err := request.FormFile("avatar")
		if err != nil {
			a.writeError(writer, http.StatusBadRequest, "avatar file is required")
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxBrandAvatarBytes+1))
		if err != nil || len(data) == 0 || len(data) > maxBrandAvatarBytes {
			a.writeError(writer, http.StatusBadRequest, "avatar must not exceed 512 KiB")
			return
		}
		mime := strings.ToLower(strings.TrimSpace(http.DetectContentType(data)))
		if !validBrandAvatar(data, mime) {
			a.writeError(writer, http.StatusBadRequest, "avatar must be PNG, JPEG, or WebP")
			return
		}
		view, err := a.store.saveBrandingAvatar(request.Context(), mime, data)
		if err != nil {
			a.writeError(writer, http.StatusInternalServerError, "avatar update failed")
			return
		}
		a.auditRequest(request, "branding.avatar", "custom", "", true)
		a.writeJSON(writer, http.StatusOK, view)
	case http.MethodDelete:
		if !sameOriginRequest(request) {
			a.writeError(writer, http.StatusForbidden, "same-origin request required")
			return
		}
		if err := a.store.clearBrandingAvatar(request.Context()); err != nil {
			a.writeError(writer, http.StatusInternalServerError, "avatar reset failed")
			return
		}
		a.auditRequest(request, "branding.avatar", "default", "", true)
		a.writeJSON(writer, http.StatusOK, brandingView{})
	default:
		a.methodNotAllowed(writer, http.MethodGet+", "+http.MethodPost+", "+http.MethodDelete)
	}
}
