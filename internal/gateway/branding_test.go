package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrandingAvatarUploadIsAuthenticatedAndSharedPublicly(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	avatar, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}

	unauthenticated := adminRequest(t, gateway, http.MethodGet, "/_admin/api/branding", nil, nil, false)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated branding status=%d", unauthenticated.Code)
	}
	crossOrigin := uploadBrandingAvatar(t, gateway, avatar, cookie, false)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin avatar upload status=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}
	uploaded := uploadBrandingAvatar(t, gateway, avatar, cookie, true)
	if uploaded.Code != http.StatusOK {
		t.Fatalf("avatar upload status=%d body=%s", uploaded.Code, uploaded.Body.String())
	}
	var view brandingView
	if err := json.NewDecoder(uploaded.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if !view.Custom || view.UpdatedAt <= 0 {
		t.Fatalf("avatar view=%#v", view)
	}

	publicRequest := httptest.NewRequest(http.MethodGet, "https://proxy.test/_gateway/avatar", nil)
	publicResponse := httptest.NewRecorder()
	gateway.ServeHTTP(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusOK || publicResponse.Header().Get("Content-Type") != "image/png" ||
		!bytes.Equal(publicResponse.Body.Bytes(), avatar) || publicResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public avatar status=%d headers=%#v bytes=%d", publicResponse.Code, publicResponse.Header(), publicResponse.Body.Len())
	}

	reset := adminRequest(t, gateway, http.MethodDelete, "/_admin/api/branding", nil, cookie, true)
	if reset.Code != http.StatusOK || reset.Body.String() != "{\"custom\":false,\"updated_at\":0}\n" {
		t.Fatalf("avatar reset status=%d body=%s", reset.Code, reset.Body.String())
	}
}

func TestBrandingAvatarRejectsDisguisedImage(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	fake := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte("not-an-image"), 20)...)
	response := uploadBrandingAvatar(t, gateway, fake, cookie, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("fake avatar status=%d body=%s", response.Code, response.Body.String())
	}
}

func uploadBrandingAvatar(t *testing.T, gateway *Gateway, data []byte, cookie *http.Cookie, withOrigin bool) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("avatar", "avatar.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://proxy.test/_admin/api/branding", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	if withOrigin {
		request.Header.Set("Origin", "https://proxy.test")
	}
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	return response
}
