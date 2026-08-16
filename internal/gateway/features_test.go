package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyPolicyMatchingAndPrecedence(t *testing.T) {
	target := mustURL(t, "https://media.example.com/Videos/1/stream.m3u8")
	policy := &proxyPolicy{Mode: proxyModeOff, Rules: []proxyRule{{Action: "deny", DomainSuffix: "example.com", Enabled: true}}}
	if !policy.Allows(target) {
		t.Fatal("off mode blocked a request")
	}

	policy.Mode = proxyModeBlacklist
	if policy.Allows(target) {
		t.Fatal("deny suffix did not block a subdomain")
	}
	if !policy.Allows(mustURL(t, "https://badexample.com/Videos/1")) {
		t.Fatal("domain suffix matched without a label boundary")
	}

	policy = &proxyPolicy{
		Mode: proxyModeWhitelist,
		Rules: []proxyRule{
			{Action: "deny", DomainSuffix: "example.com", Enabled: true},
			{Action: "allow", DomainSuffix: "media.example.com", Enabled: true},
		},
	}
	if !policy.Allows(target) {
		t.Fatal("whitelist rule did not allow the domain")
	}
	if !policy.Allows(mustURL(t, "https://media.example.com/Items/1")) {
		t.Fatal("domain allow rule did not apply to every path")
	}
	if policy.Allows(mustURL(t, "https://other.example.com/Items/1")) {
		t.Fatal("whitelist mode allowed an unlisted subdomain")
	}
	if policy.Allows(mustURL(t, "https://unmatched.test/Items/1")) {
		t.Fatal("whitelist mode allowed an unlisted domain")
	}
}

func TestProxyPolicyIPRuleMatchesOnlyTheAddress(t *testing.T) {
	rule, err := normalizeProxyRule("allow", "2001:0db8:0:0:0:0:0:1")
	if err != nil {
		t.Fatal(err)
	}
	if rule.DomainSuffix != "2001:db8::1" || !rule.matchesHost("2001:db8::1") {
		t.Fatalf("IPv6 rule was not canonicalized: %#v", rule)
	}
	ipv4, err := normalizeProxyRule("allow", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if ipv4.matchesHost("foo.8.8.8.8") {
		t.Fatal("IP rule matched a DNS name with the same textual suffix")
	}
}

func TestPolicyCanBeManagedAndBlocksBeforeDNS(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)

	created := adminRequest(t, gateway, http.MethodPut, "/_admin/api/rules/domain", map[string]any{
		"access": "block", "domain": "blocked.invalid",
	}, cookie, true)
	if created.Code != http.StatusOK {
		t.Fatalf("create rule status=%d body=%s", created.Code, created.Body.String())
	}
	if gateway.policy.Load().Mode != proxyModeBlacklist {
		t.Fatal("quick block did not activate blacklist mode")
	}

	gateway.cfg.AllowUnsigned = true
	request := httptest.NewRequest(http.MethodGet, "https://proxy.test/https://blocked.invalid/any/path", nil)
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "proxy policy") {
		t.Fatalf("blocked request status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	released := adminRequest(t, gateway, http.MethodPut, "/_admin/api/rules/domain", map[string]any{
		"access": "allow", "domain": "blocked.invalid",
	}, cookie, true)
	if released.Code != http.StatusOK || !gateway.policy.Load().Allows(mustURL(t, "https://blocked.invalid/another/path")) {
		t.Fatalf("quick allow did not release the domain: status=%d body=%s", released.Code, released.Body.String())
	}
	if len(gateway.policy.Load().Rules) != 0 {
		t.Fatal("quick allow did not remove the blacklist rule")
	}

	mode := adminRequest(t, gateway, http.MethodPut, "/_admin/api/policy", map[string]string{"mode": proxyModeWhitelist}, cookie, true)
	if mode.Code != http.StatusOK {
		t.Fatalf("enable whitelist status=%d body=%s", mode.Code, mode.Body.String())
	}
	allowed := adminRequest(t, gateway, http.MethodPut, "/_admin/api/rules/domain", map[string]any{
		"access": "allow", "domain": "allowed.invalid",
	}, cookie, true)
	if allowed.Code != http.StatusOK || !gateway.policy.Load().Allows(mustURL(t, "https://allowed.invalid/any")) {
		t.Fatalf("quick whitelist status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if gateway.policy.Load().Allows(mustURL(t, "https://other.invalid/any")) {
		t.Fatal("whitelist mode allowed an unlisted domain")
	}
}

func TestProxyPolicyDefaultsOffAndMigratesLegacyRules(t *testing.T) {
	gateway := newAdminTestGateway(t)
	if gateway.policy.Load().Mode != proxyModeOff {
		t.Fatalf("new policy mode = %q, want off", gateway.policy.Load().Mode)
	}
	if _, err := gateway.telemetry.db.Exec(
		`INSERT INTO proxy_rules(action,domain_suffix,path_prefix,enabled,created_at) VALUES('deny','legacy.invalid','/old/path',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.telemetry.db.Exec(
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES('proxy_policy_enabled','1',1)`); err != nil {
		t.Fatal(err)
	}
	if err := gateway.reloadProxyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	policy := gateway.policy.Load()
	if policy.Mode != proxyModeBlacklist {
		t.Fatalf("legacy policy mode = %q, want blacklist", policy.Mode)
	}
	if policy.Allows(mustURL(t, "https://legacy.invalid/completely/different/path")) {
		t.Fatal("legacy path_prefix still affected domain-only matching")
	}
}

func TestRuleAPIRequiresModeAndDerivesListFromIt(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)

	whileOff := adminRequest(t, gateway, http.MethodPost, "/_admin/api/rules", map[string]string{
		"domain_suffix": "blocked.invalid",
	}, cookie, true)
	if whileOff.Code != http.StatusConflict {
		t.Fatalf("rule in off mode status=%d body=%s", whileOff.Code, whileOff.Body.String())
	}

	mode := adminRequest(t, gateway, http.MethodPut, "/_admin/api/policy", map[string]string{
		"mode": proxyModeBlacklist,
	}, cookie, true)
	if mode.Code != http.StatusOK {
		t.Fatalf("blacklist mode status=%d body=%s", mode.Code, mode.Body.String())
	}
	created := adminRequest(t, gateway, http.MethodPost, "/_admin/api/rules", map[string]string{
		"domain_suffix": "blocked.invalid",
	}, cookie, true)
	if created.Code != http.StatusCreated || len(gateway.policy.Load().Rules) != 1 || gateway.policy.Load().Rules[0].Action != "deny" {
		t.Fatalf("blacklist rule status=%d body=%s policy=%#v", created.Code, created.Body.String(), gateway.policy.Load())
	}

	legacyPayload := adminRequest(t, gateway, http.MethodPost, "/_admin/api/rules", map[string]string{
		"action": "allow", "domain_suffix": "unexpected.invalid",
	}, cookie, true)
	if legacyPayload.Code != http.StatusBadRequest {
		t.Fatalf("legacy action field status=%d body=%s", legacyPayload.Code, legacyPayload.Body.String())
	}

	mode = adminRequest(t, gateway, http.MethodPut, "/_admin/api/policy", map[string]string{
		"mode": proxyModeWhitelist,
	}, cookie, true)
	if mode.Code != http.StatusOK {
		t.Fatalf("whitelist mode status=%d body=%s", mode.Code, mode.Body.String())
	}
	created = adminRequest(t, gateway, http.MethodPost, "/_admin/api/rules", map[string]string{
		"domain_suffix": "allowed.invalid",
	}, cookie, true)
	if created.Code != http.StatusCreated || gateway.policy.Load().Rules[0].Action != "allow" {
		t.Fatalf("whitelist rule status=%d body=%s policy=%#v", created.Code, created.Body.String(), gateway.policy.Load())
	}
}

func TestRateMeterCountsActualRequestAndResponseBytes(t *testing.T) {
	meter := newRateMeter()
	defer meter.Close()

	body := &countingReadCloser{ReadCloser: io.NopCloser(strings.NewReader("request-body")), meter: meter}
	read, err := io.ReadAll(body)
	if err != nil || string(read) != "request-body" || body.Count() != int64(len(read)) {
		t.Fatalf("request counter read=%q count=%d err=%v", read, body.Count(), err)
	}
	recorder := httptest.NewRecorder()
	writer := &accessResponseWriter{ResponseWriter: recorder, meter: meter}
	if _, err := io.Copy(writer, bytes.NewBufferString("response-body")); err != nil {
		t.Fatal(err)
	}
	snapshot := meter.Snapshot(2)
	if snapshot.UploadTotal != int64(len("request-body")) || snapshot.DownloadTotal != int64(len("response-body")) || snapshot.ActiveRequests != 2 {
		t.Fatalf("unexpected live snapshot: %#v", snapshot)
	}
}

func TestTelegramTokenIsEncryptedAndNeverReturnedByAPI(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	token := "123456789:" + strings.Repeat("A", 35)

	saved := adminRequest(t, gateway, http.MethodPut, "/_admin/api/telegram", map[string]any{
		"enabled": true, "bot_token": token, "chat_id": "-1001234567890", "send_hour": 8,
	}, cookie, true)
	if saved.Code != http.StatusOK || strings.Contains(saved.Body.String(), token) {
		t.Fatalf("save telegram status=%d body=%s", saved.Code, saved.Body.String())
	}
	record, err := gateway.telemetry.TelegramRecord(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if record.EncryptedToken == "" || strings.Contains(record.EncryptedToken, token) {
		t.Fatal("telegram token was not encrypted at rest")
	}
	plain, err := gateway.telegram.cipher.Decrypt(record.EncryptedToken)
	if err != nil || plain != token {
		t.Fatalf("decrypt token=%q err=%v", plain, err)
	}

	loaded := adminRequest(t, gateway, http.MethodGet, "/_admin/api/telegram", nil, cookie, false)
	if loaded.Code != http.StatusOK || strings.Contains(loaded.Body.String(), token) || strings.Contains(loaded.Body.String(), record.EncryptedToken) {
		t.Fatalf("telegram API exposed a secret: %s", loaded.Body.String())
	}
	var config telegramConfig
	if err := json.Unmarshal(loaded.Body.Bytes(), &config); err != nil || !config.TokenSet {
		t.Fatalf("telegram API response=%s err=%v", loaded.Body.String(), err)
	}
}

func TestTokenCipherRejectsDifferentSecret(t *testing.T) {
	first, err := newTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newTokenCipher([]byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := first.Encrypt("123456789:" + strings.Repeat("B", 35))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Decrypt(encrypted); err == nil {
		t.Fatal("ciphertext decrypted with a different administrator secret")
	}
}
