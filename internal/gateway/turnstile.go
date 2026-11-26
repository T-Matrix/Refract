package gateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const turnstileSiteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var turnstileSiteKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{10,128}$`)

var (
	errTurnstileNotTested = errors.New("Turnstile configuration must pass self-test before it can be enabled")
	errTurnstileMissing   = errors.New("Turnstile configuration is incomplete")
	errTurnstileStore     = errors.New("Turnstile database unavailable")
)

type turnstileConfig struct {
	Enabled    bool   `json:"enabled"`
	SiteKey    string `json:"site_key"`
	Hostname   string `json:"hostname"`
	SecretSet  bool   `json:"secret_set"`
	Tested     bool   `json:"tested"`
	VerifiedAt int64  `json:"verified_at"`
}

type turnstileRecord struct {
	turnstileConfig
	EncryptedSecret   string
	TestedFingerprint string
}

type turnstileManager struct {
	store         *telemetryStore
	cipher        *tokenCipher
	client        *http.Client
	siteverifyURL string
}

type turnstileVerification struct {
	Success    bool     `json:"success"`
	Action     string   `json:"action"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

func newTurnstileManager(store *telemetryStore, secret []byte) (*turnstileManager, error) {
	cipher, err := newScopedTokenCipher(secret, "turnstile-secret")
	if err != nil {
		return nil, err
	}
	return &turnstileManager{
		store:         store,
		cipher:        cipher,
		client:        &http.Client{Timeout: 10 * time.Second},
		siteverifyURL: turnstileSiteverifyURL,
	}, nil
}

func (m *turnstileManager) Config(ctx context.Context) (turnstileRecord, error) {
	var record turnstileRecord
	var enabled int
	err := m.store.db.QueryRowContext(ctx,
		`SELECT enabled,site_key,secret,hostname,tested_fingerprint,verified_at
		 FROM turnstile_settings WHERE id=1`,
	).Scan(&enabled, &record.SiteKey, &record.EncryptedSecret, &record.Hostname, &record.TestedFingerprint, &record.VerifiedAt)
	if err != nil {
		return turnstileRecord{}, err
	}
	record.Enabled = enabled == 1
	record.SecretSet = record.EncryptedSecret != ""
	if record.SecretSet {
		secret, decryptErr := m.cipher.Decrypt(record.EncryptedSecret)
		if decryptErr == nil {
			record.Tested = record.TestedFingerprint != "" && record.TestedFingerprint == turnstileFingerprint(record.SiteKey, secret, record.Hostname)
		}
	}
	return record, nil
}

func (m *turnstileManager) Public(ctx context.Context) (turnstileConfig, error) {
	record, err := m.Config(ctx)
	if err != nil {
		return turnstileConfig{}, err
	}
	if !record.Enabled || !record.Tested {
		return turnstileConfig{}, nil
	}
	return turnstileConfig{Enabled: true, SiteKey: record.SiteKey}, nil
}

func (m *turnstileManager) Save(ctx context.Context, payload turnstileConfig, plainSecret string) (turnstileRecord, error) {
	if payload.Hostname != "" {
		payload.Hostname = normalizeTurnstileHostname(payload.Hostname)
	}
	if err := validateTurnstileConfig(payload, plainSecret); err != nil {
		return turnstileRecord{}, err
	}
	current, err := m.Config(ctx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return turnstileRecord{}, err
	}
	if payload.SiteKey == "" && payload.Hostname == "" && plainSecret == "" {
		if _, err := m.store.db.ExecContext(ctx,
			`UPDATE turnstile_settings SET enabled=0,site_key='',secret=X'',hostname='',tested_fingerprint='',verified_at=0,updated_at=? WHERE id=1`,
			time.Now().Unix()); err != nil {
			return turnstileRecord{}, err
		}
		return m.Config(ctx)
	}
	if plainSecret == "" && current.EncryptedSecret != "" {
		plainSecret, err = m.cipher.Decrypt(current.EncryptedSecret)
		if err != nil {
			return turnstileRecord{}, errors.New("stored Turnstile secret is unavailable")
		}
	}
	if (payload.SiteKey != "" || payload.Hostname != "") && plainSecret == "" {
		return turnstileRecord{}, errTurnstileMissing
	}
	if payload.SiteKey == "" && payload.Hostname == "" && plainSecret == "" {
		payload.Enabled = false
	}
	fingerprint := ""
	encrypted := current.EncryptedSecret
	if plainSecret != "" {
		fingerprint = turnstileFingerprint(payload.SiteKey, plainSecret, payload.Hostname)
		encrypted, err = m.cipher.Encrypt(plainSecret)
		if err != nil {
			return turnstileRecord{}, err
		}
	}
	if payload.Enabled && (current.TestedFingerprint == "" || current.TestedFingerprint != fingerprint) {
		return turnstileRecord{}, errTurnstileNotTested
	}
	testedFingerprint := ""
	verifiedAt := int64(0)
	if current.TestedFingerprint != "" && current.TestedFingerprint == fingerprint &&
		current.SiteKey == payload.SiteKey && current.Hostname == payload.Hostname {
		testedFingerprint = current.TestedFingerprint
		verifiedAt = current.VerifiedAt
	}
	if _, err := m.store.db.ExecContext(ctx,
		`UPDATE turnstile_settings SET enabled=?,site_key=?,secret=?,hostname=?,tested_fingerprint=?,verified_at=?,updated_at=? WHERE id=1`,
		boolInt(payload.Enabled), payload.SiteKey, encrypted, payload.Hostname, testedFingerprint, verifiedAt, time.Now().Unix()); err != nil {
		return turnstileRecord{}, err
	}
	return m.Config(ctx)
}

func (m *turnstileManager) Test(ctx context.Context, token, remoteIP string) (turnstileRecord, error) {
	record, err := m.Config(ctx)
	if err != nil {
		return turnstileRecord{}, fmt.Errorf("%w: %v", errTurnstileStore, err)
	}
	if record.SiteKey == "" || record.Hostname == "" || !record.SecretSet {
		return turnstileRecord{}, errTurnstileMissing
	}
	secret, err := m.cipher.Decrypt(record.EncryptedSecret)
	if err != nil {
		return turnstileRecord{}, errors.New("stored Turnstile secret is unavailable")
	}
	if err := m.verify(ctx, secret, token, "config_test", record.Hostname, remoteIP); err != nil {
		return turnstileRecord{}, err
	}
	fingerprint := turnstileFingerprint(record.SiteKey, secret, record.Hostname)
	if _, err := m.store.db.ExecContext(ctx,
		`UPDATE turnstile_settings SET tested_fingerprint=?,verified_at=?,updated_at=? WHERE id=1`,
		fingerprint, time.Now().Unix(), time.Now().Unix()); err != nil {
		return turnstileRecord{}, fmt.Errorf("%w: %v", errTurnstileStore, err)
	}
	updated, err := m.Config(ctx)
	if err != nil {
		return turnstileRecord{}, fmt.Errorf("%w: %v", errTurnstileStore, err)
	}
	return updated, nil
}

func (m *turnstileManager) VerifyLogin(ctx context.Context, token, remoteIP, requestHostname string) error {
	record, err := m.Config(ctx)
	if err != nil {
		return err
	}
	if !record.Enabled {
		return nil
	}
	if !record.Tested || record.SiteKey == "" || record.Hostname == "" || !record.SecretSet {
		return errTurnstileNotTested
	}
	if normalizeTurnstileHostname(requestHostname) != record.Hostname {
		return errors.New("Turnstile hostname mismatch")
	}
	secret, err := m.cipher.Decrypt(record.EncryptedSecret)
	if err != nil {
		return errors.New("stored Turnstile secret is unavailable")
	}
	return m.verify(ctx, secret, token, "login", record.Hostname, remoteIP)
}

func (m *turnstileManager) verify(ctx context.Context, secret, token, action, hostname, remoteIP string) error {
	if len(token) == 0 || len(token) > 2048 {
		return errors.New("Turnstile 验证令牌无效，请刷新页面后重试")
	}
	form := url.Values{"secret": {secret}, "response": {token}}
	if addr, parseErr := netip.ParseAddr(strings.TrimSpace(remoteIP)); parseErr == nil {
		unmapped := addr.Unmap()
		if unmapped.IsValid() && !unmapped.IsLoopback() && !unmapped.IsPrivate() && !unmapped.IsLinkLocalUnicast() && !unmapped.IsUnspecified() {
			form.Set("remoteip", unmapped.String())
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.siteverifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("无法创建 Cloudflare Turnstile 验证请求")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := m.client.Do(request)
	if err != nil {
		return errors.New("主控无法连接 Cloudflare Turnstile 验证接口，请检查服务器网络")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare Turnstile 验证接口返回 HTTP %d", response.StatusCode)
	}
	var result turnstileVerification
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&result); err != nil {
		return errors.New("Cloudflare Turnstile 响应解析失败")
	}
	if !result.Success {
		for _, code := range result.ErrorCodes {
			switch code {
			case "invalid-input-secret", "missing-input-secret":
				return errors.New("Secret key 无效，请核对 Cloudflare Turnstile 后台的 Secret key")
			case "timeout-or-duplicate":
				return errors.New("验证令牌已过期或已使用，请重新完成人机验证后再试")
			case "invalid-input-response", "missing-input-response", "bad-request":
				return errors.New("验证令牌无效（请确认 Site key 与 Secret key 来自同一个 Turnstile 小组件）")
			}
		}
		if len(result.ErrorCodes) > 0 {
			return fmt.Errorf("Cloudflare Turnstile 校验未通过（%s）", strings.Join(result.ErrorCodes, ", "))
		}
		return errors.New("Cloudflare Turnstile 校验未通过")
	}
	if result.Action != action {
		return errors.New("Turnstile 验证动作不匹配，请刷新页面后重新验证")
	}
	if !strings.EqualFold(result.Hostname, hostname) {
		return fmt.Errorf("Turnstile 域名不匹配：Cloudflare 返回 %s，当前主控域名为 %s", result.Hostname, hostname)
	}
	return nil
}

func validateTurnstileConfig(config turnstileConfig, plainSecret string) error {
	configured := config.SiteKey != "" || config.Hostname != "" || plainSecret != ""
	if !configured {
		if config.Enabled {
			return errTurnstileMissing
		}
		return nil
	}
	if !turnstileSiteKeyPattern.MatchString(config.SiteKey) || len(plainSecret) > 256 || plainSecret != "" && strings.TrimSpace(plainSecret) != plainSecret || !validTurnstileHostname(config.Hostname) {
		return errors.New("invalid Turnstile configuration")
	}
	return nil
}

func validTurnstileHostname(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "/\\?#:@\r\n\t ") {
		return false
	}
	u, err := url.Parse("https://" + raw)
	return err == nil && u.Hostname() == raw && u.Port() == "" && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func normalizeTurnstileHostname(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

func turnstileFingerprint(siteKey, secret, hostname string) string {
	digest := sha256.Sum256([]byte("vps-url-gateway/turnstile-config/v1\x00" + siteKey + "\x00" + hostname + "\x00" + secret))
	return hex.EncodeToString(digest[:])
}
