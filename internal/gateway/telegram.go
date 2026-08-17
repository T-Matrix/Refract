package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

var (
	telegramTokenPattern = regexp.MustCompile(`^[0-9]{6,15}:[A-Za-z0-9_-]{30,}$`)
	telegramChatPattern  = regexp.MustCompile(`^(?:-?[0-9]{1,24}|@[A-Za-z0-9_]{5,32})$`)
)

type telegramConfig struct {
	Enabled      bool   `json:"enabled"`
	ChatID       string `json:"chat_id"`
	SendHour     int    `json:"send_hour"`
	TokenSet     bool   `json:"token_set"`
	LastSentDate string `json:"last_sent_date"`
}

type telegramRecord struct {
	telegramConfig
	EncryptedToken string `json:"-"`
}

type dailyReport struct {
	Requests int64
	BytesIn  int64
	BytesOut int64
	Errors   int64
	Targets  int64
	Top      []targetSummary
}

type tokenCipher struct {
	aead cipher.AEAD
	aad  []byte
}

func newTokenCipher(secret []byte) (*tokenCipher, error) {
	return newScopedTokenCipherWithAAD(secret, "telegram-token", "telegram-bot-token")
}

func newScopedTokenCipher(secret []byte, scope string) (*tokenCipher, error) {
	return newScopedTokenCipherWithAAD(secret, scope, scope)
}

func newScopedTokenCipherWithAAD(secret []byte, scope, aad string) (*tokenCipher, error) {
	digest := sha256.Sum256(append([]byte("vps-url-gateway/"+scope+"/v1\x00"), secret...))
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &tokenCipher{aead: aead, aad: []byte(aad)}, nil
}

func (c *tokenCipher) Encrypt(value string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(value), c.aad)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (c *tokenCipher) Decrypt(value string) (string, error) {
	encoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(encoded) < c.aead.NonceSize() {
		return "", errors.New("invalid encrypted token")
	}
	nonce, ciphertext := encoded[:c.aead.NonceSize()], encoded[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, ciphertext, c.aad)
	if err != nil {
		return "", errors.New("invalid encrypted token")
	}
	return string(plain), nil
}

type telegramReporter struct {
	store   *telemetryStore
	gateway *Gateway
	cipher  *tokenCipher
	client  *http.Client
	apiBase string
	zone    *time.Location
	stop    chan struct{}
	done    chan struct{}
	wake    chan struct{}
	close   sync.Once
}

func newTelegramReporter(store *telemetryStore, gateway *Gateway, secret []byte) (*telegramReporter, error) {
	cipher, err := newTokenCipher(secret)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	reporter := &telegramReporter{
		store: store, gateway: gateway, cipher: cipher,
		client:  &http.Client{Transport: transport, Timeout: 15 * time.Second},
		apiBase: telegramAPIBase, zone: applicationLocation,
		stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	go reporter.run()
	return reporter, nil
}

func (t *telegramReporter) Close() {
	if t == nil {
		return
	}
	t.close.Do(func() {
		close(t.stop)
		<-t.done
		t.client.CloseIdleConnections()
	})
}

func (t *telegramReporter) run() {
	defer close(t.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			t.maybeSend(context.Background(), now)
		case <-t.wake:
			t.maybeSend(context.Background(), time.Now())
		case <-t.stop:
			return
		}
	}
}

func (t *telegramReporter) Wake() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *telegramReporter) maybeSend(ctx context.Context, now time.Time) {
	record, err := t.store.TelegramRecord(ctx)
	if err != nil || !record.Enabled || record.EncryptedToken == "" || record.ChatID == "" {
		return
	}
	local := now.In(t.zone)
	date := local.Format("2006-01-02")
	if local.Hour() != record.SendHour || record.LastSentDate == date {
		return
	}
	if err := t.sendRecord(ctx, record); err != nil {
		return
	}
	_ = t.store.MarkTelegramSent(ctx, date)
}

func (t *telegramReporter) SendTest(ctx context.Context) error {
	record, err := t.store.TelegramRecord(ctx)
	if err != nil {
		return err
	}
	if record.EncryptedToken == "" || record.ChatID == "" {
		return errors.New("telegram token and chat id are required")
	}
	return t.sendMessage(ctx, record, "Refract Telegram 通知测试成功。")
}

func (t *telegramReporter) sendRecord(ctx context.Context, record telegramRecord) error {
	report, err := t.store.DailyReport(ctx)
	if err != nil {
		return err
	}
	lines := []string{
		"Refract 日报",
		"统计周期：最近 24 小时",
		fmt.Sprintf("请求：%d", report.Requests),
		fmt.Sprintf("上传：%s", formatReportBytes(report.BytesIn)),
		fmt.Sprintf("下载：%s", formatReportBytes(report.BytesOut)),
		fmt.Sprintf("错误：%d", report.Errors),
		fmt.Sprintf("后端：%d", report.Targets),
		fmt.Sprintf("安全拦截：%d", t.gateway.blocked.Load()),
	}
	if len(report.Top) > 0 {
		lines = append(lines, "", "Top 后端：")
		for index, target := range report.Top {
			lines = append(lines, fmt.Sprintf("%d. %s · %s", index+1, target.Host, formatReportBytes(target.BytesOut)))
		}
	}
	return t.sendMessage(ctx, record, strings.Join(lines, "\n"))
}

func (t *telegramReporter) sendMessage(ctx context.Context, record telegramRecord, message string) error {
	token, err := t.cipher.Decrypt(record.EncryptedToken)
	if err != nil || !telegramTokenPattern.MatchString(token) {
		return errors.New("telegram token is unavailable")
	}
	form := url.Values{"chat_id": {record.ChatID}, "text": {message}, "disable_web_page_preview": {"true"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.apiBase+"/bot"+url.PathEscape(token)+"/sendMessage", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("telegram request unavailable")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := t.client.Do(request)
	if err != nil {
		return errors.New("telegram request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("telegram rejected the request")
	}
	return nil
}

func formatReportBytes(value int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	size := float64(value)
	index := 0
	for size >= 1024 && index < len(units)-1 {
		size /= 1024
		index++
	}
	if index == 0 || size >= 10 {
		return fmt.Sprintf("%.0f %s", size, units[index])
	}
	return fmt.Sprintf("%.1f %s", size, units[index])
}

func (s *telemetryStore) TelegramRecord(ctx context.Context) (telegramRecord, error) {
	var record telegramRecord
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT enabled,bot_token,chat_id,send_hour,last_sent_date FROM telegram_settings WHERE id=1`).
		Scan(&enabled, &record.EncryptedToken, &record.ChatID, &record.SendHour, &record.LastSentDate)
	record.Enabled = enabled == 1
	record.TokenSet = record.EncryptedToken != ""
	return record, err
}

func (s *telemetryStore) SaveTelegram(ctx context.Context, config telegramConfig, encryptedToken string) error {
	if config.SendHour < 0 || config.SendHour > 23 || (config.ChatID != "" && !telegramChatPattern.MatchString(config.ChatID)) {
		return errors.New("invalid telegram settings")
	}
	if encryptedToken == "" {
		_, err := s.db.ExecContext(ctx,
			`UPDATE telegram_settings SET enabled=?,chat_id=?,send_hour=?,updated_at=? WHERE id=1`,
			boolInt(config.Enabled), config.ChatID, config.SendHour, time.Now().Unix())
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE telegram_settings SET enabled=?,bot_token=?,chat_id=?,send_hour=?,updated_at=? WHERE id=1`,
		boolInt(config.Enabled), encryptedToken, config.ChatID, config.SendHour, time.Now().Unix())
	return err
}

func (s *telemetryStore) MarkTelegramSent(ctx context.Context, date string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE telegram_settings SET last_sent_date=?,updated_at=? WHERE id=1`, date, time.Now().Unix())
	return err
}

func (s *telemetryStore) DailyReport(ctx context.Context) (dailyReport, error) {
	since := time.Now().Add(-24 * time.Hour).Unix()
	var report dailyReport
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0),COALESCE(SUM(bytes_in),0),COALESCE(SUM(bytes_out),0),COALESCE(SUM(errors),0),COUNT(DISTINCT host)
		 FROM traffic_minutes WHERE minute>=?`, since).
		Scan(&report.Requests, &report.BytesIn, &report.BytesOut, &report.Errors, &report.Targets)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return dailyReport{}, err
	}
	report.Top, err = s.targets(ctx, since, 5)
	return report, err
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
