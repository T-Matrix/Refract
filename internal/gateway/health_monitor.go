package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	embyHealthCheckInterval = time.Minute
	embyHealthProbeTimeout  = 8 * time.Second
	embyHealthRetention     = 31 * 24 * time.Hour
	embyHealthMaxServers    = 200
	embyHealthHistoryPoints = 100
	embyHealthDefaultPath   = "/emby/System/Info/Public"
	embyHealthFallbackPath  = "/System/Info/Public"
	embyHealthUserAgent     = "Yamby/1.9.10"
	embyProbeSettingsKey    = "emby_probe_settings"
	embyHealthDefaultRetry  = 2
	embyHealthDefaultDelay  = 2
	embyHealthMaxRetry      = 5
	embyHealthMaxDelaySec   = 10
	embyHealthMinTimeoutSec = 3
	embyHealthMaxTimeoutSec = 15
)

type embyProbeSettings struct {
	DefaultRetryCount    int `json:"default_retry_count"`
	DefaultRetryDelaySec int `json:"default_retry_delay_sec"`
	ProbeTimeoutSec      int `json:"probe_timeout_sec"`
}

func defaultEmbyProbeSettings() embyProbeSettings {
	return embyProbeSettings{
		DefaultRetryCount:    embyHealthDefaultRetry,
		DefaultRetryDelaySec: embyHealthDefaultDelay,
		ProbeTimeoutSec:      int(embyHealthProbeTimeout / time.Second),
	}
}

func normalizeEmbyProbeSettings(raw embyProbeSettings) embyProbeSettings {
	out := raw
	if out.DefaultRetryCount < 0 {
		out.DefaultRetryCount = 0
	} else if out.DefaultRetryCount > embyHealthMaxRetry {
		out.DefaultRetryCount = embyHealthMaxRetry
	}
	if out.DefaultRetryDelaySec < 1 {
		out.DefaultRetryDelaySec = 1
	} else if out.DefaultRetryDelaySec > embyHealthMaxDelaySec {
		out.DefaultRetryDelaySec = embyHealthMaxDelaySec
	}
	if out.ProbeTimeoutSec < embyHealthMinTimeoutSec {
		out.ProbeTimeoutSec = embyHealthMinTimeoutSec
	} else if out.ProbeTimeoutSec > embyHealthMaxTimeoutSec {
		out.ProbeTimeoutSec = embyHealthMaxTimeoutSec
	}
	return out
}

func clampEmbyRetry(count, delaySec int) (int, int) {
	if count < 0 {
		count = 0
	} else if count > embyHealthMaxRetry {
		count = embyHealthMaxRetry
	}
	if delaySec < 1 {
		delaySec = embyHealthDefaultDelay
	} else if delaySec > embyHealthMaxDelaySec {
		delaySec = embyHealthMaxDelaySec
	}
	return count, delaySec
}

func (s *telemetryStore) LoadEmbyProbeSettings(ctx context.Context) embyProbeSettings {
	def := defaultEmbyProbeSettings()
	if s == nil {
		return def
	}
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, embyProbeSettingsKey).Scan(&raw); err != nil || strings.TrimSpace(raw) == "" {
		return def
	}
	var parsed embyProbeSettings
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return def
	}
	return normalizeEmbyProbeSettings(parsed)
}

func (s *telemetryStore) SaveEmbyProbeSettings(ctx context.Context, settings embyProbeSettings, applyToAll bool) (embyProbeSettings, error) {
	clean := normalizeEmbyProbeSettings(settings)
	data, err := json.Marshal(clean)
	if err != nil {
		return clean, err
	}
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		embyProbeSettingsKey, string(data), now,
	); err != nil {
		return clean, err
	}
	if applyToAll {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE monitored_emby_servers SET retry_count=?, retry_delay_sec=?, updated_at=?`,
			clean.DefaultRetryCount, clean.DefaultRetryDelaySec, now,
		); err != nil {
			return clean, err
		}
	}
	return clean, nil
}

var errEmbyHealthLimit = errors.New("maximum monitored server count reached")
var errEmbyHealthDisabled = errors.New("monitored server is disabled")

type embyHealthCheckPoint struct {
	CheckedAt   int64 `json:"checked_at"`
	Success     bool  `json:"success"`
	LatencyMS   int64 `json:"latency_ms"`
	StatusCode  int   `json:"status_code"`
	RetriesUsed int   `json:"retries_used"`
}

type embyHealthServer struct {
	ID                 int64                  `json:"id"`
	GroupName          string                 `json:"group_name"`
	Name               string                 `json:"name"`
	LineName           string                 `json:"line_name"`
	Note               string                 `json:"note"`
	BaseURL            string                 `json:"base_url"`
	ProbePath          string                 `json:"probe_path"`
	EffectiveProbePath string                 `json:"effective_probe_path"`
	ServerVersion      string                 `json:"server_version"`
	DetectedName       string                 `json:"detected_name"`
	RetryCount         int                    `json:"retry_count"`
	RetryDelaySec      int                    `json:"retry_delay_sec"`
	Enabled            bool                   `json:"enabled"`
	Status             string                 `json:"status"`
	LatencyMS          int64                  `json:"latency_ms"`
	AvgLatencyMS       int64                  `json:"avg_latency_ms"`
	LastStatusCode     int                    `json:"last_status_code"`
	LastCheckedAt      int64                  `json:"last_checked_at"`
	ConfigVersion      int64                  `json:"-"`
	Availability24H    *float64               `json:"availability_24h"`
	Availability7D     *float64               `json:"availability_7d"`
	Availability30D    *float64               `json:"availability_30d"`
	RecentChecks       []embyHealthCheckPoint `json:"recent_checks"`
	CreatedAt          int64                  `json:"created_at"`
	UpdatedAt          int64                  `json:"updated_at"`
}

type publicEmbyHealthServer struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	LineName        string   `json:"line_name"`
	Note            string   `json:"note"`
	Status          string   `json:"status"`
	LatencyMS       int64    `json:"latency_ms"`
	LastCheckedAt   int64    `json:"last_checked_at"`
	Availability24H *float64 `json:"availability_24h"`
	Availability7D  *float64 `json:"availability_7d"`
	Availability30D *float64 `json:"availability_30d"`
}

type publicEmbyHealthGroup struct {
	Name    string                   `json:"name"`
	Servers []publicEmbyHealthServer `json:"servers"`
}

type publicEmbyHealthSnapshot struct {
	Groups    []publicEmbyHealthGroup `json:"groups"`
	UpdatedAt int64                   `json:"updated_at"`
}

type embyHealthSample struct {
	CheckedAt     int64
	Success       bool
	LatencyMS     int64
	StatusCode    int
	RetriesUsed   int
	ServerVersion string
	DetectedName  string
}

func normalizeEmbyProbePath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", nil
	}
	if len(path) > 256 || hasControlCharacters(path) || strings.ContainsAny(path, "?# \t") {
		return "", errors.New("invalid probe path")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("probe path cannot contain dot segments")
		}
	}
	return path, nil
}

func effectiveEmbyProbePath(baseURL, probePath string) string {
	if p := strings.TrimSpace(probePath); p != "" {
		return p
	}
	if parsed, err := url.Parse(baseURL); err == nil {
		cleanBase := strings.TrimRight(strings.ToLower(parsed.Path), "/")
		if cleanBase == "/emby" || strings.HasSuffix(cleanBase, "/emby") {
			return embyHealthFallbackPath
		}
	}
	return embyHealthDefaultPath
}

func normalizeEmbyHealthServer(groupName, name, rawURL string, enabled bool) (embyHealthServer, error) {
	return normalizeEmbyHealthServerDetails(groupName, name, "", "", rawURL, enabled)
}

func normalizeEmbyHealthServerDetails(groupName, name, lineName, note, rawURL string, enabled bool) (embyHealthServer, error) {
	return normalizeEmbyHealthServerFull(groupName, name, lineName, note, rawURL, "", enabled)
}

func normalizeEmbyHealthServerFull(groupName, name, lineName, note, rawURL, probePath string, enabled bool) (embyHealthServer, error) {
	groupName = strings.TrimSpace(groupName)
	name = strings.TrimSpace(name)
	lineName = strings.TrimSpace(lineName)
	note = strings.TrimSpace(note)
	rawURL = strings.TrimSpace(rawURL)
	cleanProbePath, pathErr := normalizeEmbyProbePath(probePath)
	if pathErr != nil {
		return embyHealthServer{}, pathErr
	}
	if groupName == "" || len(groupName) > 128 || hasControlCharacters(groupName) {
		return embyHealthServer{}, errors.New("invalid group name")
	}
	if name == "" || len(name) > 128 || hasControlCharacters(name) {
		return embyHealthServer{}, errors.New("invalid server name")
	}
	if len(lineName) > 128 || hasControlCharacters(lineName) {
		return embyHealthServer{}, errors.New("invalid line name")
	}
	if len(note) > 512 || hasControlCharacters(note) {
		return embyHealthServer{}, errors.New("server note is too long")
	}
	if rawURL == "" || len(rawURL) > 2048 || hasControlCharacters(rawURL) {
		return embyHealthServer{}, errors.New("invalid server URL")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return embyHealthServer{}, errors.New("server URL must be an HTTP(S) base URL without credentials, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		portNumber, parseErr := strconv.Atoi(port)
		if parseErr != nil || portNumber < 1 || portNumber > 65535 {
			return embyHealthServer{}, errors.New("invalid server URL port")
		}
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return embyHealthServer{}, errors.New("server URL path cannot contain dot segments")
		}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	baseStr := strings.TrimRight(parsed.String(), "/")
	return embyHealthServer{
		GroupName: groupName, Name: name, LineName: lineName, Note: note,
		BaseURL: baseStr, ProbePath: cleanProbePath, EffectiveProbePath: effectiveEmbyProbePath(baseStr, cleanProbePath),
		RetryCount: embyHealthDefaultRetry, RetryDelaySec: embyHealthDefaultDelay,
		Enabled: enabled, RecentChecks: []embyHealthCheckPoint{},
	}, nil
}

func hasControlCharacters(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0
}

func (s *telemetryStore) SaveEmbyHealthServer(ctx context.Context, server embyHealthServer) (int64, error) {
	retryCount, retryDelay := clampEmbyRetry(server.RetryCount, server.RetryDelaySec)
	if server.ID == 0 {
		now := time.Now().Unix()
		result, err := s.db.ExecContext(ctx,
			`INSERT INTO monitored_emby_servers(group_name,name,line_name,note,base_url,probe_path,retry_count,retry_delay_sec,enabled,config_version,created_at,updated_at)
			 SELECT ?,?,?,?,?,?,?,?,?,1,?,? WHERE (SELECT COUNT(*) FROM monitored_emby_servers) < ?`,
			server.GroupName, server.Name, server.LineName, server.Note, server.BaseURL, server.ProbePath, retryCount, retryDelay, server.Enabled, now, now, embyHealthMaxServers)
		if err != nil {
			return 0, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rows != 1 {
			return 0, errEmbyHealthLimit
		}
		id, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}
		return id, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var previousURL, previousPath string
	if err := tx.QueryRowContext(ctx, `SELECT base_url,probe_path FROM monitored_emby_servers WHERE id=?`, server.ID).Scan(&previousURL, &previousPath); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE monitored_emby_servers SET group_name=?,name=?,line_name=?,note=?,base_url=?,probe_path=?,retry_count=?,retry_delay_sec=?,enabled=?,
		 config_version=config_version+CASE WHEN base_url<>? OR probe_path<>? OR enabled<>? THEN 1 ELSE 0 END,updated_at=? WHERE id=?`,
		server.GroupName, server.Name, server.LineName, server.Note, server.BaseURL, server.ProbePath, retryCount, retryDelay, server.Enabled,
		server.BaseURL, server.ProbePath, server.Enabled, time.Now().Unix(), server.ID)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows != 1 {
		return 0, sql.ErrNoRows
	}
	if previousURL != server.BaseURL || previousPath != server.ProbePath {
		if _, err := tx.ExecContext(ctx, `DELETE FROM emby_health_checks WHERE server_id=?`, server.ID); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE monitored_emby_servers SET server_version='',detected_name='' WHERE id=?`, server.ID); err != nil {
			return 0, err
		}
	}
	return server.ID, tx.Commit()
}

func (s *telemetryStore) DeleteEmbyHealthServer(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM monitored_emby_servers WHERE id=?`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	return nil
}

type embyHealthProbeTarget struct {
	ID            int64
	BaseURL       string
	ProbePath     string
	RetryCount    int
	RetryDelaySec int
	Enabled       bool
	ConfigVersion int64
}

func (s *telemetryStore) EmbyHealthEnabledServerIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM monitored_emby_servers WHERE enabled=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *telemetryStore) EmbyHealthProbeTarget(ctx context.Context, id int64) (embyHealthProbeTarget, error) {
	var target embyHealthProbeTarget
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT id,base_url,probe_path,retry_count,retry_delay_sec,enabled,config_version FROM monitored_emby_servers WHERE id=?`, id,
	).Scan(&target.ID, &target.BaseURL, &target.ProbePath, &target.RetryCount, &target.RetryDelaySec, &enabled, &target.ConfigVersion)
	if err != nil {
		return embyHealthProbeTarget{}, err
	}
	target.RetryCount, target.RetryDelaySec = clampEmbyRetry(target.RetryCount, target.RetryDelaySec)
	target.Enabled = enabled == 1
	return target, nil
}

func (s *telemetryStore) EmbyHealthServers(ctx context.Context, includeDisabled bool) ([]embyHealthServer, error) {
	now := time.Now()
	query := `SELECT s.id,s.group_name,s.name,s.line_name,s.note,s.base_url,s.probe_path,s.server_version,s.detected_name,s.retry_count,s.retry_delay_sec,s.enabled,s.created_at,s.updated_at,s.config_version,
		l.checked_at,l.success,l.latency_ms,l.status_code,
		(SELECT AVG(success)*100.0 FROM emby_health_checks WHERE server_id=s.id AND checked_at>=?),
		(SELECT AVG(success)*100.0 FROM emby_health_checks WHERE server_id=s.id AND checked_at>=?),
		(SELECT AVG(success)*100.0 FROM emby_health_checks WHERE server_id=s.id AND checked_at>=?)
		FROM monitored_emby_servers s
		LEFT JOIN emby_health_checks l ON l.id=(SELECT id FROM emby_health_checks WHERE server_id=s.id ORDER BY checked_at DESC,id DESC LIMIT 1)`
	if !includeDisabled {
		query += ` WHERE s.enabled=1`
	}
	query += ` ORDER BY s.group_name COLLATE NOCASE,s.name COLLATE NOCASE,s.id`
	rows, err := s.db.QueryContext(ctx, query,
		now.Add(-24*time.Hour).Unix(), now.Add(-7*24*time.Hour).Unix(), now.Add(-30*24*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	servers := make([]embyHealthServer, 0)
	byID := make(map[int64]int)
	for rows.Next() {
		var server embyHealthServer
		var enabled int
		var checkedAt, success, latency, statusCode sql.NullInt64
		var availability24h, availability7d, availability30d sql.NullFloat64
		if err := rows.Scan(&server.ID, &server.GroupName, &server.Name, &server.LineName, &server.Note, &server.BaseURL,
			&server.ProbePath, &server.ServerVersion, &server.DetectedName, &server.RetryCount, &server.RetryDelaySec, &enabled,
			&server.CreatedAt, &server.UpdatedAt, &server.ConfigVersion, &checkedAt, &success, &latency, &statusCode,
			&availability24h, &availability7d, &availability30d); err != nil {
			return nil, err
		}
		server.RetryCount, server.RetryDelaySec = clampEmbyRetry(server.RetryCount, server.RetryDelaySec)
		server.Enabled = enabled == 1
		server.EffectiveProbePath = effectiveEmbyProbePath(server.BaseURL, server.ProbePath)
		server.RecentChecks = make([]embyHealthCheckPoint, 0)
		if checkedAt.Valid {
			server.LastCheckedAt = checkedAt.Int64
			server.LatencyMS = latency.Int64
			server.LastStatusCode = int(statusCode.Int64)
			switch {
			case !server.Enabled:
				server.Status = "disabled"
			case now.Unix()-server.LastCheckedAt > int64(3*embyHealthCheckInterval/time.Second):
				server.Status = "unknown"
			case success.Int64 == 1:
				server.Status = "online"
			default:
				server.Status = "offline"
			}
		} else if server.Enabled {
			server.Status = "unknown"
		} else {
			server.Status = "disabled"
		}
		if availability24h.Valid {
			value := availability24h.Float64
			server.Availability24H = &value
		}
		if availability7d.Valid {
			value := availability7d.Float64
			server.Availability7D = &value
		}
		if availability30d.Valid {
			value := availability30d.Float64
			server.Availability30D = &value
		}
		byID[server.ID] = len(servers)
		servers = append(servers, server)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(servers) > 0 {
		hRows, hErr := s.db.QueryContext(ctx, `
			SELECT server_id, checked_at, success, latency_ms, status_code, retries_used FROM (
				SELECT server_id, checked_at, success, latency_ms, status_code, retries_used,
					ROW_NUMBER() OVER (PARTITION BY server_id ORDER BY checked_at DESC, id DESC) AS rn
				FROM emby_health_checks
			) WHERE rn <= ?
			ORDER BY server_id ASC, checked_at ASC, rn DESC`, embyHealthHistoryPoints)
		if hErr == nil {
			defer hRows.Close()
			for hRows.Next() {
				var srvID int64
				var pt embyHealthCheckPoint
				var okInt int
				if err := hRows.Scan(&srvID, &pt.CheckedAt, &okInt, &pt.LatencyMS, &pt.StatusCode, &pt.RetriesUsed); err != nil {
					break
				}
				pt.Success = okInt == 1
				if idx, ok := byID[srvID]; ok {
					servers[idx].RecentChecks = append(servers[idx].RecentChecks, pt)
				}
			}
		}
		for i := range servers {
			var sum, cnt int64
			for _, pt := range servers[i].RecentChecks {
				if pt.Success && pt.LatencyMS > 0 {
					sum += pt.LatencyMS
					cnt++
				}
			}
			if cnt > 0 {
				servers[i].AvgLatencyMS = sum / cnt
			} else if servers[i].LatencyMS > 0 {
				servers[i].AvgLatencyMS = servers[i].LatencyMS
			}
		}
	}
	return servers, nil
}

func (s *telemetryStore) EmbyHealthTargetLabels(ctx context.Context) ([]embyHealthServer, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_name,name,line_name,note,base_url FROM monitored_emby_servers WHERE enabled=1 ORDER BY group_name COLLATE NOCASE,name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	servers := make([]embyHealthServer, 0)
	for rows.Next() {
		var server embyHealthServer
		if err := rows.Scan(&server.GroupName, &server.Name, &server.LineName, &server.Note, &server.BaseURL); err != nil {
			return nil, err
		}
		server.Enabled = true
		servers = append(servers, server)
	}
	return servers, rows.Err()
}

func (s *telemetryStore) RecordEmbyHealthCheck(ctx context.Context, serverID, configVersion int64, sample embyHealthSample) error {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO emby_health_checks(server_id,checked_at,success,latency_ms,status_code,retries_used)
		 SELECT ?,?,?,?,?,? WHERE EXISTS (
			SELECT 1 FROM monitored_emby_servers WHERE id=? AND config_version=? AND enabled=1
		 )`,
		serverID, sample.CheckedAt, sample.Success, sample.LatencyMS, sample.StatusCode, sample.RetriesUsed, serverID, configVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return sql.ErrNoRows
	}
	if sample.ServerVersion != "" || sample.DetectedName != "" {
		_, _ = s.db.ExecContext(ctx,
			`UPDATE monitored_emby_servers
			 SET server_version=CASE WHEN ?<>'' THEN ? ELSE server_version END,
			     detected_name=CASE WHEN ?<>'' THEN ? ELSE detected_name END
			 WHERE id=? AND config_version=?`,
			sample.ServerVersion, sample.ServerVersion, sample.DetectedName, sample.DetectedName, serverID, configVersion)
	}
	return nil
}

func (s *telemetryStore) CleanupEmbyHealthChecks(ctx context.Context, cutoff int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM emby_health_checks WHERE checked_at<?`, cutoff)
	return err
}

type embyHealthMonitor struct {
	store      *telemetryStore
	resolver   *safeResolver
	client     *http.Client
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	wake       chan struct{}
	flightMu   sync.Mutex
	inFlight   map[int64]*embyHealthFlight
	probeSlots chan struct{}
}

type embyHealthFlight struct {
	done chan struct{}
	err  error
}

func newEmbyHealthMonitor(store *telemetryStore, resolver *safeResolver) *embyHealthMonitor {
	if resolver == nil {
		resolver = newSafeResolver(time.Minute, false)
	}
	ctx, cancel := context.WithCancel(context.Background())
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: time.Duration(embyHealthMaxTimeoutSec) * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		info, _ := ctx.Value(targetContextKey{}).(*targetInfo)
		if info == nil || !sameDialAddress(address, targetHostPort(info.URL)) {
			return nil, errors.New("health probe dial target was not validated")
		}
		dialer := &net.Dialer{Timeout: time.Duration(embyHealthMaxTimeoutSec) * time.Second, KeepAlive: 15 * time.Second}
		var lastErr error
		for _, resolved := range info.DialAddresses {
			connection, err := dialer.DialContext(ctx, network, resolved)
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = errors.New("health probe target has no validated addresses")
		}
		return nil, lastErr
	}
	monitor := &embyHealthMonitor{
		store: store, resolver: resolver, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1),
		inFlight: make(map[int64]*embyHealthFlight), probeSlots: make(chan struct{}, 8),
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(embyHealthMaxTimeoutSec+2) * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	go monitor.run()
	return monitor
}

func (m *embyHealthMonitor) Close() {
	if m == nil {
		return
	}
	m.cancel()
	<-m.done
	m.client.CloseIdleConnections()
}

func (m *embyHealthMonitor) Wake() {
	if m == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *embyHealthMonitor) run() {
	defer close(m.done)
	ticker := time.NewTicker(embyHealthCheckInterval)
	cleanupTicker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	for {
		m.checkEnabledServers()
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		case <-cleanupTicker.C:
			_ = m.store.CleanupEmbyHealthChecks(m.ctx, time.Now().Add(-embyHealthRetention).Unix())
		}
	}
}

func (m *embyHealthMonitor) checkEnabledServers() {
	serverIDs, err := m.store.EmbyHealthEnabledServerIDs(m.ctx)
	if err != nil || len(serverIDs) == 0 {
		return
	}
	semaphore := make(chan struct{}, 8)
	var checks sync.WaitGroup
	for _, serverID := range serverIDs {
		select {
		case semaphore <- struct{}{}:
		case <-m.ctx.Done():
			checks.Wait()
			return
		}
		checks.Add(1)
		go func(id int64) {
			defer checks.Done()
			defer func() { <-semaphore }()
			_ = m.CheckNow(m.ctx, id)
		}(serverID)
	}
	checks.Wait()
}

func (m *embyHealthMonitor) CheckAllNow(ctx context.Context) error {
	if m == nil {
		return errors.New("health monitor unavailable")
	}
	serverIDs, err := m.store.EmbyHealthEnabledServerIDs(ctx)
	if err != nil {
		return err
	}
	if len(serverIDs) == 0 {
		return nil
	}
	semaphore := make(chan struct{}, 8)
	var checks sync.WaitGroup
	for _, serverID := range serverIDs {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			checks.Wait()
			return ctx.Err()
		case <-m.ctx.Done():
			checks.Wait()
			return m.ctx.Err()
		}
		checks.Add(1)
		go func(id int64) {
			defer checks.Done()
			defer func() { <-semaphore }()
			_ = m.CheckNow(ctx, id)
		}(serverID)
	}
	checks.Wait()
	return nil
}

func (m *embyHealthMonitor) CheckNow(ctx context.Context, serverID int64) (resultErr error) {
	if m == nil {
		return errors.New("health monitor unavailable")
	}
	m.flightMu.Lock()
	if flight, ok := m.inFlight[serverID]; ok {
		m.flightMu.Unlock()
		select {
		case <-flight.done:
			return flight.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	flight := &embyHealthFlight{done: make(chan struct{})}
	m.inFlight[serverID] = flight
	m.flightMu.Unlock()
	defer func() {
		m.flightMu.Lock()
		flight.err = resultErr
		delete(m.inFlight, serverID)
		close(flight.done)
		m.flightMu.Unlock()
	}()

	select {
	case m.probeSlots <- struct{}{}:
		defer func() { <-m.probeSlots }()
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
	loadCtx, cancelLoad := context.WithTimeout(ctx, 3*time.Second)
	target, err := m.store.EmbyHealthProbeTarget(loadCtx, serverID)
	settings := m.store.LoadEmbyProbeSettings(loadCtx)
	cancelLoad()
	if err != nil {
		return err
	}
	if !target.Enabled {
		return errEmbyHealthDisabled
	}
	perAttemptTimeout := time.Duration(settings.ProbeTimeoutSec) * time.Second
	if perAttemptTimeout < time.Duration(embyHealthMinTimeoutSec)*time.Second {
		perAttemptTimeout = embyHealthProbeTimeout
	}
	retryDelay := time.Duration(target.RetryDelaySec) * time.Second
	totalBudget := time.Duration(1+target.RetryCount)*(perAttemptTimeout+2*time.Second) + time.Duration(target.RetryCount)*retryDelay
	if totalBudget > 65*time.Second {
		totalBudget = 65 * time.Second
	}
	requestContext, cancel := context.WithTimeout(ctx, totalBudget)
	stopOnClose := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stopOnClose()
		cancel()
	}()
	sample := m.probeWithRetry(requestContext, target.BaseURL, target.ProbePath, target.RetryCount, retryDelay, perAttemptTimeout)
	// Do not record a fake server outage if the caller canceled the manual check request or the monitor is closing.
	if ctx.Err() != nil || m.ctx.Err() != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return m.ctx.Err()
	}
	writeContext, cancelWrite := context.WithTimeout(m.ctx, 3*time.Second)
	defer cancelWrite()
	return m.store.RecordEmbyHealthCheck(writeContext, serverID, target.ConfigVersion, sample)
}

func sanitizeDetectedEmbyMeta(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || hasControlCharacters(value) {
		return ""
	}
	return truncateRunes(value, 64)
}

func (m *embyHealthMonitor) probe(ctx context.Context, baseURL string) embyHealthSample {
	return m.probeWithPath(ctx, baseURL, "")
}

func (m *embyHealthMonitor) probeWithRetry(ctx context.Context, baseURL, probePath string, retryCount int, retryDelay, perAttemptTimeout time.Duration) embyHealthSample {
	if retryCount < 0 {
		retryCount = 0
	} else if retryCount > embyHealthMaxRetry {
		retryCount = embyHealthMaxRetry
	}
	if perAttemptTimeout <= 0 {
		perAttemptTimeout = embyHealthProbeTimeout
	}
	var lastSample embyHealthSample
	for attempt := 0; attempt <= retryCount; attempt++ {
		if attempt > 0 && retryDelay > 0 {
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return lastSample
			case <-timer.C:
			}
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, perAttemptTimeout)
		sample := m.probeWithPath(attemptCtx, baseURL, probePath)
		cancelAttempt()
		sample.RetriesUsed = attempt
		lastSample = sample
		if sample.Success || ctx.Err() != nil {
			return sample
		}
	}
	return lastSample
}

func (m *embyHealthMonitor) probeWithPath(ctx context.Context, baseURL, probePath string) (sample embyHealthSample) {
	sample = embyHealthSample{CheckedAt: time.Now().Unix()}
	started := time.Now()
	defer func() { sample.LatencyMS = time.Since(started).Milliseconds() }()
	base, err := url.Parse(baseURL)
	if err != nil {
		return sample
	}
	dialAddresses, err := m.resolver.Resolve(ctx, base)
	if err != nil {
		return sample
	}

	baseCleanPath := strings.TrimRight(base.Path, "/")
	primaryPath := effectiveEmbyProbePath(baseURL, probePath)
	pathsToTry := []string{primaryPath}
	if strings.TrimSpace(probePath) == "" && primaryPath == embyHealthDefaultPath {
		// Automatically fall back to /System/Info/Public for Jellyfin servers that do not expose /emby prefix.
		pathsToTry = append(pathsToTry, embyHealthFallbackPath)
	}

	for idx, suffix := range pathsToTry {
		probeURL := *base
		probeURL.Path = baseCleanPath + suffix
		probeURL.RawPath = ""
		request, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
		if reqErr != nil {
			return sample
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", embyHealthUserAgent)
		request = request.WithContext(context.WithValue(request.Context(), targetContextKey{}, &targetInfo{URL: &probeURL, DialAddresses: dialAddresses}))
		response, doErr := m.client.Do(request)
		if doErr != nil {
			if idx == 0 && len(pathsToTry) > 1 && ctx.Err() == nil {
				continue
			}
			return sample
		}
		statusCode := response.StatusCode
		if statusCode < 0 {
			statusCode = 0
		} else if statusCode > 599 {
			statusCode = 599
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		_ = response.Body.Close()

		// Retry fallback path when default /emby/System/Info/Public returns 404 (e.g. Jellyfin).
		if statusCode == http.StatusNotFound && idx == 0 && len(pathsToTry) > 1 {
			continue
		}
		sample.StatusCode = statusCode
		if statusCode == http.StatusOK && len(bodyBytes) > 0 {
			var info struct {
				ServerName string `json:"ServerName"`
				Version    string `json:"Version"`
			}
			if json.Unmarshal(bodyBytes, &info) == nil {
				sample.DetectedName = sanitizeDetectedEmbyMeta(info.ServerName)
				sample.ServerVersion = sanitizeDetectedEmbyMeta(info.Version)
			}
		}
		// 2xx/3xx prove the server responded cleanly; 401/403 on private Emby deployments that deny
		// anonymous system info still confirm the HTTP edge is alive. 404 (after fallback), 408, 429,
		// 5xx, and transport failures count as unavailable.
		sample.Success = (statusCode >= 200 && statusCode < 400) || statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
		return sample
	}
	return sample
}

func looksLikeOriginHost(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, "://") {
		return true
	}
	if strings.ContainsAny(trimmed, " \t\r\n/") {
		return false
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return true
	}
	dot := strings.LastIndexByte(host, '.')
	if dot <= 0 || dot >= len(host)-1 {
		return false
	}
	tld := host[dot+1:]
	if len(tld) < 2 || len(tld) > 10 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		c := tld[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func embyHealthPublicSnapshot(servers []embyHealthServer) publicEmbyHealthSnapshot {
	snapshot := publicEmbyHealthSnapshot{Groups: make([]publicEmbyHealthGroup, 0), UpdatedAt: time.Now().Unix()}
	groupIndexes := make(map[string]int)
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		displayName := strings.TrimSpace(server.Name)
		if looksLikeOriginHost(displayName) {
			if det := strings.TrimSpace(server.DetectedName); det != "" && !looksLikeOriginHost(det) {
				displayName = det
			} else {
				displayName = "Emby 节点"
			}
		}
		index, exists := groupIndexes[server.GroupName]
		if !exists {
			index = len(snapshot.Groups)
			groupIndexes[server.GroupName] = index
			snapshot.Groups = append(snapshot.Groups, publicEmbyHealthGroup{Name: server.GroupName, Servers: make([]publicEmbyHealthServer, 0)})
		}
		snapshot.Groups[index].Servers = append(snapshot.Groups[index].Servers, publicEmbyHealthServer{
			ID: server.ID, Name: displayName, LineName: server.LineName, Note: server.Note, Status: server.Status, LatencyMS: server.LatencyMS,
			LastCheckedAt: server.LastCheckedAt, Availability24H: server.Availability24H,
			Availability7D: server.Availability7D, Availability30D: server.Availability30D,
		})
	}
	return snapshot
}
