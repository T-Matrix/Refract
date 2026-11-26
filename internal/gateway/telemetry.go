package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	telemetryQueueSize = 4096
	requestLogLimit    = 20000
	requestLogTTL      = 7 * 24 * time.Hour
)

type telemetryEvent struct {
	NodeID     string
	FlowID     string
	Timestamp  time.Time
	ClientIP   string
	DeviceID   string
	DeviceName string
	ClientName string
	Host       string
	Scheme     string
	Method     string
	Path       string
	Category   string
	Status     int
	BytesIn    int64
	BytesOut   int64
	DurationMS int64
}

type requestLog struct {
	ID             int64  `json:"id"`
	NodeID         string `json:"node_id,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	Timestamp      int64  `json:"timestamp"`
	ClientIP       string `json:"client_ip,omitempty"`
	Location       string `json:"location,omitempty"`
	Host           string `json:"host"`
	Scheme         string `json:"scheme"`
	EmbyServerName string `json:"emby_server_name,omitempty"`
	EmbyGroupName  string `json:"emby_group_name,omitempty"`
	EmbyLineName   string `json:"emby_line_name,omitempty"`
	EmbyNote       string `json:"emby_note,omitempty"`
	DeviceID       string `json:"device_id"`
	DeviceName     string `json:"device_name"`
	ClientName     string `json:"client_name"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	Category       string `json:"category"`
	Status         int    `json:"status"`
	BytesIn        int64  `json:"bytes_in"`
	BytesOut       int64  `json:"bytes_out"`
	DurationMS     int64  `json:"duration_ms"`
}

type requestLogStatusCount struct {
	Status int   `json:"status"`
	Count  int64 `json:"count"`
}

type requestLogPage struct {
	Logs       []requestLog            `json:"logs"`
	Statuses   []requestLogStatusCount `json:"statuses"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"page_size"`
	TotalPages int                     `json:"total_pages"`
}

type targetSummary struct {
	Host           string `json:"host"`
	Domain         string `json:"domain"`
	EmbyServerName string `json:"emby_server_name,omitempty"`
	EmbyGroupName  string `json:"emby_group_name,omitempty"`
	EmbyLineName   string `json:"emby_line_name,omitempty"`
	EmbyNote       string `json:"emby_note,omitempty"`
	Requests       int64  `json:"requests"`
	BytesOut       int64  `json:"bytes_out"`
	Errors         int64  `json:"errors"`
	AvgLatency     int64  `json:"avg_latency_ms"`
	LastSeen       int64  `json:"last_seen"`
}

type trafficPoint struct {
	Timestamp int64 `json:"timestamp"`
	Requests  int64 `json:"requests"`
	BytesIn   int64 `json:"bytes_in"`
	BytesOut  int64 `json:"bytes_out"`
	Errors    int64 `json:"errors"`
}

type dashboardSnapshot struct {
	Requests24H    int64                 `json:"requests_24h"`
	BytesIn24H     int64                 `json:"bytes_in_24h"`
	BytesOut24H    int64                 `json:"bytes_out_24h"`
	Errors24H      int64                 `json:"errors_24h"`
	Targets24H     int64                 `json:"targets_24h"`
	ActiveRequests int64                 `json:"active_requests"`
	BlockedTotal   uint64                `json:"blocked_total"`
	DroppedLogs    uint64                `json:"dropped_logs"`
	UptimeSeconds  int64                 `json:"uptime_seconds"`
	Timeline       []trafficPoint        `json:"timeline"`
	Targets        []targetSummary       `json:"targets"`
	Recent         []requestLog          `json:"recent"`
	ActiveTargets  []activeTargetTraffic `json:"active_targets"`
}

type authRecord struct {
	Username     string
	PasswordHash string
	Version      int64
}

type telemetryStore struct {
	db        *sql.DB
	events    chan telemetryEvent
	done      chan struct{}
	closeOnce sync.Once
	dropped   atomic.Uint64
	pendingMu sync.Mutex
	closed    bool
	pending   []telemetryEvent
}

func openTelemetryStore(path, username, passwordHash string) (*telemetryStore, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	statements := []string{
		`CREATE TABLE IF NOT EXISTS admin_users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			auth_version INTEGER NOT NULL DEFAULT 1,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS request_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			host TEXT NOT NULL,
			scheme TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			category TEXT NOT NULL,
			status INTEGER NOT NULL,
			bytes_in INTEGER NOT NULL,
			bytes_out INTEGER NOT NULL,
			duration_ms INTEGER NOT NULL,
			device_id TEXT NOT NULL DEFAULT '',
			device_name TEXT NOT NULL DEFAULT '',
			client_name TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_request_logs_host_timestamp ON request_logs(host, timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS traffic_minutes (
			minute INTEGER NOT NULL,
			host TEXT NOT NULL,
			requests INTEGER NOT NULL,
			bytes_in INTEGER NOT NULL,
			bytes_out INTEGER NOT NULL,
			errors INTEGER NOT NULL,
			duration_ms INTEGER NOT NULL,
			PRIMARY KEY (minute, host)
		)`,
		`CREATE TABLE IF NOT EXISTS gateway_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL CHECK(action IN ('allow','deny')),
			domain_suffix TEXT NOT NULL DEFAULT '',
			path_prefix TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK(quota_bytes >= 0),
			quota_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK(quota_used_bytes >= 0),
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_device_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id TEXT NOT NULL UNIQUE,
			device_name TEXT NOT NULL DEFAULT '',
			client_name TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS proxy_player_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			player_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
			note TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS monitored_emby_servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			group_name TEXT NOT NULL,
			name TEXT NOT NULL,
			base_url TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			config_version INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_monitored_emby_servers_group ON monitored_emby_servers(group_name COLLATE NOCASE,name COLLATE NOCASE,id)`,
		`CREATE TABLE IF NOT EXISTS emby_health_checks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL REFERENCES monitored_emby_servers(id) ON DELETE CASCADE,
			checked_at INTEGER NOT NULL,
			success INTEGER NOT NULL CHECK(success IN (0,1)),
			latency_ms INTEGER NOT NULL CHECK(latency_ms >= 0),
			status_code INTEGER NOT NULL DEFAULT 0 CHECK(status_code BETWEEN 0 AND 599)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_emby_health_checks_server_time ON emby_health_checks(server_id,checked_at DESC,id DESC)`,
		`CREATE TABLE IF NOT EXISTS telegram_settings (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
			bot_token BLOB NOT NULL DEFAULT X'',
			chat_id TEXT NOT NULL DEFAULT '',
			send_hour INTEGER NOT NULL DEFAULT 9 CHECK(send_hour BETWEEN 0 AND 23),
			last_sent_date TEXT NOT NULL DEFAULT '',
				updated_at INTEGER NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS turnstile_settings (
				id INTEGER PRIMARY KEY CHECK(id = 1),
				enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
				site_key TEXT NOT NULL DEFAULT '',
				secret BLOB NOT NULL DEFAULT X'',
				hostname TEXT NOT NULL DEFAULT '',
				tested_fingerprint TEXT NOT NULL DEFAULT '',
				verified_at INTEGER NOT NULL DEFAULT 0,
				updated_at INTEGER NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS geo_ip_cache (
			ip TEXT PRIMARY KEY,
			country TEXT NOT NULL DEFAULT '',
			country_code TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			latitude REAL NOT NULL DEFAULT 0,
			longitude REAL NOT NULL DEFAULT 0,
			looked_up INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS client_geo_hours (
			hour INTEGER NOT NULL,
			ip TEXT NOT NULL,
			requests INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			peak_bps INTEGER NOT NULL DEFAULT 0,
			last_seen INTEGER NOT NULL,
			PRIMARY KEY (hour, ip)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_client_geo_hours_last_seen ON client_geo_hours(last_seen DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_client_geo_hours_peak ON client_geo_hours(peak_bps DESC)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER NOT NULL,
			username TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			resource TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			success INTEGER NOT NULL CHECK(success IN (0,1))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)`,
		`CREATE TABLE IF NOT EXISTS admin_login_attempts (
			client_ip TEXT PRIMARY KEY,
			failures INTEGER NOT NULL CHECK(failures >= 0),
			first_failure INTEGER NOT NULL,
			blocked_until INTEGER NOT NULL DEFAULT 0,
			last_seen INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_login_attempts_last_seen ON admin_login_attempts(last_seen ASC)`,
		`CREATE TABLE IF NOT EXISTS edge_nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			group_name TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			public_url TEXT NOT NULL,
			public_visible INTEGER NOT NULL DEFAULT 1 CHECK(public_visible IN (0,1)),
			draining INTEGER NOT NULL DEFAULT 0 CHECK(draining IN (0,1)),
			token_hash TEXT NOT NULL DEFAULT '',
			enroll_token_hash TEXT NOT NULL DEFAULT '',
			enroll_expires_at INTEGER NOT NULL DEFAULT 0,
			overrides_json TEXT NOT NULL DEFAULT '{}',
			applied_revision INTEGER NOT NULL DEFAULT 0,
			applied_sha256 TEXT NOT NULL DEFAULT '',
			agent_version TEXT NOT NULL DEFAULT '',
			arch TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '',
			public_ipv4 TEXT NOT NULL DEFAULT '',
			public_ipv6 TEXT NOT NULL DEFAULT '',
			manual_ipv4 TEXT NOT NULL DEFAULT '',
			manual_ipv6 TEXT NOT NULL DEFAULT '',
			dns_sync_enabled INTEGER NOT NULL DEFAULT 0,
			dns_ip_mode TEXT NOT NULL DEFAULT 'auto',
			monthly_quota_gb REAL NOT NULL DEFAULT 0,
			quota_reset_day INTEGER NOT NULL DEFAULT 1,
			quota_direction TEXT NOT NULL DEFAULT 'out',
			quota_auto_drain INTEGER NOT NULL DEFAULT 1,
			quota_auto_drained INTEGER NOT NULL DEFAULT 0,
			quota_cycle_key TEXT NOT NULL DEFAULT '',
			quota_alert_level INTEGER NOT NULL DEFAULT 0,
			binary_sha256 TEXT NOT NULL DEFAULT '',
			last_seen_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS node_traffic_minutes (
			minute INTEGER NOT NULL,
			node_id TEXT NOT NULL,
			host TEXT NOT NULL,
			requests INTEGER NOT NULL,
			bytes_in INTEGER NOT NULL,
			bytes_out INTEGER NOT NULL,
			errors INTEGER NOT NULL,
			duration_ms INTEGER NOT NULL,
			PRIMARY KEY (minute, node_id, host)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_node_traffic_minutes_node ON node_traffic_minutes(node_id, minute DESC)`,
		`CREATE TABLE IF NOT EXISTS node_nic_traffic_minutes (
			minute INTEGER NOT NULL,
			node_id TEXT NOT NULL,
			ifaces TEXT NOT NULL DEFAULT '',
			rx_bytes INTEGER NOT NULL DEFAULT 0,
			tx_bytes INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (minute, node_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_node_nic_traffic_minutes_node ON node_nic_traffic_minutes(node_id, minute DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_node_nic_traffic_minute ON node_nic_traffic_minutes(minute DESC)`,
		`CREATE TABLE IF NOT EXISTS node_nic_state (
			node_id TEXT PRIMARY KEY,
			boot_id TEXT NOT NULL DEFAULT '',
			ifaces TEXT NOT NULL DEFAULT '',
			counters_json TEXT NOT NULL DEFAULT '{}',
			sampled_at INTEGER NOT NULL DEFAULT 0,
			updated_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS edge_domains (
			id TEXT PRIMARY KEY,
			domain TEXT NOT NULL UNIQUE COLLATE NOCASE,
			name TEXT NOT NULL DEFAULT '',
			note TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			public_visible INTEGER NOT NULL DEFAULT 1 CHECK(public_visible IN (0,1)),
			node_ids_json TEXT NOT NULL DEFAULT '[]',
			dns_mode TEXT NOT NULL DEFAULT 'manual',
			dns_ip_mode TEXT NOT NULL DEFAULT 'auto',
			dns_proxied TEXT NOT NULL DEFAULT 'inherit',
			dns_active_node_id TEXT NOT NULL DEFAULT '',
			dns_last_sync_at INTEGER NOT NULL DEFAULT 0,
			dns_last_error TEXT NOT NULL DEFAULT '',
			tls_mode TEXT NOT NULL DEFAULT 'auto',
			cert_pem TEXT NOT NULL DEFAULT '',
			key_pem_enc TEXT NOT NULL DEFAULT '',
			cert_issuer TEXT NOT NULL DEFAULT '',
			cert_not_after INTEGER NOT NULL DEFAULT 0,
			cert_status TEXT NOT NULL DEFAULT 'idle',
			cert_error TEXT NOT NULL DEFAULT '',
			cert_updated_at INTEGER NOT NULL DEFAULT 0,
			overrides_json TEXT NOT NULL DEFAULT '{}',
			node_limits_json TEXT NOT NULL DEFAULT '{}',
			waf_rule_ids_json TEXT NOT NULL DEFAULT '[]',
			smart_dns_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_edge_domains_domain ON edge_domains(domain COLLATE NOCASE)`,
		`CREATE TABLE IF NOT EXISTS waf_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
			is_global INTEGER NOT NULL DEFAULT 0 CHECK(is_global IN (0,1)),
			graph_json TEXT NOT NULL DEFAULT '{}',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS smart_dns_profiles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			provider_uuid TEXT NOT NULL DEFAULT '',
			provider_source TEXT NOT NULL DEFAULT 'platform',
			provider_type TEXT NOT NULL DEFAULT '',
			zone_uuid TEXT NOT NULL DEFAULT '',
			zone_name TEXT NOT NULL DEFAULT '',
			zone_plan TEXT NOT NULL DEFAULT '',
			auto_cf_cname INTEGER NOT NULL DEFAULT 1 CHECK(auto_cf_cname IN (0,1)),
			lines_json TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_rules_global ON waf_rules(is_global DESC, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS watch_history (
			session_key TEXT PRIMARY KEY,
			node_id TEXT NOT NULL DEFAULT '',
			node_name TEXT NOT NULL DEFAULT '',
			user_name TEXT NOT NULL DEFAULT '',
			client_ip TEXT NOT NULL DEFAULT '',
			client_name TEXT NOT NULL DEFAULT '',
			device_name TEXT NOT NULL DEFAULT '',
			upstream_host TEXT NOT NULL DEFAULT '',
			item_id TEXT NOT NULL DEFAULT '',
			media_type TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL DEFAULT '',
			series_name TEXT NOT NULL DEFAULT '',
			season_number INTEGER NOT NULL DEFAULT 0,
			episode_number INTEGER NOT NULL DEFAULT 0,
			production_year INTEGER NOT NULL DEFAULT 0,
			video_quality TEXT NOT NULL DEFAULT '',
			play_method TEXT NOT NULL DEFAULT '',
			position_sec INTEGER NOT NULL DEFAULT 0,
			duration_sec INTEGER NOT NULL DEFAULT 0,
			progress_pct INTEGER NOT NULL DEFAULT 0,
			bytes_out INTEGER NOT NULL DEFAULT 0,
			started_at INTEGER NOT NULL DEFAULT 0,
			last_seen_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_watch_history_last_seen ON watch_history(last_seen_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize telemetry database: %w", err)
		}
	}
	for column, definition := range map[string]string{
		"device_id":        "TEXT NOT NULL DEFAULT ''",
		"device_name":      "TEXT NOT NULL DEFAULT ''",
		"client_name":      "TEXT NOT NULL DEFAULT ''",
		"client_ip":        "TEXT NOT NULL DEFAULT ''",
		"node_id":          "TEXT NOT NULL DEFAULT 'local'",
		"quota_bytes":      "INTEGER NOT NULL DEFAULT 0 CHECK(quota_bytes >= 0)",
		"quota_used_bytes": "INTEGER NOT NULL DEFAULT 0 CHECK(quota_used_bytes >= 0)",
		"line_name":        "TEXT NOT NULL DEFAULT ''",
		"note":             "TEXT NOT NULL DEFAULT ''",
		"probe_path":       "TEXT NOT NULL DEFAULT ''",
		"server_version":   "TEXT NOT NULL DEFAULT ''",
		"detected_name":    "TEXT NOT NULL DEFAULT ''",
		"retry_count":      "INTEGER NOT NULL DEFAULT 2",
		"retry_delay_sec":  "INTEGER NOT NULL DEFAULT 2",
	} {
		table := "proxy_rules"
		if column == "line_name" || column == "note" || column == "probe_path" || column == "server_version" || column == "detected_name" || column == "retry_count" || column == "retry_delay_sec" {
			table = "monitored_emby_servers"
		} else if column == "device_id" || column == "device_name" || column == "client_name" || column == "client_ip" || column == "node_id" {
			table = "request_logs"
		}
		if err := ensureSQLiteColumn(db, table, column, definition); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate telemetry schema: %w", err)
		}
	}
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip ON request_logs(client_ip, timestamp DESC)`)
	for column, definition := range map[string]string{
		"public_ipv4":        "TEXT NOT NULL DEFAULT ''",
		"public_ipv6":        "TEXT NOT NULL DEFAULT ''",
		"manual_ipv4":        "TEXT NOT NULL DEFAULT ''",
		"manual_ipv6":        "TEXT NOT NULL DEFAULT ''",
		"dns_sync_enabled":   "INTEGER NOT NULL DEFAULT 0",
		"dns_ip_mode":        "TEXT NOT NULL DEFAULT 'auto'",
		"monthly_quota_gb":   "REAL NOT NULL DEFAULT 0",
		"quota_reset_day":    "INTEGER NOT NULL DEFAULT 1",
		"quota_direction":    "TEXT NOT NULL DEFAULT 'out'",
		"quota_auto_drain":   "INTEGER NOT NULL DEFAULT 1",
		"quota_auto_drained": "INTEGER NOT NULL DEFAULT 0",
		"quota_cycle_key":    "TEXT NOT NULL DEFAULT ''",
		"quota_alert_level":  "INTEGER NOT NULL DEFAULT 0",
		"binary_sha256":      "TEXT NOT NULL DEFAULT ''",
	} {
		if err := ensureSQLiteColumn(db, "edge_nodes", column, definition); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate edge_nodes schema: %w", err)
		}
	}
	if err := ensureSQLiteColumn(db, "emby_health_checks", "retries_used", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate emby_health_checks schema: %w", err)
	}
	if err := ensureSQLiteColumn(db, "edge_domains", "node_limits_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate edge_domains schema: %w", err)
	}
	if err := ensureSQLiteColumn(db, "edge_domains", "waf_rule_ids_json", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate edge_domains waf_rule_ids_json: %w", err)
	}
	if err := ensureSQLiteColumn(db, "edge_domains", "smart_dns_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate edge_domains smart_dns_json: %w", err)
	}
	if err := ensureSQLiteColumn(db, "node_nic_state", "sampled_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate node_nic_state sampled_at: %w", err)
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_request_logs_node_timestamp ON request_logs(node_id, timestamp DESC)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("index request_logs node_id: %w", err)
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.Chmod(path, 0600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("secure telemetry database: %w", err)
		}
	}
	if username != "" && passwordHash != "" {
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO admin_users(username, password_hash, auth_version, updated_at) VALUES(?,?,1,?)`,
			username, passwordHash, time.Now().Unix(),
		); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize administrator: %w", err)
		}
	}
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO telegram_settings(id, enabled, bot_token, chat_id, send_hour, last_sent_date, updated_at)
		 VALUES(1,0,X'','',9,'',?)`, time.Now().Unix(),
	); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize telegram settings: %w", err)
	}
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO turnstile_settings(id, enabled, site_key, secret, hostname, tested_fingerprint, verified_at, updated_at)
		 VALUES(1,0,'',X'','','',0,?)`, time.Now().Unix(),
	); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize Turnstile settings: %w", err)
	}
	store := &telemetryStore{db: db, events: make(chan telemetryEvent, telemetryQueueSize), done: make(chan struct{})}
	go store.runWriter()
	return store, nil
}

func ensureSQLiteColumn(db *sql.DB, table, column, definition string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func (s *telemetryStore) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.pendingMu.Lock()
		s.closed = true
		close(s.events)
		s.pendingMu.Unlock()
		<-s.done
		invalidateBrandAvatarCache(s)
		_ = s.db.Close()
	})
}

func (s *telemetryStore) Record(event telemetryEvent) {
	if s == nil {
		return
	}
	var valid bool
	event, valid = s.prepareEvent(event)
	if !valid {
		return
	}
	s.pendingMu.Lock()
	if s.closed {
		s.pendingMu.Unlock()
		return
	}
	overflow := s.enqueueEventLocked(event)
	s.pendingMu.Unlock()
	if overflow {
		if err := s.writeBatch([]telemetryEvent{event}); err != nil {
			s.dropped.Add(1)
		}
	}
}

func (s *telemetryStore) RecordCompleted(event telemetryEvent, connections *connectionTracker, flow *connectionFlow) {
	if s == nil {
		connections.Finish(flow)
		return
	}
	var valid bool
	event, valid = s.prepareEvent(event)
	overflow := false
	s.pendingMu.Lock()
	if valid && !s.closed {
		overflow = s.enqueueEventLocked(event)
	}
	connections.Finish(flow)
	s.pendingMu.Unlock()
	if overflow {
		if err := s.writeBatch([]telemetryEvent{event}); err != nil {
			s.dropped.Add(1)
		}
	}
}

func (s *telemetryStore) prepareEvent(event telemetryEvent) (telemetryEvent, bool) {
	event.NodeID = truncateRunes(strings.TrimSpace(event.NodeID), 48)
	if event.NodeID == "" {
		event.NodeID = "local"
	}
	event.Host = strings.TrimSpace(event.Host)
	event.ClientIP = normalizeTelemetryClientIP(event.ClientIP)
	event.DeviceID = truncateRunes(strings.TrimSpace(event.DeviceID), 256)
	event.DeviceName = truncateRunes(strings.TrimSpace(event.DeviceName), 128)
	event.ClientName = truncateRunes(strings.TrimSpace(event.ClientName), 128)
	event.Path, _, _ = strings.Cut(event.Path, "?")
	event.Path, _, _ = strings.Cut(event.Path, "#")
	if len(event.Host) > 255 || event.Host == "" || len(event.Method) > 16 {
		s.dropped.Add(1)
		return telemetryEvent{}, false
	}
	if event.Path == "" {
		event.Path = "/"
	}
	if len(event.Path) > 512 {
		event.Path = event.Path[:512]
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	return event, true
}

func (s *telemetryStore) enqueueEventLocked(event telemetryEvent) bool {
	select {
	case s.events <- event:
		s.pending = append(s.pending, event)
		return false
	default:
		// Signal caller to persist synchronously outside pendingMu so hot-path writers don't stall.
		return true
	}
}

func (s *telemetryStore) runWriter() {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	cleanupTicker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	defer cleanupTicker.Stop()
	batch := make([]telemetryEvent, 0, 128)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.writeBatch(batch); err != nil {
			s.dropped.Add(uint64(len(batch)))
		}
		n := len(batch)
		s.pendingMu.Lock()
		if len(s.pending) >= n {
			clear(s.pending[:n])
			s.pending = s.pending[n:]
			if len(s.pending) == 0 {
				s.pending = s.pending[:0]
			}
		} else {
			clear(s.pending)
			s.pending = s.pending[:0]
		}
		s.pendingMu.Unlock()
		clear(batch)
		batch = batch[:0]
	}
	for {
		select {
		case event, ok := <-s.events:
			if !ok {
				flush()
				return
			}
			batch = append(batch, event)
			if len(batch) >= 128 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-cleanupTicker.C:
			flush()
			s.cleanup()
		}
	}
}

func (s *telemetryStore) writeBatch(events []telemetryEvent) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		nodeID := event.NodeID
		if nodeID == "" {
			nodeID = "local"
		}
		clientIP := normalizeTelemetryClientIP(event.ClientIP)
		if _, err := tx.Exec(
			`INSERT INTO request_logs(node_id,timestamp,client_ip,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms,device_id,device_name,client_name)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			nodeID, event.Timestamp.Unix(), clientIP, event.Host, event.Scheme, event.Method, event.Path, event.Category,
			event.Status, event.BytesIn, event.BytesOut, event.DurationMS, event.DeviceID, event.DeviceName, event.ClientName,
		); err != nil {
			return err
		}
		minute := event.Timestamp.Truncate(time.Minute).Unix()
		errorsCount := 0
		if event.Status >= 400 && event.Status != 499 {
			errorsCount = 1
		}
		if _, err := tx.Exec(
			`INSERT INTO traffic_minutes(minute,host,requests,bytes_in,bytes_out,errors,duration_ms)
			 VALUES(?,?,1,?,?,?,?)
			 ON CONFLICT(minute,host) DO UPDATE SET
			 requests=requests+1, bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out,
			 errors=errors+excluded.errors, duration_ms=duration_ms+excluded.duration_ms`,
			minute, event.Host, event.BytesIn, event.BytesOut, errorsCount, event.DurationMS,
		); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO node_traffic_minutes(minute,node_id,host,requests,bytes_in,bytes_out,errors,duration_ms)
			 VALUES(?,?,?,1,?,?,?,?)
			 ON CONFLICT(minute,node_id,host) DO UPDATE SET
			 requests=requests+1, bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out,
			 errors=errors+excluded.errors, duration_ms=duration_ms+excluded.duration_ms`,
			minute, nodeID, event.Host, event.BytesIn, event.BytesOut, errorsCount, event.DurationMS,
		); err != nil {
			return err
		}
		if event.ClientIP != "" {
			hour := event.Timestamp.Truncate(time.Hour).Unix()
			if _, err := tx.Exec(
				`INSERT INTO client_geo_hours(hour,ip,requests,bytes_out,peak_bps,last_seen)
				 VALUES(?,?,1,?,0,?)
				 ON CONFLICT(hour,ip) DO UPDATE SET
				 requests=requests+1,
				 bytes_out=bytes_out+excluded.bytes_out,
				 last_seen=MAX(last_seen,excluded.last_seen)`,
				hour, event.ClientIP, event.BytesOut, event.Timestamp.Unix(),
			); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func normalizeTelemetryClientIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "unknown" {
		return raw
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (s *telemetryStore) cleanup() {
	cutoff := time.Now().Add(-requestLogTTL).Unix()
	trafficCutoff := reportingPeriodStart(90 * 24 * time.Hour)
	_, _ = s.db.Exec(`DELETE FROM request_logs WHERE timestamp < ?`, cutoff)
	_, _ = s.db.Exec(`DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY id DESC LIMIT ?)`, requestLogLimit)
	_, _ = s.db.Exec(`DELETE FROM traffic_minutes WHERE minute < ?`, trafficCutoff)
	_, _ = s.db.Exec(`DELETE FROM traffic_minutes WHERE rowid NOT IN (SELECT rowid FROM traffic_minutes ORDER BY minute DESC LIMIT 200000)`)
	_, _ = s.db.Exec(`DELETE FROM node_traffic_minutes WHERE minute < ?`, trafficCutoff)
	_, _ = s.db.Exec(`DELETE FROM node_traffic_minutes WHERE rowid NOT IN (SELECT rowid FROM node_traffic_minutes ORDER BY minute DESC LIMIT 200000)`)
	_, _ = s.db.Exec(`DELETE FROM node_nic_traffic_minutes WHERE minute < ?`, trafficCutoff)
	_, _ = s.db.Exec(`DELETE FROM client_geo_hours WHERE hour < ?`, trafficCutoff)
	_, _ = s.db.Exec(`DELETE FROM client_geo_hours WHERE rowid NOT IN (SELECT rowid FROM client_geo_hours ORDER BY hour DESC LIMIT 100000)`)
	_, _ = s.db.Exec(`DELETE FROM geo_ip_cache WHERE looked_up < ? AND ip NOT IN (SELECT DISTINCT ip FROM client_geo_hours)`, time.Now().Add(-90*24*time.Hour).Unix())
	_, _ = s.db.Exec(`DELETE FROM geo_ip_cache WHERE rowid NOT IN (SELECT rowid FROM geo_ip_cache ORDER BY looked_up DESC LIMIT 50000)`)
	_, _ = s.db.Exec(`DELETE FROM audit_logs WHERE timestamp < ?`, time.Now().Add(-auditLogTTL).Unix())
	_, _ = s.db.Exec(`DELETE FROM audit_logs WHERE id NOT IN (SELECT id FROM audit_logs ORDER BY id DESC LIMIT 20000)`)
	_, _ = s.db.Exec(`DELETE FROM watch_history WHERE last_seen_at < ?`, time.Now().Add(-playbackHistoryRetention).Unix())
}

func (s *telemetryStore) recordClientGeo(event clientGeoEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	hour := event.Timestamp.Truncate(time.Hour).Unix()
	_, err := s.db.Exec(
		`INSERT INTO client_geo_hours(hour,ip,requests,bytes_out,peak_bps,last_seen)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(hour,ip) DO UPDATE SET
		 requests=requests+excluded.requests,
		 bytes_out=bytes_out+excluded.bytes_out,
		 peak_bps=MAX(peak_bps,excluded.peak_bps),
		 last_seen=MAX(last_seen,excluded.last_seen)`,
		hour, event.IP, event.Requests, event.BytesOut, event.PeakBPS, event.Timestamp.Unix(),
	)
	return err
}

func (s *telemetryStore) cachedGeo(ctx context.Context, ip string) (geoLocation, bool, error) {
	var location geoLocation
	err := s.db.QueryRowContext(ctx,
		`SELECT country,country_code,region,latitude,longitude,looked_up FROM geo_ip_cache WHERE ip=?`, ip,
	).Scan(&location.Country, &location.CountryCode, &location.Region, &location.Latitude, &location.Longitude, &location.LookedUp)
	if errors.Is(err, sql.ErrNoRows) {
		return geoLocation{}, false, nil
	}
	return location, err == nil, err
}

func (s *telemetryStore) saveGeo(ctx context.Context, ip string, location geoLocation) error {
	if location.LookedUp == 0 {
		location.LookedUp = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO geo_ip_cache(ip,country,country_code,region,latitude,longitude,looked_up)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET
		 country=excluded.country,country_code=excluded.country_code,region=excluded.region,
		 latitude=excluded.latitude,longitude=excluded.longitude,looked_up=excluded.looked_up`,
		ip, location.Country, location.CountryCode, location.Region, location.Latitude, location.Longitude, location.LookedUp,
	)
	return err
}

func (s *telemetryStore) Geography(ctx context.Context, period time.Duration) (geographySnapshot, error) {
	if period < time.Hour || period > geographyRetention {
		period = 24 * time.Hour
	}
	return s.geographySince(ctx, period, reportingPeriodStart(period))
}

func (s *telemetryStore) geographySince(ctx context.Context, period time.Duration, since int64) (geographySnapshot, error) {
	snapshot := geographySnapshot{
		PeriodHours: int64(period / time.Hour), Regions: []geoRegionSummary{}, IPs: []geoIPSummary{},
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT d.ip,SUM(d.requests),SUM(d.bytes_out),MAX(d.peak_bps),MAX(d.last_seen),
		 COALESCE(c.country,''),COALESCE(c.country_code,''),COALESCE(c.region,''),
		 COALESCE(c.latitude,0),COALESCE(c.longitude,0)
		 FROM client_geo_hours d LEFT JOIN geo_ip_cache c ON c.ip=d.ip
		 WHERE d.hour>=? GROUP BY d.ip ORDER BY MAX(d.peak_bps) DESC`, since,
	)
	if err != nil {
		return geographySnapshot{}, err
	}
	defer rows.Close()
	regions := make(map[string]*geoRegionSummary)
	for rows.Next() {
		var item geoIPSummary
		var rawRegion string
		if err := rows.Scan(&item.IP, &item.Requests, &item.BytesOut, &item.PeakBPS, &item.LastSeen,
			&item.Country, &item.CountryCode, &rawRegion, &item.Latitude, &item.Longitude); err != nil {
			return geographySnapshot{}, err
		}
		if item.CountryCode == "" {
			item.Label = "待定位"
			snapshot.UnlocatedIPs++
			snapshot.IPs = append(snapshot.IPs, item)
			continue
		}
		snapshot.LocatedIPs++
		key, mapName, label, province := geographyRegion(item.Country, item.CountryCode, rawRegion)
		item.Label, item.Province = label, province
		snapshot.IPs = append(snapshot.IPs, item)
		region := regions[key]
		if region == nil {
			region = &geoRegionSummary{
				Key: key, MapName: mapName, Label: label, Country: item.Country,
				CountryCode: item.CountryCode, Province: province,
			}
			regions[key] = region
		}
		region.Latitude = (region.Latitude*float64(region.UniqueIPs) + item.Latitude) / float64(region.UniqueIPs+1)
		region.Longitude = (region.Longitude*float64(region.UniqueIPs) + item.Longitude) / float64(region.UniqueIPs+1)
		region.UniqueIPs++
		region.Requests += item.Requests
		region.BytesOut += item.BytesOut
		region.PeakBPS = max(region.PeakBPS, item.PeakBPS)
	}
	if err := rows.Err(); err != nil {
		return geographySnapshot{}, err
	}
	for _, region := range regions {
		snapshot.Regions = append(snapshot.Regions, *region)
	}
	sort.Slice(snapshot.IPs, func(i, j int) bool {
		if snapshot.IPs[i].PeakBPS == snapshot.IPs[j].PeakBPS {
			return snapshot.IPs[i].BytesOut > snapshot.IPs[j].BytesOut
		}
		return snapshot.IPs[i].PeakBPS > snapshot.IPs[j].PeakBPS
	})
	if len(snapshot.IPs) > 200 {
		snapshot.IPs = snapshot.IPs[:200]
	}
	sort.Slice(snapshot.Regions, func(i, j int) bool {
		if snapshot.Regions[i].PeakBPS == snapshot.Regions[j].PeakBPS {
			return snapshot.Regions[i].Requests > snapshot.Regions[j].Requests
		}
		return snapshot.Regions[i].PeakBPS > snapshot.Regions[j].PeakBPS
	})
	return snapshot, nil
}

func geographyRegion(country, code, region string) (key, mapName, label, province string) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "CN" && strings.TrimSpace(region) != "" {
		province = normalizeChinaRegion(region)
		return "CN:" + province, chinaProvinceMapName(province), province, province
	}
	return code, worldCountryMapName(code, country), country, ""
}

func chinaProvinceMapName(province string) string {
	suffixes := map[string]string{
		"北京": "北京市", "天津": "天津市", "上海": "上海市", "重庆": "重庆市",
		"内蒙古": "内蒙古自治区", "广西": "广西壮族自治区", "西藏": "西藏自治区",
		"宁夏": "宁夏回族自治区", "新疆": "新疆维吾尔自治区",
	}
	if name := suffixes[province]; name != "" {
		return name
	}
	if province == "香港" || province == "澳门" {
		return province + "特别行政区"
	}
	return province + "省"
}

func worldCountryMapName(code, country string) string {
	overrides := map[string]string{
		"US": "United States of America", "GB": "United Kingdom", "BS": "The Bahamas",
		"CI": "Ivory Coast", "CD": "Democratic Republic of the Congo", "CG": "Republic of the Congo",
		"CZ": "Czech Republic", "KR": "South Korea", "KP": "North Korea", "RU": "Russia",
		"VN": "Vietnam", "LA": "Laos", "TZ": "United Republic of Tanzania", "SY": "Syria",
		"IR": "Iran", "BO": "Bolivia", "VE": "Venezuela", "MD": "Moldova",
	}
	if name := overrides[code]; name != "" {
		return name
	}
	return country
}

func (s *telemetryStore) AuthRecord(ctx context.Context, username string) (authRecord, error) {
	var record authRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT username,password_hash,auth_version FROM admin_users WHERE username=?`, username,
	).Scan(&record.Username, &record.PasswordHash, &record.Version)
	return record, err
}

func (s *telemetryStore) HasAdministrator(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users`).Scan(&count)
	return count > 0, err
}

func (s *telemetryStore) CreateFirstAdministrator(ctx context.Context, username, passwordHash string) (authRecord, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_users(username,password_hash,auth_version,updated_at)
		 SELECT ?,?,1,? WHERE NOT EXISTS (SELECT 1 FROM admin_users)`,
		username, passwordHash, time.Now().Unix())
	if err != nil {
		return authRecord{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return authRecord{}, errors.New("administrator already configured")
	}
	return s.AuthRecord(ctx, username)
}

func (s *telemetryStore) ChangePassword(ctx context.Context, username, passwordHash string) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`UPDATE admin_users SET password_hash=?, auth_version=auth_version+1, updated_at=? WHERE username=?`,
		passwordHash, time.Now().Unix(), username,
	)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return 0, errors.New("administrator account not found")
	}
	record, err := s.AuthRecord(ctx, username)
	return record.Version, err
}

func (s *telemetryStore) Snapshot(ctx context.Context, period time.Duration, active int64, blocked uint64, uptime time.Duration, connections *connectionTracker) (dashboardSnapshot, error) {
	return s.SnapshotForNode(ctx, period, "", active, blocked, uptime, connections.Snapshot())
}

func (s *telemetryStore) SnapshotForNode(ctx context.Context, period time.Duration, nodeID string, active int64, blocked uint64, uptime time.Duration, activeConns []connectionSnapshot) (dashboardSnapshot, error) {
	if period != 24*time.Hour && period != 7*24*time.Hour && period != 30*24*time.Hour {
		period = 24 * time.Hour
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "all" {
		nodeID = ""
	}
	since := time.Now().Add(-period).Unix()
	bucket := int64(time.Hour / time.Second)
	if period == 7*24*time.Hour {
		bucket = int64(6 * time.Hour / time.Second)
	} else if period == 30*24*time.Hour {
		bucket = int64(24 * time.Hour / time.Second)
	}
	snapshot := dashboardSnapshot{
		ActiveRequests: active,
		BlockedTotal:   blocked,
		DroppedLogs:    s.dropped.Load(),
		UptimeSeconds:  int64(uptime.Seconds()),
		Timeline:       []trafficPoint{},
		Targets:        []targetSummary{},
		Recent:         []requestLog{},
	}
	var err error
	if nodeID == "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COALESCE(SUM(errors),0), COUNT(DISTINCT host)
			 FROM traffic_minutes WHERE minute>=?`, since,
		).Scan(&snapshot.Requests24H, &snapshot.BytesIn24H, &snapshot.BytesOut24H, &snapshot.Errors24H, &snapshot.Targets24H)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COALESCE(SUM(errors),0), COUNT(DISTINCT host)
			 FROM node_traffic_minutes WHERE node_id=? AND minute>=?`, nodeID, since,
		).Scan(&snapshot.Requests24H, &snapshot.BytesIn24H, &snapshot.BytesOut24H, &snapshot.Errors24H, &snapshot.Targets24H)
	}
	if err != nil {
		return dashboardSnapshot{}, err
	}
	var rows *sql.Rows
	if nodeID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT (minute/?)*?, SUM(requests), SUM(bytes_in), SUM(bytes_out), SUM(errors)
			 FROM traffic_minutes WHERE minute>=? GROUP BY (minute/?) ORDER BY (minute/?)`,
			bucket, bucket, since, bucket, bucket,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT (minute/?)*?, SUM(requests), SUM(bytes_in), SUM(bytes_out), SUM(errors)
			 FROM node_traffic_minutes WHERE node_id=? AND minute>=? GROUP BY (minute/?) ORDER BY (minute/?)`,
			bucket, bucket, nodeID, since, bucket, bucket,
		)
	}
	if err != nil {
		return dashboardSnapshot{}, err
	}
	for rows.Next() {
		var point trafficPoint
		if err := rows.Scan(&point.Timestamp, &point.Requests, &point.BytesIn, &point.BytesOut, &point.Errors); err != nil {
			_ = rows.Close()
			return dashboardSnapshot{}, err
		}
		snapshot.Timeline = append(snapshot.Timeline, point)
	}
	if err := rows.Close(); err != nil {
		return dashboardSnapshot{}, err
	}
	snapshot.Targets, err = s.targetsForNode(ctx, since, 20, nodeID)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	snapshot.Recent, err = s.recentForNode(ctx, 20, "", nodeID)
	if err == nil {
		s.pendingMu.Lock()
		var pending []telemetryEvent
		if nodeID == "" {
			pending = append([]telemetryEvent(nil), s.pending...)
		} else {
			pending = make([]telemetryEvent, 0, len(s.pending))
			for _, ev := range s.pending {
				if ev.NodeID == nodeID {
					pending = append(pending, ev)
				}
			}
		}
		s.pendingMu.Unlock()
		mergeRealtimeDashboard(&snapshot, since, bucket, pending, activeConns)
	}
	return snapshot, err
}

type targetRealtimeAccumulator struct {
	summary  targetSummary
	duration int64
}

func mergeRealtimeDashboard(snapshot *dashboardSnapshot, since, bucketSeconds int64, pending []telemetryEvent, active []connectionSnapshot) {
	targets := make(map[string]*targetRealtimeAccumulator, len(snapshot.Targets)+len(pending)+len(active))
	knownAllTargets := snapshot.Targets24H <= int64(len(snapshot.Targets))
	for _, item := range snapshot.Targets {
		copy := item
		targets[item.Host] = &targetRealtimeAccumulator{summary: copy, duration: item.AvgLatency * item.Requests}
	}
	timeline := make(map[int64]*trafficPoint, len(snapshot.Timeline)+1)
	for index := range snapshot.Timeline {
		point := snapshot.Timeline[index]
		timeline[point.Timestamp] = &point
	}
	pendingFlows := make(map[string]struct{}, len(pending))
	add := func(timestamp int64, host, domain string, requests, bytesIn, bytesOut, errorsCount, duration int64) {
		if timestamp < since || host == "" {
			return
		}
		snapshot.Requests24H += requests
		snapshot.BytesIn24H += bytesIn
		snapshot.BytesOut24H += bytesOut
		snapshot.Errors24H += errorsCount
		target := targets[host]
		if target == nil {
			target = &targetRealtimeAccumulator{summary: targetSummary{Host: host, Domain: domain}}
			targets[host] = target
			if knownAllTargets {
				snapshot.Targets24H++
			}
		}
		target.summary.Requests += requests
		target.summary.BytesOut += bytesOut
		target.summary.Errors += errorsCount
		target.duration += duration
		target.summary.LastSeen = max(target.summary.LastSeen, timestamp)
		bucket := (timestamp / bucketSeconds) * bucketSeconds
		point := timeline[bucket]
		if point == nil {
			point = &trafficPoint{Timestamp: bucket}
			timeline[bucket] = point
		}
		point.Requests += requests
		point.BytesIn += bytesIn
		point.BytesOut += bytesOut
		point.Errors += errorsCount
	}
	for _, event := range pending {
		if event.FlowID != "" {
			pendingFlows[event.FlowID] = struct{}{}
		}
		errorsCount := int64(0)
		if event.Status >= 400 && event.Status != 499 {
			errorsCount = 1
		}
		add(event.Timestamp.Unix(), event.Host, targetDomain(event.Host), 1, event.BytesIn, event.BytesOut, errorsCount, event.DurationMS)
	}
	for _, connection := range active {
		if _, completed := pendingFlows[connection.ID]; completed {
			continue
		}
		add(time.Now().Unix(), connection.Host, connection.Domain, 1, connection.UploadTotal, connection.DownloadTotal, 0, connection.DurationMS)
	}
	snapshot.ActiveTargets = summarizeActiveTargets(active)
	snapshot.Timeline = snapshot.Timeline[:0]
	for _, point := range timeline {
		snapshot.Timeline = append(snapshot.Timeline, *point)
	}
	sort.Slice(snapshot.Timeline, func(i, j int) bool { return snapshot.Timeline[i].Timestamp < snapshot.Timeline[j].Timestamp })
	snapshot.Targets = snapshot.Targets[:0]
	for _, target := range targets {
		if target.summary.Requests > 0 {
			target.summary.AvgLatency = target.duration / target.summary.Requests
		}
		snapshot.Targets = append(snapshot.Targets, target.summary)
	}
	sort.Slice(snapshot.Targets, func(i, j int) bool {
		if snapshot.Targets[i].BytesOut == snapshot.Targets[j].BytesOut {
			return snapshot.Targets[i].LastSeen > snapshot.Targets[j].LastSeen
		}
		return snapshot.Targets[i].BytesOut > snapshot.Targets[j].BytesOut
	})
	if len(snapshot.Targets) > 20 {
		snapshot.Targets = snapshot.Targets[:20]
	}
}

func (s *telemetryStore) targets(ctx context.Context, since int64, limit int) ([]targetSummary, error) {
	return s.targetsForNode(ctx, since, limit, "")
}

func (s *telemetryStore) targetsForNode(ctx context.Context, since int64, limit int, nodeID string) ([]targetSummary, error) {
	var rows *sql.Rows
	var err error
	if nodeID == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT host, SUM(requests), SUM(bytes_out), SUM(errors),
			 CASE WHEN SUM(requests)>0 THEN SUM(duration_ms)/SUM(requests) ELSE 0 END, MAX(minute)
			 FROM traffic_minutes WHERE minute>=? GROUP BY host ORDER BY SUM(bytes_out) DESC LIMIT ?`, since, limit,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT host, SUM(requests), SUM(bytes_out), SUM(errors),
			 CASE WHEN SUM(requests)>0 THEN SUM(duration_ms)/SUM(requests) ELSE 0 END, MAX(minute)
			 FROM node_traffic_minutes WHERE node_id=? AND minute>=? GROUP BY host ORDER BY SUM(bytes_out) DESC LIMIT ?`, nodeID, since, limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]targetSummary, 0, limit)
	for rows.Next() {
		var item targetSummary
		if err := rows.Scan(&item.Host, &item.Requests, &item.BytesOut, &item.Errors, &item.AvgLatency, &item.LastSeen); err != nil {
			return nil, err
		}
		item.Domain = targetDomain(item.Host)
		result = append(result, item)
	}
	return result, rows.Err()
}

func targetDomain(host string) string {
	parsed, err := url.Parse("//" + host)
	if err == nil && parsed.Hostname() != "" {
		return normalizeHost(parsed.Hostname())
	}
	return normalizeHost(host)
}

func (s *telemetryStore) recent(ctx context.Context, limit int, host string) ([]requestLog, error) {
	return s.recentForNode(ctx, limit, host, "")
}

func (s *telemetryStore) recentForNode(ctx context.Context, limit int, host, nodeID string) ([]requestLog, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	query := `SELECT id,node_id,timestamp,client_ip,host,scheme,device_id,device_name,client_name,method,path,category,status,bytes_in,bytes_out,duration_ms FROM request_logs`
	args := make([]any, 0, 3)
	var clauses []string
	if host = strings.TrimSpace(host); host != "" {
		clauses = append(clauses, `host=?`)
		args = append(args, host)
	}
	if nodeID = strings.TrimSpace(nodeID); nodeID != "" && nodeID != "all" {
		clauses = append(clauses, `node_id=?`)
		args = append(args, nodeID)
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]requestLog, 0, limit)
	for rows.Next() {
		var item requestLog
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Timestamp, &item.ClientIP, &item.Host, &item.Scheme, &item.DeviceID, &item.DeviceName, &item.ClientName, &item.Method, &item.Path, &item.Category,
			&item.Status, &item.BytesIn, &item.BytesOut, &item.DurationMS); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *telemetryStore) requestLogPage(ctx context.Context, page, pageSize int, host string, status *int) (requestLogPage, error) {
	return s.requestLogPageForNode(ctx, page, pageSize, host, "", "", status)
}

func (s *telemetryStore) requestLogPageForNode(ctx context.Context, page, pageSize int, host, nodeID, clientIP string, status *int) (requestLogPage, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	host = strings.TrimSpace(host)
	nodeID = strings.TrimSpace(nodeID)
	clientIP = strings.TrimSpace(clientIP)
	if nodeID == "all" {
		nodeID = ""
	}

	statusClauses := make([]string, 0, 3)
	statusArgs := make([]any, 0, 3)
	if host != "" {
		statusClauses = append(statusClauses, `host=?`)
		statusArgs = append(statusArgs, host)
	}
	if nodeID != "" {
		statusClauses = append(statusClauses, `node_id=?`)
		statusArgs = append(statusArgs, nodeID)
	}
	if clientIP != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(clientIP)
		statusClauses = append(statusClauses, `client_ip LIKE ? ESCAPE '\'`)
		statusArgs = append(statusArgs, escaped+"%")
	}
	statusQuery := `SELECT status,COUNT(*) FROM request_logs`
	if len(statusClauses) > 0 {
		statusQuery += ` WHERE ` + strings.Join(statusClauses, ` AND `)
	}
	statusQuery += ` GROUP BY status ORDER BY status`
	statusRows, err := s.db.QueryContext(ctx, statusQuery, statusArgs...)
	if err != nil {
		return requestLogPage{}, err
	}
	statuses := make([]requestLogStatusCount, 0, 8)
	for statusRows.Next() {
		var item requestLogStatusCount
		if err := statusRows.Scan(&item.Status, &item.Count); err != nil {
			statusRows.Close()
			return requestLogPage{}, err
		}
		statuses = append(statuses, item)
	}
	if err := statusRows.Close(); err != nil {
		return requestLogPage{}, err
	}
	if err := statusRows.Err(); err != nil {
		return requestLogPage{}, err
	}

	clauses := append([]string(nil), statusClauses...)
	args := append([]any(nil), statusArgs...)
	if status != nil {
		clauses = append(clauses, `status=?`)
		args = append(args, *status)
	}
	where := ""
	if len(clauses) > 0 {
		where = ` WHERE ` + strings.Join(clauses, ` AND `)
	}

	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM request_logs`+where, args...).Scan(&total); err != nil {
		return requestLogPage{}, err
	}
	totalPages := max(1, int((total+int64(pageSize)-1)/int64(pageSize)))
	page = min(page, totalPages)
	offset := (page - 1) * pageSize

	query := `SELECT id,node_id,timestamp,client_ip,host,scheme,device_id,device_name,client_name,method,path,category,status,bytes_in,bytes_out,duration_ms FROM request_logs` +
		where + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any(nil), args...), pageSize, offset)
	rows, err := s.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return requestLogPage{}, err
	}
	defer rows.Close()
	logs := make([]requestLog, 0, pageSize)
	for rows.Next() {
		var item requestLog
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Timestamp, &item.ClientIP, &item.Host, &item.Scheme, &item.DeviceID, &item.DeviceName, &item.ClientName, &item.Method, &item.Path, &item.Category,
			&item.Status, &item.BytesIn, &item.BytesOut, &item.DurationMS); err != nil {
			return requestLogPage{}, err
		}
		logs = append(logs, item)
	}
	if err := rows.Err(); err != nil {
		return requestLogPage{}, err
	}
	return requestLogPage{
		Logs: logs, Statuses: statuses, Total: total, Page: page, PageSize: pageSize, TotalPages: totalPages,
	}, nil
}

func (s *telemetryStore) EnrichRequestLogLocations(ctx context.Context, logs []requestLog) {
	if s == nil || len(logs) == 0 {
		return
	}
	unique := make(map[string]struct{}, len(logs))
	for _, item := range logs {
		if item.ClientIP != "" && item.ClientIP != "unknown" {
			unique[item.ClientIP] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return
	}
	args := make([]any, 0, len(unique))
	ph := make([]string, 0, len(unique))
	for ip := range unique {
		args = append(args, ip)
		ph = append(ph, "?")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip,country,country_code,region FROM geo_ip_cache WHERE ip IN (`+strings.Join(ph, ",")+`)`, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	locs := make(map[string]string, len(unique))
	for rows.Next() {
		var ip, country, code, region string
		if rows.Scan(&ip, &country, &code, &region) == nil && code != "" {
			_, _, label, _ := geographyRegion(country, code, region)
			locs[ip] = label
		}
	}
	for i := range logs {
		if loc := locs[logs[i].ClientIP]; loc != "" {
			logs[i].Location = loc
		}
	}
}

func decorateRequestLogNodes(logs []requestLog, names map[string]string) {
	for i := range logs {
		if logs[i].NodeID == "" || logs[i].NodeID == "local" {
			logs[i].NodeID = "local"
			logs[i].NodeName = "本机节点"
			continue
		}
		if name := names[logs[i].NodeID]; name != "" {
			logs[i].NodeName = name
		} else {
			logs[i].NodeName = logs[i].NodeID
		}
	}
}
