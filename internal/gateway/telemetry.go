package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	FlowID     string
	Timestamp  time.Time
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
	ID         int64  `json:"id"`
	Timestamp  int64  `json:"timestamp"`
	Host       string `json:"host"`
	Scheme     string `json:"scheme"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Category   string `json:"category"`
	Status     int    `json:"status"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	DurationMS int64  `json:"duration_ms"`
}

type targetSummary struct {
	Host       string `json:"host"`
	Domain     string `json:"domain"`
	Requests   int64  `json:"requests"`
	BytesOut   int64  `json:"bytes_out"`
	Errors     int64  `json:"errors"`
	AvgLatency int64  `json:"avg_latency_ms"`
	LastSeen   int64  `json:"last_seen"`
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
			duration_ms INTEGER NOT NULL
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
			created_at INTEGER NOT NULL
		)`,
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
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize telemetry database: %w", err)
		}
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

func (s *telemetryStore) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		close(s.events)
		<-s.done
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
	s.enqueueEventLocked(event)
	s.pendingMu.Unlock()
}

func (s *telemetryStore) RecordCompleted(event telemetryEvent, connections *connectionTracker, flow *connectionFlow) {
	if s == nil {
		connections.Finish(flow)
		return
	}
	var valid bool
	event, valid = s.prepareEvent(event)
	s.pendingMu.Lock()
	if valid {
		s.enqueueEventLocked(event)
	}
	connections.Finish(flow)
	s.pendingMu.Unlock()
}

func (s *telemetryStore) prepareEvent(event telemetryEvent) (telemetryEvent, bool) {
	event.Host = strings.TrimSpace(event.Host)
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

func (s *telemetryStore) enqueueEventLocked(event telemetryEvent) {
	select {
	case s.events <- event:
		s.pending = append(s.pending, event)
	default:
		s.dropped.Add(1)
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
		s.pendingMu.Lock()
		if err := s.writeBatch(batch); err != nil {
			s.dropped.Add(uint64(len(batch)))
		}
		if len(s.pending) >= len(batch) {
			s.pending = s.pending[len(batch):]
		} else {
			s.pending = s.pending[:0]
		}
		s.pendingMu.Unlock()
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
		if _, err := tx.Exec(
			`INSERT INTO request_logs(timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			event.Timestamp.Unix(), event.Host, event.Scheme, event.Method, event.Path, event.Category,
			event.Status, event.BytesIn, event.BytesOut, event.DurationMS,
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
	}
	return tx.Commit()
}

func (s *telemetryStore) cleanup() {
	cutoff := time.Now().Add(-requestLogTTL).Unix()
	_, _ = s.db.Exec(`DELETE FROM request_logs WHERE timestamp < ?`, cutoff)
	_, _ = s.db.Exec(`DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY id DESC LIMIT ?)`, requestLogLimit)
	_, _ = s.db.Exec(`DELETE FROM traffic_minutes WHERE minute < ?`, time.Now().Add(-90*24*time.Hour).Unix())
	_, _ = s.db.Exec(`DELETE FROM client_geo_hours WHERE hour < ?`, time.Now().Add(-geographyRetention).Unix())
	_, _ = s.db.Exec(`DELETE FROM geo_ip_cache WHERE looked_up < ? AND ip NOT IN (SELECT DISTINCT ip FROM client_geo_hours)`, time.Now().Add(-90*24*time.Hour).Unix())
	_, _ = s.db.Exec(`DELETE FROM audit_logs WHERE timestamp < ?`, time.Now().Add(-auditLogTTL).Unix())
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
	snapshot := geographySnapshot{
		PeriodHours: int64(period / time.Hour), Regions: []geoRegionSummary{}, IPs: []geoIPSummary{},
	}
	since := time.Now().Add(-period).Truncate(time.Hour).Unix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT d.ip,SUM(d.requests),SUM(d.bytes_out),MAX(d.peak_bps),MAX(d.last_seen),
		 COALESCE(c.country,''),COALESCE(c.country_code,''),COALESCE(c.region,''),
		 COALESCE(c.latitude,0),COALESCE(c.longitude,0)
		 FROM client_geo_hours d LEFT JOIN geo_ip_cache c ON c.ip=d.ip
		 WHERE d.hour>=? GROUP BY d.ip ORDER BY MAX(d.peak_bps) DESC LIMIT 5000`, since,
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
			snapshot.UnlocatedIPs++
			continue
		}
		snapshot.LocatedIPs++
		key, mapName, label, province := geographyRegion(item.Country, item.CountryCode, rawRegion)
		item.Label, item.Province = label, province
		if len(snapshot.IPs) < 200 {
			snapshot.IPs = append(snapshot.IPs, item)
		}
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
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if period != 24*time.Hour && period != 7*24*time.Hour && period != 30*24*time.Hour {
		period = 24 * time.Hour
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
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0), COALESCE(SUM(errors),0), COUNT(DISTINCT host)
		 FROM traffic_minutes WHERE minute>=?`, since,
	).Scan(&snapshot.Requests24H, &snapshot.BytesIn24H, &snapshot.BytesOut24H, &snapshot.Errors24H, &snapshot.Targets24H); err != nil {
		return dashboardSnapshot{}, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT (minute/?)*?, SUM(requests), SUM(bytes_in), SUM(bytes_out), SUM(errors)
		 FROM traffic_minutes WHERE minute>=? GROUP BY (minute/?) ORDER BY (minute/?)`,
		bucket, bucket, since, bucket, bucket,
	)
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
	snapshot.Targets, err = s.targets(ctx, since, 20)
	if err != nil {
		return dashboardSnapshot{}, err
	}
	snapshot.Recent, err = s.recent(ctx, 20, "")
	if err == nil {
		mergeRealtimeDashboard(&snapshot, since, bucket, s.pending, connections.Snapshot())
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
	rows, err := s.db.QueryContext(ctx,
		`SELECT host, SUM(requests), SUM(bytes_out), SUM(errors),
		 CASE WHEN SUM(requests)>0 THEN SUM(duration_ms)/SUM(requests) ELSE 0 END, MAX(minute)
		 FROM traffic_minutes WHERE minute>=? GROUP BY host ORDER BY SUM(bytes_out) DESC LIMIT ?`, since, limit,
	)
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
	if limit < 1 || limit > 200 {
		limit = 50
	}
	query := `SELECT id,timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms FROM request_logs`
	args := make([]any, 0, 2)
	if host = strings.TrimSpace(host); host != "" {
		query += ` WHERE host=?`
		args = append(args, host)
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
		if err := rows.Scan(&item.ID, &item.Timestamp, &item.Host, &item.Scheme, &item.Method, &item.Path, &item.Category,
			&item.Status, &item.BytesIn, &item.BytesOut, &item.DurationMS); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
