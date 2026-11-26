package gateway

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBackupUploadBytes = 512 << 20

var backupNamePattern = regexp.MustCompile(`^refract-(manual|auto|safety|import)-[0-9]{8}-[0-9]{6}-[a-f0-9]{6}\.sqlite$`)

type backupConfig struct {
	Enabled   bool `json:"enabled"`
	Hour      int  `json:"hour"`
	Retention int  `json:"retention"`
}

type backupFile struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
	modified  time.Time
}

type backupSnapshot struct {
	Config  backupConfig `json:"config"`
	Files   []backupFile `json:"files"`
	NextRun int64        `json:"next_run"`
}

type backupManager struct {
	store     *telemetryStore
	directory string
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	stop      chan struct{}
	done      chan struct{}
	wake      chan struct{}
	closeOnce sync.Once
}

func newBackupManager(store *telemetryStore, cfg Config) (*backupManager, error) {
	directory := strings.TrimSpace(cfg.AdminBackupDir)
	if directory == "" {
		directory = filepath.Join(filepath.Dir(cfg.AdminDatabasePath), "backups")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := &backupManager{
		store: store, directory: directory, ctx: ctx, cancel: cancel,
		stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	go manager.run()
	return manager, nil
}

func (m *backupManager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		m.cancel()
		close(m.stop)
		<-m.done
	})
}

func (m *backupManager) Wake() {
	if m == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *backupManager) run() {
	defer close(m.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			m.maybeCreate(now)
		case <-m.wake:
			m.maybeCreate(time.Now())
		case <-m.stop:
			return
		}
	}
}

func (m *backupManager) maybeCreate(now time.Time) {
	now = inApplicationTimezone(now)
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()
	config, err := m.store.LoadBackupConfig(ctx)
	if err != nil || !config.Enabled || now.Hour() != config.Hour {
		return
	}
	date := now.Format("2006-01-02")
	lastDate, _ := m.store.setting(ctx, "backup_last_auto_date")
	if lastDate == date {
		return
	}
	file, err := m.Create(ctx, "auto")
	if err != nil {
		m.store.RecordAudit(ctx, auditEntry{Username: "system", Action: "backup.auto", Detail: err.Error(), Success: false})
		return
	}
	_ = m.store.setSetting(ctx, "backup_last_auto_date", date)
	m.store.RecordAudit(ctx, auditEntry{Username: "system", Action: "backup.auto", Resource: file.Name, Success: true})
}

func (m *backupManager) Snapshot(ctx context.Context) (backupSnapshot, error) {
	config, err := m.store.LoadBackupConfig(ctx)
	if err != nil {
		return backupSnapshot{}, err
	}
	files, err := m.List()
	if err != nil {
		return backupSnapshot{}, err
	}
	return backupSnapshot{Config: config, Files: files, NextRun: nextBackupRun(time.Now(), config)}, nil
}

func (m *backupManager) Create(ctx context.Context, kind string) (backupFile, error) {
	if m == nil || !map[string]bool{"manual": true, "auto": true, "safety": true}[kind] {
		return backupFile{}, errors.New("invalid backup kind")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createLocked(ctx, kind, nil)
}

func (m *backupManager) createLocked(ctx context.Context, kind string, protected map[string]bool) (backupFile, error) {
	name := backupFilename(kind)
	path := filepath.Join(m.directory, name)
	escaped := strings.ReplaceAll(path, "'", "''")
	if _, err := m.store.db.ExecContext(ctx, "VACUUM INTO '"+escaped+"'"); err != nil {
		return backupFile{}, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = os.Remove(path)
		return backupFile{}, err
	}
	if err := validateSQLiteBackup(path); err != nil {
		_ = os.Remove(path)
		return backupFile{}, err
	}
	config, _ := m.store.LoadBackupConfig(ctx)
	_ = m.prune(max(1, config.Retention), protected)
	return backupInfo(path)
}

func (m *backupManager) Import(reader io.Reader) (backupFile, error) {
	if m == nil {
		return backupFile{}, errors.New("backup manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	name := backupFilename("import")
	path := filepath.Join(m.directory, name)
	temporary := path + ".partial"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return backupFile{}, err
	}
	written, copyErr := io.Copy(file, io.LimitReader(reader, maxBackupUploadBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > maxBackupUploadBytes {
		_ = os.Remove(temporary)
		if written > maxBackupUploadBytes {
			return backupFile{}, errors.New("backup file exceeds 512 MB")
		}
		return backupFile{}, errors.Join(copyErr, closeErr)
	}
	if err := validateSQLiteBackup(temporary); err != nil {
		_ = os.Remove(temporary)
		return backupFile{}, err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return backupFile{}, err
	}
	return backupInfo(path)
}

func (m *backupManager) Restore(ctx context.Context, name string) (backupFile, error) {
	if m == nil {
		return backupFile{}, errors.New("backup manager unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	path, err := m.path(name)
	if err != nil {
		return backupFile{}, err
	}
	if err := validateSQLiteBackup(path); err != nil {
		return backupFile{}, err
	}
	safety, err := m.createLocked(ctx, "safety", map[string]bool{name: true})
	if err != nil {
		return backupFile{}, fmt.Errorf("create safety backup: %w", err)
	}
	if err := m.store.restoreSQLite(ctx, path); err != nil {
		return backupFile{}, err
	}
	config, _ := m.store.LoadBackupConfig(ctx)
	_ = m.prune(max(1, config.Retention), nil)
	return safety, nil
}

func (m *backupManager) Delete(name string) error {
	path, err := m.path(name)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.Remove(path)
}

func (m *backupManager) Open(name string) (*os.File, os.FileInfo, error) {
	path, err := m.path(name)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func (m *backupManager) List() ([]backupFile, error) {
	entries, err := os.ReadDir(m.directory)
	if err != nil {
		return nil, err
	}
	result := make([]backupFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !backupNamePattern.MatchString(entry.Name()) {
			continue
		}
		item, err := backupInfo(filepath.Join(m.directory, entry.Name()))
		if err == nil {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].modified.Equal(result[j].modified) {
			return result[i].Name > result[j].Name
		}
		return result[i].modified.After(result[j].modified)
	})
	return result, nil
}

func (m *backupManager) path(name string) (string, error) {
	if !backupNamePattern.MatchString(name) || filepath.Base(name) != name {
		return "", errors.New("invalid backup name")
	}
	path := filepath.Join(m.directory, name)
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

func (m *backupManager) prune(retention int, protected map[string]bool) error {
	files, err := m.List()
	if err != nil {
		return err
	}
	kept := 0
	for _, file := range files {
		if protected[file.Name] {
			continue
		}
		if kept < retention {
			kept++
			continue
		}
		if err := os.Remove(filepath.Join(m.directory, file.Name)); err != nil {
			return err
		}
	}
	return nil
}

func backupFilename(kind string) string {
	random := make([]byte, 3)
	_, _ = rand.Read(random)
	return "refract-" + kind + "-" + inApplicationTimezone(time.Now()).Format("20060102-150405") + "-" + hex.EncodeToString(random) + ".sqlite"
}

func backupInfo(path string) (backupFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return backupFile{}, err
	}
	match := backupNamePattern.FindStringSubmatch(info.Name())
	if len(match) != 2 {
		return backupFile{}, errors.New("invalid backup name")
	}
	return backupFile{Name: info.Name(), Kind: match[1], Size: info.Size(), CreatedAt: info.ModTime().Unix(), modified: info.ModTime()}, nil
}

func validateSQLiteBackup(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	header := make([]byte, 16)
	_, readErr := io.ReadFull(file, header)
	_ = file.Close()
	if readErr != nil || string(header) != "SQLite format 3\x00" {
		return errors.New("file is not a SQLite database")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)&_pragma=trusted_schema(0)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("backup integrity check failed")
	}
	// Reject triggers, views, virtual tables, and generated columns to neutralize hostile SQLite schemas.
	var unsafeObjects int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sqlite_master
		WHERE type IN ('trigger','view')
		   OR UPPER(COALESCE(sql,'')) LIKE '%CREATE VIRTUAL TABLE%'
		   OR UPPER(COALESCE(sql,'')) LIKE '%GENERATED ALWAYS AS%'
	`).Scan(&unsafeObjects); err != nil || unsafeObjects > 0 {
		return errors.New("backup contains unsupported triggers, views, virtual tables, or generated columns")
	}
	for _, table := range []string{"request_logs", "traffic_minutes", "gateway_settings", "proxy_rules", "telegram_settings", "geo_ip_cache", "client_geo_hours"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			return fmt.Errorf("backup is missing table %s", table)
		}
	}
	return nil
}

func commonTableColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	mainCols := make(map[string]struct{})
	rows, err := tx.QueryContext(ctx, `SELECT name FROM main.pragma_table_info('`+table+`')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		mainCols[name] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	restoredRows, err := tx.QueryContext(ctx, `SELECT name FROM restored.pragma_table_info('`+table+`')`)
	if err != nil {
		return nil, err
	}
	var common []string
	for restoredRows.Next() {
		var name string
		if err := restoredRows.Scan(&name); err != nil {
			_ = restoredRows.Close()
			return nil, err
		}
		if _, ok := mainCols[name]; ok {
			common = append(common, name)
		}
	}
	if err := restoredRows.Close(); err != nil {
		return nil, err
	}
	return common, nil
}

func (s *telemetryStore) restoreSQLite(ctx context.Context, path string) error {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := connection.ExecContext(ctx, `PRAGMA trusted_schema = OFF`); err != nil {
		return err
	}
	if _, err := connection.ExecContext(ctx, `ATTACH DATABASE ? AS restored`, path); err != nil {
		return err
	}
	defer connection.ExecContext(context.Background(), `DETACH DATABASE restored`)
	tx, err := connection.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tables := []struct {
		name     string
		optional bool
	}{
		{"request_logs", false},
		{"traffic_minutes", false},
		{"node_traffic_minutes", true},
		{"node_nic_traffic_minutes", true},
		{"node_nic_state", true},
		{"gateway_settings", false},
		{"proxy_rules", false},
		{"proxy_player_rules", true},
		{"telegram_settings", false},
		{"turnstile_settings", true},
		{"geo_ip_cache", false},
		{"client_geo_hours", false},
		{"audit_logs", true},
		{"edge_nodes", true},
		{"edge_domains", true},
		{"waf_rules", true},
		{"smart_dns_profiles", true},
		{"watch_history", true},
	}
	for _, table := range tables {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.sqlite_master WHERE type='table' AND name=?`, table.name).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if table.optional {
				continue
			}
			return fmt.Errorf("backup is missing table %s", table.name)
		}
		cols, err := commonTableColumns(ctx, tx, table.name)
		if err != nil {
			return err
		}
		if len(cols) == 0 {
			continue
		}
		colList := strings.Join(cols, ",")
		if _, err := tx.ExecContext(ctx, "DELETE FROM main."+table.name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO main."+table.name+"("+colList+") SELECT "+colList+" FROM restored."+table.name); err != nil {
			return err
		}
	}
	// Guarantee singleton settings rows exist even if an imported backup had empty tables.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO main.telegram_settings(id,enabled,bot_token,chat_id,send_hour,last_sent_date,updated_at) VALUES(1,0,X'','',9,'',0)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO main.turnstile_settings(id,enabled,site_key,secret,hostname,tested_fingerprint,verified_at,updated_at) VALUES(1,0,'',X'','','',0,0)`); err != nil {
		return err
	}
	if err := restoreEmbyHealthTables(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func restoreEmbyHealthTables(ctx context.Context, tx *sql.Tx) error {
	var serverTable, checkTable int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.sqlite_master WHERE type='table' AND name='monitored_emby_servers'`).Scan(&serverTable); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.sqlite_master WHERE type='table' AND name='emby_health_checks'`).Scan(&checkTable); err != nil {
		return err
	}
	if serverTable == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM main.emby_health_checks`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM main.monitored_emby_servers`); err != nil {
		return err
	}
	var lineName, note, probePath, serverVersion, detectedName, retryCount, retryDelay int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='line_name'`).Scan(&lineName); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='note'`).Scan(&note); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='probe_path'`).Scan(&probePath); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='server_version'`).Scan(&serverVersion); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='detected_name'`).Scan(&detectedName); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='retry_count'`).Scan(&retryCount); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('monitored_emby_servers') WHERE name='retry_delay_sec'`).Scan(&retryDelay); err != nil {
		return err
	}
	if lineName == 1 && note == 1 && probePath == 1 && serverVersion == 1 && detectedName == 1 && retryCount == 1 && retryDelay == 1 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.monitored_emby_servers
			(id,group_name,name,line_name,note,base_url,probe_path,server_version,detected_name,retry_count,retry_delay_sec,enabled,config_version,created_at,updated_at)
			SELECT id,group_name,name,line_name,note,base_url,probe_path,server_version,detected_name,retry_count,retry_delay_sec,enabled,config_version,created_at,updated_at
			FROM restored.monitored_emby_servers`); err != nil {
			return err
		}
	} else if lineName == 1 && note == 1 && probePath == 1 && serverVersion == 1 && detectedName == 1 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.monitored_emby_servers
			(id,group_name,name,line_name,note,base_url,probe_path,server_version,detected_name,enabled,config_version,created_at,updated_at)
			SELECT id,group_name,name,line_name,note,base_url,probe_path,server_version,detected_name,enabled,config_version,created_at,updated_at
			FROM restored.monitored_emby_servers`); err != nil {
			return err
		}
	} else if lineName == 1 && note == 1 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.monitored_emby_servers
			(id,group_name,name,line_name,note,base_url,enabled,config_version,created_at,updated_at)
			SELECT id,group_name,name,line_name,note,base_url,enabled,config_version,created_at,updated_at
			FROM restored.monitored_emby_servers`); err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.monitored_emby_servers
			(id,group_name,name,base_url,enabled,config_version,created_at,updated_at)
			SELECT id,group_name,name,base_url,enabled,config_version,created_at,updated_at
			FROM restored.monitored_emby_servers`); err != nil {
			return err
		}
	}
	if checkTable == 1 {
		var retriesCol int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.pragma_table_info('emby_health_checks') WHERE name='retries_used'`).Scan(&retriesCol); err != nil {
			return err
		}
		if retriesCol == 1 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO main.emby_health_checks
				(id,server_id,checked_at,success,latency_ms,status_code,retries_used)
				SELECT id,server_id,checked_at,success,latency_ms,status_code,retries_used
				FROM restored.emby_health_checks`); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `INSERT INTO main.emby_health_checks
				(id,server_id,checked_at,success,latency_ms,status_code)
				SELECT id,server_id,checked_at,success,latency_ms,status_code
				FROM restored.emby_health_checks`); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *telemetryStore) LoadBackupConfig(ctx context.Context) (backupConfig, error) {
	config := backupConfig{Enabled: true, Hour: 3, Retention: 7}
	values := map[string]*string{}
	var enabled, hour, retention string
	values["backup_enabled"], values["backup_hour"], values["backup_retention"] = &enabled, &hour, &retention
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM gateway_settings WHERE key IN ('backup_enabled','backup_hour','backup_retention')`)
	if err != nil {
		return backupConfig{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return backupConfig{}, err
		}
		if destination := values[key]; destination != nil {
			*destination = value
		}
	}
	if enabled != "" {
		config.Enabled = enabled == "1"
	}
	if parsed, err := strconv.Atoi(hour); err == nil && parsed >= 0 && parsed <= 23 {
		config.Hour = parsed
	}
	if parsed, err := strconv.Atoi(retention); err == nil && parsed >= 1 && parsed <= 30 {
		config.Retention = parsed
	}
	return config, rows.Err()
}

func (s *telemetryStore) SaveBackupConfig(ctx context.Context, config backupConfig) error {
	if config.Hour < 0 || config.Hour > 23 || config.Retention < 1 || config.Retention > 30 {
		return errors.New("invalid backup settings")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	values := map[string]string{
		"backup_enabled": strconv.Itoa(boolInt(config.Enabled)), "backup_hour": strconv.Itoa(config.Hour), "backup_retention": strconv.Itoa(config.Retention),
	}
	for key, value := range values {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`,
			key, value, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *telemetryStore) setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *telemetryStore) setSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`,
		key, value, time.Now().Unix())
	return err
}

func nextBackupRun(now time.Time, config backupConfig) int64 {
	if !config.Enabled {
		return 0
	}
	now = inApplicationTimezone(now)
	next := time.Date(now.Year(), now.Month(), now.Day(), config.Hour, 0, 0, 0, applicationLocation)
	if !next.After(now) {
		next = time.Date(now.Year(), now.Month(), now.Day()+1, config.Hour, 0, 0, 0, applicationLocation)
	}
	return next.Unix()
}
