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
	manager := &backupManager{
		store: store, directory: directory, stop: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1),
	}
	go manager.run()
	return manager, nil
}

func (m *backupManager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("backup integrity check failed")
	}
	for _, table := range []string{"request_logs", "traffic_minutes", "gateway_settings", "proxy_rules", "telegram_settings", "geo_ip_cache", "client_geo_hours"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			return fmt.Errorf("backup is missing table %s", table)
		}
	}
	return nil
}

func (s *telemetryStore) restoreSQLite(ctx context.Context, path string) error {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
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
		columns  string
		optional bool
	}{
		{"request_logs", "id,timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms", false},
		{"traffic_minutes", "minute,host,requests,bytes_in,bytes_out,errors,duration_ms", false},
		{"gateway_settings", "key,value,updated_at", false},
		{"proxy_rules", "id,action,domain_suffix,path_prefix,enabled,created_at", false},
		{"telegram_settings", "id,enabled,bot_token,chat_id,send_hour,last_sent_date,updated_at", false},
		{"geo_ip_cache", "ip,country,country_code,region,latitude,longitude,looked_up", false},
		{"client_geo_hours", "hour,ip,requests,bytes_out,peak_bps,last_seen", false},
		{"audit_logs", "id,timestamp,username,client_ip,action,resource,detail,success", true},
	}
	for _, table := range tables {
		if table.optional {
			var count int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM restored.sqlite_master WHERE type='table' AND name=?`, table.name).Scan(&count); err != nil {
				return err
			}
			if count == 0 {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM main."+table.name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO main."+table.name+"("+table.columns+") SELECT "+table.columns+" FROM restored."+table.name); err != nil {
			return err
		}
	}
	return tx.Commit()
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
