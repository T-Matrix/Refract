package gateway

import (
	"context"
	"database/sql"
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
	embyHealthProbeTimeout  = 5 * time.Second
	embyHealthRetention     = 31 * 24 * time.Hour
	embyHealthMaxServers    = 200
)

var errEmbyHealthLimit = errors.New("maximum monitored server count reached")
var errEmbyHealthDisabled = errors.New("monitored server is disabled")

type embyHealthServer struct {
	ID              int64    `json:"id"`
	GroupName       string   `json:"group_name"`
	Name            string   `json:"name"`
	LineName        string   `json:"line_name"`
	Note            string   `json:"note"`
	BaseURL         string   `json:"base_url"`
	Enabled         bool     `json:"enabled"`
	Status          string   `json:"status"`
	LatencyMS       int64    `json:"latency_ms"`
	LastStatusCode  int      `json:"last_status_code"`
	LastCheckedAt   int64    `json:"last_checked_at"`
	ConfigVersion   int64    `json:"-"`
	Availability24H *float64 `json:"availability_24h"`
	Availability7D  *float64 `json:"availability_7d"`
	Availability30D *float64 `json:"availability_30d"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
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
	CheckedAt  int64
	Success    bool
	LatencyMS  int64
	StatusCode int
}

func normalizeEmbyHealthServer(groupName, name, rawURL string, enabled bool) (embyHealthServer, error) {
	return normalizeEmbyHealthServerDetails(groupName, name, "", "", rawURL, enabled)
}

func normalizeEmbyHealthServerDetails(groupName, name, lineName, note, rawURL string, enabled bool) (embyHealthServer, error) {
	groupName = strings.TrimSpace(groupName)
	name = strings.TrimSpace(name)
	lineName = strings.TrimSpace(lineName)
	note = strings.TrimSpace(note)
	rawURL = strings.TrimSpace(rawURL)
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
	return embyHealthServer{
		GroupName: groupName, Name: name, LineName: lineName, Note: note,
		BaseURL: strings.TrimRight(parsed.String(), "/"), Enabled: enabled,
	}, nil
}

func hasControlCharacters(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0
}

func (s *telemetryStore) SaveEmbyHealthServer(ctx context.Context, server embyHealthServer) (int64, error) {
	if server.ID == 0 {
		now := time.Now().Unix()
		result, err := s.db.ExecContext(ctx,
			`INSERT INTO monitored_emby_servers(group_name,name,line_name,note,base_url,enabled,config_version,created_at,updated_at)
			 SELECT ?,?,?,?,?,?,1,?,? WHERE (SELECT COUNT(*) FROM monitored_emby_servers) < ?`,
			server.GroupName, server.Name, server.LineName, server.Note, server.BaseURL, server.Enabled, now, now, embyHealthMaxServers)
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
	var previousURL string
	if err := tx.QueryRowContext(ctx, `SELECT base_url FROM monitored_emby_servers WHERE id=?`, server.ID).Scan(&previousURL); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE monitored_emby_servers SET group_name=?,name=?,line_name=?,note=?,base_url=?,enabled=?,
		 config_version=config_version+CASE WHEN base_url<>? OR enabled<>? THEN 1 ELSE 0 END,updated_at=? WHERE id=?`,
		server.GroupName, server.Name, server.LineName, server.Note, server.BaseURL, server.Enabled,
		server.BaseURL, server.Enabled, time.Now().Unix(), server.ID)
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
	if previousURL != server.BaseURL {
		if _, err := tx.ExecContext(ctx, `DELETE FROM emby_health_checks WHERE server_id=?`, server.ID); err != nil {
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

func (s *telemetryStore) EmbyHealthServers(ctx context.Context, includeDisabled bool) ([]embyHealthServer, error) {
	now := time.Now()
	query := `SELECT s.id,s.group_name,s.name,s.line_name,s.note,s.base_url,s.enabled,s.created_at,s.updated_at,s.config_version,
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
	for rows.Next() {
		var server embyHealthServer
		var enabled int
		var checkedAt, success, latency, statusCode sql.NullInt64
		var availability24h, availability7d, availability30d sql.NullFloat64
		if err := rows.Scan(&server.ID, &server.GroupName, &server.Name, &server.LineName, &server.Note, &server.BaseURL, &enabled,
			&server.CreatedAt, &server.UpdatedAt, &server.ConfigVersion, &checkedAt, &success, &latency, &statusCode,
			&availability24h, &availability7d, &availability30d); err != nil {
			return nil, err
		}
		server.Enabled = enabled == 1
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
		servers = append(servers, server)
	}
	return servers, rows.Err()
}

func (s *telemetryStore) RecordEmbyHealthCheck(ctx context.Context, serverID, configVersion int64, sample embyHealthSample) error {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO emby_health_checks(server_id,checked_at,success,latency_ms,status_code)
		 SELECT ?,?,?,?,? WHERE EXISTS (
			SELECT 1 FROM monitored_emby_servers WHERE id=? AND config_version=? AND enabled=1
		 )`,
		serverID, sample.CheckedAt, sample.Success, sample.LatencyMS, sample.StatusCode, serverID, configVersion)
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
	ctx, cancel := context.WithCancel(context.Background())
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: embyHealthProbeTimeout,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		info, _ := ctx.Value(targetContextKey{}).(*targetInfo)
		if info == nil || !sameDialAddress(address, targetHostPort(info.URL)) {
			return nil, errors.New("health probe dial target was not validated")
		}
		dialer := &net.Dialer{Timeout: embyHealthProbeTimeout, KeepAlive: 15 * time.Second}
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
			Timeout:   embyHealthProbeTimeout,
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
	servers, err := m.store.EmbyHealthServers(m.ctx, false)
	if err != nil || len(servers) == 0 {
		return
	}
	semaphore := make(chan struct{}, 8)
	var checks sync.WaitGroup
	for _, server := range servers {
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
		}(server.ID)
	}
	checks.Wait()
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
	requestContext, cancel := context.WithTimeout(ctx, embyHealthProbeTimeout)
	stopOnClose := context.AfterFunc(m.ctx, cancel)
	defer func() {
		stopOnClose()
		cancel()
	}()
	servers, err := m.store.EmbyHealthServers(requestContext, true)
	if err != nil {
		return err
	}
	var server *embyHealthServer
	for index := range servers {
		if servers[index].ID == serverID {
			server = &servers[index]
			break
		}
	}
	if server == nil {
		return sql.ErrNoRows
	}
	if !server.Enabled {
		return errEmbyHealthDisabled
	}
	sample := m.probe(requestContext, server.BaseURL)
	writeContext, cancelWrite := context.WithTimeout(m.ctx, 3*time.Second)
	defer cancelWrite()
	return m.store.RecordEmbyHealthCheck(writeContext, serverID, server.ConfigVersion, sample)
}

func (m *embyHealthMonitor) probe(ctx context.Context, baseURL string) (sample embyHealthSample) {
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
	base.Path = strings.TrimRight(base.Path, "/") + "/System/Info/Public"
	base.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return sample
	}
	request.Header.Set("Accept", "application/json")
	request = request.WithContext(context.WithValue(request.Context(), targetContextKey{}, &targetInfo{URL: base, DialAddresses: dialAddresses}))
	response, err := m.client.Do(request)
	if err != nil {
		return sample
	}
	defer response.Body.Close()
	sample.StatusCode = response.StatusCode
	// Some Emby deployments intentionally deny anonymous system endpoints with
	// 403; that still proves the HTTP edge is reachable. A 5xx response instead
	// indicates an upstream or gateway failure and counts as an unavailable
	// probe. Keep the code in the sample for diagnosis.
	sample.Success = response.StatusCode >= 100 && response.StatusCode < 500
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return sample
}

func embyHealthPublicSnapshot(servers []embyHealthServer) publicEmbyHealthSnapshot {
	snapshot := publicEmbyHealthSnapshot{Groups: make([]publicEmbyHealthGroup, 0), UpdatedAt: time.Now().Unix()}
	groupIndexes := make(map[string]int)
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		index, exists := groupIndexes[server.GroupName]
		if !exists {
			index = len(snapshot.Groups)
			groupIndexes[server.GroupName] = index
			snapshot.Groups = append(snapshot.Groups, publicEmbyHealthGroup{Name: server.GroupName, Servers: make([]publicEmbyHealthServer, 0)})
		}
		snapshot.Groups[index].Servers = append(snapshot.Groups[index].Servers, publicEmbyHealthServer{
			ID: server.ID, Name: server.Name, LineName: server.LineName, Note: server.Note, Status: server.Status, LatencyMS: server.LatencyMS,
			LastCheckedAt: server.LastCheckedAt, Availability24H: server.Availability24H,
			Availability7D: server.Availability7D, Availability30D: server.Availability30D,
		})
	}
	return snapshot
}
