package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type connectionFlow struct {
	id            string
	started       time.Time
	clientIP      string
	method        string
	host          string
	domain        string
	path          string
	category      string
	userAgent     string
	cancel        context.CancelFunc
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	uploadRate    atomic.Int64
	downloadRate  atomic.Int64
	lastUpload    int64
	lastDownload  int64
}

type connectionSnapshot struct {
	ID            string `json:"id"`
	StartedAt     int64  `json:"started_at"`
	DurationMS    int64  `json:"duration_ms"`
	ClientIP      string `json:"client_ip"`
	Location      string `json:"location"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Domain        string `json:"domain"`
	Path          string `json:"path"`
	Category      string `json:"category"`
	UserAgent     string `json:"user_agent"`
	UploadBPS     int64  `json:"upload_bps"`
	DownloadBPS   int64  `json:"download_bps"`
	UploadTotal   int64  `json:"upload_total"`
	DownloadTotal int64  `json:"download_total"`
}

type activeTargetTraffic struct {
	Host        string `json:"host"`
	Domain      string `json:"domain"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	Connections int64  `json:"connections"`
}

type connectionTracker struct {
	mu        sync.RWMutex
	items     map[string]*connectionFlow
	sequence  atomic.Uint64
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newConnectionTracker() *connectionTracker {
	tracker := &connectionTracker{items: make(map[string]*connectionFlow), stop: make(chan struct{}), done: make(chan struct{})}
	go tracker.run()
	return tracker
}

func (t *connectionTracker) run() {
	defer close(t.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.mu.RLock()
			items := make([]*connectionFlow, 0, len(t.items))
			for _, item := range t.items {
				items = append(items, item)
			}
			t.mu.RUnlock()
			for _, item := range items {
				upload, download := item.uploadTotal.Load(), item.downloadTotal.Load()
				item.uploadRate.Store(max(0, upload-item.lastUpload))
				item.downloadRate.Store(max(0, download-item.lastDownload))
				item.lastUpload, item.lastDownload = upload, download
			}
		case <-t.stop:
			return
		}
	}
}

func (t *connectionTracker) Close() {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() {
		t.mu.Lock()
		for _, item := range t.items {
			item.cancel()
		}
		t.mu.Unlock()
		close(t.stop)
		<-t.done
	})
}

func (t *connectionTracker) Start(cancel context.CancelFunc, clientIP, method, host, domain, path, category, userAgent string) *connectionFlow {
	if t == nil {
		return nil
	}
	identifier := make([]byte, 9)
	if _, err := rand.Read(identifier); err != nil {
		identifier = []byte(strconv.FormatUint(t.sequence.Add(1), 10))
	}
	flow := &connectionFlow{
		id: hex.EncodeToString(identifier), started: time.Now(), cancel: cancel,
		clientIP: clientIP, method: method, host: host, domain: domain,
		path: truncateRunes(path, 256), category: category, userAgent: truncateRunes(userAgent, 160),
	}
	t.mu.Lock()
	t.items[flow.id] = flow
	t.mu.Unlock()
	return flow
}

func (t *connectionTracker) Finish(flow *connectionFlow) {
	if t == nil || flow == nil {
		return
	}
	t.mu.Lock()
	delete(t.items, flow.id)
	t.mu.Unlock()
}

func (t *connectionTracker) Cancel(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.RLock()
	flow := t.items[id]
	t.mu.RUnlock()
	if flow == nil {
		return false
	}
	flow.cancel()
	return true
}

func (t *connectionTracker) Snapshot() []connectionSnapshot {
	if t == nil {
		return []connectionSnapshot{}
	}
	now := time.Now()
	t.mu.RLock()
	result := make([]connectionSnapshot, 0, len(t.items))
	for _, item := range t.items {
		result = append(result, connectionSnapshot{
			ID: item.id, StartedAt: item.started.Unix(), DurationMS: now.Sub(item.started).Milliseconds(),
			ClientIP: item.clientIP, Method: item.method, Host: item.host, Domain: item.domain,
			Path: item.path, Category: item.category, UserAgent: item.userAgent,
			UploadBPS: item.uploadRate.Load(), DownloadBPS: item.downloadRate.Load(),
			UploadTotal: item.uploadTotal.Load(), DownloadTotal: item.downloadTotal.Load(),
		})
	}
	t.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].DownloadBPS == result[j].DownloadBPS {
			return result[i].StartedAt < result[j].StartedAt
		}
		return result[i].DownloadBPS > result[j].DownloadBPS
	})
	return result
}

func (t *connectionTracker) ActiveTargets() []activeTargetTraffic {
	return summarizeActiveTargets(t.Snapshot())
}

func summarizeActiveTargets(items []connectionSnapshot) []activeTargetTraffic {
	byHost := make(map[string]*activeTargetTraffic, len(items))
	for _, item := range items {
		target := byHost[item.Host]
		if target == nil {
			target = &activeTargetTraffic{Host: item.Host, Domain: item.Domain}
			byHost[item.Host] = target
		}
		target.BytesIn += item.UploadTotal
		target.BytesOut += item.DownloadTotal
		target.Connections++
	}
	result := make([]activeTargetTraffic, 0, len(byHost))
	for _, target := range byHost {
		result = append(result, *target)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].BytesOut == result[j].BytesOut {
			return result[i].Host < result[j].Host
		}
		return result[i].BytesOut > result[j].BytesOut
	})
	return result
}

func (s *telemetryStore) EnrichConnectionLocations(ctx context.Context, items []connectionSnapshot) error {
	if len(items) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.ClientIP != "" {
			unique[item.ClientIP] = struct{}{}
		}
	}
	if len(unique) == 0 {
		return nil
	}
	arguments := make([]any, 0, len(unique))
	placeholders := make([]string, 0, len(unique))
	for ip := range unique {
		arguments = append(arguments, ip)
		placeholders = append(placeholders, "?")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip,country,country_code,region FROM geo_ip_cache WHERE ip IN (`+strings.Join(placeholders, ",")+`)`, arguments...)
	if err != nil {
		return err
	}
	defer rows.Close()
	locations := make(map[string]string, len(unique))
	for rows.Next() {
		var ip, country, countryCode, region string
		if err := rows.Scan(&ip, &country, &countryCode, &region); err != nil {
			return err
		}
		if countryCode != "" {
			_, _, label, _ := geographyRegion(country, countryCode, region)
			locations[ip] = label
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for index := range items {
		items[index].Location = locations[items[index].ClientIP]
	}
	return nil
}

func (f *connectionFlow) AddUpload(value int64) {
	if f != nil && value > 0 {
		f.uploadTotal.Add(value)
	}
}

func (f *connectionFlow) AddDownload(value int64) {
	if f != nil && value > 0 {
		f.downloadTotal.Add(value)
	}
}

func truncateRunes(value string, limit int) string {
	characters := []rune(value)
	if len(characters) <= limit {
		return value
	}
	return string(characters[:limit])
}
