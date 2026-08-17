package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestConnectionTrackerMeasuresAndCancels(t *testing.T) {
	tracker := newConnectionTracker()
	t.Cleanup(tracker.Close)
	requestContext, cancel := context.WithCancel(context.Background())
	flow := tracker.Start(cancel, "1.1.1.1", http.MethodGet, "media.example:443", "media.example", "/Videos/1/stream", "stream", "Refract test")
	flow.AddUpload(128)
	flow.AddDownload(2048)

	deadline := time.Now().Add(2 * time.Second)
	for {
		items := tracker.Snapshot()
		if len(items) == 1 && items[0].UploadBPS == 128 && items[0].DownloadBPS == 2048 {
			if items[0].UploadTotal != 128 || items[0].DownloadTotal != 2048 || items[0].ClientIP != "1.1.1.1" {
				t.Fatalf("unexpected connection snapshot: %#v", items[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection rates were not updated: %#v", items)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !tracker.Cancel(flow.id) {
		t.Fatal("active connection could not be cancelled")
	}
	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("connection cancellation did not cancel the request context")
	}
	tracker.Finish(flow)
	if items := tracker.Snapshot(); len(items) != 0 {
		t.Fatalf("finished connection remained visible: %#v", items)
	}
}

func TestConnectionAdminAPIListsAndTerminates(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	requestContext, cancel := context.WithCancel(context.Background())
	flow := gateway.connections.Start(cancel, "1.1.1.1", http.MethodGet, "media.example", "media.example", "/stream", "stream", "test")
	defer gateway.connections.Finish(flow)

	listed := adminRequest(t, gateway, http.MethodGet, "/_admin/api/connections", nil, cookie, false)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), flow.id) || !strings.Contains(listed.Body.String(), "1.1.1.1") {
		t.Fatalf("connection list status=%d body=%s", listed.Code, listed.Body.String())
	}
	terminated := adminRequest(t, gateway, http.MethodDelete, "/_admin/api/connections/"+flow.id, nil, cookie, true)
	if terminated.Code != http.StatusOK {
		t.Fatalf("connection termination status=%d body=%s", terminated.Code, terminated.Body.String())
	}
	select {
	case <-requestContext.Done():
	case <-time.After(time.Second):
		t.Fatal("admin termination did not cancel the connection")
	}
}

func TestRequestLogsAPIPaginatesAndFiltersExactStatuses(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	now := time.Now().Unix()
	for index := 0; index < 45; index++ {
		status := http.StatusOK
		switch {
		case index >= 40:
			status = http.StatusInternalServerError
		case index >= 30:
			status = 499
		}
		if _, err := gateway.telemetry.db.Exec(
			`INSERT INTO request_logs(timestamp,host,scheme,method,path,category,status,bytes_in,bytes_out,duration_ms)
			 VALUES(?,?,?,?,?,?,?,?,?,?)`,
			now+int64(index), "media.example", "https", http.MethodGet, fmt.Sprintf("/item/%d", index), "api", status, 0, index, 10,
		); err != nil {
			t.Fatal(err)
		}
	}

	decodePage := func(path string) requestLogPage {
		t.Helper()
		response := adminRequest(t, gateway, http.MethodGet, path, nil, cookie, false)
		if response.Code != http.StatusOK {
			t.Fatalf("request logs status=%d body=%s", response.Code, response.Body.String())
		}
		var page requestLogPage
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}

	second := decodePage("/_admin/api/requests?page=2&page_size=20")
	if second.Page != 2 || second.PageSize != 20 || second.Total != 45 || second.TotalPages != 3 || len(second.Logs) != 20 {
		t.Fatalf("unexpected second page: %#v", second)
	}
	wantCounts := map[int]int64{http.StatusOK: 30, 499: 10, http.StatusInternalServerError: 5}
	for _, item := range second.Statuses {
		if item.Count != wantCounts[item.Status] {
			t.Fatalf("status %d count=%d want=%d", item.Status, item.Count, wantCounts[item.Status])
		}
		delete(wantCounts, item.Status)
	}
	if len(wantCounts) != 0 {
		t.Fatalf("missing status counts: %#v", wantCounts)
	}

	filtered := decodePage("/_admin/api/requests?page=2&page_size=4&status=499")
	if filtered.Page != 2 || filtered.Total != 10 || filtered.TotalPages != 3 || len(filtered.Logs) != 4 {
		t.Fatalf("unexpected filtered page: %#v", filtered)
	}
	for _, item := range filtered.Logs {
		if item.Status != 499 {
			t.Fatalf("filtered page contained status %d", item.Status)
		}
	}

	last := decodePage("/_admin/api/requests?page=999&page_size=20")
	if last.Page != 3 || len(last.Logs) != 5 {
		t.Fatalf("out-of-range page was not clamped: %#v", last)
	}
	for _, path := range []string{
		"/_admin/api/requests?page=0", "/_admin/api/requests?page_size=101", "/_admin/api/requests?status=99",
	} {
		response := adminRequest(t, gateway, http.MethodGet, path, nil, cookie, false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestRealtimeDashboardKeepsTrafficAcrossActivePendingAndPersistedStages(t *testing.T) {
	gateway := newAdminTestGateway(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow := gateway.connections.Start(cancel, "1.1.1.1", http.MethodGet, "media.example:443", "media.example", "/Videos/1/stream", "stream", "test")
	flow.AddUpload(128)
	flow.AddDownload(4096)

	snapshot, err := gateway.telemetry.Snapshot(context.Background(), 24*time.Hour, 1, 0, time.Minute, gateway.connections)
	if err != nil {
		t.Fatal(err)
	}
	assertRealtimeTraffic(t, snapshot, 1, 128, 4096)
	if len(snapshot.ActiveTargets) != 1 || snapshot.ActiveTargets[0].BytesOut != 4096 {
		t.Fatalf("active targets not included in dashboard: %#v", snapshot.ActiveTargets)
	}

	gateway.telemetry.RecordCompleted(telemetryEvent{
		FlowID: flow.id, Timestamp: time.Now(), Host: "media.example:443", Scheme: "https", Method: http.MethodGet,
		Path: "/Videos/1/stream", Category: "stream", Status: http.StatusOK, BytesIn: 128, BytesOut: 4096, DurationMS: 250,
	}, gateway.connections, flow)
	if items := gateway.connections.Snapshot(); len(items) != 0 {
		t.Fatalf("completed flow remained active: %#v", items)
	}

	snapshot, err = gateway.telemetry.Snapshot(context.Background(), 24*time.Hour, 0, 0, time.Minute, gateway.connections)
	if err != nil {
		t.Fatal(err)
	}
	assertRealtimeTraffic(t, snapshot, 1, 128, 4096)

	deadline := time.Now().Add(3 * time.Second)
	for {
		var persisted int64
		if err := gateway.telemetry.db.QueryRow(`SELECT COALESCE(SUM(bytes_out),0) FROM traffic_minutes`).Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if persisted == 4096 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("telemetry was not persisted, bytes_out=%d", persisted)
		}
		time.Sleep(20 * time.Millisecond)
	}

	snapshot, err = gateway.telemetry.Snapshot(context.Background(), 24*time.Hour, 0, 0, time.Minute, gateway.connections)
	if err != nil {
		t.Fatal(err)
	}
	assertRealtimeTraffic(t, snapshot, 1, 128, 4096)
}

func TestAbortedProxyRequestPersistsPartialTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", "65536")
		_, _ = writer.Write([]byte(strings.Repeat("x", 64<<10)))
	}))
	defer upstream.Close()

	gateway := newAdminTestGateway(t)
	gateway.cfg.DefaultUpstream = mustURL(t, upstream.URL)
	gateway.cfg.AllowedUpstreams = []TargetPattern{patternFromURL(gateway.cfg.DefaultUpstream)}
	gateway.resolver = newSafeResolver(time.Minute, true)

	serverContext := context.WithValue(context.Background(), http.ServerContextKey, &http.Server{})
	requestContext, cancel := context.WithCancel(serverContext)
	request := httptest.NewRequest(http.MethodGet, "https://proxy.test/stream", nil).WithContext(requestContext)
	writer := &cancelingErrorWriter{header: make(http.Header), cancel: cancel, limit: 4096}
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		gateway.ServeHTTP(writer, request)
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("proxy panic=%v, want http.ErrAbortHandler", recovered)
	}
	if writer.written <= 0 || writer.written >= 64<<10 {
		t.Fatalf("partial response bytes=%d, want an incomplete non-zero response", writer.written)
	}
	wantBytesOut := int64(writer.written)

	deadline := time.Now().Add(3 * time.Second)
	for {
		var status int
		var bytesOut int64
		err := gateway.telemetry.db.QueryRow(`SELECT status,bytes_out FROM request_logs ORDER BY id DESC LIMIT 1`).Scan(&status, &bytesOut)
		if err == nil && status == 499 && bytesOut == wantBytesOut {
			break
		}
		if err != nil && err != sql.ErrNoRows {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("aborted request was not persisted: status=%d bytes_out=%d err=%v", status, bytesOut, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var requests, bytesOut, errorsCount int64
	if err := gateway.telemetry.db.QueryRow(`SELECT COALESCE(SUM(requests),0),COALESCE(SUM(bytes_out),0),COALESCE(SUM(errors),0) FROM traffic_minutes`).Scan(&requests, &bytesOut, &errorsCount); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || bytesOut != wantBytesOut || errorsCount != 0 {
		t.Fatalf("aborted traffic totals requests=%d bytes_out=%d errors=%d", requests, bytesOut, errorsCount)
	}
}

type cancelingErrorWriter struct {
	header  http.Header
	cancel  context.CancelFunc
	limit   int
	written int
}

func (w *cancelingErrorWriter) Header() http.Header { return w.header }

func (w *cancelingErrorWriter) WriteHeader(int) {}

func (w *cancelingErrorWriter) Write(data []byte) (int, error) {
	remaining := max(0, w.limit-w.written)
	written := min(len(data), remaining)
	w.written += written
	w.cancel()
	return written, io.ErrClosedPipe
}

func TestLiveAPIAggregatesActiveTrafficByTarget(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	_, cancelFirst := context.WithCancel(context.Background())
	_, cancelSecond := context.WithCancel(context.Background())
	t.Cleanup(cancelFirst)
	t.Cleanup(cancelSecond)
	first := gateway.connections.Start(cancelFirst, "1.1.1.1", http.MethodGet, "media.example:443", "media.example", "/first", "stream", "test")
	second := gateway.connections.Start(cancelSecond, "2.2.2.2", http.MethodGet, "media.example:443", "media.example", "/second", "stream", "test")
	t.Cleanup(func() {
		gateway.connections.Finish(first)
		gateway.connections.Finish(second)
	})
	first.AddUpload(40)
	first.AddDownload(100)
	second.AddUpload(60)
	second.AddDownload(250)

	response := adminRequest(t, gateway, http.MethodGet, "/_admin/api/live", nil, cookie, false)
	if response.Code != http.StatusOK {
		t.Fatalf("live status=%d body=%s", response.Code, response.Body.String())
	}
	var live liveSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	if len(live.ActiveTargets) != 1 {
		t.Fatalf("active targets=%#v", live.ActiveTargets)
	}
	target := live.ActiveTargets[0]
	if target.Host != "media.example:443" || target.Connections != 2 || target.BytesIn != 100 || target.BytesOut != 350 {
		t.Fatalf("unexpected active target aggregation: %#v", target)
	}
}

func assertRealtimeTraffic(t *testing.T, snapshot dashboardSnapshot, requests, bytesIn, bytesOut int64) {
	t.Helper()
	if snapshot.Requests24H != requests || snapshot.BytesIn24H != bytesIn || snapshot.BytesOut24H != bytesOut {
		t.Fatalf("unexpected realtime totals: want requests=%d bytes_in=%d bytes_out=%d snapshot=%#v", requests, bytesIn, bytesOut, snapshot)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].Host != "media.example:443" || snapshot.Targets[0].BytesOut != bytesOut {
		t.Fatalf("unexpected realtime targets: %#v", snapshot.Targets)
	}
}

func TestReportAggregationAndCSVExport(t *testing.T) {
	gateway := newAdminTestGateway(t)
	cookie := loginAdmin(t, gateway)
	now := time.Now().Unix()
	hour := now - now%3600
	minute := hour - 30*60
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO traffic_minutes(minute,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?)`, []any{minute - 60, "=unsafe.example", 2, 100, 1000, 1, 80}},
		{`INSERT INTO traffic_minutes(minute,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?)`, []any{minute, "media.example", 3, 200, 4000, 0, 120}},
		{`INSERT INTO geo_ip_cache(ip,country,country_code,region,latitude,longitude,looked_up) VALUES(?,?,?,?,?,?,?)`, []any{"1.1.1.1", "China", "CN", "Guangdong", 23.1, 113.3, now}},
		{`INSERT INTO client_geo_hours(hour,ip,requests,bytes_out,peak_bps,last_seen) VALUES(?,?,?,?,?,?)`, []any{hour, "1.1.1.1", 5, 5000, 2048, now}},
	}
	for _, statement := range statements {
		if _, err := gateway.telemetry.db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	report, err := gateway.telemetry.Report(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if report.Requests != 5 || report.BytesIn != 300 || report.BytesOut != 5000 || report.Errors != 1 || report.Targets != 2 {
		t.Fatalf("unexpected report totals: %#v", report)
	}
	if len(report.Timeline) != 1 || len(report.TopTargets) != 2 || len(report.TopClients) != 1 || len(report.Regions) != 1 {
		t.Fatalf("unexpected report breakdown: %#v", report)
	}

	exported := adminRequest(t, gateway, http.MethodGet, "/_admin/api/reports/export?period=24h&kind=targets", nil, cookie, false)
	if exported.Code != http.StatusOK || !strings.HasPrefix(exported.Body.String(), "\xef\xbb\xbf") {
		t.Fatalf("CSV export status=%d body=%q", exported.Code, exported.Body.String())
	}
	if strings.Contains(exported.Body.String(), "\n=unsafe.example,") || !strings.Contains(exported.Body.String(), "\n'=unsafe.example,") {
		t.Fatalf("CSV formula injection was not neutralized: %q", exported.Body.String())
	}
	invalid := adminRequest(t, gateway, http.MethodGet, "/_admin/api/reports?period=year", nil, cookie, false)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid report period status=%d", invalid.Code)
	}
}

func TestAuditSanitizesSecretsAndQueryParameters(t *testing.T) {
	gateway := newAdminTestGateway(t)
	token := "123456789:" + strings.Repeat("A", 35)
	gateway.telemetry.RecordAudit(context.Background(), auditEntry{
		Username: "admin", Action: "test.secret", Resource: "https://example.test/path?api_key=top-secret",
		Detail: "password=hunter2 token=" + token, Success: false,
	})
	entries, err := gateway.telemetry.AuditLogs(context.Background(), 10)
	if err != nil || len(entries) == 0 {
		t.Fatalf("audit entries=%#v err=%v", entries, err)
	}
	encoded := entries[0].Resource + " " + entries[0].Detail
	for _, secret := range []string{"top-secret", "hunter2", token} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("audit entry leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(encoded, "[REDACTED]") {
		t.Fatalf("audit entry did not mark redacted content: %s", encoded)
	}
}

func TestBackupCreateImportRestoreAndPreserveAdministrator(t *testing.T) {
	gateway := newAdminTestGateway(t)
	ctx := context.Background()
	if err := gateway.telemetry.setSetting(ctx, "restore_marker", "before"); err != nil {
		t.Fatal(err)
	}
	created, err := gateway.backups.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(gateway.backups.directory, created.Name)
	if err := validateSQLiteBackup(backupPath); err != nil {
		t.Fatalf("created backup is invalid: %v", err)
	}

	if err := gateway.telemetry.setSetting(ctx, "restore_marker", "after"); err != nil {
		t.Fatal(err)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte("new administrator password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.telemetry.ChangePassword(ctx, "admin", string(newHash)); err != nil {
		t.Fatal(err)
	}
	authBeforeRestore, err := gateway.telemetry.AuthRecord(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}

	safety, err := gateway.backups.Restore(ctx, created.Name)
	if err != nil {
		t.Fatal(err)
	}
	marker, err := gateway.telemetry.setting(ctx, "restore_marker")
	if err != nil || marker != "before" {
		t.Fatalf("restored marker=%q err=%v", marker, err)
	}
	authAfterRestore, err := gateway.telemetry.AuthRecord(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if authAfterRestore.PasswordHash != authBeforeRestore.PasswordHash || authAfterRestore.Version != authBeforeRestore.Version {
		t.Fatal("restore replaced the active administrator credentials")
	}

	safetyDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(gateway.backups.directory, safety.Name))+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer safetyDB.Close()
	var safetyMarker string
	if err := safetyDB.QueryRow(`SELECT value FROM gateway_settings WHERE key='restore_marker'`).Scan(&safetyMarker); err != nil || safetyMarker != "after" {
		t.Fatalf("safety backup marker=%q err=%v", safetyMarker, err)
	}

	file, _, err := gateway.backups.Open(created.Name)
	if err != nil {
		t.Fatal(err)
	}
	imported, importErr := gateway.backups.Import(file)
	_ = file.Close()
	if importErr != nil || imported.Kind != "import" {
		t.Fatalf("imported=%#v err=%v", imported, importErr)
	}
}

func TestBackupRestoreProtectsSourceAtRetentionOne(t *testing.T) {
	gateway := newAdminTestGateway(t)
	ctx := context.Background()
	if err := gateway.telemetry.SaveBackupConfig(ctx, backupConfig{Enabled: true, Hour: 3, Retention: 1}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.telemetry.setSetting(ctx, "restore_marker", "before"); err != nil {
		t.Fatal(err)
	}
	source, err := gateway.backups.Create(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.telemetry.setSetting(ctx, "restore_marker", "after"); err != nil {
		t.Fatal(err)
	}
	safety, err := gateway.backups.Restore(ctx, source.Name)
	if err != nil {
		t.Fatalf("restore with retention one failed: %v", err)
	}
	marker, err := gateway.telemetry.setting(ctx, "restore_marker")
	if err != nil || marker != "before" {
		t.Fatalf("restored marker=%q err=%v", marker, err)
	}
	files, err := gateway.backups.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != safety.Name || files[0].Kind != "safety" {
		t.Fatalf("retention did not preserve the safety snapshot: %#v", files)
	}
}
