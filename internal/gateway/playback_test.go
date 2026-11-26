package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPlaybackTrackerPassiveEmbyAndFilenameFallback(t *testing.T) {
	tr := newPlaybackTracker()
	host := "emby.example.com"

	// 1. Auth response captures username + token mapping
	metaAuth := playbackRequestMeta{
		ClientIP: "198.51.100.10", DeviceID: "appletv-1", DeviceName: "客厅 Apple TV",
		ClientName: "Infuse", UpstreamHost: host, Path: "/emby/Users/AuthenticateByName",
	}
	tr.ObserveJSONResponse(metaAuth, map[string]any{
		"AccessToken": "tok-secret-1",
		"User":        map[string]any{"Id": "u100", "Name": "Alice"},
	})

	// 2. Item detail response populates rich episode metadata
	metaItem := playbackRequestMeta{
		ClientIP: "198.51.100.10", DeviceID: "appletv-1", DeviceName: "客厅 Apple TV",
		ClientName: "Infuse", UpstreamHost: host, Path: "/emby/Users/u100/Items/98765",
	}
	tr.ObserveJSONResponse(metaItem, map[string]any{
		"Id":                "98765",
		"Name":              "红岸基地",
		"Type":              "Episode",
		"SeriesName":        "三体",
		"ParentIndexNumber": json.Number("1"),
		"IndexNumber":       json.Number("3"),
		"ProductionYear":    json.Number("2023"),
		"RunTimeTicks":      json.Number("27000000000"), // 2700s = 45m
	})

	// 3. PlaybackInfo adds 4K HEVC HDR quality specs
	metaPB := playbackRequestMeta{
		ClientIP: "198.51.100.10", DeviceID: "appletv-1", DeviceName: "客厅 Apple TV",
		ClientName: "Infuse", UpstreamHost: host, Path: "/emby/Items/98765/PlaybackInfo",
	}
	tr.ObserveJSONResponse(metaPB, map[string]any{
		"PlaySessionId": "ps-1",
		"MediaSources": []any{
			map[string]any{
				"Id":        "ms-1",
				"Name":      "Three-Body.S01E03.2160p.HEVC.mkv",
				"Container": "mkv",
				"MediaStreams": []any{
					map[string]any{"Type": "Video", "Width": json.Number("3840"), "Height": json.Number("2160"), "Codec": "hevc", "VideoRangeType": "HDR10"},
				},
			},
		},
	})

	// 4. Playing Progress report updates position & progress percentage
	metaProg := playbackRequestMeta{
		ClientIP: "198.51.100.10", DeviceID: "appletv-1", DeviceName: "客厅 Apple TV",
		ClientName: "Infuse", UpstreamHost: host, Path: "/emby/Sessions/Playing/Progress",
	}
	tr.ObservePlayingReport(metaProg, []byte(`{"ItemId":"98765","PositionTicks":13500000000,"IsPaused":false,"PlayMethod":"DirectPlay"}`))

	snaps := tr.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("expected 1 active playback session, got %d", len(snaps))
	}
	s := snaps[0]
	if s.UserName != "Alice" || s.SeriesName != "三体" || s.SeasonNumber != 1 || s.EpisodeNumber != 3 || s.Title != "红岸基地" {
		t.Fatalf("unexpected playback metadata: %+v", s)
	}
	if s.VideoQuality != "4K HEVC HDR" || s.ProgressPct != 50 || s.PlayMethod != "DirectPlay" {
		t.Fatalf("unexpected playback quality/progress: %+v", s)
	}

	// 5. Fallback filename parsing when Content-Disposition arrives without prior /Items call
	metaStream := playbackRequestMeta{
		ClientIP: "198.51.100.22", DeviceID: "iphone-2", DeviceName: "iPhone 16",
		ClientName: "Hills", UpstreamHost: host, Path: "/emby/Videos/55555/stream.mkv",
	}
	tr.ObserveStreamStart(metaStream)
	h := http.Header{}
	h.Set("Content-Disposition", `inline; filename="Breaking.Bad.S05E14.2160p.mkv"`)
	tr.ObserveStreamResponseHeaders(metaStream, h)

	snaps = tr.Snapshot()
	var foundFallback *playbackSessionSnapshot
	for i := range snaps {
		if snaps[i].ItemID == "55555" {
			foundFallback = &snaps[i]
		}
	}
	if foundFallback == nil || foundFallback.SeriesName != "Breaking Bad" || foundFallback.SeasonNumber != 5 || foundFallback.EpisodeNumber != 14 || foundFallback.VideoQuality != "4K" {
		t.Fatalf("expected filename fallback parsed cleanly, got %+v", foundFallback)
	}
}

func TestPlaybackClusterEndToEndControllerAggregation(t *testing.T) {
	streamRelease := make(chan struct{})
	defer close(streamRelease)

	// Mock Emby upstream server serving Auth, Item detail, PlaybackInfo, Progress, and an active video stream
	embyUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/Users/AuthenticateByName"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"AccessToken":"tok-cluster-1","User":{"Id":"user-42","Name":"Bob"}}`))
		case strings.HasSuffix(r.URL.Path, "/Users/user-42/Items/7001"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"7001","Name":"古筝行动","Type":"Episode","SeriesName":"三体","ParentIndexNumber":1,"IndexNumber":29,"ProductionYear":2023,"RunTimeTicks":27000000000}`))
		case strings.HasSuffix(r.URL.Path, "/Items/7001/PlaybackInfo"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"PlaySessionId":"ps-7001","MediaSources":[{"Id":"ms-7001","Name":"Three.Body.S01E29.2160p.mkv","Container":"mkv","MediaStreams":[{"Type":"Video","Width":3840,"Height":2160,"Codec":"hevc","VideoRangeType":"DOVI"}]}]}`))
		case strings.HasSuffix(r.URL.Path, "/Sessions/Playing/Progress"):
			_, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusNoContent)
		case strings.Contains(r.URL.Path, "/Videos/7001/stream"):
			w.Header().Set("Content-Type", "video/x-matroska")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("A"), 64*1024))
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			select {
			case <-streamRelease:
			case <-r.Context().Done():
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer embyUpstream.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Enable unsigned generic reverse proxy targets
	rtReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/runtime-config", map[string]any{
		"default_upstream":                "",
		"allowed_upstreams":               "",
		"allow_unsigned_targets":          true,
		"pass_client_ip":                  false,
		"disable_cache":                   true,
		"rewrite_max_bytes":               4 * 1024 * 1024,
		"dns_cache_ttl_seconds":           30,
		"dial_timeout_seconds":            10,
		"response_header_timeout_seconds": 30,
		"max_concurrent_requests":         128,
		"max_concurrent_per_ip":           32,
		"max_download_mbps_per_ip":        0,
		"upstream_ip_mode":                "auto",
	})
	rtResp, err := adminClient.Do(rtReq)
	if err != nil || rtResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT runtime-config failed: %v", err)
	}
	rtResp.Body.Close()

	// Create & enroll an Agent with public_url so generic reverse proxy accepts requests
	nReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
		"name": "东京 9929", "group_name": "亚太", "region": "Tokyo", "public_url": "https://jp.proxy.test",
	})
	nResp, err := adminClient.Do(nReq)
	if err != nil || nResp.StatusCode != http.StatusCreated {
		t.Fatalf("create node failed: %v", err)
	}
	var nodeOut struct {
		Node   edgeNodeView `json:"node"`
		Deploy struct {
			EnrollToken string `json:"enroll_token"`
		} `json:"deploy"`
	}
	_ = json.NewDecoder(nResp.Body).Decode(&nodeOut)
	nResp.Body.Close()

	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = nodeOut.Deploy.EnrollToken
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-pb-state.json")

	agentGW, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("create agent failed: %v", err)
	}
	defer agentGW.Close()
	agentSrv := httptest.NewServer(agentGW)
	defer agentSrv.Close()

	// Wait for agent to enroll and sync config
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if agentGW.liveRuntime().AllowUnsigned {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !agentGW.liveRuntime().AllowUnsigned {
		t.Fatalf("agent did not sync AllowUnsigned runtime config")
	}

	// Simulate an Emby client (Infuse) using generic URL reverse proxy format through the Agent!
	authHdr := `MediaBrowser Client="Infuse", Device="客厅 Apple TV", DeviceId="atv-77", Version="8.0", Token="tok-cluster-1"`
	doProxy := func(method, subPath string, body string) {
		req, _ := http.NewRequest(method, agentSrv.URL+"/"+embyUpstream.URL+subPath, strings.NewReader(body))
		req.Header.Set("X-Emby-Authorization", authHdr)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("proxy %s %s failed: %v", method, subPath, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			t.Fatalf("proxy %s %s returned status=%d body=%s", method, subPath, resp.StatusCode, string(raw))
		}
	}

	doProxy(http.MethodPost, "/emby/Users/AuthenticateByName", `{"Username":"Bob"}`)
	doProxy(http.MethodGet, "/emby/Users/user-42/Items/7001", "")
	doProxy(http.MethodPost, "/emby/Items/7001/PlaybackInfo", `{}`)
	doProxy(http.MethodPost, "/emby/Sessions/Playing/Progress", `{"ItemId":"7001","PositionTicks":9000000000,"IsPaused":false,"PlayMethod":"DirectPlay"}`)

	// Start an active video stream in the background
	streamCtx, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	streamStarted := make(chan struct{})
	go func() {
		req, _ := http.NewRequestWithContext(streamCtx, http.MethodGet, agentSrv.URL+"/"+embyUpstream.URL+"/emby/Videos/7001/stream.mkv", nil)
		req.Header.Set("X-Emby-Authorization", authHdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		_, _ = resp.Body.Read(buf)
		close(streamStarted)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	select {
	case <-streamStarted:
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for active stream to start")
	}

	// Trigger immediate heartbeat from agent so controller sees live playback immediately
	if err := agentGW.agent.sendHeartbeat(context.Background()); err != nil {
		t.Fatalf("agent sendHeartbeat failed: %v", err)
	}

	// Query Controller's /_admin/api/playbacks
	pbResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/playbacks")
	if err != nil || pbResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_admin/api/playbacks failed: %v", err)
	}
	var pbOut struct {
		Summary playbackSummary           `json:"summary"`
		Active  []playbackSessionSnapshot `json:"active"`
		History []watchHistoryRecord      `json:"history"`
	}
	_ = json.NewDecoder(pbResp.Body).Decode(&pbOut)
	pbResp.Body.Close()

	if pbOut.Summary.WatchingCount != 1 || len(pbOut.Active) != 1 {
		t.Fatalf("expected 1 active watching session on controller, got summary=%+v active=%+v", pbOut.Summary, pbOut.Active)
	}
	s := pbOut.Active[0]
	if s.UserName != "Bob" || s.SeriesName != "三体" || s.SeasonNumber != 1 || s.EpisodeNumber != 29 || s.VideoQuality != "4K HEVC DV" || s.NodeName != "东京 9929" || s.FlowID == "" {
		t.Fatalf("unexpected controller aggregated playback session: %+v", s)
	}
	if len(pbOut.History) == 0 || pbOut.History[0].SeriesName != "三体" {
		t.Fatalf("expected watch history persisted on controller, got %+v", pbOut.History)
	}

	// Verify /_admin/api/live reports watching_count == 1
	liveResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/live")
	if err != nil || liveResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_admin/api/live failed: %v", err)
	}
	var liveOut liveSnapshot
	_ = json.NewDecoder(liveResp.Body).Decode(&liveOut)
	liveResp.Body.Close()
	if liveOut.WatchingCount != 1 {
		t.Fatalf("expected watching_count=1 in /_admin/api/live, got %d", liveOut.WatchingCount)
	}

	// Verify /_admin/api/connections carries MediaTitle on the active stream
	connResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/connections")
	if err != nil || connResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_admin/api/connections failed: %v", err)
	}
	var connOut struct {
		Connections []connectionSnapshot `json:"connections"`
	}
	_ = json.NewDecoder(connResp.Body).Decode(&connOut)
	connResp.Body.Close()
	foundMediaConn := false
	for _, c := range connOut.Connections {
		if c.MediaTitle == "三体" {
			foundMediaConn = true
		}
	}
	if !foundMediaConn {
		t.Fatalf("expected active connection to include media_title=三体, got %+v", connOut.Connections)
	}
}

func TestPlaybackTerminateCancelsAllFlowsAndBlocksReconnect(t *testing.T) {
	startedCh := make(chan struct{}, 4)
	canceledCount := 0
	var cancelMu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/System/Info" {
			_, _ = w.Write([]byte(`{"ServerName":"Demo"}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/Videos/777/stream") {
			w.Header().Set("Content-Type", "video/mp4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("chunk1"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case startedCh <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			cancelMu.Lock()
			canceledCount++
			cancelMu.Unlock()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Enable unlimited unsigned proxy + PassClientIP on controller
	rtReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/runtime-config", map[string]any{
		"allow_unsigned_targets":          true,
		"pass_client_ip":                  false,
		"rewrite_max_bytes":               1 << 20,
		"dns_cache_ttl_seconds":           60,
		"dial_timeout_seconds":            5,
		"response_header_timeout_seconds": 30,
		"max_concurrent_requests":         64,
		"max_concurrent_per_ip":           32,
		"max_download_mbps_per_ip":        0,
		"upstream_ip_mode":                "auto",
	})
	rtRes, err := adminClient.Do(rtReq)
	if err != nil || rtRes.StatusCode != http.StatusOK {
		t.Fatalf("runtime setup failed: err=%v res=%v", err, rtRes)
	}
	rtRes.Body.Close()

	nReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
		"name": "Kick Edge", "group_name": "测试", "region": "HK", "public_url": "https://kick.proxy.test",
	})
	nRes, err := adminClient.Do(nReq)
	if err != nil || nRes.StatusCode != http.StatusCreated {
		t.Fatalf("create node failed: err=%v res=%v", err, nRes)
	}
	var nodeOut struct {
		Node   edgeNodeView `json:"node"`
		Deploy struct {
			EnrollToken string `json:"enroll_token"`
		} `json:"deploy"`
	}
	_ = json.NewDecoder(nRes.Body).Decode(&nodeOut)
	nRes.Body.Close()

	cfg := testConfig()
	cfg.Role = RoleAgent
	cfg.AdminEnabled = false
	cfg.AllowPrivateTargets = true
	cfg.AgentControllerURL = ctrlSrv.URL
	cfg.AgentEnrollToken = nodeOut.Deploy.EnrollToken
	cfg.AgentStatePath = filepath.Join(t.TempDir(), "kick-agent.json")
	cfg.AgentHeartbeatInterval = 150 * time.Millisecond
	cfg.AgentTelemetryInterval = time.Second
	agent := New(cfg)
	agent.agent.skipIPDetect.Store(true)
	t.Cleanup(agent.Close)

	if err := agent.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("agent syncConfig: %v", err)
	}
	if !agent.liveRuntime().AllowUnsigned {
		t.Fatalf("expected agent AllowUnsigned synced to true")
	}

	agentSrv := httptest.NewServer(agent)
	defer agentSrv.Close()

	// Open TWO concurrent stream requests for the same viewer + item 777
	streamErrCh := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, agentSrv.URL+"/"+upstream.URL+"/Videos/777/stream.mp4?DeviceId=dev-kick-1", nil)
			req.Header.Set("User-Agent", "SenPlayer/5.2")
			if idx == 1 {
				// Simulate a second concurrent stream request without DeviceId fallback key
				req.URL.RawQuery = "MediaSourceId=ms1"
			}
			resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
			if err != nil {
				streamErrCh <- err
				return
			}
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			streamErrCh <- err
		}(i)
	}

	for i := 0; i < 2; i++ {
		select {
		case <-startedCh:
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for concurrent streams to reach upstream")
		}
	}

	// Wait until Controller /_admin/api/playbacks shows the active session
	var targetSession playbackSessionSnapshot
	deadline := time.Now().Add(4 * time.Second)
	for {
		pbResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/playbacks")
		if err == nil && pbResp.StatusCode == http.StatusOK {
			var pbOut struct {
				Active []playbackSessionSnapshot `json:"active"`
			}
			_ = json.NewDecoder(pbResp.Body).Decode(&pbOut)
			pbResp.Body.Close()
			if len(pbOut.Active) > 0 {
				targetSession = pbOut.Active[0]
				break
			}
		} else if pbResp != nil {
			pbResp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for active playback session on controller")
		}
		time.Sleep(60 * time.Millisecond)
	}

	// Terminate playback session via POST /_admin/api/playbacks/terminate
	termReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/playbacks/terminate", map[string]any{
		"session_key": targetSession.SessionKey,
		"node_id":     targetSession.NodeID,
		"flow_id":     targetSession.FlowID,
	})
	termRes, err := adminClient.Do(termReq)
	if err != nil || termRes.StatusCode != http.StatusOK {
		t.Fatalf("terminate playback failed: err=%v res=%v", err, termRes)
	}
	termRes.Body.Close()

	// 1. Immediate /_admin/api/playbacks check MUST return 0 active sessions (tombstone prevents flicker)
	afterPBResp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/playbacks")
	if err != nil || afterPBResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_admin/api/playbacks after terminate: %v", err)
	}
	var afterPB struct {
		Active []playbackSessionSnapshot `json:"active"`
	}
	_ = json.NewDecoder(afterPBResp.Body).Decode(&afterPB)
	afterPBResp.Body.Close()
	if len(afterPB.Active) != 0 {
		t.Fatalf("expected 0 active playback sessions immediately after terminate, got %+v", afterPB.Active)
	}

	// 2. Wait for BOTH concurrent streams to be canceled promptly
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("expected BOTH concurrent playback streams to terminate promptly")
	}

	// 3. Reconnect retry to /Videos/777/stream from same viewer MUST be blocked with 403 Forbidden
	retryRec := httptest.NewRecorder()
	retryReq := httptest.NewRequest(http.MethodGet, "https://kick.proxy.test/"+upstream.URL+"/Videos/777/stream.mp4?DeviceId=dev-kick-1", nil)
	retryReq.Header.Set("User-Agent", "SenPlayer/5.2")
	retryReq.RemoteAddr = "127.0.0.1:45678"
	agent.ServeHTTP(retryRec, retryReq)
	if retryRec.Code != http.StatusForbidden || !strings.Contains(retryRec.Body.String(), "playback session terminated by administrator") {
		t.Fatalf("expected 403 playback terminated on reconnect attempt, got %d body=%s", retryRec.Code, retryRec.Body.String())
	}

	// 4. Normal Emby UI browsing (/System/Info) remains allowed (200 OK)
	browseRec := httptest.NewRecorder()
	browseReq := httptest.NewRequest(http.MethodGet, "https://kick.proxy.test/"+upstream.URL+"/System/Info", nil)
	browseReq.Header.Set("User-Agent", "SenPlayer/5.2")
	browseReq.RemoteAddr = "127.0.0.1:45678"
	agent.ServeHTTP(browseRec, browseReq)
	if browseRec.Code != http.StatusOK {
		t.Fatalf("expected normal /System/Info browse 200 after playback kick, got %d body=%s", browseRec.Code, browseRec.Body.String())
	}
}

func TestPlaybackCoalescesGenericStreamWithDeviceReport(t *testing.T) {
	tr := newPlaybackTracker()
	conns := newConnectionTracker()
	defer conns.Close()

	// Order A: stream without DeviceId arrives first, then POST /Sessions/Playing with DeviceId arrives.
	streamFlow := conns.StartForIdentity(func() {}, "198.51.100.25", http.MethodGet, "emby-a.example.test", "emby-a.example.test", "/videos/1612584/original.mp4", "stream", "SenPlayer/5.2", "", "SenPlayer")
	streamMeta := playbackRequestMeta{
		ClientIP:     "198.51.100.25",
		ClientName:   "SenPlayer",
		UpstreamHost: "emby-a.example.test",
		Path:         "/videos/1612584/original.mp4",
		Flow:         streamFlow,
	}
	itemID, _, _ := tr.ObserveStreamStart(streamMeta)
	if itemID != "1612584" {
		t.Fatalf("expected itemID 1612584, got %q", itemID)
	}
	streamFlow.AddDownload(4096)

	reportMeta := playbackRequestMeta{
		ClientIP:     "198.51.100.25",
		DeviceID:     "DEV-MAC-1",
		DeviceName:   "Mac",
		ClientName:   "SenPlayer",
		UpstreamHost: "emby-a.example.test",
		Path:         "/emby/Sessions/Playing",
	}
	reportBody := []byte(`{"ItemId":"1612584","PositionTicks":1060000000,"PlayMethod":"DirectStream","Item":{"Id":"1612584","Name":"Ep1","Type":"Episode","SeriesName":"TestSeries","ParentIndexNumber":1,"IndexNumber":1,"RunTimeTicks":13160000000}}`)
	tr.ObservePlayingReport(reportMeta, reportBody)

	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 coalesced session, got %d: %+v", len(snap), snap)
	}
	if snap[0].DeviceID != "DEV-MAC-1" || snap[0].BytesOut != 4096 || snap[0].ActiveStreams != 1 {
		t.Fatalf("unexpected coalesced snapshot: %+v", snap[0])
	}

	// Second distinct device behind the same IP remains separate (2 sessions total).
	reportMeta2 := playbackRequestMeta{
		ClientIP:     "198.51.100.25",
		DeviceID:     "DEV-IPHONE-2",
		DeviceName:   "iPhone",
		ClientName:   "SenPlayer",
		UpstreamHost: "emby-a.example.test",
		Path:         "/emby/Sessions/Playing",
	}
	tr.ObservePlayingReport(reportMeta2, reportBody)
	snap = tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 distinct sessions for different DeviceIDs, got %d", len(snap))
	}

	// Order B: DeviceId session exists first, then stream without DeviceId arrives.
	streamFlow2 := conns.StartForIdentity(func() {}, "10.0.0.5", http.MethodGet, "other.emby.test", "other.emby.test", "/emos/emby/videos/999/stream.mp4", "stream", "Infuse", "", "Infuse")
	tr.ObservePlayingReport(playbackRequestMeta{
		ClientIP:     "10.0.0.5",
		DeviceID:     "INFUSE-TV",
		DeviceName:   "AppleTV",
		ClientName:   "Infuse",
		UpstreamHost: "other.emby.test",
		Path:         "/emby/Sessions/Playing",
	}, []byte(`{"ItemId":"999","PositionTicks":50000000,"Item":{"Id":"999","Name":"Movie","Type":"Movie"}}`))
	tr.ObserveStreamStart(playbackRequestMeta{
		ClientIP:     "10.0.0.5",
		ClientName:   "",
		UpstreamHost: "other.emby.test",
		Path:         "/emos/emby/videos/999/stream.mp4",
		Flow:         streamFlow2,
	})
	streamFlow2.AddDownload(2048)
	tr.ObserveStreamEnd(playbackRequestMeta{Flow: streamFlow2}, 2048)
	snap = tr.Snapshot()
	var found999 *playbackSessionSnapshot
	for i := range snap {
		if snap[i].ItemID == "999" {
			found999 = &snap[i]
		}
	}
	if found999 == nil || found999.BytesOut != 2048 {
		t.Fatalf("expected session 999 coalesced and credited 2048 bytes, got %+v", found999)
	}

	// UpsertWatchHistory merges and deletes stale |generic| twin row.
	store, err := openTelemetryStore(":memory:", "admin", "hash")
	if err != nil {
		t.Fatalf("openTelemetryStore: %v", err)
	}
	defer store.Close()
	now := time.Now().Unix()
	_ = store.UpsertWatchHistory(context.Background(), []playbackSessionSnapshot{
		{
			SessionKey:   "nd_1|198.51.100.25|generic|emby-a.example.test|1612584",
			NodeID:       "nd_1",
			ClientIP:     "198.51.100.25",
			UpstreamHost: "emby-a.example.test",
			ItemID:       "1612584",
			Title:        "Ep1",
			BytesOut:     8192,
			StartedAt:    now - 100,
			LastSeenAt:   now - 50,
		},
	})
	_ = store.UpsertWatchHistory(context.Background(), []playbackSessionSnapshot{
		{
			SessionKey:   "nd_1|198.51.100.25|DEV-MAC-1|emby-a.example.test|1612584",
			NodeID:       "nd_1",
			ClientIP:     "198.51.100.25",
			ClientName:   "SenPlayer",
			UpstreamHost: "emby-a.example.test",
			ItemID:       "1612584",
			Title:        "Ep1",
			BytesOut:     4096,
			StartedAt:    now - 40,
			LastSeenAt:   now,
		},
	})
	hist, _, err := store.ListWatchHistory(context.Background(), "nd_1", 20)
	if err != nil || len(hist) != 1 || hist[0].BytesOut != 8192 || hist[0].StartedAt != now-100 {
		t.Fatalf("expected merged single watch_history row preserving 8192 bytes and earlier started_at, got %+v err=%v", hist, err)
	}
}

func TestPlaybackTracks302RedirectedStreamAndTerminatesIt(t *testing.T) {
	startedCh := make(chan struct{}, 2)
	canceledCh := make(chan struct{}, 2)

	var edgeSrv *httptest.Server
	edgeSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/serve" && r.URL.Query().Get("token") == "tok123" {
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Disposition", `attachment; filename="DongDaGaoWu.S01E01.2160p.mp4"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, 32*1024))
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			startedCh <- struct{}{}
			<-r.Context().Done()
			canceledCh <- struct{}{}
			return
		}
		http.NotFound(w, r)
	}))
	defer edgeSrv.Close()

	var embyOrigin *httptest.Server
	embyOrigin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/videos/1612584/original.mp4":
			http.Redirect(w, r, edgeSrv.URL+"/storage/serve?token=tok123", http.StatusFound)
		case r.URL.Path == "/emby/Sessions/Playing":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/System/Info":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ServerName":"ExampleEmby"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer embyOrigin.Close()

	embyURL, _ := url.Parse(embyOrigin.URL)

	ctrlSrv, adminClient := newTestClusterController(t, RoleController)

	// Configure runtime and create Edge node
	rtReq := mustAdminJSONRequest(t, http.MethodPut, ctrlSrv.URL+"/_admin/api/runtime-config", map[string]any{
		"allow_unsigned_targets":          true,
		"pass_client_ip":                  false,
		"rewrite_max_bytes":               1 << 20,
		"dns_cache_ttl_seconds":           60,
		"dial_timeout_seconds":            5,
		"response_header_timeout_seconds": 30,
		"max_concurrent_requests":         64,
		"max_concurrent_per_ip":           32,
		"max_download_mbps_per_ip":        0,
		"upstream_ip_mode":                "auto",
	})
	rtRes, err := adminClient.Do(rtReq)
	if err != nil || rtRes.StatusCode != http.StatusOK {
		t.Fatalf("runtime setup failed: err=%v res=%v", err, rtRes)
	}
	rtRes.Body.Close()

	nReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/nodes", map[string]any{
		"name": "Edge-Redirect", "group_name": "测试", "region": "HK", "public_url": "https://redir.proxy.test",
	})
	nRes, err := adminClient.Do(nReq)
	if err != nil || nRes.StatusCode != http.StatusCreated {
		t.Fatalf("create node failed: err=%v res=%v", err, nRes)
	}
	var nodeOut struct {
		Node   edgeNodeView `json:"node"`
		Deploy struct {
			EnrollToken string `json:"enroll_token"`
		} `json:"deploy"`
	}
	_ = json.NewDecoder(nRes.Body).Decode(&nodeOut)
	nRes.Body.Close()

	agentCfg := testConfig()
	agentCfg.Role = RoleAgent
	agentCfg.AdminEnabled = false
	agentCfg.AllowPrivateTargets = true
	agentCfg.AgentControllerURL = ctrlSrv.URL
	agentCfg.AgentEnrollToken = nodeOut.Deploy.EnrollToken
	agentCfg.AgentStatePath = filepath.Join(t.TempDir(), "agent-state.json")
	agentCfg.AgentHeartbeatInterval = 150 * time.Millisecond
	agentCfg.AgentTelemetryInterval = time.Second
	agentGW, err := NewChecked(agentCfg)
	if err != nil {
		t.Fatalf("NewChecked agent: %v", err)
	}
	agentGW.agent.skipIPDetect.Store(true)
	t.Cleanup(agentGW.Close)

	if err := agentGW.agent.syncConfig(context.Background()); err != nil {
		t.Fatalf("syncConfig failed: %v", err)
	}

	// 1. Player requests /videos/1612584/original.mp4 (without DeviceId) -> gets rewritten 302 Location
	redirRec := httptest.NewRecorder()
	redirReq := httptest.NewRequest(http.MethodGet, "https://redir.proxy.test/"+embyOrigin.URL+"/videos/1612584/original.mp4", nil)
	redirReq.Header.Set("User-Agent", "SenPlayer/5.2")
	redirReq.RemoteAddr = "198.51.100.25:50001"
	agentGW.ServeHTTP(redirRec, redirReq)
	if redirRec.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d body=%s", redirRec.Code, redirRec.Body.String())
	}
	loc := redirRec.Header().Get("Location")
	if !strings.Contains(loc, "/storage/serve") {
		t.Fatalf("expected rewritten Location containing /storage/serve, got %q", loc)
	}

	// 2. Player UI posts /emby/Sessions/Playing with DeviceId
	playBody := `{"ItemId":"1612584","PositionTicks":10000000,"PlayMethod":"DirectStream","Item":{"Id":"1612584","Name":"绝境觉醒","Type":"Episode","SeriesName":"东大高武学院","ParentIndexNumber":1,"IndexNumber":1}}`
	playRec := httptest.NewRecorder()
	playReq := httptest.NewRequest(http.MethodPost, "https://redir.proxy.test/"+embyOrigin.URL+"/emby/Sessions/Playing?DeviceId=DEV-REDIR-1", strings.NewReader(playBody))
	playReq.Header.Set("User-Agent", "SenPlayer/5.2")
	playReq.RemoteAddr = "198.51.100.25:50002"
	agentGW.ServeHTTP(playRec, playReq)
	if playRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on Playing report, got %d", playRec.Code)
	}

	// 3. Player follows the rewritten 302 Location to /storage/serve (without DeviceId)
	agentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "198.51.100.25:50003"
		agentGW.ServeHTTP(w, r)
	}))
	defer agentSrv.Close()

	locParsed, _ := url.Parse(loc)
	streamClientURL := agentSrv.URL + locParsed.RequestURI()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest(http.MethodGet, streamClientURL, nil)
		req.Header.Set("User-Agent", "SenPlayer/5.2")
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	select {
	case <-startedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for redirected /storage/serve stream")
	}

	// 4. Verify Controller /_admin/api/playbacks shows ONE coalesced session with real BytesOut > 0 and FlowID != ""
	var activeSess playbackSessionSnapshot
	deadline := time.Now().Add(4 * time.Second)
	for {
		resp, err := adminClient.Get(ctrlSrv.URL + "/_admin/api/playbacks")
		if err == nil && resp.StatusCode == http.StatusOK {
			var pbOut struct {
				Active []playbackSessionSnapshot `json:"active"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&pbOut)
			resp.Body.Close()
			if len(pbOut.Active) == 1 && pbOut.Active[0].BytesOut >= 32*1024 && pbOut.Active[0].FlowID != "" {
				activeSess = pbOut.Active[0]
				break
			}
		} else if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for single coalesced 302-redirected session with bytes_out>0")
		}
		time.Sleep(60 * time.Millisecond)
	}
	if activeSess.UpstreamHost != embyURL.Host {
		t.Fatalf("expected upstream_host attributed to Emby %q, got %q", embyURL.Host, activeSess.UpstreamHost)
	}

	// 5. Terminate via POST /_admin/api/playbacks/terminate and assert /storage/serve cancels + reconnect 403
	termReq := mustAdminJSONRequest(t, http.MethodPost, ctrlSrv.URL+"/_admin/api/playbacks/terminate", map[string]any{
		"session_key": activeSess.SessionKey,
		"node_id":     activeSess.NodeID,
		"flow_id":     activeSess.FlowID,
	})
	termRes, err := adminClient.Do(termReq)
	if err != nil || termRes.StatusCode != http.StatusOK {
		t.Fatalf("terminate failed: err=%v res=%v", err, termRes)
	}
	termRes.Body.Close()

	select {
	case <-canceledCh:
	case <-time.After(3 * time.Second):
		t.Fatal("expected redirected /storage/serve stream to be canceled")
	}
	wg.Wait()

	retryReq, _ := http.NewRequest(http.MethodGet, streamClientURL, nil)
	retryReq.Header.Set("User-Agent", "SenPlayer/5.2")
	retryRes, err := http.DefaultClient.Do(retryReq)
	if err != nil {
		t.Fatalf("reconnect request err: %v", err)
	}
	retryBody, _ := io.ReadAll(retryRes.Body)
	retryRes.Body.Close()
	if retryRes.StatusCode != http.StatusForbidden || !strings.Contains(string(retryBody), "playback session terminated by administrator") {
		t.Fatalf("expected 403 on redirected /storage/serve reconnect, got %d body=%s", retryRes.StatusCode, string(retryBody))
	}
}

func TestPlaybackMultiVersionDirectStreamURLCoalescing(t *testing.T) {
	tr := newPlaybackTracker()
	conns := newConnectionTracker()
	defer conns.Close()

	host := "emby-b.example.test"
	baseMeta := playbackRequestMeta{
		ClientIP:     "198.51.100.25",
		DeviceID:     "DEV-MAC-MV",
		DeviceName:   "Mac",
		ClientName:   "SenPlayer",
		UpstreamHost: host,
	}

	// 1. /Shows/{id}/Episodes populates item metadata + MediaSources mapping
	epMeta := baseMeta
	epMeta.Path = "/emby/Shows/agg-2948493-l2/Episodes"
	tr.ObserveJSONResponse(epMeta, map[string]any{
		"Items": []any{
			map[string]any{
				"Id":                "ep-78925497",
				"Name":              "线下见面",
				"Type":              "Episode",
				"SeriesName":        "成也萧河",
				"ParentIndexNumber": 1,
				"IndexNumber":       9,
				"ProductionYear":    2026,
				"RunTimeTicks":      12600000000,
			},
		},
	})

	// 2. /Items/ep-78925497/PlaybackInfo returns a relative DirectStreamUrl using ep-78925498
	pbMeta := baseMeta
	pbMeta.Path = "/emby/Items/ep-78925497/PlaybackInfo"
	tr.ObserveJSONResponse(pbMeta, map[string]any{
		"PlaySessionId": "ps-1",
		"MediaSources": []any{
			map[string]any{
				"Id":              "ms-1",
				"ItemId":          "ep-78925498",
				"Name":            "1080p",
				"DirectStreamUrl": "/emby/videos/ep-78925498/stream.mp4?MediaSourceId=ms-1&PlaySessionId=ps-1",
				"MediaStreams": []any{
					map[string]any{"Type": "Video", "Width": 1920, "Height": 1080, "Codec": "h264"},
				},
			},
		},
	})

	// 3. Player fetches the stream on alias ID ep-78925498
	canceled := false
	streamFlow := conns.StartForIdentity(func() { canceled = true }, "198.51.100.25", http.MethodGet, host, host, "/emby/emby/videos/ep-78925498/stream.mp4", "stream", "SenPlayer/5.2", "DEV-MAC-MV", "SenPlayer")
	streamMeta := baseMeta
	streamMeta.Path = "/emby/emby/videos/ep-78925498/stream.mp4"
	streamMeta.RawQuery = "MediaSourceId=ms-1&PlaySessionId=ps-1"
	streamMeta.Flow = streamFlow
	streamItemID, _, _ := tr.ObserveStreamStart(streamMeta)
	if streamItemID != "ep-78925497" {
		t.Fatalf("expected alias stream ep-78925498 to resolve to ep-78925497, got %q", streamItemID)
	}
	streamFlow.AddDownload(65536)

	// 4. Player posts /Sessions/Playing/Progress for ep-78925497
	progMeta := baseMeta
	progMeta.Path = "/emby/Sessions/Playing/Progress"
	tr.ObservePlayingReport(progMeta, []byte(`{"ItemId":"ep-78925497","MediaSourceId":"ms-1","PlaySessionId":"ps-1","PositionTicks":2230000000,"PlayMethod":"DirectStream"}`))

	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 coalesced session for multi-version stream, got %d: %+v", len(snap), snap)
	}
	if snap[0].ItemID != "ep-78925497" || snap[0].SeriesName != "成也萧河" || snap[0].Title != "线下见面" || snap[0].BytesOut != 65536 || snap[0].ActiveStreams != 1 {
		t.Fatalf("unexpected coalesced multi-version snapshot: %+v", snap[0])
	}

	// 5. Terminating the canonical session cancels the ep-78925498 flow and blocks reconnects on ep-78925498
	nCanceled, _, _, _ := tr.TerminateSession(snap[0].SessionKey, 30*time.Second)
	if nCanceled != 1 || !canceled {
		t.Fatalf("expected TerminateSession to cancel alias stream flow (n=%d, canceled=%v)", nCanceled, canceled)
	}
	if !tr.IsRequestBlocked("198.51.100.25", host, "/emby/emby/videos/ep-78925498/stream.mp4", "", "DEV-MAC-MV", "SenPlayer", time.Now()) {
		t.Fatal("expected alias stream path /emby/emby/videos/ep-78925498/stream.mp4 to be blocked after TerminateSession")
	}
}

func TestPlaybackPlayingReportMergesEarlierUnresolvedAliasStream(t *testing.T) {
	tr := newPlaybackTracker()
	conns := newConnectionTracker()
	defer conns.Close()

	host := "emby-b.example.test"
	baseMeta := playbackRequestMeta{
		ClientIP:     "198.51.100.25",
		DeviceID:     "DEV-MAC-1",
		DeviceName:   "Mac",
		ClientName:   "SenPlayer",
		UpstreamHost: host,
	}

	// 1. Cold-start stream arrives without PlaybackInfo or query IDs -> creates 媒体 #ep-78925498
	f1 := conns.StartForIdentity(func() {}, "198.51.100.25", http.MethodGet, host, host, "/emby/emby/videos/ep-78925498/stream.mp4", "stream", "SenPlayer", "DEV-MAC-1", "SenPlayer")
	sMeta := baseMeta
	sMeta.Path = "/emby/emby/videos/ep-78925498/stream.mp4"
	sMeta.Flow = f1
	tr.ObserveStreamStart(sMeta)
	f1.AddDownload(102400)

	// 2. Playing report arrives for canonical ep-78925497 on the same DeviceID
	pMeta := baseMeta
	pMeta.Path = "/emby/Sessions/Playing"
	tr.ObservePlayingReport(pMeta, []byte(`{"ItemId":"ep-78925497","PositionTicks":10000000,"PlayMethod":"DirectStream","Item":{"Id":"ep-78925497","Name":"线下见面","Type":"Episode","SeriesName":"成也萧河","ParentIndexNumber":1,"IndexNumber":9}}`))

	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 merged session, got %d: %+v", len(snap), snap)
	}
	if snap[0].ItemID != "ep-78925497" || snap[0].BytesOut != 102400 || snap[0].ActiveStreams != 1 || snap[0].SeriesName != "成也萧河" {
		t.Fatalf("expected ep-78925497 to inherit alias stream bytes & flow, got %+v", snap[0])
	}

	// Subsequent request on ep-78925499 with cached metadata remains separate (2 sessions total).
	ep99Meta := baseMeta
	ep99Meta.Path = "/emby/Users/u1/Items/ep-78925499"
	tr.ObserveJSONResponse(ep99Meta, map[string]any{
		"Id": "ep-78925499", "Name": "第十集", "Type": "Episode", "SeriesName": "成也萧河", "ParentIndexNumber": 1, "IndexNumber": 10,
	})
	f3 := conns.StartForIdentity(func() {}, "198.51.100.25", http.MethodGet, host, host, "/emby/videos/ep-78925499/stream.mp4", "stream", "SenPlayer", "DEV-MAC-1", "SenPlayer")
	sMeta3 := baseMeta
	sMeta3.Path = "/emby/videos/ep-78925499/stream.mp4"
	sMeta3.Flow = f3
	tr.ObserveStreamStart(sMeta3)
	snap = tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected known distinct episode ep-78925499 to remain separate session, got %d: %+v", len(snap), snap)
	}
}

func TestUpsertWatchHistoryMergesPlaceholderAliasTwin(t *testing.T) {
	store, err := openTelemetryStore(":memory:", "admin", "hash")
	if err != nil {
		t.Fatalf("openTelemetryStore: %v", err)
	}
	defer store.Close()

	now := time.Now().Unix()
	_ = store.UpsertWatchHistory(context.Background(), []playbackSessionSnapshot{
		{
			SessionKey:   "nd_1|198.51.100.25|DEV-MAC-1|emby-b.example.test|ep-78925498",
			NodeID:       "nd_1",
			ClientIP:     "198.51.100.25",
			ClientName:   "SenPlayer",
			UpstreamHost: "emby-b.example.test",
			ItemID:       "ep-78925498",
			Title:        "媒体 #ep-78925498",
			BytesOut:     551791839,
			StartedAt:    now - 40,
			LastSeenAt:   now - 5,
		},
	})
	_ = store.UpsertWatchHistory(context.Background(), []playbackSessionSnapshot{
		{
			SessionKey:   "nd_1|198.51.100.25|DEV-MAC-1|emby-b.example.test|ep-78925497",
			NodeID:       "nd_1",
			ClientIP:     "198.51.100.25",
			ClientName:   "SenPlayer",
			UpstreamHost: "emby-b.example.test",
			ItemID:       "ep-78925497",
			MediaType:    "Episode",
			SeriesName:   "成也萧河",
			Title:        "线下见面",
			BytesOut:     0,
			StartedAt:    now - 34,
			LastSeenAt:   now,
		},
	})

	hist, _, err := store.ListWatchHistory(context.Background(), "nd_1", 20)
	if err != nil {
		t.Fatalf("ListWatchHistory: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("expected 1 merged watch_history row, got %d: %+v", len(hist), hist)
	}
	if hist[0].ItemID != "ep-78925497" || hist[0].BytesOut != 551791839 || hist[0].StartedAt != now-40 {
		t.Fatalf("expected ep-78925497 to inherit 551791839 bytes and earlier started_at, got %+v", hist[0])
	}
}

func TestEmbyNonStreamSubpathsIgnored(t *testing.T) {
	tr := newPlaybackTracker()
	nonStreamPaths := []string{
		"/emby/Videos/1015500/AdditionalParts",
		"/emby/Videos/1015500/Subtitles/0/Stream.srt",
		"/emby/Videos/1015500/Trickplay/320/0.jpg",
	}
	for _, p := range nonStreamPaths {
		itemID, isStream, _ := extractEmbyItemIDFromPath(p)
		if isStream || itemID != "" {
			t.Fatalf("expected non-stream path %q to be ignored, got itemID=%q isStream=%v", p, itemID, isStream)
		}
		gotID, needLookup, blocked := tr.ObserveStreamStart(playbackRequestMeta{
			ClientIP:     "198.51.100.25",
			DeviceID:     "dev-subpath",
			DeviceName:   "Desktop",
			ClientName:   "RodelPlayer",
			UpstreamHost: "emby-a.example.test",
			Path:         p,
			Token:        "tok-1",
		})
		if blocked || needLookup || gotID != "" {
			t.Fatalf("ObserveStreamStart(%q) unexpectedly matched item=%q lookup=%v blocked=%v", p, gotID, needLookup, blocked)
		}
	}
	if snaps := tr.Snapshot(); len(snaps) != 0 {
		t.Fatalf("expected 0 playback sessions for non-stream subpaths, got %d: %+v", len(snaps), snaps)
	}
}

func TestPlayingReport401DoesNotPoisonTracker(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer upstream.Close()

	cfg := testConfig()
	cfg.AllowPrivateTargets = true
	cfg.AllowUnsigned = true
	gw, err := NewChecked(cfg)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	defer gw.Close()

	body := `{"ItemId":"998877","MediaSourceId":"ms-99","PlaySessionId":"ps-99","PositionTicks":10000000}`
	req := httptest.NewRequest(http.MethodPost, "https://proxy.test/"+upstream.URL+"/emby/Sessions/Playing", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.33:44001"
	req.Header.Set("X-Emby-Client", "SenPlayer")
	req.Header.Set("X-Emby-Device-Id", "dev-401")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from upstream, got %d", rec.Code)
	}
	if snaps := gw.playback.Snapshot(); len(snaps) != 0 {
		t.Fatalf("expected 0 playback sessions after 401 Playing report, got %d", len(snaps))
	}
}

func TestRememberItemAliasResistsTwoCycle(t *testing.T) {
	tr := newPlaybackTracker()
	tr.mu.Lock()
	defer tr.mu.Unlock()

	tr.rememberItemAliasLocked("emby-a.example.test", "A", "B")
	if got := tr.canonicalItemIDLocked("emby-a.example.test", "A", "", ""); got != "B" {
		t.Fatalf("expected A->B, got %q", got)
	}
	// Attempting reverse B->A must not form a cycle or point B->A.
	tr.rememberItemAliasLocked("emby-a.example.test", "B", "A")
	if gotA := tr.canonicalItemIDLocked("emby-a.example.test", "A", "", ""); gotA != "B" {
		t.Fatalf("expected canonical(A)=B, got %q", gotA)
	}
	if gotB := tr.canonicalItemIDLocked("emby-a.example.test", "B", "", ""); gotB != "B" {
		t.Fatalf("expected canonical(B)=B (no cycle back to A), got %q", gotB)
	}
}

func TestNATCrossDeviceSessionsDoNotMerge(t *testing.T) {
	tr := newPlaybackTracker()
	tr.ObservePlayingReport(playbackRequestMeta{
		ClientIP:     "203.0.113.50",
		DeviceID:     "dev-user-1",
		DeviceName:   "Phone-1",
		ClientName:   "SenPlayer",
		UserID:       "user-1",
		UpstreamHost: "emby-a.example.test",
		Path:         "/emby/Sessions/Playing",
	}, []byte(`{"ItemId":"111","PlaySessionId":"ps-1","PositionTicks":10000000}`))
	tr.ObservePlayingReport(playbackRequestMeta{
		ClientIP:     "203.0.113.50",
		DeviceID:     "dev-user-2",
		DeviceName:   "Phone-2",
		ClientName:   "SenPlayer",
		UserID:       "user-2",
		UpstreamHost: "emby-a.example.test",
		Path:         "/emby/Sessions/Playing",
	}, []byte(`{"ItemId":"222","PlaySessionId":"ps-2","PositionTicks":10000000}`))

	snaps := tr.Snapshot()
	if len(snaps) != 2 {
		t.Fatalf("expected 2 isolated NAT device sessions, got %d: %+v", len(snaps), snaps)
	}
}
