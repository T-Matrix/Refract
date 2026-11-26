package gateway

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *adminServer) handlePlaybacks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	var localActive []playbackSessionSnapshot
	if a.gateway.playback != nil {
		localActive = a.gateway.playback.Snapshot()
	}
	var active []playbackSessionSnapshot
	if a.gateway.cluster != nil {
		active = a.gateway.cluster.AggregatePlaybacks(r.Context(), localActive, nodeID)
	} else {
		active = localActive
	}
	history, count24h, err := a.store.ListWatchHistory(r.Context(), nodeID, limit)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "playback history unavailable")
		return
	}
	a.store.EnrichPlaybackLocations(r.Context(), active, history)
	if a.store != nil {
		if servers, healthErr := a.store.EmbyHealthTargetLabels(r.Context()); healthErr == nil && len(servers) > 0 {
			labels := buildEmbyHealthLabels(servers)
			for i := range active {
				if lbl := matchEmbyHealthLabel(active[i].UpstreamHost, "", labels); lbl != nil {
					active[i].EmbyServerName = lbl.serverName
				}
			}
			for i := range history {
				if lbl := matchEmbyHealthLabel(history[i].UpstreamHost, "", labels); lbl != nil {
					history[i].EmbyServerName = lbl.serverName
				}
			}
		}
	}
	uniqueViewers := make(map[string]struct{}, len(active))
	var totalDown int64
	for _, s := range active {
		totalDown += s.DownloadBPS
		who := strings.TrimSpace(s.UserName)
		if who == "" {
			who = s.ClientIP + "|" + s.DeviceID
		}
		uniqueViewers[who] = struct{}{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"summary": playbackSummary{
			WatchingCount:    len(active),
			UniqueUsers:      len(uniqueViewers),
			TotalDownloadBPS: totalDown,
			History24h:       count24h,
		},
		"active":     active,
		"history":    history,
		"updated_at": time.Now().Unix(),
	})
}

func (a *adminServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	localItems := a.gateway.connections.Snapshot()
	var items []connectionSnapshot
	if a.gateway.cluster != nil {
		items = a.gateway.cluster.AggregateConnections(r.Context(), localItems, nodeID)
	} else {
		items = localItems
	}
	if err := a.store.EnrichConnectionLocations(r.Context(), items); err != nil {
		a.writeError(w, http.StatusInternalServerError, "live connections unavailable")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"connections": items, "updated_at": time.Now().Unix()})
}

func (a *adminServer) handleConnectionCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		a.methodNotAllowed(w, http.MethodDelete)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/_admin/api/connections/")
	if len(id) < 2 || len(id) > 32 || strings.Contains(id, "/") || strings.Trim(id, "0123456789abcdef") != "" {
		a.writeError(w, http.StatusBadRequest, "invalid connection id")
		return
	}
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID != "" && nodeID != "local" && a.gateway.cluster != nil {
		if !a.gateway.cluster.CancelRemoteConnection(nodeID, id) {
			a.writeError(w, http.StatusNotFound, "connection not found")
			return
		}
		a.auditRequest(r, "connection.terminate", id, "node_id="+nodeID, true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if a.gateway.connections.Cancel(id) {
		a.auditRequest(r, "connection.terminate", id, "", true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if a.gateway.cluster != nil {
		if remoteNode, ok := a.gateway.cluster.CancelRemoteFlowByID(id); ok {
			a.auditRequest(r, "connection.terminate", id, "node_id="+remoteNode, true)
			a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
	}
	a.writeError(w, http.StatusNotFound, "connection not found")
}

func (a *adminServer) handlePlaybackTerminate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var req struct {
		SessionKey string `json:"session_key"`
		NodeID     string `json:"node_id"`
		FlowID     string `json:"flow_id"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sessionKey := strings.TrimSpace(req.SessionKey)
	nodeID := strings.TrimSpace(req.NodeID)
	flowID := strings.TrimSpace(req.FlowID)
	if sessionKey == "" && flowID == "" {
		a.writeError(w, http.StatusBadRequest, "session_key or flow_id is required")
		return
	}
	if nodeID != "" && nodeID != "local" && a.gateway.cluster != nil {
		if !a.gateway.cluster.CancelRemotePlayback(nodeID, sessionKey, flowID) {
			a.writeError(w, http.StatusNotFound, "playback session not found")
			return
		}
		a.auditRequest(r, "playback.terminate", sessionKey, "node_id="+nodeID, true)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cooldown_sec": int(playbackKickBlockTTL / time.Second)})
		return
	}
	a.gateway.terminatePlaybackSession(sessionKey, flowID)
	a.auditRequest(r, "playback.terminate", sessionKey, "local", true)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cooldown_sec": int(playbackKickBlockTTL / time.Second)})
}

func (a *adminServer) handleReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	period, ok := parseReportPeriod(strings.TrimSpace(r.URL.Query().Get("period")))
	if !ok {
		a.writeError(w, http.StatusBadRequest, "period must be 24h, 7d, 30d, or 90d")
		return
	}
	report, err := a.store.Report(r.Context(), period)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "report unavailable")
		return
	}
	if a.gateway.cfg.Role == RoleStandalone {
		if servers, healthErr := a.store.EmbyHealthTargetLabels(r.Context()); healthErr == nil {
			decorateTargetSummaries(report.TopTargets, servers)
		}
	}
	a.writeJSON(w, http.StatusOK, report)
}

func (a *adminServer) handleReportExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	period, ok := parseReportPeriod(strings.TrimSpace(r.URL.Query().Get("period")))
	if !ok {
		a.writeError(w, http.StatusBadRequest, "invalid report period")
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind != "traffic" && kind != "targets" && kind != "clients" && kind != "regions" {
		a.writeError(w, http.StatusBadRequest, "invalid report export")
		return
	}
	report, err := a.store.Report(r.Context(), period)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "report unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="refract-%s-%s.csv"`, kind, reportPeriodName(period)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0xef, 0xbb, 0xbf})
	output := csv.NewWriter(w)
	switch kind {
	case "traffic":
		_ = output.Write([]string{"时间", "请求", "上传字节", "下载字节", "错误"})
		for _, point := range report.Timeline {
			_ = output.Write([]string{inApplicationTimezone(time.Unix(point.Timestamp, 0)).Format(time.RFC3339), integerCell(point.Requests), integerCell(point.BytesIn), integerCell(point.BytesOut), integerCell(point.Errors)})
		}
	case "targets":
		_ = output.Write([]string{"后端", "请求", "下载字节", "错误", "平均耗时毫秒", "最近活动"})
		for _, target := range report.TopTargets {
			_ = output.Write([]string{safeCSVCell(target.Host), integerCell(target.Requests), integerCell(target.BytesOut), integerCell(target.Errors), integerCell(target.AvgLatency), inApplicationTimezone(time.Unix(target.LastSeen, 0)).Format(time.RFC3339)})
		}
	case "clients":
		_ = output.Write([]string{"IP", "位置", "请求", "下载字节", "最大下行Bps", "最近活动"})
		for _, client := range report.TopClients {
			_ = output.Write([]string{safeCSVCell(client.IP), safeCSVCell(client.Label), integerCell(client.Requests), integerCell(client.BytesOut), integerCell(client.PeakBPS), inApplicationTimezone(time.Unix(client.LastSeen, 0)).Format(time.RFC3339)})
		}
	case "regions":
		_ = output.Write([]string{"地域", "IP数", "请求", "下载字节", "最大下行Bps"})
		for _, region := range report.Regions {
			_ = output.Write([]string{safeCSVCell(region.Label), integerCell(region.UniqueIPs), integerCell(region.Requests), integerCell(region.BytesOut), integerCell(region.PeakBPS)})
		}
	}
	output.Flush()
}

func (a *adminServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := a.store.AuditLogs(r.Context(), limit)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "audit log unavailable")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (a *adminServer) handleBackups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snapshot, err := a.gateway.backups.Snapshot(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "backups unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, snapshot)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		file, err := a.gateway.backups.Create(r.Context(), "manual")
		if err != nil {
			a.auditRequest(r, "backup.create", "", err.Error(), false)
			a.writeError(w, http.StatusInternalServerError, "backup creation failed")
			return
		}
		a.auditRequest(r, "backup.create", file.Name, "", true)
		snapshot, _ := a.gateway.backups.Snapshot(r.Context())
		a.writeJSON(w, http.StatusCreated, snapshot)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleBackupConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config, err := a.store.LoadBackupConfig(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "backup settings unavailable")
			return
		}
		a.writeJSON(w, http.StatusOK, config)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var config backupConfig
		if err := decodeAdminJSON(w, r, &config); err != nil || config.Hour < 0 || config.Hour > 23 || config.Retention < 1 || config.Retention > 30 {
			a.writeError(w, http.StatusBadRequest, "invalid backup settings")
			return
		}
		if err := a.store.SaveBackupConfig(r.Context(), config); err != nil {
			a.writeError(w, http.StatusInternalServerError, "backup settings update failed")
			return
		}
		a.gateway.backups.Wake()
		a.auditRequest(r, "backup.settings", "automatic", fmt.Sprintf("enabled=%t hour=%d retention=%d", config.Enabled, config.Hour, config.Retention), true)
		a.writeJSON(w, http.StatusOK, config)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}

func (a *adminServer) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid backup upload")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		a.writeError(w, http.StatusBadRequest, "backup file is required")
		return
	}
	defer file.Close()
	imported, err := a.gateway.backups.Import(file)
	if err != nil {
		a.auditRequest(r, "backup.import", "", err.Error(), false)
		a.writeError(w, http.StatusBadRequest, "backup import failed")
		return
	}
	a.auditRequest(r, "backup.import", imported.Name, "", true)
	snapshot, _ := a.gateway.backups.Snapshot(r.Context())
	a.writeJSON(w, http.StatusCreated, snapshot)
}

func (a *adminServer) handleBackupItem(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/backups/")
	parts := strings.Split(remainder, "/")
	if len(parts) != 2 || parts[0] == "" {
		a.writeError(w, http.StatusNotFound, "backup route not found")
		return
	}
	name, operation := parts[0], parts[1]
	switch operation {
	case "download":
		if r.Method != http.MethodGet {
			a.methodNotAllowed(w, http.MethodGet)
			return
		}
		file, info, err := a.gateway.backups.Open(name)
		if err != nil {
			a.writeError(w, http.StatusNotFound, "backup not found")
			return
		}
		defer file.Close()
		w.Header().Set("Content-Type", "application/vnd.sqlite3")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		http.ServeContent(w, r, name, info.ModTime(), file)
	case "restore":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		safety, err := a.gateway.backups.Restore(r.Context(), name)
		if err != nil || a.gateway.reloadProxyPolicyReplacingQuota(r.Context()) != nil {
			detail := "restore failed"
			if err != nil {
				detail = err.Error()
			}
			a.auditRequest(r, "backup.restore", name, detail, false)
			a.writeError(w, http.StatusInternalServerError, "backup restore failed")
			return
		}
		a.gateway.publicPortal.Store(a.store.LoadPublicPortalEnabled(r.Context()))
		a.gateway.reloadWAFRules(r.Context())
		invalidateBrandAvatarCache(a.store)
		if a.gateway.cloudflare != nil {
			a.gateway.cloudflare.clearSyncCache()
		}
		if a.gateway.axisnow != nil {
			a.gateway.axisnow.clearSyncCache()
		}
		a.gateway.connections.CancelAll()
		if a.gateway.cluster != nil {
			a.gateway.cluster.CancelAllRemoteConnections()
		}
		if a.gateway.embyHealth != nil {
			a.gateway.embyHealth.Wake()
		}
		a.gateway.telegram.Wake()
		a.gateway.backups.Wake()
		a.auditRequest(r, "backup.restore", name, "safety="+safety.Name, true)
		snapshot, _ := a.gateway.backups.Snapshot(r.Context())
		a.writeJSON(w, http.StatusOK, snapshot)
	case "delete":
		if r.Method != http.MethodDelete {
			a.methodNotAllowed(w, http.MethodDelete)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if err := a.gateway.backups.Delete(name); err != nil {
			a.writeError(w, http.StatusNotFound, "backup not found")
			return
		}
		a.auditRequest(r, "backup.delete", name, "", true)
		snapshot, _ := a.gateway.backups.Snapshot(r.Context())
		a.writeJSON(w, http.StatusOK, snapshot)
	default:
		a.writeError(w, http.StatusNotFound, "backup route not found")
	}
}

func (a *adminServer) auditRequest(r *http.Request, action, resource, detail string, success bool) {
	session, _ := a.authenticate(r)
	a.store.RecordAudit(r.Context(), auditEntry{
		Username: session.Username, ClientIP: adminClientIP(r, a.trustProxy, a.trustedProxyCIDRs...), Action: action,
		Resource: resource, Detail: detail, Success: success,
	})
}

func safeCSVCell(value string) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if value == "" {
		return value
	}
	first := rune(value[0])
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if strings.ContainsRune("=+-@\t\r\n", first) || (trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + value
	}
	return value
}

func integerCell(value int64) string { return strconv.FormatInt(value, 10) }
