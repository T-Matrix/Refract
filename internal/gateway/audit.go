package gateway

import (
	"context"
	"regexp"
	"strings"
	"time"
)

const auditLogTTL = 90 * 24 * time.Hour

var (
	auditTelegramTokenPattern = regexp.MustCompile(`\b[0-9]{6,12}:[A-Za-z0-9_-]{20,}\b`)
	auditSecretPattern        = regexp.MustCompile(`(?i)\b(password|passwd|token|api[_-]?key|authorization|secret)\s*[:=]\s*[^\s,;]+`)
	auditQueryPattern         = regexp.MustCompile(`(?i)(https?://[^\s?]+|/[^\s?]*)\?[^\s]*`)
)

type auditEntry struct {
	ID        int64  `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Username  string `json:"username"`
	ClientIP  string `json:"client_ip"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Detail    string `json:"detail"`
	Success   bool   `json:"success"`
}

func (s *telemetryStore) RecordAudit(ctx context.Context, entry auditEntry) {
	if s == nil {
		return
	}
	entry.Username = truncateRunes(strings.TrimSpace(entry.Username), 64)
	entry.ClientIP = truncateRunes(strings.TrimSpace(entry.ClientIP), 64)
	entry.Action = truncateRunes(strings.TrimSpace(entry.Action), 64)
	entry.Resource = truncateRunes(sanitizeAuditField(entry.Resource), 255)
	entry.Detail = truncateRunes(sanitizeAuditField(entry.Detail), 512)
	if entry.Timestamp == 0 {
		entry.Timestamp = time.Now().Unix()
	}
	if entry.Action == "" {
		return
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs(timestamp,username,client_ip,action,resource,detail,success) VALUES(?,?,?,?,?,?,?)`,
		entry.Timestamp, entry.Username, entry.ClientIP, entry.Action, entry.Resource, entry.Detail, boolInt(entry.Success)); err != nil {
		s.dropped.Add(1)
	}
}

func sanitizeAuditField(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\x00", "")
	value = auditTelegramTokenPattern.ReplaceAllString(value, "[REDACTED_TOKEN]")
	value = auditSecretPattern.ReplaceAllString(value, "$1=[REDACTED]")
	return auditQueryPattern.ReplaceAllString(value, "$1?[REDACTED]")
}

func (s *telemetryStore) AuditLogs(ctx context.Context, limit int) ([]auditEntry, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,timestamp,username,client_ip,action,resource,detail,success FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]auditEntry, 0, limit)
	for rows.Next() {
		var entry auditEntry
		var success int
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.Username, &entry.ClientIP, &entry.Action, &entry.Resource, &entry.Detail, &success); err != nil {
			return nil, err
		}
		entry.Success = success == 1
		result = append(result, entry)
	}
	return result, rows.Err()
}
