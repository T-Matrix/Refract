package gateway

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const enrollTokenTTL = 15 * time.Minute

const edgeNodeSelectCols = `id,name,group_name,region,public_url,public_visible,draining,
	token_hash,enroll_token_hash,enroll_expires_at,overrides_json,
	applied_revision,applied_sha256,agent_version,arch,hostname,
	public_ipv4,public_ipv6,manual_ipv4,manual_ipv6,dns_sync_enabled,dns_ip_mode,
	monthly_quota_gb,quota_reset_day,quota_direction,quota_auto_drain,
	quota_auto_drained,quota_cycle_key,quota_alert_level,binary_sha256,
	last_seen_at,created_at,updated_at`

func normalizeDNSIPMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	case "dual":
		return "dual"
	default:
		return "auto"
	}
}

func normalizeQuotaDirection(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "both":
		return "both"
	default:
		return "out"
	}
}

func normalizeQuotaResetDay(day int) int {
	if day < 1 {
		return 1
	}
	if day > 28 {
		return 28
	}
	return day
}

func normalizeOptionalNodeIP(raw string, wantV6 bool) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(raw), "[]")
	if trimmed == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q", raw)
	}
	addr = addr.Unmap()
	if wantV6 && !addr.Is6() {
		return "", fmt.Errorf("%q is not a valid IPv6 address", raw)
	}
	if !wantV6 && !addr.Is4() {
		return "", fmt.Errorf("%q is not a valid IPv4 address", raw)
	}
	return addr.String(), nil
}

func billingCycleWindow(now time.Time, resetDay int) (cycleKey string, startUnix, nextResetUnix int64) {
	resetDay = normalizeQuotaResetDay(resetDay)
	local := inApplicationTimezone(now)
	year, month, day := local.Date()
	var start time.Time
	if day >= resetDay {
		start = time.Date(year, month, resetDay, 0, 0, 0, 0, applicationLocation)
	} else {
		start = time.Date(year, month-1, resetDay, 0, 0, 0, 0, applicationLocation)
	}
	next := start.AddDate(0, 1, 0)
	return start.Format("2006-01-02"), start.Unix(), next.Unix()
}

func monthlyQuotaGBToBytes(gb float64) int64 {
	if gb <= 0 || math.IsNaN(gb) || math.IsInf(gb, 0) {
		return 0
	}
	return int64(math.Round(gb * 1024 * 1024 * 1024))
}

func generateRandomHex(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *telemetryStore) ListEdgeNodes(ctx context.Context) ([]edgeNodeRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+edgeNodeSelectCols+`
		FROM edge_nodes
		ORDER BY group_name COLLATE NOCASE ASC, name COLLATE NOCASE ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make([]edgeNodeRecord, 0)
	for rows.Next() {
		node, scanErr := scanEdgeNode(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *telemetryStore) GetEdgeNode(ctx context.Context, id string) (edgeNodeRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT `+edgeNodeSelectCols+`
		FROM edge_nodes WHERE id=?`, strings.TrimSpace(id))
	return scanEdgeNode(row)
}

func (s *telemetryStore) FindEdgeNodeByTokenHash(ctx context.Context, tokenHash string) (edgeNodeRecord, error) {
	if tokenHash == "" {
		return edgeNodeRecord{}, sql.ErrNoRows
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT `+edgeNodeSelectCols+`
		FROM edge_nodes WHERE token_hash=?`, tokenHash)
	return scanEdgeNode(row)
}

func (s *telemetryStore) FindEdgeNodeByEnrollTokenHash(ctx context.Context, enrollHash string) (edgeNodeRecord, error) {
	if enrollHash == "" {
		return edgeNodeRecord{}, sql.ErrNoRows
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT `+edgeNodeSelectCols+`
		FROM edge_nodes WHERE enroll_token_hash=?`, enrollHash)
	return scanEdgeNode(row)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEdgeNode(scanner rowScanner) (edgeNodeRecord, error) {
	var node edgeNodeRecord
	var visibleInt, drainingInt, dnsSyncInt, quotaAutoDrainInt, quotaAutoDrainedInt int
	var overridesRaw string
	err := scanner.Scan(
		&node.ID, &node.Name, &node.GroupName, &node.Region, &node.PublicURL,
		&visibleInt, &drainingInt, &node.TokenHash, &node.EnrollTokenHash, &node.EnrollExpiresAt,
		&overridesRaw, &node.AppliedRevision, &node.AppliedSHA256,
		&node.AgentVersion, &node.Arch, &node.Hostname,
		&node.PublicIPv4, &node.PublicIPv6, &node.ManualIPv4, &node.ManualIPv6,
		&dnsSyncInt, &node.DNSIPMode,
		&node.MonthlyQuotaGB, &node.QuotaResetDay, &node.QuotaDirection,
		&quotaAutoDrainInt, &quotaAutoDrainedInt, &node.QuotaCycleKey, &node.QuotaAlertLevel,
		&node.BinarySHA256,
		&node.LastSeenAt, &node.CreatedAt, &node.UpdatedAt,
	)
	if err != nil {
		return edgeNodeRecord{}, err
	}
	node.PublicVisible = visibleInt == 1
	node.Draining = drainingInt == 1
	node.DNSSyncEnabled = dnsSyncInt == 1
	node.DNSIPMode = normalizeDNSIPMode(node.DNSIPMode)
	node.QuotaResetDay = normalizeQuotaResetDay(node.QuotaResetDay)
	node.QuotaDirection = normalizeQuotaDirection(node.QuotaDirection)
	node.QuotaAutoDrain = quotaAutoDrainInt == 1
	node.QuotaAutoDrained = quotaAutoDrainedInt == 1
	if strings.TrimSpace(overridesRaw) != "" {
		_ = json.Unmarshal([]byte(overridesRaw), &node.Overrides)
	}
	return node, nil
}

func (s *telemetryStore) CreateEdgeNode(ctx context.Context, node edgeNodeRecord) (edgeNodeRecord, string, error) {
	node.Name = truncateRunes(strings.TrimSpace(node.Name), 64)
	node.GroupName = truncateRunes(strings.TrimSpace(node.GroupName), 48)
	node.Region = truncateRunes(strings.TrimSpace(node.Region), 48)
	if node.Name == "" {
		return edgeNodeRecord{}, "", errors.New("node name is required")
	}
	var err error
	if strings.TrimSpace(node.PublicURL) != "" {
		var publicURL string
		publicURL, err = normalizeNodePublicURL(node.PublicURL)
		if err != nil {
			return edgeNodeRecord{}, "", err
		}
		node.PublicURL = publicURL
	} else {
		node.PublicURL = ""
	}
	if node.ManualIPv4, err = normalizeOptionalNodeIP(node.ManualIPv4, false); err != nil {
		return edgeNodeRecord{}, "", err
	}
	if node.ManualIPv6, err = normalizeOptionalNodeIP(node.ManualIPv6, true); err != nil {
		return edgeNodeRecord{}, "", err
	}
	if node.MonthlyQuotaGB < 0 || math.IsNaN(node.MonthlyQuotaGB) || math.IsInf(node.MonthlyQuotaGB, 0) || node.MonthlyQuotaGB > 1000000 {
		return edgeNodeRecord{}, "", errors.New("monthly_quota_gb must be between 0 and 1000000")
	}
	node.DNSIPMode = normalizeDNSIPMode(node.DNSIPMode)
	node.QuotaResetDay = normalizeQuotaResetDay(node.QuotaResetDay)
	node.QuotaDirection = normalizeQuotaDirection(node.QuotaDirection)

	id, err := generateRandomHex(8)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	enrollRaw, err := generateRandomHex(24)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	enrollToken := "rf_enr_" + enrollRaw
	now := time.Now()
	node.ID = "nd_" + id
	node.EnrollTokenHash = hashAgentToken(enrollToken)
	node.EnrollExpiresAt = now.Add(enrollTokenTTL).Unix()
	node.CreatedAt = now.Unix()
	node.UpdatedAt = now.Unix()

	overridesJSON, err := json.Marshal(node.Overrides)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO edge_nodes(
			id,name,group_name,region,public_url,public_visible,draining,
			token_hash,enroll_token_hash,enroll_expires_at,overrides_json,
			applied_revision,applied_sha256,agent_version,arch,hostname,
			manual_ipv4,manual_ipv6,dns_sync_enabled,dns_ip_mode,
			monthly_quota_gb,quota_reset_day,quota_direction,quota_auto_drain,
			last_seen_at,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,'','','','',?,?,?,?,?,?,?,?,0,?,?)`,
		node.ID, node.Name, node.GroupName, node.Region, node.PublicURL,
		boolToInt(node.PublicVisible), boolToInt(node.Draining),
		"", node.EnrollTokenHash, node.EnrollExpiresAt, string(overridesJSON),
		node.ManualIPv4, node.ManualIPv6, boolToInt(node.DNSSyncEnabled), node.DNSIPMode,
		node.MonthlyQuotaGB, node.QuotaResetDay, node.QuotaDirection, boolToInt(node.QuotaAutoDrain),
		node.CreatedAt, node.UpdatedAt,
	)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	return node, enrollToken, nil
}

type edgeNodeUpdateInput struct {
	Name           string
	GroupName      string
	Region         string
	PublicURL      string
	PublicVisible  bool
	Draining       bool
	Overrides      edgeNodeOverrides
	ManualIPv4     string
	ManualIPv6     string
	DNSSyncEnabled bool
	DNSIPMode      string
	MonthlyQuotaGB float64
	QuotaResetDay  int
	QuotaDirection string
	QuotaAutoDrain bool
}

func (s *telemetryStore) UpdateEdgeNode(ctx context.Context, id string, in edgeNodeUpdateInput) (edgeNodeRecord, error) {
	in.Name = truncateRunes(strings.TrimSpace(in.Name), 64)
	in.GroupName = truncateRunes(strings.TrimSpace(in.GroupName), 48)
	in.Region = truncateRunes(strings.TrimSpace(in.Region), 48)
	if in.Name == "" {
		return edgeNodeRecord{}, errors.New("node name is required")
	}
	normalizedURL := ""
	if strings.TrimSpace(in.PublicURL) != "" {
		var err error
		normalizedURL, err = normalizeNodePublicURL(in.PublicURL)
		if err != nil {
			return edgeNodeRecord{}, err
		}
	}
	manualV4, err := normalizeOptionalNodeIP(in.ManualIPv4, false)
	if err != nil {
		return edgeNodeRecord{}, err
	}
	manualV6, err := normalizeOptionalNodeIP(in.ManualIPv6, true)
	if err != nil {
		return edgeNodeRecord{}, err
	}
	if in.MonthlyQuotaGB < 0 || math.IsNaN(in.MonthlyQuotaGB) || math.IsInf(in.MonthlyQuotaGB, 0) || in.MonthlyQuotaGB > 1000000 {
		return edgeNodeRecord{}, errors.New("monthly_quota_gb must be between 0 and 1000000")
	}
	in.DNSIPMode = normalizeDNSIPMode(in.DNSIPMode)
	in.QuotaResetDay = normalizeQuotaResetDay(in.QuotaResetDay)
	in.QuotaDirection = normalizeQuotaDirection(in.QuotaDirection)

	overridesJSON, err := json.Marshal(in.Overrides)
	if err != nil {
		return edgeNodeRecord{}, err
	}
	now := time.Now().Unix()
	// If operator manually un-drains or increases/clears quota, clear quota_auto_drained flag when draining is false.
	autoDrainedClear := 0
	if !in.Draining {
		autoDrainedClear = 1
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE edge_nodes
		SET name=?, group_name=?, region=?, public_url=?, public_visible=?, draining=?, overrides_json=?,
		    manual_ipv4=?, manual_ipv6=?, dns_sync_enabled=?, dns_ip_mode=?,
		    monthly_quota_gb=?, quota_reset_day=?, quota_direction=?, quota_auto_drain=?,
		    quota_auto_drained=CASE WHEN ?=1 THEN 0 ELSE quota_auto_drained END,
		    quota_alert_level=CASE WHEN ?=1 OR monthly_quota_gb != ? THEN 0 ELSE quota_alert_level END,
		    updated_at=?
		WHERE id=?`,
		in.Name, in.GroupName, in.Region, normalizedURL, boolToInt(in.PublicVisible), boolToInt(in.Draining), string(overridesJSON),
		manualV4, manualV6, boolToInt(in.DNSSyncEnabled), in.DNSIPMode,
		in.MonthlyQuotaGB, in.QuotaResetDay, in.QuotaDirection, boolToInt(in.QuotaAutoDrain),
		autoDrainedClear, autoDrainedClear, in.MonthlyQuotaGB, now, id,
	)
	if err != nil {
		return edgeNodeRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return edgeNodeRecord{}, sql.ErrNoRows
	}
	return s.GetEdgeNode(ctx, id)
}

func (s *telemetryStore) RotateEdgeNodeEnrollToken(ctx context.Context, id string, revokeExisting bool) (edgeNodeRecord, string, error) {
	enrollRaw, err := generateRandomHex(24)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	enrollToken := "rf_enr_" + enrollRaw
	now := time.Now()
	expiresAt := now.Add(enrollTokenTTL).Unix()
	var res sql.Result
	if revokeExisting {
		res, err = s.db.ExecContext(ctx, `
			UPDATE edge_nodes
			SET token_hash='', enroll_token_hash=?, enroll_expires_at=?, updated_at=?
			WHERE id=?`,
			hashAgentToken(enrollToken), expiresAt, now.Unix(), id,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
			UPDATE edge_nodes
			SET enroll_token_hash=?, enroll_expires_at=?, updated_at=?
			WHERE id=?`,
			hashAgentToken(enrollToken), expiresAt, now.Unix(), id,
		)
	}
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return edgeNodeRecord{}, "", sql.ErrNoRows
	}
	node, err := s.GetEdgeNode(ctx, id)
	return node, enrollToken, err
}

func (s *telemetryStore) CompleteEdgeNodeEnrollment(ctx context.Context, enrollToken, version, arch, hostname string) (edgeNodeRecord, string, error) {
	enrollHash := hashAgentToken(enrollToken)
	node, err := s.FindEdgeNodeByEnrollTokenHash(ctx, enrollHash)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	now := time.Now().Unix()
	if node.EnrollExpiresAt <= 0 || now > node.EnrollExpiresAt {
		return edgeNodeRecord{}, "", errors.New("enrollment token expired")
	}
	secretRaw, err := generateRandomHex(32)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	agentSecret := "rf_agt_" + secretRaw
	res, err := s.db.ExecContext(ctx, `
		UPDATE edge_nodes
		SET token_hash=?, enroll_token_hash='', enroll_expires_at=0,
		    agent_version=?, arch=?, hostname=?, last_seen_at=?, updated_at=?
		WHERE id=? AND enroll_token_hash=?`,
		hashAgentToken(agentSecret),
		truncateRunes(strings.TrimSpace(version), 48),
		truncateRunes(strings.TrimSpace(arch), 32),
		truncateRunes(strings.TrimSpace(hostname), 128),
		now, now, node.ID, enrollHash,
	)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return edgeNodeRecord{}, "", errors.New("enrollment token already consumed")
	}
	updated, err := s.GetEdgeNode(ctx, node.ID)
	return updated, agentSecret, err
}

func (s *telemetryStore) CreateEnrolledEdgeNodeFromDiscovery(ctx context.Context, name, groupName, region, version, arch, hostname string) (edgeNodeRecord, string, error) {
	id, err := generateRandomHex(8)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	secretRaw, err := generateRandomHex(32)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	nodeID := "nd_" + id
	agentSecret := "rf_agt_" + secretRaw
	name = truncateRunes(strings.TrimSpace(name), 64)
	if name == "" {
		name = truncateRunes(strings.TrimSpace(hostname), 64)
	}
	if name == "" {
		name = "edge-" + id[:6]
	}
	groupName = truncateRunes(strings.TrimSpace(groupName), 48)
	region = truncateRunes(strings.TrimSpace(region), 48)
	now := time.Now().Unix()

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO edge_nodes(
			id,name,group_name,region,public_url,public_visible,draining,
			token_hash,enroll_token_hash,enroll_expires_at,overrides_json,
			applied_revision,applied_sha256,agent_version,arch,hostname,
			manual_ipv4,manual_ipv6,dns_sync_enabled,dns_ip_mode,
			monthly_quota_gb,quota_reset_day,quota_direction,quota_auto_drain,
			last_seen_at,created_at,updated_at
		) VALUES(?,?,?,?,'',0,0,?,'',0,'{}',0,'',?,?,?,'','',0,'auto',0,1,'out',1,?,?,?)`,
		nodeID, name, groupName, region,
		hashAgentToken(agentSecret),
		truncateRunes(strings.TrimSpace(version), 48),
		truncateRunes(strings.TrimSpace(arch), 32),
		truncateRunes(strings.TrimSpace(hostname), 128),
		now, now, now,
	)
	if err != nil {
		return edgeNodeRecord{}, "", err
	}
	created, err := s.GetEdgeNode(ctx, nodeID)
	return created, agentSecret, err
}

func (s *telemetryStore) RecordEdgeNodeHeartbeat(ctx context.Context, id string, revision int64, sha, version, arch, hostname, publicIPv4, publicIPv6, binarySHA string, seenAt int64) error {
	ipv4 := strings.TrimSpace(publicIPv4)
	if v4, err := normalizeOptionalNodeIP(ipv4, false); err == nil {
		ipv4 = v4
	} else {
		ipv4 = ""
	}
	ipv6 := strings.TrimSpace(publicIPv6)
	if v6, err := normalizeOptionalNodeIP(ipv6, true); err == nil {
		ipv6 = v6
	} else {
		ipv6 = ""
	}
	binSHA := truncateRunes(strings.ToLower(strings.TrimSpace(binarySHA)), 64)
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_nodes
		SET applied_revision=?, applied_sha256=?, agent_version=?, arch=?, hostname=?,
		    public_ipv4=CASE WHEN ?!='' THEN ? ELSE public_ipv4 END,
		    public_ipv6=CASE WHEN ?!='' THEN ? ELSE public_ipv6 END,
		    binary_sha256=CASE WHEN ?!='' THEN ? ELSE binary_sha256 END,
		    last_seen_at=?
		WHERE id=?`,
		revision, truncateRunes(strings.TrimSpace(sha), 64),
		truncateRunes(strings.TrimSpace(version), 48),
		truncateRunes(strings.TrimSpace(arch), 32),
		truncateRunes(strings.TrimSpace(hostname), 128),
		ipv4, ipv4,
		ipv6, ipv6,
		binSHA, binSHA,
		seenAt, id,
	)
	return err
}

func addSaturated(a, b, limit uint64) uint64 {
	if a >= limit {
		return limit
	}
	rem := limit - a
	if b >= rem {
		return limit
	}
	return a + b
}

func (s *telemetryStore) RecordNodeNICTrafficSample(ctx context.Context, nodeID string, sample *hostNICTrafficReport, at time.Time) error {
	if s == nil || nodeID == "" || sample == nil {
		return nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	minute := at.Truncate(time.Minute).Unix()

	const (
		maxNICIfaces   = 16
		maxNICIfaceLen = 32
	)
	ifaces := make([]string, 0, min(len(sample.Interfaces), maxNICIfaces))
	seenIface := make(map[string]struct{}, maxNICIfaces)
	for _, raw := range sample.Interfaces {
		name := strings.TrimSpace(raw)
		if name == "" || len(name) > maxNICIfaceLen {
			continue
		}
		if _, ok := seenIface[name]; !ok {
			seenIface[name] = struct{}{}
			ifaces = append(ifaces, name)
			if len(ifaces) >= maxNICIfaces {
				break
			}
		}
	}
	if len(ifaces) == 0 && len(sample.Counters) > 0 {
		counterNames := make([]string, 0, len(sample.Counters))
		for name := range sample.Counters {
			name = strings.TrimSpace(name)
			if name != "" && len(name) <= maxNICIfaceLen {
				counterNames = append(counterNames, name)
			}
		}
		sort.Strings(counterNames)
		if len(counterNames) > maxNICIfaces {
			counterNames = counterNames[:maxNICIfaces]
		}
		ifaces = append(ifaces, counterNames...)
	}
	sort.Strings(ifaces)
	if len(ifaces) > maxNICIfaces {
		ifaces = ifaces[:maxNICIfaces]
	}
	ifacesJoined := strings.Join(ifaces, ",")

	counters := make(map[string]nicByteCounter, min(max(1, len(sample.Counters)), maxNICIfaces))
	if len(sample.Counters) > 0 {
		keys := make([]string, 0, len(sample.Counters))
		for k := range sample.Counters {
			trimmed := strings.TrimSpace(k)
			if trimmed != "" && len(trimmed) <= maxNICIfaceLen {
				keys = append(keys, trimmed)
			}
		}
		sort.Strings(keys)
		if len(keys) > maxNICIfaces {
			keys = keys[:maxNICIfaces]
		}
		for _, k := range keys {
			if v, ok := sample.Counters[k]; ok {
				counters[k] = v
			} else {
				for rawK, rawV := range sample.Counters {
					if strings.TrimSpace(rawK) == k {
						counters[k] = rawV
						break
					}
				}
			}
		}
	} else {
		key := ifacesJoined
		if key == "" || len(key) > maxNICIfaceLen {
			key = "primary"
		}
		counters[key] = nicByteCounter{RXBytes: sample.RXBytes, TXBytes: sample.TXBytes}
	}
	if len(counters) == 0 {
		return nil
	}
	countersRaw, err := json.Marshal(counters)
	if err != nil {
		return err
	}
	bootID := strings.TrimSpace(sample.BootID)
	sampledAt := sample.SampledAt
	if sampledAt < 0 {
		sampledAt = 0
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var prevBootID, prevIfaces, prevCountersRaw string
	var prevSampledAt int64
	rowErr := tx.QueryRowContext(ctx, `SELECT boot_id, ifaces, counters_json, sampled_at FROM node_nic_state WHERE node_id=?`, nodeID).Scan(&prevBootID, &prevIfaces, &prevCountersRaw, &prevSampledAt)
	if rowErr != nil && !errors.Is(rowErr, sql.ErrNoRows) {
		return rowErr
	}

	if errors.Is(rowErr, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_nic_state(node_id, boot_id, ifaces, counters_json, sampled_at, updated_at) VALUES(?,?,?,?,?,?)`,
			nodeID, bootID, ifacesJoined, string(countersRaw), sampledAt, at.Unix(),
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_nic_traffic_minutes(minute, node_id, ifaces, rx_bytes, tx_bytes)
			 VALUES(?,?,?,0,0)
			 ON CONFLICT(minute, node_id) DO UPDATE SET
			 ifaces=CASE WHEN excluded.ifaces!='' THEN excluded.ifaces ELSE node_nic_traffic_minutes.ifaces END`,
			minute, nodeID, ifacesJoined,
		); err != nil {
			return err
		}
		return tx.Commit()
	}

	if sampledAt > 0 && prevSampledAt > 0 && sampledAt < prevSampledAt && prevBootID == bootID {
		return nil
	}
	if prevBootID == bootID && prevIfaces == ifacesJoined && string(countersRaw) == prevCountersRaw && (sampledAt == 0 || sampledAt <= prevSampledAt) {
		return nil
	}

	prevCounters := make(map[string]nicByteCounter)
	if strings.TrimSpace(prevCountersRaw) != "" {
		_ = json.Unmarshal([]byte(prevCountersRaw), &prevCounters)
	}

	rebooted := prevBootID != "" && bootID != "" && prevBootID != bootID
	const maxSampleDelta uint64 = uint64(1) << 40      // 1 TiB single-heartbeat sanity cap
	const maxCounterResetAccept uint64 = uint64(2) << 30 // 2 GiB plausibility cap for in-boot NIC resets
	var deltaRX, deltaTX uint64
	var anyIncreased, anyDroppedNonReset bool

	for iface, cur := range counters {
		prev, existed := prevCounters[iface]
		if !existed {
			if rebooted {
				if cur.RXBytes <= maxSampleDelta {
					deltaRX = addSaturated(deltaRX, cur.RXBytes, maxSampleDelta)
				}
				if cur.TXBytes <= maxSampleDelta {
					deltaTX = addSaturated(deltaTX, cur.TXBytes, maxSampleDelta)
				}
			}
			continue
		}
		if rebooted {
			if cur.RXBytes <= maxSampleDelta {
				deltaRX = addSaturated(deltaRX, cur.RXBytes, maxSampleDelta)
			}
			if cur.TXBytes <= maxSampleDelta {
				deltaTX = addSaturated(deltaTX, cur.TXBytes, maxSampleDelta)
			}
			continue
		}
		if cur.RXBytes > prev.RXBytes {
			anyIncreased = true
			deltaRX = addSaturated(deltaRX, cur.RXBytes-prev.RXBytes, maxSampleDelta)
		} else if cur.RXBytes < prev.RXBytes {
			if cur.RXBytes <= maxCounterResetAccept && cur.RXBytes < prev.RXBytes/2 {
				deltaRX = addSaturated(deltaRX, cur.RXBytes, maxSampleDelta)
			} else {
				anyDroppedNonReset = true
			}
		}
		if cur.TXBytes > prev.TXBytes {
			anyIncreased = true
			deltaTX = addSaturated(deltaTX, cur.TXBytes-prev.TXBytes, maxSampleDelta)
		} else if cur.TXBytes < prev.TXBytes {
			if cur.TXBytes <= maxCounterResetAccept && cur.TXBytes < prev.TXBytes/2 {
				deltaTX = addSaturated(deltaTX, cur.TXBytes, maxSampleDelta)
			} else {
				anyDroppedNonReset = true
			}
		}
	}

	if !rebooted && !anyIncreased && anyDroppedNonReset {
		return nil
	}

	nextSampledAt := sampledAt
	if nextSampledAt <= 0 {
		nextSampledAt = prevSampledAt
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE node_nic_state SET boot_id=?, ifaces=?, counters_json=?, sampled_at=?, updated_at=? WHERE node_id=?`,
		bootID, ifacesJoined, string(countersRaw), nextSampledAt, at.Unix(), nodeID,
	); err != nil {
		return err
	}
	if deltaRX > 0 || deltaTX > 0 {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO node_nic_traffic_minutes(minute, node_id, ifaces, rx_bytes, tx_bytes)
			 VALUES(?,?,?,?,?)
			 ON CONFLICT(minute, node_id) DO UPDATE SET
			 ifaces=CASE WHEN excluded.ifaces!='' THEN excluded.ifaces ELSE node_nic_traffic_minutes.ifaces END,
			 rx_bytes=rx_bytes+excluded.rx_bytes,
			 tx_bytes=tx_bytes+excluded.tx_bytes`,
			minute, nodeID, ifacesJoined, int64(deltaRX), int64(deltaTX),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *telemetryStore) EdgeNodeNICInterfaces(ctx context.Context) (map[string][]string, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, ifaces FROM node_nic_state WHERE ifaces!=''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]string)
	for rows.Next() {
		var nodeID, rawIfaces string
		if err := rows.Scan(&nodeID, &rawIfaces); err != nil {
			return nil, err
		}
		var list []string
		for _, part := range strings.Split(rawIfaces, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				list = append(list, trimmed)
			}
		}
		if len(list) > 0 {
			out[nodeID] = list
		}
	}
	return out, rows.Err()
}

func (s *telemetryStore) NodeCycleTrafficUsage(ctx context.Context, nodeID string, since int64, direction string) (int64, error) {
	if s == nil || nodeID == "" {
		return 0, nil
	}
	var firstNICMin sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MIN(minute) FROM node_nic_traffic_minutes WHERE node_id=?`, nodeID).Scan(&firstNICMin); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	both := normalizeQuotaDirection(direction) == "both"
	if !firstNICMin.Valid {
		expr := `COALESCE(SUM(bytes_out),0)`
		if both {
			expr = `COALESCE(SUM(bytes_in + bytes_out),0)`
		}
		var total int64
		err := s.db.QueryRowContext(ctx, `SELECT `+expr+` FROM node_traffic_minutes WHERE node_id=? AND minute>=?`, nodeID, since).Scan(&total)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		return total, nil
	}

	nicExpr := `COALESCE(SUM(tx_bytes),0)`
	if both {
		nicExpr = `COALESCE(SUM(rx_bytes + tx_bytes),0)`
	}
	var nicTotal int64
	if err := s.db.QueryRowContext(ctx, `SELECT `+nicExpr+` FROM node_nic_traffic_minutes WHERE node_id=? AND minute>=?`, nodeID, since).Scan(&nicTotal); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if firstNICMin.Int64 > since {
		preExpr := `COALESCE(SUM(bytes_out),0)`
		if both {
			preExpr = `COALESCE(SUM(bytes_in + bytes_out),0)`
		}
		var preTotal int64
		if err := s.db.QueryRowContext(ctx, `SELECT `+preExpr+` FROM node_traffic_minutes WHERE node_id=? AND minute>=? AND minute<?`, nodeID, since, firstNICMin.Int64).Scan(&preTotal); err == nil {
			nicTotal += preTotal
		}
	}
	return nicTotal, nil
}

func (s *telemetryStore) UpdateEdgeNodeQuotaState(ctx context.Context, id, cycleKey string, alertLevel int, autoDrained bool, draining *bool) error {
	now := time.Now().Unix()
	if draining != nil {
		_, err := s.db.ExecContext(ctx, `
			UPDATE edge_nodes
			SET quota_cycle_key=?, quota_alert_level=?, quota_auto_drained=?, draining=?, updated_at=?
			WHERE id=?`,
			cycleKey, alertLevel, boolToInt(autoDrained), boolToInt(*draining), now, id,
		)
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE edge_nodes
		SET quota_cycle_key=?, quota_alert_level=?, quota_auto_drained=?, updated_at=?
		WHERE id=?`,
		cycleKey, alertLevel, boolToInt(autoDrained), now, id,
	)
	return err
}

func (s *telemetryStore) DeleteEdgeNode(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM edge_nodes WHERE id=?`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return sql.ErrNoRows
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM node_nic_state WHERE node_id=?`, strings.TrimSpace(id))
	return nil
}

func (s *telemetryStore) EdgeNodeNames(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM edge_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := make(map[string]string)
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		names[id] = name
	}
	return names, rows.Err()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

const publicPortalSettingKey = "public_portal_enabled"

func (s *telemetryStore) LoadPublicPortalEnabled(ctx context.Context) bool {
	if s == nil {
		return true
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, publicPortalSettingKey).Scan(&raw)
	if err != nil {
		return true
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	return raw != "0" && raw != "false"
}

func (s *telemetryStore) SavePublicPortalEnabled(ctx context.Context, enabled bool) error {
	val := "0"
	if enabled {
		val = "1"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		publicPortalSettingKey, val, time.Now().Unix(),
	)
	return err
}
