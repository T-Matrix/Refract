package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	proxyModeOff       = "off"
	proxyModeBlacklist = "blacklist"
	proxyModeWhitelist = "whitelist"
)

type proxyRule struct {
	ID           int64  `json:"id"`
	Action       string `json:"action"`
	DomainSuffix string `json:"domain_suffix"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    int64  `json:"created_at"`
}

type proxyPolicy struct {
	Mode            string      `json:"mode"`
	Rules           []proxyRule `json:"rules"`
	ScheduleEnabled bool        `json:"schedule_enabled"`
	ScheduleStart   string      `json:"schedule_start"`
	ScheduleEnd     string      `json:"schedule_end"`
}

type proxyPolicyJSON struct {
	Mode                   string      `json:"mode"`
	Rules                  []proxyRule `json:"rules"`
	ScheduleEnabled        bool        `json:"schedule_enabled"`
	ScheduleStart          string      `json:"schedule_start"`
	ScheduleEnd            string      `json:"schedule_end"`
	ScheduleOpen           bool        `json:"schedule_open"`
	ScheduleTimezone       string      `json:"schedule_timezone"`
	ScheduleNextTransition int64       `json:"schedule_next_transition"`
}

func (p *proxyPolicy) MarshalJSON() ([]byte, error) {
	open, next := p.scheduleStatus(time.Now())
	nextUnix := int64(0)
	if !next.IsZero() {
		nextUnix = next.Unix()
	}
	return json.Marshal(proxyPolicyJSON{
		Mode: p.Mode, Rules: p.Rules,
		ScheduleEnabled: p.ScheduleEnabled, ScheduleStart: p.ScheduleStart, ScheduleEnd: p.ScheduleEnd,
		ScheduleOpen: open, ScheduleTimezone: applicationTimezone, ScheduleNextTransition: nextUnix,
	})
}

func (g *Gateway) reloadProxyPolicy(ctx context.Context) error {
	policy, err := g.telemetry.LoadProxyPolicy(ctx)
	if err != nil {
		return err
	}
	g.policy.Store(policy)
	return nil
}

func (p *proxyPolicy) Allows(target *url.URL) bool {
	return p.AllowsAt(target, time.Now())
}

func (p *proxyPolicy) AllowsAt(target *url.URL, now time.Time) bool {
	if p == nil || p.Mode == proxyModeOff {
		return p == nil || p.scheduleAllows(now)
	}
	if !p.scheduleAllows(now) {
		return false
	}
	host := normalizeHost(target.Hostname())
	switch p.Mode {
	case proxyModeBlacklist:
		return p.matchingRule(host, "deny") == nil
	case proxyModeWhitelist:
		return p.matchingRule(host, "allow") != nil
	default:
		return true
	}
}

func (p *proxyPolicy) scheduleAllows(now time.Time) bool {
	if p == nil || !p.ScheduleEnabled {
		return true
	}
	open, _ := p.scheduleStatus(now)
	return open
}

func (p *proxyPolicy) scheduleStatus(now time.Time) (bool, time.Time) {
	if p == nil || !p.ScheduleEnabled {
		return true, time.Time{}
	}
	now = inApplicationTimezone(now)
	start, startOK := parseScheduleMinute(p.ScheduleStart)
	end, endOK := parseScheduleMinute(p.ScheduleEnd)
	if !startOK || !endOK || start == end {
		return false, time.Time{}
	}
	atMinute := func(dayOffset, value int) time.Time {
		return time.Date(now.Year(), now.Month(), now.Day()+dayOffset, value/60, value%60, 0, 0, applicationLocation)
	}
	minute := now.Hour()*60 + now.Minute()
	if start < end {
		switch {
		case minute < start:
			return false, atMinute(0, start)
		case minute < end:
			return true, atMinute(0, end)
		default:
			return false, atMinute(1, start)
		}
	}
	if minute >= start {
		return true, atMinute(1, end)
	}
	if minute < end {
		return true, atMinute(0, end)
	}
	return false, atMinute(0, start)
}

func normalizeProxySchedule(enabled bool, start, end string) (bool, string, string, error) {
	start = strings.TrimSpace(start)
	end = strings.TrimSpace(end)
	if start == "" {
		start = "09:00"
	}
	if end == "" {
		end = "23:00"
	}
	startMinute, startOK := parseScheduleMinute(start)
	endMinute, endOK := parseScheduleMinute(end)
	if !startOK || !endOK || startMinute == endMinute {
		return false, "", "", errors.New("schedule must use two different HH:MM times")
	}
	return enabled, formatScheduleMinute(startMinute), formatScheduleMinute(endMinute), nil
}

func parseScheduleMinute(value string) (int, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 2 {
		return 0, false
	}
	hour, hourErr := strconv.Atoi(parts[0])
	minute, minuteErr := strconv.Atoi(parts[1])
	if hourErr != nil || minuteErr != nil || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func formatScheduleMinute(value int) string {
	return fmt.Sprintf("%02d:%02d", value/60, value%60)
}

func (p *proxyPolicy) matchingRule(host, action string) *proxyRule {
	var match *proxyRule
	for index := range p.Rules {
		rule := &p.Rules[index]
		if !rule.Enabled || rule.Action != action || !rule.matchesHost(host) {
			continue
		}
		if match == nil || len(rule.DomainSuffix) > len(match.DomainSuffix) {
			match = rule
		}
	}
	return match
}

func (r proxyRule) matchesHost(host string) bool {
	if ruleIP := net.ParseIP(r.DomainSuffix); ruleIP != nil {
		hostIP := net.ParseIP(host)
		return hostIP != nil && ruleIP.Equal(hostIP)
	}
	return host == r.DomainSuffix || strings.HasSuffix(host, "."+r.DomainSuffix)
}

func normalizeProxyRule(action, domainSuffix string) (proxyRule, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "allow" && action != "deny" {
		return proxyRule{}, errors.New("action must be allow or deny")
	}
	domainSuffix = strings.ToLower(strings.TrimSpace(domainSuffix))
	domainSuffix = strings.TrimPrefix(domainSuffix, "*.")
	domainSuffix = strings.Trim(domainSuffix, ".")
	if domainSuffix == "" || !validRuleDomain(domainSuffix) {
		return proxyRule{}, errors.New("invalid domain suffix")
	}
	if ip := net.ParseIP(domainSuffix); ip != nil {
		domainSuffix = ip.String()
	}
	return proxyRule{Action: action, DomainSuffix: domainSuffix, Enabled: true}, nil
}

func validProxyMode(mode string) bool {
	return mode == proxyModeOff || mode == proxyModeBlacklist || mode == proxyModeWhitelist
}

func validRuleDomain(value string) bool {
	if len(value) > 253 {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if strings.ContainsAny(value, "/\\:@ ") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func (s *telemetryStore) LoadProxyPolicy(ctx context.Context) (*proxyPolicy, error) {
	policy := &proxyPolicy{Mode: proxyModeOff, Rules: []proxyRule{}, ScheduleStart: "09:00", ScheduleEnd: "23:00"}
	var storedMode string
	modeErr := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key='proxy_policy_mode'`).Scan(&storedMode)
	if modeErr != nil && !errors.Is(modeErr, sql.ErrNoRows) {
		return nil, modeErr
	}
	var legacyEnabled string
	legacyErr := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key='proxy_policy_enabled'`).Scan(&legacyEnabled)
	if legacyErr != nil && !errors.Is(legacyErr, sql.ErrNoRows) {
		return nil, legacyErr
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id,action,domain_suffix,path_prefix,enabled,created_at FROM proxy_rules ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hasDeny, hasAllow := false, false
	for rows.Next() {
		var rule proxyRule
		var legacyPath string
		var enabledInt int
		if err := rows.Scan(&rule.ID, &rule.Action, &rule.DomainSuffix, &legacyPath, &enabledInt, &rule.CreatedAt); err != nil {
			return nil, err
		}
		if rule.DomainSuffix == "" {
			continue
		}
		rule.Enabled = enabledInt == 1
		hasDeny = hasDeny || (rule.Enabled && rule.Action == "deny")
		hasAllow = hasAllow || (rule.Enabled && rule.Action == "allow")
		policy.Rules = append(policy.Rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if validProxyMode(storedMode) {
		policy.Mode = storedMode
	} else if legacyEnabled == "1" {
		switch {
		case hasDeny:
			policy.Mode = proxyModeBlacklist
		case hasAllow:
			policy.Mode = proxyModeWhitelist
		default:
			policy.Mode = proxyModeBlacklist
		}
	}
	var scheduleEnabled, scheduleStart, scheduleEnd string
	for key, destination := range map[string]*string{
		"proxy_schedule_enabled": &scheduleEnabled,
		"proxy_schedule_start":   &scheduleStart,
		"proxy_schedule_end":     &scheduleEnd,
	} {
		err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, key).Scan(destination)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	enabled, start, end, scheduleErr := normalizeProxySchedule(scheduleEnabled == "1", scheduleStart, scheduleEnd)
	if scheduleErr == nil {
		policy.ScheduleEnabled = enabled
		policy.ScheduleStart = start
		policy.ScheduleEnd = end
	}
	return policy, nil
}

func (s *telemetryStore) SetProxyPolicyMode(ctx context.Context, mode string) error {
	if !validProxyMode(mode) {
		return errors.New("invalid proxy policy mode")
	}
	legacyEnabled := "1"
	if mode == proxyModeOff {
		legacyEnabled = "0"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{"proxy_policy_mode": mode, "proxy_policy_enabled": legacyEnabled} {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *telemetryStore) SetProxyPolicySchedule(ctx context.Context, enabled bool, start, end string) error {
	enabled, start, end, err := normalizeProxySchedule(enabled, start, end)
	if err != nil {
		return err
	}
	enabledValue := "0"
	if enabled {
		enabledValue = "1"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{
		"proxy_schedule_enabled": enabledValue,
		"proxy_schedule_start":   start,
		"proxy_schedule_end":     end,
	} {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`, key, value, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *telemetryStore) UpsertProxyRule(ctx context.Context, rule proxyRule) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_rules WHERE domain_suffix=? AND action=?`, rule.DomainSuffix, rule.Action); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO proxy_rules(action,domain_suffix,path_prefix,enabled,created_at) VALUES(?,?, '',1,?)`,
		rule.Action, rule.DomainSuffix, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *telemetryStore) DeleteProxyRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM proxy_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("rule not found")
	}
	return nil
}
