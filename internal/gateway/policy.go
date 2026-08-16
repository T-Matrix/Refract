package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
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
	Mode  string      `json:"mode"`
	Rules []proxyRule `json:"rules"`
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
	if p == nil || p.Mode == proxyModeOff {
		return true
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
	policy := &proxyPolicy{Mode: proxyModeOff, Rules: []proxyRule{}}
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
