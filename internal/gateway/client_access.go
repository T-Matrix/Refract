package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const clientAccessPolicySettingKey = "client_access_policy_json"

type clientAccessPolicy struct {
	IPMode          string   `json:"ip_mode"`
	IPRules         []string `json:"ip_rules"`
	GeoMode         string   `json:"geo_mode"`
	Countries       []string `json:"countries"`
	AllowUnknownGeo bool     `json:"allow_unknown_geo"`

	prefixes   []netip.Prefix
	countrySet map[string]struct{}
}

func defaultClientAccessPolicy() clientAccessPolicy {
	return clientAccessPolicy{
		IPMode:          proxyModeOff,
		IPRules:         []string{},
		GeoMode:         proxyModeOff,
		Countries:       []string{},
		AllowUnknownGeo: true,
	}
}

func normalizeClientAccessPolicy(in clientAccessPolicy) (clientAccessPolicy, error) {
	out := clientAccessPolicy{
		IPMode:          normalizePolicyModeOrDefault(in.IPMode),
		GeoMode:         normalizePolicyModeOrDefault(in.GeoMode),
		AllowUnknownGeo: in.AllowUnknownGeo,
		IPRules:         make([]string, 0, len(in.IPRules)),
		Countries:       make([]string, 0, len(in.Countries)),
	}
	if out.IPMode == "" {
		return clientAccessPolicy{}, errors.New("invalid client IP policy mode")
	}
	if out.GeoMode == "" {
		return clientAccessPolicy{}, errors.New("invalid client geo policy mode")
	}

	seenPrefix := make(map[string]struct{}, len(in.IPRules))
	for _, raw := range in.IPRules {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if len(out.IPRules) >= 512 {
			return clientAccessPolicy{}, errors.New("too many IP rules (max 512)")
		}
		var prefix netip.Prefix
		if strings.Contains(item, "/") {
			parsed, err := netip.ParsePrefix(item)
			if err != nil {
				return clientAccessPolicy{}, fmt.Errorf("invalid CIDR %q", item)
			}
			prefix = parsed.Masked()
		} else {
			addr, err := netip.ParseAddr(strings.Trim(item, "[]"))
			if err != nil {
				return clientAccessPolicy{}, fmt.Errorf("invalid IP address %q", item)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		canonical := prefix.String()
		if _, dup := seenPrefix[canonical]; dup {
			continue
		}
		seenPrefix[canonical] = struct{}{}
		out.IPRules = append(out.IPRules, canonical)
		out.prefixes = append(out.prefixes, prefix)
	}

	seenCountry := make(map[string]struct{}, len(in.Countries))
	out.countrySet = make(map[string]struct{}, len(in.Countries))
	for _, raw := range in.Countries {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if code == "" {
			continue
		}
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return clientAccessPolicy{}, fmt.Errorf("invalid country code %q (use 2-letter ISO code like CN, US, JP)", raw)
		}
		if _, dup := seenCountry[code]; dup {
			continue
		}
		seenCountry[code] = struct{}{}
		out.Countries = append(out.Countries, code)
		out.countrySet[code] = struct{}{}
	}
	sort.Strings(out.Countries)
	return out, nil
}

func normalizePolicyModeOrDefault(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", proxyModeOff:
		return proxyModeOff
	case proxyModeBlacklist:
		return proxyModeBlacklist
	case proxyModeWhitelist:
		return proxyModeWhitelist
	default:
		return ""
	}
}

func (p *clientAccessPolicy) compile() {
	if p == nil {
		return
	}
	compiled, err := normalizeClientAccessPolicy(*p)
	if err == nil {
		*p = compiled
	}
}

func (p *clientAccessPolicy) AllowsIP(rawIP string) bool {
	if p == nil || p.IPMode == "" || p.IPMode == proxyModeOff {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(rawIP), "[]"))
	if err != nil {
		return p.IPMode != proxyModeWhitelist
	}
	addr = addr.Unmap()
	matched := false
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			matched = true
			break
		}
	}
	switch p.IPMode {
	case proxyModeBlacklist:
		return !matched
	case proxyModeWhitelist:
		return matched
	default:
		return true
	}
}

func (p *clientAccessPolicy) AllowsCountry(countryCode string) bool {
	if p == nil || p.GeoMode == "" || p.GeoMode == proxyModeOff {
		return true
	}
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if code == "" || code == "XX" || code == "T1" {
		return p.AllowUnknownGeo
	}
	_, matched := p.countrySet[code]
	switch p.GeoMode {
	case proxyModeBlacklist:
		return !matched
	case proxyModeWhitelist:
		return matched
	default:
		return true
	}
}

func (s *telemetryStore) LoadClientAccessPolicy(ctx context.Context) clientAccessPolicy {
	if s == nil {
		return defaultClientAccessPolicy()
	}
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, clientAccessPolicySettingKey).Scan(&raw)
	if err != nil || strings.TrimSpace(raw) == "" {
		return defaultClientAccessPolicy()
	}
	var loaded clientAccessPolicy
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		return defaultClientAccessPolicy()
	}
	normalized, err := normalizeClientAccessPolicy(loaded)
	if err != nil {
		return defaultClientAccessPolicy()
	}
	return normalized
}

func (s *telemetryStore) SaveClientAccessPolicy(ctx context.Context, policy clientAccessPolicy) (clientAccessPolicy, error) {
	normalized, err := normalizeClientAccessPolicy(policy)
	if err != nil {
		return clientAccessPolicy{}, err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return clientAccessPolicy{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		clientAccessPolicySettingKey, string(data), time.Now().Unix(),
	)
	return normalized, err
}

func (s *telemetryStore) RecentIPCountries(ctx context.Context, limit int) map[string]string {
	if s == nil {
		return nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, country_code FROM geo_ip_cache WHERE country_code != '' ORDER BY looked_up DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var ip, code string
		if err := rows.Scan(&ip, &code); err == nil && ip != "" && code != "" {
			result[ip] = strings.ToUpper(strings.TrimSpace(code))
		}
	}
	return result
}

func (a *adminServer) handleClientAccessPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policy := a.store.LoadClientAccessPolicy(r.Context())
		a.writeJSON(w, http.StatusOK, policy)
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req clientAccessPolicy
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := a.store.SaveClientAccessPolicy(r.Context(), req)
		if err != nil {
			a.auditRequest(r, "policy.client_access", "client-access", err.Error(), false)
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := a.gateway.reloadProxyPolicy(r.Context()); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to reload access policy")
			return
		}
		a.auditRequest(r, "policy.client_access", "client-access",
			fmt.Sprintf("ip_mode=%s(%d) geo_mode=%s(%d)", saved.IPMode, len(saved.IPRules), saved.GeoMode, len(saved.Countries)), true)
		a.writeJSON(w, http.StatusOK, saved)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut)
	}
}
