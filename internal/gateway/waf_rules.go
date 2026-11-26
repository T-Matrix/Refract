package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	wafNodeStart         = "start"
	wafNodeHostMatch     = "host_match"
	wafNodeIPMatch       = "ip_match"
	wafNodeGeoMatch      = "geo_match"
	wafNodePathMatch     = "path_match"
	wafNodePlayerMatch   = "player_match"
	wafNodeScheduleMatch = "schedule_match"
	wafNodePass          = "pass"
	wafNodeBlock         = "block"

	wafMaxNodesPerRule = 48
	wafMaxEdgesPerRule = 96

	wafRuleSelectCols = `id,name,description,enabled,is_global,graph_json,created_at,updated_at`
)

type wafNodeConfig struct {
	Hosts           []string `json:"hosts,omitempty"`
	IPs             []string `json:"ips,omitempty"`
	Countries       []string `json:"countries,omitempty"`
	MatchUnknownGeo bool     `json:"match_unknown_geo,omitempty"`
	MatchMode       string   `json:"match_mode,omitempty"` // "contains" | "prefix" | "regex"
	Patterns        []string `json:"patterns,omitempty"`
	ScheduleStart   string   `json:"schedule_start,omitempty"`
	ScheduleEnd     string   `json:"schedule_end,omitempty"`
	StatusCode      int      `json:"status_code,omitempty"`
	Message         string   `json:"message,omitempty"`
}

type wafGraphNode struct {
	ID     string        `json:"id"`
	Type   string        `json:"type"`
	Label  string        `json:"label,omitempty"`
	X      float64       `json:"x"`
	Y      float64       `json:"y"`
	Config wafNodeConfig `json:"config,omitempty"`
}

type wafGraphEdge struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	SourcePort string `json:"source_port"` // "next" | "true" | "false"
	Target     string `json:"target"`
}

type wafRuleGraph struct {
	Nodes []wafGraphNode `json:"nodes"`
	Edges []wafGraphEdge `json:"edges"`
}

type wafRuleRecord struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     bool         `json:"enabled"`
	IsGlobal    bool         `json:"is_global"`
	Graph       wafRuleGraph `json:"graph"`
	CreatedAt   int64        `json:"created_at"`
	UpdatedAt   int64        `json:"updated_at"`
}

type wafRuleBrief struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	IsGlobal bool   `json:"is_global"`
}

type wafBoundDomainBrief struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

type wafRuleView struct {
	wafRuleRecord
	BoundDomains []wafBoundDomainBrief `json:"bound_domains"`
	Summary      string                `json:"summary"`
	NodeCount    int                   `json:"node_count"`
}

type wafRulesSummary struct {
	Total        int `json:"total"`
	Enabled      int `json:"enabled"`
	Global       int `json:"global"`
	BoundDomains int `json:"bound_domains"`
}

type wafRulesListResponse struct {
	Summary wafRulesSummary `json:"summary"`
	Rules   []wafRuleView   `json:"rules"`
}

type wafEvalContext struct {
	TargetHost  string
	ClientIP    string
	CountryCode string
	Path        string
	RawQuery    string
	UserAgent   string
	ClientName  string
	Now         time.Time
}

type wafEvalDecision struct {
	Blocked    bool     `json:"blocked"`
	StatusCode int      `json:"status_code,omitempty"`
	Message    string   `json:"message,omitempty"`
	RuleID     string   `json:"rule_id,omitempty"`
	RuleName   string   `json:"rule_name,omitempty"`
	NodeLabel  string   `json:"node_label,omitempty"`
	TraceNodes []string `json:"trace_nodes,omitempty"`
	TraceEdges []string `json:"trace_edges,omitempty"`
}

type compiledWAFNode struct {
	id              string
	nodeType        string
	label           string
	nextIdx         int
	nextEdgeID      string
	trueIdx         int
	trueEdgeID      string
	falseIdx        int
	falseEdgeID     string
	hosts           []string
	prefixes        []netip.Prefix
	countries       map[string]struct{}
	matchUnknownGeo bool
	matchMode       string
	patterns        []string
	regexps         []*regexp.Regexp
	schedStart      int
	schedEnd        int
	statusCode      int
	message         string
}

type compiledWAFRule struct {
	id         string
	name       string
	isGlobal   bool
	usesGeo    bool
	startIdx   int
	nodes      []compiledWAFNode
}

func wafNodeDefaultLabel(nodeType string) string {
	switch nodeType {
	case wafNodeStart:
		return "请求入口"
	case wafNodeHostMatch:
		return "目标域名匹配"
	case wafNodeIPMatch:
		return "IP / CIDR 匹配"
	case wafNodeGeoMatch:
		return "国家 / 地区匹配"
	case wafNodePathMatch:
		return "路径 / 攻击特征"
	case wafNodePlayerMatch:
		return "客户端 / 播放器"
	case wafNodeScheduleMatch:
		return "开放时段匹配"
	case wafNodePass:
		return "放行通过"
	case wafNodeBlock:
		return "拦截阻断"
	default:
		return nodeType
	}
}

func isWAFMatchNodeType(nodeType string) bool {
	switch nodeType {
	case wafNodeHostMatch, wafNodeIPMatch, wafNodeGeoMatch, wafNodePathMatch, wafNodePlayerMatch, wafNodeScheduleMatch:
		return true
	default:
		return false
	}
}

func isWAFValidNodeType(nodeType string) bool {
	switch nodeType {
	case wafNodeStart, wafNodePass, wafNodeBlock,
		wafNodeHostMatch, wafNodeIPMatch, wafNodeGeoMatch, wafNodePathMatch, wafNodePlayerMatch, wafNodeScheduleMatch:
		return true
	default:
		return false
	}
}

func normalizeWAFHostPattern(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimPrefix(s, "*.")
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	s = strings.Trim(s, ".")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n") {
		return ""
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Zone() != "" {
			return ""
		}
		return addr.Unmap().String()
	}
	return s
}

func defaultWAFRuleGraph() wafRuleGraph {
	return wafRuleGraph{
		Nodes: []wafGraphNode{
			{ID: "n_start", Type: wafNodeStart, Label: "请求入口", X: 60, Y: 140},
			{ID: "n_pass", Type: wafNodePass, Label: "放行通过", X: 360, Y: 140},
		},
		Edges: []wafGraphEdge{
			{ID: "e_1", Source: "n_start", SourcePort: "next", Target: "n_pass"},
		},
	}
}

func summarizeWAFRuleGraph(g wafRuleGraph) string {
	if len(g.Nodes) == 0 {
		return "空规则"
	}
	parts := make([]string, 0, 5)
	hasPass := false
	blockCode := 0
	for _, n := range g.Nodes {
		switch n.Type {
		case wafNodeHostMatch:
			parts = append(parts, fmt.Sprintf("目标域名(%d)", len(n.Config.Hosts)))
		case wafNodeIPMatch:
			parts = append(parts, fmt.Sprintf("IP匹配(%d)", len(n.Config.IPs)))
		case wafNodeGeoMatch:
			if len(n.Config.Countries) > 0 {
				sample := strings.Join(n.Config.Countries[:min(3, len(n.Config.Countries))], ",")
				if len(n.Config.Countries) > 3 {
					sample += "…"
				}
				parts = append(parts, fmt.Sprintf("地区(%s)", sample))
			} else {
				parts = append(parts, "地区匹配")
			}
		case wafNodePathMatch:
			parts = append(parts, fmt.Sprintf("路径防护(%d)", len(n.Config.Patterns)))
		case wafNodePlayerMatch:
			parts = append(parts, fmt.Sprintf("客户端(%d)", len(n.Config.Patterns)))
		case wafNodeScheduleMatch:
			parts = append(parts, fmt.Sprintf("时段(%s-%s)", n.Config.ScheduleStart, n.Config.ScheduleEnd))
		case wafNodePass:
			hasPass = true
		case wafNodeBlock:
			if blockCode == 0 {
				blockCode = n.Config.StatusCode
				if blockCode == 0 {
					blockCode = http.StatusForbidden
				}
			}
		}
	}
	actions := make([]string, 0, 2)
	if hasPass {
		actions = append(actions, "放行")
	}
	if blockCode > 0 {
		actions = append(actions, fmt.Sprintf("拦截 %d", blockCode))
	}
	if len(parts) == 0 {
		if len(actions) > 0 {
			return "入口 → " + strings.Join(actions, " / ")
		}
		return "仅入口"
	}
	if len(parts) > 3 {
		parts = append(parts[:3], fmt.Sprintf("+%d节点", len(parts)-3))
	}
	res := "入口 → " + strings.Join(parts, " → ")
	if len(actions) > 0 {
		res += " → " + strings.Join(actions, " / ")
	}
	return res
}

func normalizeAndCompileWAFRule(rec wafRuleRecord) (wafRuleRecord, *compiledWAFRule, error) {
	rec.Name = truncateRunes(strings.TrimSpace(rec.Name), 64)
	if rec.Name == "" {
		return wafRuleRecord{}, nil, errors.New("规则名称不能为空")
	}
	rec.Description = truncateRunes(strings.TrimSpace(rec.Description), 200)

	if len(rec.Graph.Nodes) == 0 {
		return wafRuleRecord{}, nil, errors.New("规则图不能为空，请至少保留入口节点")
	}
	if len(rec.Graph.Nodes) > wafMaxNodesPerRule {
		return wafRuleRecord{}, nil, fmt.Errorf("单个规则最多支持 %d 个节点", wafMaxNodesPerRule)
	}
	if len(rec.Graph.Edges) > wafMaxEdgesPerRule {
		return wafRuleRecord{}, nil, fmt.Errorf("单个规则最多支持 %d 条连线", wafMaxEdgesPerRule)
	}

	normNodes := make([]wafGraphNode, 0, len(rec.Graph.Nodes))
	idxByID := make(map[string]int, len(rec.Graph.Nodes))
	compiledNodes := make([]compiledWAFNode, 0, len(rec.Graph.Nodes))
	startIdx := -1
	usesGeo := false

	for i, raw := range rec.Graph.Nodes {
		id := strings.TrimSpace(raw.ID)
		if id == "" || len(id) > 64 {
			return wafRuleRecord{}, nil, fmt.Errorf("第 %d 个节点 ID 无效", i+1)
		}
		if _, dup := idxByID[id]; dup {
			return wafRuleRecord{}, nil, fmt.Errorf("存在重复的节点 ID：%s", id)
		}
		nodeType := strings.ToLower(strings.TrimSpace(raw.Type))
		if !isWAFValidNodeType(nodeType) {
			return wafRuleRecord{}, nil, fmt.Errorf("不支持的节点类型：%s", raw.Type)
		}
		label := truncateRunes(strings.TrimSpace(raw.Label), 48)
		if label == "" {
			label = wafNodeDefaultLabel(nodeType)
		}
		if nodeType == wafNodeStart {
			if startIdx >= 0 {
				return wafRuleRecord{}, nil, errors.New("每条规则只能包含一个「请求入口」节点")
			}
			startIdx = len(compiledNodes)
		}

		cn := compiledWAFNode{
			id:          id,
			nodeType:    nodeType,
			label:       label,
			nextIdx:     -1,
			trueIdx:     -1,
			falseIdx:    -1,
			schedStart:  -1,
			schedEnd:    -1,
			statusCode:  http.StatusForbidden,
			message:     "blocked by WAF rule",
		}
		normCfg := wafNodeConfig{}

		switch nodeType {
		case wafNodeHostMatch:
			seen := make(map[string]struct{})
			for _, rawHost := range raw.Config.Hosts {
				h := normalizeWAFHostPattern(rawHost)
				if h == "" {
					if strings.TrimSpace(rawHost) != "" {
						return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」中的目标域名格式无效：%s", label, rawHost)
					}
					continue
				}
				if _, dup := seen[h]; dup {
					continue
				}
				seen[h] = struct{}{}
				normCfg.Hosts = append(normCfg.Hosts, h)
				cn.hosts = append(cn.hosts, h)
			}
		case wafNodeIPMatch:
			seen := make(map[string]struct{})
			for _, rawIP := range raw.Config.IPs {
				item := strings.TrimSpace(rawIP)
				if item == "" {
					continue
				}
				var prefix netip.Prefix
				if strings.Contains(item, "/") {
					p, err := netip.ParsePrefix(item)
					if err != nil {
						return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」中的 CIDR 格式无效：%s", label, item)
					}
					prefix = p.Masked()
				} else {
					addr, err := netip.ParseAddr(strings.Trim(item, "[]"))
					if err != nil {
						return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」中的 IP 格式无效：%s", label, item)
					}
					addr = addr.Unmap()
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
				canon := prefix.String()
				if _, dup := seen[canon]; dup {
					continue
				}
				seen[canon] = struct{}{}
				normCfg.IPs = append(normCfg.IPs, canon)
				cn.prefixes = append(cn.prefixes, prefix)
			}
		case wafNodeGeoMatch:
			usesGeo = true
			seen := make(map[string]struct{})
			cn.countries = make(map[string]struct{})
			cn.matchUnknownGeo = raw.Config.MatchUnknownGeo
			normCfg.MatchUnknownGeo = raw.Config.MatchUnknownGeo
			for _, rawCode := range raw.Config.Countries {
				code := strings.ToUpper(strings.TrimSpace(rawCode))
				if code == "" {
					continue
				}
				if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
					return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」中的国家代码无效：%s（请使用两位 ISO 代码，如 CN、HK）", label, rawCode)
				}
				if _, dup := seen[code]; dup {
					continue
				}
				seen[code] = struct{}{}
				normCfg.Countries = append(normCfg.Countries, code)
				cn.countries[code] = struct{}{}
			}
			sort.Strings(normCfg.Countries)
		case wafNodePathMatch:
			mode := strings.ToLower(strings.TrimSpace(raw.Config.MatchMode))
			if mode == "" {
				mode = "contains"
			}
			if mode != "contains" && mode != "prefix" && mode != "regex" {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的路径匹配模式无效：%s", label, mode)
			}
			normCfg.MatchMode = mode
			cn.matchMode = mode
			for _, rawPat := range raw.Config.Patterns {
				pat := strings.TrimSpace(rawPat)
				if pat == "" {
					continue
				}
				if len(pat) > 256 {
					return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」中存在过长的匹配规则（最大 256 字符）", label)
				}
				if mode == "regex" {
					re, err := regexp.Compile("(?i)" + pat)
					if err != nil {
						return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」正则表达式无效（%s）：%v", label, pat, err)
					}
					cn.regexps = append(cn.regexps, re)
				} else {
					cn.patterns = append(cn.patterns, strings.ToLower(pat))
				}
				normCfg.Patterns = append(normCfg.Patterns, pat)
			}
		case wafNodePlayerMatch:
			for _, rawPat := range raw.Config.Patterns {
				pat := strings.TrimSpace(rawPat)
				if pat == "" {
					continue
				}
				if len(pat) > 128 {
					return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」客户端关键词过长", label)
				}
				normCfg.Patterns = append(normCfg.Patterns, pat)
				cn.patterns = append(cn.patterns, strings.ToLower(pat))
			}
		case wafNodeScheduleMatch:
			sStr := strings.TrimSpace(raw.Config.ScheduleStart)
			eStr := strings.TrimSpace(raw.Config.ScheduleEnd)
			if sStr == "" {
				sStr = "09:00"
			}
			if eStr == "" {
				eStr = "23:00"
			}
			sMin, sOK := parseScheduleMinute(sStr)
			eMin, eOK := parseScheduleMinute(eStr)
			if !sOK || !eOK || sMin == eMin {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的开放时段格式无效（请使用两个不同的 HH:MM 时间）", label)
			}
			normCfg.ScheduleStart = formatScheduleMinute(sMin)
			normCfg.ScheduleEnd = formatScheduleMinute(eMin)
			cn.schedStart = sMin
			cn.schedEnd = eMin
		case wafNodeBlock:
			code := raw.Config.StatusCode
			if code == 0 {
				code = http.StatusForbidden
			}
			if code < 400 || code > 599 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的拦截状态码必须在 400–599 之间", label)
			}
			msg := truncateRunes(strings.TrimSpace(raw.Config.Message), 200)
			if msg == "" {
				msg = "blocked by WAF rule"
			}
			normCfg.StatusCode = code
			normCfg.Message = msg
			cn.statusCode = code
			cn.message = msg
		}

		idxByID[id] = len(compiledNodes)
		compiledNodes = append(compiledNodes, cn)
		normNodes = append(normNodes, wafGraphNode{
			ID:     id,
			Type:   nodeType,
			Label:  label,
			X:      raw.X,
			Y:      raw.Y,
			Config: normCfg,
		})
	}

	if startIdx < 0 {
		return wafRuleRecord{}, nil, errors.New("规则图缺少「请求入口」节点")
	}

	normEdges := make([]wafGraphEdge, 0, len(rec.Graph.Edges))
	seenOutPort := make(map[string]struct{}, len(rec.Graph.Edges))
	adj := make([][]int, len(compiledNodes))

	for i, raw := range rec.Graph.Edges {
		srcID := strings.TrimSpace(raw.Source)
		dstID := strings.TrimSpace(raw.Target)
		port := strings.ToLower(strings.TrimSpace(raw.SourcePort))
		srcIdx, srcOK := idxByID[srcID]
		dstIdx, dstOK := idxByID[dstID]
		if !srcOK || !dstOK {
			return wafRuleRecord{}, nil, errors.New("存在指向不存在节点的连线，请检查画布连接")
		}
		if srcIdx == dstIdx {
			return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」不能连接到自身", compiledNodes[srcIdx].label)
		}
		srcType := compiledNodes[srcIdx].nodeType
		if compiledNodes[dstIdx].nodeType == wafNodeStart {
			return wafRuleRecord{}, nil, errors.New("不允许将连线指回「请求入口」节点")
		}
		switch srcType {
		case wafNodeStart:
			if port == "" {
				port = "next"
			}
			if port != "next" {
				return wafRuleRecord{}, nil, errors.New("「请求入口」节点仅支持单一输出端口")
			}
		case wafNodePass, wafNodeBlock:
			return wafRuleRecord{}, nil, fmt.Errorf("终结节点「%s」不允许向外连线", compiledNodes[srcIdx].label)
		default:
			if port != "true" && port != "false" {
				return wafRuleRecord{}, nil, fmt.Errorf("条件节点「%s」的出口必须为「命中」或「未命中」", compiledNodes[srcIdx].label)
			}
		}

		portKey := srcID + ":" + port
		if _, dup := seenOutPort[portKey]; dup {
			return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的同一出口不能重复连接多条线", compiledNodes[srcIdx].label)
		}
		seenOutPort[portKey] = struct{}{}

		edgeID := strings.TrimSpace(raw.ID)
		if edgeID == "" || len(edgeID) > 64 {
			edgeID = fmt.Sprintf("e_%d", i+1)
		}

		switch port {
		case "next":
			compiledNodes[srcIdx].nextIdx = dstIdx
			compiledNodes[srcIdx].nextEdgeID = edgeID
		case "true":
			compiledNodes[srcIdx].trueIdx = dstIdx
			compiledNodes[srcIdx].trueEdgeID = edgeID
		case "false":
			compiledNodes[srcIdx].falseIdx = dstIdx
			compiledNodes[srcIdx].falseEdgeID = edgeID
		}
		adj[srcIdx] = append(adj[srcIdx], dstIdx)
		normEdges = append(normEdges, wafGraphEdge{
			ID:         edgeID,
			Source:     srcID,
			SourcePort: port,
			Target:     dstID,
		})
	}

	// Cycle detection (3-color DFS across entire graph)
	color := make([]uint8, len(compiledNodes)) // 0=unvisited, 1=visiting, 2=done
	var hasCycle func(u int) bool
	hasCycle = func(u int) bool {
		color[u] = 1
		for _, v := range adj[u] {
			if color[v] == 1 {
				return true
			}
			if color[v] == 0 && hasCycle(v) {
				return true
			}
		}
		color[u] = 2
		return false
	}
	for i := range compiledNodes {
		if color[i] == 0 && hasCycle(i) {
			return wafRuleRecord{}, nil, errors.New("规则图存在循环连线，请移除闭环后保存")
		}
	}

	// Reachability & dangling outlet validation from start node
	reachable := make([]bool, len(compiledNodes))
	queue := []int{startIdx}
	reachable[startIdx] = true
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		cn := compiledNodes[u]
		switch cn.nodeType {
		case wafNodeStart:
			if cn.nextIdx < 0 {
				return wafRuleRecord{}, nil, errors.New("「请求入口」节点尚未连线到下一个节点")
			}
		case wafNodeHostMatch, wafNodeIPMatch, wafNodeGeoMatch, wafNodePathMatch, wafNodePlayerMatch, wafNodeScheduleMatch:
			if cn.trueIdx < 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的「命中」分支尚未连线", cn.label)
			}
			if cn.falseIdx < 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」的「未命中」分支尚未连线", cn.label)
			}
			if cn.nodeType == wafNodeHostMatch && len(cn.hosts) == 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」请至少填写 1 个目标域名或域名后缀", cn.label)
			}
			if cn.nodeType == wafNodeIPMatch && len(cn.prefixes) == 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」请至少填写 1 条 IP 或 CIDR", cn.label)
			}
			if cn.nodeType == wafNodeGeoMatch && len(cn.countries) == 0 && !cn.matchUnknownGeo {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」请至少选择 1 个国家或地区", cn.label)
			}
			if cn.nodeType == wafNodePathMatch && len(cn.patterns) == 0 && len(cn.regexps) == 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」请至少填写 1 条路径或特征规则", cn.label)
			}
			if cn.nodeType == wafNodePlayerMatch && len(cn.patterns) == 0 {
				return wafRuleRecord{}, nil, fmt.Errorf("节点「%s」请至少填写 1 个客户端或 UA 关键词", cn.label)
			}
		}
		for _, v := range adj[u] {
			if !reachable[v] {
				reachable[v] = true
				queue = append(queue, v)
			}
		}
	}

	rec.Graph = wafRuleGraph{Nodes: normNodes, Edges: normEdges}
	compiled := &compiledWAFRule{
		id:       rec.ID,
		name:     rec.Name,
		isGlobal: rec.IsGlobal,
		usesGeo:  usesGeo,
		startIdx: startIdx,
		nodes:    compiledNodes,
	}
	return rec, compiled, nil
}

func (c *compiledWAFRule) Evaluate(req wafEvalContext, trace bool) wafEvalDecision {
	if c == nil || c.startIdx < 0 || c.startIdx >= len(c.nodes) {
		return wafEvalDecision{}
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	var traceNodes []string
	var traceEdges []string
	idx := c.startIdx
	maxSteps := len(c.nodes) + 1

	for step := 0; step < maxSteps && idx >= 0 && idx < len(c.nodes); step++ {
		node := c.nodes[idx]
		if trace {
			traceNodes = append(traceNodes, node.id)
		}
		switch node.nodeType {
		case wafNodeStart:
			if trace && node.nextEdgeID != "" {
				traceEdges = append(traceEdges, node.nextEdgeID)
			}
			idx = node.nextIdx
		case wafNodePass:
			return wafEvalDecision{
				Blocked:    false,
				RuleID:     c.id,
				RuleName:   c.name,
				NodeLabel:  node.label,
				TraceNodes: traceNodes,
				TraceEdges: traceEdges,
			}
		case wafNodeBlock:
			return wafEvalDecision{
				Blocked:    true,
				StatusCode: node.statusCode,
				Message:    node.message,
				RuleID:     c.id,
				RuleName:   c.name,
				NodeLabel:  node.label,
				TraceNodes: traceNodes,
				TraceEdges: traceEdges,
			}
		default:
			matched := node.matches(req, now)
			if matched {
				if trace && node.trueEdgeID != "" {
					traceEdges = append(traceEdges, node.trueEdgeID)
				}
				idx = node.trueIdx
			} else {
				if trace && node.falseEdgeID != "" {
					traceEdges = append(traceEdges, node.falseEdgeID)
				}
				idx = node.falseIdx
			}
		}
	}
	return wafEvalDecision{TraceNodes: traceNodes, TraceEdges: traceEdges}
}

func fromHexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func lenientQueryUnescape(raw string) string {
	if !strings.ContainsAny(raw, "%+") {
		return raw
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '+' {
			b.WriteByte(' ')
			continue
		}
		if c == '%' && i+2 < len(raw) {
			hi, ok1 := fromHexDigit(raw[i+1])
			lo, ok2 := fromHexDigit(raw[i+2])
			if ok1 && ok2 {
				b.WriteByte((hi << 4) | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func (n compiledWAFNode) matches(req wafEvalContext, now time.Time) bool {
	switch n.nodeType {
	case wafNodeHostMatch:
		host := normalizeWAFHostPattern(req.TargetHost)
		if host == "" {
			return false
		}
		for _, rule := range n.hosts {
			if host == rule || strings.HasSuffix(host, "."+rule) {
				return true
			}
		}
		return false
	case wafNodeIPMatch:
		raw := strings.Trim(strings.TrimSpace(req.ClientIP), "[]")
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		for _, prefix := range n.prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	case wafNodeGeoMatch:
		code := strings.ToUpper(strings.TrimSpace(req.CountryCode))
		if code == "" || code == "XX" || code == "T1" {
			return n.matchUnknownGeo
		}
		_, ok := n.countries[code]
		return ok
	case wafNodePathMatch:
		rawPath := req.Path
		if rawPath == "" {
			rawPath = "/"
		}
		decodedPath := rawPath
		if unesc, uErr := url.PathUnescape(rawPath); uErr == nil {
			decodedPath = unesc
		}
		// Normalize dot segments & duplicate slashes so //secret, /./secret, /x/../secret, /.%65nv cannot bypass WAF.
		cleanRawPath := path.Clean("/" + strings.ReplaceAll(rawPath, "\\", "/"))
		cleanDecodedPath := path.Clean("/" + strings.ReplaceAll(decodedPath, "\\", "/"))
		pathCandidates := []string{rawPath, cleanRawPath, decodedPath, cleanDecodedPath}

		rawQuery := req.RawQuery
		decodedQuery := rawQuery
		if rawQuery != "" {
			decodedQuery = lenientQueryUnescape(rawQuery)
		}
		fullCandidates := make([]string, 0, len(pathCandidates)*3)
		for _, pc := range pathCandidates {
			fullCandidates = append(fullCandidates, pc)
			if rawQuery != "" {
				fullCandidates = append(fullCandidates, pc+"?"+rawQuery)
				if decodedQuery != rawQuery {
					fullCandidates = append(fullCandidates, pc+"?"+decodedQuery)
				}
			}
		}
		if n.matchMode == "regex" {
			for _, re := range n.regexps {
				for _, cand := range fullCandidates {
					if re.MatchString(cand) {
						return true
					}
				}
			}
			return false
		}
		for _, pat := range n.patterns {
			if n.matchMode == "prefix" {
				for _, pc := range pathCandidates {
					if strings.HasPrefix(strings.ToLower(pc), pat) {
						return true
					}
				}
			} else {
				for _, fc := range fullCandidates {
					if strings.Contains(strings.ToLower(fc), pat) {
						return true
					}
				}
			}
		}
		return false
	case wafNodePlayerMatch:
		lowerUA := strings.ToLower(strings.TrimSpace(req.UserAgent))
		lowerClient := strings.ToLower(strings.TrimSpace(req.ClientName))
		for _, pat := range n.patterns {
			if (lowerClient != "" && strings.Contains(lowerClient, pat)) ||
				(lowerUA != "" && strings.Contains(lowerUA, pat)) {
				return true
			}
		}
		return false
	case wafNodeScheduleMatch:
		if n.schedStart < 0 || n.schedEnd < 0 || n.schedStart == n.schedEnd {
			return false
		}
		localNow := inApplicationTimezone(now)
		minute := localNow.Hour()*60 + localNow.Minute()
		if n.schedStart < n.schedEnd {
			return minute >= n.schedStart && minute < n.schedEnd
		}
		return minute >= n.schedStart || minute < n.schedEnd
	default:
		return false
	}
}

func compileWAFRulesList(records []wafRuleRecord) ([]*compiledWAFRule, bool) {
	if len(records) == 0 {
		return nil, false
	}
	out := make([]*compiledWAFRule, 0, len(records))
	usesGeo := false
	for _, rec := range records {
		if !rec.Enabled {
			continue
		}
		_, compiled, err := normalizeAndCompileWAFRule(rec)
		if err != nil || compiled == nil {
			continue
		}
		if compiled.usesGeo {
			usesGeo = true
		}
		out = append(out, compiled)
	}
	return out, usesGeo
}

func evaluateWAFRules(rules []*compiledWAFRule, req wafEvalContext) wafEvalDecision {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if decision := rule.Evaluate(req, false); decision.Blocked {
			return decision
		}
	}
	return wafEvalDecision{}
}

// EvaluateGeoOnly walks the compiled WAF graph considering ONLY geo_match (and ip_match bypasses),
// returning Blocked=true strictly when a path passing through at least one geo_match node reaches
// a block action without depending on player, target host, path, or schedule conditions.
// This powers the friendly homepage region-unavailable notice without causing false positives
// for browsers on player/host/path rules.
func (c *compiledWAFRule) EvaluateGeoOnly(countryCode, clientIP string, now time.Time) wafEvalDecision {
	if c == nil || !c.usesGeo || c.startIdx < 0 || c.startIdx >= len(c.nodes) {
		return wafEvalDecision{}
	}
	req := wafEvalContext{
		CountryCode: countryCode,
		ClientIP:    clientIP,
		Now:         now,
	}
	idx := c.startIdx
	steps := 0
	maxSteps := len(c.nodes) + 2
	sawGeo := false
	for idx >= 0 && idx < len(c.nodes) && steps < maxSteps {
		steps++
		node := c.nodes[idx]
		switch node.nodeType {
		case wafNodeStart:
			idx = node.nextIdx
		case wafNodePass:
			return wafEvalDecision{}
		case wafNodeBlock:
			if !sawGeo {
				return wafEvalDecision{}
			}
			return wafEvalDecision{
				Blocked:    true,
				StatusCode: node.statusCode,
				Message:    node.message,
				RuleID:     c.id,
				RuleName:   c.name,
				NodeLabel:  node.label,
			}
		case wafNodeGeoMatch:
			sawGeo = true
			if node.matches(req, now) {
				idx = node.trueIdx
			} else {
				idx = node.falseIdx
			}
		case wafNodeIPMatch:
			if node.matches(req, now) {
				idx = node.trueIdx
			} else {
				idx = node.falseIdx
			}
		default:
			// Depends on player / target host / path / schedule — cannot determine geo-only block on homepage
			return wafEvalDecision{}
		}
	}
	return wafEvalDecision{}
}

func evaluateWAFRulesGeoOnly(rules []*compiledWAFRule, countryCode, clientIP string, now time.Time) wafEvalDecision {
	for _, rule := range rules {
		if rule == nil || !rule.usesGeo {
			continue
		}
		if decision := rule.EvaluateGeoOnly(countryCode, clientIP, now); decision.Blocked {
			return decision
		}
	}
	return wafEvalDecision{}
}

// EvaluateIPOnly evaluates ONLY ip_match -> block/pass paths on the WAF graph.
// Used on the public homepage (GET /) so explicitly banned abusive IPs remain rejected
// while player, host, path, schedule, and geo rules never lock browsers out of the landing page.
func (c *compiledWAFRule) EvaluateIPOnly(clientIP string) wafEvalDecision {
	if c == nil || c.startIdx < 0 || c.startIdx >= len(c.nodes) {
		return wafEvalDecision{}
	}
	req := wafEvalContext{ClientIP: clientIP}
	now := time.Now()
	idx := c.startIdx
	steps := 0
	maxSteps := len(c.nodes) + 2
	sawIP := false
	for idx >= 0 && idx < len(c.nodes) && steps < maxSteps {
		steps++
		node := c.nodes[idx]
		switch node.nodeType {
		case wafNodeStart:
			idx = node.nextIdx
		case wafNodePass:
			return wafEvalDecision{}
		case wafNodeBlock:
			if !sawIP {
				return wafEvalDecision{}
			}
			return wafEvalDecision{
				Blocked:    true,
				StatusCode: node.statusCode,
				Message:    node.message,
				RuleID:     c.id,
				RuleName:   c.name,
				NodeLabel:  node.label,
			}
		case wafNodeIPMatch:
			sawIP = true
			if node.matches(req, now) {
				idx = node.trueIdx
			} else {
				idx = node.falseIdx
			}
		default:
			return wafEvalDecision{}
		}
	}
	return wafEvalDecision{}
}

func evaluateWAFRulesIPOnly(rules []*compiledWAFRule, clientIP string) wafEvalDecision {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if decision := rule.EvaluateIPOnly(clientIP); decision.Blocked {
			return decision
		}
	}
	return wafEvalDecision{}
}

/* -------------------- SQLite Store for WAF Rules -------------------- */

func scanWAFRule(scanner rowScanner) (wafRuleRecord, error) {
	var rec wafRuleRecord
	var enabledInt, globalInt int
	var graphRaw string
	err := scanner.Scan(
		&rec.ID, &rec.Name, &rec.Description, &enabledInt, &globalInt, &graphRaw, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		return wafRuleRecord{}, err
	}
	rec.Enabled = enabledInt == 1
	rec.IsGlobal = globalInt == 1
	if strings.TrimSpace(graphRaw) != "" {
		_ = json.Unmarshal([]byte(graphRaw), &rec.Graph)
	}
	if len(rec.Graph.Nodes) == 0 {
		rec.Graph = defaultWAFRuleGraph()
	}
	return rec, nil
}

func (s *telemetryStore) ListWAFRules(ctx context.Context) ([]wafRuleRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+wafRuleSelectCols+` FROM waf_rules ORDER BY is_global DESC, created_at DESC, name COLLATE NOCASE ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]wafRuleRecord, 0)
	for rows.Next() {
		rec, err := scanWAFRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *telemetryStore) GetWAFRule(ctx context.Context, id string) (wafRuleRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+wafRuleSelectCols+` FROM waf_rules WHERE id=?`, strings.TrimSpace(id))
	return scanWAFRule(row)
}

func (s *telemetryStore) CreateWAFRule(ctx context.Context, rec wafRuleRecord) (wafRuleRecord, error) {
	norm, _, err := normalizeAndCompileWAFRule(rec)
	if err != nil {
		return wafRuleRecord{}, err
	}
	rawID, err := generateRandomHex(8)
	if err != nil {
		return wafRuleRecord{}, err
	}
	norm.ID = "waf_" + rawID
	now := time.Now().Unix()
	norm.CreatedAt = now
	norm.UpdatedAt = now
	graphJSON, err := json.Marshal(norm.Graph)
	if err != nil {
		return wafRuleRecord{}, err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO waf_rules(id,name,description,enabled,is_global,graph_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		norm.ID, norm.Name, norm.Description, boolToInt(norm.Enabled), boolToInt(norm.IsGlobal), string(graphJSON), norm.CreatedAt, norm.UpdatedAt,
	)
	if err != nil {
		return wafRuleRecord{}, err
	}
	return s.GetWAFRule(ctx, norm.ID)
}

func (s *telemetryStore) UpdateWAFRule(ctx context.Context, id string, rec wafRuleRecord) (wafRuleRecord, error) {
	norm, _, err := normalizeAndCompileWAFRule(rec)
	if err != nil {
		return wafRuleRecord{}, err
	}
	now := time.Now().Unix()
	graphJSON, err := json.Marshal(norm.Graph)
	if err != nil {
		return wafRuleRecord{}, err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE waf_rules
		SET name=?, description=?, enabled=?, is_global=?, graph_json=?, updated_at=?
		WHERE id=?`,
		norm.Name, norm.Description, boolToInt(norm.Enabled), boolToInt(norm.IsGlobal), string(graphJSON), now, strings.TrimSpace(id),
	)
	if err != nil {
		return wafRuleRecord{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return wafRuleRecord{}, sql.ErrNoRows
	}
	return s.GetWAFRule(ctx, id)
}

func (s *telemetryStore) DeleteWAFRule(ctx context.Context, id string) ([]string, error) {
	id = strings.TrimSpace(id)
	res, err := s.db.ExecContext(ctx, `DELETE FROM waf_rules WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows == 0 {
		return nil, sql.ErrNoRows
	}
	// Cleanly detach deleted WAF rule ID from any bound edge domains
	affectedNodes := make([]string, 0)
	if domains, dErr := s.ListEdgeDomains(ctx); dErr == nil {
		now := time.Now().Unix()
		for _, dom := range domains {
			nextIDs := make([]string, 0, len(dom.WAFRuleIDs))
			changed := false
			for _, rid := range dom.WAFRuleIDs {
				if rid == id {
					changed = true
					continue
				}
				nextIDs = append(nextIDs, rid)
			}
			if !changed {
				continue
			}
			raw, _ := json.Marshal(nextIDs)
			_, _ = s.db.ExecContext(ctx, `UPDATE edge_domains SET waf_rule_ids_json=?, updated_at=? WHERE id=?`, string(raw), now, dom.ID)
			affectedNodes = append(affectedNodes, dom.NodeIDs...)
		}
	}
	return affectedNodes, nil
}

func (g *Gateway) reloadWAFRules(ctx context.Context) {
	if g == nil || g.telemetry == nil {
		return
	}
	rules, err := g.telemetry.ListWAFRules(ctx)
	if err != nil {
		return
	}
	globals := make([]wafRuleRecord, 0)
	for _, r := range rules {
		if r.Enabled && r.IsGlobal {
			globals = append(globals, r)
		}
	}
	compiled, _ := compileWAFRulesList(globals)
	g.globalWAFRules.Store(&compiled)
}

/* -------------------- Admin API (/_admin/api/waf-rules*) -------------------- */

type wafRuleMutationRequest struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Enabled     *bool        `json:"enabled"`
	IsGlobal    *bool        `json:"is_global"`
	Graph       wafRuleGraph `json:"graph"`
}

func (a *adminServer) buildWAFRulesListResponse(ctx context.Context) (wafRulesListResponse, error) {
	rules, err := a.store.ListWAFRules(ctx)
	if err != nil {
		return wafRulesListResponse{}, err
	}
	domains, _ := a.store.ListEdgeDomains(ctx)
	domainsByRule := make(map[string][]wafBoundDomainBrief)
	boundDomainSet := make(map[string]struct{})
	for _, dom := range domains {
		for _, rid := range dom.WAFRuleIDs {
			domainsByRule[rid] = append(domainsByRule[rid], wafBoundDomainBrief{
				ID: dom.ID, Domain: dom.Domain, Name: dom.Name,
			})
			boundDomainSet[dom.ID] = struct{}{}
		}
	}

	var summary wafRulesSummary
	summary.Total = len(rules)
	summary.BoundDomains = len(boundDomainSet)
	views := make([]wafRuleView, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			summary.Enabled++
		}
		if r.IsGlobal {
			summary.Global++
		}
		bound := domainsByRule[r.ID]
		if bound == nil {
			bound = []wafBoundDomainBrief{}
		}
		views = append(views, wafRuleView{
			wafRuleRecord: r,
			BoundDomains:  bound,
			Summary:       summarizeWAFRuleGraph(r.Graph),
			NodeCount:     len(r.Graph.Nodes),
		})
	}
	return wafRulesListResponse{Summary: summary, Rules: views}, nil
}

func (a *adminServer) handleWAFRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		res, err := a.buildWAFRulesListResponse(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load WAF rules")
			return
		}
		a.writeJSON(w, http.StatusOK, res)
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req wafRuleMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		isGlobal := false
		if req.IsGlobal != nil {
			isGlobal = *req.IsGlobal
		}
		created, err := a.store.CreateWAFRule(r.Context(), wafRuleRecord{
			Name:        req.Name,
			Description: req.Description,
			Enabled:     enabled,
			IsGlobal:    isGlobal,
			Graph:       req.Graph,
		})
		if err != nil {
			a.auditRequest(r, "waf_rule.create", req.Name, err.Error(), false)
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.reloadWAFRules(r.Context())
		a.gateway.notifyClusterConfigChanged("")
		a.auditRequest(r, "waf_rule.create", created.Name, fmt.Sprintf("id=%s global=%t nodes=%d", created.ID, created.IsGlobal, len(created.Graph.Nodes)), true)
		list, _ := a.buildWAFRulesListResponse(r.Context())
		for _, v := range list.Rules {
			if v.ID == created.ID {
				a.writeJSON(w, http.StatusCreated, v)
				return
			}
		}
		a.writeJSON(w, http.StatusCreated, created)
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleWAFRuleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var req struct {
		Name        string       `json:"name"`
		Graph       wafRuleGraph `json:"graph"`
		TargetHost  string       `json:"target_host"`
		ClientIP    string       `json:"client_ip"`
		CountryCode string       `json:"country_code"`
		Path        string       `json:"path"`
		UserAgent   string       `json:"user_agent"`
		ClientName  string       `json:"client_name"`
		TimeHHMM    string       `json:"time_hhmm"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "模拟测试"
	}
	_, compiled, err := normalizeAndCompileWAFRule(wafRuleRecord{Name: name, Enabled: true, Graph: req.Graph})
	if err != nil {
		a.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	evalNow := time.Now()
	if minVal, ok := parseScheduleMinute(strings.TrimSpace(req.TimeHHMM)); ok {
		locNow := inApplicationTimezone(evalNow)
		evalNow = time.Date(locNow.Year(), locNow.Month(), locNow.Day(), minVal/60, minVal%60, 0, 0, applicationLocation)
	}
	pathVal := strings.TrimSpace(req.Path)
	rawQuery := ""
	if p, q, found := strings.Cut(pathVal, "?"); found {
		pathVal = p
		rawQuery = q
	}
	if pathVal == "" {
		pathVal = "/"
	}
	decision := compiled.Evaluate(wafEvalContext{
		TargetHost:  strings.TrimSpace(req.TargetHost),
		ClientIP:    strings.TrimSpace(req.ClientIP),
		CountryCode: strings.ToUpper(strings.TrimSpace(req.CountryCode)),
		Path:        pathVal,
		RawQuery:    rawQuery,
		UserAgent:   req.UserAgent,
		ClientName:  req.ClientName,
		Now:         evalNow,
	}, true)
	a.writeJSON(w, http.StatusOK, decision)
}

type wafDetectedPlayer struct {
	Name     string `json:"name"`
	Requests int64  `json:"requests"`
	LastSeen int64  `json:"last_seen"`
	Active   bool   `json:"active"`
}

var defaultWAFPlayerPresets = []string{
	"SenPlayer", "Infuse", "VidHub", "Yamby", "Hills",
	"RodelPlayer", "CapyPlayer", "Forward", "AfuseKt", "Fileball",
	"Emby", "Jellyfin",
}

func (s *telemetryStore) ListDetectedPlayers(
	ctx context.Context,
	liveConns []connectionSnapshot,
	livePlaybacks []playbackSessionSnapshot,
) ([]wafDetectedPlayer, error) {
	type playerAgg struct {
		bestName      string
		bestNameScore int64
		requests      int64
		lastSeen      int64
		active        bool
	}
	byKey := make(map[string]*playerAgg)
	merge := func(rawName string, count int64, lastSeen int64, active bool) {
		name := strings.TrimSpace(rawName)
		if name == "" || len(name) > 96 {
			return
		}
		key := strings.ToLower(name)
		agg, ok := byKey[key]
		if !ok {
			agg = &playerAgg{bestName: name, bestNameScore: count}
			byKey[key] = agg
		} else if count > agg.bestNameScore || (agg.bestNameScore == 0 && active) {
			agg.bestName = name
			agg.bestNameScore = count
		}
		agg.requests += count
		if lastSeen > agg.lastSeen {
			agg.lastSeen = lastSeen
		}
		if active {
			agg.active = true
		}
	}

	cutoff := time.Now().Add(-30 * 24 * time.Hour).Unix()
	if s != nil && s.db != nil {
		if rows, err := s.db.QueryContext(ctx, `
			SELECT TRIM(client_name) AS cname, COUNT(*) AS cnt, MAX(timestamp) AS last_ts
			FROM request_logs
			WHERE TRIM(client_name) != '' AND timestamp >= ?
			GROUP BY TRIM(client_name)
			ORDER BY cnt DESC, last_ts DESC
			LIMIT 80`, cutoff); err == nil {
			for rows.Next() {
				var name string
				var cnt, ts int64
				if rows.Scan(&name, &cnt, &ts) == nil {
					merge(name, cnt, ts, false)
				}
			}
			_ = rows.Close()
		}
		if rows, err := s.db.QueryContext(ctx, `
			SELECT TRIM(client_name) AS cname, COUNT(*) AS cnt, MAX(last_seen_at) AS last_ts
			FROM watch_history
			WHERE TRIM(client_name) != '' AND last_seen_at >= ?
			GROUP BY TRIM(client_name)
			ORDER BY cnt DESC, last_ts DESC
			LIMIT 80`, cutoff); err == nil {
			for rows.Next() {
				var name string
				var cnt, ts int64
				if rows.Scan(&name, &cnt, &ts) == nil {
					merge(name, cnt, ts, false)
				}
			}
			_ = rows.Close()
		}
	}

	nowSec := time.Now().Unix()
	for _, conn := range liveConns {
		if strings.TrimSpace(conn.ClientName) != "" {
			merge(conn.ClientName, 0, nowSec, true)
		}
	}
	for _, pb := range livePlaybacks {
		if strings.TrimSpace(pb.ClientName) != "" {
			ts := pb.LastSeenAt
			if ts <= 0 {
				ts = nowSec
			}
			merge(pb.ClientName, 0, ts, true)
		}
	}

	out := make([]wafDetectedPlayer, 0, len(byKey))
	for _, agg := range byKey {
		out = append(out, wafDetectedPlayer{
			Name:     agg.bestName,
			Requests: agg.requests,
			LastSeen: agg.lastSeen,
			Active:   agg.active,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if len(out) > 40 {
		out = out[:40]
	}
	return out, nil
}

func (a *adminServer) handleWAFRuleDetectedPlayers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.methodNotAllowed(w, http.MethodGet)
		return
	}
	var localConns []connectionSnapshot
	if a.gateway != nil && a.gateway.connections != nil {
		localConns = a.gateway.connections.Snapshot()
	}
	var localPlaybacks []playbackSessionSnapshot
	if a.gateway != nil && a.gateway.playback != nil {
		localPlaybacks = a.gateway.playback.Snapshot()
	}
	allConns := localConns
	allPlaybacks := localPlaybacks
	if a.gateway != nil && a.gateway.cluster != nil {
		allConns = a.gateway.cluster.AggregateConnections(r.Context(), localConns, "")
		allPlaybacks = a.gateway.cluster.AggregatePlaybacks(r.Context(), localPlaybacks, "")
	}
	players, err := a.store.ListDetectedPlayers(r.Context(), allConns, allPlaybacks)
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "failed to load detected players")
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"players": players,
		"presets": defaultWAFPlayerPresets,
	})
}

func (a *adminServer) handleWAFRuleItem(w http.ResponseWriter, r *http.Request) {
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/waf-rules/")
	if remainder == "simulate" {
		a.handleWAFRuleSimulate(w, r)
		return
	}
	if remainder == "detected-players" {
		a.handleWAFRuleDetectedPlayers(w, r)
		return
	}
	ruleID := strings.TrimSpace(remainder)
	if ruleID == "" || strings.Contains(ruleID, "/") || len(ruleID) > 48 {
		a.writeError(w, http.StatusBadRequest, "invalid WAF rule id")
		return
	}

	switch r.Method {
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetWAFRule(r.Context(), ruleID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "WAF rule not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load WAF rule")
			return
		}
		var req wafRuleMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		next := existing
		if strings.TrimSpace(req.Name) != "" {
			next.Name = req.Name
		}
		next.Description = req.Description
		if req.Enabled != nil {
			next.Enabled = *req.Enabled
		}
		if req.IsGlobal != nil {
			next.IsGlobal = *req.IsGlobal
		}
		if len(req.Graph.Nodes) > 0 {
			next.Graph = req.Graph
		}
		updated, err := a.store.UpdateWAFRule(r.Context(), ruleID, next)
		if err != nil {
			a.auditRequest(r, "waf_rule.update", next.Name, err.Error(), false)
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.reloadWAFRules(r.Context())
		a.gateway.notifyClusterConfigChanged("")
		a.auditRequest(r, "waf_rule.update", updated.Name, fmt.Sprintf("id=%s enabled=%t global=%t nodes=%d", updated.ID, updated.Enabled, updated.IsGlobal, len(updated.Graph.Nodes)), true)
		list, _ := a.buildWAFRulesListResponse(r.Context())
		for _, v := range list.Rules {
			if v.ID == updated.ID {
				a.writeJSON(w, http.StatusOK, v)
				return
			}
		}
		a.writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetWAFRule(r.Context(), ruleID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "WAF rule not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load WAF rule")
			return
		}
		if _, err := a.store.DeleteWAFRule(r.Context(), ruleID); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete WAF rule")
			return
		}
		a.gateway.reloadWAFRules(r.Context())
		a.gateway.notifyClusterConfigChanged("")
		a.auditRequest(r, "waf_rule.delete", existing.Name, "id="+ruleID, true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.methodNotAllowed(w, http.MethodPut+", "+http.MethodDelete)
	}
}
