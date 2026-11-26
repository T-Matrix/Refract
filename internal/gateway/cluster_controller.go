package gateway

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxAgentTelemetryBodyBytes = 2 << 20
	maxAgentTelemetryEvents    = 1000
	agentCommandTTL            = 30 * time.Second
)

type queuedAgentCommand struct {
	event     agentSSEEvent
	createdAt time.Time
}

type edgeNodeLiveState struct {
	lastSeen        time.Time
	metrics         edgeNodeMetrics
	connections     []connectionSnapshot
	playbacks       []playbackSessionSnapshot
	kickedPlaybacks map[string]time.Time
	commands        []queuedAgentCommand
	blockedTotal    uint64
	droppedTotal    uint64
}

type clusterController struct {
	gateway    *Gateway
	store      *telemetryStore
	discovery  *clusterDiscoveryManager
	certCipher *tokenCipher
	acme       *controllerACMEIssuer

	revision atomic.Int64

	mu          sync.RWMutex
	closed      bool
	live        map[string]*edgeNodeLiveState
	subscribers map[string]map[chan agentSSEEvent]struct{}

	monitorMu      sync.Mutex
	offlineAlerted map[string]bool
	tlsAlerted     map[string]time.Time
	hbDNSSyncBusy  atomic.Bool
	hbDNSSyncDirty atomic.Bool
	hbDNSSyncMu    sync.Mutex
	hbDNSSyncNodes map[string]edgeNodeRecord

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newClusterController(gateway *Gateway, store *telemetryStore) *clusterController {
	ctx, cancel := context.WithCancel(context.Background())
	discovery, _ := newClusterDiscoveryManager(store, gateway.cfg.AdminSessionSecret)
	certCipher, _ := newScopedTokenCipher(gateway.cfg.AdminSessionSecret, "edge-domain-certs")
	acmeIssuer, _ := newControllerACMEIssuer(store, gateway, gateway.cfg.AdminSessionSecret, certCipher)
	store.MigrateLegacyNodeDomains(context.Background())

	c := &clusterController{
		gateway:        gateway,
		store:          store,
		discovery:      discovery,
		certCipher:     certCipher,
		acme:           acmeIssuer,
		live:           make(map[string]*edgeNodeLiveState),
		subscribers:    make(map[string]map[chan agentSSEEvent]struct{}),
		offlineAlerted: make(map[string]bool),
		tlsAlerted:     make(map[string]time.Time),
		hbDNSSyncNodes: make(map[string]edgeNodeRecord),
		ctx:            ctx,
		cancel:         cancel,
	}
	c.revision.Store(time.Now().Unix())
	c.wg.Add(1)
	go c.runMonitorLoop()
	return c
}

func (c *clusterController) runTracked(fn func()) {
	if c == nil || fn == nil {
		return
	}
	c.mu.RLock()
	if c.closed || c.ctx.Err() != nil {
		c.mu.RUnlock()
		return
	}
	c.wg.Add(1)
	c.mu.RUnlock()
	go func() {
		defer c.wg.Done()
		fn()
	}()
}

func (c *clusterController) triggerDomainBackgroundTasks(dom edgeDomainRecord, oldDomain string) {
	if c == nil {
		return
	}
	if dom.DNSMode == domainDNSAxisNowSmart && c.gateway.axisnow != nil {
		dCopy, oldCopy := dom, oldDomain
		c.runTracked(func() {
			ctx, cancel := context.WithTimeout(c.ctx, 25*time.Second)
			defer cancel()
			if oldCopy != "" && oldCopy != dCopy.Domain && c.gateway.cloudflare != nil {
				_ = c.gateway.cloudflare.SyncEdgeDomainDNS(ctx, dCopy, oldCopy, time.Now())
			}
			_ = c.gateway.axisnow.SyncEdgeDomainSmartDNS(ctx, dCopy, time.Now())
		})
	} else if c.gateway.cloudflare != nil && dom.DNSMode != domainDNSManual {
		dCopy, oldCopy := dom, oldDomain
		c.runTracked(func() {
			ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
			defer cancel()
			_ = c.gateway.cloudflare.SyncEdgeDomainDNS(ctx, dCopy, oldCopy, time.Now())
		})
	}
	if c.acme != nil && dom.Enabled && dom.TLSMode == domainTLSAuto && len(dom.NodeIDs) > 0 && dom.CertPEM == "" {
		cf := c.store.LoadCloudflareDNS(context.Background())
		if cf.Enabled && cf.EncryptedToken != "" {
			if cf.RootDomain == "" && cf.ZoneID != "" && c.gateway.cloudflare != nil {
				resolveCtx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
				if resolved, _, rErr := c.gateway.cloudflare.activeCredentials(resolveCtx); rErr == nil && resolved.RootDomain != "" {
					cf = resolved
				}
				cancel()
			}
			if hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), cf.RootDomain) {
				_ = c.acme.StartIssuanceAsync(dom.ID)
			}
		}
	}
}

func (c *clusterController) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		for nodeID, subs := range c.subscribers {
			for ch := range subs {
				close(ch)
			}
			delete(c.subscribers, nodeID)
		}
		c.mu.Unlock()
		c.cancel()
		c.wg.Wait()
	})
}

func (c *clusterController) runMonitorLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			evalCtx, cancel := context.WithTimeout(c.ctx, 12*time.Second)
			c.EvaluateMonitorCycle(evalCtx, now)
			cancel()
		}
	}
}

func (c *clusterController) EvaluateMonitorCycle(ctx context.Context, now time.Time) {
	if c == nil || c.store == nil {
		return
	}
	nodes, err := c.store.ListEdgeNodes(ctx)
	if err != nil {
		return
	}
	alerts := c.store.LoadTelegramAlerts(ctx)
	offlineThreshold := time.Duration(alerts.OfflineThresholdSec) * time.Second
	if offlineThreshold < 15*time.Second {
		offlineThreshold = 60 * time.Second
	}

	type pendingAlert struct {
		kind        string
		title       string
		lines       []string
		offlineNode string
		tlsKey      string
		tlsAt       time.Time
	}
	var pendingAlerts []pendingAlert

	for _, node := range nodes {
		if node.TokenHash == "" {
			continue
		}
		_, online := c.nodeStatus(node, now)

		lastSeen := node.LastSeenAt
		var tlsStatus agentTLSStatus
		c.mu.RLock()
		if state := c.live[node.ID]; state != nil {
			if state.lastSeen.Unix() > lastSeen {
				lastSeen = state.lastSeen.Unix()
			}
			tlsStatus = state.metrics.agentTLSStatus
		}
		c.mu.RUnlock()

		// 1. Offline / Recovery alert with debounce (dispatched after DNS failover so slow Telegram never stalls failover).
		c.monitorMu.Lock()
		wasAlerted := c.offlineAlerted[node.ID]
		if !online {
			if lastSeen > 0 && now.Sub(time.Unix(lastSeen, 0)) >= offlineThreshold && !wasAlerted {
				c.monitorMu.Unlock()
				pendingAlerts = append(pendingAlerts, pendingAlert{
					kind:        "node_offline",
					title:       "边缘节点已离线",
					offlineNode: node.ID,
					lines: []string{
						fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
						fmt.Sprintf("入口：%s", node.PublicURL),
						fmt.Sprintf("最后心跳：%s", time.Unix(lastSeen, 0).In(applicationLocation).Format("2006-01-02 15:04:05")),
					},
				})
			} else {
				c.monitorMu.Unlock()
			}
		} else if wasAlerted {
			delete(c.offlineAlerted, node.ID)
			c.monitorMu.Unlock()
			pendingAlerts = append(pendingAlerts, pendingAlert{
				kind:  "node_offline",
				title: "边缘节点已恢复在线",
				lines: []string{
					fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
					fmt.Sprintf("入口：%s", node.PublicURL),
				},
			})
		} else {
			c.monitorMu.Unlock()
		}

		// 2. Monthly traffic quota evaluation & auto-drain protection.
		if node.MonthlyQuotaGB <= 0 {
			if (node.QuotaAutoDrained && node.Draining) || node.QuotaAlertLevel > 0 || node.QuotaAutoDrained {
				var nextDrain *bool
				if node.QuotaAutoDrained && node.Draining {
					f := false
					nextDrain = &f
				}
				if err := c.store.UpdateEdgeNodeQuotaState(ctx, node.ID, "", 0, false, nextDrain); err == nil && nextDrain != nil {
					c.NotifyConfigChanged(node.ID)
					pendingAlerts = append(pendingAlerts, pendingAlert{
						kind:  "node_quota",
						title: "节点月流量配额已取消，已恢复服务",
						lines: []string{
							fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
						},
					})
				}
			}
		} else {
			quotaBytes := monthlyQuotaGBToBytes(node.MonthlyQuotaGB)
			cycleKey, startUnix, _ := billingCycleWindow(now, node.QuotaResetDay)
			curCycle := node.QuotaCycleKey
			curAlertLevel := node.QuotaAlertLevel
			curAutoDrained := node.QuotaAutoDrained
			curDraining := node.Draining

			if curCycle != cycleKey {
				var nextDrain *bool
				nextDraining := curDraining
				if curAutoDrained && curDraining {
					f := false
					nextDrain = &f
					nextDraining = false
				}
				if err := c.store.UpdateEdgeNodeQuotaState(ctx, node.ID, cycleKey, 0, false, nextDrain); err == nil {
					curCycle = cycleKey
					curAlertLevel = 0
					curAutoDrained = false
					curDraining = nextDraining
					if nextDrain != nil {
						c.NotifyConfigChanged(node.ID)
						pendingAlerts = append(pendingAlerts, pendingAlert{
							kind:  "node_quota",
							title: "节点月流量周期重置，已恢复服务",
							lines: []string{
								fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
								fmt.Sprintf("新计费周期：%s", curCycle),
							},
						})
					}
				}
			}

			usedBytes, usageErr := c.store.NodeCycleTrafficUsage(ctx, node.ID, startUnix, node.QuotaDirection)
			if usageErr == nil && quotaBytes > 0 {
				pct := float64(usedBytes) * 100 / float64(quotaBytes)
				if pct < 100 && ((curAutoDrained && curDraining) || curAlertLevel >= 100) {
					nextAlert := 0
					if pct >= 80 {
						nextAlert = 80
					}
					var nextDrain *bool
					if curAutoDrained && curDraining {
						f := false
						nextDrain = &f
					}
					if err := c.store.UpdateEdgeNodeQuotaState(ctx, node.ID, curCycle, nextAlert, false, nextDrain); err == nil && nextDrain != nil {
						c.NotifyConfigChanged(node.ID)
						pendingAlerts = append(pendingAlerts, pendingAlert{
							kind:  "node_quota",
							title: "节点月流量配额调整后充足，已恢复服务",
							lines: []string{
								fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
								fmt.Sprintf("已用 / 上限：%s / %s (%.1f%%)", formatReportBytes(usedBytes), formatReportBytes(quotaBytes), pct),
							},
						})
					}
				} else if pct >= 100 && curAlertLevel < 100 {
					var nextDrain *bool
					autoDrained := curAutoDrained
					if node.QuotaAutoDrain && !curDraining {
						t := true
						nextDrain = &t
						autoDrained = true
					}
					if err := c.store.UpdateEdgeNodeQuotaState(ctx, node.ID, curCycle, 100, autoDrained, nextDrain); err == nil {
						if nextDrain != nil {
							c.NotifyConfigChanged(node.ID)
							c.store.RecordAudit(ctx, auditEntry{
								Username: "system",
								Action:   "node.quota.auto_drain",
								Resource: node.Name,
								Detail:   fmt.Sprintf("node_id=%s used=%s quota=%s", node.ID, formatReportBytes(usedBytes), formatReportBytes(quotaBytes)),
								Success:  true,
							})
						}
						actionText := "仅告警（未开启自动排空）"
						if nextDrain != nil || curDraining {
							actionText = "已自动进入排空停流状态"
						}
						pendingAlerts = append(pendingAlerts, pendingAlert{
							kind:  "node_quota",
							title: "节点月流量已用尽 (100%)",
							lines: []string{
								fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
								fmt.Sprintf("已用 / 上限：%s / %s (%.1f%%)", formatReportBytes(usedBytes), formatReportBytes(quotaBytes), pct),
								fmt.Sprintf("保护动作：%s", actionText),
							},
						})
					}
				} else if pct >= 80 && curAlertLevel < 80 {
					if err := c.store.UpdateEdgeNodeQuotaState(ctx, node.ID, curCycle, 80, curAutoDrained, nil); err == nil {
						pendingAlerts = append(pendingAlerts, pendingAlert{
							kind:  "node_quota",
							title: "节点月流量预警 (≥80%)",
							lines: []string{
								fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
								fmt.Sprintf("已用 / 上限：%s / %s (%.1f%%)", formatReportBytes(usedBytes), formatReportBytes(quotaBytes), pct),
							},
						})
					}
				}
			}
		}

		// 3. AutoTLS certificate error or near-expiry alert (24h cooldown).
		if online && tlsStatus.Mode == "auto" {
			alertKey := ""
			alertTitle := ""
			var alertLines []string
			if tlsStatus.Status == "error" && tlsStatus.Error != "" {
				alertKey = node.ID + ":error:" + tlsStatus.Domain
				alertTitle = "节点 HTTPS 证书签发异常"
				alertLines = []string{
					fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
					fmt.Sprintf("域名：%s", tlsStatus.Domain),
					fmt.Sprintf("错误：%s", tlsStatus.Error),
				}
			} else if tlsStatus.Status == "ready" && tlsStatus.NotAfter > 0 {
				remain := time.Unix(tlsStatus.NotAfter, 0).Sub(now)
				if remain > 0 && remain < 7*24*time.Hour {
					alertKey = node.ID + ":expiring:" + tlsStatus.Domain
					alertTitle = "节点 HTTPS 证书即将过期"
					alertLines = []string{
						fmt.Sprintf("节点：%s (%s)", node.Name, node.ID),
						fmt.Sprintf("域名：%s", tlsStatus.Domain),
						fmt.Sprintf("到期时间：%s", time.Unix(tlsStatus.NotAfter, 0).In(applicationLocation).Format("2006-01-02 15:04")),
					}
				}
			}
			if alertKey != "" {
				c.monitorMu.Lock()
				lastSent := c.tlsAlerted[alertKey]
				shouldSend := lastSent.IsZero() || now.Sub(lastSent) >= 24*time.Hour
				c.monitorMu.Unlock()
				if shouldSend {
					pendingAlerts = append(pendingAlerts, pendingAlert{
						kind:   "node_tls",
						title:  alertTitle,
						lines:  alertLines,
						tlsKey: alertKey,
						tlsAt:  now,
					})
				}
			}
		}
	}

	// 4. Cloudflare DNS Failover & Edge Domains DNS + AxisNow Smart DNS evaluation (runs BEFORE Telegram alerts).
	if c.gateway.cloudflare != nil {
		if _, err := c.gateway.cloudflare.EvaluateFailoverGroups(ctx, now); err != nil {
			log.Printf("cloudflare failover evaluation warning: %v", err)
		}
		if _, err := c.gateway.cloudflare.EvaluateEdgeDomainsDNS(ctx, now); err != nil {
			log.Printf("cloudflare edge domains dns evaluation warning: %v", err)
		}
	}
	if c.gateway.axisnow != nil {
		if _, err := c.gateway.axisnow.EvaluateEdgeDomainsSmartDNS(ctx, now); err != nil {
			log.Printf("axisnow smart dns evaluation warning: %v", err)
		}
	}

	// 5. Controller ACME DNS-01 automatic issuance & renewal (<30d).
	if c.acme != nil {
		c.acme.EnsureAutoRenewals(ctx, now)
	}

	// 6. Dispatch queued Telegram alerts with a bounded sub-context and only record debounce after success.
	if len(pendingAlerts) > 0 && c.gateway.telegram != nil {
		for _, alert := range pendingAlerts {
			alertCtx, alertCancel := context.WithTimeout(c.ctx, 4*time.Second)
			sendErr := c.gateway.telegram.SendAlert(alertCtx, alert.kind, alert.title, alert.lines)
			alertCancel()
			if sendErr == nil {
				c.monitorMu.Lock()
				if alert.offlineNode != "" {
					c.offlineAlerted[alert.offlineNode] = true
				}
				if alert.tlsKey != "" {
					c.tlsAlerted[alert.tlsKey] = alert.tlsAt
				}
				c.monitorMu.Unlock()
			}
		}
	}
}

func (c *clusterController) TriggerNodeUpgrade(nodeID string) bool {
	if c == nil || nodeID == "" {
		return false
	}
	event := agentSSEEvent{Type: "upgrade"}
	if c.publish(nodeID, event) > 0 {
		return true
	}
	c.mu.Lock()
	state := c.live[nodeID]
	recentlySeen := state != nil && time.Since(state.lastSeen) <= edgeNodeOnlineThresholdSeconds*time.Second
	if state != nil && recentlySeen {
		state.commands = append(state.commands, queuedAgentCommand{event: event, createdAt: time.Now()})
		if len(state.commands) > 64 {
			state.commands = state.commands[len(state.commands)-64:]
		}
	}
	c.mu.Unlock()
	return recentlySeen
}

func (c *clusterController) controllerBinarySHA256ForArch(arch string) string {
	targetOS, targetArch := runtime.GOOS, runtime.GOARCH
	if parts := strings.Split(strings.TrimSpace(arch), "/"); len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		targetOS, targetArch = strings.ToLower(parts[0]), strings.ToLower(parts[1])
	}
	binPath, err := c.resolveAgentBinaryPath(targetOS, targetArch)
	if err != nil {
		return ""
	}
	digest, _, err := fileSHA256Cached(binPath)
	if err != nil {
		return ""
	}
	return digest
}

func (c *clusterController) nextRevision() int64 {
	return c.revision.Add(1)
}

func (c *clusterController) currentRevision() int64 {
	return c.revision.Load()
}

const maxSSESubscribersPerNode = 4

func (c *clusterController) subscribe(nodeID string) (chan agentSSEEvent, bool) {
	ch := make(chan agentSSEEvent, 16)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, false
	}
	if c.subscribers[nodeID] == nil {
		c.subscribers[nodeID] = make(map[chan agentSSEEvent]struct{})
	}
	if len(c.subscribers[nodeID]) >= maxSSESubscribersPerNode {
		// Evict an existing stale stream so reconnect storms can't exhaust controller goroutines.
		for oldCh := range c.subscribers[nodeID] {
			delete(c.subscribers[nodeID], oldCh)
			close(oldCh)
			break
		}
	}
	c.subscribers[nodeID][ch] = struct{}{}
	return ch, true
}

func (c *clusterController) unsubscribe(nodeID string, ch chan agentSSEEvent) {
	c.mu.Lock()
	if subs := c.subscribers[nodeID]; subs != nil {
		delete(subs, ch)
		if len(subs) == 0 {
			delete(c.subscribers, nodeID)
		}
	}
	c.mu.Unlock()
}

func (c *clusterController) disconnectNode(nodeID string) {
	c.mu.Lock()
	if subs := c.subscribers[nodeID]; subs != nil {
		for ch := range subs {
			close(ch)
		}
		delete(c.subscribers, nodeID)
	}
	delete(c.live, nodeID)
	c.mu.Unlock()

	c.monitorMu.Lock()
	delete(c.offlineAlerted, nodeID)
	prefix := nodeID + ":"
	for k := range c.tlsAlerted {
		if strings.HasPrefix(k, prefix) {
			delete(c.tlsAlerted, k)
		}
	}
	c.monitorMu.Unlock()
}

func (c *clusterController) isNodeConnected(nodeID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.subscribers[nodeID]) > 0
}

func (c *clusterController) publish(nodeID string, event agentSSEEvent) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sent := 0
	sendTo := func(subs map[chan agentSSEEvent]struct{}) {
		for ch := range subs {
			select {
			case ch <- event:
				sent++
			default:
			}
		}
	}
	if nodeID == "" {
		for _, subs := range c.subscribers {
			sendTo(subs)
		}
		return sent
	}
	if subs := c.subscribers[nodeID]; subs != nil {
		sendTo(subs)
	}
	return sent
}

func (c *clusterController) NotifyConfigChanged(nodeID string) {
	if c == nil {
		return
	}
	rev := c.nextRevision()
	c.publish(nodeID, agentSSEEvent{Type: "config_changed", Revision: rev})
}

func (c *clusterController) CancelRemoteConnection(nodeID, flowID string) bool {
	if c == nil || nodeID == "" || flowID == "" {
		return false
	}
	event := agentSSEEvent{Type: "cancel_flow", FlowID: flowID}
	sent := c.publish(nodeID, event) > 0
	c.mu.Lock()
	state := c.live[nodeID]
	found := sent
	if state != nil {
		filteredConns := state.connections[:0]
		for _, conn := range state.connections {
			if conn.ID == flowID {
				found = true
				continue
			}
			filteredConns = append(filteredConns, conn)
		}
		state.connections = filteredConns
		if !sent && found {
			state.commands = append(state.commands, queuedAgentCommand{event: event, createdAt: time.Now()})
			if len(state.commands) > 64 {
				state.commands = state.commands[len(state.commands)-64:]
			}
		}
	}
	c.mu.Unlock()
	return found
}

func (c *clusterController) CancelRemotePlayback(nodeID, sessionKey, flowID string) bool {
	nodeID = strings.TrimSpace(nodeID)
	sessionKey = strings.TrimSpace(sessionKey)
	flowID = strings.TrimSpace(flowID)
	if c == nil || nodeID == "" || (sessionKey == "" && flowID == "") {
		return false
	}
	agentSessionKey := strings.TrimPrefix(sessionKey, nodeID+"|")
	stampedKey := sessionKey
	if sessionKey != "" && !strings.HasPrefix(stampedKey, nodeID+"|") {
		stampedKey = nodeID + "|" + agentSessionKey
	}

	var targetClientIP, targetUpstreamHost, targetItemID string
	if parts := strings.SplitN(agentSessionKey, "|", 4); len(parts) == 4 {
		targetClientIP = normalizeTelemetryClientIP(parts[0])
		targetUpstreamHost = strings.TrimSpace(parts[2])
		targetItemID = strings.TrimSpace(parts[3])
	}

	c.mu.Lock()
	state := c.live[nodeID]
	if state == nil {
		c.mu.Unlock()
		return false
	}
	for _, pb := range state.playbacks {
		if (stampedKey != "" && pb.SessionKey == stampedKey) ||
			(agentSessionKey != "" && pb.SessionKey == agentSessionKey) ||
			(flowID != "" && pb.FlowID == flowID) {
			if pb.ClientIP != "" {
				targetClientIP = normalizeTelemetryClientIP(pb.ClientIP)
			}
			if pb.UpstreamHost != "" {
				targetUpstreamHost = strings.TrimSpace(pb.UpstreamHost)
			}
			if pb.ItemID != "" {
				targetItemID = strings.TrimSpace(pb.ItemID)
			}
			break
		}
	}
	exp := time.Now().Add(10 * time.Second)
	if state.kickedPlaybacks == nil {
		state.kickedPlaybacks = make(map[string]time.Time)
	}
	if stampedKey != "" {
		state.kickedPlaybacks[stampedKey] = exp
	}
	var streamBlockKey string
	if targetClientIP != "" && targetUpstreamHost != "" && targetItemID != "" {
		streamBlockKey = nodeID + "|" + playbackStreamBlockKey(targetClientIP, targetUpstreamHost, targetItemID)
		state.kickedPlaybacks[streamBlockKey] = exp
	}
	filteredPB := make([]playbackSessionSnapshot, 0, len(state.playbacks))
	for _, pb := range state.playbacks {
		sameKey := (stampedKey != "" && pb.SessionKey == stampedKey) ||
			(agentSessionKey != "" && pb.SessionKey == agentSessionKey) ||
			(flowID != "" && pb.FlowID == flowID)
		sameStream := targetClientIP != "" && targetUpstreamHost != "" && targetItemID != "" &&
			normalizeTelemetryClientIP(pb.ClientIP) == targetClientIP &&
			strings.EqualFold(pb.UpstreamHost, targetUpstreamHost) &&
			pb.ItemID == targetItemID
		if sameKey || sameStream {
			continue
		}
		filteredPB = append(filteredPB, pb)
	}
	state.playbacks = filteredPB
	if flowID != "" {
		filteredConns := make([]connectionSnapshot, 0, len(state.connections))
		for _, conn := range state.connections {
			if conn.ID == flowID {
				continue
			}
			filteredConns = append(filteredConns, conn)
		}
		state.connections = filteredConns
	}
	c.mu.Unlock()

	event := agentSSEEvent{Type: "cancel_playback", SessionKey: agentSessionKey, FlowID: flowID}
	if c.publish(nodeID, event) == 0 {
		c.mu.Lock()
		if st := c.live[nodeID]; st != nil {
			st.commands = append(st.commands, queuedAgentCommand{event: event, createdAt: time.Now()})
			if len(st.commands) > 64 {
				st.commands = st.commands[len(st.commands)-64:]
			}
		}
		c.mu.Unlock()
	}
	return true
}

func (c *clusterController) CancelRemoteFlowByID(flowID string) (string, bool) {
	if c == nil || flowID == "" {
		return "", false
	}
	c.mu.RLock()
	var targetNode string
	now := time.Now()
	for nodeID, state := range c.live {
		if now.Sub(state.lastSeen) > edgeNodeOnlineThresholdSeconds*time.Second {
			continue
		}
		for _, conn := range state.connections {
			if conn.ID == flowID {
				targetNode = nodeID
				break
			}
		}
		if targetNode != "" {
			break
		}
	}
	c.mu.RUnlock()
	if targetNode == "" {
		return "", false
	}
	return targetNode, c.CancelRemoteConnection(targetNode, flowID)
}

func (c *clusterController) CancelAllRemoteConnections() {
	if c == nil {
		return
	}
	event := agentSSEEvent{Type: "cancel_all"}
	c.mu.Lock()
	now := time.Now()
	for nodeID, state := range c.live {
		// Only queue for heartbeat fallback when the node has no active SSE subscriber,
		// preventing online agents from receiving cancel_all twice and dropping new streams.
		if len(c.subscribers[nodeID]) == 0 {
			state.commands = append(state.commands, queuedAgentCommand{event: event, createdAt: now})
			if len(state.commands) > 64 {
				state.commands = state.commands[len(state.commands)-64:]
			}
		}
	}
	c.mu.Unlock()
	c.publish("", event)
}

func (c *clusterController) drainCommands(nodeID string) []agentSSEEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.live[nodeID]
	if state == nil || len(state.commands) == 0 {
		return nil
	}
	cutoff := time.Now().Add(-agentCommandTTL)
	result := make([]agentSSEEvent, 0, len(state.commands))
	for _, item := range state.commands {
		if item.createdAt.After(cutoff) {
			result = append(result, item.event)
		}
	}
	state.commands = nil
	return result
}

func (c *clusterController) globalRuntimeSettings() runtimeSettings {
	if c.gateway.runtime != nil {
		return c.gateway.runtime.View(false).runtimeSettings
	}
	return runtimeSettingsFromConfig(c.gateway.cfg)
}

func (c *clusterController) buildConfigBundle(ctx context.Context, node edgeNodeRecord) (agentConfigBundle, error) {
	global := c.globalRuntimeSettings()
	merged := node.Overrides.ApplyTo(global)
	_, canonicalRuntime, err := applyRuntimeSettings(Config{}, merged)
	if err != nil {
		canonicalRuntime = global
	}

	policy := c.gateway.policy.Load()
	if policy == nil && c.store != nil {
		loaded, loadErr := c.store.LoadProxyPolicy(ctx)
		if loadErr == nil {
			policy = loaded
		}
	}
	if policy == nil {
		policy = &proxyPolicy{Mode: proxyModeOff, Rules: []proxyRule{}, PlayerPolicy: playerPolicy{Mode: proxyModeOff, Rules: []playerRule{}}}
	}
	rules := append([]proxyRule(nil), policy.Rules...)
	for i := range rules {
		if rules[i].quota != nil {
			rules[i].QuotaBytes, rules[i].QuotaUsedBytes = rules[i].quota.Snapshot()
		}
		if rules[i].QuotaBytes > 0 {
			rules[i].QuotaRemainingBytes = max(0, rules[i].QuotaBytes-rules[i].QuotaUsedBytes)
			rules[i].QuotaReached = rules[i].QuotaUsedBytes >= rules[i].QuotaBytes
		}
		rules[i].quota = nil
	}
	playerRules := append([]playerRule(nil), policy.PlayerPolicy.Rules...)
	ttlSec := int64(c.gateway.cfg.SignedURLTTL / time.Second)
	if ttlSec <= 0 {
		ttlSec = int64((24 * time.Hour) / time.Second)
	}

	clientAccess := policy.ClientAccess
	if clientAccess.IPMode == "" {
		clientAccess = defaultClientAccessPolicy()
	}

	var globalWAFRules []wafRuleRecord
	wafByID := make(map[string]wafRuleRecord)
	wafNeedsGeo := false
	if c.store != nil {
		if allWAF, wErr := c.store.ListWAFRules(ctx); wErr == nil {
			for _, wr := range allWAF {
				if !wr.Enabled {
					continue
				}
				wafByID[wr.ID] = wr
				if wr.IsGlobal {
					globalWAFRules = append(globalWAFRules, wr)
					for _, gn := range wr.Graph.Nodes {
						if gn.Type == wafNodeGeoMatch {
							wafNeedsGeo = true
						}
					}
				}
			}
		}
	}

	// Collect ONLY enabled edge domains explicitly assigned to this node.
	var assignedDomains []agentDomainConfig
	if c.store != nil {
		cfStored := c.store.LoadCloudflareDNS(ctx)
		if allDomains, domErr := c.store.ListEdgeDomains(ctx); domErr == nil {
			for _, dom := range allDomains {
				if !dom.Enabled {
					continue
				}
				bound := false
				for _, nid := range dom.NodeIDs {
					if nid == node.ID {
						bound = true
						break
					}
				}
				if !bound {
					continue
				}
				effOverrides := dom.Overrides
				if nl, ok := dom.NodeLimits[node.ID]; ok {
					effOverrides = nl.applyToOverrides(effOverrides)
				}
				var domWAFRules []wafRuleRecord
				for _, rid := range dom.WAFRuleIDs {
					if wr, ok := wafByID[rid]; ok && !wr.IsGlobal {
						domWAFRules = append(domWAFRules, wr)
						for _, gn := range wr.Graph.Nodes {
							if gn.Type == wafNodeGeoMatch {
								wafNeedsGeo = true
							}
						}
					}
				}
				item := agentDomainConfig{
					ID:        dom.ID,
					Domain:    dom.Domain,
					TLSMode:   "agent_http01",
					Overrides: effOverrides,
					WAFRules:  domWAFRules,
				}
				switch dom.TLSMode {
				case domainTLSExternal:
					item.TLSMode = "external"
				case domainTLSManual:
					item.TLSMode = "external"
					if dom.CertPEM != "" && dom.KeyPEMEnc != "" && c.certCipher != nil {
						if keyPEM, decErr := c.certCipher.Decrypt(dom.KeyPEMEnc); decErr == nil && keyPEM != "" {
							item.TLSMode = "managed_pem"
							item.CertPEM = dom.CertPEM
							item.KeyPEM = keyPEM
							item.CertNotAfter = dom.CertNotAfter
						}
					}
				case domainTLSAuto:
					if dom.CertPEM != "" && dom.KeyPEMEnc != "" && c.certCipher != nil {
						if keyPEM, decErr := c.certCipher.Decrypt(dom.KeyPEMEnc); decErr == nil && keyPEM != "" {
							item.TLSMode = "managed_pem"
							item.CertPEM = dom.CertPEM
							item.KeyPEM = keyPEM
							item.CertNotAfter = dom.CertNotAfter
						}
					} else if cfStored.Enabled && cfStored.EncryptedToken != "" && hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), cfStored.RootDomain) {
						// Controller ACME DNS-01 owns issuance for this domain; never tell agents to race HTTP-01.
						item.TLSMode = "external"
					}
				}
				assignedDomains = append(assignedDomains, item)
			}
		}
	}

	var ipCountries map[string]string
	if ((clientAccess.GeoMode != "" && clientAccess.GeoMode != proxyModeOff) || wafNeedsGeo) && c.store != nil {
		ipCountries = c.store.RecentIPCountries(ctx, 2000)
	}

	portalEnabled := c.gateway.publicPortal.Load()
	payload := agentConfigPayload{
		NodeID:              node.ID,
		NodeName:            node.Name,
		PublicBaseURL:       node.PublicURL,
		PublicPortalEnabled: &portalEnabled,
		Draining:            node.Draining,
		SigningSecretHex:    hex.EncodeToString(c.gateway.cfg.SigningSecret),
		SignedURLTTLSeconds: ttlSec,
		Runtime:             canonicalRuntime,
		Policy: agentPolicyBundle{
			Mode:            policy.Mode,
			Rules:           rules,
			PlayerPolicy:    playerPolicy{Mode: policy.PlayerPolicy.Mode, Rules: playerRules},
			ClientAccess:    clientAccess,
			ScheduleEnabled: policy.ScheduleEnabled,
			ScheduleStart:   policy.ScheduleStart,
			ScheduleEnd:     policy.ScheduleEnd,
		},
		Domains:        assignedDomains,
		GlobalWAFRules: globalWAFRules,
		IPCountries:    ipCountries,
	}
	digest, err := computeAgentConfigSHA256(payload)
	if err != nil {
		return agentConfigBundle{}, err
	}
	return agentConfigBundle{
		agentConfigPayload: payload,
		Revision:           c.currentRevision(),
		SHA256:             digest,
		GeneratedAt:        time.Now().Unix(),
	}, nil
}

func (c *clusterController) nodeStatus(node edgeNodeRecord, now time.Time) (status string, online bool) {
	if node.TokenHash == "" {
		return edgeNodeStatusPending, false
	}
	lastSeen := node.LastSeenAt
	c.mu.RLock()
	if state := c.live[node.ID]; state != nil && state.lastSeen.Unix() > lastSeen {
		lastSeen = state.lastSeen.Unix()
	}
	c.mu.RUnlock()

	online = lastSeen > 0 && now.Unix()-lastSeen <= edgeNodeOnlineThresholdSeconds
	if !online {
		return edgeNodeStatusOffline, false
	}
	if node.Draining {
		return edgeNodeStatusDraining, true
	}
	return edgeNodeStatusOnline, true
}

func (c *clusterController) ListNodeViews(ctx context.Context) ([]edgeNodeView, edgeNodesSummary, error) {
	records, err := c.store.ListEdgeNodes(ctx)
	if err != nil {
		return nil, edgeNodesSummary{}, err
	}
	now := time.Now()
	views := make([]edgeNodeView, 0, len(records))
	var summary edgeNodesSummary
	summary.Total = len(records)

	assignedByNode := make(map[string][]string)
	if domains, domErr := c.store.ListEdgeDomains(ctx); domErr == nil {
		for _, dom := range domains {
			if !dom.Enabled {
				continue
			}
			for _, nid := range dom.NodeIDs {
				assignedByNode[nid] = append(assignedByNode[nid], dom.Domain)
			}
		}
	}

	nicNames := map[string][]string{}
	if nicMap, nErr := c.store.EdgeNodeNICInterfaces(ctx); nErr == nil && nicMap != nil {
		nicNames = nicMap
	}
	for _, node := range records {
		status, online := c.nodeStatus(node, now)
		bundle, bundleErr := c.buildConfigBundle(ctx, node)
		desiredSHA := ""
		desiredRev := c.currentRevision()
		effective := node.Overrides.ApplyTo(c.globalRuntimeSettings())
		if bundleErr == nil {
			desiredSHA = bundle.SHA256
			desiredRev = bundle.Revision
			effective = bundle.Runtime
		}

		var metrics edgeNodeMetrics
		lastSeen := node.LastSeenAt
		c.mu.RLock()
		if state := c.live[node.ID]; state != nil {
			if state.lastSeen.Unix() > lastSeen {
				lastSeen = state.lastSeen.Unix()
			}
			if online {
				metrics = state.metrics
				metrics.Connections = nil // omit per-connection array in list summary
			}
		}
		connected := len(c.subscribers[node.ID]) > 0
		c.mu.RUnlock()

		synced := online && desiredSHA != "" && node.AppliedSHA256 == desiredSHA
		switch status {
		case edgeNodeStatusPending:
			summary.Pending++
		case edgeNodeStatusOffline:
			summary.Offline++
		case edgeNodeStatusDraining:
			summary.Draining++
			summary.Online++
		case edgeNodeStatusOnline:
			summary.Online++
		}
		if synced {
			summary.Synced++
		}
		if online {
			summary.TotalUploadBPS += metrics.UploadBPS
			summary.TotalDownloadBPS += metrics.DownloadBPS
			if metrics.NICTraffic != nil && len(metrics.NICTraffic.Interfaces) > 0 {
				summary.HasNICMetrics = true
				summary.TotalNICRXBPS += metrics.NICTraffic.RXBPS
				summary.TotalNICTXBPS += metrics.NICTraffic.TXBPS
			} else {
				summary.TotalNICTXBPS += metrics.DownloadBPS
				summary.TotalNICRXBPS += metrics.UploadBPS
			}
			summary.ActiveRequests += metrics.ActiveRequests
		}

		effV4, effV6 := effectiveNodeIPs(node)
		quotaBytes := monthlyQuotaGBToBytes(node.MonthlyQuotaGB)
		_, cycleStart, nextResetAt := billingCycleWindow(now, node.QuotaResetDay)
		usedBytes, _ := c.store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, node.QuotaDirection)
		usagePct := 0.0
		quotaExceeded := false
		if quotaBytes > 0 {
			usagePct = float64(usedBytes) * 100 / float64(quotaBytes)
			quotaExceeded = usedBytes >= quotaBytes
		}
		controllerBinSHA := c.controllerBinarySHA256ForArch(node.Arch)
		upgradeAvail := online && controllerBinSHA != "" && node.BinarySHA256 != "" && !strings.EqualFold(controllerBinSHA, node.BinarySHA256)
		var nicIfaces []string
		if metrics.NICTraffic != nil && len(metrics.NICTraffic.Interfaces) > 0 {
			nicIfaces = append([]string(nil), metrics.NICTraffic.Interfaces...)
		} else if len(nicNames[node.ID]) > 0 {
			nicIfaces = append([]string(nil), nicNames[node.ID]...)
		}

		metrics.Playbacks = nil
		views = append(views, edgeNodeView{
			ID:                node.ID,
			Name:              node.Name,
			GroupName:         node.GroupName,
			Region:            node.Region,
			PublicURL:         node.PublicURL,
			PublicVisible:     node.PublicVisible,
			Draining:          node.Draining,
			Enrolled:          node.TokenHash != "",
			Status:            status,
			Connected:         connected,
			Synced:            synced,
			Overrides:         node.Overrides,
			Effective:         effective,
			AppliedRevision:   node.AppliedRevision,
			DesiredRevision:   desiredRev,
			AppliedSHA256:     node.AppliedSHA256,
			DesiredSHA256:     desiredSHA,
			AgentVersion:      node.AgentVersion,
			Arch:              node.Arch,
			Hostname:          node.Hostname,
			PublicIPv4:        node.PublicIPv4,
			PublicIPv6:        node.PublicIPv6,
			ManualIPv4:        node.ManualIPv4,
			ManualIPv6:        node.ManualIPv6,
			EffectiveIPv4:     effV4,
			EffectiveIPv6:     effV6,
			DNSSyncEnabled:    node.DNSSyncEnabled,
			DNSIPMode:         node.DNSIPMode,
			MonthlyQuotaGB:    node.MonthlyQuotaGB,
			QuotaResetDay:     node.QuotaResetDay,
			QuotaDirection:    node.QuotaDirection,
			QuotaAutoDrain:    node.QuotaAutoDrain,
			QuotaAutoDrained:  node.QuotaAutoDrained,
			MonthlyUsedBytes:  usedBytes,
			MonthlyQuotaBytes: quotaBytes,
			MonthlyUsagePct:   usagePct,
			QuotaResetAt:      nextResetAt,
			QuotaExceeded:     quotaExceeded,
			NICInterfaces:     nicIfaces,
			BinarySHA256:      node.BinarySHA256,
			UpgradeAvailable:  upgradeAvail,
			AssignedDomains:   assignedByNode[node.ID],
			LastSeenAt:        lastSeen,
			CreatedAt:         node.CreatedAt,
			UpdatedAt:         node.UpdatedAt,
			EnrollExpiresAt:   node.EnrollExpiresAt,
			Metrics:           metrics,
		})
	}
	return views, summary, nil
}

func (c *clusterController) OnlineNodeCount(ctx context.Context) int {
	if c == nil || c.store == nil {
		return 0
	}
	nodes, _, err := c.ListNodeViews(ctx)
	if err != nil {
		return 0
	}
	online := 0
	for _, node := range nodes {
		if node.Status == edgeNodeStatusOnline && !node.Draining {
			online++
		}
	}
	return online
}

func (c *clusterController) PublicNodes(ctx context.Context) ([]publicEdgeNode, error) {
	if c == nil || c.store == nil {
		return []publicEdgeNode{}, nil
	}
	if c.gateway != nil && c.gateway.cfg.Role == RoleController && !c.gateway.publicPortal.Load() {
		return []publicEdgeNode{}, nil
	}
	records, err := c.store.ListEdgeNodes(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	globalRuntime := c.globalRuntimeSettings()
	nodeMap := make(map[string]edgeNodeRecord, len(records))
	onlineMap := make(map[string]bool, len(records))
	activeMap := make(map[string]int64, len(records))
	liveSeenMap := make(map[string]int64, len(records))
	for _, node := range records {
		nodeMap[node.ID] = node
		if node.TokenHash == "" || node.Draining {
			continue
		}
		_, online := c.nodeStatus(node, now)
		if !online {
			continue
		}
		onlineMap[node.ID] = true
		c.mu.RLock()
		if state := c.live[node.ID]; state != nil {
			activeMap[node.ID] = state.metrics.ActiveRequests
			if state.lastSeen.Unix() > liveSeenMap[node.ID] {
				liveSeenMap[node.ID] = state.lastSeen.Unix()
			}
		}
		c.mu.RUnlock()
	}

	result := make([]publicEdgeNode, 0, len(records))
	seenHosts := make(map[string]struct{})
	var seenWildcards []string

	// First expose enabled, public_visible managed edge domains with at least one healthy node.
	if domains, domErr := c.store.ListEdgeDomains(ctx); domErr == nil {
		for _, dom := range domains {
			domHost := strings.ToLower(strings.TrimSpace(dom.Domain))
			if strings.HasPrefix(domHost, "*.") {
				seenWildcards = append(seenWildcards, domHost)
			} else if domHost != "" {
				// Record ALL managed domains (enabled, disabled, hidden) so legacy node.PublicURL never leaks them.
				seenHosts[domHost] = struct{}{}
			}
			if !dom.Enabled || strings.HasPrefix(domHost, "*.") || !dom.PublicVisible {
				continue
			}
			var healthy int
			var existingTotal int
			var totalActive int64
			region := dom.Note
			groupName := ""
			version := ""
			var lastSeen int64
			for _, nid := range dom.NodeIDs {
				n, ok := nodeMap[nid]
				if !ok {
					continue
				}
				existingTotal++
				if !onlineMap[nid] {
					continue
				}
				healthy++
				totalActive += activeMap[nid]
				if groupName == "" {
					groupName = n.GroupName
				}
				if region == "" {
					region = n.Region
				}
				if version == "" && n.AgentVersion != "" {
					version = n.AgentVersion
				}
				seen := max(n.LastSeenAt, liveSeenMap[nid])
				if seen > lastSeen {
					lastSeen = seen
				}
			}
			if healthy == 0 {
				continue
			}
			displayName := strings.TrimSpace(dom.Name)
			if displayName == "" {
				displayName = dom.Domain
			}
			effRuntime := dom.Overrides.ApplyTo(globalRuntime)
			result = append(result, publicEdgeNode{
				ID:                 dom.ID,
				Name:               displayName,
				GroupName:          groupName,
				Region:             region,
				PublicURL:          "https://" + dom.Domain,
				Online:             true,
				Draining:           false,
				ActiveRequests:     totalActive,
				HealthyNodes:       healthy,
				TotalNodes:         existingTotal,
				Version:            version,
				LastSeen:           lastSeen,
				HasDefaultUpstream: strings.TrimSpace(effRuntime.DefaultUpstream) != "",
			})
		}
	}

	// Keep legacy nodes with explicit PublicURL visible if not already covered by a managed domain.
	for _, node := range records {
		if !node.PublicVisible || !onlineMap[node.ID] || strings.TrimSpace(node.PublicURL) == "" {
			continue
		}
		if parsed, parseErr := url.Parse(node.PublicURL); parseErr == nil {
			host := strings.ToLower(parsed.Hostname())
			if _, exists := seenHosts[host]; exists {
				continue
			}
			matchedWildcard := false
			for _, wc := range seenWildcards {
				if matchEdgeDomainHost(wc, host) {
					matchedWildcard = true
					break
				}
			}
			if matchedWildcard {
				continue
			}
		}
		effRuntime := node.Overrides.ApplyTo(globalRuntime)
		result = append(result, publicEdgeNode{
			ID:                 node.ID,
			Name:               node.Name,
			GroupName:          node.GroupName,
			Region:             node.Region,
			PublicURL:          node.PublicURL,
			Online:             true,
			Draining:           node.Draining,
			ActiveRequests:     activeMap[node.ID],
			HealthyNodes:       1,
			TotalNodes:         1,
			Version:            node.AgentVersion,
			LastSeen:           max(node.LastSeenAt, liveSeenMap[node.ID]),
			HasDefaultUpstream: strings.TrimSpace(effRuntime.DefaultUpstream) != "",
		})
	}
	return result, nil
}

func (c *clusterController) AggregateLive(local liveSnapshot, localConns []connectionSnapshot, nodeFilter string) liveSnapshot {
	isPureController := c != nil && c.gateway != nil && c.gateway.cfg.Role == RoleController
	includeLocal := !isPureController && (nodeFilter == "" || nodeFilter == "all" || nodeFilter == "local")
	var result liveSnapshot
	allConns := make([]connectionSnapshot, 0, len(localConns))
	if includeLocal {
		result = local
		allConns = append(allConns, localConns...)
		if c != nil && c.gateway != nil && c.gateway.playback != nil {
			result.WatchingCount += len(c.gateway.playback.Snapshot())
		}
	}
	if c == nil || nodeFilter == "local" {
		result.ActiveTargets = summarizeActiveTargets(allConns)
		return result
	}
	now := time.Now()
	c.mu.RLock()
	for nodeID, state := range c.live {
		if nodeFilter != "" && nodeFilter != "all" && nodeFilter != nodeID {
			continue
		}
		if now.Sub(state.lastSeen) > edgeNodeOnlineThresholdSeconds*time.Second {
			continue
		}
		result.UploadBPS += state.metrics.UploadBPS
		result.DownloadBPS += state.metrics.DownloadBPS
		result.UploadTotal += state.metrics.UploadTotal
		result.DownloadTotal += state.metrics.DownloadTotal
		result.ActiveRequests += state.metrics.ActiveRequests
		result.WatchingCount += len(state.playbacks)
		allConns = append(allConns, state.connections...)
	}
	c.mu.RUnlock()
	result.ActiveTargets = summarizeActiveTargets(allConns)
	return result
}

func (c *clusterController) AggregateConnections(ctx context.Context, localConns []connectionSnapshot, nodeFilter string) []connectionSnapshot {
	result := make([]connectionSnapshot, 0, len(localConns))
	isPureController := c != nil && c.gateway != nil && c.gateway.cfg.Role == RoleController
	if !isPureController && (nodeFilter == "" || nodeFilter == "all" || nodeFilter == "local") {
		for _, conn := range localConns {
			conn.NodeID = "local"
			conn.NodeName = "本机节点"
			result = append(result, conn)
		}
	}
	if c == nil || nodeFilter == "local" {
		return result
	}
	names, _ := c.store.EdgeNodeNames(ctx)
	now := time.Now()
	c.mu.RLock()
	for nodeID, state := range c.live {
		if nodeFilter != "" && nodeFilter != "all" && nodeFilter != nodeID {
			continue
		}
		if now.Sub(state.lastSeen) > edgeNodeOnlineThresholdSeconds*time.Second {
			continue
		}
		nodeName := names[nodeID]
		if nodeName == "" {
			nodeName = nodeID
		}
		for _, conn := range state.connections {
			conn.NodeID = nodeID
			conn.NodeName = nodeName
			result = append(result, conn)
		}
	}
	c.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].DownloadBPS == result[j].DownloadBPS {
			return result[i].StartedAt < result[j].StartedAt
		}
		return result[i].DownloadBPS > result[j].DownloadBPS
	})
	return result
}

func (c *clusterController) AggregatePlaybacks(ctx context.Context, localPlaybacks []playbackSessionSnapshot, nodeFilter string) []playbackSessionSnapshot {
	result := make([]playbackSessionSnapshot, 0, len(localPlaybacks))
	isPureController := c != nil && c.gateway != nil && c.gateway.cfg.Role == RoleController
	if !isPureController && (nodeFilter == "" || nodeFilter == "all" || nodeFilter == "local") {
		for _, pb := range localPlaybacks {
			pb.NodeID = "local"
			pb.NodeName = "本机节点"
			result = append(result, pb)
		}
	}
	if c == nil || nodeFilter == "local" {
		return result
	}
	names, _ := c.store.EdgeNodeNames(ctx)
	now := time.Now()
	c.mu.RLock()
	for nodeID, state := range c.live {
		if nodeFilter != "" && nodeFilter != "all" && nodeFilter != nodeID {
			continue
		}
		if now.Sub(state.lastSeen) > edgeNodeOnlineThresholdSeconds*time.Second {
			continue
		}
		nodeName := names[nodeID]
		if nodeName == "" {
			nodeName = nodeID
		}
		for _, pb := range state.playbacks {
			pb.NodeID = nodeID
			pb.NodeName = nodeName
			result = append(result, pb)
		}
	}
	c.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].DownloadBPS != result[j].DownloadBPS {
			return result[i].DownloadBPS > result[j].DownloadBPS
		}
		return result[i].LastSeenAt > result[j].LastSeenAt
	})
	return result
}

func (c *clusterController) AggregateCounters(localActive int64, localBlocked uint64, nodeFilter string) (int64, uint64) {
	var active int64
	var blocked uint64
	isPureController := c != nil && c.gateway != nil && c.gateway.cfg.Role == RoleController
	if !isPureController && (nodeFilter == "" || nodeFilter == "all" || nodeFilter == "local") {
		active += localActive
		blocked += localBlocked
	}
	if c == nil || nodeFilter == "local" {
		return active, blocked
	}
	now := time.Now()
	c.mu.RLock()
	for nodeID, state := range c.live {
		if nodeFilter != "" && nodeFilter != "all" && nodeFilter != nodeID {
			continue
		}
		if now.Sub(state.lastSeen) <= edgeNodeOnlineThresholdSeconds*time.Second {
			active += state.metrics.ActiveRequests
		}
		blocked += state.blockedTotal
	}
	c.mu.RUnlock()
	return active, blocked
}

/* -------------------- Agent HTTP API (/_agent/api/v1/*) -------------------- */

func (c *clusterController) HandleAgentAPI(w http.ResponseWriter, r *http.Request) bool {
	if c == nil || !strings.HasPrefix(r.URL.Path, "/_agent/api/v1/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case "/_agent/api/v1/install.sh":
		c.handleAgentInstallScript(w, r)
	case "/_agent/api/v1/binary":
		c.handleAgentBinaryDownload(w, r)
	case "/_agent/api/v1/enroll":
		c.handleAgentEnroll(w, r)
	case "/_agent/api/v1/events":
		c.handleAgentEvents(w, r)
	case "/_agent/api/v1/config":
		c.handleAgentConfig(w, r)
	case "/_agent/api/v1/heartbeat":
		c.handleAgentHeartbeat(w, r)
	case "/_agent/api/v1/telemetry":
		c.handleAgentTelemetry(w, r)
	default:
		writeGatewayError(w, http.StatusNotFound, "agent endpoint not found")
	}
	return true
}

func (c *clusterController) authenticateAgent(r *http.Request) (edgeNodeRecord, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return edgeNodeRecord{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if len(token) < 16 {
		return edgeNodeRecord{}, false
	}
	node, err := c.store.FindEdgeNodeByTokenHash(r.Context(), hashAgentToken(token))
	if err != nil {
		return edgeNodeRecord{}, false
	}
	return node, true
}

func (c *clusterController) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req agentEnrollRequest
	if err := decodeAgentJSON(w, r, &req, 16<<10); err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid enrollment request")
		return
	}
	rawToken := strings.TrimSpace(req.EnrollToken)
	if rawToken == "" {
		writeGatewayError(w, http.StatusBadRequest, "enroll_token is required")
		return
	}
	var node edgeNodeRecord
	var secret string
	var err error
	auditAction := "edge_node.enroll"
	if strings.HasPrefix(rawToken, "rf_dsc_") {
		disc, ok := c.discovery.Verify(r.Context(), rawToken)
		if !ok {
			writeGatewayError(w, http.StatusUnauthorized, "cluster discovery token disabled or invalid")
			return
		}
		node, secret, err = c.store.CreateEnrolledEdgeNodeFromDiscovery(
			r.Context(), req.Hostname, disc.DefaultGroup, disc.DefaultRegion,
			req.Version, req.Arch, req.Hostname,
		)
		auditAction = "edge_node.discovery_enroll"
	} else {
		node, secret, err = c.store.CompleteEdgeNodeEnrollment(r.Context(), rawToken, req.Version, req.Arch, req.Hostname)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeGatewayError(w, http.StatusUnauthorized, "invalid enrollment token")
			return
		}
		writeGatewayError(w, http.StatusUnauthorized, err.Error())
		return
	}
	c.disconnectNode(node.ID)
	c.mu.Lock()
	c.live[node.ID] = &edgeNodeLiveState{lastSeen: time.Now()}
	c.mu.Unlock()
	c.store.RecordAudit(r.Context(), auditEntry{
		Username: "agent:" + node.ID, ClientIP: adminClientIP(r, c.gateway.cfg.TrustProxyHeaders, c.gateway.cfg.TrustedProxyCIDRs...),
		Action: auditAction, Resource: node.Name,
		Detail: fmt.Sprintf("node_id=%s version=%s arch=%s", node.ID, node.AgentVersion, node.Arch), Success: true,
	})
	writeJSON(w, http.StatusOK, agentEnrollResponse{
		NodeID:               node.ID,
		NodeName:             node.Name,
		AgentSecret:          secret,
		PublicURL:            node.PublicURL,
		HeartbeatIntervalSec: 5,
		TelemetryIntervalSec: 5,
	})
}

func (c *clusterController) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node, ok := c.authenticateAgent(r)
	if !ok {
		writeGatewayError(w, http.StatusUnauthorized, "invalid agent credentials")
		return
	}
	bundle, err := c.buildConfigBundle(r.Context(), node)
	if err != nil {
		writeGatewayError(w, http.StatusInternalServerError, "failed to build node config")
		return
	}
	if inm := strings.Trim(strings.TrimSpace(r.Header.Get("If-None-Match")), `"`); inm != "" && inm == bundle.SHA256 {
		w.Header().Set("ETag", `"`+bundle.SHA256+`"`)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"`+bundle.SHA256+`"`)
	writeJSON(w, http.StatusOK, bundle)
}

func (c *clusterController) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node, ok := c.authenticateAgent(r)
	if !ok {
		writeGatewayError(w, http.StatusUnauthorized, "invalid agent credentials")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeGatewayError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ch, ok := c.subscribe(node.ID)
	if !ok {
		writeGatewayError(w, http.StatusServiceUnavailable, "controller shutting down")
		return
	}
	defer c.unsubscribe(node.ID, ch)

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Send initial handshake event with current revision so agent syncs immediately on reconnect.
	initial := agentSSEEvent{Type: "config_changed", Revision: c.currentRevision()}
	if data, err := json.Marshal(initial); err == nil {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	rc := http.NewResponseController(w)
	connectedAt := time.Now()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-r.Context().Done():
			return
		case event, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, wErr := fmt.Fprintf(w, "data: %s\n\n", data)
			if wErr == nil {
				flusher.Flush()
			}
			_ = rc.SetWriteDeadline(time.Time{})
			if wErr != nil {
				return
			}
		case <-ticker.C:
			now := time.Now()
			if now.Sub(connectedAt) > time.Duration(edgeNodeOnlineThresholdSeconds)*time.Second {
				lastSeenUnix := node.LastSeenAt
				c.mu.RLock()
				if st := c.live[node.ID]; st != nil && st.lastSeen.Unix() > lastSeenUnix {
					lastSeenUnix = st.lastSeen.Unix()
				}
				c.mu.RUnlock()
				if lastSeenUnix == 0 || now.Unix()-lastSeenUnix > edgeNodeOnlineThresholdSeconds {
					return
				}
			}
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, wErr := fmt.Fprint(w, ": ping\n\n")
			if wErr == nil {
				flusher.Flush()
			}
			_ = rc.SetWriteDeadline(time.Time{})
			if wErr != nil {
				return
			}
		}
	}
}

func (c *clusterController) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node, ok := c.authenticateAgent(r)
	if !ok {
		writeGatewayError(w, http.StatusUnauthorized, "invalid agent credentials")
		return
	}
	var req agentHeartbeatRequest
	if err := decodeAgentJSON(w, r, &req, 512<<10); err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid heartbeat payload")
		return
	}
	now := time.Now()
	conns := req.Metrics.Connections
	if len(conns) > 500 {
		conns = conns[:500]
	}
	pbs := req.Metrics.Playbacks
	if len(pbs) > 256 {
		pbs = pbs[:256]
	}
	stampedPBs := make([]playbackSessionSnapshot, len(pbs))
	for i, pb := range pbs {
		pb.NodeID = node.ID
		pb.NodeName = node.Name
		if pb.SessionKey != "" {
			pb.SessionKey = node.ID + "|" + pb.SessionKey
		}
		stampedPBs[i] = pb
	}
	c.mu.Lock()
	state := c.live[node.ID]
	if state == nil {
		state = &edgeNodeLiveState{}
		c.live[node.ID] = state
	}
	for k, exp := range state.kickedPlaybacks {
		if !now.Before(exp) {
			delete(state.kickedPlaybacks, k)
		}
	}
	filteredPBs := make([]playbackSessionSnapshot, 0, len(stampedPBs))
	for _, pb := range stampedPBs {
		if exp, kicked := state.kickedPlaybacks[pb.SessionKey]; kicked && now.Before(exp) {
			continue
		}
		if pb.ClientIP != "" && pb.UpstreamHost != "" && pb.ItemID != "" {
			sKey := node.ID + "|" + playbackStreamBlockKey(pb.ClientIP, pb.UpstreamHost, pb.ItemID)
			if exp, kicked := state.kickedPlaybacks[sKey]; kicked && now.Before(exp) {
				continue
			}
		}
		filteredPBs = append(filteredPBs, pb)
	}
	if req.Metrics.UploadBPS < 0 {
		req.Metrics.UploadBPS = 0
	}
	if req.Metrics.DownloadBPS < 0 {
		req.Metrics.DownloadBPS = 0
	}
	if req.Metrics.NICTraffic != nil {
		if req.Metrics.NICTraffic.RXBPS < 0 {
			req.Metrics.NICTraffic.RXBPS = 0
		}
		if req.Metrics.NICTraffic.TXBPS < 0 {
			req.Metrics.NICTraffic.TXBPS = 0
		}
	}
	state.lastSeen = now
	state.metrics = req.Metrics
	state.connections = append([]connectionSnapshot(nil), conns...)
	state.playbacks = filteredPBs
	state.blockedTotal = req.Metrics.BlockedTotal
	state.droppedTotal = req.Metrics.DroppedLogs
	c.mu.Unlock()
	if len(filteredPBs) > 0 && c.store != nil {
		_ = c.store.UpsertWatchHistory(r.Context(), filteredPBs)
	}
	if req.Metrics.NICTraffic != nil && c.store != nil {
		_ = c.store.RecordNodeNICTrafficSample(r.Context(), node.ID, req.Metrics.NICTraffic, now)
	}

	normV4 := ""
	if v4, ipErr := normalizeOptionalNodeIP(req.Metrics.PublicIPv4, false); ipErr == nil && v4 != "" {
		if addr, pErr := netip.ParseAddr(v4); pErr == nil && (c.gateway.cfg.AllowPrivateTargets || !isBlockedAddress(addr)) {
			normV4 = v4
		}
	}
	normV6 := ""
	if v6, ipErr := normalizeOptionalNodeIP(req.Metrics.PublicIPv6, true); ipErr == nil && v6 != "" {
		if addr, pErr := netip.ParseAddr(v6); pErr == nil && (c.gateway.cfg.AllowPrivateTargets || !isBlockedAddress(addr)) {
			normV6 = v6
		}
	}
	hbErr := c.store.RecordEdgeNodeHeartbeat(
		r.Context(), node.ID, req.AppliedRevision, req.AppliedSHA256,
		req.Version, req.Arch, req.Hostname,
		normV4, normV6, req.Metrics.BinarySHA256,
		now.Unix(),
	)
	ipChanged := hbErr == nil && ((normV4 != "" && normV4 != node.PublicIPv4) || (normV6 != "" && normV6 != node.PublicIPv6))
	if ipChanged && (c.gateway.cloudflare != nil || c.gateway.axisnow != nil) {
		updatedNode := node
		if normV4 != "" {
			updatedNode.PublicIPv4 = normV4
		}
		if normV6 != "" {
			updatedNode.PublicIPv6 = normV6
		}
		c.hbDNSSyncMu.Lock()
		c.hbDNSSyncNodes[updatedNode.ID] = updatedNode
		c.hbDNSSyncMu.Unlock()
		c.hbDNSSyncDirty.Store(true)
		if c.hbDNSSyncBusy.CompareAndSwap(false, true) {
			c.runTracked(func() {
				defer c.hbDNSSyncBusy.Store(false)
				for c.hbDNSSyncDirty.Swap(false) {
					c.hbDNSSyncMu.Lock()
					batchNodes := make([]edgeNodeRecord, 0, len(c.hbDNSSyncNodes))
					for id, nRec := range c.hbDNSSyncNodes {
						batchNodes = append(batchNodes, nRec)
						delete(c.hbDNSSyncNodes, id)
					}
					c.hbDNSSyncMu.Unlock()
					syncCtx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
					if c.gateway.cloudflare != nil {
						for _, nCopy := range batchNodes {
							if nCopy.DNSSyncEnabled {
								_ = c.gateway.cloudflare.SyncNodeDNS(syncCtx, nCopy, "")
							}
						}
						_, _ = c.gateway.cloudflare.EvaluateEdgeDomainsDNS(syncCtx, time.Now())
					}
					if c.gateway.axisnow != nil {
						_, _ = c.gateway.axisnow.EvaluateEdgeDomainsSmartDNS(syncCtx, time.Now())
					}
					cancel()
				}
			})
		}
	}

	bundle, err := c.buildConfigBundle(r.Context(), node)
	desiredRev := c.currentRevision()
	desiredSHA := ""
	if err == nil {
		desiredRev = bundle.Revision
		desiredSHA = bundle.SHA256
	}
	commands := c.drainCommands(node.ID)
	writeJSON(w, http.StatusOK, agentHeartbeatResponse{
		OK:              true,
		DesiredRevision: desiredRev,
		DesiredSHA256:   desiredSHA,
		Draining:        node.Draining,
		ServerTime:      now.Unix(),
		Commands:        commands,
	})
}

func (c *clusterController) handleAgentTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	node, ok := c.authenticateAgent(r)
	if !ok {
		writeGatewayError(w, http.StatusUnauthorized, "invalid agent credentials")
		return
	}
	var reader io.Reader = http.MaxBytesReader(w, r.Body, maxAgentTelemetryBodyBytes)
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			writeGatewayError(w, http.StatusBadRequest, "invalid gzip telemetry body")
			return
		}
		defer gz.Close()
		reader = io.LimitReader(gz, maxAgentTelemetryBodyBytes*4)
	}
	var batch agentTelemetryBatch
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&batch); err != nil {
		writeGatewayError(w, http.StatusBadRequest, "invalid telemetry payload")
		return
	}
	if len(batch.Events) > maxAgentTelemetryEvents {
		batch.Events = batch.Events[:maxAgentTelemetryEvents]
	}
	for _, ev := range batch.Events {
		ts := time.Unix(ev.Timestamp, 0)
		if ev.Timestamp <= 0 {
			ts = time.Now()
		}
		bytesIn := ev.BytesIn
		if bytesIn < 0 {
			bytesIn = 0
		}
		bytesOut := ev.BytesOut
		if bytesOut < 0 {
			bytesOut = 0
		}
		durMS := ev.DurationMS
		if durMS < 0 {
			durMS = 0
		}
		c.store.Record(telemetryEvent{
			NodeID:     node.ID,
			FlowID:     ev.FlowID,
			Timestamp:  ts,
			ClientIP:   ev.ClientIP,
			DeviceID:   ev.DeviceID,
			DeviceName: ev.DeviceName,
			ClientName: ev.ClientName,
			Host:       ev.Host,
			Scheme:     ev.Scheme,
			Method:     ev.Method,
			Path:       ev.Path,
			Category:   ev.Category,
			Status:     ev.Status,
			BytesIn:    bytesIn,
			BytesOut:   bytesOut,
			DurationMS: durMS,
		})
		if c.gateway.geo != nil && ev.ClientIP != "" {
			c.gateway.geo.ObserveClient(ev.ClientIP)
		}
	}
	if c.gateway.geo != nil {
		peaks := batch.ClientPeaks
		if len(peaks) > maxAgentTelemetryEvents {
			peaks = peaks[:maxAgentTelemetryEvents]
		}
		for _, peak := range peaks {
			if peak.IP != "" && peak.PeakBPS > 0 {
				c.gateway.geo.ObservePeak(peak.IP, peak.PeakBPS)
			}
		}
	}
	quotaChanged := false
	const maxSingleQuotaDelta = int64(1) << 40 // 1 TiB sanity ceiling per telemetry batch
	for ruleID, delta := range batch.QuotaDeltas {
		if ruleID <= 0 || delta <= 0 || delta > maxSingleQuotaDelta {
			continue
		}
		if err := c.store.AddProxyRuleQuotaUsage(ruleID, delta); err == nil {
			quotaChanged = true
		}
	}
	if quotaChanged {
		prevPolicy := c.gateway.policy.Load()
		prevExhausted := make(map[int64]bool)
		if prevPolicy != nil {
			for _, r := range prevPolicy.Rules {
				if r.QuotaBytes > 0 && (r.QuotaUsedBytes >= r.QuotaBytes || (r.quota != nil && r.quota.Exhausted())) {
					prevExhausted[r.ID] = true
				}
			}
		}
		if nextPolicy, lErr := c.store.LoadProxyPolicy(r.Context()); lErr == nil {
			if c.gateway.quota != nil {
				c.gateway.quota.Sync(nextPolicy)
			}
			c.gateway.policy.Store(nextPolicy)
			newlyExhausted := false
			for _, r := range nextPolicy.Rules {
				if r.QuotaBytes > 0 && r.QuotaUsedBytes >= r.QuotaBytes && !prevExhausted[r.ID] {
					newlyExhausted = true
					break
				}
			}
			if newlyExhausted {
				c.gateway.notifyClusterConfigChanged("")
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeAgentJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

/* -------------------- Admin API for Edge Nodes (/_admin/api/nodes*) -------------------- */

func (a *adminServer) resolveControllerURL(r *http.Request) string {
	if a.gateway.cfg.PublicBaseURL != nil {
		return strings.TrimRight(a.gateway.cfg.PublicBaseURL.String(), "/")
	}
	if base, err := publicBaseForRequest(a.gateway.cfg, r); err == nil && base != "" {
		return strings.TrimRight(base, "/")
	}
	return "https://your-controller-domain"
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func safeDeployControllerURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if isSafeShellURL(raw) {
		return raw
	}
	return "https://your-controller-domain"
}

func buildAgentDeployCommands(controllerURL, publicURL, enrollToken string, expiresAt int64) agentDeployCommands {
	controllerURL = safeDeployControllerURL(controllerURL)
	host := "node.example.com"
	if parsed, err := parseHTTPURL(publicURL); err == nil && validRuleDomain(parsed.Hostname()) {
		host = normalizeHost(parsed.Hostname())
	}
	oneClickAutoTLS := fmt.Sprintf(`curl -fsSL %s | { [ "$(id -u)" -eq 0 ] && bash || sudo bash; }`, shellSingleQuote(controllerURL+"/_agent/api/v1/install.sh?token="+enrollToken))
	oneClickProxy := fmt.Sprintf(`curl -fsSL %s | { [ "$(id -u)" -eq 0 ] && bash || sudo bash; }`, shellSingleQuote(controllerURL+"/_agent/api/v1/install.sh?token="+enrollToken+"&tls=off"))
	cliCmd := fmt.Sprintf("REFRACT_MODE=agent REFRACT_CONTROLLER_URL=%s REFRACT_ENROLL_TOKEN=%s REFRACT_AGENT_STATE_PATH=/var/lib/refract-agent/state.json LISTEN_ADDR=127.0.0.1:8080 ./refract", shellSingleQuote(controllerURL), shellSingleQuote(enrollToken))
	systemdCmd := fmt.Sprintf(`SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
$SUDO mkdir -p /opt/refract-agent /var/lib/refract-agent/certs && \
cat <<'EOF' | $SUDO tee /etc/refract-agent.env >/dev/null
REFRACT_MODE=agent
REFRACT_AGENT_AUTO_TLS=true
LISTEN_ADDR=:80
REFRACT_AGENT_TLS_LISTEN_ADDR=:443
REFRACT_AGENT_CERT_DIR=/var/lib/refract-agent/certs
REFRACT_CONTROLLER_URL=%s
REFRACT_ENROLL_TOKEN=%s
REFRACT_AGENT_STATE_PATH=/var/lib/refract-agent/state.json
EOF
$SUDO chmod 600 /etc/refract-agent.env`, controllerURL, enrollToken)
	caddyBlock := fmt.Sprintf(`%s {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
        # 若前方接入 Cloudflare / OpenFlare 等 CDN，请配置 trusted_proxies 以避免伪造客户端 IP
        header_up -CF-Connecting-IP
        header_up -True-Client-IP
        header_up -EO-Connecting-IP
        header_up -CF-IPCountry
        header_up X-Real-IP {http.request.client_ip}
    }
}`, host)
	dockerCmd := fmt.Sprintf(`docker run -d --name refract-agent --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v refract-agent-data:/data \
  -e REFRACT_MODE=agent \
  -e REFRACT_AGENT_AUTO_TLS=true \
  -e LISTEN_ADDR=:80 \
  -e REFRACT_AGENT_TLS_LISTEN_ADDR=:443 \
  -e REFRACT_AGENT_CERT_DIR=/data/certs \
  -e REFRACT_CONTROLLER_URL=%s \
  -e REFRACT_ENROLL_TOKEN=%s \
  -e REFRACT_AGENT_STATE_PATH=/data/state.json \
  ghcr.io/t-matrix/refract:latest`, shellSingleQuote(controllerURL), shellSingleQuote(enrollToken))
	return agentDeployCommands{
		EnrollToken:     enrollToken,
		EnrollExpiresAt: expiresAt,
		ControllerURL:   controllerURL,
		OneClickAutoTLS: oneClickAutoTLS,
		OneClickProxy:   oneClickProxy,
		SystemdScript:   systemdCmd,
		CaddyBlock:      caddyBlock,
		DockerCommand:   dockerCmd,
		CLICommand:      cliCmd,
	}
}

type edgeNodeMutationRequest struct {
	Name           string            `json:"name"`
	GroupName      string            `json:"group_name"`
	Region         string            `json:"region"`
	PublicURL      string            `json:"public_url"`
	PublicVisible  *bool             `json:"public_visible"`
	Draining       bool              `json:"draining"`
	Overrides      edgeNodeOverrides `json:"overrides"`
	ManualIPv4     string            `json:"manual_ipv4"`
	ManualIPv6     string            `json:"manual_ipv6"`
	DNSSyncEnabled bool              `json:"dns_sync_enabled"`
	DNSIPMode      string            `json:"dns_ip_mode"`
	MonthlyQuotaGB float64           `json:"monthly_quota_gb"`
	QuotaResetDay  int               `json:"quota_reset_day"`
	QuotaDirection string            `json:"quota_direction"`
	QuotaAutoDrain *bool             `json:"quota_auto_drain"`
}

func (a *adminServer) handleEdgeNodes(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge node controller unavailable")
		return
	}
	switch r.Method {
	case http.MethodGet:
		views, summary, err := a.gateway.cluster.ListNodeViews(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load edge nodes")
			return
		}
		a.writeJSON(w, http.StatusOK, edgeNodesListResponse{
			Role:                   a.gateway.cfg.Role,
			ControllerURL:          a.resolveControllerURL(r),
			ControllerVersion:      normalizedVersion(Version),
			ControllerBinarySHA256: a.gateway.cluster.controllerBinarySHA256ForArch(runtime.GOOS + "/" + runtime.GOARCH),
			Summary:                summary,
			Nodes:                  views,
		})
	case http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req edgeNodeMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// Validate merged overrides against runtime config validation rules.
		merged := req.Overrides.ApplyTo(a.gateway.cluster.globalRuntimeSettings())
		if _, _, err := applyRuntimeSettings(Config{}, merged); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid node runtime overrides: "+err.Error())
			return
		}
		visible := true
		if req.PublicVisible != nil {
			visible = *req.PublicVisible
		}
		autoDrain := true
		if req.QuotaAutoDrain != nil {
			autoDrain = *req.QuotaAutoDrain
		}
		record, enrollToken, err := a.store.CreateEdgeNode(r.Context(), edgeNodeRecord{
			Name:           req.Name,
			GroupName:      req.GroupName,
			Region:         req.Region,
			PublicURL:      req.PublicURL,
			PublicVisible:  visible,
			Draining:       req.Draining,
			Overrides:      req.Overrides,
			ManualIPv4:     req.ManualIPv4,
			ManualIPv6:     req.ManualIPv6,
			DNSSyncEnabled: req.DNSSyncEnabled,
			DNSIPMode:      req.DNSIPMode,
			MonthlyQuotaGB: req.MonthlyQuotaGB,
			QuotaResetDay:  req.QuotaResetDay,
			QuotaDirection: req.QuotaDirection,
			QuotaAutoDrain: autoDrain,
		})
		if err != nil {
			a.auditRequest(r, "edge_node.create", req.Name, err.Error(), false)
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if record.DNSSyncEnabled && a.gateway.cloudflare != nil {
			nCopy := record
			a.gateway.cluster.runTracked(func() {
				syncCtx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 15*time.Second)
				defer cancel()
				_ = a.gateway.cloudflare.SyncNodeDNS(syncCtx, nCopy, "")
			})
		}
		a.auditRequest(r, "edge_node.create", record.Name, fmt.Sprintf("node_id=%s public_url=%s", record.ID, record.PublicURL), true)
		deploy := buildAgentDeployCommands(a.resolveControllerURL(r), record.PublicURL, enrollToken, record.EnrollExpiresAt)
		a.writeJSON(w, http.StatusCreated, map[string]any{
			"node":   record,
			"deploy": deploy,
		})
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (a *adminServer) handleEdgeNodesUpgradeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.methodNotAllowed(w, http.MethodPost)
		return
	}
	if !sameOriginRequest(r) {
		a.writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge node controller unavailable")
		return
	}
	nodes, err := a.store.ListEdgeNodes(r.Context())
	if err != nil {
		a.writeError(w, http.StatusInternalServerError, "failed to load edge nodes")
		return
	}
	triggered := make([]string, 0)
	now := time.Now()
	for _, node := range nodes {
		if _, online := a.gateway.cluster.nodeStatus(node, now); !online {
			continue
		}
		if a.gateway.cluster.TriggerNodeUpgrade(node.ID) {
			triggered = append(triggered, node.ID)
		}
	}
	a.auditRequest(r, "edge_node.upgrade", "all-online", fmt.Sprintf("triggered=%d", len(triggered)), true)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"triggered": len(triggered),
		"node_ids":  triggered,
	})
}

func (a *adminServer) handleEdgeNodeItem(w http.ResponseWriter, r *http.Request) {
	if a.gateway.cluster == nil {
		a.writeError(w, http.StatusServiceUnavailable, "edge node controller unavailable")
		return
	}
	remainder := strings.TrimPrefix(r.URL.Path, "/_admin/api/nodes/")
	parts := strings.Split(remainder, "/")
	nodeID := strings.TrimSpace(parts[0])
	if nodeID == "" || len(nodeID) > 48 || strings.ContainsAny(nodeID, " \t\r\n") {
		a.writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	if len(parts) == 2 && parts[1] == "rotate-token" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var payload struct {
			RevokeExisting bool `json:"revoke_existing"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&payload)
		record, enrollToken, err := a.store.RotateEdgeNodeEnrollToken(r.Context(), nodeID, payload.RevokeExisting)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "edge node not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to rotate node token")
			return
		}
		if payload.RevokeExisting {
			a.gateway.cluster.disconnectNode(nodeID)
		}
		a.auditRequest(r, "edge_node.rotate_token", record.Name, fmt.Sprintf("node_id=%s revoke=%t", nodeID, payload.RevokeExisting), true)
		deploy := buildAgentDeployCommands(a.resolveControllerURL(r), record.PublicURL, enrollToken, record.EnrollExpiresAt)
		a.writeJSON(w, http.StatusOK, map[string]any{"node": record, "deploy": deploy})
		return
	}

	if len(parts) == 2 && parts[1] == "upgrade" {
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		node, err := a.store.GetEdgeNode(r.Context(), nodeID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "edge node not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load edge node")
			return
		}
		if !a.gateway.cluster.TriggerNodeUpgrade(nodeID) {
			a.writeError(w, http.StatusConflict, "edge node is offline")
			return
		}
		a.auditRequest(r, "edge_node.upgrade", node.Name, "node_id="+nodeID, true)
		a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "node_id": nodeID})
		return
	}

	if len(parts) != 1 {
		a.writeError(w, http.StatusNotFound, "edge node route not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		views, _, err := a.gateway.cluster.ListNodeViews(r.Context())
		if err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to load edge node")
			return
		}
		for _, view := range views {
			if view.ID == nodeID {
				a.writeJSON(w, http.StatusOK, view)
				return
			}
		}
		a.writeError(w, http.StatusNotFound, "edge node not found")
	case http.MethodPut:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		var req edgeNodeMutationRequest
		if err := decodeAdminJSON(w, r, &req); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		merged := req.Overrides.ApplyTo(a.gateway.cluster.globalRuntimeSettings())
		if _, _, err := applyRuntimeSettings(Config{}, merged); err != nil {
			a.writeError(w, http.StatusBadRequest, "invalid node runtime overrides: "+err.Error())
			return
		}
		previous, prevErr := a.store.GetEdgeNode(r.Context(), nodeID)
		if prevErr != nil {
			if errors.Is(prevErr, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "edge node not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load edge node")
			return
		}
		visible := true
		if req.PublicVisible != nil {
			visible = *req.PublicVisible
		}
		autoDrain := previous.QuotaAutoDrain
		if req.QuotaAutoDrain != nil {
			autoDrain = *req.QuotaAutoDrain
		}
		record, err := a.store.UpdateEdgeNode(r.Context(), nodeID, edgeNodeUpdateInput{
			Name:           req.Name,
			GroupName:      req.GroupName,
			Region:         req.Region,
			PublicURL:      req.PublicURL,
			PublicVisible:  visible,
			Draining:       req.Draining,
			Overrides:      req.Overrides,
			ManualIPv4:     req.ManualIPv4,
			ManualIPv6:     req.ManualIPv6,
			DNSSyncEnabled: req.DNSSyncEnabled,
			DNSIPMode:      req.DNSIPMode,
			MonthlyQuotaGB: req.MonthlyQuotaGB,
			QuotaResetDay:  req.QuotaResetDay,
			QuotaDirection: req.QuotaDirection,
			QuotaAutoDrain: autoDrain,
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "edge node not found")
				return
			}
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.gateway.cluster.NotifyConfigChanged(nodeID)
		if a.gateway.cloudflare != nil || a.gateway.axisnow != nil {
			updCopy, prevCopy := record, previous
			a.gateway.cluster.runTracked(func() {
				syncCtx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 20*time.Second)
				defer cancel()
				if a.gateway.cloudflare != nil {
					if updCopy.DNSSyncEnabled || prevCopy.DNSSyncEnabled {
						_ = a.gateway.cloudflare.SyncNodeDNS(syncCtx, updCopy, prevCopy.PublicURL)
					}
					if updCopy.Draining != prevCopy.Draining {
						_, _ = a.gateway.cloudflare.EvaluateFailoverGroups(syncCtx, time.Now())
						_, _ = a.gateway.cloudflare.EvaluateEdgeDomainsDNS(syncCtx, time.Now())
					}
				}
				if a.gateway.axisnow != nil && (updCopy.Draining != prevCopy.Draining || updCopy.ManualIPv4 != prevCopy.ManualIPv4 || updCopy.MonthlyQuotaGB != prevCopy.MonthlyQuotaGB) {
					_, _ = a.gateway.axisnow.EvaluateEdgeDomainsSmartDNS(syncCtx, time.Now())
				}
			})
		}
		a.auditRequest(r, "edge_node.update", record.Name, fmt.Sprintf("node_id=%s draining=%t visible=%t", record.ID, record.Draining, record.PublicVisible), true)
		views, _, _ := a.gateway.cluster.ListNodeViews(r.Context())
		for _, view := range views {
			if view.ID == nodeID {
				a.writeJSON(w, http.StatusOK, view)
				return
			}
		}
		a.writeJSON(w, http.StatusOK, record)
	case http.MethodDelete:
		if !sameOriginRequest(r) {
			a.writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		existing, err := a.store.GetEdgeNode(r.Context(), nodeID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				a.writeError(w, http.StatusNotFound, "edge node not found")
				return
			}
			a.writeError(w, http.StatusInternalServerError, "failed to load edge node")
			return
		}
		if err := a.store.DeleteEdgeNode(r.Context(), nodeID); err != nil {
			a.writeError(w, http.StatusInternalServerError, "failed to delete edge node")
			return
		}
		_, _ = a.store.RemoveNodeFromAllDomains(r.Context(), nodeID)
		a.store.RemoveNodeFromAllSmartDNSProfiles(r.Context(), nodeID)
		a.gateway.cluster.disconnectNode(nodeID)
		if a.gateway.cloudflare != nil || a.gateway.axisnow != nil {
			nCopy := existing
			a.gateway.cluster.runTracked(func() {
				syncCtx, cancel := context.WithTimeout(a.gateway.cluster.ctx, 20*time.Second)
				defer cancel()
				if a.gateway.cloudflare != nil {
					if nCopy.DNSSyncEnabled {
						a.gateway.cloudflare.DeleteNodeDNS(syncCtx, nCopy)
					}
					_, _ = a.gateway.cloudflare.EvaluateEdgeDomainsDNS(syncCtx, time.Now())
				}
				if a.gateway.axisnow != nil {
					_, _ = a.gateway.axisnow.EvaluateEdgeDomainsSmartDNS(syncCtx, time.Now())
				}
			})
		}
		a.auditRequest(r, "edge_node.delete", existing.Name, "node_id="+nodeID, true)
		a.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		a.methodNotAllowed(w, http.MethodGet+", "+http.MethodPut+", "+http.MethodDelete)
	}
}
