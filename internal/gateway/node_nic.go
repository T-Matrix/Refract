package gateway

import (
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nicByteCounter struct {
	RXBytes uint64 `json:"rx_bytes"`
	TXBytes uint64 `json:"tx_bytes"`
}

type hostNICTrafficReport struct {
	Interfaces []string                  `json:"interfaces,omitempty"`
	Counters   map[string]nicByteCounter `json:"counters,omitempty"`
	RXBytes    uint64                    `json:"rx_bytes"`
	TXBytes    uint64                    `json:"tx_bytes"`
	RXBPS      int64                     `json:"rx_bps,omitempty"`
	TXBPS      int64                     `json:"tx_bps,omitempty"`
	BootID     string                    `json:"boot_id,omitempty"`
	SampledAt  int64                     `json:"sampled_at,omitempty"`
}

type hostNICSampler struct {
	mu           sync.Mutex
	bootID       string
	lastAt       time.Time
	lastCounters map[string]nicByteCounter
	lastRXBPS    int64
	lastTXBPS    int64
	reader       func(bootID string) *hostNICTrafficReport
}

func newHostNICSampler(bootID string) *hostNICSampler {
	return &hostNICSampler{
		bootID: strings.TrimSpace(bootID),
		reader: readHostPrimaryNICTraffic,
	}
}

func (s *hostNICSampler) Sample() *hostNICTrafficReport {
	return s.SampleAt(time.Now())
}

func (s *hostNICSampler) SampleAt(now time.Time) *hostNICTrafficReport {
	if s == nil || s.reader == nil {
		return nil
	}
	report := s.reader(s.bootID)
	if report == nil || len(report.Interfaces) == 0 {
		return nil
	}
	report.SampledAt = now.UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastAt.IsZero() {
		s.lastAt = now
		s.lastCounters = make(map[string]nicByteCounter, len(report.Counters))
		for k, v := range report.Counters {
			s.lastCounters[k] = v
		}
		s.lastRXBPS = 0
		s.lastTXBPS = 0
		return report
	}

	elapsed := now.Sub(s.lastAt)
	if elapsed < 500*time.Millisecond {
		report.RXBPS = s.lastRXBPS
		report.TXBPS = s.lastTXBPS
		return report
	}

	var deltaRX, deltaTX uint64
	for iface, cur := range report.Counters {
		prev, ok := s.lastCounters[iface]
		if !ok {
			continue
		}
		if cur.RXBytes >= prev.RXBytes {
			deltaRX += cur.RXBytes - prev.RXBytes
		}
		if cur.TXBytes >= prev.TXBytes {
			deltaTX += cur.TXBytes - prev.TXBytes
		}
	}
	secs := elapsed.Seconds()
	rxBPS := int64(math.Round(float64(deltaRX) / secs))
	txBPS := int64(math.Round(float64(deltaTX) / secs))

	s.lastAt = now
	s.lastCounters = make(map[string]nicByteCounter, len(report.Counters))
	for k, v := range report.Counters {
		s.lastCounters[k] = v
	}
	s.lastRXBPS = rxBPS
	s.lastTXBPS = txBPS
	report.RXBPS = rxBPS
	report.TXBPS = txBPS
	return report
}

const (
	arphrdEther    = 1
	arphrdPPP      = 512
	arphrdTunnel   = 768
	arphrdTunnel6  = 769
	arphrdLoopback = 772
	arphrdSIT      = 776
	arphrdIPGRE    = 778
	arphrdIP6GRE   = 823
	arphrdNone     = 65534

	iffUp          = 0x1
	iffLoopback    = 0x8
	iffPointToPoint = 0x10
	iffSlave       = 0x800
)

type sysfsNICInfo struct {
	HasSysfs     bool
	HasDevice    bool
	IsVirtual    bool
	IsBondMaster bool
	IsBridge     bool
	IsBridgePort bool
	IsTunTap     bool
	DevType      string
	ARPType      int
	HasFlags     bool
	Flags        uint64
	OperState    string
}

func inspectSysfsNIC(sysNetDir, iface string) sysfsNICInfo {
	info := sysfsNICInfo{ARPType: -1}
	if sysNetDir == "" || iface == "" {
		return info
	}
	dir := filepath.Join(sysNetDir, iface)
	if _, err := os.Lstat(dir); err != nil {
		return info
	}
	info.HasSysfs = true

	if target, err := os.Readlink(dir); err == nil {
		slashed := strings.ReplaceAll(target, `\`, "/")
		if strings.Contains(slashed, "/devices/virtual/") {
			info.IsVirtual = true
		} else {
			info.HasDevice = true
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "device")); err == nil {
		info.HasDevice = true
		info.IsVirtual = false
	}
	if uevRaw, err := os.ReadFile(filepath.Join(dir, "uevent")); err == nil {
		for _, line := range strings.Split(string(uevRaw), "\n") {
			if strings.HasPrefix(line, "DEVTYPE=") {
				info.DevType = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "DEVTYPE=")))
				break
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bonding", "slaves")); err == nil || info.DevType == "bond" || info.DevType == "team" {
		info.IsBondMaster = true
	}
	if _, err := os.Stat(filepath.Join(dir, "bridge")); err == nil || info.DevType == "bridge" {
		info.IsBridge = true
	}
	if _, err := os.Stat(filepath.Join(dir, "brport")); err == nil {
		info.IsBridgePort = true
	}
	if _, err := os.Stat(filepath.Join(dir, "tun_flags")); err == nil {
		info.IsTunTap = true
	}
	if rawType, err := os.ReadFile(filepath.Join(dir, "type")); err == nil {
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(string(rawType))); parseErr == nil {
			info.ARPType = parsed
		}
	}
	if rawFlags, err := os.ReadFile(filepath.Join(dir, "flags")); err == nil {
		s := strings.TrimSpace(strings.ToLower(string(rawFlags)))
		s = strings.TrimPrefix(s, "0x")
		if parsed, parseErr := strconv.ParseUint(s, 16, 64); parseErr == nil {
			info.HasFlags = true
			info.Flags = parsed
		}
	}
	if rawOper, err := os.ReadFile(filepath.Join(dir, "operstate")); err == nil {
		info.OperState = strings.ToLower(strings.TrimSpace(string(rawOper)))
	}
	return info
}

func (i sysfsNICInfo) isLoopback() bool {
	return i.ARPType == arphrdLoopback || (i.HasFlags && i.Flags&iffLoopback != 0)
}

func (i sysfsNICInfo) isKnownTunnelARP() bool {
	switch i.ARPType {
	case arphrdPPP, arphrdTunnel, arphrdTunnel6, arphrdSIT, arphrdIPGRE, arphrdIP6GRE:
		return true
	default:
		return false
	}
}

func (i sysfsNICInfo) isVirtualTunnelOrOverlay() bool {
	if i.IsTunTap || i.isKnownTunnelARP() || i.ARPType == arphrdNone || (i.HasFlags && i.Flags&iffPointToPoint != 0) {
		return true
	}
	switch i.DevType {
	case "wireguard", "vxlan", "geneve", "gre", "sit", "ipip", "ip6tnl", "ip6gre", "dummy", "ifb", "macvlan", "ipvlan", "vlan":
		return true
	default:
		return false
	}
}

func (i sysfsNICInfo) isSlave() bool {
	return i.HasFlags && i.Flags&iffSlave != 0
}

func (i sysfsNICInfo) isOperUp() bool {
	switch i.OperState {
	case "down", "notpresent", "lowerlayerdown":
		return false
	}
	if i.HasFlags && i.Flags&iffUp == 0 {
		return false
	}
	return true
}

func (i sysfsNICInfo) isHardwarePrimaryCandidate() bool {
	return i.HasSysfs && (i.HasDevice || i.IsBondMaster) && !i.isLoopback() && !i.IsBridge && !i.isVirtualTunnelOrOverlay() && !i.isSlave()
}

func (i sysfsNICInfo) isContainerEthernetCandidate() bool {
	return i.HasSysfs && !i.isLoopback() && !i.IsBridge && !i.IsBridgePort && !i.IsTunTap && !i.isVirtualTunnelOrOverlay() && !i.isSlave() && (i.ARPType == arphrdEther || i.ARPType == -1)
}

func (i sysfsNICInfo) isContainerPtPCandidate() bool {
	if !i.HasSysfs || i.isLoopback() || i.IsBridge || i.IsBridgePort || i.IsTunTap || i.isKnownTunnelARP() || i.isSlave() {
		return false
	}
	switch i.DevType {
	case "wireguard", "dummy", "vxlan", "geneve":
		return false
	default:
		return true
	}
}

func ifaceHasPublicIP(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface == nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, raw := range addrs {
		var addr netip.Addr
		if p, pErr := netip.ParsePrefix(raw.String()); pErr == nil {
			addr = p.Addr().Unmap()
		} else if a, aErr := netip.ParseAddr(raw.String()); aErr == nil {
			addr = a.Unmap()
		} else {
			continue
		}
		if addr.IsGlobalUnicast() && !isBlockedAddress(addr) {
			return true
		}
	}
	return false
}

func parseProcNetDev(raw string) map[string]nicByteCounter {
	out := make(map[string]nicByteCounter)
	for _, line := range strings.Split(raw, "\n") {
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		iface := strings.TrimSpace(line[:colon])
		if iface == "" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[iface] = nicByteCounter{RXBytes: rx, TXBytes: tx}
	}
	return out
}

func parseProcNetRouteDefaultIfaces(raw string) []string {
	var ifaces []string
	seen := make(map[string]struct{})
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		iface := strings.TrimSpace(fields[0])
		dest := strings.TrimSpace(fields[1])
		flagsHex := strings.TrimSpace(fields[3])
		mask := strings.TrimSpace(fields[7])
		if iface == "" || dest != "00000000" || mask != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(flagsHex, 16, 64)
		if err != nil || flags&0x1 == 0 || flags&0x0200 != 0 {
			continue
		}
		if _, ok := seen[iface]; !ok {
			seen[iface] = struct{}{}
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

func resolveLowerNICs(sysNetDir, iface string, maxDepth int) []string {
	if sysNetDir == "" || iface == "" || maxDepth <= 0 {
		return nil
	}
	var out []string
	seen := map[string]struct{}{iface: {}}
	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if depth <= 0 {
			return
		}
		entries, err := os.ReadDir(filepath.Join(sysNetDir, cur))
		if err != nil {
			return
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "lower_") {
				continue
			}
			lower := strings.TrimPrefix(name, "lower_")
			if lower == "" || lower == "lo" {
				continue
			}
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			out = append(out, lower)
			walk(lower, depth-1)
		}
	}
	walk(iface, maxDepth)
	return out
}

func parseProcNetIPv6RouteDefaultIfaces(raw string) []string {
	var ifaces []string
	seen := make(map[string]struct{})
	const zeroAddr = "00000000000000000000000000000000"
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		dest := strings.TrimSpace(fields[0])
		prefixLen := strings.TrimSpace(fields[1])
		flagsHex := strings.TrimSpace(fields[8])
		iface := strings.TrimSpace(fields[9])
		if iface == "" || iface == "lo" || dest != zeroAddr || prefixLen != "00" {
			continue
		}
		flags, err := strconv.ParseUint(flagsHex, 16, 64)
		if err != nil || flags&0x1 == 0 || flags&0x0200 != 0 {
			continue
		}
		if _, ok := seen[iface]; !ok {
			seen[iface] = struct{}{}
			ifaces = append(ifaces, iface)
		}
	}
	return ifaces
}

func selectPrimaryNICs(devMap map[string]nicByteCounter, v4Defaults, v6Defaults []string, sysNetDir string) []string {
	return selectPrimaryNICsWithIPCheck(devMap, v4Defaults, v6Defaults, sysNetDir, ifaceHasPublicIP)
}

func selectPrimaryNICsWithIPCheck(
	devMap map[string]nicByteCounter,
	v4Defaults, v6Defaults []string,
	sysNetDir string,
	hasPublicIP func(string) bool,
) []string {
	if len(devMap) == 0 {
		return nil
	}

	defaultSet := make(map[string]struct{})
	for _, name := range append(append([]string(nil), v4Defaults...), v6Defaults...) {
		if _, ok := devMap[name]; ok {
			defaultSet[name] = struct{}{}
		}
		for _, lower := range resolveLowerNICs(sysNetDir, name, 4) {
			if _, ok := devMap[lower]; ok {
				defaultSet[lower] = struct{}{}
			}
		}
	}

	infos := make(map[string]sysfsNICInfo, len(devMap))
	anySysfs := false
	hwNICs := make([]string, 0, len(devMap))
	for name := range devMap {
		info := inspectSysfsNIC(sysNetDir, name)
		infos[name] = info
		if info.HasSysfs {
			anySysfs = true
		}
		if info.isHardwarePrimaryCandidate() {
			hwNICs = append(hwNICs, name)
		}
	}

	narrowCandidates := func(cands []string) []string {
		if len(cands) == 0 {
			return nil
		}
		if len(cands) > 1 {
			up := make([]string, 0, len(cands))
			for _, name := range cands {
				if infos[name].isOperUp() {
					up = append(up, name)
				}
			}
			if len(up) > 0 {
				cands = up
			}
		}
		if len(cands) > 1 && hasPublicIP != nil {
			pub := make([]string, 0, len(cands))
			for _, name := range cands {
				if hasPublicIP(name) {
					pub = append(pub, name)
				}
			}
			if len(pub) > 0 {
				cands = pub
			}
		}
		if len(cands) > 1 {
			active := make([]string, 0, len(cands))
			for _, name := range cands {
				c := devMap[name]
				if c.RXBytes > 0 || c.TXBytes > 0 {
					active = append(active, name)
				}
			}
			if len(active) > 0 {
				cands = active
			}
		}
		sort.Strings(cands)
		return cands
	}

	if len(hwNICs) > 0 {
		hwDefaults := make([]string, 0, len(hwNICs))
		for _, name := range hwNICs {
			if _, ok := defaultSet[name]; ok {
				hwDefaults = append(hwDefaults, name)
			}
		}
		if len(hwDefaults) > 0 {
			sort.Strings(hwDefaults)
			return hwDefaults
		}
		return narrowCandidates(hwNICs)
	}

	if anySysfs {
		var ethCands, ptpCands, ethDefaults, ptpDefaults []string
		for name, info := range infos {
			if info.isContainerEthernetCandidate() {
				ethCands = append(ethCands, name)
				if _, ok := defaultSet[name]; ok {
					ethDefaults = append(ethDefaults, name)
				}
			} else if info.isContainerPtPCandidate() {
				ptpCands = append(ptpCands, name)
				if _, ok := defaultSet[name]; ok {
					ptpDefaults = append(ptpDefaults, name)
				}
			}
		}
		if len(ethDefaults) > 0 {
			sort.Strings(ethDefaults)
			return ethDefaults
		}
		if len(ptpDefaults) > 0 {
			sort.Strings(ptpDefaults)
			return ptpDefaults
		}
		if len(ethCands) > 0 {
			return narrowCandidates(ethCands)
		}
		if len(ptpCands) > 0 {
			return narrowCandidates(ptpCands)
		}
		return nil
	}

	// Graceful fallback only when sysfs (/sys/class/net) itself is completely unavailable.
	var fallback []string
	for name := range defaultSet {
		if name != "lo" {
			fallback = append(fallback, name)
		}
	}
	if len(fallback) > 0 {
		sort.Strings(fallback)
		return fallback
	}
	var bestName string
	var bestTotal uint64
	for name, c := range devMap {
		if name == "lo" {
			continue
		}
		if sum := c.RXBytes + c.TXBytes; bestName == "" || sum > bestTotal {
			bestName = name
			bestTotal = sum
		}
	}
	if bestName != "" {
		return []string{bestName}
	}
	return nil
}

func readHostPrimaryNICTrafficFrom(procDevPath, procRoutePath, procIPv6RoutePath, sysNetDir, bootID string) *hostNICTrafficReport {
	rawDev, err := os.ReadFile(procDevPath)
	if err != nil {
		return nil
	}
	devMap := parseProcNetDev(string(rawDev))
	if len(devMap) == 0 {
		return nil
	}
	var v4Defaults, v6Defaults []string
	if rawR4, r4Err := os.ReadFile(procRoutePath); r4Err == nil {
		v4Defaults = parseProcNetRouteDefaultIfaces(string(rawR4))
	}
	if rawR6, r6Err := os.ReadFile(procIPv6RoutePath); r6Err == nil {
		v6Defaults = parseProcNetIPv6RouteDefaultIfaces(string(rawR6))
	}
	ifaces := selectPrimaryNICs(devMap, v4Defaults, v6Defaults, sysNetDir)
	if len(ifaces) == 0 {
		return nil
	}
	report := &hostNICTrafficReport{
		Interfaces: ifaces,
		Counters:   make(map[string]nicByteCounter, len(ifaces)),
		BootID:     strings.TrimSpace(bootID),
	}
	for _, iface := range ifaces {
		c := devMap[iface]
		report.Counters[iface] = c
		report.RXBytes += c.RXBytes
		report.TXBytes += c.TXBytes
	}
	return report
}

func readHostPrimaryNICTraffic(bootID string) *hostNICTrafficReport {
	if runtime.GOOS != "linux" {
		return nil
	}
	if strings.TrimSpace(bootID) == "" {
		bootID = readHostBootID()
	}
	return readHostPrimaryNICTrafficFrom("/proc/net/dev", "/proc/net/route", "/proc/net/ipv6_route", "/sys/class/net", bootID)
}

func readHostBootID() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
