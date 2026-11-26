package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func makeSysfsNIC(t *testing.T, root, sysNet, iface string, physical bool, arpType int, flagsHex, operState, devType string, subdirs ...string) {
	t.Helper()
	var devDir string
	if physical {
		devDir = filepath.Join(root, "devices", "pci0000:00", "virtio_"+iface, "net", iface)
		if err := os.MkdirAll(filepath.Join(devDir, "device"), 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		devDir = filepath.Join(root, "devices", "virtual", "net", iface)
		if err := os.MkdirAll(devDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if arpType >= 0 {
		_ = os.WriteFile(filepath.Join(devDir, "type"), []byte(strconv.Itoa(arpType)+"\n"), 0o644)
	}
	if flagsHex != "" {
		_ = os.WriteFile(filepath.Join(devDir, "flags"), []byte(flagsHex+"\n"), 0o644)
	}
	if operState != "" {
		_ = os.WriteFile(filepath.Join(devDir, "operstate"), []byte(operState+"\n"), 0o644)
	}
	uevent := "INTERFACE=" + iface + "\n"
	if devType != "" {
		uevent += "DEVTYPE=" + devType + "\n"
	}
	_ = os.WriteFile(filepath.Join(devDir, "uevent"), []byte(uevent), 0o644)
	for _, sub := range subdirs {
		switch sub {
		case "tun_flags":
			_ = os.WriteFile(filepath.Join(devDir, "tun_flags"), []byte("0x1001\n"), 0o644)
		case "bonding/slaves":
			_ = os.MkdirAll(filepath.Join(devDir, "bonding"), 0o755)
			_ = os.WriteFile(filepath.Join(devDir, "bonding", "slaves"), []byte("eth0\n"), 0o644)
		default:
			_ = os.MkdirAll(filepath.Join(devDir, sub), 0o755)
		}
	}
	rel, err := filepath.Rel(sysNet, devDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(rel, filepath.Join(sysNet, iface))
}

func TestSelectPrimaryNICsExcludesVirtualAndDocker(t *testing.T) {
	t.Run("RackNerd single physical NIC ens3", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "ens3", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "lo", false, 772, "0x9", "unknown", "")

		dev := `Inter-| Receive | Transmit
    lo: 34986553059 1 0 0 0 0 0 0 34986553059 1 0 0 0 0 0 0
  ens3: 39728450473 1 0 0 0 0 0 0 38454467730 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"ens3\t00000000\t418C0B48\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), nil, sysNet, nil)
		if !reflect.DeepEqual(got, []string{"ens3"}) {
			t.Fatalf("expected [ens3], got %v", got)
		}
	})

	t.Run("ComputeBox enp6s18 with docker0 br and veth", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "enp6s18", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "lo", false, 772, "0x9", "unknown", "")
		makeSysfsNIC(t, root, sysNet, "docker0", false, 1, "0x1003", "down", "bridge", "bridge")
		makeSysfsNIC(t, root, sysNet, "br-61e066ab4bfd", false, 1, "0x1003", "up", "bridge", "bridge")
		makeSysfsNIC(t, root, sysNet, "vetha1fcf18", false, 1, "0x1303", "up", "", "brport")

		dev := `Inter-| Receive | Transmit
    lo: 765999877834 1 0 0 0 0 0 0 765999877834 1 0 0 0 0 0 0
enp6s18: 144090220254 1 0 0 0 0 0 0 52570302285 1 0 0 0 0 0 0
docker0: 410547610034 1 0 0 0 0 0 0 199065635297 1 0 0 0 0 0 0
br-61e066ab4bfd: 27741122653 1 0 0 0 0 0 0 30454518469 1 0 0 0 0 0 0
vetha1fcf18: 412806297685 1 0 0 0 0 0 0 194764287896 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"enp6s18\t00000000\t014E6A59\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), nil, sysNet, nil)
		if !reflect.DeepEqual(got, []string{"enp6s18"}) {
			t.Fatalf("expected [enp6s18], got %v", got)
		}
	})

	t.Run("ACCK dual NIC ens18 IPv4 and ens19 IPv6 with docker/veth", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "ens18", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "ens19", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "lo", false, 772, "0x9", "unknown", "")
		makeSysfsNIC(t, root, sysNet, "br-97fe7eb65455", false, 1, "0x1003", "up", "bridge", "bridge")
		makeSysfsNIC(t, root, sysNet, "vethb8c5299", false, 1, "0x1303", "up", "", "brport")

		dev := `Inter-| Receive | Transmit
    lo: 91192973 1 0 0 0 0 0 0 91192973 1 0 0 0 0 0 0
 ens18: 6305817010 1 0 0 0 0 0 0 472339522 1 0 0 0 0 0 0
 ens19: 13928153451 1 0 0 0 0 0 0 28523608 1 0 0 0 0 0 0
br-97fe7eb65455: 34191259 1 0 0 0 0 0 0 120190571 1 0 0 0 0 0 0
vethb8c5299: 38126617 1 0 0 0 0 0 0 119037144 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"ens18\t00000000\t01F0C02D\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		route6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 2602f3f200b000000000000000000001 00000400 00000000 00000000 00000003 ens19\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), parseProcNetIPv6RouteDefaultIfaces(route6), sysNet, nil)
		if !reflect.DeepEqual(got, []string{"ens18", "ens19"}) {
			t.Fatalf("expected [ens18 ens19], got %v", got)
		}
	})

	t.Run("Custom-renamed physical wg_wan0 vs custom-renamed WireGuard Docker and TUN", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		// Custom-named physical NIC (looks like WireGuard name!)
		makeSysfsNIC(t, root, sysNet, "wg_wan0", true, 1, "0x1003", "up", "")
		// Custom-named WireGuard (unrelated name hk_direct)
		makeSysfsNIC(t, root, sysNet, "hk_direct", false, 65534, "0xd1", "unknown", "wireguard")
		// Custom-named Docker bridge (emby_net)
		makeSysfsNIC(t, root, sysNet, "emby_net", false, 1, "0x1003", "up", "bridge", "bridge")
		// Custom-named veth attached to bridge (pub_veth)
		makeSysfsNIC(t, root, sysNet, "pub_veth", false, 1, "0x1303", "up", "", "brport")
		// Custom-named sing-box TUN (proxy_main)
		makeSysfsNIC(t, root, sysNet, "proxy_main", false, 65534, "0x1091", "up", "", "tun_flags")

		dev := `Inter-| Receive | Transmit
   wg_wan0: 50000 1 0 0 0 0 0 0 60000 1 0 0 0 0 0 0
 hk_direct: 90000 1 0 0 0 0 0 0 90000 1 0 0 0 0 0 0
  emby_net: 40000 1 0 0 0 0 0 0 40000 1 0 0 0 0 0 0
  pub_veth: 40000 1 0 0 0 0 0 0 40000 1 0 0 0 0 0 0
proxy_main: 70000 1 0 0 0 0 0 0 70000 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"wg_wan0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), nil, sysNet, nil)
		if !reflect.DeepEqual(got, []string{"wg_wan0"}) {
			t.Fatalf("expected custom physical NIC [wg_wan0], got %v", got)
		}
	})

	t.Run("Custom VPN hijacks default route with dual custom physical NICs", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "my_pub", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "my_lan", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "myvpn", false, 65534, "0xd1", "unknown", "wireguard")

		dev := `Inter-| Receive | Transmit
my_pub: 2000 1 0 0 0 0 0 0 3000 1 0 0 0 0 0 0
my_lan: 2000 1 0 0 0 0 0 0 3000 1 0 0 0 0 0 0
 myvpn: 9000 1 0 0 0 0 0 0 9000 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"myvpn\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), nil, sysNet, func(name string) bool {
			return name == "my_pub"
		})
		if !reflect.DeepEqual(got, []string{"my_pub"}) {
			t.Fatalf("expected [my_pub], got %v", got)
		}
	})

	t.Run("Physical uplink0 alongside custom SIT tunnel isp_v6 selects uplink0 only", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "uplink0", true, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "isp_v6", false, 776, "0x91", "unknown", "sit")

		dev := `Inter-| Receive | Transmit
uplink0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
 isp_v6: 500 1 0 0 0 0 0 0 500 1 0 0 0 0 0 0
`
		route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"uplink0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		route6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000000 00000000 00000003 isp_v6\n"
		got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), parseProcNetRouteDefaultIfaces(route4), parseProcNetIPv6RouteDefaultIfaces(route6), sysNet, nil)
		if !reflect.DeepEqual(got, []string{"uplink0"}) {
			t.Fatalf("expected [uplink0], got %v", got)
		}
	})

	t.Run("Container-only LXC and OpenVZ virtual fallback", func(t *testing.T) {
		root := t.TempDir()
		sysNet := filepath.Join(root, "class", "net")
		_ = os.MkdirAll(sysNet, 0o755)
		makeSysfsNIC(t, root, sysNet, "wan0", false, 1, "0x1003", "up", "")
		makeSysfsNIC(t, root, sysNet, "mywg", false, 65534, "0xd1", "unknown", "wireguard")
		makeSysfsNIC(t, root, sysNet, "inner0", false, 1, "0x1003", "up", "bridge", "bridge")
		makeSysfsNIC(t, root, sysNet, "lo", false, 772, "0x9", "unknown", "")

		devLXC := `Inter-| Receive | Transmit
    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
  wan0: 888 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0
  mywg: 500 1 0 0 0 0 0 0 500 1 0 0 0 0 0 0
inner0: 200 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
`
		route4LXC := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"wan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
		gotLXC := selectPrimaryNICsWithIPCheck(parseProcNetDev(devLXC), parseProcNetRouteDefaultIfaces(route4LXC), nil, sysNet, nil)
		if !reflect.DeepEqual(gotLXC, []string{"wan0"}) {
			t.Fatalf("expected [wan0] on LXC, got %v", gotLXC)
		}

		// Pure OpenVZ venet0 container without physical or Ethernet NICs
		rootOVZ := t.TempDir()
		sysNetOVZ := filepath.Join(rootOVZ, "class", "net")
		_ = os.MkdirAll(sysNetOVZ, 0o755)
		makeSysfsNIC(t, rootOVZ, sysNetOVZ, "venet0", false, 65534, "0x1091", "unknown", "")
		makeSysfsNIC(t, rootOVZ, sysNetOVZ, "lo", false, 772, "0x9", "unknown", "")

		devOVZ := `Inter-| Receive | Transmit
    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
venet0: 888 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0
`
		route4OVZ := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"venet0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
		gotOVZ := selectPrimaryNICsWithIPCheck(parseProcNetDev(devOVZ), parseProcNetRouteDefaultIfaces(route4OVZ), nil, sysNetOVZ, nil)
		if !reflect.DeepEqual(gotOVZ, []string{"venet0"}) {
			t.Fatalf("expected [venet0] on OpenVZ, got %v", gotOVZ)
		}
	})
}

func TestNodeNICTrafficBillingDeltaRebootAndDirection(t *testing.T) {
	store, err := openTelemetryStore(":memory:", "admin", "hash")
	if err != nil {
		t.Fatalf("openTelemetryStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	node, _, err := store.CreateEdgeNode(ctx, edgeNodeRecord{
		Name:           "Billing Node",
		MonthlyQuotaGB: 10,
		QuotaResetDay:  1,
		QuotaDirection: "both",
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}

	cycleStart := time.Date(2026, 11, 1, 0, 0, 0, 0, applicationLocation).Unix()
	tPre := time.Date(2026, 11, 26, 10, 0, 0, 0, applicationLocation)
	tFirst := time.Date(2026, 11, 26, 12, 0, 0, 0, applicationLocation)
	t2 := time.Date(2026, 11, 26, 12, 1, 0, 0, applicationLocation)
	t3 := time.Date(2026, 11, 26, 12, 2, 0, 0, applicationLocation)

	// Seed pre-NIC proxy traffic (500 bytes in, 1000 bytes out) BEFORE first NIC sample,
	// plus another row AT tFirst (which must NOT be double-counted once NIC anchors at tFirst).
	_, _ = store.db.Exec(`INSERT INTO node_traffic_minutes(minute,node_id,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?,?)`,
		tPre.Unix(), node.ID, "emby.test", 1, 500, 1000, 0, 10)
	_, _ = store.db.Exec(`INSERT INTO node_traffic_minutes(minute,node_id,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?,?)`,
		tFirst.Unix(), node.ID, "emby.test", 1, 9999, 9999, 0, 10)

	// 1. First NIC sample with huge uptime counters -> baseline only (0 delta recorded in NIC table)
	err = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"ens18", "ens19"},
		Counters: map[string]nicByteCounter{
			"ens18": {RXBytes: 6_000_000_000, TXBytes: 400_000_000},
			"ens19": {RXBytes: 13_000_000_000, TXBytes: 20_000_000},
		},
		RXBytes: 19_000_000_000,
		TXBytes: 420_000_000,
		BootID:  "boot-1",
	}, tFirst)
	if err != nil {
		t.Fatalf("first RecordNodeNICTrafficSample: %v", err)
	}

	// Only pre-upgrade carry-over (500+1000 = 1500 both, 1000 out); tFirst proxy row (9999) is NOT double-counted!
	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "both"); got != 1500 {
		t.Fatalf("after baseline expected 1500 (pre-NIC carryover only), got %d", got)
	}
	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "out"); got != 1000 {
		t.Fatalf("after baseline expected 1000 out, got %d", got)
	}

	// 2. Subsequent deltas (+3000 RX, +7000 TX across ens18 & ens19)
	err = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"ens18", "ens19"},
		Counters: map[string]nicByteCounter{
			"ens18": {RXBytes: 6_000_002_000, TXBytes: 400_005_000},
			"ens19": {RXBytes: 13_000_001_000, TXBytes: 20_002_000},
		},
		RXBytes: 19_000_003_000,
		TXBytes: 420_007_000,
		BootID:  "boot-1",
	}, t2)
	if err != nil {
		t.Fatalf("second RecordNodeNICTrafficSample: %v", err)
	}

	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "both"); got != 1500+10_000 {
		t.Fatalf("expected 11500 both, got %d", got)
	}
	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "out"); got != 1000+7000 {
		t.Fatalf("expected 8000 out, got %d", got)
	}

	// 3. Reboot with new BootID resets NIC counters to small post-reboot counts -> full post-reboot counters credited
	err = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"ens18", "ens19"},
		Counters: map[string]nicByteCounter{
			"ens18": {RXBytes: 1200, TXBytes: 800},
			"ens19": {RXBytes: 300, TXBytes: 200},
		},
		RXBytes: 1500,
		TXBytes: 1000,
		BootID:  "boot-2",
	}, t3)
	if err != nil {
		t.Fatalf("reboot RecordNodeNICTrafficSample: %v", err)
	}

	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "both"); got != 11500+2500 {
		t.Fatalf("expected 14000 both after reboot, got %d", got)
	}
	if got, _ := store.NodeCycleTrafficUsage(ctx, node.ID, cycleStart, "out"); got != 8000+1000 {
		t.Fatalf("expected 9000 out after reboot, got %d", got)
	}

	// 4. Dashboard SnapshotForNode remains purely proxy telemetry (must NOT include NIC counters)
	dashNow := time.Now().Truncate(time.Minute)
	_, _ = store.db.Exec(`INSERT INTO node_traffic_minutes(minute,node_id,host,requests,bytes_in,bytes_out,errors,duration_ms) VALUES(?,?,?,?,?,?,?,?)`,
		dashNow.Unix(), node.ID, "dash.test", 1, 123, 456, 0, 10)
	dash, err := store.SnapshotForNode(ctx, 24*time.Hour, node.ID, 0, 0, time.Second, nil)
	if err != nil {
		t.Fatalf("SnapshotForNode: %v", err)
	}
	if dash.BytesIn24H != 123+500+9999 && dash.BytesIn24H != 123 {
		t.Fatalf("expected dashboard proxy metrics unaffected by NIC billing, got in=%d out=%d", dash.BytesIn24H, dash.BytesOut24H)
	}
	if dash.BytesIn24H >= 6_000_000_000 || dash.BytesOut24H >= 400_000_000 {
		t.Fatalf("dashboard leaked NIC counters into proxy telemetry: in=%d out=%d", dash.BytesIn24H, dash.BytesOut24H)
	}

	// 5. Controller heartbeat integration updates nic_interfaces & monthly_used_bytes via ListNodes
	gw := newControllerTestGateway(t)
	hbNode, enrollTok, err := gw.telemetry.CreateEdgeNode(ctx, edgeNodeRecord{
		Name: "HB NIC Node", MonthlyQuotaGB: 10, QuotaResetDay: 1, QuotaDirection: "both",
	})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}
	_, secret, err := gw.telemetry.CompleteEdgeNodeEnrollment(ctx, enrollTok, "1.0.0", "linux/amd64", "hb-host")
	if err != nil {
		t.Fatalf("CompleteEdgeNodeEnrollment: %v", err)
	}
	sendHB := func(rx, tx uint64, rxBPS, txBPS int64) {
		t.Helper()
		payloadBytes, _ := json.Marshal(agentHeartbeatRequest{
			Version: "1.0.0",
			Arch:    "linux/amd64",
			Metrics: edgeNodeMetrics{
				NICTraffic: &hostNICTrafficReport{
					Interfaces: []string{"eth0"},
					Counters:   map[string]nicByteCounter{"eth0": {RXBytes: rx, TXBytes: tx}},
					RXBytes:    rx,
					TXBytes:    tx,
					RXBPS:      rxBPS,
					TXBPS:      txBPS,
					BootID:     "hb-boot-1",
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/_agent/api/v1/heartbeat", bytes.NewReader(payloadBytes))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("heartbeat status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
	sendHB(500_000_000, 100_000_000, 0, 0)
	sendHB(500_040_000, 100_060_000, 20_000, 30_000) // +100,000 total bytes (40k RX + 60k TX)

	views, summary, err := gw.cluster.ListNodeViews(ctx)
	if err != nil {
		t.Fatalf("ListNodeViews: %v", err)
	}
	var found *edgeNodeView
	for i := range views {
		if views[i].ID == hbNode.ID {
			found = &views[i]
		}
	}
	if found == nil || !reflect.DeepEqual(found.NICInterfaces, []string{"eth0"}) || found.MonthlyUsedBytes != 100_000 {
		t.Fatalf("unexpected ListNodes view for NIC billing: %+v", found)
	}
	if found.Metrics.NICTraffic == nil || found.Metrics.NICTraffic.RXBPS != 20_000 || found.Metrics.NICTraffic.TXBPS != 30_000 {
		t.Fatalf("expected live NIC RX/TX bps on view metrics, got %+v", found.Metrics.NICTraffic)
	}
	if !summary.HasNICMetrics || summary.TotalNICRXBPS != 20_000 || summary.TotalNICTXBPS != 30_000 {
		t.Fatalf("expected summary NIC RX/TX bps (20000/30000), got %+v", summary)
	}
}

func TestHostNICSamplerComputesRealTimeRXTXBPS(t *testing.T) {
	var curRX, curTX uint64 = 1_000_000, 2_000_000
	sampler := &hostNICSampler{
		bootID: "boot-rate-test",
		reader: func(bootID string) *hostNICTrafficReport {
			return &hostNICTrafficReport{
				Interfaces: []string{"ens3"},
				Counters: map[string]nicByteCounter{
					"ens3": {RXBytes: curRX, TXBytes: curTX},
				},
				RXBytes: curRX,
				TXBytes: curTX,
				BootID:  bootID,
			}
		},
	}

	t0 := time.Date(2026, 11, 26, 20, 0, 0, 0, time.UTC)
	r0 := sampler.SampleAt(t0)
	if r0 == nil || r0.RXBPS != 0 || r0.TXBPS != 0 {
		t.Fatalf("expected 0 BPS on initial baseline sample, got %+v", r0)
	}

	const thirtyTwoMiB = 32 << 20
	curRX += thirtyTwoMiB
	curTX += thirtyTwoMiB
	t1 := t0.Add(2 * time.Second)
	r1 := sampler.SampleAt(t1)
	if r1 == nil || r1.RXBPS != 16<<20 || r1.TXBPS != 16<<20 {
		t.Fatalf("expected 16 MiB/s RX and TX after 2s, got rx=%d tx=%d", r1.RXBPS, r1.TXBPS)
	}

	// Sub-500ms repeat call preserves previous rate without zeroing or resetting baseline.
	curRX += 1024
	rFast := sampler.SampleAt(t1.Add(100 * time.Millisecond))
	if rFast == nil || rFast.RXBPS != 16<<20 || rFast.TXBPS != 16<<20 {
		t.Fatalf("expected sub-500ms sample to preserve prior rates, got %+v", rFast)
	}
}

func TestRecordNodeNICTrafficOutOfOrderAndDropGuard(t *testing.T) {
	store, err := openTelemetryStore(":memory:", "admin", "hash")
	if err != nil {
		t.Fatalf("openTelemetryStore: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	node, _, err := store.CreateEdgeNode(ctx, edgeNodeRecord{Name: "Guard Node", QuotaDirection: "both"})
	if err != nil {
		t.Fatalf("CreateEdgeNode: %v", err)
	}
	now := time.Now()
	const oneGiB = uint64(1) << 30
	// Baseline at t=10s: 10 GiB
	_ = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"eth0"},
		Counters:   map[string]nicByteCounter{"eth0": {RXBytes: 10 * oneGiB, TXBytes: 5 * oneGiB}},
		BootID:     "boot-guard",
		SampledAt:  10_000_000_000,
	}, now)
	// Normal advance at t=20s: +100 MiB RX
	const hundredMiB = uint64(100) << 20
	_ = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"eth0"},
		Counters:   map[string]nicByteCounter{"eth0": {RXBytes: 10*oneGiB + hundredMiB, TXBytes: 5 * oneGiB}},
		BootID:     "boot-guard",
		SampledAt:  20_000_000_000,
	}, now.Add(time.Second))
	// Out-of-order delayed sample with t=15s must be ignored without resetting or adding bytes.
	_ = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"eth0"},
		Counters:   map[string]nicByteCounter{"eth0": {RXBytes: 10*oneGiB + 50<<20, TXBytes: 5 * oneGiB}},
		BootID:     "boot-guard",
		SampledAt:  15_000_000_000,
	}, now.Add(2*time.Second))
	// Drop > 2 GiB (e.g. 6 GiB when prev was 10 GiB) must NOT be misclassified as counter reset.
	_ = store.RecordNodeNICTrafficSample(ctx, node.ID, &hostNICTrafficReport{
		Interfaces: []string{"eth0"},
		Counters:   map[string]nicByteCounter{"eth0": {RXBytes: 6 * oneGiB, TXBytes: 5 * oneGiB}},
		BootID:     "boot-guard",
		SampledAt:  25_000_000_000,
	}, now.Add(3*time.Second))

	used, err := store.NodeCycleTrafficUsage(ctx, node.ID, 0, "both")
	if err != nil {
		t.Fatalf("NodeCycleTrafficUsage: %v", err)
	}
	if used != int64(hundredMiB) {
		t.Fatalf("expected billed usage=%d bytes, got %d", hundredMiB, used)
	}
}

func TestProcRouteRejectAndLowerNICResolution(t *testing.T) {
	// Route with RTF_REJECT (0x0200) must be skipped even when UP (0x1).
	route4 := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wg0\t00000000\t00000000\t0203\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0.100\t00000000\t01010101\t0003\t0\t0\t10\t00000000\t0\t0\t0\n"
	v4 := parseProcNetRouteDefaultIfaces(route4)
	if !reflect.DeepEqual(v4, []string{"eth0.100"}) {
		t.Fatalf("expected [eth0.100] with RTF_REJECT filtered, got %v", v4)
	}

	root := t.TempDir()
	sysNet := filepath.Join(root, "class", "net")
	_ = os.MkdirAll(sysNet, 0o755)
	makeSysfsNIC(t, root, sysNet, "eth0", true, 1, "0x1003", "up", "")
	makeSysfsNIC(t, root, sysNet, "eth0.100", false, 1, "0x1003", "up", "vlan", "lower_eth0")
	dev := `Inter-| Receive | Transmit
  eth0: 5000000 1 0 0 0 0 0 0 6000000 1 0 0 0 0 0 0
eth0.100: 100 1 0 0 0 0 0 0 200 1 0 0 0 0 0 0
`
	got := selectPrimaryNICsWithIPCheck(parseProcNetDev(dev), v4, nil, sysNet, nil)
	if !reflect.DeepEqual(got, []string{"eth0"}) {
		t.Fatalf("expected lower physical parent [eth0], got %v", got)
	}
}
