package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	geographyRetention = 30 * 24 * time.Hour
	geoSuccessTTL      = 30 * 24 * time.Hour
	geoFailureTTL      = time.Hour
	geoQueueSize       = 4096
)

type clientGeoEvent struct {
	IP        string
	Timestamp time.Time
	Requests  int64
	BytesOut  int64
	PeakBPS   int64
}

type geoLocation struct {
	Country     string
	CountryCode string
	Region      string
	Latitude    float64
	Longitude   float64
	LookedUp    int64
}

type geoRegionSummary struct {
	Key         string  `json:"key"`
	MapName     string  `json:"map_name"`
	Label       string  `json:"label"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Province    string  `json:"province,omitempty"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Requests    int64   `json:"requests"`
	BytesOut    int64   `json:"bytes_out"`
	PeakBPS     int64   `json:"peak_bps"`
	UniqueIPs   int64   `json:"unique_ips"`
}

type geoIPSummary struct {
	IP          string  `json:"ip"`
	Label       string  `json:"label"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Province    string  `json:"province,omitempty"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Requests    int64   `json:"requests"`
	BytesOut    int64   `json:"bytes_out"`
	PeakBPS     int64   `json:"peak_bps"`
	LastSeen    int64   `json:"last_seen"`
}

type geographySnapshot struct {
	PeriodHours  int64              `json:"period_hours"`
	LocatedIPs   int64              `json:"located_ips"`
	UnlocatedIPs int64              `json:"unlocated_ips"`
	Regions      []geoRegionSummary `json:"regions"`
	IPs          []geoIPSummary     `json:"ips"`
}

type geoTracker struct {
	store     *telemetryStore
	lookupURL string
	interval  time.Duration
	client    *http.Client
	stats     chan clientGeoEvent
	lookups   chan string
	ctx       context.Context
	cancel    context.CancelFunc
	wait      sync.WaitGroup
	queueMu   sync.Mutex
	queued    map[string]struct{}
	closeOnce sync.Once
}

func newGeoTracker(store *telemetryStore, cfg Config) *geoTracker {
	ctx, cancel := context.WithCancel(context.Background())
	tracker := &geoTracker{
		store: store, lookupURL: strings.TrimSpace(cfg.GeoIPLookupURL), interval: cfg.GeoIPLookupInterval,
		client: &http.Client{Timeout: cfg.GeoIPLookupTimeout}, stats: make(chan clientGeoEvent, geoQueueSize),
		lookups: make(chan string, 1024), ctx: ctx, cancel: cancel, queued: make(map[string]struct{}),
	}
	tracker.wait.Add(1)
	go tracker.runStats()
	if tracker.lookupURL != "" {
		tracker.wait.Add(1)
		go tracker.runLookups()
	}
	return tracker
}

func (g *geoTracker) Close() {
	if g == nil {
		return
	}
	g.closeOnce.Do(func() {
		g.cancel()
		g.wait.Wait()
	})
}

func (g *geoTracker) ObserveRequest(ip string, bytesOut int64) {
	g.observe(clientGeoEvent{IP: ip, Timestamp: time.Now(), Requests: 1, BytesOut: max(0, bytesOut)})
}

func (g *geoTracker) ObservePeak(ip string, bytesPerSecond int64) {
	if bytesPerSecond <= 0 {
		return
	}
	g.observe(clientGeoEvent{IP: ip, Timestamp: time.Now(), PeakBPS: bytesPerSecond})
}

func (g *geoTracker) observe(event clientGeoEvent) {
	if g == nil {
		return
	}
	ip, ok := publicClientIP(event.IP)
	if !ok {
		return
	}
	event.IP = ip
	select {
	case g.stats <- event:
	case <-g.ctx.Done():
	default:
		g.store.dropped.Add(1)
	}
	g.queueLookup(ip)
}

func (g *geoTracker) queueLookup(ip string) {
	if g.lookupURL == "" {
		return
	}
	g.queueMu.Lock()
	if _, exists := g.queued[ip]; exists {
		g.queueMu.Unlock()
		return
	}
	g.queued[ip] = struct{}{}
	g.queueMu.Unlock()
	select {
	case g.lookups <- ip:
	case <-g.ctx.Done():
		g.clearQueued(ip)
	default:
		g.clearQueued(ip)
	}
}

func (g *geoTracker) clearQueued(ip string) {
	g.queueMu.Lock()
	delete(g.queued, ip)
	g.queueMu.Unlock()
}

func (g *geoTracker) runStats() {
	defer g.wait.Done()
	for {
		select {
		case event := <-g.stats:
			if err := g.store.recordClientGeo(event); err != nil {
				g.store.dropped.Add(1)
			}
		case <-g.ctx.Done():
			return
		}
	}
}

func (g *geoTracker) runLookups() {
	defer g.wait.Done()
	interval := g.interval
	if interval <= 0 {
		interval = 1100 * time.Millisecond
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case ip := <-g.lookups:
			select {
			case <-timer.C:
			case <-g.ctx.Done():
				return
			}
			g.resolve(ip)
			g.clearQueued(ip)
			timer.Reset(interval)
		}
	}
}

func (g *geoTracker) resolve(ip string) {
	cached, found, err := g.store.cachedGeo(g.ctx, ip)
	if err == nil && found {
		ttl := geoSuccessTTL
		if cached.CountryCode == "" {
			ttl = geoFailureTTL
		}
		if time.Since(time.Unix(cached.LookedUp, 0)) < ttl {
			return
		}
	}
	location, err := g.lookup(g.ctx, ip)
	if err != nil {
		location = geoLocation{LookedUp: time.Now().Unix()}
	}
	_ = g.store.saveGeo(g.ctx, ip, location)
}

type flexibleFloat float64

func (f *flexibleFloat) UnmarshalJSON(data []byte) error {
	raw := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if raw == "" || raw == "null" {
		*f = 0
		return nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return err
	}
	*f = flexibleFloat(value)
	return nil
}

func (g *geoTracker) lookup(ctx context.Context, ip string) (geoLocation, error) {
	requestURL := strings.ReplaceAll(g.lookupURL, "{ip}", url.PathEscape(ip))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return geoLocation{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Refract/1.4")
	response, err := g.client.Do(request)
	if err != nil {
		return geoLocation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return geoLocation{}, fmt.Errorf("geo lookup returned %d", response.StatusCode)
	}
	var payload struct {
		Success        *bool         `json:"success"`
		IP             string        `json:"ip"`
		Country        string        `json:"country"`
		CountryCode    string        `json:"country_code"`
		CountryCodeAlt string        `json:"countryCode"`
		Region         string        `json:"region"`
		Latitude       flexibleFloat `json:"latitude"`
		Longitude      flexibleFloat `json:"longitude"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&payload); err != nil {
		return geoLocation{}, err
	}
	if payload.Success != nil && !*payload.Success {
		return geoLocation{}, errors.New("geo lookup reported failure")
	}
	returnedIP, ok := publicClientIP(payload.IP)
	if !ok || returnedIP != ip {
		return geoLocation{}, errors.New("geo lookup did not return the requested IP")
	}
	countryCode := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	if countryCode == "" {
		countryCode = strings.ToUpper(strings.TrimSpace(payload.CountryCodeAlt))
	}
	if len(countryCode) != 2 || strings.TrimSpace(payload.Country) == "" {
		return geoLocation{}, errors.New("geo lookup response is missing country data")
	}
	latitude, longitude := float64(payload.Latitude), float64(payload.Longitude)
	if latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180 {
		return geoLocation{}, errors.New("geo lookup response has invalid coordinates")
	}
	region := strings.TrimSpace(payload.Region)
	if countryCode == "CN" {
		region = normalizeChinaRegion(region)
	}
	return geoLocation{
		Country: strings.TrimSpace(payload.Country), CountryCode: countryCode, Region: region,
		Latitude: latitude, Longitude: longitude, LookedUp: time.Now().Unix(),
	}, nil
}

func publicClientIP(raw string) (string, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return "", false
	}
	return ip.String(), true
}

func normalizeChinaRegion(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	compact := strings.NewReplacer(" ", "", "-", "", "_", "", "province", "", "sheng", "").Replace(value)
	regions := []struct {
		name string
		keys []string
	}{
		{"北京", []string{"北京", "beijing"}}, {"天津", []string{"天津", "tianjin"}},
		{"河北", []string{"河北", "hebei"}}, {"山西", []string{"山西", "shanxi"}},
		{"内蒙古", []string{"内蒙古", "innermongolia", "neimenggu"}}, {"辽宁", []string{"辽宁", "liaoning"}},
		{"吉林", []string{"吉林", "jilin"}}, {"黑龙江", []string{"黑龙江", "heilongjiang"}},
		{"上海", []string{"上海", "shanghai"}}, {"江苏", []string{"江苏", "jiangsu"}},
		{"浙江", []string{"浙江", "zhejiang"}}, {"安徽", []string{"安徽", "anhui"}},
		{"福建", []string{"福建", "fujian"}}, {"江西", []string{"江西", "jiangxi"}},
		{"山东", []string{"山东", "shandong"}}, {"河南", []string{"河南", "henan"}},
		{"湖北", []string{"湖北", "hubei"}}, {"湖南", []string{"湖南", "hunan"}},
		{"广东", []string{"广东", "guangdong"}}, {"广西", []string{"广西", "guangxi"}},
		{"海南", []string{"海南", "hainan"}}, {"重庆", []string{"重庆", "chongqing"}},
		{"四川", []string{"四川", "sichuan"}}, {"贵州", []string{"贵州", "guizhou"}},
		{"云南", []string{"云南", "yunnan"}}, {"西藏", []string{"西藏", "tibet", "xizang"}},
		{"陕西", []string{"陕西", "shaanxi"}}, {"甘肃", []string{"甘肃", "gansu"}},
		{"青海", []string{"青海", "qinghai"}}, {"宁夏", []string{"宁夏", "ningxia"}},
		{"新疆", []string{"新疆", "xinjiang"}},
	}
	for _, region := range regions {
		for _, key := range region.keys {
			if strings.Contains(compact, key) {
				return region.name
			}
		}
	}
	return strings.TrimSpace(raw)
}
