package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGeoLookupNormalizesChinaProvinceAndRejectsWrongIP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/")
		if r.URL.Query().Get("wrong") == "1" {
			ip = "203.0.113.99"
		}
		_, _ = fmt.Fprintf(w, `{"success":true,"ip":%q,"country":"China","country_code":"CN","region":"Zhejiang Sheng","latitude":"30.24","longitude":"120.20"}`, ip)
	}))
	defer server.Close()

	tracker := &geoTracker{lookupURL: server.URL + "/{ip}", client: server.Client()}
	location, err := tracker.lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if location.Region != "浙江" || location.CountryCode != "CN" || location.Latitude != 30.24 {
		t.Fatalf("unexpected location: %#v", location)
	}

	tracker.lookupURL = server.URL + "/{ip}?wrong=1"
	if _, err := tracker.lookup(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("lookup accepted a response for a different IP")
	}
}

func TestClientPeakMeterCombinesConcurrentWritesByIP(t *testing.T) {
	meter := newRateMeter()
	defer meter.Close()
	peaks := make(chan int64, 1)
	meter.SetClientPeakSink(func(ip string, bps int64) {
		if ip == "8.8.8.8" {
			peaks <- bps
		}
	})
	meter.AddClientDownload("8.8.8.8", 400)
	meter.AddClientDownload("8.8.8.8", 600)
	meter.flushClientRates(time.Second)
	select {
	case peak := <-peaks:
		if peak != 1000 {
			t.Fatalf("peak=%d, want 1000", peak)
		}
	case <-time.After(time.Second):
		t.Fatal("client peak was not reported")
	}
}

func TestGeographyAggregatesChinaByProvinceAndOtherLocationsByCountry(t *testing.T) {
	gateway := newAdminTestGateway(t)
	now := time.Now()
	locations := map[string]geoLocation{
		"8.8.8.8": {Country: "United States", CountryCode: "US", Region: "California", Latitude: 37.3, Longitude: -121.9},
		"1.2.3.4": {Country: "China", CountryCode: "CN", Region: "广东", Latitude: 23.1, Longitude: 113.2},
		"1.2.3.5": {Country: "China", CountryCode: "CN", Region: "广东", Latitude: 22.5, Longitude: 114.1},
	}
	for ip, location := range locations {
		if err := gateway.telemetry.saveGeo(context.Background(), ip, location); err != nil {
			t.Fatal(err)
		}
	}
	events := []clientGeoEvent{
		{IP: "8.8.8.8", Timestamp: now, Requests: 2, BytesOut: 2000, PeakBPS: 900},
		{IP: "1.2.3.4", Timestamp: now, Requests: 3, BytesOut: 3000, PeakBPS: 1200},
		{IP: "1.2.3.5", Timestamp: now, Requests: 4, BytesOut: 4000, PeakBPS: 1800},
	}
	for _, event := range events {
		if err := gateway.telemetry.recordClientGeo(event); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := gateway.telemetry.Geography(context.Background(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.LocatedIPs != 3 || len(snapshot.Regions) != 2 {
		t.Fatalf("unexpected geography summary: %#v", snapshot)
	}
	guangdong := snapshot.Regions[0]
	if guangdong.Key != "CN:广东" || guangdong.MapName != "广东省" || guangdong.UniqueIPs != 2 ||
		guangdong.Requests != 7 || guangdong.PeakBPS != 1800 {
		t.Fatalf("unexpected Guangdong aggregation: %#v", guangdong)
	}
}

func TestGeographyAPIRequiresAuthenticationAndValidatesPeriod(t *testing.T) {
	gateway := newAdminTestGateway(t)
	unauthenticated := adminRequest(t, gateway, http.MethodGet, "/_admin/api/geography?period=24h", nil, nil, false)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated geography status=%d", unauthenticated.Code)
	}
	cookie := loginAdmin(t, gateway)
	invalid := adminRequest(t, gateway, http.MethodGet, "/_admin/api/geography?period=forever", nil, cookie, false)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid period status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	valid := adminRequest(t, gateway, http.MethodGet, "/_admin/api/geography?period=7d", nil, cookie, false)
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"period_hours":168`) {
		t.Fatalf("geography status=%d body=%s", valid.Code, valid.Body.String())
	}
}

func TestPublicClientIPRejectsInternalAddresses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "not-an-ip"} {
		if _, ok := publicClientIP(ip); ok {
			t.Fatalf("accepted internal client IP %q", ip)
		}
	}
	if normalized, ok := publicClientIP("2001:4860:4860::8888"); !ok || normalized != "2001:4860:4860::8888" {
		t.Fatalf("public IPv6 normalization=%q ok=%v", normalized, ok)
	}
}
