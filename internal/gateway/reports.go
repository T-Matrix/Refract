package gateway

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type reportSnapshot struct {
	PeriodHours          int64              `json:"period_hours"`
	Requests             int64              `json:"requests"`
	BytesIn              int64              `json:"bytes_in"`
	BytesOut             int64              `json:"bytes_out"`
	ClientBytesOut       int64              `json:"client_bytes_out"`
	UnattributedBytesOut int64              `json:"unattributed_bytes_out"`
	Errors               int64              `json:"errors"`
	Targets              int64              `json:"targets_count"`
	Timeline             []trafficPoint     `json:"timeline"`
	TopTargets           []targetSummary    `json:"top_targets"`
	TopClients           []geoIPSummary     `json:"top_clients"`
	Regions              []geoRegionSummary `json:"regions"`
}

func (s *telemetryStore) Report(ctx context.Context, period time.Duration) (reportSnapshot, error) {
	if period < time.Hour || period > 90*24*time.Hour {
		period = 24 * time.Hour
	}
	since := reportingPeriodStart(period)
	bucket := int64(time.Hour / time.Second)
	if period > 7*24*time.Hour {
		bucket = int64(24 * time.Hour / time.Second)
	} else if period > 24*time.Hour {
		bucket = int64(6 * time.Hour / time.Second)
	}
	report := reportSnapshot{PeriodHours: int64(period / time.Hour), Timeline: []trafficPoint{}, TopTargets: []targetSummary{}, TopClients: []geoIPSummary{}, Regions: []geoRegionSummary{}}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0),COALESCE(SUM(bytes_in),0),COALESCE(SUM(bytes_out),0),COALESCE(SUM(errors),0),COUNT(DISTINCT host)
		 FROM traffic_minutes WHERE minute>=?`, since).
		Scan(&report.Requests, &report.BytesIn, &report.BytesOut, &report.Errors, &report.Targets); err != nil {
		return reportSnapshot{}, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT (minute/?)*?,SUM(requests),SUM(bytes_in),SUM(bytes_out),SUM(errors)
		 FROM traffic_minutes WHERE minute>=? GROUP BY (minute/?) ORDER BY (minute/?)`,
		bucket, bucket, since, bucket, bucket)
	if err != nil {
		return reportSnapshot{}, err
	}
	for rows.Next() {
		var point trafficPoint
		if err := rows.Scan(&point.Timestamp, &point.Requests, &point.BytesIn, &point.BytesOut, &point.Errors); err != nil {
			_ = rows.Close()
			return reportSnapshot{}, err
		}
		report.Timeline = append(report.Timeline, point)
	}
	if err := rows.Close(); err != nil {
		return reportSnapshot{}, err
	}
	report.TopTargets, err = s.targets(ctx, since, 20)
	if err != nil {
		return reportSnapshot{}, err
	}
	geography, err := s.geographySince(ctx, period, since)
	if err != nil {
		return reportSnapshot{}, err
	}
	var clientRequests int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0),COALESCE(SUM(bytes_out),0) FROM client_geo_hours WHERE hour>=?`, since,
	).Scan(&clientRequests, &report.ClientBytesOut); err != nil {
		return reportSnapshot{}, err
	}
	report.UnattributedBytesOut = max(0, report.BytesOut-report.ClientBytesOut)
	clientLimit := 20
	if report.UnattributedBytesOut > 0 {
		clientLimit--
	}
	report.TopClients, err = s.topClients(ctx, since, clientLimit)
	if err != nil {
		return reportSnapshot{}, err
	}
	if report.UnattributedBytesOut > 0 {
		report.TopClients = append(report.TopClients, geoIPSummary{
			IP: "-", Label: "历史未归属（升级前）", Requests: max(0, report.Requests-clientRequests),
			BytesOut: report.UnattributedBytesOut,
		})
		sort.Slice(report.TopClients, func(i, j int) bool { return report.TopClients[i].BytesOut > report.TopClients[j].BytesOut })
		if len(report.TopClients) > 20 {
			report.TopClients = report.TopClients[:20]
		}
	}
	report.Regions = append(report.Regions, geography.Regions...)
	sort.Slice(report.Regions, func(i, j int) bool { return report.Regions[i].BytesOut > report.Regions[j].BytesOut })
	return report, nil
}

func reportingPeriodStart(period time.Duration) int64 {
	return time.Now().Add(-period).Truncate(time.Hour).Unix()
}

func (s *telemetryStore) topClients(ctx context.Context, since int64, limit int) ([]geoIPSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT d.ip,SUM(d.requests),SUM(d.bytes_out),MAX(d.peak_bps),MAX(d.last_seen),
		 COALESCE(c.country,''),COALESCE(c.country_code,''),COALESCE(c.region,''),
		 COALESCE(c.latitude,0),COALESCE(c.longitude,0)
		 FROM client_geo_hours d LEFT JOIN geo_ip_cache c ON c.ip=d.ip
		 WHERE d.hour>=? GROUP BY d.ip ORDER BY SUM(d.bytes_out) DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]geoIPSummary, 0, limit)
	for rows.Next() {
		var item geoIPSummary
		var region string
		if err := rows.Scan(&item.IP, &item.Requests, &item.BytesOut, &item.PeakBPS, &item.LastSeen,
			&item.Country, &item.CountryCode, &region, &item.Latitude, &item.Longitude); err != nil {
			return nil, err
		}
		if item.CountryCode == "" {
			item.Label = "待定位"
		} else {
			_, _, item.Label, item.Province = geographyRegion(item.Country, item.CountryCode, region)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func parseReportPeriod(raw string) (time.Duration, bool) {
	switch raw {
	case "", "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	case "90d":
		return 90 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func reportPeriodName(period time.Duration) string {
	if period%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(period/(24*time.Hour)))
	}
	return fmt.Sprintf("%dh", int(period/time.Hour))
}
