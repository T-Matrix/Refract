package gateway

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type reportSnapshot struct {
	PeriodHours int64              `json:"period_hours"`
	Requests    int64              `json:"requests"`
	BytesIn     int64              `json:"bytes_in"`
	BytesOut    int64              `json:"bytes_out"`
	Errors      int64              `json:"errors"`
	Targets     int64              `json:"targets_count"`
	Timeline    []trafficPoint     `json:"timeline"`
	TopTargets  []targetSummary    `json:"top_targets"`
	TopClients  []geoIPSummary     `json:"top_clients"`
	Regions     []geoRegionSummary `json:"regions"`
}

func (s *telemetryStore) Report(ctx context.Context, period time.Duration) (reportSnapshot, error) {
	if period < time.Hour || period > 90*24*time.Hour {
		period = 24 * time.Hour
	}
	since := time.Now().Add(-period).Unix()
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
	geographyPeriod := min(period, geographyRetention)
	geography, err := s.Geography(ctx, geographyPeriod)
	if err != nil {
		return reportSnapshot{}, err
	}
	report.TopClients = append(report.TopClients, geography.IPs...)
	sort.Slice(report.TopClients, func(i, j int) bool { return report.TopClients[i].BytesOut > report.TopClients[j].BytesOut })
	if len(report.TopClients) > 20 {
		report.TopClients = report.TopClients[:20]
	}
	report.Regions = append(report.Regions, geography.Regions...)
	sort.Slice(report.Regions, func(i, j int) bool { return report.Regions[i].BytesOut > report.Regions[j].BytesOut })
	return report, nil
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
