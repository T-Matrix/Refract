package gateway

import (
	"testing"
	"time"
)

func TestNextBackupRunAlwaysUsesShanghaiTime(t *testing.T) {
	now := time.Date(2026, 8, 16, 18, 30, 0, 0, time.UTC)
	next := time.Unix(nextBackupRun(now, backupConfig{Enabled: true, Hour: 3}), 0).In(applicationLocation)
	if next.Year() != 2026 || next.Month() != time.August || next.Day() != 17 || next.Hour() != 3 || next.Minute() != 0 {
		t.Fatalf("next Shanghai backup = %s", next)
	}
}
