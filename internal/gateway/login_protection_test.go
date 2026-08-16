package gateway

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLoginBlockPersistsAcrossStoreRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "gateway.db")
	store, err := openTelemetryStore(databasePath, "", "")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)
	for attempt := 1; attempt <= loginFailureLimit; attempt++ {
		retry, err := store.recordLoginFailure(context.Background(), "198.51.100.40", now)
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if attempt < loginFailureLimit && retry != 0 {
			store.Close()
			t.Fatalf("attempt %d blocked early", attempt)
		}
	}
	store.Close()

	reopened, err := openTelemetryStore(databasePath, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, err := reopened.loginRetryAfter(context.Background(), "198.51.100.40", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if retry < 23*time.Hour || retry > loginBlockDuration {
		t.Fatalf("persisted retry duration=%s", retry)
	}
	otherRetry, err := reopened.loginRetryAfter(context.Background(), "198.51.100.41", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if otherRetry != 0 {
		t.Fatalf("different IP retry duration=%s", otherRetry)
	}
}
