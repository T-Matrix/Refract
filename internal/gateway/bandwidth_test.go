package gateway

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestBandwidthLimiterAggregatesReservationsByClientIP(t *testing.T) {
	limiter := newBandwidthLimiter(1000)
	now := time.Unix(1_800_000_000, 0)
	if delay := limiter.reserve("203.0.113.10", 250, now); delay != 0 {
		t.Fatalf("first reservation delay = %s, want 0", delay)
	}
	if delay := limiter.reserve("203.0.113.10", 250, now); delay != 250*time.Millisecond {
		t.Fatalf("shared IP reservation delay = %s, want 250ms", delay)
	}
	if delay := limiter.reserve("203.0.113.11", 250, now); delay != 0 {
		t.Fatalf("different IP reservation delay = %s, want 0", delay)
	}
}

func TestWriteWithBandwidthLimitPacesLargeWrites(t *testing.T) {
	limiter := newBandwidthLimiter(1 << 20)
	var destination bytes.Buffer
	started := time.Now()
	written, err := writeWithBandwidthLimit(context.Background(), limiter, "203.0.113.10", make([]byte, 64<<10), destination.Write)
	if err != nil || written != 64<<10 {
		t.Fatalf("write result = %d, %v", written, err)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond {
		t.Fatalf("large write completed without pacing in %s", elapsed)
	}
}

func TestBandwidthLimiterWaitHonorsCancellation(t *testing.T) {
	limiter := newBandwidthLimiter(1)
	now := time.Now()
	limiter.reserve("203.0.113.10", 10, now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx, "203.0.113.10", 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want context cancellation", err)
	}
}
