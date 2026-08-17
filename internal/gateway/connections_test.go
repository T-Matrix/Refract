package gateway

import (
	"sync/atomic"
	"testing"
)

func TestConnectionTrackerCancelAll(t *testing.T) {
	tracker := newConnectionTracker()
	defer tracker.Close()
	var canceled atomic.Int64
	for range 3 {
		tracker.Start(func() { canceled.Add(1) }, "203.0.113.10", "GET", "media.example", "media.example", "/video", "video", "test")
	}
	if count := tracker.CancelAll(); count != 3 {
		t.Fatalf("CancelAll count = %d, want 3", count)
	}
	if canceled.Load() != 3 {
		t.Fatalf("canceled callbacks = %d, want 3", canceled.Load())
	}
}
