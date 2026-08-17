package gateway

import (
	"context"
	"io"
	"sync"
	"time"
)

const bandwidthWriteChunk = 32 << 10

type bandwidthReservation struct {
	mu       sync.Mutex
	next     time.Time
	lastSeen time.Time
}

type bandwidthLimiter struct {
	mu             sync.Mutex
	bytesPerSecond int64
	clients        map[string]*bandwidthReservation
	lastCleanup    time.Time
}

func newBandwidthLimiter(bytesPerSecond int64) *bandwidthLimiter {
	return &bandwidthLimiter{
		bytesPerSecond: max(0, bytesPerSecond),
		clients:        make(map[string]*bandwidthReservation),
	}
}

func (l *bandwidthLimiter) Wait(ctx context.Context, client string, size int) error {
	if l == nil || l.bytesPerSecond <= 0 || client == "" || size <= 0 {
		return nil
	}
	reservation := l.client(client, time.Now())
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	now := time.Now()
	start := now
	if reservation.next.After(start) {
		start = reservation.next
	}
	delay := start.Sub(now)
	if delay <= 0 {
		reservation.next = start.Add(l.duration(size))
		reservation.lastSeen = now
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		reservation.next = start.Add(l.duration(size))
		reservation.lastSeen = time.Now()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *bandwidthLimiter) reserve(client string, size int, now time.Time) time.Duration {
	if l.bytesPerSecond <= 0 || client == "" || size <= 0 {
		return 0
	}
	reservation := l.client(client, now)
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	start := now
	if reservation.next.After(start) {
		start = reservation.next
	}
	reservation.next = start.Add(l.duration(size))
	reservation.lastSeen = now
	return start.Sub(now)
}

func (l *bandwidthLimiter) duration(size int) time.Duration {
	return time.Duration(float64(size) / float64(l.bytesPerSecond) * float64(time.Second))
}

func (l *bandwidthLimiter) client(client string, now time.Time) *bandwidthReservation {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation := l.clients[client]
	if reservation == nil {
		reservation = &bandwidthReservation{lastSeen: now}
		l.clients[client] = reservation
	}
	if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= time.Minute {
		l.cleanup(now, reservation)
	}
	return reservation
}

func (l *bandwidthLimiter) cleanup(now time.Time, preserve *bandwidthReservation) {
	cutoff := now.Add(-10 * time.Minute)
	for client, reservation := range l.clients {
		if reservation == preserve {
			continue
		}
		reservation.mu.Lock()
		if reservation.lastSeen.Before(cutoff) && !reservation.next.After(now) {
			delete(l.clients, client)
		}
		reservation.mu.Unlock()
	}
	l.lastCleanup = now
}

func writeWithBandwidthLimit(ctx context.Context, limiter *bandwidthLimiter, client string, data []byte, write func([]byte) (int, error)) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	writtenTotal := 0
	for len(data) > 0 {
		chunkSize := min(len(data), bandwidthWriteChunk)
		chunk := data[:chunkSize]
		if err := limiter.Wait(ctx, client, len(chunk)); err != nil {
			return writtenTotal, err
		}
		written, err := write(chunk)
		writtenTotal += written
		if err != nil {
			return writtenTotal, err
		}
		if written != len(chunk) {
			return writtenTotal, io.ErrShortWrite
		}
		data = data[chunkSize:]
	}
	return writtenTotal, nil
}
