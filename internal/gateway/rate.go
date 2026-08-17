package gateway

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type rateMeter struct {
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	uploadRate    atomic.Int64
	downloadRate  atomic.Int64
	clientMu      sync.Mutex
	clientBytes   map[string]int64
	sinkMu        sync.RWMutex
	peakSink      func(string, int64)
	stop          chan struct{}
	done          chan struct{}
	closeOnce     sync.Once
}

type liveSnapshot struct {
	UploadBPS      int64                 `json:"upload_bps"`
	DownloadBPS    int64                 `json:"download_bps"`
	UploadTotal    int64                 `json:"upload_total"`
	DownloadTotal  int64                 `json:"download_total"`
	ActiveRequests int64                 `json:"active_requests"`
	ActiveTargets  []activeTargetTraffic `json:"active_targets"`
}

func newRateMeter() *rateMeter {
	meter := &rateMeter{clientBytes: make(map[string]int64), stop: make(chan struct{}), done: make(chan struct{})}
	go meter.run()
	return meter
}

func (m *rateMeter) run() {
	defer close(m.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastUpload, lastDownload := int64(0), int64(0)
	lastClientTick := time.Now()
	for {
		select {
		case tickedAt := <-ticker.C:
			upload, download := m.uploadTotal.Load(), m.downloadTotal.Load()
			m.uploadRate.Store(max(0, upload-lastUpload))
			m.downloadRate.Store(max(0, download-lastDownload))
			lastUpload, lastDownload = upload, download
			m.flushClientRates(tickedAt.Sub(lastClientTick))
			lastClientTick = tickedAt
		case <-m.stop:
			m.flushClientRates(time.Since(lastClientTick))
			return
		}
	}
}

func (m *rateMeter) flushClientRates(elapsed time.Duration) {
	m.clientMu.Lock()
	current := m.clientBytes
	m.clientBytes = make(map[string]int64, len(current))
	m.clientMu.Unlock()
	m.sinkMu.RLock()
	sink := m.peakSink
	m.sinkMu.RUnlock()
	if sink == nil {
		return
	}
	for ip, bytesPerSecond := range current {
		if bytesPerSecond > 0 {
			if elapsed > 0 {
				bytesPerSecond = int64(float64(bytesPerSecond) / elapsed.Seconds())
			}
			sink(ip, bytesPerSecond)
		}
	}
}

func (m *rateMeter) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.stop)
		<-m.done
	})
}

func (m *rateMeter) AddUpload(value int64) {
	if m != nil && value > 0 {
		m.uploadTotal.Add(value)
	}
}

func (m *rateMeter) AddDownload(value int64) {
	if m != nil && value > 0 {
		m.downloadTotal.Add(value)
	}
}

func (m *rateMeter) AddClientDownload(ip string, value int64) {
	if m == nil || ip == "" || value <= 0 {
		return
	}
	m.clientMu.Lock()
	m.clientBytes[ip] += value
	m.clientMu.Unlock()
}

func (m *rateMeter) SetClientPeakSink(sink func(string, int64)) {
	if m == nil {
		return
	}
	m.sinkMu.Lock()
	m.peakSink = sink
	m.sinkMu.Unlock()
}

func (m *rateMeter) Snapshot(active int64) liveSnapshot {
	return liveSnapshot{
		UploadBPS: m.uploadRate.Load(), DownloadBPS: m.downloadRate.Load(),
		UploadTotal: m.uploadTotal.Load(), DownloadTotal: m.downloadTotal.Load(), ActiveRequests: active,
	}
}

type countingReadCloser struct {
	io.ReadCloser
	meter *rateMeter
	flow  *connectionFlow
	count atomic.Int64
}

func (r *countingReadCloser) Read(buffer []byte) (int, error) {
	read, err := r.ReadCloser.Read(buffer)
	if read > 0 {
		r.count.Add(int64(read))
		r.meter.AddUpload(int64(read))
		r.flow.AddUpload(int64(read))
	}
	return read, err
}

func (r *countingReadCloser) Count() int64 { return r.count.Load() }

type meteredConn struct {
	net.Conn
	meter     *rateMeter
	flow      *connectionFlow
	clientIP  string
	bandwidth *bandwidthLimiter
	quota     *domainQuotaAccount
	context   context.Context
}

func (c *meteredConn) Read(buffer []byte) (int, error) {
	read, err := c.Conn.Read(buffer)
	c.meter.AddUpload(int64(read))
	c.flow.AddUpload(int64(read))
	return read, err
}

func (c *meteredConn) Write(buffer []byte) (int, error) {
	written, err := writeMeteredPayload(c.context, c.bandwidth, c.quota, c.clientIP, buffer, c.Conn.Write)
	c.meter.AddDownload(int64(written))
	c.meter.AddClientDownload(c.clientIP, int64(written))
	c.flow.AddDownload(int64(written))
	return written, err
}

func writeMeteredPayload(ctx context.Context, bandwidth *bandwidthLimiter, quota *domainQuotaAccount, clientIP string, data []byte, write func([]byte) (int, error)) (int, error) {
	allowed := len(data)
	limited := false
	if quota != nil {
		allowed, limited = quota.Reserve(len(data))
		if allowed == 0 && limited {
			return 0, errDomainQuotaExceeded
		}
	}
	written, err := writeWithBandwidthLimit(ctx, bandwidth, clientIP, data[:allowed], write)
	if quota != nil && written < allowed {
		quota.Release(allowed - written)
	}
	if err == nil && limited {
		err = errDomainQuotaExceeded
	}
	return written, err
}
