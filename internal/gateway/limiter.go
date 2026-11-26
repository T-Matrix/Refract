package gateway

import "sync"

type requestLimiter struct {
	mu        sync.Mutex
	global    int
	globalMax int
	perIP     map[string]int
	perIPMax  int
}

func newRequestLimiter(globalMax, perIPMax int) *requestLimiter {
	return &requestLimiter{
		globalMax: globalMax,
		perIP:     make(map[string]int),
		perIPMax:  perIPMax,
	}
}

func (l *requestLimiter) Acquire(client string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global >= l.globalMax || l.perIP[client] >= l.perIPMax {
		return false
	}
	l.global++
	l.perIP[client]++
	return true
}

func (l *requestLimiter) UpdateLimits(globalMax, perIPMax int) {
	if l == nil {
		return
	}
	if globalMax < 1 {
		globalMax = 1
	}
	if perIPMax < 1 || perIPMax > globalMax {
		perIPMax = globalMax
	}
	l.mu.Lock()
	l.globalMax = globalMax
	l.perIPMax = perIPMax
	l.mu.Unlock()
}

func (l *requestLimiter) Limits() (int, int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalMax, l.perIPMax
}

func (l *requestLimiter) Release(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global > 0 {
		l.global--
	}
	if l.perIP[client] <= 1 {
		delete(l.perIP, client)
	} else {
		l.perIP[client]--
	}
}
