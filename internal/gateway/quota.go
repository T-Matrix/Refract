package gateway

import (
	"context"
	"errors"
	"sync"
	"time"
)

var errDomainQuotaExceeded = errors.New("domain traffic quota exhausted")

type domainQuotaAccount struct {
	mu      sync.Mutex
	ruleID  int64
	limit   int64
	used    int64
	dirty   int64
	enforce bool
	store   *telemetryStore
}

func (a *domainQuotaAccount) Snapshot() (limit, used int64) {
	if a == nil {
		return 0, 0
	}
	a.mu.Lock()
	limit, used = a.limit, a.used
	a.mu.Unlock()
	return limit, used
}

func (a *domainQuotaAccount) Exhausted() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	exhausted := a.enforce && a.limit > 0 && a.used >= a.limit
	a.mu.Unlock()
	return exhausted
}

func (a *domainQuotaAccount) Reserve(wanted int) (allowed int, limited bool) {
	if a == nil || wanted <= 0 {
		return max(0, wanted), false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enforce || a.limit <= 0 {
		return wanted, false
	}
	remaining := max(int64(0), a.limit-a.used)
	allowed64 := min(int64(wanted), remaining)
	a.used += allowed64
	a.dirty += allowed64
	return int(allowed64), allowed64 < int64(wanted)
}

func (a *domainQuotaAccount) Release(reserved int) {
	if a == nil || reserved <= 0 {
		return
	}
	a.mu.Lock()
	value := min(int64(reserved), a.used)
	a.used -= value
	a.dirty -= value
	a.mu.Unlock()
}

func (a *domainQuotaAccount) flush() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dirty == 0 {
		return nil
	}
	delta := a.dirty
	if err := a.store.AddProxyRuleQuotaUsage(a.ruleID, delta); err != nil {
		return err
	}
	a.dirty = 0
	return nil
}

type domainQuotaManager struct {
	store     *telemetryStore
	mu        sync.Mutex
	accounts  map[int64]*domainQuotaAccount
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newDomainQuotaManager(store *telemetryStore) *domainQuotaManager {
	manager := &domainQuotaManager{
		store: store, accounts: make(map[int64]*domainQuotaAccount), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go manager.run()
	return manager
}

func (m *domainQuotaManager) run() {
	defer close(m.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.flush()
		case <-m.stop:
			m.flush()
			return
		}
	}
}

func (m *domainQuotaManager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.stop)
		<-m.done
	})
}

func (m *domainQuotaManager) Sync(policy *proxyPolicy) {
	if m == nil || policy == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, account := range m.accounts {
		account.mu.Lock()
		account.enforce = false
		account.mu.Unlock()
	}
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if rule.Action != "allow" || rule.QuotaBytes <= 0 {
			if account := m.accounts[rule.ID]; account != nil && rule.Action == "allow" {
				account.mu.Lock()
				account.limit = 0
				account.used = 0
				account.dirty = 0
				account.mu.Unlock()
			}
			continue
		}
		account := m.accounts[rule.ID]
		if account == nil {
			account = &domainQuotaAccount{
				ruleID: rule.ID, limit: rule.QuotaBytes, used: rule.QuotaUsedBytes, store: m.store,
			}
			m.accounts[rule.ID] = account
		}
		account.mu.Lock()
		account.limit = rule.QuotaBytes
		account.enforce = policy.Mode == proxyModeWhitelist && rule.Enabled
		account.mu.Unlock()
		rule.quota = account
	}
}

func (m *domainQuotaManager) Replace(policy *proxyPolicy) {
	if m == nil || policy == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, account := range m.accounts {
		account.mu.Lock()
		account.enforce = false
		account.dirty = 0
		account.mu.Unlock()
	}
	m.accounts = make(map[int64]*domainQuotaAccount)
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		if rule.Action != "allow" || rule.QuotaBytes <= 0 {
			continue
		}
		account := &domainQuotaAccount{
			ruleID: rule.ID, limit: rule.QuotaBytes, used: rule.QuotaUsedBytes,
			enforce: policy.Mode == proxyModeWhitelist && rule.Enabled, store: m.store,
		}
		m.accounts[rule.ID] = account
		rule.quota = account
	}
}

func (m *domainQuotaManager) Reset(ctx context.Context, id int64) error {
	if m == nil {
		return errors.New("quota manager unavailable")
	}
	m.mu.Lock()
	account := m.accounts[id]
	m.mu.Unlock()
	if account == nil {
		return m.store.ResetProxyRuleQuota(ctx, id)
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	if err := m.store.ResetProxyRuleQuota(ctx, id); err != nil {
		return err
	}
	account.used = 0
	account.dirty = 0
	return nil
}

func (m *domainQuotaManager) flush() {
	if m == nil {
		return
	}
	m.mu.Lock()
	accounts := make([]*domainQuotaAccount, 0, len(m.accounts))
	for _, account := range m.accounts {
		accounts = append(accounts, account)
	}
	m.mu.Unlock()
	for _, account := range accounts {
		if err := account.flush(); err != nil {
			m.store.dropped.Add(1)
		}
	}
}
