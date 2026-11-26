package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const acmeAccountKeySettingKey = "acme_account_key_enc"

type controllerACMEIssuer struct {
	store           *telemetryStore
	gateway         *Gateway
	accountCipher   *tokenCipher
	certCipher      *tokenCipher
	directoryURL    string
	httpClient      *http.Client
	propagationWait time.Duration
	skipDNSCheck    bool

	mu           sync.Mutex
	accountKeyMu sync.Mutex
	inFlight     map[string]bool
}

func newControllerACMEIssuer(store *telemetryStore, gateway *Gateway, secret []byte, certCipher *tokenCipher) (*controllerACMEIssuer, error) {
	acctCipher, err := newScopedTokenCipher(secret, "acme-account")
	if err != nil {
		return nil, err
	}
	return &controllerACMEIssuer{
		store:           store,
		gateway:         gateway,
		accountCipher:   acctCipher,
		certCipher:      certCipher,
		directoryURL:    acme.LetsEncryptURL,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		propagationWait: 12 * time.Second,
		inFlight:        make(map[string]bool),
	}, nil
}

func (m *controllerACMEIssuer) loadOrCreateAccountKey(ctx context.Context) (*ecdsa.PrivateKey, error) {
	m.accountKeyMu.Lock()
	defer m.accountKeyMu.Unlock()
	var enc string
	err := m.store.db.QueryRowContext(ctx, `SELECT value FROM gateway_settings WHERE key=?`, acmeAccountKeySettingKey).Scan(&enc)
	if err == nil && strings.TrimSpace(enc) != "" {
		pemStr, decErr := m.accountCipher.Decrypt(enc)
		if decErr != nil {
			return nil, fmt.Errorf("decrypt stored ACME account key: %w", decErr)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, errors.New("corrupted stored ACME account key PEM")
		}
		key, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse stored ACME account key: %w", parseErr)
		}
		return key, nil
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	encrypted, err := m.accountCipher.Encrypt(string(pemBytes))
	if err != nil {
		return nil, err
	}
	_, err = m.store.db.ExecContext(ctx,
		`INSERT INTO gateway_settings(key,value,updated_at) VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		acmeAccountKeySettingKey, encrypted, time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (m *controllerACMEIssuer) StartIssuanceAsync(domainID string) error {
	if m == nil || m.gateway == nil || m.gateway.cluster == nil {
		return errors.New("ACME issuer unavailable")
	}
	dom, err := m.store.GetEdgeDomain(context.Background(), domainID)
	if err != nil {
		return err
	}
	if dom.TLSMode != domainTLSAuto {
		return errors.New("仅自动证书模式（auto）支持主控 ACME DNS-01 自动签发")
	}
	cf := m.store.LoadCloudflareDNS(context.Background())
	if !cf.Enabled || cf.EncryptedToken == "" {
		return errors.New("请先在「系统设置 → Cloudflare DNS」启用并配置 API Token，主控才能通过 DNS-01 自动签发证书")
	}
	if cf.RootDomain == "" && cf.ZoneID != "" && m.gateway.cloudflare != nil {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if resolved, _, rErr := m.gateway.cloudflare.activeCredentials(resolveCtx); rErr == nil && resolved.RootDomain != "" {
			cf = resolved
		}
		cancel()
	}
	if !hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), cf.RootDomain) {
		return fmt.Errorf("域名 %q 不属于 Cloudflare 根域名 %q，无法执行 DNS-01 验证", dom.Domain, cf.RootDomain)
	}
	m.mu.Lock()
	if m.inFlight[domainID] {
		m.mu.Unlock()
		return nil
	}
	m.inFlight[domainID] = true
	m.mu.Unlock()

	_ = m.store.UpdateEdgeDomainCertStatusOnly(context.Background(), domainID, "issuing", "")
	m.gateway.cluster.runTracked(func() {
		defer func() {
			m.mu.Lock()
			delete(m.inFlight, domainID)
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(m.gateway.cluster.ctx, 3*time.Minute)
		defer cancel()
		if err := m.IssueDomainCertificate(ctx, domainID); err != nil {
			log.Printf("controller ACME DNS-01 issuance failed domain=%s error=%v", dom.Domain, err)
		}
	})
	return nil
}

func (m *controllerACMEIssuer) IssueDomainCertificate(ctx context.Context, domainID string) error {
	dom, err := m.store.GetEdgeDomain(ctx, domainID)
	if err != nil {
		return err
	}
	origDomain := dom.Domain
	if m.gateway.cloudflare == nil {
		return errors.New("cloudflare DNS manager unavailable")
	}
	persistStatus := func(status, errMsg string) {
		statusCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cur, curErr := m.store.GetEdgeDomain(statusCtx, domainID)
		if curErr != nil || !strings.EqualFold(cur.Domain, origDomain) || cur.TLSMode != domainTLSAuto {
			return
		}
		_ = m.store.UpdateEdgeDomainCertStatusOnly(statusCtx, domainID, status, errMsg)
	}
	storedCF, cfToken, err := m.gateway.cloudflare.activeCredentials(ctx)
	if err != nil || !storedCF.Enabled || cfToken == "" {
		if err == nil {
			err = errors.New("cloudflare DNS is disabled or token missing")
		}
		persistStatus("error", err.Error())
		return err
	}
	baseHost := edgeDomainBaseHost(dom.Domain)
	if !hostnameBelongsToRoot(baseHost, storedCF.RootDomain) {
		err = fmt.Errorf("domain %q does not belong to cloudflare root domain %q", dom.Domain, storedCF.RootDomain)
		persistStatus("error", err.Error())
		return err
	}

	persistStatus("issuing", "")

	fail := func(cause error) error {
		persistStatus("error", cause.Error())
		if m.gateway.telegram != nil {
			alertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = m.gateway.telegram.SendAlert(alertCtx, "node_tls", "主控域名证书签发失败 (DNS-01)", []string{
				fmt.Sprintf("域名：%s", origDomain),
				fmt.Sprintf("错误：%s", truncateRunes(cause.Error(), 200)),
			})
		}
		return cause
	}

	accountKey, err := m.loadOrCreateAccountKey(ctx)
	if err != nil {
		return fail(fmt.Errorf("load ACME account key: %w", err))
	}
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: m.directoryURL,
		HTTPClient:   m.httpClient,
		UserAgent:    "Refract/" + normalizedVersion(Version),
	}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fail(fmt.Errorf("ACME account register: %w", err))
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(dom.Domain))
	if err != nil {
		return fail(fmt.Errorf("ACME authorize order: %w", err))
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fail(fmt.Errorf("ACME get authorization: %w", err))
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, candidate := range authz.Challenges {
			if candidate.Type == "dns-01" {
				chal = candidate
				break
			}
		}
		if chal == nil {
			return fail(errors.New("ACME server did not offer dns-01 challenge"))
		}
		txtValue, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fail(fmt.Errorf("compute dns-01 record: %w", err))
		}
		txtName := "_acme-challenge." + strings.TrimPrefix(strings.ToLower(authz.Identifier.Value), "*.")
		recID, err := m.gateway.cloudflare.CreateTXTRecord(ctx, cfToken, storedCF.ZoneID, txtName, txtValue)
		if err != nil {
			return fail(fmt.Errorf("create Cloudflare TXT %s: %w", txtName, err))
		}
		defer func(zone, id string) {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = m.gateway.cloudflare.DeleteRecordByID(cleanCtx, cfToken, zone, id)
		}(storedCF.ZoneID, recID)

		if err := m.waitForTXTPropagation(ctx, txtName, txtValue); err != nil {
			return fail(err)
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return fail(fmt.Errorf("ACME accept dns-01: %w", err))
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fail(fmt.Errorf("ACME verify dns-01: %w", err))
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		return fail(fmt.Errorf("ACME wait order: %w", err))
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail(fmt.Errorf("generate cert key: %w", err))
	}
	csrTemplate := &x509.CertificateRequest{
		DNSNames: []string{dom.Domain},
	}
	if len(dom.Domain) <= 64 {
		csrTemplate.Subject = pkix.Name{CommonName: dom.Domain}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return fail(fmt.Errorf("create CSR: %w", err))
	}
	derChain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fail(fmt.Errorf("ACME finalize certificate: %w", err))
	}

	var certBuf bytes.Buffer
	for _, der := range derChain {
		_ = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return fail(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	certPEM := certBuf.String()

	issuer, notAfter, err := parseAndValidateCertKeyPair(certPEM, keyPEM)
	if err != nil {
		return fail(err)
	}
	encKey, err := m.certCipher.Encrypt(keyPEM)
	if err != nil {
		return fail(err)
	}
	// Verify domain was not renamed, deleted, or switched to manual/external TLS while ACME was in flight.
	saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer saveCancel()
	currentDom, curErr := m.store.GetEdgeDomain(saveCtx, domainID)
	if curErr != nil {
		if errors.Is(curErr, sql.ErrNoRows) {
			return nil
		}
		return fail(fmt.Errorf("reload edge domain before saving cert: %w", curErr))
	}
	if !strings.EqualFold(currentDom.Domain, origDomain) || currentDom.TLSMode != domainTLSAuto {
		log.Printf("controller ACME DNS-01 discarded stale cert for domain_id=%s orig=%s current=%s mode=%s", domainID, origDomain, currentDom.Domain, currentDom.TLSMode)
		return nil
	}
	if err := m.store.UpdateEdgeDomainCertState(saveCtx, domainID, certPEM, encKey, issuer+" (DNS-01)", notAfter, "ready", "", time.Now().Unix()); err != nil {
		return fail(err)
	}

	// Reload fresh node list and push the new certificate to ONLY bound nodes!
	latest, err := m.store.GetEdgeDomain(saveCtx, domainID)
	if err == nil {
		m.gateway.cluster.notifyNodesList(latest.NodeIDs)
	}
	m.store.RecordAudit(saveCtx, auditEntry{
		Username: "system",
		Action:   "edge_domain.cert_issued",
		Resource: dom.Domain,
		Detail:   fmt.Sprintf("issuer=%s expires=%s", issuer, time.Unix(notAfter, 0).Format("2006-01-02")),
		Success:  true,
	})
	log.Printf("controller ACME DNS-01 certificate ready domain=%s expires=%s", dom.Domain, time.Unix(notAfter, 0).Format("2006-01-02"))
	return nil
}

func (m *controllerACMEIssuer) waitForTXTPropagation(ctx context.Context, txtName, expected string) error {
	wait := m.propagationWait
	if wait <= 0 {
		wait = 10 * time.Millisecond
	}
	timer := time.NewTimer(wait)
	select {
	case <-timer.C:
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	}
	if m.skipDNSCheck {
		return nil
	}
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		txts, err := net.DefaultResolver.LookupTXT(lookupCtx, txtName)
		cancel()
		if err == nil {
			for _, v := range txts {
				if strings.TrimSpace(v) == expected {
					return nil
				}
			}
		}
		poll := time.NewTimer(4 * time.Second)
		select {
		case <-poll.C:
		case <-ctx.Done():
			poll.Stop()
			return ctx.Err()
		}
	}
	// Proceed to ACME validation even if local resolver is cached; ACME authoritative lookup may already see it.
	return nil
}

func (m *controllerACMEIssuer) EnsureAutoRenewals(ctx context.Context, now time.Time) {
	if m == nil || m.gateway == nil || m.gateway.cluster == nil {
		return
	}
	cf := m.store.LoadCloudflareDNS(ctx)
	if !cf.Enabled || cf.EncryptedToken == "" {
		return
	}
	if cf.RootDomain == "" && cf.ZoneID != "" && m.gateway.cloudflare != nil {
		if resolved, _, rErr := m.gateway.cloudflare.activeCredentials(ctx); rErr == nil && resolved.RootDomain != "" {
			cf = resolved
		}
	}
	domains, err := m.store.ListEdgeDomains(ctx)
	if err != nil {
		return
	}
	for _, dom := range domains {
		if !dom.Enabled || dom.TLSMode != domainTLSAuto || len(dom.NodeIDs) == 0 {
			continue
		}
		if !hostnameBelongsToRoot(edgeDomainBaseHost(dom.Domain), cf.RootDomain) {
			continue
		}
		needsIssue := false
		switch dom.CertStatus {
		case "", "idle":
			needsIssue = true
		case "issuing":
			m.mu.Lock()
			active := m.inFlight[dom.ID]
			m.mu.Unlock()
			if !active {
				needsIssue = true
			}
		case "ready":
			if dom.CertPEM == "" || dom.KeyPEMEnc == "" || (dom.CertNotAfter > 0 && time.Unix(dom.CertNotAfter, 0).Sub(now) < 30*24*time.Hour) {
				needsIssue = true
			}
		case "error":
			if now.Unix()-dom.CertUpdatedAt >= 600 {
				needsIssue = true
			}
		}
		if needsIssue {
			_ = m.StartIssuanceAsync(dom.ID)
		}
	}
}
