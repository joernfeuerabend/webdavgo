// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// tls.go – TLS for the WebDAV listener with certificates from ACME.
//
// CertMagic does the ACME work. Everything outside this file talks to the
// certProvider interface only, so the library can be swapped without
// touching the server wiring or the admin UI.
//
// Only TLS-ALPN-01 is used: the CA validates on port 443 of the domain, which
// is forwarded to the WebDAV listener, and the listener itself answers the
// challenge in its TLS handshake. That needs no second port (HTTP-01) and no
// DNS provider credentials (DNS-01).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// hstsValue is sent on every WebDAV response once TLS is on. One year is the
// common minimum for HSTS. includeSubDomains follows the security audit: it
// keeps a sibling host from being used to plant cookies over plain HTTP.
// preload is left out because it is hard to undo for the operator's domain.
const hstsValue = "max-age=31536000; includeSubDomains"

// certProvider obtains and renews the certificate of the WebDAV listener.
type certProvider interface {
	// TLSConfig returns the listener configuration. It must also answer
	// TLS-ALPN-01 challenges, which arrive as ordinary handshakes.
	TLSConfig() *tls.Config
	// Start begins obtaining and renewing in the background. It is called
	// after the listener accepts connections, because the CA's validation
	// connects to that listener.
	Start()
	// Status reports the certificate state for the admin status page.
	Status() tlsStatus
	// Stop ends all background work.
	Stop()
}

// certs is nil while tls_mode = "off". The domain wizard sets it at runtime,
// so it is only accessed through currentCerts and setCerts. pendingCerts is
// the provider of an order the wizard is running; the WebDAV listener uses
// it for handshakes until the order succeeds or fails.
var (
	certsMu      sync.RWMutex
	certs        certProvider
	pendingCerts certProvider
)

func currentCerts() certProvider {
	certsMu.RLock()
	defer certsMu.RUnlock()
	return certs
}

func setCerts(p certProvider) {
	certsMu.Lock()
	certs, pendingCerts = p, nil
	certsMu.Unlock()
}

func setPendingCerts(p certProvider) {
	certsMu.Lock()
	pendingCerts = p
	certsMu.Unlock()
}

// handshakeCerts returns the provider that answers a handshake on the
// WebDAV listener. The CA's validation (acmeTLS) goes to the wizard's
// pending order if there is one; clients keep the current certificate while
// that order runs.
func handshakeCerts(acmeTLS bool) certProvider {
	certsMu.RLock()
	defer certsMu.RUnlock()
	if (acmeTLS || certs == nil) && pendingCerts != nil {
		return pendingCerts
	}
	return certs
}

var errNoCertificate = errors.New("no certificate available yet")

// webdavTLSConfig is the TLS configuration of the WebDAV listener. The
// certificate is looked up per handshake, so the domain wizard can hand the
// listener a new provider without restarting it.
func webdavTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The HTTP protocols come first so that normal clients negotiate
		// them; acme-tls/1 is only for the CA's TLS-ALPN-01 validation.
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}, // RFC 8737
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			p := handshakeCerts(slices.Contains(hello.SupportedProtos, "acme-tls/1"))
			if p == nil {
				return nil, errNoCertificate
			}
			return p.TLSConfig().GetCertificate(hello)
		},
	}
}

// tlsStatus is a snapshot of the certificate state.
type tlsStatus struct {
	Domain      string
	CA          string
	Issuer      string // issuer common name of the certificate in use
	NotBefore   time.Time
	NotAfter    time.Time
	LastSuccess time.Time // last obtain or renewal
	LastError   string
	LastErrorAt time.Time
	// ARIStart and ARIEnd are the renewal window the CA suggested through
	// ACME Renewal Information (RFC 9773); zero if it sent none.
	ARIStart, ARIEnd time.Time
	// NextRenewal is when CertMagic will renew: the time it picked in the
	// ARI window, or else when a third of the lifetime is left.
	NextRenewal  time.Time
	RenewalByARI bool
}

// lifetimeLow reports whether less than a third of the certificate lifetime
// is left. Renewal normally happens at that point (or earlier, per ARI), so
// crossing it means renewal is overdue and the operator should look at the
// last error.
func (s tlsStatus) lifetimeLow(now time.Time) bool {
	if s.NotAfter.IsZero() || !s.NotAfter.After(s.NotBefore) {
		return false
	}
	return s.NotAfter.Sub(now) < s.NotAfter.Sub(s.NotBefore)/3
}

// certmagicProvider implements certProvider with CertMagic.
type certmagicProvider struct {
	domain string
	cache  *certmagic.Cache
	magic  *certmagic.Config
	issuer *certmagic.ACMEIssuer
	tc     *tls.Config
	trial  bool // a throw-away order of the domain wizard, see obtainTrial
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	status tlsStatus
}

// newCertProvider sets up CertMagic for c.Domain. webdavAddr is the listen
// address of the WebDAV listener, where challenges are answered.
func newCertProvider(c Config, webdavAddr string) (certProvider, error) {
	return newCertmagicProvider(c, webdavAddr, c.CertDir, false)
}

// newCertmagicProvider is newCertProvider with the storage directory and
// the trial flag of the domain wizard's trial order.
func newCertmagicProvider(c Config, webdavAddr, storageDir string, trial bool) (*certmagicProvider, error) {
	host, portStr, err := net.SplitHostPort(webdavAddr)
	if err != nil {
		return nil, fmt.Errorf("webdav address %q: %w", webdavAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("webdav address %q: port: %w", webdavAddr, err)
	}

	var roots *x509.CertPool
	if c.ACMECARoot != "" {
		pem, err := os.ReadFile(c.ACMECARoot)
		if err != nil {
			return nil, fmt.Errorf("acme_ca_root: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("acme_ca_root %s: no PEM certificate found", c.ACMECARoot)
		}
	}

	ca := c.ACMECA
	switch ca {
	case "production":
		ca = certmagic.LetsEncryptProductionCA
	case "staging":
		ca = certmagic.LetsEncryptStagingCA
	}

	if err := os.MkdirAll(storageDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert_dir: %w", err)
	}

	zl := zap.New(slogCore{})
	p := &certmagicProvider{domain: c.Domain, trial: trial, status: tlsStatus{Domain: c.Domain, CA: ca}}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return p.magic, nil },
		Logger:           zl,
	})
	p.magic = certmagic.New(p.cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: storageDir},
		OnEvent: p.onEvent,
		Logger:  zl,
		// Clients that send no SNI (some WebDAV clients, access by IP)
		// still get the domain's certificate instead of a failed handshake.
		DefaultServerName: c.Domain,
		// tls_get_certificate fires on every handshake and is not used.
		ShouldEmitFunc: func(event string) bool { return event != "tls_get_certificate" },
	})
	p.issuer = certmagic.NewACMEIssuer(p.magic, certmagic.ACMEIssuer{
		CA:                   ca,
		Email:                c.ACMEEmail,
		Agreed:               true,
		DisableHTTPChallenge: true,
		// CertMagic tries to bind ListenHost:AltTLSALPNPort for its own
		// challenge server. Pointing it at our listener's address makes
		// that bind fail with "address in use", which CertMagic takes as
		// "the existing listener answers challenges" -- exactly our setup.
		// test.sh (C98, and the domain wizard criteria on port 443) is the
		// regression test for this behaviour after a CertMagic update.
		ListenHost:     host,
		AltTLSALPNPort: port,
		TrustedRoots:   roots,
		Logger:         zl,
	})
	p.magic.Issuers = []certmagic.Issuer{p.issuer}
	p.tc = p.magic.TLSConfig()
	p.tc.MinVersion = tls.VersionTLS12
	// CertMagic's config offers only acme-tls/1; the HTTP protocols must
	// come first so that normal clients negotiate them.
	p.tc.NextProtos = append([]string{"h2", "http/1.1"}, p.tc.NextProtos...)
	return p, nil
}

func (p *certmagicProvider) TLSConfig() *tls.Config {
	return p.tc
}

// obtainAndManage obtains the certificate now, or loads it from storage,
// and keeps renewing it in the background. Unlike Start it reports the
// outcome, which the domain wizard waits for.
func (p *certmagicProvider) obtainAndManage(ctx context.Context) error {
	if err := p.magic.ManageSync(ctx, []string{p.domain}); err != nil {
		p.recordError(err)
		return err
	}
	return nil
}

// obtainTrial places one order and throws the certificate away again; only
// the outcome matters. The account stays in storage for the next trial.
func (p *certmagicProvider) obtainTrial(ctx context.Context) error {
	if err := p.magic.ObtainCertSync(ctx, p.domain); err != nil {
		return err
	}
	// A stored certificate would make the next trial skip its order.
	if err := p.magic.Storage.Delete(ctx, certmagic.StorageKeys.CertsSitePrefix(p.issuer.IssuerKey(), p.domain)); err != nil {
		logger.Warn("cannot remove trial certificate", "domain", p.domain, "err", err)
	}
	return nil
}

func (p *certmagicProvider) Start() {
	// ManageAsync loads a stored certificate synchronously and obtains or
	// renews in the background, retrying with backoff on failure.
	if err := p.magic.ManageAsync(p.ctx, []string{p.domain}); err != nil {
		p.recordError(err)
		logger.Error("certificate management failed to start", "domain", p.domain, "err", err)
	}
}

func (p *certmagicProvider) Stop() {
	p.cancel()
	p.cache.Stop()
}

func (p *certmagicProvider) Status() tlsStatus {
	p.mu.Lock()
	s := p.status
	p.mu.Unlock()
	leaf := p.currentLeaf()
	if leaf == nil {
		return s
	}
	s.NotBefore, s.NotAfter = leaf.NotBefore, leaf.NotAfter
	s.Issuer = leaf.Issuer.CommonName
	if s.Issuer == "" && len(leaf.Issuer.Organization) > 0 {
		s.Issuer = leaf.Issuer.Organization[0]
	}
	var selected time.Time
	s.ARIStart, s.ARIEnd, selected = p.renewalInfo()
	switch {
	case !selected.IsZero():
		s.NextRenewal, s.RenewalByARI = selected, true
	case !s.ARIStart.IsZero():
		s.NextRenewal, s.RenewalByARI = s.ARIStart, true
	default:
		// CertMagic's default renewal ratio: renew with a third left.
		s.NextRenewal = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	}
	return s
}

// renewalInfo reads the ARI window CertMagic stored with the certificate.
// CertMagic keeps it in the site metadata only; it has no API for it.
func (p *certmagicProvider) renewalInfo() (start, end, selected time.Time) {
	data, err := p.magic.Storage.Load(p.ctx, certmagic.StorageKeys.SiteMeta(p.issuer.IssuerKey(), p.domain))
	if err != nil {
		return
	}
	var meta struct {
		IssuerData struct {
			RenewalInfo *struct {
				SuggestedWindow struct {
					Start time.Time `json:"start"`
					End   time.Time `json:"end"`
				} `json:"suggestedWindow"`
				SelectedTime time.Time `json:"_selectedTime"`
			} `json:"renewal_info"`
		} `json:"issuer_data"`
	}
	if json.Unmarshal(data, &meta) != nil || meta.IssuerData.RenewalInfo == nil {
		return
	}
	ri := meta.IssuerData.RenewalInfo
	return ri.SuggestedWindow.Start, ri.SuggestedWindow.End, ri.SelectedTime
}

// currentLeaf returns the cached certificate for the domain that expires
// last; during a renewal the old and the new one may both be cached.
func (p *certmagicProvider) currentLeaf() *x509.Certificate {
	var best *x509.Certificate
	for _, c := range p.cache.AllMatchingCertificates(p.domain) {
		if c.Leaf != nil && (best == nil || c.Leaf.NotAfter.After(best.NotAfter)) {
			best = c.Leaf
		}
	}
	return best
}

func (p *certmagicProvider) recordError(err error) {
	p.mu.Lock()
	p.status.LastError = err.Error()
	p.status.LastErrorAt = time.Now()
	p.mu.Unlock()
}

// onEvent records certificate events for the status page and the log.
// CertMagic calls it synchronously, so it must stay quick.
func (p *certmagicProvider) onEvent(_ context.Context, event string, data map[string]any) error {
	renewal, _ := data["renewal"].(bool)
	switch event {
	case "cert_obtained":
		p.mu.Lock()
		p.status.LastSuccess = time.Now()
		p.mu.Unlock()
		msg := "certificate obtained"
		switch {
		case p.trial:
			msg = "trial certificate obtained"
		case renewal:
			msg = "certificate renewed"
		}
		logger.Info(msg, "domain", data["identifier"], "issuer", data["issuer"])
	case "cert_failed":
		err, _ := data["error"].(error)
		if err == nil {
			err = errors.New("unknown error")
		}
		p.recordError(err)
		msg := "certificate obtain failed"
		switch {
		case p.trial:
			msg = "trial certificate order failed"
		case renewal:
			msg = "certificate renewal failed"
		}
		logger.Error(msg, "domain", data["identifier"], "err", err)
	case "cached_managed_cert":
		// Fires when a certificate enters the in-memory cache: after an
		// obtain or renewal, and at startup when it is loaded from cert_dir.
		if leaf := p.currentLeaf(); leaf != nil {
			logger.Info("certificate in use", "domain", p.domain,
				"not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// ---- CertMagic logging --------------------------------------------------------

// slogCore routes CertMagic's zap output into the global logger, so that all
// diagnostics stay in one stream and format. CertMagic's Info lines (each
// ACME step) go to Debug: the events above already log the outcomes at Info.
type slogCore struct {
	fields []zapcore.Field
}

func (c slogCore) Enabled(l zapcore.Level) bool {
	return logger.Enabled(context.Background(), slogLevel(l))
}

func (c slogCore) With(fields []zapcore.Field) zapcore.Core {
	return slogCore{fields: append(append([]zapcore.Field{}, c.fields...), fields...)}
}

func (c slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c slogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.fields {
		f.AddTo(enc)
	}
	for _, f := range fields {
		f.AddTo(enc)
	}
	keys := make([]string, 0, len(enc.Fields))
	for k := range enc.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := []any{"component", "certmagic"}
	if e.LoggerName != "" {
		attrs = append(attrs, "logger", e.LoggerName)
	}
	for _, k := range keys {
		attrs = append(attrs, k, enc.Fields[k])
	}
	logger.Log(context.Background(), slogLevel(e.Level), e.Message, attrs...)
	return nil
}

func (c slogCore) Sync() error { return nil }

func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l <= zapcore.InfoLevel:
		return slog.LevelDebug
	case l == zapcore.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}
