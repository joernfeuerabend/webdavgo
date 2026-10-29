// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// wizard.go – the certificate request that Apply in the Settings page's
// TLS & domain section runs, its progress page and the finish page.
//
// The step checks DNS and port 443, places a trial order (by default against
// Let's Encrypt staging, whose rate limits are generous), then the real one,
// and moves the WebDAV listener to :443 with TLS without a restart. The new
// listener starts first, because it has to answer the CA's TLS-ALPN-01
// validation; the old plaintext one is drained only after the certificate
// is in place. If anything fails, the old listener simply keeps running.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"golang.org/x/net/netutil"
)

// domainJobTimeout bounds one run of the step. Each ACME order normally
// takes seconds; CertMagic's own retries are what can make it long.
const domainJobTimeout = 10 * time.Minute

// jobStep is one line of the progress list.
type jobStep struct {
	Text   string
	State  string // running, ok, warn or fail
	Detail string // underlying error or extra facts, shown folded
}

// domainJob is the state of the current or last run; only one runs at a
// time.
type domainJob struct {
	mu        sync.Mutex
	started   bool
	running   bool
	ok        bool
	domain    string
	steps     []jobStep
	errMsg    string
	errDetail string
	cancel    context.CancelFunc
	// submitted holds the values of the last request until the TLS
	// section is submitted again; after a failure the Settings page shows
	// them, since nothing was saved.
	submitted *Config
}

var job domainJob

// jobSnapshot is a copy of the job for templates.
type jobSnapshot struct {
	Started, Running, Done, OK bool
	Domain                     string
	Steps                      []jobStep
	Error, ErrorDetail         string
}

func (j *domainJob) snapshot() jobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return jobSnapshot{
		Started: j.started, Running: j.running, Done: j.started && !j.running, OK: j.ok,
		Domain: j.domain, Steps: slices.Clone(j.steps), Error: j.errMsg, ErrorDetail: j.errDetail,
	}
}

// step appends a running step and returns its index for finishStep.
func (j *domainJob) step(text string) int {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.steps = append(j.steps, jobStep{Text: text, State: "running"})
	return len(j.steps) - 1
}

func (j *domainJob) finishStep(i int, state, text, detail string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.steps[i].State = state
	if text != "" {
		j.steps[i].Text = text
	}
	j.steps[i].Detail = detail
}

// fail ends the run with a plain-English message; detail is the underlying
// error for the folded details element.
func (j *domainJob) fail(msg string, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.running, j.ok, j.errMsg = false, false, msg
	if err != nil {
		j.errDetail = err.Error()
	}
	logger.Warn("domain setup failed", "domain", j.domain, "reason", msg, "err", err)
}

// failedRequest returns the submitted values and the error of the last
// request if it failed and the TLS section has not been submitted since.
func (j *domainJob) failedRequest() (Config, string, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.started || j.running || j.ok || j.submitted == nil {
		return Config{}, "", false
	}
	return *j.submitted, j.errMsg, true
}

// forgetFailure drops the values of a finished request.
func (j *domainJob) forgetFailure() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.running {
		j.submitted = nil
	}
}

// cancelDomainJob stops a running order at shutdown.
func cancelDomainJob() {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.cancel != nil {
		job.cancel()
	}
}

// ---- handlers --------------------------------------------------------------------

// handleDomainGET shows the progress of the certificate request that
// Apply in the TLS & domain section of the Settings page started.
func handleDomainGET(w http.ResponseWriter, r *http.Request) {
	s := job.snapshot()
	if !s.Started {
		http.Redirect(w, r, "/admin/settings#tls", http.StatusSeeOther)
		return
	}
	c := conf()
	renderPage(w, r, "domain", map[string]any{
		"Page":       "settings",
		"Job":        s,
		"AdminReach": adminReach(c.webguiAddr()),
	})
}

// startDomainJob starts the certificate request for the TLS settings of t
// (domain, acme_email, acme_ca, acme_trial_ca, acme_ca_root) in the
// background; the domain wizard's checks and orders run as before. Nothing
// is written to the config file unless it succeeds. It fails only if a
// request is already running.
func startDomainJob(t Config, by string) error {
	job.mu.Lock()
	if job.running {
		job.mu.Unlock()
		return errors.New("a certificate request is already running; wait for it to finish")
	}
	ctx, cancel := context.WithTimeout(context.Background(), domainJobTimeout)
	job.started, job.running, job.ok = true, true, false
	job.domain, job.steps, job.errMsg, job.errDetail = t.Domain, nil, "", ""
	job.cancel, job.submitted = cancel, &t
	job.mu.Unlock()

	logger.Info("domain setup started", "domain", t.Domain, "by", by)
	go func() {
		defer cancel()
		runDomainJob(ctx, t)
	}()
	return nil
}

// handleDomainProgress serves the progress fragment that the page polls
// while the job runs; the fragment stops polling once it is done.
func handleDomainProgress(w http.ResponseWriter, r *http.Request) {
	s := job.snapshot()
	if s.Done && s.OK {
		// HTMX follows this with a full page load.
		w.Header().Set("HX-Redirect", "/admin/domain/done")
	}
	renderPage(w, r, "domain-progress", map[string]any{"Job": s})
}

// handleDomainDone is the finish page: certificate status and the public
// WebDAV URL.
func handleDomainDone(w http.ResponseWriter, r *http.Request) {
	c := currentConfig()
	p := currentCerts()
	if c.TLSMode != "acme" || p == nil {
		http.Redirect(w, r, "/admin/settings#tls", http.StatusSeeOther)
		return
	}
	data := certStatusData(p.Status())
	data["Page"] = "settings"
	data["URL"] = publicURL(c)
	data["AdminReach"] = adminReach(c.webguiAddr())
	renderPage(w, r, "finish", data)
}

// publicURL is the WebDAV URL clients use. The port is left out for 443,
// the only external port TLS-ALPN-01 works with.
func publicURL(c Config) string {
	if c.WebDAVPort == 443 {
		return "https://" + c.Domain + "/"
	}
	return "https://" + net.JoinHostPort(c.Domain, strconv.Itoa(c.WebDAVPort)) + "/"
}

// caDirectoryURL resolves the acme_ca shorthands like newCertmagicProvider.
func caDirectoryURL(ca string) string {
	switch ca {
	case "production":
		return certmagic.LetsEncryptProductionCA
	case "staging":
		return certmagic.LetsEncryptStagingCA
	}
	return ca
}

// caName is the CA as shown to the operator; "" means no trial order.
func caName(ca string) string {
	switch ca {
	case "production":
		return "Let's Encrypt"
	case "staging":
		return "Let's Encrypt staging"
	}
	return ca
}

// ---- the job ---------------------------------------------------------------------

// runDomainJob runs preflight, trial and real order, then the switch, for
// the TLS settings of t. It owns job.running until it returns.
func runDomainJob(ctx context.Context, t Config) {
	c := currentConfig()
	c.TLSMode = "acme"
	c.Domain, c.ACMEEmail, c.ACMECA, c.ACMETrialCA, c.ACMECARoot = t.Domain, t.ACMEEmail, t.ACMECA, t.ACMETrialCA, t.ACMECARoot
	domain := c.Domain
	customCA := c.ACMECA != "production" && c.ACMECA != "staging"

	if !checkDNS(ctx, domain, customCA) {
		return
	}

	// ---- port 443 -------------------------------------------------------------------
	// Port 443 on the configured listen address: TLS-ALPN-01 works only
	// there.
	const port = 443
	addr := net.JoinHostPort(c.WebDAVListenAddress, strconv.Itoa(port))
	reuse := webdavServesTLSOn443(c)
	var newSrv *http.Server
	var ln net.Listener
	i := job.step("Checking that this server can use port 443")
	if reuse {
		job.finishStep(i, "ok", "WebDAV already listens on port 443 with TLS; the new certificate replaces the current one there", "")
	} else {
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			job.finishStep(i, "fail", "", err.Error())
			job.fail(explainBindError(err), err)
			return
		}
		ln = trackConns(netutil.LimitListener(ln, conf().MaxConnections), "webdav")
		newSrv = newServer("webdav", running.webdavHandler)
		newSrv.TLSConfig = webdavTLSConfig()
		serve("webdav", newSrv, ln)
		job.finishStep(i, "ok", "Port 443 is free; a TLS listener is waiting there for the certificate authority", "")
	}
	// abort closes the new listener; the old one never stopped.
	abort := func(msg string, err error) {
		setPendingCerts(nil)
		if newSrv != nil {
			newSrv.Close()
		}
		job.fail(msg, err)
	}

	// ---- trial order ----------------------------------------------------------------
	if trial := c.trialCA(); trial != "" {
		i := job.step("Trial order at " + caName(trial) + " (protects the real CA's rate limits)")
		tc := c
		tc.ACMECA = trial
		p, err := newCertmagicProvider(tc, addr, filepath.Join(c.CertDir, "trial"), true)
		if err != nil {
			job.finishStep(i, "fail", "", err.Error())
			abort("Could not prepare the trial order.", err)
			return
		}
		setPendingCerts(p)
		err = p.obtainTrial(ctx)
		setPendingCerts(nil)
		p.Stop()
		if err != nil {
			job.finishStep(i, "fail", "", err.Error())
			abort(explainACMEError(domain, trial, err), err)
			return
		}
		job.finishStep(i, "ok", "Trial order at "+caName(trial)+" succeeded", "")
	} else {
		i := job.step("Trial order")
		job.finishStep(i, "ok", "Trial order skipped (acme_trial_ca or a CA other than Let's Encrypt production)", "")
	}

	// ---- real order -----------------------------------------------------------------
	i = job.step("Requesting the certificate from " + caName(c.ACMECA))
	p, err := newCertmagicProvider(c, addr, c.CertDir, false)
	if err != nil {
		job.finishStep(i, "fail", "", err.Error())
		abort("Could not prepare the certificate request.", err)
		return
	}
	setPendingCerts(p)
	if err := p.obtainAndManage(ctx); err != nil {
		p.Stop()
		job.finishStep(i, "fail", "", err.Error())
		abort(explainACMEError(domain, c.ACMECA, err), err)
		return
	}
	job.finishStep(i, "ok", "Certificate for "+domain+" obtained from "+caName(c.ACMECA), "")

	// ---- switch ---------------------------------------------------------------------
	i = job.step("Switching WebDAV to HTTPS on port 443")
	// Only now, with the certificate in place, and in one write: the file
	// must never name a domain without a certificate for it, nor tls_mode
	// acme without its listener address.
	kv := map[string]any{"tls_mode": "acme", "webdav_port": int64(port), "domain": domain, "acme_email": c.ACMEEmail,
		"acme_ca": c.ACMECA, "acme_trial_ca": c.ACMETrialCA, "acme_ca_root": c.ACMECARoot}
	if err := saveConfig(c.ConfigFile, kv); err != nil {
		p.Stop()
		job.finishStep(i, "fail", "", err.Error())
		abort("The certificate was obtained, but the settings could not be saved to "+c.ConfigFile+"; WebDAV stays on its current listener.", err)
		return
	}
	oldAddr := switchWebDAV(p, newSrv, c, port)
	text := "WebDAV now answers at " + publicURL(currentConfig())
	if oldAddr != "" {
		text += "; the plain-HTTP listener on " + oldAddr + " finishes its running requests and closes"
	}
	job.finishStep(i, "ok", text, "")

	job.mu.Lock()
	job.running, job.ok = false, true
	job.mu.Unlock()
	logger.Info("domain setup complete", "domain", domain, "addr", addr)
}

// checkDNS runs the DNS preflight and reports whether to go on. Not
// finding this host's own address is only a warning: behind NAT the record
// points at the router. A name that does not resolve at all fails, except
// with a custom CA, which may use its own resolver (Pebble in tests).
func checkDNS(ctx context.Context, domain string, customCA bool) bool {
	i := job.step("Checking DNS for " + domain)
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lctx, domain)
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no A or AAAA records")
		}
		if customCA {
			job.finishStep(i, "warn", domain+" does not resolve here; continuing because acme_ca is a custom CA, which may resolve names its own way", err.Error())
			return true
		}
		job.finishStep(i, "fail", "", err.Error())
		job.fail("DNS for "+domain+" does not resolve. Create an A record (and AAAA for IPv6) pointing at your public address, wait for it to propagate, then try again.", err)
		return false
	}
	var list []string
	own := false
	local := map[string]bool{}
	for _, ip := range lanAddrs() {
		local[ip.String()] = true
	}
	for _, a := range addrs {
		list = append(list, a.IP.String())
		if local[a.IP.String()] {
			own = true
		}
	}
	text := domain + " resolves to " + strings.Join(list, ", ")
	if own {
		job.finishStep(i, "ok", text+" (an address of this host)", "")
		return true
	}
	job.finishStep(i, "warn", text+". None of these is an address of this host: that is expected behind a NAT router if it is your router's public address; otherwise DNS for "+domain+" does not point to this server.", "")
	return true
}

// webdavServesTLSOn443 reports whether the running WebDAV listener already
// is the TLS one on port 443, so a new domain only needs a new certificate.
func webdavServesTLSOn443(c Config) bool {
	running.mu.Lock()
	srv := running.webdav
	running.mu.Unlock()
	return srv != nil && srv.TLSConfig != nil && c.WebDAVPort == 443
}

// switchWebDAV makes p the certificate provider for the TLS settings of t
// and, if newSrv is set, the new server the WebDAV listener on port; the
// old server drains in the background. It returns the address of the old
// listener, or "" if there was none to replace.
func switchWebDAV(p certProvider, newSrv *http.Server, t Config, port int) string {
	oldCerts := currentCerts()
	setCerts(p)
	if oldCerts != nil {
		oldCerts.Stop()
	}

	cfgMu.Lock()
	c := currentConfig()
	oldAddr := c.webdavAddr()
	c.TLSMode, c.Domain, c.ACMEEmail, c.ACMECA, c.ACMETrialCA, c.ACMECARoot = "acme", t.Domain, t.ACMEEmail, t.ACMECA, t.ACMETrialCA, t.ACMECARoot
	c.WebDAVPort = port
	setConf(c)
	cfgMu.Unlock()

	if newSrv == nil {
		return ""
	}
	running.mu.Lock()
	old := running.webdav
	running.webdav = newSrv
	if old != nil {
		running.draining = append(running.draining, old)
	}
	running.mu.Unlock()
	if old == nil {
		return ""
	}
	go drainServer("webdav", old, oldAddr)
	return oldAddr
}

// drainServer closes a replaced server the way shutdown does: no new
// connections, running requests may finish within shutdown_timeout.
func drainServer(name string, srv *http.Server, addr string) {
	logger.Info("old "+name+" listener draining", "addr", addr, "timeout", conf().ShutdownTimeout.String())
	ctx, cancel := context.WithTimeout(context.Background(), conf().ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Warn("old "+name+" listener: drain timeout expired, closing connections", "addr", addr)
		srv.Close()
	}
	running.mu.Lock()
	running.draining = slices.DeleteFunc(running.draining, func(s *http.Server) bool { return s == srv })
	running.mu.Unlock()
	logger.Info("old "+name+" listener closed", "addr", addr)
}

// explainBindError turns a failed bind on port 443 into advice.
func explainBindError(err error) string {
	switch {
	case errors.Is(err, syscall.EACCES):
		return "webdavgo is not allowed to use port 443. The systemd unit written by \"webdavgo install\" grants CAP_NET_BIND_SERVICE; when you start webdavgo by hand, start it as root or grant it that capability."
	case errors.Is(err, syscall.EADDRINUSE):
		return "Port 443 is already in use by another program, for example a web server. webdavgo needs port 443 itself; running behind a reverse proxy is not supported yet."
	}
	return "Cannot listen on port 443."
}

// explainACMEError turns an ACME failure into advice. The checks look at
// the ACME problem types (RFC 8555 section 6.7) and at the texts Let's
// Encrypt and Pebble put into them.
func explainACMEError(domain, ca string, err error) string {
	s := strings.ToLower(err.Error())
	// Only a failure to reach the CA itself names its directory URL; the
	// URLs of orders and challenges have other paths.
	if dir := caDirectoryURL(ca); dir != "" && strings.Contains(s, strings.ToLower(dir)) {
		return "Cannot talk to the certificate authority (" + dir + ") – check this server's internet connection (and acme_ca / acme_ca_root for a custom CA)."
	}
	has := func(subs ...string) bool {
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				return true
			}
		}
		return false
	}
	switch {
	case has("ratelimited", "rate limit", "too many"):
		return "The certificate authority's rate limit is reached. Wait (Let's Encrypt states how long in the details) and try again."
	case has("error:caa", " caa "):
		return "A CAA record in the DNS of " + domain + " does not allow this certificate authority to issue certificates for it."
	case has("error:dns", "nxdomain", "no valid a records", "servfail", "dns problem"):
		return "DNS for " + domain + " does not point to this server."
	case has("error:connection", "connection refused", "timeout during connect", "i/o timeout", "no route to host", "connection reset"):
		return "Port 443 is not reachable from the internet – check port forwarding (external TCP 443 to this server)."
	case has("error:unauthorized", "error:tls", "incorrect validation certificate", "key authorization"):
		return "The certificate authority reached port 443, but not this server – check that port 443 is forwarded to this machine and DNS for " + domain + " points to your public address."
	case has("directory", "no such host", "certificate signed by unknown authority", "x509"):
		return "Cannot talk to the certificate authority – check this server's internet connection (and acme_ca / acme_ca_root for a custom CA)."
	case has("context deadline exceeded", "context canceled"):
		return "The certificate request did not finish in time."
	}
	return "The certificate request failed."
}
