// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	"golang.org/x/net/webdav"
)

// forcedCloseGrace bounds how long shutdown waits for handlers after their
// connections were force-closed. Handlers notice the closed connection on
// their next read or write; the wait lets an interrupted PUT remove its temp
// file before the process exits.
const forcedCloseGrace = 5 * time.Second

var davHandlers sync.Map // username -> *webdav.Handler

func getDavHandler(username string) *webdav.Handler {
	h := &webdav.Handler{
		Prefix:     "/",
		FileSystem: davFS{webdav.Dir(userDataRoot(username))},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err == nil {
				return
			}
			status := davStatus(r)
			logger.Log(r.Context(), davErrorLevel(status, err), "webdav internal error", "user", username,
				"client", remoteIP(r), "method", r.Method, "path", r.URL.Path, "status", status, "err", err)
		},
	}
	actual, _ := davHandlers.LoadOrStore(username, h)
	return actual.(*webdav.Handler)
}

// adminFingerprint is the SHA-256 fingerprint of the self-signed admin
// certificate, set once in main for the status page.
var adminFingerprint string

// version is set at build time with -ldflags "-X main.version=..." (see
// the Makefile); a plain go build reports "dev".
var version = "dev"

const usage = "webdavgo [flags] | webdavgo reset-totp [flags] <username> | webdavgo setup-info [flags] | " +
	"webdavgo healthcheck [-config file] | webdavgo install [-root dir] | webdavgo uninstall [-root dir] [-purge [-yes]]"

func main() {
	// First of all: a container runtime runs healthcheck every few seconds
	// next to the service, so it must not set up logging or touch anything
	// the service owns.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}
	initLogger("", "")

	args := os.Args[1:]
	// install and uninstall work on the system, not on a configuration, so
	// they parse their own flags.
	if len(args) > 0 {
		switch args[0] {
		case "install":
			os.Exit(runInstall(args[1:]))
		case "uninstall":
			os.Exit(runUninstall(args[1:]))
		}
	}
	command := ""
	if len(args) > 0 && (args[0] == "reset-totp" || args[0] == "setup-info") {
		command, args = args[0], args[1:]
	}
	c, rest, err := loadConfig(args, command == "")
	if err != nil {
		logger.Error("cannot load configuration", "err", err)
		os.Exit(1)
	}
	setConf(c)
	switch command {
	case "reset-totp":
		os.Exit(runResetTOTP(rest))
	case "setup-info":
		os.Exit(runSetupInfo(rest))
	}
	if len(rest) > 0 {
		logger.Error("unknown command", "command", rest[0], "usage", usage)
		os.Exit(2)
	}
	level, _ := parseLogLevel(conf().LogLevel)
	logLevel.Set(level)
	logRing.resize(conf().LogBufferEntries)
	// Only here, after the CLI commands have returned: they log to the
	// terminal and must not touch the service's log files. Under systemd,
	// LogsDirectory= has created the directory; a server started otherwise
	// creates it.
	for _, p := range []string{conf().AccessLog, conf().ServerLog} {
		if p == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0750); err != nil {
			logger.Error("cannot create log directory", "path", filepath.Dir(p), "err", err)
			os.Exit(1)
		}
	}
	if err := initLogger(conf().AccessLog, conf().ServerLog); err != nil {
		os.Exit(1)
	}
	authCache = newCredCache(conf().AuthCacheTTL)
	limiter = newBruteForce(*conf())
	unauthLimiter = newUnauthLimit(*conf())
	limited = newLimitRegistry(conf().BruteforceMaxEntries)

	logger.Info("startup", "version", version)

	if conf().ConfigRead != "" && conf().ConfigRead != conf().ConfigFile {
		if err := migrateConfigFile(conf().ConfigRead, conf().ConfigFile); err != nil {
			logger.Error("cannot create the config file from the old one; for an installed service run \"sudo webdavgo install\" again",
				"from", conf().ConfigRead, "to", conf().ConfigFile, "err", err)
			os.Exit(1)
		}
		logger.Info("config file migrated; the old file is left as it is", "from", conf().ConfigRead, "to", conf().ConfigFile)
		c.ConfigRead = c.ConfigFile
		setConf(c)
	}

	if err := os.MkdirAll(conf().DataDir, 0755); err != nil {
		logger.Error("cannot create data directory", "path", conf().DataDir, "err", err)
		os.Exit(1)
	}

	if err := openDB(filepath.Join(conf().DataDir, "webdavgo.db")); err != nil {
		logger.Error("cannot open database", "err", err)
		os.Exit(1)
	}

	// Starting without the values an older version kept in the database
	// could mean TLS off or other listeners, so a failure here is fatal.
	changed, err := migrateStoredSettings(conf().ConfigFile)
	if err != nil {
		logger.Error("cannot move the settings stored in the database to the config file",
			"path", conf().ConfigFile, "err", err)
		os.Exit(1)
	}
	if changed {
		if c, _, err = loadConfig(args, false); err != nil {
			logger.Error("invalid configuration", "err", err)
			os.Exit(1)
		}
		setConf(c)
	}
	if err := conf().validateTLS(); err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	logger.Info("config", conf().logAttrs()...)
	webdavAddr, webguiAddr := conf().webdavAddr(), conf().webguiAddr()

	adminCert, err := loadOrCreateAdminCert(conf().CertDir)
	if err != nil {
		logger.Error("cannot set up admin certificate", "err", err)
		os.Exit(1)
	}
	adminFingerprint = certFingerprint(adminCert)
	// Logged on every start so the operator can always look it up to verify
	// a browser warning, not only at the moment it was created.
	logger.Info("admin certificate", "sha256", adminFingerprint,
		"path", filepath.Join(conf().CertDir, adminCertFile))

	webdavOn := true
	if conf().TLSMode == "acme" {
		p, err := newCertProvider(*conf(), webdavAddr)
		if err != nil {
			logger.Error("cannot set up TLS", "err", err)
			os.Exit(1)
		}
		setCerts(p)
	} else if conf().RequireTLS && !isLoopbackAddr(webdavAddr) {
		// Clear-text Basic Auth must never reach a network; the admin
		// listener still starts so that the Settings page can
		// turn TLS on.
		webdavOn = false
		logger.Warn("webdav listener not started: require_tls is set and tls_mode is off; "+
			"set up TLS on the admin UI (Settings, TLS & domain) or set webdav_listen_address to a loopback address",
			"addr", webdavAddr)
	} else {
		logger.Warn("tls_mode is off: WebDAV credentials are sent in clear text; use only for development or on a trusted LAN",
			"addr", webdavAddr)
	}

	// Must run before the listeners open: only then is it certain that no
	// upload owns any of these files.
	removeStaleTempFiles(filepath.Join(conf().DataDir, "users"))
	if err := reconcileUsage(); err != nil {
		logger.Error("cannot reconcile storage usage", "err", err)
		os.Exit(1)
	}

	loadTemplates()

	hasAdmin, err := adminExists()
	if err != nil {
		logger.Error("cannot query for admin user", "err", err)
		os.Exit(1)
	}
	if !hasAdmin {
		enterSetupMode(webguiAddr, adminFingerprint)
	}

	var webdavLn net.Listener
	if webdavOn {
		if webdavLn, err = listen(webdavAddr, "webdav"); err != nil {
			logger.Error("webdav listener failed", "addr", webdavAddr, "err", err)
			os.Exit(1)
		}
	}
	webguiLn, err := listen(webguiAddr, "admin")
	if err != nil {
		logger.Error("webgui listener failed", "addr", webguiAddr, "err", err)
		os.Exit(1)
	}
	var healthLn net.Listener
	if conf().HealthEnabled {
		if healthLn, err = listenHealth(conf().healthAddr()); err != nil {
			logger.Error("health listener failed", "addr", conf().healthAddr(), "err", err)
			os.Exit(1)
		}
	}

	running.webdavHandler = buildWebDAVHandler()
	running.webguiHandler = buildWebGUIHandler()
	webguiSrv := newServer("admin", running.webguiHandler)
	// TLS only, also on localhost: there is no plaintext admin listener to
	// fall back to, so remote access goes through an SSH tunnel instead.
	webguiSrv.TLSConfig = adminTLSConfig(adminCert)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if webdavOn {
		webdavSrv := newServer("webdav", running.webdavHandler)
		if currentCerts() != nil {
			webdavSrv.TLSConfig = webdavTLSConfig()
		}
		running.mu.Lock()
		running.webdav = webdavSrv
		running.mu.Unlock()
		serve("webdav", webdavSrv, webdavLn)
	}
	running.mu.Lock()
	running.webgui = webguiSrv
	running.mu.Unlock()
	serve("webgui", webguiSrv, webguiLn)
	if healthLn != nil {
		serveHealth(healthLn)
	}
	notifyReady()
	// Only now: the CA validates TLS-ALPN-01 by connecting to the WebDAV
	// listener, which therefore has to accept connections first.
	if p := currentCerts(); p != nil {
		p.Start()
	}

	select {
	case err := <-running.serveErr:
		logger.Error("server error", "err", err)
		os.Exit(1)
	case <-ctx.Done():
	}
	// Restore default signal handling so a second Ctrl-C ends the process
	// immediately instead of waiting for the shutdown timeout.
	stop()

	cancelDomainJob()
	shutdown(running.servers(), &running.inflight, &running.openConns)
	if p := currentCerts(); p != nil {
		p.Stop()
	}
	if err := db.Close(); err != nil {
		logger.Error("close database", "err", err)
	}
	logger.Info("shutdown complete")
}

// listenerSet holds the running servers. The domain wizard replaces the
// WebDAV server at runtime, so shutdown asks for the current set instead of
// main keeping its own.
type listenerSet struct {
	webdavHandler http.Handler
	// webguiHandler outlives a re-bound admin listener (Apply on the
	// Settings page), and with it the admin sessions.
	webguiHandler http.Handler
	inflight      requestTracker
	openConns     atomic.Int64
	conns         connRegistry
	serveErr      chan error

	mu       sync.Mutex
	webdav   *http.Server // nil while require_tls keeps WebDAV off
	webgui   *http.Server
	health   *http.Server   // nil while health_enabled is false
	draining []*http.Server // replaced servers finishing their requests
}

var running = listenerSet{serveErr: make(chan error, 1)}

// servers returns every server that may still have connections.
func (l *listenerSet) servers() []*http.Server {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]*http.Server(nil), l.draining...)
	for _, s := range []*http.Server{l.webdav, l.webgui, l.health} {
		if s != nil {
			out = append(out, s)
		}
	}
	return out
}

// serve runs srv on ln in the background. Errors other than a regular close
// end the process through main's select.
func serve(name string, srv *http.Server, ln net.Listener) {
	attrs := []any{"addr", ln.Addr().String(), "tls", srv.TLSConfig != nil}
	if name == "webgui" {
		attrs = append(attrs, "reach", adminReach(ln.Addr().String()))
	}
	logger.Info(name+" listener", attrs...)
	go func() {
		var err error
		if srv.TLSConfig != nil {
			// No files: the certificate comes from TLSConfig.GetCertificate.
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if !errors.Is(err, http.ErrServerClosed) {
			select {
			case running.serveErr <- fmt.Errorf("%s server: %w", name, err):
			default:
			}
		}
	}()
}

// isLoopbackAddr reports whether a listen address only accepts connections
// from this host. An empty host binds every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// listen opens a TCP listener capped at max_connections so that a flood of
// connections queues in the kernel instead of exhausting file descriptors.
// listener names it for the Status page, as in newServer.
func listen(addr, listener string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return trackConns(netutil.LimitListener(ln, conf().MaxConnections), listener), nil
}

// requestTracker counts running handlers so that a forced shutdown can wait
// for them. sync.WaitGroup does not fit: its Add must not race with Wait,
// but a handler on an already accepted connection can start while shutdown
// is waiting.
type requestTracker struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n drops to 0; nil while nobody waits
}

func (t *requestTracker) start() {
	t.mu.Lock()
	t.n++
	t.mu.Unlock()
}

func (t *requestTracker) done() {
	t.mu.Lock()
	t.n--
	if t.n == 0 && t.idle != nil {
		close(t.idle)
		t.idle = nil
	}
	t.mu.Unlock()
}

// waitIdle returns a channel that is closed once no handler runs.
func (t *requestTracker) waitIdle() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == 0 {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	if t.idle == nil {
		t.idle = make(chan struct{})
	}
	return t.idle
}

// newServer builds an http.Server with the configured timeouts. There is
// deliberately no ReadTimeout or WriteTimeout: a single upload or download
// may legitimately take several minutes on a slow link. Stalled request
// bodies and responses are handled per read and write instead (see
// guardBody and guardResponse). listener names the server on the Status
// page's connection list and in its statistics.
func newServer(listener string, h http.Handler) *http.Server {
	sl := statListenerIndex(listener)
	return &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			running.inflight.start()
			defer running.inflight.done()
			if ci, _ := r.Context().Value(ctxConn).(*connInfo); ci != nil {
				defer ci.end(ci.begin(r))
			}
			gw := guardResponse(w, r)
			defer gw.finish()
			defer func() { stats.request(sl, gw.status) }()
			h.ServeHTTP(gw, r)
		}),
		ReadHeaderTimeout: conf().ReadHeaderTimeout,
		IdleTimeout:       conf().IdleTimeout,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          newServerErrorLog(listener),
		// max_connections caps connections; without a stream limit each
		// HTTP/2 connection could still carry 250 requests at once.
		HTTP2:       &http.HTTP2Config{MaxConcurrentStreams: conf().HTTP2MaxConcurrentStreams},
		ConnContext: running.conns.connContext(listener),
		ConnState: func(c net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				running.openConns.Add(1)
				stats.connOpened(sl)
			case http.StateClosed, http.StateHijacked:
				running.openConns.Add(-1)
				stats.connClosed(sl)
			}
			running.conns.connState(c, state)
		},
	}
}

// shutdown stops accepting connections and lets in-flight requests finish
// within shutdown_timeout. Requests still running after that are cut, which
// is still a clean exit from the operator's point of view.
func shutdown(servers []*http.Server, inflight *requestTracker, openConns *atomic.Int64) {
	logger.Info("shutdown started", "timeout", conf().ShutdownTimeout.String())
	ctx, cancel := context.WithTimeout(context.Background(), conf().ShutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Shutdown(ctx)
		}()
	}
	wg.Wait()
	if ctx.Err() == nil {
		return
	}

	logger.Warn("shutdown timeout expired, closing connections", "connections_cut", openConns.Load())
	for _, s := range servers {
		s.Close()
	}
	select {
	case <-inflight.waitIdle():
	case <-time.After(forcedCloseGrace):
		logger.Warn("handlers still running after forced close")
	}
}

// removeStaleTempFiles deletes upload temp files left behind when a previous
// process ended during a PUT (kill -9, OOM, power loss).
func removeStaleTempFiles(root string) {
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			logger.Warn("temp file scan: cannot read", "path", p, "err", err)
			return nil
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), tmpPrefix) {
			return nil
		}
		if err := os.Remove(p); err != nil {
			logger.Warn("cannot remove stale upload temp file", "path", p, "err", err)
			return nil
		}
		logger.Warn("removed stale upload temp file", "path", p)
		return nil
	})
	if err != nil {
		logger.Warn("temp file scan failed", "root", root, "err", err)
	}
}

// buildWebDAVHandler returns the handler chain for the WebDAV listener:
//
//	SetupGate -> BodyLimit -> (share | API | BasicAuth -> SEARCH | PROPFIND | per-user webdav.Handler)
func buildWebDAVHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The log line starts here so that duration includes authentication,
		// which with bcrypt dominates small requests.
		rl := &requestLog{start: time.Now(), auth: "none"}
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() { rl.write(r, rw.status) }()

		// Set before any branch can answer, so error pages carry it too.
		rw.Header().Set("X-Frame-Options", "DENY")
		// Only over TLS: during the domain wizard's listener switch the old
		// plaintext listener still finishes its requests.
		if r.TLS != nil {
			rw.Header().Set("Strict-Transport-Security", hstsValue)
		}
		guardBody(w, r)

		if isSetupActive() {
			http.Error(rw, "setup required, see server console", http.StatusServiceUnavailable)
			return
		}
		if rejectLargeBody(rw, r) {
			return
		}
		// Every path answers a request without credentials with 401, so it
		// is limited here, before routing. Requests with credentials never
		// count: the brute-force limiter handles those.
		if _, _, ok := r.BasicAuth(); !ok && checkUnauthRate(rw, r) {
			return
		}

		if strings.HasPrefix(r.URL.Path, "/s/") {
			handleShareRequest(rw, r, rl)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			handleAPIRequest(rw, r, rl)
			return
		}

		username, password, ok := r.BasicAuth()
		res := authBad
		if ok {
			authStart := time.Now()
			var method string
			var wait time.Duration
			var err error
			res, method, wait, err = authenticateUserLimited(r, username, password)
			rl.authDone(method, authStart)
			if err != nil {
				serviceUnavailable(rw, r, "user auth lookup failed", err)
				return
			}
			if res == authThrottled {
				tooManyAttempts(rw, wait)
				return
			}
		}
		if res != authOK {
			rw.Header().Set("WWW-Authenticate", `Basic realm="webdavgo"`)
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		rl.user = username
		noteIdentity(r, username)
		stats.userActive(username)

		if requestTouchesReserved(r) {
			http.Error(rw, "forbidden", http.StatusForbidden)
			return
		}

		// Create user data directory on first access.
		root := userDataRoot(username)
		if err := os.MkdirAll(root, 0755); err != nil {
			logger.Error("cannot create user data dir", "user", username, "err", err)
			http.Error(rw, "internal error", http.StatusInternalServerError)
			return
		}

		switch r.Method {
		case "SEARCH":
			handleSearch(rw, r, root, "")
		case "PROPFIND":
			handlePropfind(rw, r, root, "", username)
		default:
			absPath := filepath.Join(root, filepath.FromSlash(path.Clean("/"+r.URL.Path)))
			serveDAV(rw, r, getDavHandler(username), absPath, username)
		}
	})
}

// buildWebGUIHandler returns the handler chain for the WebGUI listener:
//
//	SecurityHeaders -> OriginCheck -> BodyLimit -> SetupGate -> (/setup* | /admin/static/* | admin mux)
func buildWebGUIHandler() http.Handler {
	adminMux := NewAdminMux()

	// Serve embedded static assets under /admin/static/.
	staticFS, _ := fs.Sub(assetsFS, "assets")
	staticHandler := http.StripPrefix("/admin/static/", http.FileServer(http.FS(staticFS)))

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// At Debug: the admin UI polls every few seconds while it is open.
		// URL.Path only: a query string may carry a setup token.
		start := time.Now()
		w := &statusRecorder{ResponseWriter: rw, status: http.StatusOK}
		defer func() {
			logger.Debug("request", "listener", "admin", "method", r.Method, "path", r.URL.Path,
				"client", remoteIP(r), "status", w.status,
				"duration", fmt.Sprintf("%dms", time.Since(start).Milliseconds()))
		}()

		setAdminHeaders(w.Header())
		if !strings.HasPrefix(r.URL.Path, "/admin/static/") {
			// Pages carry session data, setup tokens, TOTP secrets or
			// recovery codes; none of it belongs in a cache.
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			logger.Warn("admin request rejected: cross-origin", "method", r.Method, "path", r.URL.Path,
				"client", remoteIP(r), "origin", r.Header.Get("Origin"), "referer", r.Header.Get("Referer"),
				"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
			http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
			return
		}
		guardBody(w, r)
		if rejectLargeBody(w, r) {
			return
		}

		// Root redirect: send bare "/" to the admin dashboard (or login), or
		// to the setup token page while no admin exists.
		if r.URL.Path == "/" {
			if isSetupActive() && !setupAdminCreated() {
				http.Redirect(w, r, "/setup", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/admin/", http.StatusFound)
			return
		}

		// Static assets are always reachable (setup page needs style.css).
		if strings.HasPrefix(r.URL.Path, "/admin/static/") {
			staticHandler.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/setup") {
			if setupEverEntered {
				handleSetup(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}

		if strings.HasPrefix(r.URL.Path, "/admin") {
			// Once setup has created the admin, login and enrolment must be
			// reachable to finish it; every other page needs a full session,
			// which only exists after enrolment. Before that, the plain admin
			// URL leads to the page that asks for the setup token.
			if isSetupActive() && !setupAdminCreated() {
				http.Redirect(w, r, "/setup", http.StatusFound)
				return
			}
			adminMux.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	})
}

// rejectLargeBody caps request bodies of every method except PUT, whose
// bodies are file uploads of arbitrary size and go straight to disk. A
// declared oversize body is refused before it is read; a chunked one fails
// with *http.MaxBytesError at the reader (see isBodyTooLarge). It reports
// whether it already answered the request.
func rejectLargeBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPut {
		return false
	}
	if r.ContentLength > conf().MaxRequestBody {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, conf().MaxRequestBody)
	return false
}

// errBodyTooSlow aborts a request body that arrives below body_min_rate.
var errBodyTooSlow = errors.New("request body below minimum rate")

// guardBody protects the connection slots (max_connections) against clients
// that start a request body and then stall or trickle it. There is no global
// ReadTimeout, because uploads may legitimately take minutes; instead every
// read of the body pushes the connection's read deadline out by
// body_read_idle_timeout, and a body averaging less than body_min_rate after
// body_min_rate_grace is aborted. An aborted PUT is discarded by atomicFile.
func guardBody(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	r.Body = &guardedBody{
		ReadCloser: r.Body,
		rc:         http.NewResponseController(w),
		method:     r.Method,
		path:       r.URL.Path,
	}
}

type guardedBody struct {
	io.ReadCloser
	rc     *http.ResponseController
	method string
	path   string
	start  time.Time // first read
	n      int64
	err    error
}

func (b *guardedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	now := time.Now()
	if b.start.IsZero() {
		b.start = now
	}
	if elapsed := now.Sub(b.start); conf().BodyMinRate > 0 && elapsed > conf().BodyMinRateGrace &&
		float64(b.n) < float64(conf().BodyMinRate)*elapsed.Seconds() {
		b.err = errBodyTooSlow
		logger.Warn("request body aborted: below minimum rate", "method", b.method, "path", b.path,
			"bytes", b.n, "elapsed", elapsed.Round(time.Millisecond).String(),
			"min_rate", conf().BodyMinRate)
		// Expire the deadline so the server does not keep reading the rest
		// of the body after the handler returns; the connection closes.
		b.rc.SetReadDeadline(now)
		return 0, b.err
	}
	b.rc.SetReadDeadline(now.Add(conf().BodyReadIdleTimeout))
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	switch {
	case err == io.EOF:
		// A leftover deadline would make the server cancel the request
		// context while the handler is still writing a long response.
		b.rc.SetReadDeadline(time.Time{})
	case errors.Is(err, os.ErrDeadlineExceeded):
		logger.Warn("request body aborted: stalled", "method", b.method, "path", b.path,
			"bytes", b.n, "idle_timeout", conf().BodyReadIdleTimeout.String())
	}
	return n, err
}

// errResponseTooSlow aborts a response the client reads below
// response_min_rate.
var errResponseTooSlow = errors.New("response below minimum rate")

// guardResponse is the counterpart of guardBody for the other direction: a
// client that downloads and then stops reading, or reads a few bytes per
// second, would otherwise hold its max_connections slot for as long as it
// likes. There is no overall WriteTimeout because downloads may take
// minutes; instead every write pushes the write deadline out by
// response_write_idle_timeout, and a response averaging less than
// response_min_rate after response_min_rate_grace is cut.
func guardResponse(w http.ResponseWriter, r *http.Request) *guardedResponse {
	g := &guardedResponse{ResponseWriter: w, rc: http.NewResponseController(w), method: r.Method, path: r.URL.Path}
	// A deadline left from the previous request on this keep-alive
	// connection must not hit a response that writes nothing until it ends.
	g.rc.SetWriteDeadline(time.Time{})
	return g
}

type guardedResponse struct {
	http.ResponseWriter
	rc     *http.ResponseController
	method string
	path   string
	start  time.Time // first write
	n      int64
	err    error
	// status is the final status for the statistics of both listeners; 0
	// until the handler sends one.
	status int
}

func (g *guardedResponse) WriteHeader(code int) {
	if g.status == 0 && code >= 200 {
		g.status = code
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *guardedResponse) Write(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	now := time.Now()
	if g.start.IsZero() {
		g.start = now
	}
	if elapsed := now.Sub(g.start); conf().ResponseMinRate > 0 && elapsed > conf().ResponseMinRateGrace &&
		float64(g.n) < float64(conf().ResponseMinRate)*elapsed.Seconds() {
		g.err = errResponseTooSlow
		logger.Warn("response aborted: below minimum rate", "method", g.method, "path", g.path,
			"bytes", g.n, "elapsed", elapsed.Round(time.Millisecond).String(), "min_rate", conf().ResponseMinRate)
		g.rc.SetWriteDeadline(now)
		return 0, g.err
	}
	if g.status == 0 {
		g.status = http.StatusOK
	}
	g.rc.SetWriteDeadline(now.Add(conf().ResponseWriteIdleTimeout))
	n, err := g.ResponseWriter.Write(p)
	g.n += int64(n)
	if errors.Is(err, os.ErrDeadlineExceeded) && g.err == nil {
		g.err = err
		logger.Warn("response aborted: client stopped reading", "method", g.method, "path", g.path,
			"bytes", g.n, "idle_timeout", conf().ResponseWriteIdleTimeout.String())
	}
	return n, err
}

// finish bounds the flush of buffered data after the handler returned. The
// next request on the connection clears the deadline again.
func (g *guardedResponse) finish() {
	g.rc.SetWriteDeadline(time.Now().Add(conf().ResponseWriteIdleTimeout))
}

// Unwrap lets http.ResponseController reach the connection behind the
// guard.
func (g *guardedResponse) Unwrap() http.ResponseWriter {
	return g.ResponseWriter
}

// isBodyTooLarge reports whether a body read failed because of the limit set
// in rejectLargeBody.
func isBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

// serviceUnavailable answers a request whose authentication could not be
// decided because the backing store failed. 401 would tell share recipients
// that their access was revoked (clients may then delete local copies), so a
// transient fault must surface as 503 instead.
func serviceUnavailable(w http.ResponseWriter, r *http.Request, msg string, err error) {
	logger.Error(msg, "method", r.Method, "path", r.URL.Path, "err", err)
	w.Header().Set("Retry-After", "30")
	http.Error(w, "service temporarily unavailable", http.StatusServiceUnavailable)
}

// requestLog collects the fields of the per-request log line while a request
// passes through authentication and its handler. Every request on the WebDAV
// listener produces exactly one line, including rejected logins, so that
// failed authentication is visible in the same stream as normal traffic.
type requestLog struct {
	start   time.Time
	auth    string // cache | bcrypt | token | none
	authDur time.Duration
	user    string // set only after successful user authentication
	shareID string // set only after successful share authentication
}

func (l *requestLog) authDone(method string, began time.Time) {
	l.auth = method
	l.authDur = time.Since(began)
}

func (l *requestLog) write(r *http.Request, status int) {
	attrs := []any{"method", r.Method, "path", r.URL.Path, "client", remoteIP(r)}
	if l.user != "" {
		attrs = append(attrs, "user", l.user)
	}
	if l.shareID != "" {
		attrs = append(attrs, "share_id", l.shareID)
	}
	attrs = append(attrs,
		"status", status,
		"auth", l.auth,
		"auth_ms", l.authDur.Milliseconds(),
		"duration", fmt.Sprintf("%dms", time.Since(l.start).Milliseconds()),
	)
	// Scanners without credentials made up half of all journal lines; they
	// are counted for the Activity card instead. A 429 without credentials
	// comes from the unauthenticated rate limit, which counted it already
	// and logs its own Warn line once a minute.
	if l.auth == "none" {
		switch status {
		case http.StatusUnauthorized:
			stats.unauthenticated(r)
			logger.Debug("request", attrs...)
			return
		case http.StatusTooManyRequests:
			logger.Debug("request", attrs...)
			return
		}
	}
	logger.Info("request", attrs...)
}

// statusRecorder captures the HTTP status code for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the connection behind the
// recorder.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
