// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// health.go – the health listener (/livez, /readyz), the "webdavgo
// healthcheck" command that queries it, and the systemd notification
// protocol (READY=1, watchdog pings).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/netutil"
)

const (
	// healthMaxConns bounds the health listener's connections: it has no
	// authentication, and every /readyz writes a file to the data directory.
	healthMaxConns = 8
	// healthPingTimeout bounds the database ping of /readyz; with a single
	// connection it waits behind a long write.
	healthPingTimeout   = 2 * time.Second
	healthClientTimeout = 3 * time.Second
)

// healthAddr is the listen string of the health listener.
func (c Config) healthAddr() string {
	return net.JoinHostPort(c.HealthBind, strconv.Itoa(c.HealthPort))
}

// buildHealthHandler serves /livez and /readyz and 404 for everything else.
// Bodies are minimal on purpose: the listener has no authentication and
// must not reveal paths, versions or error details.
func buildHealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/livez" && r.URL.Path != "/readyz" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var reason string
		switch r.URL.Path {
		case "/livez":
			if err := checkLive(); err != nil {
				reason = "not serving"
			}
		case "/readyz":
			reason = checkReady()
		}
		logger.Debug("request", "listener", "health", "path", r.URL.Path, "client", remoteIP(r), "ok", reason == "")
		if reason != "" {
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
}

// checkLive is the liveness check of /livez and the systemd watchdog. It
// looks only at the process itself: the admin listener runs (it always
// does once main has started serving) and no server has failed. Taking
// running.mu also means a ping is skipped while that lock is stuck.
func checkLive() error {
	running.mu.Lock()
	serving := running.webgui != nil
	running.mu.Unlock()
	if !serving {
		return errors.New("admin listener not running")
	}
	if len(running.serveErr) > 0 {
		return errors.New("a listener failed")
	}
	return nil
}

// checkReady is the readiness check of /readyz: the data directory takes a
// new file and the database answers. It returns "" when ready, otherwise
// the short reason for the response body; the details go to the log only.
func checkReady() string {
	if err := probeDataDir(conf().DataDir); err != nil {
		logger.Warn("readiness check failed: data directory not writable", "path", conf().DataDir, "err", err)
		return "data directory not writable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthPingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		logger.Warn("readiness check failed: database unreachable", "err", err)
		return "database unreachable"
	}
	return ""
}

// probeDataDir creates, writes and deletes a temporary file in dir. The
// name starts with a dot so that it never shows up as a user's file;
// user files live under dir/users anyway.
func probeDataDir(dir string) error {
	f, err := os.CreateTemp(dir, ".readyz-*")
	if err != nil {
		return fmt.Errorf("create probe file: %w", err)
	}
	_, werr := f.WriteString("ok")
	cerr := f.Close()
	rerr := os.Remove(f.Name())
	if err := errors.Join(werr, cerr); err != nil {
		return fmt.Errorf("write probe file: %w", err)
	}
	if rerr != nil {
		return fmt.Errorf("delete probe file: %w", rerr)
	}
	return nil
}

// newHealthServer builds the health listener's server. It deliberately
// bypasses newServer: health probes are not traffic for the statistics or
// the connection list, and they need short timeouts, not upload-friendly
// ones.
func newHealthServer() *http.Server {
	return &http.Server{
		Handler:           buildHealthHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          newServerErrorLog("health"),
	}
}

// listenHealth binds the health listener. It is plain HTTP and not part of
// max_connections; healthMaxConns caps it on its own.
func listenHealth(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return netutil.LimitListener(ln, healthMaxConns), nil
}

// serveHealth serves the health listener on ln and records it in running.
func serveHealth(ln net.Listener) {
	srv := newHealthServer()
	running.mu.Lock()
	running.health = srv
	running.mu.Unlock()
	serve("health", srv, ln)
}

// startHealth binds and serves the health listener at addr.
func startHealth(addr string) error {
	ln, err := listenHealth(addr)
	if err != nil {
		return err
	}
	serveHealth(ln)
	return nil
}

// stopHealth closes the health listener, if it runs. Probes take
// milliseconds, so there is no drain like for the other listeners.
func stopHealth() {
	running.mu.Lock()
	old := running.health
	running.health = nil
	running.mu.Unlock()
	if old == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := old.Shutdown(ctx); err != nil {
		old.Close()
	}
}

// rebindHealth applies changed health_* values: the old listener stops
// first, because the new one may need the same port, then the new one
// starts. If it cannot bind, the old one is brought back.
func rebindHealth(enabled bool, host string, port int) (string, error) {
	old := currentConfig()
	stopHealth()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if enabled {
		if err := startHealth(addr); err != nil {
			if old.HealthEnabled {
				if rerr := startHealth(old.healthAddr()); rerr != nil {
					logger.Error("health listener could not be restored", "addr", old.healthAddr(), "err", rerr)
				}
			}
			return "", fmt.Errorf("health_enabled/health_bind/health_port not applied (they take effect after a service restart): %w", err)
		}
	}
	cfgMu.Lock()
	next := currentConfig()
	next.HealthEnabled, next.HealthBind, next.HealthPort = enabled, host, port
	setConf(next)
	cfgMu.Unlock()
	if !enabled {
		logger.Info("health listener stopped")
		return "The health listener is off.", nil
	}
	return "The health listener now listens on " + addr + ".", nil
}

// ---- healthcheck command ---------------------------------------------------

// runHealthcheck is "webdavgo healthcheck": GET /readyz on the health
// listener named in the config file, exit status 0 on 200 and 1 otherwise.
// main calls it before anything else, so it reads the config file and
// nothing more: no logger, database, data directory or listener. Errors go
// to stderr as one line, for docker inspect and journal readers.
func runHealthcheck(args []string) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "healthcheck: "+format+"\n", a...)
		return 1
	}
	// create=false: read-only, never writes or creates the file.
	c, rest, err := loadConfig(args, false)
	if err != nil {
		return fail("%v", err)
	}
	if len(rest) > 0 {
		return fail("unexpected argument %q", rest[0])
	}
	if !c.HealthEnabled {
		return fail("health listener disabled in config")
	}
	url := "http://" + net.JoinHostPort(healthDialHost(c.HealthBind), strconv.Itoa(c.HealthPort)) + "/readyz"
	client := &http.Client{
		Timeout: healthClientTimeout,
		// A proxy from the environment must not answer for this host.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fail("%v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		reason := strings.Join(strings.Fields(string(body)), " ")
		if reason == "" {
			return fail("%s", resp.Status)
		}
		return fail("%s: %s", resp.Status, reason)
	}
	return 0
}

// healthDialHost turns health_bind into a host to connect to: a wildcard
// bind is reached over loopback of the same family.
func healthDialHost(bind string) string {
	switch bind {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return bind
}

// ---- systemd notification --------------------------------------------------

// sdNotify sends state to the service manager over $NOTIFY_SOCKET (the
// sd_notify protocol: one datagram on a Unix socket). Without the variable,
// as outside systemd or with Type=simple, it does nothing. An address
// starting with "@" is in the abstract namespace; the net package maps the
// "@" to the leading NUL byte the kernel expects.
func sdNotify(state string) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("sd_notify: dial %s: %w", path, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("sd_notify: send %q: %w", state, err)
	}
	return nil
}

// notifyReady tells systemd that the service is up and, if WatchdogSec= is
// set for it, starts the watchdog pings.
func notifyReady() {
	if os.Getenv("NOTIFY_SOCKET") == "" {
		return
	}
	if err := sdNotify("READY=1"); err != nil {
		logger.Warn("cannot notify systemd", "err", err)
		return
	}
	interval := watchdogInterval()
	if interval <= 0 {
		return
	}
	logger.Info("systemd watchdog enabled", "interval", interval.String())
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			// A missed ping is the point: systemd restarts a process that
			// is no longer live.
			if err := checkLive(); err != nil {
				logger.Warn("watchdog ping skipped: liveness check failed", "err", err)
				continue
			}
			if err := sdNotify("WATCHDOG=1"); err != nil {
				logger.Warn("watchdog ping failed", "err", err)
			}
		}
	}()
}

// watchdogInterval returns half of $WATCHDOG_USEC, as sd_watchdog_enabled
// recommends, or 0 when the watchdog is off or meant for another process.
func watchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}
