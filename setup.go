// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	qrterminal "github.com/mdp/qrterminal/v3"
)

var usernameRE = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

var (
	setupMu          sync.Mutex
	setupActive      bool // true until the first admin has confirmed TOTP
	setupEverEntered bool // latched true once; never cleared in this process
	setupAdminDone   bool // the first admin exists; only enrolment is left
)

// enterSetupMode takes the stored setup token, or stores a new one, and
// prints the setup banner. The token lives in the database (see
// issueSetupToken) so that a restart keeps it and "webdavgo setup-info"
// shows the same one.
func enterSetupMode(webguiAddr, fingerprint string) {
	tok, exp, err := issueSetupToken()
	if err != nil {
		logger.Error("cannot issue setup token", "err", err)
		os.Exit(1)
	}

	setupMu.Lock()
	setupActive = true
	setupEverEntered = true
	setupMu.Unlock()

	printSetupBanner(webguiAddr, setupURLs(webguiAddr, tok), fingerprint, exp)
	logger.Info("setup mode entered", "expires", exp.Format(time.RFC3339))
}

// printSetupBanner writes the setup instructions to the console. The token
// is in the URLs only, never in a log line.
func printSetupBanner(webguiAddr string, urls []string, fingerprint string, exp time.Time) {
	fmt.Println("SETUP REQUIRED")
	fmt.Printf("The admin UI is %s.\n", adminReach(webguiAddr))
	fmt.Println("Open one of these URLs in a browser:")
	for _, u := range urls {
		fmt.Printf("  %s\n", u)
	}
	// The QR code is for a phone on the LAN, which cannot reach localhost.
	qrterminal.Generate(urls[0], qrterminal.L, os.Stdout)
	fmt.Printf("Admin certificate SHA-256 fingerprint: %s\n", fingerprint)
	fmt.Println("The browser will warn that the certificate is self-signed; continue only if it shows this fingerprint.")
	fmt.Printf("Token expires at %s\n", exp.Format(time.RFC3339))
}

// setupURLs returns the setup URL for every address the admin listener can
// be reached at: LAN addresses first (IPv4 before IPv6), localhost last.
// A listener bound to one address yields only that address.
func setupURLs(webguiAddr, token string) []string {
	return adminURLs(webguiAddr, "/setup?token="+token)
}

// adminURLs returns https URLs with path for every address the admin
// listener can be reached at, in the order of setupURLs.
func adminURLs(webguiAddr, path string) []string {
	host, port, err := net.SplitHostPort(webguiAddr)
	if err != nil {
		host, port = "", strings.TrimPrefix(webguiAddr, ":")
	}
	var hosts []string
	switch ip := net.ParseIP(host); {
	case host == "" || (ip != nil && ip.IsUnspecified()):
		for _, a := range lanAddrs() {
			hosts = append(hosts, a.String())
		}
		hosts = append(hosts, "localhost")
	default:
		hosts = []string{host}
	}
	urls := make([]string, len(hosts))
	for i, h := range hosts {
		urls[i] = fmt.Sprintf("https://%s%s", net.JoinHostPort(h, port), path)
	}
	return urls
}

// adminReach describes, for console output and the admin pages, where the
// admin listener at addr accepts connections. It names the bound address
// only: a firewall or router in front of the host is invisible from here,
// so it never claims that the port is private.
func adminReach(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "listening on " + addr
	}
	ip := net.ParseIP(host)
	switch {
	// Go binds an unspecified IPv4 or IPv6 address dual-stack on "tcp".
	case host == "" || (ip != nil && ip.IsUnspecified()):
		return fmt.Sprintf("listening on all interfaces (port %s) – reachable from any network that can reach port %s", port, port)
	case isLoopbackAddr(addr):
		return fmt.Sprintf("listening on %s only – reachable from this host only (use an SSH tunnel for remote access)", addr)
	default:
		return fmt.Sprintf("listening on %s only – reachable from any network that can reach that address", addr)
	}
}

func isSetupActive() bool {
	setupMu.Lock()
	defer setupMu.Unlock()
	return setupActive
}

func exitSetupMode() {
	setupMu.Lock()
	setupActive = false
	setupMu.Unlock()
	logger.Info("setup mode exited, server ready")
}

// setupAdminCreated reports whether setup has created the first admin and
// now only waits for that admin's TOTP enrolment.
func setupAdminCreated() bool {
	setupMu.Lock()
	defer setupMu.Unlock()
	return setupAdminDone
}

// validSetupToken checks tok against the stored token. It reads the
// database every time, because setup-info may have issued a new token
// after the old one expired.
func validSetupToken(tok string) bool {
	setupMu.Lock()
	pending := setupActive && !setupAdminDone
	setupMu.Unlock()
	if !pending || tok == "" {
		return false
	}
	stored, exp, _, err := readSetupToken()
	if err != nil {
		logger.Error("cannot check setup token", "err", err)
		return false
	}
	return stored != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(stored)) == 1 && time.Now().Before(exp)
}

// handleSetup serves GET and POST /setup.
// It is only called when setupEverEntered is true (see webgui routing in main).
func handleSetup(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	// The admin exists; a reload of the setup page must not offer to
	// create another one. Enrolment needs the session from the setup POST,
	// or a normal login.
	if setupAdminCreated() {
		http.Redirect(w, r, "/admin/enrol", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !validSetupToken(tok) {
			http.Error(w, "invalid or expired setup token", http.StatusForbidden)
			return
		}
		renderSetup(w, r, "", "")

	case http.MethodPost:
		// Re-read token from query string on POST too.
		if !validSetupToken(tok) {
			http.Error(w, "invalid or expired setup token", http.StatusForbidden)
			return
		}
		if err := processSetup(w, r); err != nil {
			// processSetup writes its own error response.
			return
		}
		// Setup is complete only once TOTP is confirmed (handleEnrolPOST),
		// so an admin without a second factor never exists after setup.
		id, _ := newSession(strings.TrimSpace(r.FormValue("username")), stageEnrol)
		http.SetCookie(w, sessionCookie(id))
		http.Redirect(w, r, "/admin/enrol", http.StatusSeeOther)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// processSetup validates form fields and creates the first admin user.
// Returns non-nil if it already wrote an error response.
func processSetup(w http.ResponseWriter, r *http.Request) error {
	uname := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	pwc := r.FormValue("password_confirm")

	if !usernameRE.MatchString(uname) {
		renderSetup(w, r, uname, "Username must be 3–32 characters: lowercase letters, digits, - or _")
		return fmt.Errorf("invalid username")
	}
	if len(pw) < 8 {
		renderSetup(w, r, uname, "Password must be at least 8 characters")
		return fmt.Errorf("short password")
	}
	if pw != pwc {
		renderSetup(w, r, uname, "Passwords do not match")
		return fmt.Errorf("password mismatch")
	}
	// Checked and set under the lock so that two concurrent setup POSTs
	// cannot both create an admin.
	setupMu.Lock()
	defer setupMu.Unlock()
	if setupAdminDone {
		http.Redirect(w, r, "/admin/enrol", http.StatusSeeOther)
		return fmt.Errorf("admin already created")
	}
	if err := createUser(uname, pw, "admin", conf().DefaultQuota); err != nil {
		renderSetup(w, r, uname, "Could not create user: "+err.Error())
		return err
	}
	setupAdminDone = true
	// The token has done its job; setup-info must not show it any more.
	if err := deleteSetupToken(); err != nil {
		logger.Error("cannot invalidate setup token", "err", err)
	}
	logger.Info("admin user created via setup wizard, totp enrolment pending", "username", uname)
	return nil
}

var setupTmpl = template.Must(template.New("setup").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>webdavgo – First-run Setup</title>
<link rel="stylesheet" href="/admin/static/style.css">
<script src="/admin/static/errors.js"></script>
</head>
<body>
<div class="setup-wrap">
  <h1>webdavgo – First-run Setup</h1>
  <p>Create the initial admin account. You can add more users from the admin UI afterwards.</p>
  <p>Next step: set up two-factor authentication (TOTP) for this account. Have an authenticator app ready.</p>
  {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
  <form method="post" action="/setup?token={{.Token}}" hx-boost="false">
    <label>Admin username
      <input type="text" name="username" value="{{.Username}}" required
             pattern="[a-z0-9_-]{3,32}" title="3–32 chars: lowercase letters, digits, - or _">
    </label>
    <label>Password
      <input type="password" name="password" required minlength="8">
    </label>
    <label>Confirm password
      <input type="password" name="password_confirm" required minlength="8">
    </label>
    <label>Data directory
      <input type="text" value="{{.DataDir}}" readonly disabled>
      <small>Set with data_dir in the config file or the -data-dir flag.</small>
    </label>
    <button type="submit">Create admin account</button>
  </form>
  <p class="warranty">This program comes with ABSOLUTELY NO WARRANTY.</p>
</div>
</body>
</html>`))

// runSetupInfo implements "webdavgo setup-info": it prints how to reach the
// admin UI and, while no admin exists, the setup URL with a valid token. It
// is meant for systemd installs, where the service's own banner only ends up
// in the journal. It opens the service's database (both may run at the same
// time; see issueSetupToken) and returns the process exit code.
func runSetupInfo(args []string) int {
	if len(args) != 0 {
		logger.Error("usage: webdavgo setup-info [-config file] [-data-dir dir]")
		return 2
	}
	if code, done := reexecAsServiceUser(); done {
		return code
	}
	dbPath := filepath.Join(conf().DataDir, "webdavgo.db")
	// sql.Open would create an empty database, and with it a token that no
	// running service knows about.
	if _, err := os.Stat(dbPath); err != nil {
		logger.Error("cannot open database; is the service running and -config the same as the service's?",
			"path", dbPath, "err", err)
		return 1
	}
	if err := openDBNoMigrate(dbPath); err != nil {
		logger.Error("cannot open database", "path", dbPath, "err", err)
		return 1
	}
	defer db.Close()

	webguiAddr := conf().webguiAddr()
	certPath := filepath.Join(conf().CertDir, adminCertFile)
	fp, err := certFileFingerprint(certPath)
	if err != nil {
		logger.Error("cannot read the admin certificate; the service creates it at its first start", "err", err)
		return 1
	}
	hasAdmin, err := adminExists()
	if err != nil {
		logger.Error("cannot query for admin user", "err", err)
		return 1
	}

	fmt.Printf("webdavgo admin UI (HTTPS only), %s:\n", adminReach(webguiAddr))
	for _, u := range adminURLs(webguiAddr, "/admin/") {
		fmt.Printf("  %s\n", u)
	}
	if hasAdmin {
		fmt.Printf("Admin certificate SHA-256 fingerprint: %s\n", fp)
		fmt.Println("Setup is complete: an admin account exists. Sign in at one of the URLs above.")
		return 0
	}
	tok, exp, err := issueSetupToken()
	if err != nil {
		logger.Error("cannot issue setup token", "err", err)
		return 1
	}
	fmt.Println()
	printSetupBanner(webguiAddr, setupURLs(webguiAddr, tok), fp, exp)
	return 0
}

func renderSetup(w http.ResponseWriter, r *http.Request, username, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setupTmpl.Execute(w, map[string]string{
		"Username": username,
		"Error":    errMsg,
		"DataDir":  conf().DataDir,
		"Token":    r.URL.Query().Get("token"),
	})
}
