// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- embedded assets -------------------------------------------------------

//go:embed assets
var assetsFS embed.FS

var tmpls *template.Template

func loadTemplates() {
	tmpls = template.Must(template.New("").ParseFS(assetsFS,
		"assets/layout.html",
		"assets/login.html",
		"assets/admin.html",
		"assets/users.html",
		"assets/settings.html",
		"assets/shares.html",
		"assets/status.html",
		"assets/totp.html",
		"assets/security.html",
		"assets/domain.html",
		"assets/connections.html",
		"assets/activity.html",
		"assets/logs.html",
		"assets/about.html",
	))
}

// renderPage executes a template. The session's username and CSRF token
// are filled in unless data already sets them, so no form can forget the
// token.
func renderPage(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if sc := currentSession(r); sc.id != "" {
		if _, ok := data["Username"]; !ok {
			data["Username"] = sc.s.username
		}
		if _, ok := data["CSRF"]; !ok {
			data["CSRF"] = sc.s.csrf
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpls.ExecuteTemplate(w, name, data); err != nil {
		logger.Error("template error", "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// ---- sessions --------------------------------------------------------------

// sessionStage separates a full admin session from one that has passed the
// password check only.
type sessionStage int

const (
	stageFull  sessionStage = iota
	stageTOTP               // TOTP enabled, code not yet entered
	stageEnrol              // no TOTP yet, enrolment must be completed
)

const (
	sessionTTL = 24 * time.Hour
	// A pending session is only good for typing a code. Keeping it short
	// limits what a stolen password plus a stolen cookie are worth.
	pendingSessionTTL = 5 * time.Minute
	sessionCookieName = "webdavgo_session"
)

type session struct {
	username    string
	stage       sessionStage
	csrf        string
	enrolSecret string // stageEnrol: the unconfirmed secret shown to the user
	expiresAt   time.Time
	// epoch is the user's session epoch at creation; a higher one in the
	// database (bumped by reset-totp) ends the session.
	epoch int64
}

var (
	sessionsMu sync.Mutex
	sessions   = make(map[string]session)
)

type ctxKey string

const ctxSession ctxKey = "session"

// sessionCtx is what requireSession puts into the request context.
type sessionCtx struct {
	id string
	s  session
}

func newSession(username string, stage sessionStage) (string, session) {
	b := make([]byte, 32)
	rand.Read(b)
	id := hex.EncodeToString(b)
	ttl := sessionTTL
	if stage != stageFull {
		ttl = pendingSessionTTL
	}
	epoch, err := sessionEpoch(username)
	if err != nil {
		// The session then fails the epoch check in requireSession and
		// the user signs in again; that is safer than guessing 0.
		logger.Error("cannot read session epoch", "user", username, "err", err)
		epoch = -1
	}
	s := session{username: username, stage: stage, csrf: newCSRFToken(), expiresAt: time.Now().Add(ttl), epoch: epoch}
	sessionsMu.Lock()
	sessions[id] = s
	sessionsMu.Unlock()
	logger.Debug("session created", "user", username, "stage", int(stage))
	return id, s
}

// lookupSession returns the session id names. slide extends a full
// session's expiry; polling requests pass false, so that a page left open
// does not keep its session alive forever.
func lookupSession(id string, slide bool) (session, bool) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[id]
	if !ok || time.Now().After(s.expiresAt) {
		delete(sessions, id)
		return session{}, false
	}
	// Sliding window for full sessions only: a pending one must not be kept
	// alive by reloading the code page.
	if slide && s.stage == stageFull {
		s.expiresAt = time.Now().Add(sessionTTL)
		sessions[id] = s
	}
	return s, true
}

func setEnrolSecret(id, secret string) {
	sessionsMu.Lock()
	if s, ok := sessions[id]; ok {
		s.enrolSecret = secret
		sessions[id] = s
	}
	sessionsMu.Unlock()
}

func destroySession(id string) {
	sessionsMu.Lock()
	delete(sessions, id)
	sessionsMu.Unlock()
	logger.Debug("session destroyed")
}

// destroyUserSessions ends every session of username, pending or full, and
// returns how many there were.
func destroyUserSessions(username string) int {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	n := 0
	for id, s := range sessions {
		if s.username == username {
			delete(sessions, id)
			n++
		}
	}
	return n
}

// upgradeSession replaces a pending session by a full one under a new ID,
// so that an ID known before the second factor is worthless afterwards.
func upgradeSession(w http.ResponseWriter, sc sessionCtx) session {
	destroySession(sc.id)
	id, s := newSession(sc.s.username, stageFull)
	http.SetCookie(w, sessionCookie(id))
	return s
}

func activeSessionCount() int {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	count := 0
	now := time.Now()
	for id, s := range sessions {
		if now.After(s.expiresAt) {
			delete(sessions, id)
		} else if s.stage == stageFull {
			count++
		}
	}
	return count
}

// sessionCookie is Secure because the admin listener is TLS-only, and
// SameSite=Strict because no legitimate admin flow starts on another site.
func sessionCookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/admin",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func clearCookie() *http.Cookie {
	c := sessionCookie("")
	c.MaxAge = -1
	return c
}

// ---- auth middleware -------------------------------------------------------

// pendingPath is the only page (besides logout) a session in stage may
// open.
func pendingPath(stage sessionStage) string {
	switch stage {
	case stageTOTP:
		return "/admin/totp"
	case stageEnrol:
		return "/admin/enrol"
	}
	return ""
}

// pollPaths are the fragments the Status and Live Log pages fetch every few
// seconds. They do not extend the session (see lookupSession).
var pollPaths = map[string]bool{
	"/admin/dashboard/webdav":   true, // the Dashboard's WebDAV block
	"/admin/status/connections": true,
	"/admin/status/activity":    true,
	"/admin/logs/entries":       true,
}

func isPoll(r *http.Request) bool {
	return r.Method == http.MethodGet && pollPaths[r.URL.Path]
}

// sessionRedirect sends the browser to target. An htmx poll gets
// HX-Redirect and no body instead: a 303 would be followed by the XHR and
// the login page swapped into the polling card.
func sessionRedirect(w http.ResponseWriter, r *http.Request, target string) {
	if isPoll(r) && r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			sessionRedirect(w, r, "/admin/login")
			return
		}
		sess, ok := lookupSession(cookie.Value, !isPoll(r))
		if !ok {
			http.SetCookie(w, clearCookie())
			sessionRedirect(w, r, "/admin/login")
			return
		}
		// Checked on every request rather than only at login: a deleted or
		// demoted admin must lose access at once, not when the session
		// expires.
		role, err := userRole(sess.username)
		if err != nil {
			serviceUnavailable(w, r, "admin session check failed", err)
			return
		}
		if role != "admin" {
			n := destroyUserSessions(sess.username)
			logger.Warn("admin session ended: user no longer exists or is no admin",
				"username", sess.username, "sessions_ended", n)
			http.SetCookie(w, clearCookie())
			sessionRedirect(w, r, "/admin/login")
			return
		}
		// reset-totp runs in another process and cannot reach this
		// session table; it bumps the epoch in the database instead.
		epoch, err := sessionEpoch(sess.username)
		if err != nil {
			serviceUnavailable(w, r, "admin session check failed", err)
			return
		}
		if sess.epoch < epoch {
			n := destroyUserSessions(sess.username)
			logger.Warn("admin session ended: sessions were revoked outside this process",
				"username", sess.username, "sessions_ended", n)
			http.SetCookie(w, clearCookie())
			sessionRedirect(w, r, "/admin/login")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if ok, reason := validCSRF(r, sess.csrf); !ok {
				logger.Warn("admin request rejected: missing or wrong CSRF token",
					"username", sess.username, "method", r.Method, "path", r.URL.Path, "reason", reason)
				http.Error(w, "forbidden: missing or invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		switch p := pendingPath(sess.stage); {
		case p != "" && r.URL.Path != p && r.URL.Path != "/admin/logout":
			sessionRedirect(w, r, p)
			return
		case p == "" && (r.URL.Path == "/admin/totp" || r.URL.Path == "/admin/enrol"):
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
			return
		}
		if sess.stage == stageFull {
			noteIdentity(r, sess.username)
		} else {
			noteIdentity(r, sess.username+" (second factor pending)")
		}
		ctx := context.WithValue(r.Context(), ctxSession, sessionCtx{id: cookie.Value, s: sess})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentSession(r *http.Request) sessionCtx {
	v, _ := r.Context().Value(ctxSession).(sessionCtx)
	return v
}

func currentUser(r *http.Request) string {
	return currentSession(r).s.username
}

// ---- admin mux -------------------------------------------------------------

// NewAdminMux builds the ServeMux for all /admin/* routes.
// Only the login page is reachable without a session; everything else,
// including the second-factor pages, is wrapped with requireSession.
func NewAdminMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/login", handleLoginGET)
	mux.HandleFunc("POST /admin/login", handleLoginPOST)

	protected := http.NewServeMux()
	protected.HandleFunc("POST /admin/logout", handleLogout)
	protected.HandleFunc("GET /admin/totp", handleTOTPGET)
	protected.HandleFunc("POST /admin/totp", handleTOTPPOST)
	protected.HandleFunc("GET /admin/enrol", handleEnrolGET)
	protected.HandleFunc("POST /admin/enrol", handleEnrolPOST)
	protected.HandleFunc("GET /admin/security", handleSecurity)
	protected.HandleFunc("POST /admin/security/unlock-client", handleUnlockClient)
	protected.HandleFunc("POST /admin/security/clear-account", handleClearAccount)
	protected.HandleFunc("POST /admin/users/{name}/totp-reset", handleUserTOTPReset)
	protected.HandleFunc("GET /admin/", handleDashboard)
	protected.HandleFunc("GET /admin/dashboard/webdav", handleDashboardWebDAV)
	protected.HandleFunc("GET /admin/users", handleUsersGET)
	protected.HandleFunc("POST /admin/users", handleUsersCreate)
	protected.HandleFunc("POST /admin/users/{name}/delete", handleUserDelete)
	protected.HandleFunc("POST /admin/users/{name}/reset", handleUserReset)
	protected.HandleFunc("POST /admin/users/{name}/quota", handleUserQuota)
	protected.HandleFunc("GET /admin/shares", handleShares)
	protected.HandleFunc("POST /admin/shares/{share_id}/revoke", handleShareRevoke)
	protected.HandleFunc("GET /admin/status", handleStatus)
	protected.HandleFunc("GET /admin/status/connections", handleConnections)
	protected.HandleFunc("GET /admin/status/activity", handleActivity)
	protected.HandleFunc("GET /admin/logs", handleLogs)
	protected.HandleFunc("GET /admin/logs/entries", handleLogEntries)
	protected.HandleFunc("GET /admin/settings", handleSettingsGET)
	protected.HandleFunc("POST /admin/settings/{section}", handleSettingsPOST)
	protected.HandleFunc("POST /admin/settings/{section}/reset", handleSettingsReset)
	protected.HandleFunc("GET /admin/domain", handleDomainGET)
	protected.HandleFunc("GET /admin/domain/progress", handleDomainProgress)
	protected.HandleFunc("GET /admin/domain/done", handleDomainDone)
	protected.HandleFunc("GET /admin/about", handleAbout)

	mux.Handle("/admin/", requireSession(protected))
	return mux
}

// ---- page data helpers -----------------------------------------------------

type pageBase struct {
	Page     string
	Username string
}

// ---- login handlers --------------------------------------------------------

func handleLoginGET(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "login", map[string]any{"Error": ""})
}

func handleLoginPOST(w http.ResponseWriter, r *http.Request) {
	uname := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")

	ip := clientKey(r)
	if locked, wait := limiter.ipLocked(ip); locked {
		logLoginThrottled(r, uname, "password", "client", wait)
		renderThrottled(w, r, "login", wait)
		return
	}
	if ok, wait := limiter.reserveAccountCheck(uname); !ok {
		logLoginThrottled(r, uname, "password", "account", wait)
		renderThrottled(w, r, "login", wait)
		return
	}

	valid, err := checkPassword(uname, pw)
	if err != nil {
		logger.Error("admin login lookup failed", "username", uname, "client", remoteIP(r), "err", err)
	}
	if !valid || !isAdmin(uname) {
		// A DB failure says nothing about the password, so it does not count.
		if err == nil {
			stats.authFailed(r, failAdminPassword, uname)
			limiter.fail(ip, uname, authSrcAdmin)
		}
		logger.Warn("login failed", "username", uname, "client", remoteIP(r))
		renderPage(w, r, "login", map[string]any{"Error": "Invalid username or password"})
		return
	}
	enabled, err := totpEnabled(uname)
	if err != nil {
		serviceUnavailable(w, r, "admin login lookup failed", err)
		return
	}
	stage := stageEnrol
	if enabled {
		stage = stageTOTP
	}
	id, _ := newSession(uname, stage)
	http.SetCookie(w, sessionCookie(id))
	logger.Info("login password accepted, second factor pending", "username", uname,
		"client", remoteIP(r), "totp_enrolled", enabled)
	http.Redirect(w, r, pendingPath(stage), http.StatusSeeOther)
}

// logLoginThrottled logs an admin login step refused by the brute-force
// limiter; scope says whether the client or the account is throttled. Every
// caller answers 429, so it also counts the refusal.
func logLoginThrottled(r *http.Request, username, step, scope string, wait time.Duration) {
	logger.Warn("login refused: throttled", "username", username, "client", remoteIP(r),
		"step", step, "scope", scope, "retry_after", wait.Round(time.Second).String())
	countRefusal(r, username, scope)
}

// renderThrottled renders page (login or totp) with 429 while the client or
// the account is throttled; no credential is checked.
func renderThrottled(w http.ResponseWriter, r *http.Request, page string, wait time.Duration) {
	minutes := int((wait + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	unit := "minutes"
	if minutes == 1 {
		unit = "minute"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
	w.WriteHeader(http.StatusTooManyRequests)
	renderPage(w, r, page, map[string]any{
		"Error": fmt.Sprintf("Too many failed login attempts. Try again in %d %s.", minutes, unit),
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	destroySession(currentSession(r).id)
	http.SetCookie(w, clearCookie())
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// ---- dashboard -------------------------------------------------------------

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"Page": "dashboard", "WebDAV": stats.webdavView(time.Now())}
	if used, err := totalUsedBytes(); err != nil {
		logger.Error("cannot sum storage usage", "err", err)
	} else {
		data["TotalUsed"] = formatGB(used)
	}
	if fsTotal, fsFree, err := fsSpace(conf().DataDir); err != nil {
		logger.Warn("cannot read filesystem size", "path", conf().DataDir, "err", err)
	} else {
		data["FSTotal"] = formatGB(int64(min(fsTotal, math.MaxInt64)))
		data["FSFree"] = formatGB(int64(min(fsFree, math.MaxInt64)))
	}
	renderPage(w, r, "dashboard", data)
}

// handleDashboardWebDAV renders the Dashboard's WebDAV block alone; the
// Dashboard polls it while it is open.
func handleDashboardWebDAV(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "dashboard-webdav", map[string]any{"WebDAV": stats.webdavView(time.Now())})
}

// ---- users -----------------------------------------------------------------

func handleUsersGET(w http.ResponseWriter, r *http.Request) {
	renderUsers(w, r, http.StatusOK, "")
}

// usersPerPage is the page size of the Users list.
const usersPerPage = 25

// usersListState returns the search and page of the Users list as the
// request carries them (?q=&page=). Row actions post to URLs that keep
// them, so the admin returns to the same view.
func usersListState(r *http.Request) (q string, page int) {
	q = strings.TrimSpace(r.URL.Query().Get("q"))
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	return q, max(page, 1)
}

// usersQuery returns "?q=…&page=…" for a search and page, "" for the
// unfiltered first page.
func usersQuery(q string, page int) string {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// usersReturnURL is the Users list as the request's action left it.
func usersReturnURL(r *http.Request) string {
	q, page := usersListState(r)
	return "/admin/users" + usersQuery(q, page)
}

func renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	q, page := usersListState(r)
	users, total, err := listUsersPage(q, (page-1)*usersPerPage, usersPerPage)
	pages := max((total+usersPerPage-1)/usersPerPage, 1)
	// A page past the end, e.g. after deleting its last user, shows the
	// last page instead of an empty one.
	if err == nil && page > pages {
		page = pages
		users, total, err = listUsersPage(q, (page-1)*usersPerPage, usersPerPage)
	}
	if err != nil {
		logger.Error("cannot list users", "err", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	data := map[string]any{
		"Page":  "users",
		"Users": users,
		// The Add user form starts with the configured default quota.
		"DefaultQuotaGB": formValue(conf(), "default_quota"),
		"Error":          errMsg,
		"Q":              q,
		"PageNo":         page,
		"Pages":          pages,
		"Matching":       total,
		// template.URL: the query is built and escaped here; as plain text
		// html/template would escape "?" and "=" in a URL path position.
		"Return":  template.URL(usersQuery(q, page)),
		"PrevURL": template.URL("/admin/users" + usersQuery(q, page-1)),
		"NextURL": template.URL("/admin/users" + usersQuery(q, page+1)),
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
	}
	renderPage(w, r, "users", data)
}

// maxQuotaGB bounds the quota field so the byte count cannot overflow.
const maxQuotaGB = 1_000_000

// parseQuotaGB parses the quota field: decimal gigabytes (1 GB = 10^9
// bytes), 0 for unlimited. A comma is accepted as decimal separator, as
// typed on German keyboards.
func parseQuotaGB(s string) (int64, error) {
	gb, err := strconv.ParseFloat(strings.ReplaceAll(strings.TrimSpace(s), ",", "."), 64)
	if err != nil || math.IsNaN(gb) || gb < 0 || gb > maxQuotaGB {
		return 0, fmt.Errorf("invalid quota %q", s)
	}
	return int64(math.Round(gb * 1e9)), nil
}

const quotaFieldError = "Quota must be a number of GB between 0 (unlimited) and 1000000"

func handleUsersCreate(w http.ResponseWriter, r *http.Request) {
	uname := strings.TrimSpace(r.FormValue("username"))
	pw := r.FormValue("password")
	role := r.FormValue("role")
	if role != "admin" && role != "user" {
		role = "user"
	}
	quota := conf().DefaultQuota
	var quotaErr error
	if s := r.FormValue("quota_gb"); s != "" {
		quota, quotaErr = parseQuotaGB(s)
	}

	var errMsg string
	if !usernameRE.MatchString(uname) {
		errMsg = "Username must be 3–32 chars: lowercase letters, digits, - or _"
	} else if len(pw) < 8 {
		errMsg = "Password must be at least 8 characters"
	} else if quotaErr != nil {
		errMsg = quotaFieldError
	} else if userExists(uname) {
		errMsg = fmt.Sprintf("User %q already exists", uname)
	}

	if errMsg != "" {
		renderUsers(w, r, http.StatusOK, errMsg)
		return
	}

	if err := createUser(uname, pw, role, quota); err != nil {
		http.Error(w, "could not create user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Info("user created", "username", uname, "role", role, "quota_bytes", quota, "by", currentUser(r))
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func handleUserQuota(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !userExists(name) {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}
	quota, err := parseQuotaGB(r.FormValue("quota_gb"))
	if err != nil {
		renderUsers(w, r, http.StatusBadRequest, quotaFieldError)
		return
	}
	if err := setUserQuota(name, quota); err != nil {
		logger.Error("quota change failed", "username", name, "err", err)
		http.Error(w, "could not change quota", http.StatusInternalServerError)
		return
	}
	logger.Info("user quota changed", "username", name, "quota_bytes", quota, "by", currentUser(r))
	http.Redirect(w, r, usersReturnURL(r), http.StatusSeeOther)
}

func handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	self := currentUser(r)

	if name == self {
		http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
		return
	}
	n, err := adminCount()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if n <= 1 && isAdmin(name) {
		http.Error(w, "cannot delete the last admin account", http.StatusBadRequest)
		return
	}
	if err := deleteUser(name); err != nil {
		http.Error(w, "could not delete user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Info("user deleted", "username", name, "by", self, "sessions_ended", destroyUserSessions(name))
	http.Redirect(w, r, usersReturnURL(r), http.StatusSeeOther)
}

func handleUserReset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	pw := r.FormValue("new_password")
	if len(pw) < 8 {
		http.Error(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	if err := resetPassword(name, pw); err != nil {
		http.Error(w, "could not reset password: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logger.Info("password reset", "username", name, "by", currentUser(r),
		"sessions_ended", destroyUserSessions(name), "client", remoteIP(r))
	http.Redirect(w, r, usersReturnURL(r), http.StatusSeeOther)
}

// handleUserTOTPReset forces another admin to enrol again at the next
// login. Resetting one's own TOTP needs a current code: a hijacked session
// alone must not be enough to replace the second factor.
func handleUserTOTPReset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	self := currentUser(r)
	if !isAdmin(name) {
		http.Error(w, "TOTP applies to admin accounts only", http.StatusBadRequest)
		return
	}
	if name == self {
		ip := clientKey(r)
		if locked, wait := limiter.ipLocked(ip); locked {
			logLoginThrottled(r, self, "own totp reset", "client", wait)
			tooManyAttempts(w, wait)
			return
		}
		// The code check is a guess like a login: a hijacked session from
		// many addresses must hit the account throttle, too.
		if ok, wait := limiter.reserveAccountCheck(self); !ok {
			logLoginThrottled(r, self, "own totp reset", "account", wait)
			tooManyAttempts(w, wait)
			return
		}
		ok, err := verifyTOTP(self, normalizeCode(r.PostFormValue("code")))
		if err != nil {
			serviceUnavailable(w, r, "totp lookup failed", err)
			return
		}
		if !ok {
			stats.authFailed(r, failAdminSecond, self)
			limiter.fail(ip, self, authSrcAdmin)
			logger.Warn("own totp reset refused: invalid code", "username", self, "client", remoteIP(r))
			renderUsers(w, r, http.StatusForbidden, "Resetting your own TOTP needs a valid current code.")
			return
		}
	}
	if _, err := resetTOTP(name); err != nil {
		logger.Error("totp reset failed", "username", name, "err", err)
		http.Error(w, "could not reset TOTP", http.StatusInternalServerError)
		return
	}
	logger.Info("totp reset", "username", name, "by", self, "sessions_ended", destroyUserSessions(name))
	http.Redirect(w, r, usersReturnURL(r), http.StatusSeeOther)
}

func isAdmin(username string) bool {
	role, _ := userRole(username)
	return role == "admin"
}

// ---- shares ----------------------------------------------------------------

func handleShares(w http.ResponseWriter, r *http.Request) {
	shares, err := listAllShares()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	renderPage(w, r, "shares", map[string]any{
		"Page":   "shares",
		"Shares": shares,
	})
}

func handleShareRevoke(w http.ResponseWriter, r *http.Request) {
	shareID := r.PathValue("share_id")
	deleted, err := deleteShareAdmin(shareID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if deleted {
		logger.Info("share revoked by admin", "share_id", shareID, "by", currentUser(r))
	}
	http.Redirect(w, r, "/admin/shares", http.StatusSeeOther)
}

// ---- status ----------------------------------------------------------------

func handleStatus(w http.ResponseWriter, r *http.Request) {
	disk := dirSize(conf().DataDir)
	dbSize := fileSize(filepath.Join(conf().DataDir, "webdavgo.db"))
	shareCount, _ := countShares()
	data := map[string]any{
		"Page":           "status",
		"DiskSize":       formatBytes(disk),
		"DBSize":         formatBytes(dbSize),
		"ActiveSessions": activeSessionCount(),
		"ActiveShares":   shareCount,
		"Conns":          running.conns.snapshot(time.Now()),
		"Activity":       stats.view(time.Now()),
	}
	renderPage(w, r, "status", data)
}

// handleConnections renders the connections card alone; the Status page
// polls it while it is open.
func handleConnections(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "connections", map[string]any{"Conns": running.conns.snapshot(time.Now())})
}

// handleActivity renders the activity card alone; the Status page polls it
// while it is open.
func handleActivity(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "activity", map[string]any{"Activity": stats.view(time.Now())})
}

// ---- logs --------------------------------------------------------------------

// logPageMaxRows caps the rows of the Live Log page: re-rendering a full buffer
// every 2 s with auto-refresh is heavy for the browser.
const logPageMaxRows = 500

// logDestination names where a log key sends its records; access_log and
// server_log take effect only at startup, so the running value is the one in
// use.
func logDestination(path string) string {
	if path == "" {
		return "stdout"
	}
	return path
}

// logPageData reads the filter from the query string: level is the minimum
// level (default debug, i.e. everything kept), q a case-insensitive text,
// auto=1 turns on polling.
func logPageData(r *http.Request) map[string]any {
	q := r.URL.Query()
	levelName := q.Get("level")
	level, err := parseLogLevel(levelName)
	if err != nil {
		levelName, level = "debug", slog.LevelDebug
	}
	text := strings.TrimSpace(q.Get("q"))
	auto := q.Get("auto") == "1"
	entries, total, capacity := logRing.query(level, text)
	matching := len(entries)
	if len(entries) > logPageMaxRows {
		entries = entries[:logPageMaxRows]
	}
	type row struct {
		Time, Level, Class, Msg, Attrs string
	}
	rows := make([]row, len(entries))
	for i, e := range entries {
		rows[i] = row{
			Time:  e.Time.UTC().Format("2006-01-02 15:04:05.000"),
			Level: e.Level.String(),
			Class: "lvl-" + strings.ToLower(e.Level.String()),
			Msg:   e.Msg,
			Attrs: e.Attrs,
		}
	}
	filter := url.Values{"level": {levelName}, "q": {text}}
	if auto {
		filter.Set("auto", "1")
	}
	return map[string]any{
		"Page":      "logs",
		"AccessLog": logDestination(conf().AccessLog),
		"ServerLog": logDestination(conf().ServerLog),
		"Level":     levelName,
		"Q":         text,
		"Auto":      auto,
		"Filter":    filter.Encode(),
		"Entries":   rows,
		"Matching":  matching,
		"Total":     total,
		"Capacity":  capacity,
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "logs", logPageData(r))
}

func handleLogEntries(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "log-entries", logPageData(r))
}

// handleAbout shows the copyright and license notice that AGPL-3.0 section
// 0 ("Appropriate Legal Notices") asks an interactive user interface to show.
func handleAbout(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "about", map[string]any{"Page": "about"})
}

// certStatusData prepares the certificate status for the status and the
// finish page.
func certStatusData(s tlsStatus) map[string]any {
	data := map[string]any{
		"Domain":       s.Domain,
		"Issuer":       s.Issuer,
		"NotAfter":     formatStatusTime(s.NotAfter),
		"NextRenewal":  formatStatusTime(s.NextRenewal),
		"RenewalByARI": s.RenewalByARI,
		"ARIStart":     formatStatusTime(s.ARIStart),
		"ARIEnd":       formatStatusTime(s.ARIEnd),
		"LastSuccess":  formatStatusTime(s.LastSuccess),
		"LastError":    s.LastError,
		"LastErrorAt":  formatStatusTime(s.LastErrorAt),
		"LifetimeLow":  s.lifetimeLow(time.Now()),
	}
	if !s.NotAfter.IsZero() {
		data["DaysLeft"] = int(time.Until(s.NotAfter).Hours() / 24)
	}
	return data
}

// ---- security (brute-force overview) -----------------------------------------

func handleSecurity(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	type clientRow struct {
		Client, LockedUntil, Remaining, LastSeen, Sources string
		Failures, Total, Lockouts                         int
		Locked                                            bool
	}
	type accountRow struct {
		Username, NextCheck, Remaining, LastSeen, Sources string
		Failures, Total                                   int
	}
	var clients []clientRow
	for _, c := range limiter.clientStates(now) {
		clients = append(clients, clientRow{
			Client:      c.Client,
			Locked:      now.Before(c.LockedUntil),
			LockedUntil: formatStatusTime(c.LockedUntil),
			Remaining:   formatRemaining(c.LockedUntil.Sub(now)),
			LastSeen:    formatStatusTime(c.LastSeen),
			Sources:     c.Sources.String(),
			Failures:    c.Failures,
			Total:       c.Sources.total(),
			Lockouts:    c.Lockouts,
		})
	}
	var accounts []accountRow
	for _, a := range limiter.throttledAccounts(now) {
		next := "now"
		if a.NextCheck.After(now) {
			next = formatStatusTime(a.NextCheck)
		}
		accounts = append(accounts, accountRow{
			Username:  a.Username,
			NextCheck: next,
			Remaining: formatRemaining(a.ThrottledUntil.Sub(now)),
			LastSeen:  formatStatusTime(a.LastSeen),
			Sources:   a.Sources.String(),
			Failures:  a.Failures,
			Total:     a.Sources.total(),
		})
	}
	limitedRows, notTracked := rateLimitedRows(now)
	renderPage(w, r, "security", map[string]any{
		"Page":        "security",
		"Clients":     clients,
		"Accounts":    accounts,
		"Window":      conf().BruteforceWindow.String(),
		"Limited":     limitedRows,
		"NotTracked":  notTracked,
		"PerIPLimit":  conf().MaxConnectionsPerIP,
		"UnauthRate":  conf().UnauthRate,
		"UnauthBurst": conf().UnauthBurst,
	})
}

// rateLimitedRow is one client of the "Rate-limited clients" table.
type rateLimitedRow struct {
	Client, Kind, Listener               string
	FirstRefusal, LastRefusal, Remaining string
	Refused                              int64
	Active                               bool
	last                                 time.Time
}

// rateLimitedRows merges the refusals of the two self-clearing limits with
// the clients they hold back now without having refused them yet (all
// connections taken, bucket empty), most recent refusal first.
func rateLimitedRows(now time.Time) ([]rateLimitedRow, int64) {
	states, lost := limited.states(now)
	atLimit := map[limitKey]bool{}
	for l := range numStatListeners {
		for _, k := range connLimits[l].atLimit() {
			atLimit[limitKey{k, limitConns, l}] = true
		}
	}
	empty := unauthLimiter.empty(now)

	var rows []rateLimitedRow
	listed := map[limitKey]bool{}
	for _, s := range states {
		k := s.limitKey
		listed[k] = true
		activeUntil := s.last.Add(limitActiveFor)
		active := now.Before(activeUntil)
		var remaining time.Duration
		switch k.kind {
		case limitConns:
			if atLimit[k] {
				// Ends when one of the connections closes, not at a time.
				active, activeUntil = true, time.Time{}
			}
		case limitUnauth:
			if wait, ok := empty[k.client]; ok {
				active = true
				activeUntil = maxTime(activeUntil, now.Add(wait))
			}
		}
		if !activeUntil.IsZero() {
			remaining = activeUntil.Sub(now)
		}
		rows = append(rows, rateLimitedRow{
			Client:       k.client,
			Kind:         limitKindNames[k.kind],
			Listener:     statListenerNames[k.listener],
			FirstRefusal: formatStatusTime(s.first),
			LastRefusal:  formatStatusTime(s.last),
			Remaining:    formatRemaining(remaining),
			Refused:      s.refused,
			Active:       active,
			last:         s.last,
		})
	}
	for k := range atLimit {
		if !listed[k] {
			rows = append(rows, rateLimitedRow{Client: k.client, Kind: limitKindNames[limitConns],
				Listener: statListenerNames[k.listener], Active: true, last: now})
		}
	}
	for client, wait := range empty {
		if k := (limitKey{client, limitUnauth, statWebDAV}); !listed[k] {
			rows = append(rows, rateLimitedRow{Client: client, Kind: limitKindNames[limitUnauth],
				Listener: statListenerNames[statWebDAV], Active: true, Remaining: formatRemaining(wait), last: now})
		}
	}
	// Rows held back now without a refusal sort as of now.
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].last.Equal(rows[j].last) {
			return rows[i].last.After(rows[j].last)
		}
		return rows[i].Client < rows[j].Client
	})
	return rows, lost
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func handleUnlockClient(w http.ResponseWriter, r *http.Request) {
	client := r.PostFormValue("client")
	if limiter.unlockClient(client) {
		logger.Info("brute-force client unlocked manually", "client", client, "by", currentUser(r))
	}
	http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
}

func handleClearAccount(w http.ResponseWriter, r *http.Request) {
	username := r.PostFormValue("username")
	if limiter.clearAccount(username) {
		logger.Info("brute-force account throttle cleared manually", "username", username, "by", currentUser(r))
	}
	http.Redirect(w, r, "/admin/security", http.StatusSeeOther)
}

// formatRemaining renders the rest of a lockout or throttle in whole
// seconds.
func formatRemaining(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.Round(time.Second).String()
}

// formatStatusTime renders t for the status page; the zero time means the
// event has not happened since the process started.
func formatStatusTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func dirSize(root string) int64 {
	var total int64
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
