// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// totp.go – mandatory second factor for admins: TOTP (RFC 6238) plus
// single-use recovery codes.
//
// A password alone only yields a pending session (see stageTOTP and
// stageEnrol in admin.go); the session becomes a full admin session once a
// valid code is entered, or, for an admin without TOTP, once enrolment is
// confirmed with a first code.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rsc.io/qr"
)

// RFC 6238 defaults; authenticator apps assume them when the otpauth URI
// carries nothing else, and several ignore other values silently.
const (
	totpDigits = 6
	totpPeriod = 30
	// One step either side tolerates clock drift and the time it takes to
	// type the code without widening the guessing window much.
	totpSkew = 1

	totpSecretBytes    = 20 // 160 bits, the HMAC-SHA1 block recommendation of RFC 4226
	recoveryCodeCount  = 10
	recoveryCodeBytes  = 10 // 80 bits each: no salt or slow hash is needed
	totpIssuer         = "webdavgo"
	secondFactorTOTP   = "totp"
	secondFactorRecov  = "recovery_code"
	errMsgInvalidCode  = "Invalid code"
	errMsgCodeRequired = "Enter the 6-digit code from your authenticator app"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var errTOTPAlreadyEnabled = errors.New("totp already enabled")

// ---- RFC 6238 ----------------------------------------------------------------

func newTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return b32.EncodeToString(b), nil
}

// totpCode computes the HOTP value (RFC 4226 section 5.3) for one time step.
func totpCode(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// totpMatch returns the time step whose code equals code, checking the
// current step and totpSkew steps either side.
func totpMatch(secret, code string, now time.Time) (int64, bool) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || !isTOTPCode(code) {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for step := cur - totpSkew; step <= cur+totpSkew; step++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(key, step)), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func isTOTPCode(s string) bool {
	if len(s) != totpDigits {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// normalizeCode strips what people type around a code: spaces and the
// dashes of recovery codes.
func normalizeCode(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(s))
}

// ---- storage -------------------------------------------------------------------

// totpEnabled reports whether username has confirmed a TOTP enrolment.
func totpEnabled(username string) (bool, error) {
	var enabled bool
	err := db.QueryRow(`SELECT enabled FROM totp WHERE username = ?`, username).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read totp state of %q: %w", username, err)
	}
	return enabled, nil
}

// verifyTOTP checks code against the stored secret and consumes its time
// step. A step that is not newer than the last accepted one is rejected:
// otherwise a code seen over someone's shoulder stays usable for up to
// 90 seconds.
func verifyTOTP(username, code string) (bool, error) {
	var secret string
	var lastStep int64
	err := db.QueryRow(`SELECT secret, last_step FROM totp WHERE username = ? AND enabled = 1`,
		username).Scan(&secret, &lastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read totp secret of %q: %w", username, err)
	}
	step, ok := totpMatch(secret, code, time.Now())
	if !ok {
		return false, nil
	}
	if step <= lastStep {
		logger.Warn("totp code replay rejected", "username", username, "step", step)
		return false, nil
	}
	// The condition makes the check-and-consume atomic: of two concurrent
	// logins with the same code only one updates the row.
	res, err := db.Exec(`UPDATE totp SET last_step = ? WHERE username = ? AND last_step < ?`,
		step, username, step)
	if err != nil {
		return false, fmt.Errorf("consume totp step of %q: %w", username, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("consume totp step of %q: %w", username, err)
	}
	return n == 1, nil
}

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// useRecoveryCode marks one unused recovery code of username as used and
// reports whether there was one; remaining is the number still unused.
func useRecoveryCode(username, code string) (ok bool, remaining int, err error) {
	res, err := db.Exec(`UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP
		WHERE username = ? AND code_hash = ? AND used_at IS NULL`, username, hashRecoveryCode(code))
	if err != nil {
		return false, 0, fmt.Errorf("use recovery code of %q: %w", username, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, 0, fmt.Errorf("use recovery code of %q: %w", username, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE username = ? AND used_at IS NULL`,
		username).Scan(&remaining); err != nil {
		return n == 1, 0, fmt.Errorf("count recovery codes of %q: %w", username, err)
	}
	return n == 1, remaining, nil
}

// checkSecondFactor accepts a TOTP code or a recovery code; kind names the
// one that was tried, for the log.
func checkSecondFactor(username, input string) (ok bool, kind string, err error) {
	code := normalizeCode(input)
	if isTOTPCode(code) {
		ok, err = verifyTOTP(username, code)
		return ok, secondFactorTOTP, err
	}
	ok, remaining, err := useRecoveryCode(username, code)
	if ok {
		logger.Info("recovery code used", "username", username, "remaining", remaining)
	}
	return ok, secondFactorRecov, err
}

// enableTOTP stores a confirmed enrolment and replaces all recovery codes.
// step is the time step of the confirming code, so that code cannot be
// replayed for the next login.
func enableTOTP(username, secret string, step int64) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		b := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		s := strings.ToLower(b32.EncodeToString(b))
		codes[i] = s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin totp enrolment: %w", err)
	}
	defer tx.Rollback()
	// Two pending enrolments of the same admin must not overwrite each
	// other's confirmed secret.
	res, err := tx.Exec(`INSERT INTO totp (username, secret, enabled, last_step) VALUES (?, ?, 1, ?)
		ON CONFLICT(username) DO UPDATE SET secret = excluded.secret, enabled = 1,
		last_step = excluded.last_step WHERE totp.enabled = 0`, username, secret, step)
	if err != nil {
		return nil, fmt.Errorf("store totp secret of %q: %w", username, err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return nil, fmt.Errorf("store totp secret of %q: %w", username, err)
	} else if n == 0 {
		return nil, errTOTPAlreadyEnabled
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE username = ?`, username); err != nil {
		return nil, fmt.Errorf("drop old recovery codes of %q: %w", username, err)
	}
	for _, c := range codes {
		if _, err := tx.Exec(`INSERT INTO recovery_codes (username, code_hash) VALUES (?, ?)`,
			username, hashRecoveryCode(c)); err != nil {
			return nil, fmt.Errorf("store recovery code of %q: %w", username, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit totp enrolment of %q: %w", username, err)
	}
	return codes, nil
}

// resetTOTP removes the TOTP secret and all recovery codes of username,
// which forces enrolment at the next login. It reports whether the user
// exists.
func resetTOTP(username string) (bool, error) {
	if !userExists(username) {
		return false, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin totp reset: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM totp WHERE username = ?`, username); err != nil {
		return false, fmt.Errorf("delete totp of %q: %w", username, err)
	}
	if _, err := tx.Exec(`DELETE FROM recovery_codes WHERE username = ?`, username); err != nil {
		return false, fmt.Errorf("delete recovery codes of %q: %w", username, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit totp reset of %q: %w", username, err)
	}
	return true, nil
}

// ---- enrolment page data ---------------------------------------------------------

// otpauthURI builds the key URI that authenticator apps import (Google
// Authenticator "Key Uri Format", the de-facto standard).
func otpauthURI(username, secret string) string {
	host := currentConfig().Domain
	if host == "" {
		host, _ = os.Hostname()
	}
	if host == "" {
		host = "localhost"
	}
	label := url.PathEscape(totpIssuer) + ":" + url.PathEscape(username+"@"+host)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// qrDataURL renders text as an inline PNG. Inline keeps the secret out of
// any URL that could end up in a log or the browser cache.
func qrDataURL(text string) (template.URL, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("encode qr code: %w", err)
	}
	c.Scale = 6
	// template.URL: html/template would otherwise replace the data: URL.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG())), nil
}

// groupSecret splits the Base32 secret into blocks of four for manual entry.
func groupSecret(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}

// ---- handlers --------------------------------------------------------------------

func handleTOTPGET(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, "totp", map[string]any{"Error": ""})
}

// handleTOTPPOST is the second login step for admins with TOTP enabled.
// Wrong codes count in the brute-force limiter exactly like wrong
// passwords: the password alone must not open an unlimited guessing window
// for six digits.
func handleTOTPPOST(w http.ResponseWriter, r *http.Request) {
	sc := currentSession(r)
	user := sc.s.username
	ip := clientKey(r)
	if locked, wait := limiter.ipLocked(ip); locked {
		logLoginThrottled(r, user, "second factor", "client", wait)
		renderThrottled(w, r, "totp", wait)
		return
	}
	if ok, wait := limiter.reserveAccountCheck(user); !ok {
		logLoginThrottled(r, user, "second factor", "account", wait)
		renderThrottled(w, r, "totp", wait)
		return
	}
	input := r.PostFormValue("code")
	if strings.TrimSpace(input) == "" {
		renderPage(w, r, "totp", map[string]any{"Error": errMsgCodeRequired})
		return
	}
	ok, kind, err := checkSecondFactor(user, input)
	if err != nil {
		serviceUnavailable(w, r, "second factor lookup failed", err)
		return
	}
	if !ok {
		stats.authFailed(r, failAdminSecond, user)
		limiter.fail(ip, user, authSrcAdmin)
		logger.Warn("login failed: second factor", "username", user, "client", remoteIP(r), "kind", kind)
		renderPage(w, r, "totp", map[string]any{"Error": errMsgInvalidCode})
		return
	}
	upgradeSession(w, sc)
	stats.adminLogin()
	logger.Info("login success", "username", user, "client", remoteIP(r), "second_factor", kind)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// enrolPageData returns the template data of the enrolment page. The secret
// lives in the pending session until it is confirmed, so an abandoned
// enrolment leaves nothing in the database.
func enrolPageData(r *http.Request, errMsg string) (map[string]any, error) {
	sc := currentSession(r)
	secret := sc.s.enrolSecret
	if secret == "" {
		var err error
		if secret, err = newTOTPSecret(); err != nil {
			return nil, err
		}
		setEnrolSecret(sc.id, secret)
	}
	uri := otpauthURI(sc.s.username, secret)
	img, err := qrDataURL(uri)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"Error":   errMsg,
		"QR":      img,
		"Secret":  groupSecret(secret),
		"URI":     uri,
		"InSetup": isSetupActive(),
	}, nil
}

func handleEnrolGET(w http.ResponseWriter, r *http.Request) {
	data, err := enrolPageData(r, "")
	if err != nil {
		logger.Error("cannot prepare totp enrolment", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	renderPage(w, r, "enrol", data)
}

func handleEnrolPOST(w http.ResponseWriter, r *http.Request) {
	sc := currentSession(r)
	user := sc.s.username
	code := normalizeCode(r.PostFormValue("code"))
	step, ok := totpMatch(sc.s.enrolSecret, code, time.Now())
	if sc.s.enrolSecret == "" || !ok {
		msg := errMsgInvalidCode
		if code == "" {
			msg = errMsgCodeRequired
		} else {
			// Not counted as a failed second factor: the admin is typing a
			// code from an app set up a moment ago, not guessing one.
			logger.Warn("login failed: totp enrolment code", "username", user, "client", remoteIP(r))
		}
		data, err := enrolPageData(r, msg)
		if err != nil {
			logger.Error("cannot prepare totp enrolment", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		renderPage(w, r, "enrol", data)
		return
	}
	codes, err := enableTOTP(user, sc.s.enrolSecret, step)
	if errors.Is(err, errTOTPAlreadyEnabled) {
		// Another session finished enrolment first; this one has to log in
		// with that secret instead.
		destroySession(sc.id)
		http.SetCookie(w, clearCookie())
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		logger.Error("totp enrolment failed", "username", user, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	full := upgradeSession(w, sc)
	logger.Info("totp enrolled", "username", user)
	// The first setup continues with the TLS & domain settings.
	next := "/admin/"
	inSetup := isSetupActive()
	if inSetup {
		exitSetupMode()
		next = "/admin/settings#tls"
	}
	stats.adminLogin()
	logger.Info("login success", "username", user, "client", remoteIP(r), "second_factor", "enrolment")
	// Shown in this response only: the database keeps nothing but hashes.
	renderPage(w, r, "recovery", map[string]any{
		"Codes":    codes,
		"Username": user,
		"CSRF":     full.csrf,
		"Next":     next,
		"InSetup":  inSetup,
	})
}

// ---- emergency command -----------------------------------------------------------

// runResetTOTP implements "webdavgo reset-totp <username>", the way back in
// for an admin who lost both the authenticator and the recovery codes. It
// works on the database directly: it needs shell access to the server,
// which is a stronger proof than anything the web UI could ask for, and no
// listener. It returns the process exit code.
func runResetTOTP(args []string) int {
	if len(args) != 1 {
		logger.Error("usage: webdavgo reset-totp [-config file] [-data-dir dir] <username>")
		return 2
	}
	username := args[0]
	if code, done := reexecAsServiceUser(); done {
		return code
	}
	dbPath := filepath.Join(conf().DataDir, "webdavgo.db")
	// sql.Open would silently create an empty database under a wrong
	// data_dir and report success for a user that is not there.
	if _, err := os.Stat(dbPath); err != nil {
		logger.Error("cannot open database", "path", dbPath, "err", err)
		return 1
	}
	if err := openDBNoMigrate(dbPath); err != nil {
		logger.Error("cannot open database", "path", dbPath, "err", err)
		return 1
	}
	defer db.Close()
	found, err := resetTOTP(username)
	if err != nil {
		logger.Error("totp reset failed", "username", username, "err", err)
		return 1
	}
	if !found {
		logger.Error("totp reset failed: no such user", "username", username)
		return 1
	}
	// Whoever forced the reset may also hold a session of this admin; the
	// running service ends it at its next request.
	if err := bumpSessionEpoch(username); err != nil {
		logger.Error("totp reset: cannot end running sessions", "username", username, "err", err)
		return 1
	}
	logger.Info("totp reset", "username", username, "by", "reset-totp command",
		"note", "enrolment is required at the next login; running sessions end")
	return 0
}
