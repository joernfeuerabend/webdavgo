// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/mail"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// The settings table holds runtime data only (setup token, session epochs).

func getSetting(key string) (string, error) {
	var value string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

// storedSetting is getSetting with a missing key as ok=false, not an error.
func storedSetting(key string) (string, bool, error) {
	v, err := getSetting(key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// ---- migration of stored configuration ------------------------------------------

// storedConfigKeys are the configuration values older versions kept in the
// settings table: the Settings page's listener addresses and what the
// Domain & certificate page configured.
var storedConfigKeys = []string{"webdav_addr", "webgui_addr", "tls_mode", "domain", "acme_email", "acme_ca"}

const (
	// oldDefaultWebGUIAddr was the default while the admin UI spoke plain
	// HTTP; adminAddrMovedKey marked a database whose webgui_addr had been
	// moved off it. A database without the mark still holds the old default
	// and gets the new one, as it would have from the older version.
	oldDefaultWebGUIAddr = ":8081"
	adminAddrMovedKey    = "webgui_addr_moved_to_tls_default"
)

// migrateStoredSettings moves the configuration values still in the
// settings table into the config file at path, once; afterwards the table
// holds runtime data only. A key the file already sets wins. A stored value
// equal to the default gets no line, because an unset key means the same;
// older versions stored the default addresses in every database. The rows
// are deleted only once the file is written, so a failed write loses
// nothing and is retried at the next start. It reports whether the file
// changed.
func migrateStoredSettings(path string) (bool, error) {
	stored := map[string]string{}
	for _, k := range append(slices.Clone(storedConfigKeys), adminAddrMovedKey) {
		v, ok, err := storedSetting(k)
		if err != nil {
			return false, fmt.Errorf("read stored %s: %w", k, err)
		}
		if ok {
			stored[k] = v
		}
	}
	if len(stored) == 0 {
		return false, nil
	}
	def := defaultConfig()
	if _, moved := stored[adminAddrMovedKey]; !moved && stored["webgui_addr"] == oldDefaultWebGUIAddr {
		stored["webgui_addr"] = def.webguiAddr()
		logger.Info("stored webgui_addr is the old plaintext default; migrated as the new default (TLS only)",
			"old", oldDefaultWebGUIAddr, "new", def.webguiAddr())
	}

	inFile := map[string]any{}
	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, &inFile); err != nil {
			return false, fmt.Errorf("read config %s: %w", path, err)
		}
	}
	defaults := map[string]string{"webdav_addr": def.webdavAddr(), "webgui_addr": def.webguiAddr(),
		"tls_mode": def.TLSMode, "domain": def.Domain, "acme_email": def.ACMEEmail, "acme_ca": def.ACMECA}
	// The stored addresses are [host]:port; the file has a listen address
	// and a port for each.
	fileKeys := map[string][]string{}
	for _, k := range oldAddrKeys {
		fileKeys[k[0]] = []string{k[1], k[2]}
	}
	kv := map[string]any{}
	for _, k := range storedConfigKeys {
		v, ok := stored[k]
		keys := fileKeys[k]
		if keys == nil {
			keys = []string{k}
		}
		switch {
		case !ok:
		case slices.ContainsFunc(keys, func(fk string) bool { return inFile[fk] != nil }):
			logger.Info("stored setting dropped: the config file sets it", "key", k, "stored", v, "path", path)
		case v == defaults[k]:
			logger.Info("stored setting dropped: it is the default", "key", k, "stored", v)
		case len(keys) == 2:
			host, portStr, err := net.SplitHostPort(v)
			port, perr := strconv.Atoi(portStr)
			if err != nil || perr != nil {
				logger.Warn("stored setting dropped: not a [host]:port address", "key", k, "stored", v)
				continue
			}
			kv[keys[0]], kv[keys[1]] = host, int64(port)
		default:
			kv[k] = v
		}
	}
	if len(kv) > 0 {
		if err := saveConfig(path, kv); err != nil {
			return false, err
		}
		for _, k := range slices.Sorted(maps.Keys(kv)) {
			logger.Info("stored setting migrated to the config file", "key", k, "value", kv[k], "path", path)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin settings cleanup: %w", err)
	}
	defer tx.Rollback()
	for k := range stored {
		if _, err := tx.Exec(`DELETE FROM settings WHERE key = ?`, k); err != nil {
			return false, fmt.Errorf("delete stored %s: %w", k, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit settings cleanup: %w", err)
	}
	return len(kv) > 0, nil
}

// ---- setup token ---------------------------------------------------------------

// setupTokenKey holds "<hex token> <unix expiry>" while setup is pending.
// It lives in the database, not in process memory, so that "webdavgo
// setup-info" can show the token the running service accepts, which under
// systemd would otherwise only be in the journal.
const (
	setupTokenKey = "setup_token"
	setupTokenTTL = time.Hour
)

// readSetupToken returns the stored token and its expiry; an empty token
// means there is none.
func readSetupToken() (token string, expiry time.Time, raw string, err error) {
	raw, err = getSetting(setupTokenKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, "", nil
	}
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("read setup token: %w", err)
	}
	tok, exp, ok := strings.Cut(raw, " ")
	sec, perr := strconv.ParseInt(exp, 10, 64)
	if !ok || perr != nil {
		return "", time.Time{}, raw, nil
	}
	return tok, time.Unix(sec, 0), raw, nil
}

// issueSetupToken returns the stored setup token if it is still valid and
// stores a new one (32 random bytes, valid for an hour) otherwise. The
// service and the setup-info command may run this at the same time against
// the same file; the write is a compare-and-swap on the old value, so both
// end up with the same token instead of one overwriting the other's.
func issueSetupToken() (string, time.Time, error) {
	for range 3 {
		tok, exp, raw, err := readSetupToken()
		if err != nil {
			return "", time.Time{}, err
		}
		if tok != "" && time.Now().Before(exp) {
			return tok, exp, nil
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", time.Time{}, fmt.Errorf("generate setup token: %w", err)
		}
		newTok := hex.EncodeToString(b)
		newExp := time.Now().Add(setupTokenTTL).Truncate(time.Second)
		value := newTok + " " + strconv.FormatInt(newExp.Unix(), 10)
		var res sql.Result
		if raw == "" {
			res, err = db.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, setupTokenKey, value)
		} else {
			res, err = db.Exec(`UPDATE settings SET value = ? WHERE key = ? AND value = ?`, value, setupTokenKey, raw)
		}
		if err != nil {
			return "", time.Time{}, fmt.Errorf("store setup token: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return "", time.Time{}, fmt.Errorf("store setup token: %w", err)
		} else if n == 1 {
			return newTok, newExp, nil
		}
		// Another process stored a token in between; use that one.
	}
	return "", time.Time{}, fmt.Errorf("store setup token: concurrent updates did not settle")
}

// deleteSetupToken invalidates the setup token once the admin exists.
func deleteSetupToken() error {
	if _, err := db.Exec(`DELETE FROM settings WHERE key = ?`, setupTokenKey); err != nil {
		return fmt.Errorf("delete setup token: %w", err)
	}
	return nil
}

// ---- session epoch ---------------------------------------------------------------

// sessionEpochKey returns the settings key of username's session epoch.
// Admin sessions live in the service's memory, which a separate process
// such as reset-totp cannot reach; it bumps this number instead, and the
// service ends every session created under an older one.
func sessionEpochKey(username string) string {
	return "session_epoch:" + username
}

// sessionEpoch returns username's current session epoch; 0 if never bumped.
func sessionEpoch(username string) (int64, error) {
	v, ok, err := storedSetting(sessionEpochKey(username))
	if err != nil {
		return 0, fmt.Errorf("read session epoch of %q: %w", username, err)
	}
	if !ok {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse session epoch of %q: %w", username, err)
	}
	return n, nil
}

// bumpSessionEpoch invalidates all sessions of username in every process
// that shares the database.
func bumpSessionEpoch(username string) error {
	_, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1`, sessionEpochKey(username))
	if err != nil {
		return fmt.Errorf("bump session epoch of %q: %w", username, err)
	}
	return nil
}

// validListenAddress reports whether s can be the host part of a listen
// address: empty (all interfaces), an IP literal, or a host name, without
// port or brackets.
func validListenAddress(s string) bool {
	if s == "" || net.ParseIP(s) != nil {
		return true
	}
	if len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(strings.ToLower(s), ".") {
		if !hostnameLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// normaliseAddr turns ":8080" into "0.0.0.0:8080" for collision detection;
// an IPv6 literal stays in brackets.
func normaliseAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, port)
}

// ---- Settings page ------------------------------------------------------------

// The Settings page shows every key of the config file in one of these
// sections. Save writes a section's changed values to the file; Apply makes
// the saved values effective in the running process where it can; Reset
// writes the section's defaults.
var settingSections = []struct{ id, title, intro string }{
	{"network", "Network & listeners", ""},
	{"tls", "TLS & domain", ""},
	{"limits", "Connections & limits", "Per-client limits count an IPv4 address or an IPv6 /64 as one client."},
	{"bruteforce", "Brute-force protection", "Failed logins (WebDAV/API Basic Auth, share tokens, admin login) are counted per client."},
	{"webdav", "WebDAV", ""},
	{"users", "Users", ""},
	{"logging", "Logging", ""},
	{"health", "Health", "Plain HTTP without authentication, for container runtimes, load balancers and \"webdavgo healthcheck\": /livez answers ok while the server runs, /readyz also checks that the data directory is writable and the database answers."},
}

// settingDef describes one key. restart marks a key the running process
// cannot change: it is fixed in a listener or server at its creation, or
// changing it would mean replacing the global logger.
type settingDef struct {
	key, label, section, desc string
	restart                   bool
	options                   []string
	note                      string
}

var settingDefs = []settingDef{
	{key: "webdav_port", label: "WebDAV port", section: "network", desc: "Port of the WebDAV listener. With tls_mode acme, external port 443 must reach it; the certificate request sets 443."},
	{key: "webdav_listen_address", label: "WebDAV listen address", section: "network", desc: "Host name or IP address the WebDAV listener binds to, without port; empty = all interfaces."},
	{key: "webgui_port", label: "Admin UI port", section: "network", desc: "Port of the admin UI (HTTPS only).",
		note: "After Apply the admin UI is reachable only at the new port."},
	{key: "webgui_listen_address", label: "Admin UI listen address", section: "network", desc: "Host name or IP address the admin UI binds to, without port; empty = all interfaces; 127.0.0.1 limits it to this host or an SSH tunnel.",
		note: "After Apply the admin UI is reachable only at the new address."},
	{key: "shutdown_timeout", label: "Shutdown timeout", section: "network", desc: "How long a stop waits for running requests before cutting them."},
	{key: "read_header_timeout", label: "Request header timeout", section: "network", desc: "Maximum time a client may take to send the request headers.", restart: true},
	{key: "idle_timeout", label: "Keep-alive idle timeout", section: "network", desc: "How long an idle keep-alive connection stays open.", restart: true},
	{key: "http2_max_concurrent_streams", label: "Max. HTTP/2 streams per connection", section: "network", desc: "Parallel requests per HTTP/2 connection.", restart: true},

	{key: "tls_mode", label: "TLS mode", section: "tls", options: []string{"off", "acme"},
		desc: "off: plain HTTP, credentials in clear text (development or trusted LAN only). acme: WebDAV serves TLS only, with a certificate obtained via TLS-ALPN-01; external port 443 of the domain must reach the WebDAV listener.",
		note: "Switching to off takes effect after service restart."},
	{key: "domain", label: "Domain", section: "tls", desc: "Public DNS name of this server; required with tls_mode acme."},
	{key: "acme_email", label: "ACME contact e-mail", section: "tls", desc: "Contact address for the ACME account (expiry notices from the CA); optional."},
	{key: "acme_ca", label: "Certificate authority", section: "tls", desc: "production (Let's Encrypt), staging (Let's Encrypt staging, untrusted certificates, generous rate limits) or an https:// ACME directory URL."},
	{key: "acme_trial_ca", label: "Trial order CA", section: "tls", desc: "CA of the trial order placed before the real one. Empty: Let's Encrypt staging when acme_ca is production, none otherwise; none disables it; staging or an https:// URL sets it."},
	{key: "acme_ca_root", label: "Extra CA root certificates", section: "tls", desc: "PEM file with extra root certificates trusted for the ACME directory connection, e.g. Pebble's roots in tests; optional."},
	{key: "require_tls", label: "Require TLS for WebDAV", section: "tls", desc: "With tls_mode off: do not start the WebDAV listener on a network address (loopback is still allowed).", restart: true},
	{key: "cert_dir", label: "Certificate directory", section: "tls", desc: "ACME account and certificates, and the admin listener's self-signed certificate.", restart: true},

	{key: "max_connections", label: "Max. connections per listener", section: "limits", desc: "Simultaneous connections per listener; further ones wait in the kernel queue.", restart: true},
	{key: "max_connections_per_ip", label: "Max. connections per client", section: "limits", desc: "Simultaneous connections per client and listener; further ones are closed right after accept."},
	{key: "unauth_rate", label: "Unauthenticated request rate", section: "limits", desc: "WebDAV requests without credentials per second and client (token bucket refill)."},
	{key: "unauth_burst", label: "Unauthenticated request burst", section: "limits", desc: "Bucket size for unauth_rate; beyond it such requests get 429."},
	{key: "body_read_idle_timeout", label: "Request body idle timeout", section: "limits", desc: "A request body that sends nothing for this long is aborted."},
	{key: "body_min_rate", label: "Min. request body rate", section: "limits", desc: "Minimum average request body rate, checked after the grace period; 0 disables the check."},
	{key: "body_min_rate_grace", label: "Request body rate grace period", section: "limits", desc: "body_min_rate is checked only after this much time."},
	{key: "response_write_idle_timeout", label: "Response idle timeout", section: "limits", desc: "A response the client does not read for this long is cut."},
	{key: "response_min_rate", label: "Min. response rate", section: "limits", desc: "Minimum average response rate, checked after the grace period; 0 disables the check."},
	{key: "response_min_rate_grace", label: "Response rate grace period", section: "limits", desc: "response_min_rate is checked only after this much time."},

	{key: "bruteforce_window", label: "Brute-force window", section: "bruteforce", desc: "Window for counting failed logins."},
	{key: "bruteforce_ip_threshold", label: "Client lockout threshold", section: "bruteforce", desc: "Failures per client within the window that start a lockout (429, no password check)."},
	{key: "bruteforce_lockout_base", label: "First lockout", section: "bruteforce", desc: "First lockout; each further one doubles, up to the maximum."},
	{key: "bruteforce_lockout_max", label: "Max. lockout", section: "bruteforce", desc: "Longest lockout."},
	{key: "bruteforce_account_threshold", label: "Account throttle threshold", section: "bruteforce", desc: "Failures for one username (from any clients) within the window after which only one password check per interval runs for it."},
	{key: "bruteforce_account_interval", label: "Throttled account check interval", section: "bruteforce", desc: "One password check per interval while an account is throttled."},
	{key: "bruteforce_max_entries", label: "Max. table entries", section: "bruteforce", desc: "Size limit of the client and account tables and of the rate-limit tables."},

	{key: "data_dir", label: "Data directory", section: "webdav", desc: "Directory for the database (webdavgo.db) and user files (users/<name>/)."},
	{key: "max_request_body", label: "Max. request body", section: "webdav", desc: "Maximum request body for every method except PUT; larger bodies get 413."},
	{key: "max_dead_props_size", label: "Max. dead properties per resource", section: "webdav", desc: "Maximum total size of the dead properties of one resource; a PROPPATCH that would exceed it fails with 507 for the properties concerned. 0 = unlimited."},
	{key: "allow_propfind_infinity", label: "Allow PROPFIND Depth: infinity", section: "webdav", desc: "Allow PROPFIND with Depth: infinity (or no Depth header); otherwise 403."},
	{key: "auth_cache_ttl", label: "Login cache lifetime", section: "webdav", desc: "How long a successful WebDAV/API login is remembered to skip bcrypt; 0 disables."},

	{key: "default_quota", label: "Default quota for new users", section: "users", desc: "Storage quota a new user gets, prefilled in the Add user form; 0 = unlimited. Existing users keep their quota."},

	{key: "log_level", label: "Log level", section: "logging", options: []string{"debug", "info", "warn", "error"}, desc: "Minimum log level."},
	{key: "log_buffer_entries", label: "Live Log buffer size", section: "logging", desc: "Log records kept in memory for the Live Log page."},
	{key: "access_log", label: "Access log file", section: "logging", desc: "Absolute path of the file for the request lines; empty: stdout (the journal).", restart: true},
	{key: "server_log", label: "Server log file", section: "logging", desc: "Absolute path of the file for every other record; may be the same file as access_log; empty: stdout.", restart: true},

	{key: "health_enabled", label: "Enabled", section: "health", desc: "Run the health listener."},
	{key: "health_bind", label: "Bind address", section: "health", desc: "Host name or IP address the health listener binds to, without port; empty = all interfaces. It has no authentication; keep it on 127.0.0.1 unless something outside this host must reach it."},
	{key: "health_port", label: "Port", section: "health", desc: "Port of the health listener; must differ from the WebDAV and admin UI ports."},
}

// Every key of the file must be on the page exactly once.
func init() {
	seen := map[string]bool{}
	for _, d := range settingDefs {
		if _, ok := configKeys[d.key]; !ok || seen[d.key] {
			panic("settingDefs: unknown or duplicate key " + d.key)
		}
		seen[d.key] = true
	}
	for key := range configKeys {
		if !seen[key] {
			panic("settingDefs: no entry for config key " + key)
		}
	}
}

// acmeKeys only matter with tls_mode acme: while off is selected they are
// disabled in the form and not written.
var acmeKeys = []string{"domain", "acme_email", "acme_ca", "acme_trial_ca", "acme_ca_root"}

// wizardKeys with tls_mode acme reach the file and the running process only
// through a successful certificate request (the domain wizard), so that the
// file never names a domain without a certificate for it.
var wizardKeys = append([]string{"tls_mode"}, acmeKeys...)

// applyMode is how a saved value reaches the running process.
type applyMode int

const (
	applyLive    applyMode = iota // Apply sets it
	applyRebind                   // Apply moves the listener
	applyWizard                   // only a certificate request (TLS section)
	applyRestart                  // only a service restart
)

func howApplied(d settingDef, saved *Config) applyMode {
	switch {
	case d.restart:
		return applyRestart
	case listenerKeys[d.key] != "":
		return applyRebind
	case slices.Contains(wizardKeys, d.key):
		if saved.TLSMode == "acme" {
			return applyWizard
		}
		// The TLS listener and its certificate manager cannot be turned
		// back into plain HTTP in place.
		if conf().TLSMode == "acme" {
			return applyRestart
		}
	}
	return applyLive
}

// readOnlyReasons returns why key cannot be edited on the page, if at all.
func readOnlyReasons(key string) []string {
	var r []string
	if key == "data_dir" {
		r = append(r, "the database lives in it")
	}
	if flagName, ok := conf().Overrides[key]; ok {
		r = append(r, "overridden by command-line flag "+flagName)
	}
	return r
}

func defsOf(section string) []settingDef {
	var out []settingDef
	for _, d := range settingDefs {
		if d.section == section {
			out = append(out, d)
		}
	}
	return out
}

func sameValue(a, b *Config, key string) bool {
	return reflect.DeepEqual(configValue(a, key).Interface(), configValue(b, key).Interface())
}

// listenerKeys maps the keys that move a listener on Apply to it.
var listenerKeys = map[string]string{
	"webdav_port": "webdav", "webdav_listen_address": "webdav",
	"webgui_port": "webgui", "webgui_listen_address": "webgui",
	"health_enabled": "health", "health_bind": "health", "health_port": "health",
}

// formValue is key of c as the Settings page shows it: the file's value,
// in the file's unit.
func formValue(c *Config, key string) string {
	return fmt.Sprint(fileValue(c, key))
}

func shownValue(c *Config, key string) string {
	if v := formValue(c, key); v != "" {
		return v
	}
	return "(empty)"
}

// settingField is one field as the template renders it.
type settingField struct {
	Key, Label, Desc, Default, Value, Error, Note, Pending, Unit string
	Options                                                      []string
	Bool, Number, Checked, Restart, ACME, Disabled               bool
	ReadOnly                                                     []string
}

// settingSectionView is one card; Notice, Error and Links report the last
// action on it.
type settingSectionView struct {
	ID, Title, Intro, Notice, Error string
	Links                           []string
	Fields                          []settingField
}

// settingsView carries what the last request did to one section: the
// submitted form (redisplayed when invalid) and its messages.
type settingsView struct {
	section, notice, errMsg string
	links                   []string
	form                    map[string]string
	errs                    map[string]string
}

// settingsData builds the Settings page for the saved configuration.
func settingsData(saved Config, loadErr error, v settingsView) map[string]any {
	run := conf()
	def := defaultConfig()
	errs := map[string]string{}
	for _, fe := range saved.fieldErrors() {
		if errs[fe.Key] == "" {
			errs[fe.Key] = fe.Err.Error()
		}
	}
	maps.Copy(errs, v.errs)
	failed, failMsg, hasFail := job.failedRequest()

	var restartPending []string
	var sections []settingSectionView
	for _, s := range settingSections {
		sv := settingSectionView{ID: s.id, Title: s.title, Intro: s.intro}
		var form map[string]string
		if s.id == v.section {
			sv.Notice, sv.Error, sv.Links = v.notice, v.errMsg, v.links
			form = v.form
		}
		// A failed certificate request saved nothing; the section shows
		// what was submitted, so it can be corrected and sent again.
		if s.id == "tls" && hasFail && v.section != "tls" {
			sv.Error = "The certificate request for " + failed.Domain + " failed: " + failMsg +
				" Nothing was saved to " + run.ConfigFile + "; the form shows the submitted values."
			form = map[string]string{}
			for _, k := range wizardKeys {
				form[k] = formValue(&failed, k)
			}
		}
		tlsMode := saved.TLSMode
		if m, ok := form["tls_mode"]; ok {
			tlsMode = m
		}
		for _, d := range defsOf(s.id) {
			val := configValue(&saved, d.key)
			f := settingField{
				Key: d.key, Label: d.label, Desc: d.desc, Note: d.note, Restart: d.restart, Options: d.options,
				Default: shownValue(&def, d.key), Value: formValue(&saved, d.key),
				ReadOnly: readOnlyReasons(d.key), Error: errs[d.key], Unit: configUnit(d.key),
			}
			if _, ok := fileValue(&saved, d.key).(int64); ok {
				f.Number = true
			}
			if d.key == "cert_dir" {
				f.Default = "<data_dir>/certs"
			}
			if b, ok := val.Interface().(bool); ok {
				f.Bool, f.Checked = true, b
			}
			if raw, ok := form[d.key]; ok {
				f.Value = raw
				f.Checked = raw != ""
			}
			if slices.Contains(acmeKeys, d.key) {
				f.ACME, f.Disabled = true, tlsMode == "off"
			}
			if !sameValue(&saved, run, d.key) {
				running := shownValue(run, d.key)
				switch howApplied(d, &saved) {
				case applyRestart:
					f.Pending = "Saved; waiting for a service restart (running: " + running + ")."
					restartPending = append(restartPending, d.key+": "+running+" → "+shownValue(&saved, d.key))
				case applyWizard:
					f.Pending = "Differs from the running value (running: " + running + ")."
				default:
					f.Pending = "Saved; not applied yet (running: " + running + ")."
				}
			}
			sv.Fields = append(sv.Fields, f)
		}
		sections = append(sections, sv)
	}

	data := map[string]any{
		"Page":           "settings",
		"ConfigPath":     run.ConfigFile,
		"Sections":       sections,
		"RestartPending": restartPending,
		"TLSActive":      run.TLSMode == "acme" && currentCerts() != nil,
		"Job":            job.snapshot(),
		"AdminReach":     adminReach(run.webguiAddr()),
	}
	if loadErr != nil {
		data["LoadError"] = loadErr.Error()
	}
	if p := currentCerts(); p != nil {
		data["Cert"] = certStatusData(p.Status())
	}
	return data
}

// loadSaved returns savedConfig, or the running configuration and the
// error if the file cannot be read.
func loadSaved() (Config, error) {
	saved, err := savedConfig()
	if err != nil {
		return currentConfig(), err
	}
	return saved, nil
}

func handleSettingsGET(w http.ResponseWriter, r *http.Request) {
	saved, err := loadSaved()
	renderPage(w, r, "settings", settingsData(saved, err, settingsView{}))
}

// sectionFromRequest returns the section id of the URL, or "" if there is
// no such section.
func sectionFromRequest(r *http.Request) string {
	id := r.PathValue("section")
	for _, s := range settingSections {
		if s.id == id {
			return id
		}
	}
	return ""
}

// handleSettingsPOST saves the section's form (action=save) and, for
// action=apply, then applies the section's saved values. Apply saves first
// so that edits in the form are never silently dropped. Responses are 200
// with the page: htmx swaps nothing for 4xx.
func handleSettingsPOST(w http.ResponseWriter, r *http.Request) {
	id := sectionFromRequest(r)
	if id == "" {
		http.NotFound(w, r)
		return
	}
	v := settingsView{section: id}
	saved, err := savedConfig()
	if err != nil {
		v.errMsg = "Not saved: " + err.Error()
		renderPage(w, r, "settings", settingsData(currentConfig(), err, v))
		return
	}
	next, form, errs := parseSection(id, saved, r)
	if len(errs) > 0 {
		v.errMsg, v.form, v.errs = "Nothing was saved: correct the marked fields.", form, errs
		renderPage(w, r, "settings", settingsData(saved, nil, v))
		return
	}
	// With tls_mode acme, the TLS values go to the file only once the
	// certificate request for them has succeeded (runDomainJob writes them).
	request := id == "tls" && next.TLSMode == "acme"
	if id == "tls" {
		job.forgetFailure()
	}
	kv := map[string]any{}
	for _, d := range defsOf(id) {
		if request && slices.Contains(wizardKeys, d.key) {
			continue
		}
		if len(readOnlyReasons(d.key)) == 0 && !sameValue(&saved, &next, d.key) {
			kv[d.key] = fileValue(&next, d.key)
		}
	}
	if len(kv) > 0 {
		if err := saveConfig(saved.ConfigFile, kv); err != nil {
			logger.Error("cannot save settings", "section", id, "by", currentUser(r), "err", err)
			v.errMsg, v.form = "Not saved: "+err.Error(), form
			renderPage(w, r, "settings", settingsData(saved, nil, v))
			return
		}
		logger.Info("settings saved", "section", id, "keys", strings.Join(slices.Sorted(maps.Keys(kv)), ","), "by", currentUser(r))
		if saved, err = savedConfig(); err != nil {
			renderPage(w, r, "settings", settingsData(currentConfig(), err, v))
			return
		}
	}

	if request && certificateRequestNeeded(&next) {
		if err := startDomainJob(next, currentUser(r)); err != nil {
			v.errMsg, v.form = "Nothing was saved: "+err.Error()+".", form
			renderPage(w, r, "settings", settingsData(saved, nil, v))
			return
		}
		http.Redirect(w, r, "/admin/domain", http.StatusSeeOther)
		return
	}

	if r.PostFormValue("action") != "apply" {
		v.notice = "No changes to save."
		if len(kv) > 0 {
			v.notice = fmt.Sprintf("Saved %d value(s) to %s. Nothing takes effect until Apply or a service restart.", len(kv), saved.ConfigFile)
		}
		renderPage(w, r, "settings", settingsData(saved, nil, v))
		return
	}
	if err := applySection(id, saved, currentUser(r), &v); err != nil {
		v.errMsg = err.Error()
	}
	renderPage(w, r, "settings", settingsData(saved, nil, v))
}

// handleSettingsReset writes the default of every editable key of the
// section into the file. Like a save, it takes effect with Apply or a
// restart.
func handleSettingsReset(w http.ResponseWriter, r *http.Request) {
	id := sectionFromRequest(r)
	if id == "" {
		http.NotFound(w, r)
		return
	}
	v := settingsView{section: id}
	path := conf().ConfigFile
	def := defaultConfig()
	kv := map[string]any{}
	for _, d := range defsOf(id) {
		if len(readOnlyReasons(d.key)) == 0 {
			kv[d.key] = fileValue(&def, d.key)
		}
	}
	// The section shows the reset values from now on, not those of a
	// failed certificate request.
	if id == "tls" {
		job.forgetFailure()
	}
	if err := saveConfig(path, kv); err != nil {
		logger.Error("cannot reset settings", "section", id, "by", currentUser(r), "err", err)
		v.errMsg = "Not reset: " + err.Error()
	} else {
		logger.Info("settings reset to defaults", "section", id, "by", currentUser(r))
		v.notice = "Defaults written to " + path + ". Nothing takes effect until Apply or a service restart."
		if id == "tls" {
			v.notice = "Defaults written to " + path + ". The running TLS state stays as it is until a service restart."
		}
	}
	saved, err := loadSaved()
	renderPage(w, r, "settings", settingsData(saved, err, v))
}

// parseSection returns saved with the section's submitted values, the raw
// form values, and an error per invalid field. Every check runs, so that
// each field shows its own problem.
func parseSection(id string, saved Config, r *http.Request) (Config, map[string]string, map[string]string) {
	next := saved
	form, errs := map[string]string{}, map[string]string{}
	inSection := map[string]bool{}
	// Disabled in the form while off is selected: they keep their values.
	tlsOff := id == "tls" && strings.TrimSpace(r.PostFormValue("tls_mode")) == "off"
	for _, d := range defsOf(id) {
		inSection[d.key] = true
		if len(readOnlyReasons(d.key)) > 0 || tlsOff && slices.Contains(acmeKeys, d.key) {
			continue
		}
		raw := strings.TrimSpace(r.PostFormValue(d.key))
		form[d.key] = raw
		// Values arrive in the file's units (seconds, KB, KB/s) and go
		// through setFileValue like a value read from the file.
		var v any
		switch fileValue(&next, d.key).(type) {
		case string:
			if d.key == "domain" {
				raw = strings.ToLower(raw)
			}
			v = raw
		case bool:
			form[d.key] = ""
			if r.PostForm.Has(d.key) {
				form[d.key] = "on"
			}
			v = r.PostForm.Has(d.key)
		case int64:
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				if u := configUnit(d.key); u != "" {
					errs[d.key] = "Must be a whole number of " + u + "."
				} else {
					errs[d.key] = "Must be a whole number."
				}
				continue
			}
			v = n
		}
		if err := setFileValue(&next, d.key, v); err != nil {
			errs[d.key] = err.Error()
		}
	}
	next.resolve()
	for _, fe := range next.fieldErrors() {
		if inSection[fe.Key] && errs[fe.Key] == "" {
			errs[fe.Key] = fe.Err.Error()
		}
	}
	if inSection["acme_email"] && !tlsOff && next.ACMEEmail != "" && errs["acme_email"] == "" {
		if a, err := mail.ParseAddress(next.ACMEEmail); err != nil || a.Address != next.ACMEEmail {
			errs["acme_email"] = "Not a valid e-mail address; leave it empty for no expiry notices."
		}
	}
	return next, form, errs
}

// applySection makes the section's saved values effective where the
// running process can take them, and reports the outcome in v. TLS values
// with tls_mode acme are not its business: they take effect through the
// certificate request, which the TLS section's POST starts itself.
func applySection(id string, saved Config, by string, v *settingsView) error {
	for _, fe := range saved.fieldErrors() {
		if slices.ContainsFunc(defsOf(id), func(d settingDef) bool { return d.key == fe.Key }) {
			return fmt.Errorf("not applied: the saved %s is invalid: %w", fe.Key, fe.Err)
		}
	}
	var applied, waiting []string
	rebind := map[string]bool{}
	cfgMu.Lock()
	next := currentConfig()
	for _, d := range defsOf(id) {
		if sameValue(&saved, &next, d.key) {
			continue
		}
		switch howApplied(d, &saved) {
		case applyLive:
			configValue(&next, d.key).Set(configValue(&saved, d.key))
			applied = append(applied, d.key)
		case applyRebind:
			rebind[d.key] = true
		case applyRestart:
			waiting = append(waiting, d.key)
		}
	}
	setConf(next)
	cfgMu.Unlock()
	applyRuntime(conf())

	var notes []string
	var errs []error
	moved := func(listener string) []string {
		var keys []string
		for _, k := range slices.Sorted(maps.Keys(rebind)) {
			if listenerKeys[k] == listener {
				keys = append(keys, k)
			}
		}
		return keys
	}
	if keys := moved("webdav"); len(keys) > 0 {
		if note, err := rebindWebDAV(saved.WebDAVPort, saved.WebDAVListenAddress); err != nil {
			errs = append(errs, err)
		} else {
			applied = append(applied, keys...)
			notes = append(notes, note)
		}
	}
	if keys := moved("webgui"); len(keys) > 0 {
		if err := rebindWebGUI(saved.WebGUIPort, saved.WebGUIListenAddress); err != nil {
			errs = append(errs, err)
		} else {
			applied = append(applied, keys...)
			notes = append(notes, "The admin UI now listens on "+saved.webguiAddr()+" only; continue at one of these addresses:")
			v.links = adminURLs(saved.webguiAddr(), "/admin/settings")
		}
	}
	if keys := moved("health"); len(keys) > 0 {
		if note, err := rebindHealth(saved.HealthEnabled, saved.HealthBind, saved.HealthPort); err != nil {
			errs = append(errs, err)
		} else {
			applied = append(applied, keys...)
			notes = append(notes, note)
		}
	}
	if len(applied) > 0 {
		logger.Info("settings applied", "section", id, "keys", strings.Join(applied, ","), "by", by)
	}
	switch {
	case len(applied) > 0:
		notes = append([]string{"Applied: " + strings.Join(applied, ", ") + "."}, notes...)
	case len(waiting) == 0 && len(errs) == 0:
		notes = append(notes, "Nothing to apply: the running values already match the saved ones.")
	}
	if len(waiting) > 0 {
		notes = append(notes, "Waiting for a service restart: "+strings.Join(waiting, ", ")+".")
	}
	v.notice = strings.Join(notes, " ")
	return errors.Join(errs...)
}

// certificateRequestNeeded reports whether the TLS values of t (tls_mode
// acme) differ from what runs, so that only a request can make them
// consistent with a certificate.
func certificateRequestNeeded(t *Config) bool {
	run := conf()
	if run.TLSMode != "acme" || currentCerts() == nil {
		return true
	}
	return slices.ContainsFunc(wizardKeys, func(k string) bool { return !sameValue(t, run, k) })
}

// applyRuntime hands c's values to the parts that keep their own copy.
func applyRuntime(c *Config) {
	if level, err := parseLogLevel(c.LogLevel); err == nil {
		logLevel.Set(level)
	}
	logRing.resize(c.LogBufferEntries)
	authCache.setTTL(c.AuthCacheTTL)
	limiter.setParams(c)
	limited.setMaxEntries(c.BruteforceMaxEntries)
	unauthLimiter.setParams(c)
}

// rebindWebDAV moves the WebDAV listener to addr: the new one starts
// first, the old one drains like at shutdown. Whether it runs at all
// follows the same rule as at startup (require_tls).
func rebindWebDAV(port int, host string) (string, error) {
	c := conf()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsOn := currentCerts() != nil
	on := tlsOn || !c.RequireTLS || isLoopbackAddr(addr)
	var srv *http.Server
	if on {
		ln, err := listen(addr, "webdav")
		if err != nil {
			return "", fmt.Errorf("webdav_port/webdav_listen_address not applied (they take effect after a service restart): %w", err)
		}
		srv = newServer("webdav", running.webdavHandler)
		if tlsOn {
			srv.TLSConfig = webdavTLSConfig()
		}
		serve("webdav", srv, ln)
	}
	cfgMu.Lock()
	next := currentConfig()
	oldAddr := next.webdavAddr()
	next.WebDAVPort, next.WebDAVListenAddress = port, host
	setConf(next)
	cfgMu.Unlock()

	running.mu.Lock()
	old := running.webdav
	running.webdav = srv
	if old != nil {
		running.draining = append(running.draining, old)
	}
	running.mu.Unlock()
	if old != nil {
		go drainServer("webdav", old, oldAddr)
	}
	if !on {
		logger.Warn("webdav listener not started: require_tls is set and tls_mode is off", "addr", addr)
		return "WebDAV is off: require_tls keeps it from " + addr + " until TLS is set up.", nil
	}
	return "WebDAV now listens on " + addr + ".", nil
}

// rebindWebGUI moves the admin listener to addr. The handler, and with it
// every admin session, stays the same; the request that asked for the move
// is answered on the old listener before it closes.
func rebindWebGUI(port int, host string) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	running.mu.Lock()
	old := running.webgui
	running.mu.Unlock()
	ln, err := listen(addr, "admin")
	if err != nil {
		return fmt.Errorf("webgui_port/webgui_listen_address not applied (they take effect after a service restart): %w", err)
	}
	srv := newServer("admin", running.webguiHandler)
	srv.TLSConfig = old.TLSConfig.Clone()
	serve("webgui", srv, ln)

	cfgMu.Lock()
	next := currentConfig()
	oldAddr := next.webguiAddr()
	next.WebGUIPort, next.WebGUIListenAddress = port, host
	setConf(next)
	cfgMu.Unlock()

	running.mu.Lock()
	running.webgui = srv
	running.draining = append(running.draining, old)
	running.mu.Unlock()
	go drainServer("webgui", old, oldAddr)
	return nil
}
