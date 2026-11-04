// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// bruteforce.go – in-process brute-force protection for every login path:
// user Basic Auth (WebDAV and /api/v1/), share auth and the admin login.
//
// Two independent mechanisms:
//   - Per client (IPv4 address, IPv6 /64): too many failures within the
//     window start a lockout that doubles with each repeat. During a lockout
//     no bcrypt check runs for that client.
//   - Per account: after many failures for one username, from any number
//     of clients, at most one bcrypt check per interval runs for it. This
//     slows distributed guessing down. A request refused by this throttle
//     counts as a failure toward the lockout of its client, so polling for
//     the free slot locks the poller out. Clients that logged in to the
//     account within the last 30 days are exempt, so an attacker who keeps
//     the throttle engaged does not lock the real user out of their known
//     devices. The admin login (password and second factor) and WebDAV
//     plus the API keep separate throttle state: failures on one side
//     never throttle the other.
//
// A username that usernameRE rejects never reaches the account throttle or
// bcrypt. It is answered like a wrong password and counts toward the
// client's lockout only, so attacker-chosen names never become keys in the
// account tables.
//
// Throttled requests get 429 with Retry-After, never 401: share clients
// treat 401 as "access revoked" and may delete their local copies.

import (
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// limiter is set in main from the configuration.
var limiter = newBruteForce(defaultConfig())

// authSource is the login path a failure came from. All paths share the
// client lockout, so that guessing on one path also locks the others. The
// account throttle is kept apart for the admin login. Otherwise the source
// is kept only so the Security page can say where a lockout came from.
type authSource int

const (
	authSrcUser  authSource = iota // user Basic Auth on WebDAV and /api/v1/
	authSrcShare                   // share token on /s/<id>
	authSrcAdmin                   // admin login: password, TOTP, recovery code
	numAuthSources
)

var authSourceNames = [numAuthSources]string{"WebDAV user auth", "share token", "admin login"}

// sourceCounts counts the failures of one entry per source since the entry
// was created; unlike the windowed failures they survive a lockout.
type sourceCounts [numAuthSources]int

func (s sourceCounts) total() int {
	n := 0
	for _, c := range s {
		n += c
	}
	return n
}

// String lists the sources with failures, e.g. "admin login: 3".
func (s sourceCounts) String() string {
	var parts []string
	for i, c := range s {
		if c > 0 {
			parts = append(parts, authSourceNames[i]+": "+strconv.Itoa(c))
		}
	}
	return strings.Join(parts, ", ")
}

type bruteForce struct {
	window           time.Duration
	ipThreshold      int
	lockoutBase      time.Duration
	lockoutMax       time.Duration
	accountThreshold int
	accountInterval  time.Duration
	// maxEntries bounds each table so that an attacker cycling through
	// many addresses or usernames cannot exhaust memory.
	maxEntries int

	mu  sync.Mutex
	ips map[string]*ipRecord
	// accounts throttles WebDAV and API logins, adminAccounts the admin
	// login. Both are keyed by usernames that match usernameRE.
	accounts      map[string]*accountRecord
	adminAccounts map[string]*accountRecord
	// trusted holds the last successful login of a client to an account.
	// Such a client is exempt from that account's throttle for trustedFor.
	trusted    map[trustKey]time.Time
	lastSweep  time.Time
	fullLogged bool
}

// trustedFor is how long a successful login exempts its client from the
// throttle of that account.
const trustedFor = 30 * 24 * time.Hour

// trustKey is a client (clientKey form) that logged in to username on one
// side: admin is the admin login, otherwise WebDAV and the API.
type trustKey struct {
	username, client string
	admin            bool
}

type ipRecord struct {
	failures    []time.Time // within the window, at most ipThreshold
	lockedUntil time.Time
	lockouts    int // lockouts so far; the next one lasts base << lockouts
	lastSeen    time.Time
	sources     sourceCounts
}

type accountRecord struct {
	failures  []time.Time // within the window, at most accountThreshold
	lastCheck time.Time   // last bcrypt check while throttled
	throttled bool        // for logging the start of a throttle once
	lastSeen  time.Time
	sources   sourceCounts
}

func newBruteForce(c Config) *bruteForce {
	return &bruteForce{
		window:           c.BruteforceWindow,
		ipThreshold:      c.BruteforceIPThreshold,
		lockoutBase:      c.BruteforceLockoutBase,
		lockoutMax:       c.BruteforceLockoutMax,
		accountThreshold: c.BruteforceAccountThreshold,
		accountInterval:  c.BruteforceAccountInterval,
		maxEntries:       c.BruteforceMaxEntries,
		ips:              map[string]*ipRecord{},
		accounts:         map[string]*accountRecord{},
		adminAccounts:    map[string]*accountRecord{},
		trusted:          map[trustKey]time.Time{},
	}
}

// accountTable returns the throttle table of the side src belongs to.
func (b *bruteForce) accountTable(src authSource) map[string]*accountRecord {
	if src == authSrcAdmin {
		return b.adminAccounts
	}
	return b.accounts
}

// setParams applies changed settings (Apply on the Settings page). Records
// are kept; they are judged by the new limits from now on.
func (b *bruteForce) setParams(c *Config) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.window, b.ipThreshold = c.BruteforceWindow, c.BruteforceIPThreshold
	b.lockoutBase, b.lockoutMax = c.BruteforceLockoutBase, c.BruteforceLockoutMax
	b.accountThreshold, b.accountInterval = c.BruteforceAccountThreshold, c.BruteforceAccountInterval
	b.maxEntries = c.BruteforceMaxEntries
}

// clientKey identifies the client of r: the IPv4 address, or the /64 prefix
// for IPv6 because a single host usually controls a whole /64.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	return prefixKey(clientPrefix(addr))
}

// clientPrefix is clientKey before it becomes a string: the per-IP limits
// use it as a map key, which costs no allocation per request.
func clientPrefix(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32)
	}
	prefix, _ := addr.Prefix(64)
	return prefix
}

// requestPrefix is clientPrefix for r; ok is false if the remote address is
// not an IP address.
func requestPrefix(r *http.Request) (netip.Prefix, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Prefix{}, false
	}
	return clientPrefix(ap.Addr()), true
}

// prefixKey renders a client prefix like clientKey: an IPv4 client without
// "/32".
func prefixKey(p netip.Prefix) string {
	if p.Addr().Is4() {
		return p.Addr().String()
	}
	return p.String()
}

// remoteIP is the client address of r for log lines. Unlike clientKey it
// keeps the full IPv6 address, which is what an operator greps for.
func remoteIP(r *http.Request) string {
	return addrHost(r.RemoteAddr)
}

// ipLocked reports whether the client is locked out and for how long.
func (b *bruteForce) ipLocked(ip string) (bool, time.Duration) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	rec := b.ips[ip]
	if rec == nil || !now.Before(rec.lockedUntil) {
		return false, 0
	}
	return true, rec.lockedUntil.Sub(now)
}

// reserveAccountCheck reports whether a credential check for username by
// client ip on the login path src may run now. While the account is
// throttled it grants one check per interval and returns the wait until the
// next one otherwise. A client that logged in to the account within
// trustedFor is not throttled. A refusal counts as a failure toward the
// lockout of ip.
func (b *bruteForce) reserveAccountCheck(ip, username string, src authSource) (bool, time.Duration) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	rec := b.accountTable(src)[username]
	if rec == nil {
		return true, 0
	}
	rec.failures = pruneBefore(rec.failures, now.Add(-b.window))
	if len(rec.failures) < b.accountThreshold {
		rec.throttled = false
		return true, 0
	}
	if b.trustedLocked(trustKey{username, ip, src == authSrcAdmin}, now) {
		return true, 0
	}
	if wait := rec.lastCheck.Add(b.accountInterval).Sub(now); wait > 0 {
		b.sweepLocked(now)
		b.ipFailLocked(ip, src, now)
		return false, wait
	}
	rec.lastCheck = now
	return true, 0
}

// trustedLocked reports whether k logged in within trustedFor.
func (b *bruteForce) trustedLocked(k trustKey, now time.Time) bool {
	t, ok := b.trusted[k]
	return ok && now.Sub(t) < trustedFor
}

// succeed records a successful login by client ip to username on the login
// path src, which exempts ip from that account's throttle for trustedFor.
// The table is bounded by maxEntries. When it is full the oldest entry of
// the same side goes, so that logins to user accounts cannot push the
// admins' clients out.
func (b *bruteForce) succeed(ip, username string, src authSource) {
	now := time.Now()
	k := trustKey{username, ip, src == authSrcAdmin}
	b.mu.Lock()
	defer b.mu.Unlock()
	if t, ok := b.trusted[k]; ok {
		// Cache hits call this on every request. A fresh entry needs no
		// write.
		if now.Sub(t) >= time.Minute {
			b.trusted[k] = now
		}
		return
	}
	b.sweepLocked(now)
	if len(b.trusted) >= b.maxEntries {
		b.evictTrustedLocked(k.admin)
	}
	b.trusted[k] = now
}

// evictTrustedLocked drops the oldest entry of the side admin, or the
// oldest of all if that side has none.
func (b *bruteForce) evictTrustedLocked(admin bool) {
	var oldest, oldestAny trustKey
	var oldestAt, oldestAnyAt time.Time
	found, foundAny := false, false
	for k, t := range b.trusted {
		if !foundAny || t.Before(oldestAnyAt) {
			oldestAny, oldestAnyAt, foundAny = k, t, true
		}
		if k.admin == admin && (!found || t.Before(oldestAt)) {
			oldest, oldestAt, found = k, t, true
		}
	}
	switch {
	case found:
		delete(b.trusted, oldest)
	case foundAny:
		delete(b.trusted, oldestAny)
	}
}

// fail records a failed authentication by client ip for username on the
// login path src. username is empty for share auth, which has no account to
// throttle.
func (b *bruteForce) fail(ip, username string, src authSource) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sweepLocked(now)

	b.ipFailLocked(ip, src, now)

	if username == "" {
		return
	}
	if rec := b.accountRecordLocked(b.accountTable(src), username, now); rec != nil {
		rec.sources[src]++
		rec.failures = append(pruneBefore(rec.failures, now.Add(-b.window)), now)
		if n := len(rec.failures); n > b.accountThreshold {
			// Only the newest failures matter for the throttle.
			rec.failures = append(rec.failures[:0], rec.failures[n-b.accountThreshold:]...)
		}
		if len(rec.failures) >= b.accountThreshold && !rec.throttled {
			rec.throttled = true
			rec.lastCheck = now
			stats.throttleEngaged(username)
			logger.Warn("brute-force account throttle engaged", "username", username,
				"failures", len(rec.failures), "interval", b.accountInterval.String(),
				"window", b.window.String(), "source", authSourceNames[src])
		}
	}
}

// ipFailLocked counts a failure toward the lockout of client ip.
func (b *bruteForce) ipFailLocked(ip string, src authSource, now time.Time) {
	rec := b.ipRecordLocked(ip, now)
	if rec == nil || now.Before(rec.lockedUntil) {
		return
	}
	rec.sources[src]++
	rec.failures = append(pruneBefore(rec.failures, now.Add(-b.window)), now)
	if len(rec.failures) >= b.ipThreshold {
		d := b.lockoutBase << rec.lockouts
		if d > b.lockoutMax || d <= 0 {
			d = b.lockoutMax
		} else {
			rec.lockouts++
		}
		rec.lockedUntil = now.Add(d)
		stats.lockoutStarted(ip)
		logger.Warn("brute-force lockout started", "client", ip,
			"failures", len(rec.failures), "duration", d.String(), "source", authSourceNames[src])
		rec.failures = rec.failures[:0]
	}
}

func (b *bruteForce) ipRecordLocked(ip string, now time.Time) *ipRecord {
	rec := b.ips[ip]
	if rec == nil {
		if len(b.ips) >= b.maxEntries && !b.evictIPLocked(now) {
			b.logFullLocked("ips")
			return nil
		}
		rec = &ipRecord{}
		b.ips[ip] = rec
	}
	rec.lastSeen = now
	return rec
}

func (b *bruteForce) accountRecordLocked(table map[string]*accountRecord, username string, now time.Time) *accountRecord {
	rec := table[username]
	if rec == nil {
		if len(table) >= b.maxEntries && !b.evictAccountLocked(table, now) {
			b.logFullLocked("accounts")
			return nil
		}
		rec = &accountRecord{}
		table[username] = rec
	}
	rec.lastSeen = now
	return rec
}

// evictIPLocked makes room in a full table by dropping one client that is
// not locked out. Locked clients stay: evicting them would let an attacker
// end their own lockout by flooding the table.
func (b *bruteForce) evictIPLocked(now time.Time) bool {
	for k, rec := range b.ips {
		if !now.Before(rec.lockedUntil) {
			delete(b.ips, k)
			return true
		}
	}
	return false
}

// evictAccountLocked makes room in a full table by dropping the account
// seen longest ago among those that are not throttled. A throttled account
// stays for the same reason a locked client does: flooding the table with
// new usernames must not end the throttle on the one being guessed. The
// scan is linear, but it only runs while the table is full.
func (b *bruteForce) evictAccountLocked(table map[string]*accountRecord, now time.Time) bool {
	cutoff := now.Add(-b.window)
	var oldest string
	var oldestSeen time.Time
	for k, rec := range table {
		if b.accountThrottledLocked(rec, cutoff) {
			continue
		}
		if oldest == "" || rec.lastSeen.Before(oldestSeen) {
			oldest, oldestSeen = k, rec.lastSeen
		}
	}
	if oldest == "" {
		return false
	}
	delete(table, oldest)
	return true
}

// accountThrottledLocked reports whether rec has enough failures within the
// window to ration its password checks. Like the other checks it counts
// without pruning, so a read-only scan does not modify the record.
func (b *bruteForce) accountThrottledLocked(rec *accountRecord, cutoff time.Time) bool {
	n := 0
	for _, t := range rec.failures {
		if !t.Before(cutoff) {
			n++
		}
	}
	return n >= b.accountThreshold
}

func (b *bruteForce) logFullLocked(table string) {
	if !b.fullLogged {
		b.fullLogged = true
		logger.Warn("brute-force table full, new entries are not tracked", "table", table,
			"max_entries", b.maxEntries)
	}
}

// sweepLocked drops entries idle for longer than the window, at most once
// per window/4 so that failures stay cheap. A client's lockout count resets
// with its entry: a long quiet period ends the doubling.
func (b *bruteForce) sweepLocked(now time.Time) {
	if now.Sub(b.lastSweep) < b.window/4 {
		return
	}
	b.lastSweep = now
	for k, rec := range b.ips {
		if now.Sub(rec.lastSeen) > b.window && now.Sub(rec.lockedUntil) > b.window {
			delete(b.ips, k)
		}
	}
	for _, table := range []map[string]*accountRecord{b.accounts, b.adminAccounts} {
		for k, rec := range table {
			if now.Sub(rec.lastSeen) > b.window {
				delete(table, k)
			}
		}
	}
	for k, t := range b.trusted {
		if now.Sub(t) >= trustedFor {
			delete(b.trusted, k)
		}
	}
	if len(b.ips) < b.maxEntries && len(b.accounts) < b.maxEntries && len(b.adminAccounts) < b.maxEntries {
		b.fullLogged = false
	}
}

// ---- admin view -----------------------------------------------------------------

// clientState and accountState are copies made for the admin Security page,
// so that templates never hold the limiter's records or its lock.
type clientState struct {
	Client      string
	Failures    int // within the window
	LockedUntil time.Time
	Lockouts    int
	LastSeen    time.Time // of the last failure
	Sources     sourceCounts
}

type accountState struct {
	Username  string
	Failures  int // within the window
	NextCheck time.Time
	// ThrottledUntil is when the throttle ends unless more failures come:
	// then the oldest failure that keeps it engaged leaves the window.
	ThrottledUntil time.Time
	LastSeen       time.Time // of the last failure
	Sources        sourceCounts
}

// clientStates lists clients that are locked out or whose next lockout
// would be longer than the base duration, most recent activity first. A
// client with only a few failures and no lockout yet is not interesting
// enough for the overview.
func (b *bruteForce) clientStates(now time.Time) []clientState {
	b.mu.Lock()
	var out []clientState
	for k, rec := range b.ips {
		if !now.Before(rec.lockedUntil) && rec.lockouts == 0 {
			continue
		}
		out = append(out, clientState{
			Client:      k,
			Failures:    len(pruneBefore(append([]time.Time(nil), rec.failures...), now.Add(-b.window))),
			LockedUntil: rec.lockedUntil,
			Lockouts:    rec.lockouts,
			LastSeen:    rec.lastSeen,
			Sources:     rec.sources,
		})
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// throttledAccounts lists accounts whose bcrypt checks are currently
// rationed, most recent activity first. An account throttled both on the
// admin login and on WebDAV plus the API is listed once per side.
func (b *bruteForce) throttledAccounts(now time.Time) []accountState {
	b.mu.Lock()
	var out []accountState
	for _, table := range []map[string]*accountRecord{b.accounts, b.adminAccounts} {
		for k, rec := range table {
			recent := pruneBefore(append([]time.Time(nil), rec.failures...), now.Add(-b.window))
			n := len(recent)
			if n < b.accountThreshold {
				continue
			}
			out = append(out, accountState{
				Username:       k,
				Failures:       n,
				NextCheck:      rec.lastCheck.Add(b.accountInterval),
				ThrottledUntil: recent[n-b.accountThreshold].Add(b.window),
				LastSeen:       rec.lastSeen,
				Sources:        rec.sources,
			})
		}
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// activeCounts returns the number of clients locked out and of accounts
// throttled now, for the Activity card.
func (b *bruteForce) activeCounts(now time.Time) (clients, accounts int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, rec := range b.ips {
		if now.Before(rec.lockedUntil) {
			clients++
		}
	}
	cutoff := now.Add(-b.window)
	for _, table := range []map[string]*accountRecord{b.accounts, b.adminAccounts} {
		for _, rec := range table {
			if b.accountThrottledLocked(rec, cutoff) {
				accounts++
			}
		}
	}
	return clients, accounts
}

// unlockClient forgets everything about a client, including its lockout
// count: an admin unlocking a NAT address shared with legitimate users
// should not leave them one mistake away from a doubled lockout.
func (b *bruteForce) unlockClient(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.ips[key]
	delete(b.ips, key)
	return ok
}

// clearAccount ends the throttle of an account on both sides.
func (b *bruteForce) clearAccount(username string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.accounts[username]
	_, okAdmin := b.adminAccounts[username]
	delete(b.accounts, username)
	delete(b.adminAccounts, username)
	return ok || okAdmin
}

// pruneBefore drops timestamps older than cutoff from the sorted slice ts.
func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return append(ts[:0], ts[i:]...)
}

// retryAfterSeconds rounds d up to whole seconds, at least 1, for the
// Retry-After header.
func retryAfterSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return s
}

// tooManyAttempts answers a throttled request with 429 and Retry-After.
func tooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
	http.Error(w, "too many failed logins, try again later", http.StatusTooManyRequests)
}

// logAuthRefused logs a WebDAV, API or share request that gets 429 from the
// limiter, in the style of the admin's "login refused: throttled"; scope
// says whether the client or the account is throttled. username is empty
// for share auth.
func logAuthRefused(r *http.Request, src authSource, username, scope string, wait time.Duration) {
	attrs := []any{"client", remoteIP(r), "source", authSourceNames[src]}
	if username != "" {
		attrs = append(attrs, "username", logUser(username))
	}
	attrs = append(attrs, "scope", scope, "retry_after", wait.Round(time.Second).String())
	logWarnLimited(r, "auth refused: throttled", attrs...)
	countRefusal(r, username, scope)
}

// countRefusal counts a 429 of the brute-force limiter for the limit that
// caused it: scope client is a lockout, scope account a throttle.
func countRefusal(r *http.Request, username, scope string) {
	if scope == "account" {
		stats.refusedAccount(username)
		return
	}
	stats.refusedClient(clientKey(r))
}

// ---- self-clearing per-client limits -----------------------------------------
//
// max_connections_per_ip (conns.go) and the rate limit for requests without
// credentials (unauthLimit below) clear themselves within seconds, so the
// admin cannot unlock them. limitRegistry remembers their refusals for the
// Security page, the Activity card and the rate-limited log lines.

type limitKind int

const (
	limitConns  limitKind = iota // max_connections_per_ip
	limitUnauth                  // unauth_rate, unauth_burst
	numLimitKinds
)

var limitKindNames = [numLimitKinds]string{"connections per IP", "unauthenticated requests"}

// limitActiveFor is how long a refusal keeps a client listed as active, and
// limitLogEvery how often a refusal of the same client and limit is logged.
const (
	limitActiveFor = time.Minute
	limitLogEvery  = time.Minute
)

type limitKey struct {
	client   string // clientKey form
	kind     limitKind
	listener statListener
}

type limitRecord struct {
	refused     int64
	first, last time.Time // refusals
	logged      time.Time // last log line
	suppressed  int64     // refusals not logged since then
}

// limitRegistry is bounded by bruteforce_max_entries like the brute-force
// tables. Records older than 24 h go: the Security page shows no older ones.
type limitRegistry struct {
	maxEntries int

	mu         sync.Mutex
	m          map[limitKey]*limitRecord
	lost       int64 // refused within 24 h but dropped or never tracked
	lastSweep  time.Time
	fullLogged bool
}

var limited = newLimitRegistry(defaultConfig().BruteforceMaxEntries)

func newLimitRegistry(maxEntries int) *limitRegistry {
	return &limitRegistry{maxEntries: maxEntries, m: map[limitKey]*limitRecord{}}
}

// setMaxEntries applies a changed bruteforce_max_entries; a smaller table
// shrinks as entries age out.
func (g *limitRegistry) setMaxEntries(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxEntries = n
}

// refuse records a refusal and reports whether to log it; suppressed is the
// number of refusals of the same client and limit not logged since the last
// line. An untracked refusal (table full) is not logged at all, so that a
// flood from many addresses cannot flood the log either.
func (g *limitRegistry) refuse(k limitKey, now time.Time) (logIt bool, suppressed int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)
	rec := g.m[k]
	if rec == nil {
		if len(g.m) >= g.maxEntries && !g.evictLocked(now) {
			g.lost++
			if !g.fullLogged {
				g.fullLogged = true
				logger.Warn("rate-limited clients table full, new entries are not tracked",
					"max_entries", g.maxEntries)
			}
			return false, 0
		}
		rec = &limitRecord{first: now}
		g.m[k] = rec
	}
	rec.refused++
	rec.last = now
	if now.Sub(rec.logged) < limitLogEvery {
		rec.suppressed++
		return false, 0
	}
	suppressed = rec.suppressed
	rec.logged, rec.suppressed = now, 0
	return true, suppressed
}

// evictLocked drops the record refused longest ago among the inactive ones.
// Active records stay, so that flooding the table from many addresses does
// not hide the client being limited. The scan only runs while the table is
// full.
func (g *limitRegistry) evictLocked(now time.Time) bool {
	var oldest limitKey
	var oldestRec *limitRecord
	for k, rec := range g.m {
		if now.Sub(rec.last) < limitActiveFor {
			continue
		}
		if oldestRec == nil || rec.last.Before(oldestRec.last) {
			oldest, oldestRec = k, rec
		}
	}
	if oldestRec == nil {
		return false
	}
	if now.Sub(oldestRec.last) < 24*time.Hour {
		g.lost++
	}
	delete(g.m, oldest)
	return true
}

// sweepLocked drops records whose last refusal is older than 24 h, at most
// once a minute.
func (g *limitRegistry) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	for k, rec := range g.m {
		if now.Sub(rec.last) >= 24*time.Hour {
			delete(g.m, k)
		}
	}
	if len(g.m) < g.maxEntries {
		g.fullLogged = false
	}
}

// limitState is a copy of one record for the Security page.
type limitState struct {
	limitKey
	limitRecord
}

// states returns the records refused within the last 24 h and the number
// of such refusals that were not tracked.
func (g *limitRegistry) states(now time.Time) ([]limitState, int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]limitState, 0, len(g.m))
	for k, rec := range g.m {
		if now.Sub(rec.last) < 24*time.Hour {
			out = append(out, limitState{k, *rec})
		}
	}
	return out, g.lost
}

// recentlyRefused returns the clients of kind refused within limitActiveFor.
func (g *limitRegistry) recentlyRefused(kind limitKind, now time.Time) map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]bool{}
	for k, rec := range g.m {
		if k.kind == kind && now.Sub(rec.last) < limitActiveFor {
			out[k.client] = true
		}
	}
	return out
}

// logLimitRefusal writes the Warn line of a refusal if the registry allows
// one now.
func logLimitRefusal(k limitKey, now time.Time, msg string, attrs ...any) {
	logIt, suppressed := limited.refuse(k, now)
	if !logIt {
		return
	}
	attrs = append([]any{"client", k.client, "listener", statListenerNames[k.listener]}, attrs...)
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	logger.Warn(msg, attrs...)
}

// ---- rate-limited Warn lines ------------------------------------------------
//
// Some Warn lines can be triggered by a client without valid credentials
// with every request: throttled logins, share auth failures and
// cross-origin admin requests. Each is written at most once per
// limitLogEvery per client and message, and the next line carries the
// number suppressed in between.

type warnKey struct {
	client string // clientKey form
	msg    string
}

type warnRecord struct {
	logged     time.Time // last log line
	suppressed int64     // lines not written since then
}

// warnLimit is bounded by bruteforce_max_entries like the limiter tables.
type warnLimit struct {
	maxEntries int

	mu        sync.Mutex
	m         map[warnKey]*warnRecord
	lastSweep time.Time
}

var warnLimited = newWarnLimit(defaultConfig().BruteforceMaxEntries)

func newWarnLimit(maxEntries int) *warnLimit {
	return &warnLimit{maxEntries: maxEntries, m: map[warnKey]*warnRecord{}}
}

// setMaxEntries applies a changed bruteforce_max_entries.
func (g *warnLimit) setMaxEntries(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxEntries = n
}

// allow reports whether the line k may be written now, and how many lines
// of k were suppressed since the last one. A line that finds the table full
// is not written, so that a flood from many addresses cannot flood the log.
func (g *warnLimit) allow(k warnKey, now time.Time) (bool, int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)
	rec := g.m[k]
	if rec == nil {
		if len(g.m) >= g.maxEntries && !g.evictLocked(now) {
			return false, 0
		}
		rec = &warnRecord{}
		g.m[k] = rec
	}
	if now.Sub(rec.logged) < limitLogEvery {
		rec.suppressed++
		return false, 0
	}
	suppressed := rec.suppressed
	rec.logged, rec.suppressed = now, 0
	return true, suppressed
}

// idle reports whether rec has the same effect as no record.
func (rec *warnRecord) idle(now time.Time) bool {
	return rec.suppressed == 0 && now.Sub(rec.logged) >= limitLogEvery
}

// evictLocked drops an idle record, or else the one logged longest ago
// whose interval is over. Records within their interval stay, so that a
// flood from many addresses does not reopen the log for one client.
func (g *warnLimit) evictLocked(now time.Time) bool {
	var oldest warnKey
	var oldestRec *warnRecord
	for k, rec := range g.m {
		if rec.idle(now) {
			delete(g.m, k)
			return true
		}
		if now.Sub(rec.logged) < limitLogEvery {
			continue
		}
		if oldestRec == nil || rec.logged.Before(oldestRec.logged) {
			oldest, oldestRec = k, rec
		}
	}
	if oldestRec == nil {
		return false
	}
	delete(g.m, oldest)
	return true
}

// sweepLocked drops idle records and those logged more than 24 h ago, at
// most once a minute.
func (g *warnLimit) sweepLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Minute {
		return
	}
	g.lastSweep = now
	for k, rec := range g.m {
		if rec.idle(now) || now.Sub(rec.logged) >= 24*time.Hour {
			delete(g.m, k)
		}
	}
}

// logWarnLimited writes a Warn line triggered by r if warnLimited allows
// one for the client of r and msg now.
func logWarnLimited(r *http.Request, msg string, attrs ...any) {
	ok, suppressed := warnLimited.allow(warnKey{clientKey(r), msg}, time.Now())
	if !ok {
		return
	}
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	logger.Warn(msg, attrs...)
}

// unauthLimit is a token bucket per client for WebDAV requests without
// credentials. Scanners send hundreds of those per second; a real client
// sends one or two before it adds its credentials. An idle bucket (full
// again) is equivalent to none, so the table only holds clients active
// within the last seconds.
type unauthLimit struct {
	rate, burst float64
	maxEntries  int

	mu         sync.Mutex
	buckets    map[netip.Prefix]*tokenBucket
	lastSweep  time.Time
	fullLogged bool
}

type tokenBucket struct {
	tokens float64
	at     time.Time // of tokens
}

// unauthLimiter is set in main from the configuration.
var unauthLimiter = newUnauthLimit(defaultConfig())

func newUnauthLimit(c Config) *unauthLimit {
	return &unauthLimit{
		rate:       float64(c.UnauthRate),
		burst:      float64(c.UnauthBurst),
		maxEntries: c.BruteforceMaxEntries,
		buckets:    map[netip.Prefix]*tokenBucket{},
	}
}

// setParams applies changed settings; buckets are kept and capped at the
// new burst when they are next used.
func (u *unauthLimit) setParams(c *Config) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rate, u.burst, u.maxEntries = float64(c.UnauthRate), float64(c.UnauthBurst), c.BruteforceMaxEntries
}

// level is the bucket's content at now, without changing it.
func (u *unauthLimit) level(b *tokenBucket, now time.Time) float64 {
	return min(u.burst, b.tokens+now.Sub(b.at).Seconds()*u.rate)
}

// allow takes a token for client p. Without one it returns the wait until
// the next token.
func (u *unauthLimit) allow(p netip.Prefix, now time.Time) (bool, time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.sweepLocked(now)
	b := u.buckets[p]
	if b == nil {
		if len(u.buckets) >= u.maxEntries {
			if !u.fullLogged {
				u.fullLogged = true
				logger.Warn("unauthenticated rate limit table full, evicting active entries",
					"max_entries", u.maxEntries)
			}
			u.evictLocked(now)
		}
		b = &tokenBucket{tokens: u.burst, at: now}
		u.buckets[p] = b
	} else {
		b.tokens, b.at = u.level(b, now), now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, u.waitLocked(b, now)
}

func (u *unauthLimit) waitLocked(b *tokenBucket, now time.Time) time.Duration {
	missing := 1 - u.level(b, now)
	if missing <= 0 {
		return 0
	}
	return time.Duration(missing / u.rate * float64(time.Second))
}

// evictLocked makes room for a new client: an idle bucket if there is one,
// otherwise the one used longest ago. Dropping a busy bucket hands that
// client a fresh burst, which is the price of a bounded table; the
// per-IP connection limit still applies to it.
func (u *unauthLimit) evictLocked(now time.Time) {
	var oldest netip.Prefix
	var oldestAt time.Time
	for p, b := range u.buckets {
		if u.level(b, now) >= u.burst {
			delete(u.buckets, p)
			return
		}
		if oldestAt.IsZero() || b.at.Before(oldestAt) {
			oldest, oldestAt = p, b.at
		}
	}
	delete(u.buckets, oldest)
}

// sweepLocked drops idle buckets, at most once a minute.
func (u *unauthLimit) sweepLocked(now time.Time) {
	if now.Sub(u.lastSweep) < time.Minute {
		return
	}
	u.lastSweep = now
	for p, b := range u.buckets {
		if u.level(b, now) >= u.burst {
			delete(u.buckets, p)
		}
	}
	if len(u.buckets) < u.maxEntries {
		u.fullLogged = false
	}
}

// empty returns the clients without a token now and the wait until each
// gets one.
func (u *unauthLimit) empty(now time.Time) map[string]time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := map[string]time.Duration{}
	for p, b := range u.buckets {
		if u.level(b, now) < 1 {
			out[prefixKey(p)] = u.waitLocked(b, now)
		}
	}
	return out
}

// checkUnauthRate applies the unauthenticated rate limit to r, a WebDAV
// request without credentials, and answers it with 429 if the client has no
// token left. It reports whether it answered.
func checkUnauthRate(w http.ResponseWriter, r *http.Request) bool {
	p, ok := requestPrefix(r)
	if !ok {
		return false
	}
	now := time.Now()
	allowed, wait := unauthLimiter.allow(p, now)
	if allowed {
		return false
	}
	key := prefixKey(p)
	stats.unauthRefused(key)
	logLimitRefusal(limitKey{key, limitUnauth, statWebDAV}, now, "unauthenticated requests throttled",
		"rate", conf().UnauthRate, "burst", conf().UnauthBurst)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
	http.Error(w, "too many requests without credentials, try again later", http.StatusTooManyRequests)
	return true
}

// ---- user authentication with limits ----------------------------------------

// authResult is the outcome of a rate-limited user authentication.
type authResult int

const (
	authOK authResult = iota
	authBad
	authThrottled
)

// authenticateUserLimited checks Basic Auth credentials of a user on the
// WebDAV or API path. method is cache, bcrypt, blocked or invalid (a
// username usernameRE rejects) for the request log. wait is the Retry-After
// for authThrottled. A non-nil error means the answer is unknown (DB
// failure) and nothing was counted.
//
// Only accounts with role "user" may log in here. An admin account would
// otherwise reach the internet-facing listener with its password alone,
// without the second factor the admin UI demands. A correct admin password
// is answered exactly like a wrong one and counted by the limiter like
// one: if it were not counted, a guesser could tell it apart by the
// lockout that never comes.
func authenticateUserLimited(r *http.Request, username, password string) (res authResult, method string, wait time.Duration, err error) {
	if !usernameRE.MatchString(username) {
		res, method, wait = rejectInvalidUsername(r, username)
		return res, method, wait, nil
	}
	// The cache comes first so that devices already logged in keep working
	// while their shared NAT address is locked out by someone else.
	hit, epoch := authCache.lookup(username, password)
	if hit {
		// The cache only holds user accounts, but the role can change
		// after an entry was stored (directly in the database, for
		// example). A role that is no longer "user" drops the entry and
		// takes the full path below, which refuses it.
		role, err := userRole(username)
		if err != nil {
			return authBad, "cache", 0, err
		}
		if role == "user" {
			limiter.succeed(clientKey(r), username, authSrcUser)
			return authOK, "cache", 0, nil
		}
		authCache.invalidate(username)
		_, epoch = authCache.lookup(username, password)
	}
	ip := clientKey(r)
	if locked, d := limiter.ipLocked(ip); locked {
		logAuthRefused(r, authSrcUser, username, "client", d)
		return authThrottled, "blocked", d, nil
	}
	if ok, d := limiter.reserveAccountCheck(ip, username, authSrcUser); !ok {
		logAuthRefused(r, authSrcUser, username, "account", d)
		return authThrottled, "blocked", d, nil
	}
	ok, role, err := checkPasswordRole(username, password)
	if err != nil {
		return authBad, "bcrypt", 0, err
	}
	if !ok {
		// Before fail, so that a lockout this attempt starts is logged after
		// the attempt itself.
		logger.Warn("webdav auth failed", "username", logUser(username), "client", remoteIP(r),
			"method", logValue(r.Method), "path", logValue(r.URL.Path))
		stats.authFailed(r, failUser, username)
		limiter.fail(ip, username, authSrcUser)
		return authBad, "bcrypt", 0, nil
	}
	if role != "user" {
		logger.Warn("webdav auth refused: admin account", "username", logUser(username), "client", remoteIP(r),
			"method", logValue(r.Method), "path", logValue(r.URL.Path))
		stats.authFailed(r, failUser, username)
		limiter.fail(ip, username, authSrcUser)
		return authBad, "bcrypt", 0, nil
	}
	authCache.store(username, password, epoch)
	limiter.succeed(ip, username, authSrcUser)
	return authOK, "bcrypt", 0, nil
}

// rejectInvalidUsername answers a user login whose username usernameRE
// rejects. No such account can exist, so no account throttle and no bcrypt
// check is involved and the name becomes no limiter key. The attempt is
// answered and counted toward the client's lockout like a wrong password.
func rejectInvalidUsername(r *http.Request, username string) (authResult, string, time.Duration) {
	ip := clientKey(r)
	if locked, d := limiter.ipLocked(ip); locked {
		logAuthRefused(r, authSrcUser, username, "client", d)
		return authThrottled, "blocked", d
	}
	logger.Warn("webdav auth failed", "username", logUser(username), "client", remoteIP(r),
		"method", logValue(r.Method), "path", logValue(r.URL.Path), "reason", "invalid username")
	stats.authFailed(r, failUser, username)
	limiter.fail(ip, "", authSrcUser)
	return authBad, "invalid", 0
}
