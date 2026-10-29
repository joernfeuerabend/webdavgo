// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// stats.go – traffic and authentication statistics of the last 24 h for the
// Activity card on the Status page (concept 6e, 4i). Everything lives in
// memory and starts at zero with the process.
//
// Counters sit in 5-minute slots (288 for 24 h), top lists and distinct
// counts in hourly buckets (24). Both rings rotate lazily: the first event
// of a new period swaps a fresh slot in with a compare-and-swap, so the
// request path and the per-read byte counting only ever use atomic
// operations. An event racing with the swap may land in the replaced slot;
// at a 5-minute boundary that loss is irrelevant for a status page.

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	statSlotSeconds = 300 // one counter slot
	statSlots       = 24 * 3600 / statSlotSeconds
	statHours       = 24
	// statMaxKeys bounds every hourly map: an attacker cycling through
	// addresses or usernames must not grow memory without limit.
	statMaxKeys = 1000
	// statKeyBytes caps a stored username; real ones are at most 32 bytes
	// (usernameRE), anything longer is an attacker's string.
	statKeyBytes = 64
	statTopN     = 5
)

// statListener indexes the per-listener counters.
type statListener int

const (
	statWebDAV statListener = iota
	statAdmin
	numStatListeners
)

var statListenerNames = [numStatListeners]string{"webdav", "admin"}

// statListenerIndex maps the listener name used by newServer and the
// connection list to its counters.
func statListenerIndex(name string) statListener {
	if name == "admin" {
		return statAdmin
	}
	return statWebDAV
}

// failSource is where a failed attempt came from. It splits the admin login
// into password and second factor, which the limiter counts as one source.
type failSource int

const (
	failUser          failSource = iota // user Basic Auth on WebDAV and /api/v1/
	failShare                           // share token on /s/<id>
	failAdminPassword                   // admin login password
	failAdminSecond                     // TOTP, recovery and own-TOTP-reset codes
	numFailSources
)

var failSourceNames = [numFailSources]string{"WebDAV user", "share token", "admin password", "admin second factor"}

// statSlot holds the counters of one 5-minute period.
type statSlot struct {
	epoch     int64 // unix seconds / statSlotSeconds
	conns     [numStatListeners]atomic.Int64
	peak      [numStatListeners]atomic.Int64
	requests  [numStatListeners][4]atomic.Int64 // 2xx, 3xx, 4xx, 5xx
	rx, tx    [numStatListeners]atomic.Int64
	tlsErrors [numStatListeners]atomic.Int64
	// clientPeak is the most connections one client opened at once.
	clientPeak  [numStatListeners]atomic.Int64
	unauth401   atomic.Int64 // WebDAV only: the admin listener never answers 401
	connRefused [numStatListeners]atomic.Int64
	fails       [numFailSources]atomic.Int64
	expired     atomic.Int64
	logins      atomic.Int64
	lockouts    atomic.Int64
	throttles   atomic.Int64
	// 429 of the brute-force limiter, by the limit that caused it.
	refusedClient  atomic.Int64
	refusedAccount atomic.Int64
	unauthRefused  atomic.Int64
}

// keyEntry is one key of an hourly bucket. Identity buckets use last only.
type keyEntry struct {
	n     atomic.Int64
	bySrc [numFailSources]atomic.Int64
	last  atomic.Int64 // unix seconds of the latest event
}

type keyBucket struct {
	hour     int64 // unix seconds / 3600
	size     atomic.Int64
	overflow atomic.Int64 // events whose key did not fit any more
	m        sync.Map     // string -> *keyEntry
}

// entry returns the entry for key, creating it while the bucket has room,
// or nil if it is full.
func (b *keyBucket) entry(key string) *keyEntry {
	if v, ok := b.m.Load(key); ok {
		return v.(*keyEntry)
	}
	if b.size.Add(1) > statMaxKeys {
		b.size.Add(-1)
		b.overflow.Add(1)
		return nil
	}
	v, loaded := b.m.LoadOrStore(key, &keyEntry{})
	if loaded {
		b.size.Add(-1)
	}
	return v.(*keyEntry)
}

type keyRing [statHours]atomic.Pointer[keyBucket]

func (kr *keyRing) bucket(now time.Time) *keyBucket {
	h := now.Unix() / 3600
	p := &kr[h%statHours]
	for {
		b := p.Load()
		if b != nil && b.hour >= h {
			return b
		}
		nb := &keyBucket{hour: h}
		if p.CompareAndSwap(b, nb) {
			return nb
		}
	}
}

// buckets returns the buckets of the last 24 hours, the current one
// included.
func (kr *keyRing) buckets(now time.Time) []*keyBucket {
	h := now.Unix() / 3600
	var out []*keyBucket
	for i := range kr {
		if b := kr[i].Load(); b != nil && b.hour > h-statHours && b.hour <= h {
			out = append(out, b)
		}
	}
	return out
}

// distinct counts the keys seen since hourAgo and since dayAgo.
func (kr *keyRing) distinct(now time.Time) (hour, day int) {
	last := map[string]int64{}
	for _, b := range kr.buckets(now) {
		b.m.Range(func(k, v any) bool {
			if t := v.(*keyEntry).last.Load(); t > last[k.(string)] {
				last[k.(string)] = t
			}
			return true
		})
	}
	hourAgo, dayAgo := now.Add(-time.Hour).Unix(), now.Add(-24*time.Hour).Unix()
	for _, t := range last {
		if t >= dayAgo {
			day++
		}
		if t >= hourAgo {
			hour++
		}
	}
	return hour, day
}

// overflow counts the events of the last 24 hours whose key did not fit.
func (kr *keyRing) overflow(now time.Time) int64 {
	var n int64
	for _, b := range kr.buckets(now) {
		n += b.overflow.Load()
	}
	return n
}

// keyTotal is a key's failures summed over the hourly buckets.
type keyTotal struct {
	key   string
	n     int64
	bySrc [numFailSources]int64
}

// top returns the keys with the most failures in the last 24 hours and the
// number of failures that were not tracked because a bucket was full.
func (kr *keyRing) top(now time.Time) ([]keyTotal, int64) {
	sums := map[string]*keyTotal{}
	var overflow int64
	for _, b := range kr.buckets(now) {
		overflow += b.overflow.Load()
		b.m.Range(func(k, v any) bool {
			e := v.(*keyEntry)
			t := sums[k.(string)]
			if t == nil {
				t = &keyTotal{key: k.(string)}
				sums[t.key] = t
			}
			t.n += e.n.Load()
			for i := range t.bySrc {
				t.bySrc[i] += e.bySrc[i].Load()
			}
			return true
		})
	}
	out := make([]keyTotal, 0, len(sums))
	for _, t := range sums {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	if len(out) > statTopN {
		out = out[:statTopN]
	}
	return out, overflow
}

type statsCollector struct {
	start time.Time
	open  [numStatListeners]atomic.Int64
	slots [statSlots]atomic.Pointer[statSlot]

	failIPs   keyRing // full client IP
	failUsers keyRing // attempted username, WebDAV user and admin
	users     keyRing // successfully authenticated users
	shares    keyRing // successfully authenticated share IDs
	unauthIPs keyRing // full client IP of 401 responses to requests without credentials

	// Clients (client keys) and accounts an automatic limit held back: a
	// lockout or throttle that started, or a request or connection refused.
	limitedKeys [numLimitTypes]keyRing
}

// limitType is a block of the Activity card's "Automatic limits" group.
type limitType int

const (
	limitTypeLockout limitType = iota
	limitTypeThrottle
	limitTypeConns
	limitTypeUnauth
	numLimitTypes
)

var stats = &statsCollector{start: time.Now()}

func (s *statsCollector) slot(now time.Time) *statSlot {
	e := now.Unix() / statSlotSeconds
	p := &s.slots[e%statSlots]
	for {
		d := p.Load()
		if d != nil && d.epoch >= e {
			return d
		}
		nd := &statSlot{epoch: e}
		// Connections open across the boundary count toward the new
		// period's peak, even if none opens in it.
		for l := range nd.peak {
			nd.peak[l].Store(s.open[l].Load())
		}
		if p.CompareAndSwap(d, nd) {
			return nd
		}
	}
}

// ---- recording ----------------------------------------------------------------

func (s *statsCollector) connOpened(l statListener) {
	n := s.open[l].Add(1)
	d := s.slot(time.Now())
	d.conns[l].Add(1)
	for {
		p := d.peak[l].Load()
		if n <= p || d.peak[l].CompareAndSwap(p, n) {
			return
		}
	}
}

func (s *statsCollector) connClosed(l statListener) {
	// Touching the slot first records the count before the close as the
	// peak of a period that had no other event yet.
	s.slot(time.Now())
	s.open[l].Add(-1)
}

// request counts a finished request by its status class; status 0 means
// the handler wrote nothing, which net/http sends as 200.
func (s *statsCollector) request(l statListener, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	if c := status/100 - 2; c >= 0 && c < 4 {
		s.slot(time.Now()).requests[l][c].Add(1)
	}
}

func (s *statsCollector) received(l statListener, n int) {
	s.slot(time.Now()).rx[l].Add(int64(n))
}

func (s *statsCollector) sent(l statListener, n int) {
	s.slot(time.Now()).tx[l].Add(int64(n))
}

// clientConns records that one client holds n connections on l.
func (s *statsCollector) clientConns(l statListener, n int) {
	p := &s.slot(time.Now()).clientPeak[l]
	for {
		old := p.Load()
		if int64(n) <= old || p.CompareAndSwap(old, int64(n)) {
			return
		}
	}
}

func (s *statsCollector) tlsError(l statListener) { s.slot(time.Now()).tlsErrors[l].Add(1) }
func (s *statsCollector) shareExpired()           { s.slot(time.Now()).expired.Add(1) }
func (s *statsCollector) adminLogin()             { s.slot(time.Now()).logins.Add(1) }

// unauthenticated counts a WebDAV request answered 401 without credentials
// having been sent, under the full client IP for the top list.
func (s *statsCollector) unauthenticated(r *http.Request) {
	now := time.Now()
	s.slot(now).unauth401.Add(1)
	if e := s.unauthIPs.bucket(now).entry(remoteIP(r)); e != nil {
		e.n.Add(1)
		e.last.Store(now.Unix())
	}
}

// The limit events take the client key (accounts: the username), so that
// "clients limited" counts what the limits count.
func (s *statsCollector) lockoutStarted(key string) {
	s.slot(time.Now()).lockouts.Add(1)
	s.limited(limitTypeLockout, key)
}

func (s *statsCollector) throttleEngaged(username string) {
	s.slot(time.Now()).throttles.Add(1)
	s.limited(limitTypeThrottle, truncateKey(username))
}

func (s *statsCollector) refusedClient(key string) {
	s.slot(time.Now()).refusedClient.Add(1)
	s.limited(limitTypeLockout, key)
}

func (s *statsCollector) refusedAccount(username string) {
	s.slot(time.Now()).refusedAccount.Add(1)
	s.limited(limitTypeThrottle, truncateKey(username))
}

func (s *statsCollector) connRefused(l statListener, key string) {
	s.slot(time.Now()).connRefused[l].Add(1)
	s.limited(limitTypeConns, key)
}

func (s *statsCollector) unauthRefused(key string) {
	s.slot(time.Now()).unauthRefused.Add(1)
	s.limited(limitTypeUnauth, key)
}

func (s *statsCollector) limited(t limitType, key string) { seen(&s.limitedKeys[t], key) }

// authFailed counts a failed attempt from the client of r. username is the
// attempted one; share failures have none.
func (s *statsCollector) authFailed(r *http.Request, src failSource, username string) {
	now := time.Now()
	s.slot(now).fails[src].Add(1)
	addFailure(s.failIPs.bucket(now).entry(remoteIP(r)), src, now)
	if src != failShare {
		addFailure(s.failUsers.bucket(now).entry(truncateKey(username)), src, now)
	}
}

func addFailure(e *keyEntry, src failSource, now time.Time) {
	if e == nil {
		return
	}
	e.n.Add(1)
	e.bySrc[src].Add(1)
	e.last.Store(now.Unix())
}

// userActive and shareActive run on every authenticated request; once the
// key exists in the current hour they cost a map read and an atomic store.
func (s *statsCollector) userActive(username string) { seen(&s.users, username) }
func (s *statsCollector) shareActive(id string)      { seen(&s.shares, id) }

func seen(kr *keyRing, key string) {
	now := time.Now()
	if e := kr.bucket(now).entry(key); e != nil {
		if t := now.Unix(); e.last.Load() != t {
			e.last.Store(t)
		}
	}
}

func truncateKey(s string) string {
	if len(s) <= statKeyBytes {
		return s
	}
	return strings.ToValidUTF8(s[:statKeyBytes], "") + "…"
}

// ---- view ---------------------------------------------------------------------

// activityRow is one metric with its value over the last hour and the last
// 24 h. Group starts a new section; Now marks a current value that spans
// both columns.
type activityRow struct {
	Group, Label, Hour, Day string
	Now                     bool
}

type topRow struct {
	Key     string
	Sources []string // "<source>: <count>", one entry per source with failures
	Count   int64
	Known   bool // usernames: the account exists
}

type chartBar struct {
	Label, Title string
	Segments     []chartSegment
}

type chartSegment struct {
	Class string // colour of the source and quantised height
}

type activityView struct {
	DayHeader             string
	Traffic, Auth, Limits []activityRow
	TopIPs                []topRow
	TopUsers              []topRow
	TopUnauth             []topRow
	IPOverflow            int64
	UserOverflow          int64
	UnauthOverflow        int64
	Chart                 []chartBar
	ChartEmpty            bool
	Sources               []string // chart legend, in the order of the src-N classes
	UpdatedAt             string
}

// slotSums adds up the slots from the last n periods, the current one
// included.
type slotSums struct {
	conns, peak, rx, tx, tlsErrors [numStatListeners]int64
	clientPeak, connRefused        [numStatListeners]int64
	requests                       [numStatListeners][4]int64
	fails                          [numFailSources]int64
	expired, logins, lockouts      int64
	throttles, unauth401           int64
	refusedClient, refusedAccount  int64
	unauthRefused                  int64
}

func (s *statsCollector) sums(now time.Time, n int64) slotSums {
	e := now.Unix() / statSlotSeconds
	var t slotSums
	for i := range s.slots {
		d := s.slots[i].Load()
		if d == nil || d.epoch <= e-n || d.epoch > e {
			continue
		}
		for l := range numStatListeners {
			t.conns[l] += d.conns[l].Load()
			t.peak[l] = max(t.peak[l], d.peak[l].Load())
			t.rx[l] += d.rx[l].Load()
			t.tx[l] += d.tx[l].Load()
			t.tlsErrors[l] += d.tlsErrors[l].Load()
			t.clientPeak[l] = max(t.clientPeak[l], d.clientPeak[l].Load())
			t.connRefused[l] += d.connRefused[l].Load()
			for c := range t.requests[l] {
				t.requests[l][c] += d.requests[l][c].Load()
			}
		}
		for f := range t.fails {
			t.fails[f] += d.fails[f].Load()
		}
		t.expired += d.expired.Load()
		t.logins += d.logins.Load()
		t.lockouts += d.lockouts.Load()
		t.throttles += d.throttles.Load()
		t.unauth401 += d.unauth401.Load()
		t.refusedClient += d.refusedClient.Load()
		t.refusedAccount += d.refusedAccount.Load()
		t.unauthRefused += d.unauthRefused.Load()
	}
	for l := range numStatListeners {
		t.peak[l] = max(t.peak[l], s.open[l].Load())
		// Like peak: connections held since an earlier period count, too.
		t.clientPeak[l] = max(t.clientPeak[l], int64(connLimits[l].maxOpen()))
	}
	return t
}

// periods returns the sums of the last hour and the last 24 h, and the
// header of the second period, with the restart in brackets while the
// process is younger than 24 h.
func (s *statsCollector) periods(now time.Time) (hour, day slotSums, dayHeader string) {
	hour = s.sums(now, 3600/statSlotSeconds)
	day = s.sums(now, statSlots)
	dayHeader = "last 24 h"
	// The counters are in memory: after a restart the column covers less
	// than its label, which the note in brackets says.
	if up := now.Sub(s.start); up < 24*time.Hour {
		ago := "<1 h"
		if up >= time.Hour {
			ago = fmt.Sprintf("%d h", int(up.Hours()))
		}
		dayHeader = "last 24 h (restarted " + ago + " ago)"
	}
	return hour, day, dayHeader
}

// trafficRows are listener l's rows of the Traffic table. unauth adds the
// WebDAV-only count of 401s without credentials.
func (s *statsCollector) trafficRows(l statListener, hour, day slotSums, unauth bool) []activityRow {
	num := func(n int64) string { return fmt.Sprint(n) }
	classes := func(t slotSums) string {
		r := t.requests[l]
		return fmt.Sprintf("%d · %d · %d · %d", r[0], r[1], r[2], r[3])
	}
	bytes := func(t slotSums) string { return formatBytes(t.rx[l]) + " / " + formatBytes(t.tx[l]) }
	rows := []activityRow{
		{Label: "Open connections", Hour: num(s.open[l].Load()), Now: true},
		{Label: "Peak open connections", Hour: num(hour.peak[l]), Day: num(day.peak[l])},
		{Label: "Peak open connections from a single client", Hour: num(hour.clientPeak[l]), Day: num(day.clientPeak[l])},
		{Label: "New connections", Hour: num(hour.conns[l]), Day: num(day.conns[l])},
		{Label: "Requests 2xx · 3xx · 4xx · 5xx", Hour: classes(hour), Day: classes(day)},
	}
	if unauth {
		rows = append(rows, activityRow{Label: "Unauthenticated 401", Hour: num(hour.unauth401), Day: num(day.unauth401)})
	}
	return append(rows,
		activityRow{Label: "Received / sent", Hour: bytes(hour), Day: bytes(day)},
		activityRow{Label: "TLS handshake errors", Hour: num(hour.tlsErrors[l]), Day: num(day.tlsErrors[l])},
	)
}

// webdavActivity is the Dashboard's WebDAV block: all of the WebDAV
// listener's Traffic rows of the Activity card, without the admin listener.
type webdavActivity struct {
	DayHeader, UpdatedAt string
	Tiles                []activityRow
}

func (s *statsCollector) webdavView(now time.Time) webdavActivity {
	hour, day, dayHeader := s.periods(now)
	return webdavActivity{DayHeader: dayHeader, UpdatedAt: formatStatusTime(now),
		Tiles: s.trafficRows(statWebDAV, hour, day, true)}
}

// view prepares the Activity card. Usernames of the top list are looked up
// now, so "exists" reflects the accounts as they are, not as they were.
func (s *statsCollector) view(now time.Time) activityView {
	hour, day, dayHeader := s.periods(now)
	v := activityView{DayHeader: dayHeader, UpdatedAt: formatStatusTime(now)}

	num := func(n int64) string { return fmt.Sprint(n) }
	for l := range numStatListeners {
		rows := s.trafficRows(l, hour, day, l == statWebDAV)
		rows[0].Group = statListenerNames[l]
		v.Traffic = append(v.Traffic, rows...)
	}

	var failHour, failDay int64
	for f := range numFailSources {
		failHour += hour.fails[f]
		failDay += day.fails[f]
	}
	v.Auth = append(v.Auth, activityRow{Group: "Failed attempts", Label: "Total", Hour: num(failHour), Day: num(failDay)})
	for f := range numFailSources {
		v.Auth = append(v.Auth, activityRow{Label: failSourceNames[f], Hour: num(hour.fails[f]), Day: num(day.fails[f])})
	}
	ips, ipOver := s.failIPs.top(now)
	ipHour, ipDay := s.failIPs.distinct(now)
	// Untracked attempts may come from further addresses.
	atLeast := ""
	if ipOver > 0 {
		atLeast = "≥ "
	}
	userHour, userDay := s.users.distinct(now)
	shareHour, shareDay := s.shares.distinct(now)
	v.Auth = append(v.Auth,
		activityRow{Label: "Client IPs with failed attempts", Hour: atLeast + fmt.Sprint(ipHour), Day: atLeast + fmt.Sprint(ipDay)},
		activityRow{Label: "Expired share tokens used (not counted as failures)", Hour: num(hour.expired), Day: num(day.expired)},
		activityRow{Group: "Successful", Label: "Active users", Hour: fmt.Sprint(userHour), Day: fmt.Sprint(userDay)},
		activityRow{Label: "Active shares", Hour: fmt.Sprint(shareHour), Day: fmt.Sprint(shareDay)},
		activityRow{Label: "Admin logins", Hour: num(hour.logins), Day: num(day.logins)},
	)
	v.Limits = s.limitRows(now, hour, day)

	for _, t := range ips {
		v.TopIPs = append(v.TopIPs, topRow{Key: t.key, Count: t.n, Sources: sourceDetail(t.bySrc)})
	}
	users, userOver := s.failUsers.top(now)
	for _, t := range users {
		key := t.key
		if key == "" {
			key = "(empty)"
		}
		v.TopUsers = append(v.TopUsers, topRow{Key: key, Count: t.n, Sources: sourceDetail(t.bySrc),
			Known: t.key != "" && userExists(t.key)})
	}
	v.IPOverflow, v.UserOverflow = ipOver, userOver
	unauth, unauthOver := s.unauthIPs.top(now)
	for _, t := range unauth {
		v.TopUnauth = append(v.TopUnauth, topRow{Key: t.key, Count: t.n})
	}
	v.UnauthOverflow = unauthOver

	v.Chart, v.ChartEmpty = s.chart(now)
	v.Sources = failSourceNames[:]
	return v
}

// limitRows is the "Automatic limits" group: per limit what holds clients
// back now, how many were held back, and what was refused. The current
// state comes from the limiters themselves; the rest from the slots and
// rings.
func (s *statsCollector) limitRows(now time.Time, hour, day slotSums) []activityRow {
	num := func(n int64) string { return fmt.Sprint(n) }
	keys := func(t limitType) (string, string) {
		h, d := s.limitedKeys[t].distinct(now)
		atLeast := ""
		if s.limitedKeys[t].overflow(now) > 0 {
			atLeast = "≥ "
		}
		return atLeast + fmt.Sprint(h), atLeast + fmt.Sprint(d)
	}
	locked, throttled := limiter.activeCounts(now)

	connActive := limited.recentlyRefused(limitConns, now)
	for l := range numStatListeners {
		for _, k := range connLimits[l].atLimit() {
			connActive[k] = true
		}
	}
	unauthActive := limited.recentlyRefused(limitUnauth, now)
	for k := range unauthLimiter.empty(now) {
		unauthActive[k] = true
	}
	perListener := func(t slotSums) string {
		return fmt.Sprintf("%d · %d", t.connRefused[statWebDAV], t.connRefused[statAdmin])
	}

	lockH, lockD := keys(limitTypeLockout)
	thrH, thrD := keys(limitTypeThrottle)
	connH, connD := keys(limitTypeConns)
	unauthH, unauthD := keys(limitTypeUnauth)
	return []activityRow{
		{Group: "Client lockouts", Label: "Locked out now", Hour: fmt.Sprint(locked), Now: true},
		{Label: "Clients limited", Hour: lockH, Day: lockD},
		{Label: "Lockouts started", Hour: num(hour.lockouts), Day: num(day.lockouts)},
		{Label: "Requests refused with 429", Hour: num(hour.refusedClient), Day: num(day.refusedClient)},
		{Group: "Account throttles", Label: "Throttled now", Hour: fmt.Sprint(throttled), Now: true},
		{Label: "Accounts limited", Hour: thrH, Day: thrD},
		{Label: "Account throttles engaged", Hour: num(hour.throttles), Day: num(day.throttles)},
		{Label: "Requests refused with 429", Hour: num(hour.refusedAccount), Day: num(day.refusedAccount)},
		{Group: "Per-IP connection limit", Label: "Active now", Hour: fmt.Sprint(len(connActive)), Now: true},
		{Label: "Clients limited", Hour: connH, Day: connD},
		{Label: "Connections refused, webdav · admin", Hour: perListener(hour), Day: perListener(day)},
		{Group: "Unauthenticated rate limit", Label: "Active now", Hour: fmt.Sprint(len(unauthActive)), Now: true},
		{Label: "Clients limited", Hour: unauthH, Day: unauthD},
		{Label: "Requests refused with 429", Hour: num(hour.unauthRefused), Day: num(day.unauthRefused)},
	}
}

// sourceDetail lists the sources that failed, as the Sources column shows
// them: one entry per line, so each can wrap as a whole.
func sourceDetail(bySrc [numFailSources]int64) []string {
	var parts []string
	for f, n := range bySrc {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", failSourceNames[f], n))
		}
	}
	return parts
}

// chartSteps is the height resolution of a bar: the CSP forbids inline
// styles, so heights are classes h1…h20 in steps of 5 %.
const chartSteps = 20

// chart returns one bar per clock hour of the last 24 hours (UTC), stacked
// by source, scaled to the busiest hour.
func (s *statsCollector) chart(now time.Time) ([]chartBar, bool) {
	h := now.Unix() / 3600
	var perHour [statHours][numFailSources]int64
	e := now.Unix() / statSlotSeconds
	for i := range s.slots {
		d := s.slots[i].Load()
		if d == nil || d.epoch > e {
			continue
		}
		age := h - d.epoch*statSlotSeconds/3600
		if age < 0 || age >= statHours {
			continue
		}
		for f := range numFailSources {
			perHour[statHours-1-age][f] += d.fails[f].Load()
		}
	}
	var peak int64
	for _, hs := range perHour {
		var t int64
		for _, n := range hs {
			t += n
		}
		peak = max(peak, t)
	}
	bars := make([]chartBar, statHours)
	for i, hs := range perHour {
		start := time.Unix((h-int64(statHours-1-i))*3600, 0).UTC()
		var total int64
		parts := make([]string, 0, numFailSources)
		for f, n := range hs {
			total += n
			parts = append(parts, fmt.Sprintf("%s %d", failSourceNames[f], n))
		}
		b := chartBar{Title: fmt.Sprintf("%s–%s UTC: %d failed (%s)", start.Format("15:04"),
			start.Add(time.Hour).Format("15:04"), total, strings.Join(parts, ", "))}
		if start.Hour()%6 == 0 {
			b.Label = start.Format("15h")
		}
		if total > 0 {
			// At least one step, so that a single failure stays visible
			// next to a busy hour; cumulative rounding keeps the segments
			// adding up to the bar.
			steps := max(1, int((total*chartSteps+peak/2)/peak))
			var cum int64
			prev := 0
			for f, n := range hs {
				cum += n
				top := int((cum*int64(steps) + total/2) / total)
				if top > prev {
					b.Segments = append(b.Segments, chartSegment{Class: fmt.Sprintf("src-%d h%d", f, top-prev)})
				}
				prev = top
			}
		}
		bars[i] = b
	}
	return bars, peak == 0
}
