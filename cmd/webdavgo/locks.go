// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// locks.go: WebDAV locking (RFC 4918 §6, §7, §9.10, §9.11) and the If header
// (§10.4). One lockManager per user holds the locks and the running writes, for
// the user endpoint and the user's shares. x/net/webdav still performs the file
// operations, but takes no part in any lock decision: see noLockSystem.

import (
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/webdav"
)

// noLockSystem is the webdav.LockSystem x/net requires. Its temporary locks
// would answer 423 for state no client created, and its tokens would be
// consecutive numbers. Isolation comes from lockPaths instead, and serveDAV
// removes the If header, so only Create and Unlock are ever called.
type noLockSystem struct{}

func (noLockSystem) Confirm(time.Time, string, string, ...webdav.Condition) (func(), error) {
	return func() {}, nil
}

func (noLockSystem) Create(time.Time, webdav.LockDetails) (string, error) { return "none", nil }

func (noLockSystem) Refresh(time.Time, string, time.Duration) (webdav.LockDetails, error) {
	return webdav.LockDetails{}, webdav.ErrNoSuchLock
}

func (noLockSystem) Unlock(time.Time, string) error { return nil }

// activeLock is one lock created by LOCK.
type activeLock struct {
	Root      string
	Token     string
	OwnerXML  string // the complete DAV:owner element, self-contained
	ZeroDepth bool
	Shared    bool
	// Expiry is the zero time for a lock with an infinite timeout.
	Expiry time.Time
}

// covers reports whether the lock applies to the named resource.
func (l *activeLock) covers(name string) bool {
	return name == l.Root || !l.ZeroDepth && isBelow(name, l.Root)
}

// isBelow reports whether name lies strictly below root. Both are cleaned.
func isBelow(name, root string) bool {
	if root == "/" {
		return name != "/"
	}
	return strings.HasPrefix(name, root+"/")
}

// runningWrite is a write between its lock check and its end. tree marks a
// write that affects everything below name, member one that adds or removes
// the URL name in its parent.
type runningWrite struct {
	name   string
	tree   bool
	member bool
}

// lockManager holds the locks of one user. Names are slash paths relative to
// the user's data root. A write registers in writes under mu in the same step
// that checks the locks, so a write and a LOCK cannot both pass.
type lockManager struct {
	root   string
	mu     sync.Mutex
	locks  map[string]*activeLock // by token
	writes []runningWrite
}

func newLockManager(root string) *lockManager {
	return &lockManager{root: root, locks: map[string]*activeLock{}}
}

// nameOf returns the lock name of a filesystem path below the user's root.
func (m *lockManager) nameOf(absPath string) string {
	rel, err := filepath.Rel(m.root, absPath)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

// expire drops locks whose timeout has passed. The caller holds mu.
func (m *lockManager) expire(now time.Time) {
	for token, l := range m.locks {
		if !l.Expiry.IsZero() && !now.Before(l.Expiry) {
			delete(m.locks, token)
		}
	}
}

// covering returns the active locks that apply to name in a stable order. The
// caller holds mu.
func (m *lockManager) covering(name string) []*activeLock {
	var found []*activeLock
	for _, l := range m.locks {
		if l.covers(name) {
			found = append(found, l)
		}
	}
	slices.SortFunc(found, func(a, b *activeLock) int {
		return strings.Compare(a.Root+"\x00"+a.Token, b.Root+"\x00"+b.Token)
	})
	return found
}

// locksOn returns copies of the locks that apply to the named resource at now:
// those rooted on it and those of an ancestor locked with Depth infinity.
func (m *lockManager) locksOn(now time.Time, name string) []activeLock {
	name = path.Clean("/" + name)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(now)
	var found []activeLock
	for _, l := range m.covering(name) {
		found = append(found, *l)
	}
	return found
}

// ---- If header (RFC 4918 §10.4) ---------------------------------------------

// ifCondition is one condition of a list: a state token or an entity tag.
type ifCondition struct {
	not   bool
	token string
	etag  string // as sent, including quotes and any W/ prefix
}

// ifList is one list of conditions, which are ANDed. tag is the raw
// Resource-Tag, empty for a list that applies to the request URI.
type ifList struct {
	tag        string
	conditions []ifCondition
}

// parseIfHeader parses the If header (§10.4.2). A header may not mix tagged and
// untagged lists.
func parseIfHeader(h string) ([]ifList, error) {
	var lists []ifList
	s := strings.TrimSpace(h)
	tag, sawTag := "", false
	for s != "" {
		switch s[0] {
		case '<':
			if !sawTag && len(lists) > 0 {
				return nil, errors.New("resource tag after an untagged list")
			}
			end := strings.IndexByte(s, '>')
			if end < 0 {
				return nil, errors.New("unterminated resource tag")
			}
			tag, sawTag = s[1:end], true
			s = strings.TrimSpace(s[end+1:])
			if !strings.HasPrefix(s, "(") {
				return nil, errors.New("resource tag without a list")
			}
		case '(':
			conditions, rest, err := parseIfConditions(s[1:])
			if err != nil {
				return nil, err
			}
			lists = append(lists, ifList{tag: tag, conditions: conditions})
			s = strings.TrimSpace(rest)
		default:
			return nil, fmt.Errorf("unexpected %q", s[0])
		}
	}
	if len(lists) == 0 {
		return nil, errors.New("no list")
	}
	return lists, nil
}

// parseIfConditions parses the conditions of a list up to and including its
// closing parenthesis and returns what follows.
func parseIfConditions(s string) ([]ifCondition, string, error) {
	var conditions []ifCondition
	for {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, "", errors.New("unterminated list")
		}
		if s[0] == ')' {
			if len(conditions) == 0 {
				return nil, "", errors.New("empty list")
			}
			return conditions, s[1:], nil
		}
		var c ifCondition
		if len(s) >= 3 && strings.EqualFold(s[:3], "not") {
			c.not = true
			s = strings.TrimSpace(s[3:])
		}
		switch {
		case strings.HasPrefix(s, "<"):
			end := strings.IndexByte(s, '>')
			if end < 2 {
				return nil, "", errors.New("malformed state token")
			}
			c.token, s = s[1:end], s[end+1:]
		case strings.HasPrefix(s, "["):
			// The closing bracket is searched after the quoted part, since an
			// opaque tag may hold one.
			open := strings.IndexByte(s, '"')
			if open < 0 {
				return nil, "", errors.New("malformed entity tag")
			}
			closing := strings.IndexByte(s[open+1:], '"')
			if closing < 0 {
				return nil, "", errors.New("malformed entity tag")
			}
			quoteEnd := open + 1 + closing + 1
			if !strings.HasPrefix(s[quoteEnd:], "]") {
				return nil, "", errors.New("malformed entity tag")
			}
			c.etag, s = s[1:quoteEnd], s[quoteEnd+1:]
		default:
			return nil, "", errors.New("expected a state token or an entity tag")
		}
		conditions = append(conditions, c)
	}
}

// requestIfLists parses the request's If header. Repeated headers are read as
// one, as RFC 9110 §5.3 allows for a list.
func requestIfLists(r *http.Request) ([]ifList, error) {
	value := strings.TrimSpace(strings.Join(r.Header.Values("If"), " "))
	if value == "" {
		return nil, nil
	}
	lists, err := parseIfHeader(value)
	if err != nil {
		logger.Debug("If header rejected", "path", r.URL.Path, "reason", err)
		return nil, err
	}
	return lists, nil
}

// evalIf evaluates the If header for a request on target. It returns whether
// the request may proceed (§10.4.1: at least one list is true) and the state
// tokens in true lists, the only ones that count as submitted. A tagged list
// applies only to its tagged resource. The caller holds mu.
func (m *lockManager) evalIf(lists []ifList, target, host string) (bool, map[string]bool) {
	if len(lists) == 0 {
		return true, nil
	}
	passed := false
	submitted := map[string]bool{}
	for _, list := range lists {
		name := target
		if list.tag != "" {
			u, err := url.Parse(list.tag)
			if err != nil || u.Host != "" && u.Host != host {
				continue
			}
			name = path.Clean("/" + u.Path)
		}
		if !m.listTrue(list, name) {
			continue
		}
		passed = true
		for _, c := range list.conditions {
			if c.token != "" && !c.not {
				submitted[c.token] = true
			}
		}
	}
	return passed, submitted
}

// listTrue evaluates one list against the named resource. A state token matches
// a lock that applies to the resource, DAV:no-lock never does. An entity tag is
// compared strongly (§10.4.4), so a weak one never matches. The caller holds mu.
func (m *lockManager) listTrue(list ifList, name string) bool {
	for _, c := range list.conditions {
		var match bool
		if c.token != "" {
			l := m.locks[c.token]
			match = l != nil && l.covers(name)
		} else if fi, err := os.Stat(filepath.Join(m.root, filepath.FromSlash(name))); err == nil {
			match = c.etag == fileETag(fi)
		}
		if match == c.not {
			return false
		}
	}
	return true
}

// checkRead evaluates the If header of a method that changes nothing, where no
// lock is at stake. It answers the request and returns false if it must stop.
func (m *lockManager) checkRead(w http.ResponseWriter, r *http.Request, name string) bool {
	lists, err := requestIfLists(r)
	if err != nil {
		http.Error(w, "invalid If header", http.StatusBadRequest)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(time.Now())
	if passed, _ := m.evalIf(lists, name, r.Host); !passed {
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return false
	}
	return true
}

// ---- writes ------------------------------------------------------------------

// writeTarget is a resource a write changes.
type writeTarget struct {
	name string
	// member: the write adds or removes this URL in its parent. §7.4: a lock
	// on a collection, of any depth, protects its list of members.
	member bool
	// replaces: the write destroys what is at name, including members. §9.6.1
	// and §9.9.4 require the tokens of the locks on those too.
	replaces bool
	// tree: the write changes what is below name, for a concurrent LOCK.
	tree bool
}

// unsatisfied returns the root of a lock on name whose token was not submitted,
// or "". With several shared locks on a resource one token is enough: each of
// them entitles its holder to write (§6.1). The caller holds mu.
func (m *lockManager) unsatisfied(name string, submitted map[string]bool) string {
	locks := m.covering(name)
	if len(locks) == 0 {
		return ""
	}
	for _, l := range locks {
		if submitted[l.Token] {
			return ""
		}
	}
	return locks[0].Root
}

// checkTargets returns what keeps a write off its targets: the root of a lock on
// a target or its parent, or else the roots of the locked members. The caller
// holds mu.
func (m *lockManager) checkTargets(targets []writeTarget, submitted map[string]bool) (string, []string) {
	var members []string
	for _, t := range targets {
		if root := m.unsatisfied(t.name, submitted); root != "" {
			return root, nil
		}
		if t.member && t.name != "/" {
			if root := m.unsatisfied(path.Dir(t.name), submitted); root != "" {
				return root, nil
			}
		}
		if !t.replaces {
			continue
		}
		for _, l := range m.locks {
			if isBelow(l.Root, t.name) && m.unsatisfied(l.Root, submitted) != "" {
				members = append(members, l.Root)
			}
		}
	}
	slices.Sort(members)
	return "", slices.Compact(members)
}

// admitWrite decides whether a write on the request URI name may run, with the
// path locks of its targets already held. If it may, the write is registered and
// the returned function ends it, dropping the locks at and below the names it
// removed. Otherwise the request is answered and ok is false.
//
// §10.4.1 is applied first, so a false If header is 412, and only a request that
// passes it can get 423 for a token it did not submit. A share accepts no token:
// a recipient holds no locks, so an If header cannot be true for one and is 412,
// and the answers name no owner path.
func (m *lockManager) admitWrite(w http.ResponseWriter, r *http.Request, isShare bool, name string, targets []writeTarget) (done func(removed ...string), ok bool) {
	lists, err := requestIfLists(r)
	if err != nil {
		http.Error(w, "invalid If header", http.StatusBadRequest)
		return nil, false
	}
	if isShare && len(lists) > 0 {
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return nil, false
	}
	// x/net must not evaluate it again.
	r.Header.Del("If")

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(time.Now())
	passed, submitted := m.evalIf(lists, name, r.Host)
	if !passed {
		logger.Debug("If header false", "method", r.Method, "path", r.URL.Path)
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return nil, false
	}
	root, members := m.checkTargets(targets, submitted)
	if root != "" || len(members) > 0 {
		logger.Debug("write refused by lock", "method", r.Method, "path", r.URL.Path, "lock_root", root, "members", len(members))
		switch {
		case isShare:
			http.Error(w, "locked", http.StatusLocked)
		case root != "":
			writeLockError(w, http.StatusLocked, "lock-token-submitted", root)
		default:
			writeMemberFailures(w, members, "")
		}
		return nil, false
	}
	entries := make([]runningWrite, len(targets))
	for i, t := range targets {
		entries[i] = runningWrite{name: t.name, tree: t.tree, member: t.member}
	}
	m.writes = append(m.writes, entries...)
	return func(removed ...string) {
		m.mu.Lock()
		defer m.mu.Unlock()
		for _, e := range entries {
			if i := slices.Index(m.writes, e); i >= 0 {
				m.writes = slices.Delete(m.writes, i, i+1)
			}
		}
		for token, l := range m.locks {
			for _, gone := range removed {
				if l.Root == gone || isBelow(l.Root, gone) {
					delete(m.locks, token)
				}
			}
		}
	}, true
}

// writeRunning reports whether a running write touches what a new lock would
// cover. A Depth 0 lock on a collection covers its properties and membership
// only (§7.4), so of the writes below it only one that adds or removes a direct
// member conflicts. The caller holds mu.
func (m *lockManager) writeRunning(name string, zeroDepth bool) bool {
	for _, w := range m.writes {
		switch {
		case w.name == name:
			return true
		case isBelow(w.name, name) && !zeroDepth:
			return true
		case w.member && path.Dir(w.name) == name:
			return true
		case w.tree && isBelow(name, w.name):
			return true
		}
	}
	return false
}

// writeLockError writes a status with a precondition code (§16) naming a lock
// root.
func writeLockError(w http.ResponseWriter, status int, code, root string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:"><d:%s><d:href>%s</d:href></d:%s></d:error>`,
		code, hrefXML(root), code)
}

// writeMemberFailures answers 207 for locked members, with nothing changed.
// failedDependency, if set, is the request URI of a LOCK, which §9.10.6 wants
// listed with 424. DELETE and MOVE leave it out (§9.6.1).
func writeMemberFailures(w http.ResponseWriter, members []string, failedDependency string) {
	var b strings.Builder
	for _, name := range members {
		b.WriteString("<d:response><d:href>" + hrefXML(name) + "</d:href><d:status>HTTP/1.1 423 Locked</d:status>")
		b.WriteString("<d:error><d:lock-token-submitted><d:href>" + hrefXML(name) + "</d:href></d:lock-token-submitted></d:error></d:response>")
	}
	if failedDependency != "" {
		b.WriteString("<d:response><d:href>" + hrefXML(failedDependency) + "</d:href><d:status>HTTP/1.1 424 Failed Dependency</d:status></d:response>")
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">%s</d:multistatus>`, b.String())
}

// ---- LOCK and UNLOCK ----------------------------------------------------------

// serveLock handles LOCK (§9.10). It never waits for a write: one that is
// running on the resource gets 503, and the client tries again.
func serveLock(w http.ResponseWriter, r *http.Request, m *lockManager, absPath string) {
	duration, err := parseLockTimeout(r.Header.Get("Timeout"))
	if err != nil {
		http.Error(w, "invalid Timeout header", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "cannot read request body", http.StatusBadRequest)
		}
		return
	}
	info, err := parseLockInfo(body)
	if err != nil {
		logger.Debug("LOCK body rejected", "path", r.URL.Path, "reason", err)
		status := http.StatusBadRequest
		if errors.Is(err, errUnsupportedLock) {
			status = http.StatusNotImplemented
		}
		http.Error(w, "invalid LOCK body", status)
		return
	}
	lists, err := requestIfLists(r)
	if err != nil {
		http.Error(w, "invalid If header", http.StatusBadRequest)
		return
	}
	zeroDepth := false
	if !info.refresh {
		switch strings.ToLower(strings.TrimSpace(r.Header.Get("Depth"))) {
		case "", "infinity":
		case "0":
			zeroDepth = true
		default:
			http.Error(w, "invalid Depth header", http.StatusBadRequest)
			return
		}
	}

	name := m.nameOf(absPath)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(now)
	passed, submitted := m.evalIf(lists, name, r.Host)
	if !passed {
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return
	}
	if info.refresh {
		m.refresh(w, name, lists, submitted, duration, now)
		return
	}
	if m.writeRunning(name, zeroDepth) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "write in progress", http.StatusServiceUnavailable)
		return
	}
	if root, members := m.conflicts(name, zeroDepth, info.shared); root != "" {
		writeLockError(w, http.StatusLocked, "no-conflicting-lock", root)
		return
	} else if len(members) > 0 {
		writeMemberFailures(w, members, name)
		return
	}
	// createLockedResource tells the causes of a failed stat apart.
	_, statErr := os.Stat(absPath)
	unmapped := statErr != nil
	if unmapped && name != "/" {
		// A new resource is a new member of its parent (§7.4).
		if root := m.unsatisfied(path.Dir(name), submitted); root != "" {
			writeLockError(w, http.StatusLocked, "lock-token-submitted", root)
			return
		}
	}
	created := false
	if unmapped {
		var ok bool
		if created, ok = createLockedResource(w, absPath); !ok {
			return
		}
	}
	l := &activeLock{
		Root:      name,
		Token:     newLockToken(),
		OwnerXML:  info.ownerXML,
		ZeroDepth: zeroDepth,
		Shared:    info.shared,
		Expiry:    lockExpiry(now, duration),
	}
	m.locks[l.Token] = l
	w.Header().Set("Lock-Token", "<"+l.Token+">")
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	m.writeLockResponse(w, status, name, now)
}

// refresh handles a LOCK without a body (§9.10.2). It renews the locks on the
// resource whose tokens were submitted in a true list. The caller holds mu.
func (m *lockManager) refresh(w http.ResponseWriter, name string, lists []ifList, submitted map[string]bool, duration time.Duration, now time.Time) {
	if len(lists) == 0 {
		http.Error(w, "lock refresh without If header", http.StatusBadRequest)
		return
	}
	refreshed := false
	for _, l := range m.covering(name) {
		if submitted[l.Token] {
			l.Expiry = lockExpiry(now, duration)
			refreshed = true
		}
	}
	if !refreshed {
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return
	}
	m.writeLockResponse(w, http.StatusOK, name, now)
}

// conflicts checks a new lock against the existing ones (§6.1, §7): an exclusive
// lock conflicts with any lock, shared locks only with exclusive ones. It returns
// the root of a conflicting lock on the resource or an ancestor, or else the
// roots of conflicting locks on members. The caller holds mu.
func (m *lockManager) conflicts(name string, zeroDepth, shared bool) (string, []string) {
	var members []string
	for _, l := range m.locks {
		if shared && l.Shared {
			continue
		}
		switch {
		case l.covers(name):
			return l.Root, nil
		case !zeroDepth && isBelow(l.Root, name):
			members = append(members, l.Root)
		}
	}
	slices.Sort(members)
	return "", slices.Compact(members)
}

// createLockedResource creates the empty resource for a LOCK on an unmapped URL
// (§7.3). O_EXCL, so a file that appeared since the check is kept as it is.
func createLockedResource(w http.ResponseWriter, absPath string) (created, ok bool) {
	f, err := os.OpenFile(absPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	switch {
	case err == nil:
		if err := f.Close(); err != nil {
			logger.Error("cannot close new locked resource", "path", absPath, "err", err)
		}
		return true, true
	case errors.Is(err, os.ErrExist):
		return false, true
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		http.Error(w, "parent collection does not exist", http.StatusConflict)
	default:
		logger.Error("cannot create locked resource", "path", absPath, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
	return false, false
}

// writeLockResponse writes the body of a LOCK response (§9.10.1): DAV:lockdiscovery
// in a DAV:prop. The caller holds mu.
func (m *lockManager) writeLockResponse(w http.ResponseWriter, status int, name string, now time.Time) {
	var active []activeLock
	for _, l := range m.covering(name) {
		active = append(active, *l)
	}
	var b strings.Builder
	writeLockDiscovery(&b, active, now)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:prop xmlns:d="DAV:">%s</d:prop>`, b.String())
}

// serveUnlock handles UNLOCK (§9.11): the token must belong to a lock that
// applies to the request URI.
func serveUnlock(w http.ResponseWriter, r *http.Request, m *lockManager, absPath string) {
	token, found := strings.CutPrefix(strings.TrimSpace(r.Header.Get("Lock-Token")), "<")
	if found {
		token, found = strings.CutSuffix(token, ">")
	}
	if !found || token == "" {
		http.Error(w, "missing or invalid Lock-Token header", http.StatusBadRequest)
		return
	}
	name := m.nameOf(absPath)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expire(time.Now())
	l := m.locks[token]
	if l == nil || !l.covers(name) {
		writeLockError(w, http.StatusConflict, "lock-token-matches-request-uri", name)
		return
	}
	delete(m.locks, token)
	w.WriteHeader(http.StatusNoContent)
}

// newLockToken returns a random urn:uuid (RFC 9562 version 4), so tokens cannot
// be guessed and do not repeat after a restart.
func newLockToken() string {
	var b [16]byte
	// crypto/rand.Read does not return an error since Go 1.24.
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// parseLockTimeout reads the Timeout header (§10.7) and returns the first value
// it understands, negative for infinite. Without the header a lock is infinite,
// §10.7 leaves the choice to the server. Second-0 would be an expired lock, and
// more than 2^32-1 seconds is not allowed.
func parseLockTimeout(h string) (time.Duration, error) {
	if strings.TrimSpace(h) == "" {
		return -1, nil
	}
	for _, v := range strings.Split(h, ",") {
		v = strings.TrimSpace(v)
		if strings.EqualFold(v, "Infinite") {
			return -1, nil
		}
		if len(v) > 7 && strings.EqualFold(v[:7], "Second-") {
			if n, err := strconv.ParseUint(v[7:], 10, 32); err == nil && n > 0 {
				return time.Duration(n) * time.Second, nil
			}
		}
	}
	return 0, fmt.Errorf("no usable value in %q", h)
}

func lockExpiry(now time.Time, duration time.Duration) time.Time {
	if duration < 0 {
		return time.Time{}
	}
	return now.Add(duration)
}

// ---- lockinfo body (§14.13) ---------------------------------------------------

// errUnsupportedLock marks a well-formed request for a kind of lock this server
// does not have.
var errUnsupportedLock = errors.New("unsupported lock scope or type")

type lockInfo struct {
	refresh  bool // no body
	shared   bool
	ownerXML string
}

// parseLockInfo parses the body of a LOCK request as strictly as a PROPFIND
// body. Elements it does not know are ignored (§17).
func parseLockInfo(body []byte) (lockInfo, error) {
	text, hasBOM, err := stripPropfindBOM(body)
	if err != nil {
		return lockInfo{}, err
	}
	if len(strings.Trim(string(text), " \t\r\n")) == 0 {
		return lockInfo{refresh: true}, nil
	}
	var (
		info                  lockInfo
		depth                 int
		sawRoot               bool
		section               string
		sawScope, sawType     bool
		unsupported           bool
		sawScopeEl, sawTypeEl bool
	)
	dec := newXMLBodyDecoder(text, hasBOM)
	for {
		offset := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return lockInfo{}, fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := checkPropfindAttrs(t.Attr); err != nil {
				return lockInfo{}, err
			}
			switch depth {
			case 0:
				if sawRoot {
					return lockInfo{}, fmt.Errorf("second root element <%s>", t.Name.Local)
				}
				if t.Name.Space != "DAV:" || t.Name.Local != "lockinfo" {
					return lockInfo{}, fmt.Errorf("root element {%s}%s is not {DAV:}lockinfo", t.Name.Space, t.Name.Local)
				}
				sawRoot = true
			case 1:
				section = ""
				if t.Name.Space == "DAV:" {
					section = t.Name.Local
				}
				switch section {
				case "lockscope":
					if sawScopeEl {
						return lockInfo{}, errors.New("second <lockscope>")
					}
					sawScopeEl = true
				case "locktype":
					if sawTypeEl {
						return lockInfo{}, errors.New("second <locktype>")
					}
					sawTypeEl = true
				}
			case 2:
				isDAV := t.Name.Space == "DAV:"
				switch {
				case section == "lockscope" && isDAV && t.Name.Local == "exclusive", section == "lockscope" && isDAV && t.Name.Local == "shared":
					if sawScope {
						return lockInfo{}, errors.New("more than one lock scope")
					}
					sawScope = true
					info.shared = t.Name.Local == "shared"
				case section == "locktype" && isDAV && t.Name.Local == "write":
					sawType = true
				case section == "lockscope" || section == "locktype":
					unsupported = true
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(strings.Trim(string(t), " \t\r\n")) > 0 {
				return lockInfo{}, errors.New("text outside the root element")
			}
		case xml.ProcInst:
			if strings.EqualFold(t.Target, "xml") && offset != 0 {
				return lockInfo{}, errors.New("XML declaration not at the start of the body")
			}
		case xml.Directive:
			if sawRoot || depth > 0 {
				return lockInfo{}, errors.New("directive after the start of the root element")
			}
		}
	}
	if !sawRoot {
		return lockInfo{}, errors.New("no root element")
	}
	if err := checkPropfindPrefixes(newXMLBodyDecoder(text, hasBOM)); err != nil {
		return lockInfo{}, err
	}
	if !sawScope || !sawType {
		if unsupported {
			return lockInfo{}, errUnsupportedLock
		}
		return lockInfo{}, errors.New("lockscope or locktype missing")
	}
	info.ownerXML, err = extractLockOwner(newXMLBodyDecoder(text, hasBOM))
	if err != nil {
		return lockInfo{}, err
	}
	return info, nil
}

// extractLockOwner returns the DAV:owner child of the root as a self-contained
// element, or "". It keeps the client's prefixes and adds the declarations made
// on the elements around it, so its names keep their namespaces wherever it is
// written. It works on raw tokens, because Token replaces prefixes. The caller
// has already checked the body.
func extractLockOwner(dec *xml.Decoder) (string, error) {
	var scopes []map[string]string
	lookup := func(prefix string) string {
		for i := len(scopes) - 1; i >= 0; i-- {
			if uri, ok := scopes[i][prefix]; ok {
				return uri
			}
		}
		return ""
	}
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			scope := map[string]string{}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					scope[a.Name.Local] = a.Value
				} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
					scope[""] = a.Value
				}
			}
			scopes = append(scopes, scope)
			if len(scopes) == 2 && t.Name.Local == "owner" && lookup(t.Name.Space) == "DAV:" {
				return serializeOwner(dec, t, lookup)
			}
		case xml.EndElement:
			scopes = scopes[:len(scopes)-1]
		}
	}
}

// serializeOwner writes the owner element that starts with start, reading the
// rest of it from dec. lookup resolves a prefix in scope at start.
func serializeOwner(dec *xml.Decoder, start xml.StartElement, lookup func(string) string) (string, error) {
	var inner strings.Builder
	used := map[string]bool{start.Name.Space: true}
	for _, a := range start.Attr {
		if a.Name.Space != "xmlns" && a.Name.Space != "" {
			used[a.Name.Space] = true
		}
	}
	for depth := 1; depth > 0; {
		tok, err := dec.RawToken()
		if err != nil {
			return "", fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			used[t.Name.Space] = true
			for _, a := range t.Attr {
				if a.Name.Space != "xmlns" && a.Name.Space != "" {
					used[a.Name.Space] = true
				}
			}
			writeRawStart(&inner, t, nil)
		case xml.EndElement:
			depth--
			if depth > 0 {
				inner.WriteString("</" + rawName(t.Name) + ">")
			}
		case xml.CharData:
			xml.EscapeText(&inner, t)
		case xml.Comment:
			inner.WriteString("<!--" + string(t) + "-->")
		case xml.ProcInst:
			inner.WriteString("<?" + t.Target + " " + string(t.Inst) + "?>")
		}
	}
	// What is declared on the owner element itself stays as it is.
	declared := map[string]bool{"xml": true, "xmlns": true}
	for _, a := range start.Attr {
		if a.Name.Space == "xmlns" {
			declared[a.Name.Local] = true
		} else if a.Name.Space == "" && a.Name.Local == "xmlns" {
			declared[""] = true
		}
	}
	var extra []string
	for prefix := range used {
		if declared[prefix] {
			continue
		}
		if uri := lookup(prefix); uri != "" {
			if prefix == "" {
				extra = append(extra, ` xmlns="`+escapeXMLAttr(uri)+`"`)
			} else {
				extra = append(extra, ` xmlns:`+prefix+`="`+escapeXMLAttr(uri)+`"`)
			}
		}
	}
	slices.Sort(extra)
	var b strings.Builder
	writeRawStart(&b, start, extra)
	b.WriteString(inner.String())
	b.WriteString("</" + rawName(start.Name) + ">")
	return b.String(), nil
}

func rawName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

func writeRawStart(b *strings.Builder, t xml.StartElement, extra []string) {
	b.WriteString("<" + rawName(t.Name))
	for _, a := range t.Attr {
		b.WriteString(" " + rawName(a.Name) + `="` + escapeXMLAttr(a.Value) + `"`)
	}
	for _, e := range extra {
		b.WriteString(e)
	}
	b.WriteString(">")
}

func escapeXMLAttr(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// ---- lock properties ----------------------------------------------------------

// writeSupportedLock writes DAV:supportedlock (RFC 4918 §15.10). A share has no
// locking, so its value is empty.
func writeSupportedLock(b *strings.Builder, isShare bool) {
	if isShare {
		b.WriteString("<d:supportedlock/>")
		return
	}
	b.WriteString("<d:supportedlock>" +
		"<d:lockentry><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry>" +
		"<d:lockentry><d:lockscope><d:shared/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockentry>" +
		"</d:supportedlock>")
}

// writeLockDiscovery writes DAV:lockdiscovery (RFC 4918 §15.8) with one
// DAV:activelock (§14.1) per lock.
func writeLockDiscovery(b *strings.Builder, locks []activeLock, now time.Time) {
	if len(locks) == 0 {
		b.WriteString("<d:lockdiscovery/>")
		return
	}
	b.WriteString("<d:lockdiscovery>")
	for _, l := range locks {
		depth, scope := "infinity", "exclusive"
		if l.ZeroDepth {
			depth = "0"
		}
		if l.Shared {
			scope = "shared"
		}
		b.WriteString("<d:activelock><d:lockscope><d:" + scope + "/></d:lockscope><d:locktype><d:write/></d:locktype>")
		b.WriteString("<d:depth>" + depth + "</d:depth>")
		b.WriteString(l.OwnerXML)
		b.WriteString("<d:timeout>" + lockTimeout(l.Expiry, now) + "</d:timeout>")
		b.WriteString("<d:locktoken><d:href>" + xmlEsc(l.Token) + "</d:href></d:locktoken>")
		b.WriteString("<d:lockroot><d:href>" + hrefXML(l.Root) + "</d:href></d:lockroot>")
		b.WriteString("</d:activelock>")
	}
	b.WriteString("</d:lockdiscovery>")
}

// lockTimeout formats the remaining time as a TimeType (RFC 4918 §10.7). It
// rounds up, so a lock still active never reports Second-0.
func lockTimeout(expiry, now time.Time) string {
	if expiry.IsZero() {
		return "Infinite"
	}
	return fmt.Sprintf("Second-%d", (expiry.Sub(now)+time.Second-1)/time.Second)
}
