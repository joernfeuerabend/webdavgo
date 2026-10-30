// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// locks.go: lock state that x/net/webdav does not expose: a query on top of
// its LockSystem for DAV:lockdiscovery, the view of an owner's locks a share
// writes through, and the XML of both lock properties.

import (
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/webdav"
)

// activeLock is what the server knows about one client-visible lock.
type activeLock struct {
	Root      string
	Token     string
	OwnerXML  string
	ZeroDepth bool
	// Expiry is the zero time for a lock with an infinite timeout.
	Expiry time.Time
}

// lockTracker is a webdav.LockSystem that records what passes through it, so
// the active locks can be queried. Confirming locks stays entirely with the
// wrapped LockSystem. Its interface for callers is:
//
//   - Confirm, Create, Refresh, Unlock: the LockSystem, used for LOCK and UNLOCK
//   - locksOn: the active locks that apply to a resource
//   - temporary: the LockSystem for every other method, see there
type lockTracker struct {
	inner webdav.LockSystem
	// mu is held across calls to inner, so the records cannot disagree with
	// it about the order of two operations on the same lock.
	mu    sync.Mutex
	locks map[string]activeLock // by token
}

func newLockTracker(inner webdav.LockSystem) *lockTracker {
	return &lockTracker{inner: inner, locks: map[string]activeLock{}}
}

// Confirm implements webdav.LockSystem.
func (t *lockTracker) Confirm(now time.Time, name0, name1 string, conditions ...webdav.Condition) (func(), error) {
	return t.inner.Confirm(now, name0, name1, conditions...)
}

// Create implements webdav.LockSystem.
func (t *lockTracker) Create(now time.Time, details webdav.LockDetails) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	token, err := t.inner.Create(now, details)
	if err != nil {
		return "", err
	}
	t.locks[token] = activeLock{
		// Cleaned as x/net cleans it, so that locksOn compares like with like.
		Root:      path.Clean("/" + details.Root),
		Token:     token,
		OwnerXML:  details.OwnerXML,
		ZeroDepth: details.ZeroDepth,
		Expiry:    lockExpiry(now, details.Duration),
	}
	return token, nil
}

// Refresh implements webdav.LockSystem.
func (t *lockTracker) Refresh(now time.Time, token string, duration time.Duration) (webdav.LockDetails, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	details, err := t.inner.Refresh(now, token, duration)
	if err != nil {
		return details, err
	}
	if l, ok := t.locks[token]; ok {
		l.Expiry = lockExpiry(now, duration)
		t.locks[token] = l
	}
	return details, nil
}

// Unlock implements webdav.LockSystem.
func (t *lockTracker) Unlock(now time.Time, token string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	err := t.inner.Unlock(now, token)
	if err == nil || err == webdav.ErrNoSuchLock {
		delete(t.locks, token)
	}
	return err
}

// locksOn returns the locks that apply to the named resource at now: those
// rooted on it and those of an ancestor locked with Depth infinity. Expired
// records are dropped here, x/net gives no notice when a lock expires.
func (t *lockTracker) locksOn(now time.Time, name string) []activeLock {
	name = path.Clean("/" + name)
	t.mu.Lock()
	defer t.mu.Unlock()
	var found []activeLock
	for token, l := range t.locks {
		if !l.Expiry.IsZero() && !now.Before(l.Expiry) {
			delete(t.locks, token)
			continue
		}
		if name == l.Root || !l.ZeroDepth && (l.Root == "/" || strings.HasPrefix(name, l.Root+"/")) {
			found = append(found, l)
		}
	}
	return found
}

// temporary returns the LockSystem for all methods other than LOCK and UNLOCK.
// x/net takes a short-lived lock for each write without an If header, and
// through the Create method these look exactly like a LOCK with Depth 0, no
// owner and no timeout. They are real for conflicts but must not be recorded.
func (t *lockTracker) temporary() webdav.LockSystem {
	return t.inner
}

func lockExpiry(now time.Time, duration time.Duration) time.Time {
	if duration < 0 {
		return time.Time{}
	}
	return now.Add(duration)
}

// shareLocks is the owner's LockSystem as seen from a share. Names from x/net
// are relative to the share root and become relative to the user root here,
// so a write conflicts with the owner's locks as on the user endpoint.
type shareLocks struct {
	owner webdav.LockSystem
	root  string // share path below the user root
}

// Confirm always fails. A recipient holds no locks, and the tokens of x/net's
// MemLS are consecutive numbers, so accepting a token in an If header would
// let a recipient guess their way past the owner's lock. The result is 412,
// the answer of an If header with an unknown token.
func (s shareLocks) Confirm(time.Time, string, string, ...webdav.Condition) (func(), error) {
	return nil, webdav.ErrConfirmationFailed
}

// Create takes x/net's temporary lock for one write in the owner's lock tree.
func (s shareLocks) Create(now time.Time, details webdav.LockDetails) (string, error) {
	details.Root = path.Join(s.root, details.Root)
	return s.owner.Create(now, details)
}

// Refresh is unreachable as serveShare rejects LOCK, and refuses in any case.
func (s shareLocks) Refresh(time.Time, string, time.Duration) (webdav.LockDetails, error) {
	return webdav.LockDetails{}, webdav.ErrNoSuchLock
}

// Unlock releases a temporary lock. serveShare rejects UNLOCK, so no token
// from a recipient arrives here.
func (s shareLocks) Unlock(now time.Time, token string) error {
	return s.owner.Unlock(now, token)
}

// writeSupportedLock writes DAV:supportedlock (RFC 4918 §15.10). x/net only
// accepts exclusive write locks. A share has no locking, so its value is empty.
func writeSupportedLock(b *strings.Builder, isShare bool) {
	if isShare {
		b.WriteString("<d:supportedlock/>")
		return
	}
	b.WriteString("<d:supportedlock><d:lockentry><d:lockscope><d:exclusive/></d:lockscope>" +
		"<d:locktype><d:write/></d:locktype></d:lockentry></d:supportedlock>")
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
		depth := "infinity"
		if l.ZeroDepth {
			depth = "0"
		}
		b.WriteString("<d:activelock><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype>")
		b.WriteString("<d:depth>" + depth + "</d:depth>")
		writeLockOwner(b, l.OwnerXML)
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

// writeLockOwner writes DAV:owner (RFC 4918 §14.17). x/net keeps the client's
// XML verbatim, but the prefixes in it were declared on the LOCK request's
// elements around it, as in <D:owner><D:href>. Without declarations here a
// single such lock would make the whole multistatus unparsable for a client.
// x/net does not keep the namespaces, so every prefix is declared as DAV:,
// which is what the clients sending this form use. A declaration inside the
// owner XML still takes precedence.
func writeLockOwner(b *strings.Builder, ownerXML string) {
	if ownerXML == "" {
		return
	}
	b.WriteString("<d:owner")
	for _, prefix := range xmlPrefixes(ownerXML) {
		b.WriteString(` xmlns:` + prefix + `="DAV:"`)
	}
	b.WriteString(">" + ownerXML + "</d:owner>")
}

// xmlPrefixes returns the namespace prefixes of the element and attribute
// names in s, without the predeclared ones and the "d" of our own response.
func xmlPrefixes(s string) []string {
	var prefixes []string
	add := func(name xml.Name) {
		p := name.Space
		if p == "" || p == "d" || p == "xml" || p == "xmlns" {
			return
		}
		for _, seen := range prefixes {
			if seen == p {
				return
			}
		}
		prefixes = append(prefixes, p)
	}
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		tok, err := dec.RawToken()
		if err != nil {
			if err != io.EOF {
				logger.Debug("cannot read lock owner", "err", err)
			}
			return prefixes
		}
		if el, ok := tok.(xml.StartElement); ok {
			add(el.Name)
			for _, a := range el.Attr {
				add(a.Name)
			}
		}
	}
}
