// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// clientlist.go – the client address lists of the WebDAV and the admin
// listener (webdav_allowed_clients, webgui_allowed_clients). An empty list
// allows every client. A non-empty one lets only the listed addresses and
// prefixes connect: every other connection is reset right after accept,
// before TLS or HTTP, and gets no response. The admin listener always
// allows loopback, so that an SSH tunnel keeps working. The WebDAV listener
// with tls_mode acme cannot drop at accept, because the CA validates
// TLS-ALPN-01 from addresses nobody can list; there the TLS handshake
// decides (clientHelloVerdict).
//
// The health listener is not covered: it binds 127.0.0.1 by default and
// answers only /livez and /readyz.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// acmeALPN is the ALPN protocol of TLS-ALPN-01 (RFC 8737).
const acmeALPN = "acme-tls/1"

// clientListKeys are the config keys of the lists, per listener.
var clientListKeys = [numStatListeners]string{"webdav_allowed_clients", "webgui_allowed_clients"}

// parseClientList parses a comma separated list of IPv4 and IPv6 addresses
// and CIDR prefixes. Empty entries (a trailing comma, blanks) are skipped.
// An IPv4-mapped IPv6 address or prefix becomes its IPv4 form, which is how
// clientAllowed compares. The error names the first invalid entry.
func parseClientList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		p, err := parseClientEntry(entry)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func parseClientEntry(entry string) (netip.Prefix, error) {
	if strings.Contains(entry, "%") {
		return netip.Prefix{}, fmt.Errorf("%q: an address with a zone (%%) is not allowed", entry)
	}
	if !strings.Contains(entry, "/") {
		a, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q: not an IP address or CIDR prefix", entry)
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q: not a valid CIDR prefix", entry)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%q: the address has bits set beyond the prefix length, write %s", entry, p.Masked())
	}
	// A masked prefix with an IPv4-mapped address is /96 or longer.
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p, nil
}

// clientListContains reports whether a is in list; an empty list contains
// every address. a is compared without zone and in IPv4 form if it is an
// IPv4-mapped IPv6 address, as a dual-stack socket reports IPv4 clients.
func clientListContains(list []netip.Prefix, a netip.Addr) bool {
	if len(list) == 0 {
		return true
	}
	a = a.Unmap().WithZone("")
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientAllowedBy applies the list of listener l, given as written in the
// config file, to a. The admin listener allows loopback whatever the list
// says. A list that does not parse allows nothing else: the lists fail
// closed.
func clientAllowedBy(l statListener, raw string, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if l == statAdmin && a.IsLoopback() {
		return true
	}
	list, err := parseClientList(raw)
	if err != nil {
		return false
	}
	return clientListContains(list, a)
}

// parsedClientList caches the parsed list of one listener for the raw
// value it was parsed from. Apply and the domain wizard replace the running
// configuration, so the raw value is compared on every use.
type parsedClientList struct {
	raw  string
	list []netip.Prefix
	err  error
}

var clientListCache [numStatListeners]atomic.Pointer[parsedClientList]

// runningClientList returns the raw list of listener l in c.
func runningClientList(c *Config, l statListener) string {
	if l == statAdmin {
		return c.WebGUIAllowedClients
	}
	return c.WebDAVAllowedClients
}

// clientAllowed reports whether a may connect to listener l under the
// running configuration.
func clientAllowed(l statListener, a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if l == statAdmin && a.IsLoopback() {
		return true
	}
	raw := runningClientList(conf(), l)
	p := clientListCache[l].Load()
	if p == nil || p.raw != raw {
		list, err := parseClientList(raw)
		p = &parsedClientList{raw: raw, list: list, err: err}
		clientListCache[l].Store(p)
	}
	if p.err != nil {
		return false
	}
	return clientListContains(p.list, a)
}

// checkClientLists returns a field error for each list that does not parse.
func (c Config) checkClientLists() []fieldError {
	var errs []fieldError
	for l, key := range clientListKeys {
		if _, err := parseClientList(runningClientList(&c, statListener(l))); err != nil {
			errs = append(errs, fieldError{key, fmt.Errorf("%s: %w", key, err)})
		}
	}
	return errs
}

// adminLockoutError returns why saving raw as webgui_allowed_clients would
// lock out the client at remoteAddr (an http.Request's RemoteAddr), or nil.
// A remote address that is not an IP address is not checked.
func adminLockoutError(raw, remoteAddr string) error {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return nil
	}
	a := ap.Addr().Unmap().WithZone("")
	if clientAllowedBy(statAdmin, raw, a) {
		return nil
	}
	return fmt.Errorf("Refused: your current address %s is not in this list, so the admin UI would drop your "+
		"connection right after the change. Add %s or a prefix that contains it. Loopback is always allowed, "+
		"so you can also make the change through an SSH tunnel.", a, a)
}

// ---- dropping ------------------------------------------------------------------

// errClientNotAllowed ends the TLS handshake of a client outside the WebDAV
// list. serverErrorWriter neither logs nor counts the handshake error it
// causes: the drop counters stand for it.
var errClientNotAllowed = errors.New("client address not allowed")

// abortConn closes c with a TCP reset (SO_LINGER 0) instead of the normal
// close, so the client gets no FIN handshake either.
func abortConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}

// handshakeVerdict is what the TLS handshake of the WebDAV listener does
// with a client.
type handshakeVerdict int

const (
	handshakeNormal   handshakeVerdict = iota // client allowed
	handshakeACMEOnly                         // outside the list, TLS-ALPN-01 only
	handshakeDrop                             // outside the list, reset
)

// clientHelloVerdict decides the handshake of a client the list does not
// allow (denied) on the WebDAV listener with tls_mode acme. Only a
// ClientHello that offers acme-tls/1 and nothing else may go on, and then
// only to the challenge certificate: the CA's validation looks like that,
// and an HTTP client never does.
func clientHelloVerdict(denied bool, hello *tls.ClientHelloInfo) handshakeVerdict {
	if !denied {
		return handshakeNormal
	}
	if len(hello.SupportedProtos) == 0 {
		return handshakeDrop
	}
	for _, p := range hello.SupportedProtos {
		if p != acmeALPN {
			return handshakeDrop
		}
	}
	return handshakeACMEOnly
}

// acmeOnlyTLSConfig derives from base the configuration of a handshake for
// a client outside the list: acme-tls/1 is the only protocol it can
// negotiate, and the handshake fails if anything else was negotiated. The
// HTTP server still refuses such a connection (rejectDeniedConn).
func acmeOnlyTLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.GetConfigForClient = nil
	c.NextProtos = []string{acmeALPN}
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.NegotiatedProtocol != acmeALPN {
			return errClientNotAllowed
		}
		return nil
	}
	return c
}

// clientListGetConfigForClient is the GetConfigForClient of the WebDAV
// listener with tls_mode acme. base is the listener's configuration.
func clientListGetConfigForClient(base *tls.Config) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		cc, _ := hello.Conn.(*countingConn)
		denied := cc != nil && cc.denied.Load()
		switch clientHelloVerdict(denied, hello) {
		case handshakeACMEOnly:
			return acmeOnlyTLSConfig(base), nil
		case handshakeDrop:
			clientDrops[statWebDAV].record(cc.addr, time.Now())
			// Reset before the error, so the alert crypto/tls would send
			// goes nowhere.
			abortConn(cc.Conn)
			return nil, errClientNotAllowed
		}
		return nil, nil
	}
}

// rejectDeniedConn reports whether the request r must not be served, and
// then resets its connection: the connection is marked as outside the list
// (an ACME-only handshake, or a connection Apply took the address of), or it
// negotiated acme-tls/1, which never carries HTTP. The caller must then
// panic with http.ErrAbortHandler, so that nothing is sent.
func rejectDeniedConn(r *http.Request) bool {
	ci, _ := r.Context().Value(ctxConn).(*connInfo)
	acme := r.TLS != nil && r.TLS.NegotiatedProtocol == acmeALPN
	if !acme && (ci == nil || ci.raw == nil || !ci.raw.denied.Load()) {
		return false
	}
	if ci != nil && ci.raw != nil {
		clientDrops[ci.raw.listener].record(ci.raw.addr, time.Now())
		abortConn(ci.raw.Conn)
		ci.raw.Close()
	}
	return true
}

// enforceClientLists applies the running lists to the open connections
// after Apply changed them: a connection whose address is no longer allowed
// is reset. It returns how many were.
func (reg *connRegistry) enforceClientLists() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	n := 0
	for _, ci := range reg.conns {
		if ci.raw != nil && ci.raw.recheckClientList() {
			n++
		}
	}
	return n
}

// recheckClientList resets c if its address is no longer allowed and
// reports whether it did. On the WebDAV listener with tls_mode acme, a
// connection already outside the list at accept stays: the handshake and
// rejectDeniedConn keep it from HTTP.
func (c *countingConn) recheckClientList() bool {
	if !c.addr.IsValid() || c.closed.Load() {
		return false
	}
	if c.acme && c.deniedAtAccept {
		return false
	}
	if clientAllowed(c.listener, c.addr) {
		return false
	}
	c.denied.Store(true)
	abortConn(c.Conn)
	c.Close()
	return true
}

// ---- counting and logging ---------------------------------------------------------

// clientDropLogEvery is the shortest time between two summary lines of one
// listener, and dropSamples how many addresses a line and the Security page
// show.
const (
	clientDropLogEvery = time.Minute
	dropSamples        = 5
)

// dropCounter counts the connections one listener dropped because of its
// list. It writes no log line per drop: at most one summary line per
// clientDropLogEvery, with the count since the last line and a few
// addresses.
type dropCounter struct {
	listener statListener

	mu        sync.Mutex
	total     int64
	last      time.Time
	recent    []string // the latest distinct addresses, newest first
	pending   int64    // since the last log line
	samples   []string // distinct addresses since the last log line
	lastLog   time.Time
	scheduled bool // a flush is waiting for clientDropLogEvery to pass
}

var clientDrops = func() (d [numStatListeners]*dropCounter) {
	for l := range numStatListeners {
		d[l] = &dropCounter{listener: l}
	}
	return
}()

// record counts one dropped connection from a.
func (d *dropCounter) record(a netip.Addr, now time.Time) {
	addr := "unknown"
	if a.IsValid() {
		addr = a.Unmap().String()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	d.last = now
	d.recent = slices.DeleteFunc(d.recent, func(s string) bool { return s == addr })
	d.recent = append([]string{addr}, d.recent...)
	if len(d.recent) > dropSamples {
		d.recent = d.recent[:dropSamples]
	}
	d.pending++
	if len(d.samples) < dropSamples && !slices.Contains(d.samples, addr) {
		d.samples = append(d.samples, addr)
	}
	if wait := clientDropLogEvery - now.Sub(d.lastLog); wait > 0 {
		if !d.scheduled {
			d.scheduled = true
			time.AfterFunc(wait, d.flush)
		}
		return
	}
	d.logLocked(now)
}

// flush writes the summary line of the drops since the last one.
func (d *dropCounter) flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scheduled = false
	if d.pending > 0 {
		d.logLocked(time.Now())
	}
}

func (d *dropCounter) logLocked(now time.Time) {
	logger.Info("connections dropped: client address not allowed", "listener", statListenerNames[d.listener],
		"key", clientListKeys[d.listener], "count", d.pending, "clients", strings.Join(d.samples, ","))
	d.pending, d.samples, d.lastLog = 0, nil, now
}

// clientDropState is one row of the Security page.
type clientDropState struct {
	Total  int64
	Last   time.Time
	Recent []string
}

func (d *dropCounter) state() clientDropState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return clientDropState{Total: d.total, Last: d.last, Recent: slices.Clone(d.recent)}
}
