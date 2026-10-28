// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// conns.go – live view of the open connections on both listeners for the
// admin Status page (concept 6e). The request path pays only for atomic
// operations: byte counters on the connection and one pointer slot per
// running request. Everything else, including the transfer rate, is
// computed when the page asks.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const ctxConn ctxKey = "conn"

// countingConn counts the bytes on the wire. Below TLS these are the
// encrypted bytes, which is what the link actually carries. The same bytes
// go into the listener's 24 h statistics.
type countingConn struct {
	net.Conn
	listener statListener
	rx, tx   atomic.Int64

	// limit holds the connection's place in max_connections_per_ip; nil if
	// the remote address is not an IP address.
	limit  *connLimit
	client netip.Prefix
	closed atomic.Bool
}

// Close gives the connection's per-IP place back exactly once, however
// often net/http and crypto/tls close it.
func (c *countingConn) Close() error {
	if c.limit != nil && c.closed.CompareAndSwap(false, true) {
		c.limit.release(c.client)
	}
	return c.Conn.Close()
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rx.Add(int64(n))
	if n > 0 {
		stats.received(c.listener, n)
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.tx.Add(int64(n))
	if n > 0 {
		stats.sent(c.listener, n)
	}
	return n, err
}

type countingListener struct {
	net.Listener
	listener statListener
}

// Accept enforces max_connections_per_ip: a connection beyond the limit is
// closed here, before the TLS handshake and before net/http sees it, and
// Accept goes on with the next one.
func (l countingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		cc := &countingConn{Conn: c, listener: l.listener}
		if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			p := clientPrefix(ta.AddrPort().Addr())
			cl := connLimits[l.listener]
			n, ok := cl.acquire(p)
			if !ok {
				c.Close()
				connRefused(l.listener, p)
				continue
			}
			stats.clientConns(l.listener, n)
			cc.limit, cc.client = cl, p
		}
		return cc, nil
	}
}

// connLimit counts the open connections per client on one listener. It only
// holds clients with open connections, so max_connections bounds it.
type connLimit struct {
	mu   sync.Mutex
	open map[netip.Prefix]int
}

// connLimits are per listener and outlive a server: the domain wizard's new
// WebDAV listener shares the count with the one still draining.
var connLimits = [numStatListeners]*connLimit{
	{open: map[netip.Prefix]int{}},
	{open: map[netip.Prefix]int{}},
}

// acquire takes a place for client p and returns its open connections
// including the new one; ok is false at the limit.
func (cl *connLimit) acquire(p netip.Prefix) (n int, ok bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	n = cl.open[p]
	if n >= conf().MaxConnectionsPerIP {
		return n, false
	}
	cl.open[p] = n + 1
	return n + 1, true
}

func (cl *connLimit) release(p netip.Prefix) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if n := cl.open[p]; n > 1 {
		cl.open[p] = n - 1
	} else {
		delete(cl.open, p)
	}
}

// maxOpen returns the most connections a single client holds now.
func (cl *connLimit) maxOpen() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	m := 0
	for _, n := range cl.open {
		m = max(m, n)
	}
	return m
}

// atLimit returns the clients that hold max_connections_per_ip now.
func (cl *connLimit) atLimit() []string {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	var out []string
	for p, n := range cl.open {
		if n >= conf().MaxConnectionsPerIP {
			out = append(out, prefixKey(p))
		}
	}
	return out
}

func connRefused(l statListener, p netip.Prefix) {
	key := prefixKey(p)
	stats.connRefused(l, key)
	logLimitRefusal(limitKey{key, limitConns, l}, time.Now(), "connection refused: per-IP limit",
		"limit", conf().MaxConnectionsPerIP)
}

// trackConns wraps ln so that its connections can be shown on the Status
// page. Every listener a server from newServer runs on must be wrapped, with
// the same listener name.
func trackConns(ln net.Listener, listener string) net.Listener {
	return countingListener{Listener: ln, listener: statListenerIndex(listener)}
}

// activeRequest is one running request (an HTTP/2 stream or the current
// HTTP/1.1 request). Only the path is kept: a query string may carry a
// setup token.
type activeRequest struct {
	method, path string
	start        time.Time
}

type connInfo struct {
	listener string
	remote   string
	since    time.Time
	raw      *countingConn // nil if the listener was not wrapped

	proto    atomic.Int32 // 10*major+minor of the last request; 0 before the first
	identity atomic.Pointer[string]
	// One slot per concurrent stream the server allows; HTTP/1.1 uses one.
	reqs []atomic.Pointer[activeRequest]

	// Rate sampling, guarded by connRegistry.mu.
	sampleAt           time.Time
	sampleRx, sampleTx int64
	rateRx, rateTx     float64
}

// begin records r as running on the connection and returns its slot, or -1
// if all slots are taken.
func (ci *connInfo) begin(r *http.Request) int {
	ci.proto.Store(int32(10*r.ProtoMajor + r.ProtoMinor))
	a := &activeRequest{method: r.Method, path: r.URL.Path, start: time.Now()}
	for i := range ci.reqs {
		if ci.reqs[i].CompareAndSwap(nil, a) {
			return i
		}
	}
	return -1
}

func (ci *connInfo) end(slot int) {
	if slot >= 0 {
		ci.reqs[slot].Store(nil)
	}
}

// noteIdentity records who authenticated on the connection of r, once the
// handler knows it. A keep-alive connection shows its latest identity.
func noteIdentity(r *http.Request, id string) {
	ci, _ := r.Context().Value(ctxConn).(*connInfo)
	if ci == nil {
		return
	}
	if p := ci.identity.Load(); p == nil || *p != id {
		ci.identity.Store(&id)
	}
}

// connRegistry holds the open connections of all servers. It is bounded by
// max_connections per listener: entries are added when a server accepts a
// connection and removed when it closes.
type connRegistry struct {
	mu    sync.Mutex
	conns map[net.Conn]*connInfo
}

func (reg *connRegistry) add(listener string, c net.Conn) *connInfo {
	raw, _ := c.(*countingConn)
	if tc, ok := c.(*tls.Conn); ok {
		raw, _ = tc.NetConn().(*countingConn)
	}
	ci := &connInfo{
		listener: listener,
		remote:   addrHost(c.RemoteAddr().String()),
		since:    time.Now(),
		raw:      raw,
		reqs:     make([]atomic.Pointer[activeRequest], max(conf().HTTP2MaxConcurrentStreams, 1)),
	}
	ci.sampleAt = ci.since
	reg.mu.Lock()
	if reg.conns == nil {
		reg.conns = map[net.Conn]*connInfo{}
	}
	reg.conns[c] = ci
	reg.mu.Unlock()
	return ci
}

func (reg *connRegistry) remove(c net.Conn) {
	reg.mu.Lock()
	delete(reg.conns, c)
	reg.mu.Unlock()
}

// connContext and connState are the http.Server hooks that keep reg in
// step with a server's connections. For HTTP/2 the request contexts derive
// from the connection context, so every stream finds its connInfo.
func (reg *connRegistry) connContext(listener string) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, ctxConn, reg.add(listener, c))
	}
}

func (reg *connRegistry) connState(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateClosed, http.StateHijacked:
		reg.remove(c)
	}
}

// connView is one row of the connections table.
type connView struct {
	Listener, Remote, Proto, Since, Age, Identity string
	Requests                                      []string
	Received, Sent, RateIn, RateOut               string
	since                                         time.Time
}

// rateSampleMin keeps two admins polling at once from turning each other's
// rate into the delta of a few milliseconds.
const rateSampleMin = time.Second

// snapshot returns the open connections, oldest first per listener.
func (reg *connRegistry) snapshot(now time.Time) []connView {
	reg.mu.Lock()
	out := make([]connView, 0, len(reg.conns))
	for _, ci := range reg.conns {
		var rx, tx int64
		if ci.raw != nil {
			rx, tx = ci.raw.rx.Load(), ci.raw.tx.Load()
		}
		if dt := now.Sub(ci.sampleAt); dt >= rateSampleMin {
			ci.rateRx = float64(rx-ci.sampleRx) / dt.Seconds()
			ci.rateTx = float64(tx-ci.sampleTx) / dt.Seconds()
			ci.sampleAt, ci.sampleRx, ci.sampleTx = now, rx, tx
		}
		v := connView{
			Listener: ci.listener,
			Remote:   ci.remote,
			Proto:    protoName(ci.proto.Load()),
			Since:    formatStatusTime(ci.since),
			Age:      now.Sub(ci.since).Round(time.Second).String(),
			Identity: "unauthenticated",
			Received: formatBytes(rx),
			Sent:     formatBytes(tx),
			RateIn:   formatBytes(int64(ci.rateRx)) + "/s",
			RateOut:  formatBytes(int64(ci.rateTx)) + "/s",
			since:    ci.since,
		}
		if p := ci.identity.Load(); p != nil {
			v.Identity = *p
		}
		for i := range ci.reqs {
			if a := ci.reqs[i].Load(); a != nil {
				v.Requests = append(v.Requests, fmt.Sprintf("%s %s (%s)", a.method, a.path,
					now.Sub(a.start).Round(time.Second)))
			}
		}
		out = append(out, v)
	}
	reg.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Listener != out[j].Listener {
			return out[i].Listener < out[j].Listener
		}
		return out[i].since.Before(out[j].since)
	})
	return out
}

func protoName(p int32) string {
	switch p {
	case 0:
		return "–"
	case 20:
		return "HTTP/2"
	}
	return fmt.Sprintf("HTTP/%d.%d", p/10, p%10)
}

// addrHost strips the port from a host:port address.
func addrHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// formatBytes renders n with a decimal unit (1 KB = 1000 bytes), the units
// of the Settings page and the quota.
func formatBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
