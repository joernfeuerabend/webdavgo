// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// clientListTestEnv sets the running configuration to c and the logger to
// a buffer, and restores both afterwards.
func clientListTestEnv(t *testing.T, c Config) *syncBuffer {
	t.Helper()
	oldConf, oldLogger := conf(), logger
	setConf(c)
	buf := &syncBuffer{}
	logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		setConf(*oldConf)
		logger = oldLogger
	})
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestParseClientList(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ,  ", nil},
		{"192.0.2.10", []string{"192.0.2.10/32"}},
		{"192.0.2.10, 198.51.100.0/24,2001:db8::/32 , 2001:db8:1::5", []string{"192.0.2.10/32", "198.51.100.0/24", "2001:db8::/32", "2001:db8:1::5/128"}},
		{"192.0.2.10,", []string{"192.0.2.10/32"}},
		{"192.0.2.10, 192.0.2.10", []string{"192.0.2.10/32"}},
		{"0.0.0.0/0", []string{"0.0.0.0/0"}},
		{"::/0", []string{"::/0"}},
		// IPv4-mapped IPv6 entries become IPv4.
		{"::ffff:192.0.2.10", []string{"192.0.2.10/32"}},
		{"::ffff:198.51.100.0/120", []string{"198.51.100.0/24"}},
	} {
		got, err := parseClientList(tc.in)
		if err != nil {
			t.Errorf("parseClientList(%q): %v", tc.in, err)
			continue
		}
		var gs []string
		for _, p := range got {
			gs = append(gs, p.String())
		}
		if strings.Join(gs, " ") != strings.Join(tc.want, " ") {
			t.Errorf("parseClientList(%q) = %v, want %v", tc.in, gs, tc.want)
		}
	}
	for _, tc := range []struct{ in, wantErr string }{
		{"example.com", `"example.com": not an IP address or CIDR prefix`},
		{"192.0.2.300", "not an IP address"},
		{"192.0.2.0/33", "not a valid CIDR prefix"},
		{"192.0.2.0/", "not a valid CIDR prefix"},
		{"192.0.2.5/24", "write 192.0.2.0/24"},
		{"2001:db8::1/32", "write 2001:db8::/32"},
		{"fe80::1%eth0", "zone"},
		{"::ffff:0.0.0.0/90", "write ::ffc0:0:0/90"},
		{"192.0.2.1 192.0.2.2", "not an IP address"},
		{"192.0.2.1;192.0.2.2", "not an IP address"},
	} {
		_, err := parseClientList(tc.in)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("parseClientList(%q) error = %v, want one containing %q", tc.in, err, tc.wantErr)
		}
	}
}

func TestClientListMatching(t *testing.T) {
	list, err := parseClientList("192.0.2.10, 198.51.100.0/24, 2001:db8:1234::/48, 2001:db8:ffff::7")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"198.51.100.0", true},
		{"198.51.100.255", true},
		{"198.51.101.1", false},
		// A dual-stack socket reports IPv4 clients as mapped addresses.
		{"::ffff:192.0.2.10", true},
		{"::ffff:198.51.100.77", true},
		{"::ffff:192.0.2.11", false},
		{"2001:db8:1234::1", true},
		{"2001:db8:1234:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8:1235::1", false},
		{"2001:db8:ffff::7", true},
		{"2001:db8:ffff::8", false},
		{"127.0.0.1", false},
		{"::1", false},
	} {
		if got := clientListContains(list, netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("contains %s = %v, want %v", tc.addr, got, tc.want)
		}
	}
	// A zone does not keep an address from matching.
	if !clientListContains(mustList(t, "fe80::/64"), netip.MustParseAddr("fe80::1%eth0")) {
		t.Error("fe80::1 with zone eth0 not in fe80::/64")
	}
	// An IPv4 prefix does not match IPv6 addresses outside the mapped range.
	if clientListContains(mustList(t, "0.0.0.0/0"), netip.MustParseAddr("2001:db8::1")) {
		t.Error("0.0.0.0/0 contains 2001:db8::1")
	}
	if !clientListContains(nil, netip.MustParseAddr("203.0.113.1")) {
		t.Error("the empty list must allow every client")
	}
}

func mustList(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	l, err := parseClientList(s)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestClientAllowedLoopbackAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		l    statListener
		raw  string
		addr string
		want bool
	}{
		{statAdmin, "192.0.2.10", "127.0.0.1", true},
		{statAdmin, "192.0.2.10", "::1", true},
		{statAdmin, "192.0.2.10", "::ffff:127.0.0.1", true},
		{statAdmin, "192.0.2.10", "192.0.2.10", true},
		{statAdmin, "192.0.2.10", "192.0.2.11", false},
		// Loopback is a rule of the admin listener only.
		{statWebDAV, "192.0.2.10", "127.0.0.1", false},
		{statWebDAV, "192.0.2.10", "::1", false},
		{statWebDAV, "", "203.0.113.9", true},
		// A list that does not parse allows nothing (but loopback on admin).
		{statWebDAV, "bogus", "203.0.113.9", false},
		{statAdmin, "bogus", "203.0.113.9", false},
		{statAdmin, "bogus", "127.0.0.1", true},
	} {
		if got := clientAllowedBy(tc.l, tc.raw, netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("clientAllowedBy(%s, %q, %s) = %v, want %v", statListenerNames[tc.l], tc.raw, tc.addr, got, tc.want)
		}
	}

	// clientAllowed reads the running configuration and follows changes.
	c := defaultConfig()
	c.WebDAVAllowedClients = "192.0.2.0/24"
	clientListTestEnv(t, c)
	if !clientAllowed(statWebDAV, netip.MustParseAddr("192.0.2.5")) || clientAllowed(statWebDAV, netip.MustParseAddr("192.0.3.5")) {
		t.Error("clientAllowed does not follow webdav_allowed_clients")
	}
	c.WebDAVAllowedClients = "192.0.3.0/24"
	setConf(c)
	if clientAllowed(statWebDAV, netip.MustParseAddr("192.0.2.5")) || !clientAllowed(statWebDAV, netip.MustParseAddr("192.0.3.5")) {
		t.Error("clientAllowed keeps the old list after a change")
	}
}

func TestAdminLockoutError(t *testing.T) {
	for _, tc := range []struct {
		raw, remote string
		refused     bool
	}{
		{"", "203.0.113.5:50000", false},
		{"203.0.113.5", "203.0.113.5:50000", false},
		{"203.0.113.0/24", "203.0.113.5:50000", false},
		{"198.51.100.1", "203.0.113.5:50000", true},
		{"198.51.100.1", "[::ffff:203.0.113.5]:50000", true},
		{"203.0.113.5", "[::ffff:203.0.113.5]:50000", false},
		{"2001:db8::/32", "[2001:db8::1]:443", false},
		{"2001:db8::/32", "[2001:db9::1]:443", true},
		// An SSH tunnel arrives over loopback, which is always allowed.
		{"198.51.100.1", "127.0.0.1:40000", false},
		{"198.51.100.1", "[::1]:40000", false},
	} {
		err := adminLockoutError(tc.raw, tc.remote)
		if (err != nil) != tc.refused {
			t.Errorf("adminLockoutError(%q, %q) = %v, want refused=%v", tc.raw, tc.remote, err, tc.refused)
		}
		if err != nil && (!strings.Contains(err.Error(), "SSH tunnel") || strings.ContainsAny(err.Error(), ";—")) {
			t.Errorf("message %q", err)
		}
	}
}

func TestInvalidClientListStopsStart(t *testing.T) {
	dir := t.TempDir()
	clientListTestEnv(t, defaultConfig())
	for _, key := range clientListKeys {
		path := filepath.Join(dir, key+".conf")
		if err := os.WriteFile(path, []byte(key+` = "192.0.2.1, 10.0.0.300"`+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadConfig([]string{"-config", path}, false)
		if err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "10.0.0.300") {
			t.Errorf("%s: loadConfig error = %v, want one naming the key and the entry", key, err)
		}
	}
	path := filepath.Join(dir, "ok.conf")
	os.WriteFile(path, []byte(`webdav_allowed_clients = "192.0.2.1, 2001:db8::/32"`+"\n"+`webgui_allowed_clients = ""`+"\n"), 0600)
	c, _, err := loadConfig([]string{"-config", path}, false)
	if err != nil || c.WebDAVAllowedClients != "192.0.2.1, 2001:db8::/32" {
		t.Errorf("valid lists: %v, %q", err, c.WebDAVAllowedClients)
	}
}

// fakeConn is a net.Conn that only records Close.
type fakeConn struct {
	net.Conn
	closed bool
}

func (c *fakeConn) Close() error { c.closed = true; return nil }

func TestClientHelloVerdict(t *testing.T) {
	for _, tc := range []struct {
		denied bool
		protos []string
		want   handshakeVerdict
	}{
		{false, []string{"h2", "http/1.1"}, handshakeNormal},
		{false, nil, handshakeNormal},
		{false, []string{"acme-tls/1"}, handshakeNormal},
		{true, []string{"acme-tls/1"}, handshakeACMEOnly},
		{true, []string{"acme-tls/1", "acme-tls/1"}, handshakeACMEOnly},
		{true, nil, handshakeDrop},
		{true, []string{"h2", "http/1.1"}, handshakeDrop},
		{true, []string{"http/1.1"}, handshakeDrop},
		{true, []string{"acme-tls/1", "http/1.1"}, handshakeDrop},
		{true, []string{"http/1.1", "acme-tls/1"}, handshakeDrop},
		{true, []string{""}, handshakeDrop},
	} {
		if got := clientHelloVerdict(tc.denied, &tls.ClientHelloInfo{SupportedProtos: tc.protos}); got != tc.want {
			t.Errorf("clientHelloVerdict(%v, %q) = %v, want %v", tc.denied, tc.protos, got, tc.want)
		}
	}

	// The callback itself, with ClientHelloInfo values as crypto/tls
	// builds them on the WebDAV listener: Conn is the countingConn.
	clientListTestEnv(t, defaultConfig())
	base := &tls.Config{NextProtos: []string{"h2", "http/1.1", acmeALPN}}
	get := clientListGetConfigForClient(base)
	hello := func(denied bool, protos ...string) (*tls.ClientHelloInfo, *fakeConn) {
		fc := &fakeConn{}
		cc := &countingConn{Conn: fc, listener: statWebDAV, acme: true, addr: netip.MustParseAddr("203.0.113.9")}
		cc.denied.Store(denied)
		return &tls.ClientHelloInfo{Conn: cc, SupportedProtos: protos}, fc
	}
	before := clientDrops[statWebDAV].state().Total

	h, fc := hello(false, "h2", "http/1.1")
	if cfg, err := get(h); cfg != nil || err != nil || fc.closed {
		t.Errorf("allowed client: config %v, err %v, closed %v; want the listener's config", cfg, err, fc.closed)
	}
	h, fc = hello(true, "h2", "http/1.1")
	if cfg, err := get(h); cfg != nil || !errors.Is(err, errClientNotAllowed) || !fc.closed {
		t.Errorf("denied HTTP client: config %v, err %v, closed %v; want a reset", cfg, err, fc.closed)
	}
	h, fc = hello(true)
	if _, err := get(h); !errors.Is(err, errClientNotAllowed) || !fc.closed {
		t.Errorf("denied client without ALPN: err %v, closed %v; want a reset", err, fc.closed)
	}
	h, fc = hello(true, acmeALPN)
	cfg, err := get(h)
	if err != nil || cfg == nil || fc.closed {
		t.Fatalf("denied ACME validation: config %v, err %v, closed %v; want the ACME-only config", cfg, err, fc.closed)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != acmeALPN || cfg.GetConfigForClient != nil {
		t.Errorf("ACME-only config offers %q", cfg.NextProtos)
	}
	if cfg.VerifyConnection(tls.ConnectionState{NegotiatedProtocol: "http/1.1"}) == nil ||
		cfg.VerifyConnection(tls.ConnectionState{NegotiatedProtocol: ""}) == nil ||
		cfg.VerifyConnection(tls.ConnectionState{NegotiatedProtocol: acmeALPN}) != nil {
		t.Error("ACME-only config must accept acme-tls/1 and nothing else")
	}
	if got := clientDrops[statWebDAV].state().Total - before; got != 2 {
		t.Errorf("dropped handshakes counted: %d, want 2", got)
	}
}

func TestDropCounterLogsSummaryOncePerMinute(t *testing.T) {
	buf := clientListTestEnv(t, defaultConfig())
	d := &dropCounter{listener: statAdmin}
	now := time.Now()
	for i := range 8 {
		d.record(netip.MustParseAddr("192.0.2."+string(rune('1'+i))), now)
	}
	lines := strings.Count(buf.String(), "connections dropped")
	if lines != 1 {
		t.Fatalf("log lines after 8 drops: %d, want 1\n%s", lines, buf)
	}
	if !strings.Contains(buf.String(), "count=1") {
		t.Errorf("first line: %s", buf)
	}
	// The rest waits for the minute to pass.
	d.mu.Lock()
	pending, samples, scheduled := d.pending, len(d.samples), d.scheduled
	d.mu.Unlock()
	if pending != 7 || samples != dropSamples || !scheduled {
		t.Errorf("pending %d, samples %d, scheduled %v", pending, samples, scheduled)
	}
	d.flush()
	out := buf.String()
	if strings.Count(out, "connections dropped") != 2 || !strings.Contains(out, "count=7") ||
		!strings.Contains(out, "listener=admin") || !strings.Contains(out, "192.0.2.2,192.0.2.3") {
		t.Errorf("summary line: %s", out)
	}
	st := d.state()
	if st.Total != 8 || len(st.Recent) != dropSamples || st.Recent[0] != "192.0.2.8" {
		t.Errorf("state %+v", st)
	}
}

// startClientListServer serves a WebDAV-like listener on loopback with the
// real listener wrapper and newServer, answering "ok".
func startClientListServer(t *testing.T, acme bool, tc *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("webdav", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	wrapped := trackConns(ln, "webdav", 16, acme)
	if tc != nil {
		srv.TLSConfig = tc
		go srv.ServeTLS(wrapped, "", "")
	} else {
		go srv.Serve(wrapped)
	}
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// rawRequest sends one HTTP/1.1 request on c and returns the status line,
// or the error if the connection ends without any response.
func rawRequest(c net.Conn) (string, error) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.Status, nil
}

// TestClientListListener runs the WebDAV list on a real loopback listener:
// a client outside the list gets a reset and not a single byte, and Apply
// resets an open connection whose address it takes out of the list.
func TestClientListListener(t *testing.T) {
	c := defaultConfig()
	c.WebDAVAllowedClients = "192.0.2.1"
	buf := clientListTestEnv(t, c)
	addr := startClientListServer(t, false, nil)
	before := clientDrops[statWebDAV].state().Total

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	conn.Close()
	if n != 0 || err == nil || !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("client outside the list: read %d bytes, err %v; want a connection reset and no data", n, err)
	}
	if got := clientDrops[statWebDAV].state(); got.Total-before != 1 || got.Recent[0] != "127.0.0.1" {
		t.Errorf("drop not counted: %+v", got)
	}

	// IPv6 prefix and an IPv4 entry: 127.0.0.1 matches 127.0.0.0/8.
	c.WebDAVAllowedClients = "2001:db8::/32, 127.0.0.0/8"
	setConf(c)
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if status, err := rawRequest(conn); err != nil || status != "200 OK" {
		t.Fatalf("client in the list: %q, %v", status, err)
	}

	// Apply takes the address out: the open keep-alive connection is reset.
	c.WebDAVAllowedClients = "2001:db8::/32"
	setConf(c)
	if n := running.conns.enforceClientLists(); n < 1 {
		t.Errorf("enforceClientLists reset %d connections, want at least 1", n)
	}
	if status, err := rawRequest(conn); err == nil {
		t.Errorf("connection after Apply still served: %q", status)
	}

	// No line per drop: a burst gives one summary line at most.
	for range 5 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Read(make([]byte, 1))
			c.Close()
		}
	}
	if got := strings.Count(buf.String(), "connections dropped"); got > 1 {
		t.Errorf("%d summary lines within a minute, want at most 1", got)
	}
}

// TestClientListACMEListener runs the WebDAV listener with tls_mode acme
// on loopback: a client outside the list that offers HTTP is reset in the
// handshake, a handshake that offers only acme-tls/1 completes with the
// challenge protocol but never reaches HTTP, and a client in the list is
// served.
func TestClientListACMEListener(t *testing.T) {
	c := defaultConfig()
	c.WebDAVAllowedClients = "192.0.2.1"
	clientListTestEnv(t, c)
	cert, err := loadOrCreateAdminCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1", acmeALPN},
		Certificates: []tls.Certificate{cert},
	}
	base.GetConfigForClient = clientListGetConfigForClient(base)
	addr := startClientListServer(t, true, base)
	before := clientDrops[statWebDAV].state().Total

	dial := func(protos ...string) (*tls.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		return tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: protos})
	}

	// Outside the list, offering HTTP: no handshake.
	for _, protos := range [][]string{{"h2", "http/1.1"}, {"http/1.1"}, nil, {acmeALPN, "http/1.1"}} {
		if tc, err := dial(protos...); err == nil {
			tc.Close()
			t.Errorf("outside the list, ALPN %q: handshake completed", protos)
		}
	}
	if got := clientDrops[statWebDAV].state().Total - before; got != 4 {
		t.Errorf("handshake drops counted: %d, want 4", got)
	}

	// Outside the list, offering only acme-tls/1: the handshake completes,
	// but HTTP on that connection gets nothing.
	tc, err := dial(acmeALPN)
	if err != nil {
		t.Fatalf("ACME-only handshake: %v", err)
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != acmeALPN {
		t.Errorf("negotiated %q, want %q", p, acmeALPN)
	}
	if status, err := rawRequest(tc); err == nil {
		t.Errorf("HTTP over the ACME-only connection answered: %q", status)
	}
	tc.Close()

	// In the list: normal HTTP over TLS. Also, acme-tls/1 never carries
	// HTTP, not even for a client in the list.
	c.WebDAVAllowedClients = "127.0.0.1"
	setConf(c)
	tc, err = dial("http/1.1")
	if err != nil {
		t.Fatalf("client in the list: %v", err)
	}
	if status, err := rawRequest(tc); err != nil || status != "200 OK" {
		t.Errorf("client in the list: %q, %v", status, err)
	}
	tc.Close()
	tc, err = dial(acmeALPN)
	if err != nil {
		t.Fatalf("client in the list, acme-tls/1: %v", err)
	}
	if status, err := rawRequest(tc); err == nil {
		t.Errorf("HTTP over acme-tls/1 answered: %q", status)
	}
	tc.Close()
}

// TestAdminListenerAllowsLoopback: the admin list never locks out loopback.
func TestAdminListenerAllowsLoopback(t *testing.T) {
	c := defaultConfig()
	c.WebGUIAllowedClients = "192.0.2.1"
	clientListTestEnv(t, c)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	go srv.Serve(trackConns(ln, "admin", 16, false))
	defer srv.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if status, err := rawRequest(conn); err != nil || status != "200 OK" {
		t.Errorf("loopback on the admin listener: %q, %v", status, err)
	}
}

// TestSettingsRefuseAdminLockout posts the Network section like the
// browser does and checks that a webgui_allowed_clients that leaves out the
// requesting address is neither saved nor applied.
func TestSettingsRefuseAdminLockout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webdavgo.conf")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.DataDir, c.ConfigFile, c.ConfigRead = dir, path, path
	c.resolve()
	clientListTestEnv(t, c)
	loadTemplates()

	post := func(remote, list string) string {
		form := url.Values{"action": {"apply"}}
		for _, d := range defsOf("network") {
			form.Set(d.key, formValue(&c, d.key))
		}
		form.Set("webgui_allowed_clients", list)
		r := httptest.NewRequest(http.MethodPost, "/admin/settings/network", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetPathValue("section", "network")
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		handleSettingsPOST(w, r)
		return w.Body.String()
	}
	saved := func() string {
		data, _ := os.ReadFile(path)
		return string(data)
	}

	body := post("203.0.113.5:40000", "198.51.100.0/24")
	if !strings.Contains(body, "Refused: your current address 203.0.113.5 is not in this list") ||
		strings.Contains(saved(), "webgui_allowed_clients") || conf().WebGUIAllowedClients != "" {
		t.Fatalf("lockout not refused: file %q, running %q", saved(), conf().WebGUIAllowedClients)
	}
	// Through an SSH tunnel the same list is fine: loopback stays allowed.
	post("127.0.0.1:40000", "198.51.100.0/24")
	if !strings.Contains(saved(), `webgui_allowed_clients = "198.51.100.0/24"`) || conf().WebGUIAllowedClients != "198.51.100.0/24" {
		t.Fatalf("change over loopback not saved and applied: file %q, running %q", saved(), conf().WebGUIAllowedClients)
	}
	// An invalid entry is refused with the entry named.
	body = post("127.0.0.1:40000", "198.51.100.0/24, nonsense")
	if !strings.Contains(body, "&#34;nonsense&#34;: not an IP address or CIDR prefix") {
		t.Errorf("invalid entry not reported")
	}
}

func TestSecurityPageShowsClientListDrops(t *testing.T) {
	c := defaultConfig()
	c.WebDAVAllowedClients = "192.0.2.0/24"
	clientListTestEnv(t, c)
	loadTemplates()
	clientDrops[statWebDAV].record(netip.MustParseAddr("203.0.113.77"), time.Now())
	w := httptest.NewRecorder()
	handleSecurity(w, httptest.NewRequest(http.MethodGet, "/admin/security", nil))
	body := w.Body.String()
	for _, want := range []string{"Client address lists", "<code>192.0.2.0/24</code>", "203.0.113.77", "empty, every client allowed"} {
		if !strings.Contains(body, want) {
			t.Errorf("security page lacks %q", want)
		}
	}
}
