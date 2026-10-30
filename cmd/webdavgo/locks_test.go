// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

const (
	lockTestOwner = "lockowner"
	exclusiveLock = `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>` +
		`<D:locktype><D:write/></D:locktype><D:owner><D:href>https://example.com/alice</D:href></D:owner></D:lockinfo>`
	propLocks = `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:lockdiscovery/><d:supportedlock/></d:prop></d:propfind>`
)

// lockTestEnv prepares a user with the tree /shared/{locked.txt,free.txt,sub/}
// and a read-write share of /shared, and returns the share.
func lockTestEnv(t *testing.T) *Share {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{DataDir: dir}
	setConf(cfg)
	if err := initLogger("", ""); err != nil {
		t.Fatal(err)
	}
	if err := openDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		davHandlers.Delete(lockTestOwner)
		storageUsage.mu.Lock()
		delete(storageUsage.m, lockTestOwner)
		storageUsage.mu.Unlock()
	})
	root := filepath.Join(userDataRoot(lockTestOwner), "shared")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"locked.txt", "free.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &Share{ID: "shr_0123456789abcdef", OwnerUsername: lockTestOwner, Path: "/shared", Permission: "read-write"}
}

// ownerDo sends a request the way the user endpoint dispatches it.
func ownerDo(method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	root := userDataRoot(lockTestOwner)
	if method == "PROPFIND" {
		handlePropfind(w, r, root, "", lockTestOwner, userLocks(lockTestOwner))
		return w
	}
	serveDAV(w, r, davHandlerFor(lockTestOwner, method), filepath.Join(root, filepath.FromSlash(target)), lockTestOwner)
	return w
}

// shareDo sends a request through the share. target is relative to the share.
func shareDo(share *Share, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	prefix := "/s/" + share.ID
	r := httptest.NewRequest(method, prefix+target, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	serveShare(w, r, share, filepath.Join(userDataRoot(share.OwnerUsername), filepath.FromSlash(share.Path)))
	return w
}

// ownerLock takes a lock on the user endpoint and returns its token.
func ownerLock(t *testing.T, target, depth string) string {
	t.Helper()
	w := ownerDo("LOCK", target, exclusiveLock, map[string]string{"Depth": depth, "Timeout": "Second-600"})
	if w.Code != http.StatusOK {
		t.Fatalf("LOCK %s: status %d: %s", target, w.Code, w.Body)
	}
	return strings.Trim(w.Header().Get("Lock-Token"), "<>")
}

type discoveredLock struct {
	Scope struct {
		Exclusive *struct{} `xml:"exclusive"`
	} `xml:"lockscope"`
	Type struct {
		Write *struct{} `xml:"write"`
	} `xml:"locktype"`
	Depth     string `xml:"depth"`
	OwnerHref string `xml:"owner>href"`
	Timeout   string `xml:"timeout"`
	Token     string `xml:"locktoken>href"`
	Root      string `xml:"lockroot>href"`
}

type lockResponse struct {
	Href      string           `xml:"href"`
	Locks     []discoveredLock `xml:"propstat>prop>lockdiscovery>activelock"`
	Supported []struct {
		Scope struct {
			Exclusive *struct{} `xml:"exclusive"`
			Shared    *struct{} `xml:"shared"`
		} `xml:"lockscope"`
		Type struct {
			Write *struct{} `xml:"write"`
		} `xml:"locktype"`
	} `xml:"propstat>prop>supportedlock>lockentry"`
	Status []string `xml:"propstat>status"`
}

// parseLockResponse also proves that the body is well-formed XML. encoding/xml
// lets an undeclared prefix pass, see TestLockOwnerPrefixStaysDeclared for that.
func parseLockResponse(t *testing.T, w *httptest.ResponseRecorder) lockResponse {
	t.Helper()
	if w.Code != http.StatusMultiStatus {
		t.Fatalf("PROPFIND: status %d: %s", w.Code, w.Body)
	}
	dec := xml.NewDecoder(strings.NewReader(w.Body.String()))
	var ms struct {
		Responses []lockResponse `xml:"response"`
	}
	if err := dec.Decode(&ms); err != nil {
		t.Fatalf("response is not valid XML: %v\n%s", err, w.Body)
	}
	if len(ms.Responses) != 1 {
		t.Fatalf("got %d responses, want 1:\n%s", len(ms.Responses), w.Body)
	}
	return ms.Responses[0]
}

func depth0() map[string]string { return map[string]string{"Depth": "0"} }

func readTestFile(t *testing.T, share *Share, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(userDataRoot(share.OwnerUsername), "shared", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestShareWriteRefusedWhileOwnerHoldsLock(t *testing.T) {
	dst := func(p string) map[string]string {
		return map[string]string{"Destination": "/s/shr_0123456789abcdef" + p, "Overwrite": "T"}
	}
	tests := []struct {
		name   string
		lock   string
		depth  string
		method string
		target string
		hdr    map[string]string
	}{
		{"PUT target", "/shared/locked.txt", "0", "PUT", "/locked.txt", nil},
		{"DELETE target", "/shared/locked.txt", "0", "DELETE", "/locked.txt", nil},
		{"MKCOL below infinity lock", "/shared/sub", "infinity", "MKCOL", "/sub/new", nil},
		{"MOVE source", "/shared/locked.txt", "0", "MOVE", "/locked.txt", dst("/moved.txt")},
		{"MOVE destination", "/shared/locked.txt", "0", "MOVE", "/free.txt", dst("/locked.txt")},
		{"COPY destination", "/shared/locked.txt", "0", "COPY", "/free.txt", dst("/locked.txt")},
		{"PROPPATCH target", "/shared/locked.txt", "0", "PROPPATCH", "/locked.txt", nil},
		// The lock root lies above the share root, so only the translated
		// name can run into it.
		{"PUT below lock above share root", "/shared", "infinity", "PUT", "/locked.txt", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			share := lockTestEnv(t)
			ownerLock(t, tt.lock, tt.depth)
			body := ""
			if tt.method == "PROPPATCH" {
				body = `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"/>`
			}
			if w := shareDo(share, tt.method, tt.target, body, tt.hdr); w.Code != http.StatusLocked {
				t.Fatalf("status %d, want 423: %s", w.Code, w.Body)
			}
			if got := readTestFile(t, share, "locked.txt"); got != "original" {
				t.Errorf("locked file changed to %q", got)
			}
		})
	}
}

func TestShareWriteAllowedAfterUnlock(t *testing.T) {
	share := lockTestEnv(t)
	token := ownerLock(t, "/shared/locked.txt", "0")
	if w := shareDo(share, "PUT", "/locked.txt", "changed", nil); w.Code != http.StatusLocked {
		t.Fatalf("while locked: status %d, want 423", w.Code)
	}
	if w := ownerDo("UNLOCK", "/shared/locked.txt", "", map[string]string{"Lock-Token": "<" + token + ">"}); w.Code != http.StatusNoContent {
		t.Fatalf("UNLOCK: status %d", w.Code)
	}
	if w := shareDo(share, "PUT", "/locked.txt", "changed", nil); w.Code >= 300 {
		t.Fatalf("after unlock: status %d: %s", w.Code, w.Body)
	}
	if got := readTestFile(t, share, "locked.txt"); got != "changed" {
		t.Errorf("file holds %q, want the share's write", got)
	}
}

func TestShareWriteOutsideLockAllowed(t *testing.T) {
	share := lockTestEnv(t)
	ownerLock(t, "/shared/locked.txt", "0")
	if w := shareDo(share, "PUT", "/free.txt", "changed", nil); w.Code >= 300 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

// A token is no way past the owner's lock, even the right one: MemLS tokens
// are consecutive numbers a recipient could guess.
func TestShareIgnoresLockToken(t *testing.T) {
	share := lockTestEnv(t)
	token := ownerLock(t, "/shared/locked.txt", "0")
	w := shareDo(share, "PUT", "/locked.txt", "changed", map[string]string{"If": "(<" + token + ">)"})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("status %d, want 412", w.Code)
	}
	if got := readTestFile(t, share, "locked.txt"); got != "original" {
		t.Errorf("locked file changed to %q", got)
	}
}

func TestShareLockMethodsStayNotImplemented(t *testing.T) {
	share := lockTestEnv(t)
	for _, method := range []string{"LOCK", "UNLOCK"} {
		if w := shareDo(share, method, "/locked.txt", exclusiveLock, nil); w.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", method, w.Code)
		}
	}
}

func TestLockDiscoveryOnLockedFile(t *testing.T) {
	lockTestEnv(t)
	token := ownerLock(t, "/shared/locked.txt", "0")
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/locked.txt", propLocks, depth0()))
	if len(got.Locks) != 1 {
		t.Fatalf("got %d locks, want 1", len(got.Locks))
	}
	l := got.Locks[0]
	if l.Scope.Exclusive == nil || l.Type.Write == nil {
		t.Errorf("lockscope or locktype missing: %+v", l)
	}
	if l.Depth != "0" || l.Token != token || l.Root != "/shared/locked.txt" {
		t.Errorf("depth %q token %q root %q", l.Depth, l.Token, l.Root)
	}
	if l.OwnerHref != "https://example.com/alice" {
		t.Errorf("owner %q", l.OwnerHref)
	}
	if l.Timeout != "Second-600" && l.Timeout != "Second-599" {
		t.Errorf("timeout %q", l.Timeout)
	}
}

func TestLockDiscoveryOnDescendantOfInfinityLock(t *testing.T) {
	lockTestEnv(t)
	token := ownerLock(t, "/shared/sub", "infinity")
	if err := os.WriteFile(filepath.Join(userDataRoot(lockTestOwner), "shared", "sub", "child.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/sub/child.txt", propLocks, depth0()))
	if len(got.Locks) != 1 || got.Locks[0].Token != token || got.Locks[0].Root != "/shared/sub" || got.Locks[0].Depth != "infinity" {
		t.Fatalf("descendant shows %+v", got.Locks)
	}
	// A sibling sharing the name prefix is not below the lock root.
	if err := os.Mkdir(filepath.Join(userDataRoot(lockTestOwner), "shared", "subway"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/subway", propLocks, depth0())); len(got.Locks) != 0 {
		t.Errorf("sibling shows %+v", got.Locks)
	}
}

func TestLockDiscoveryDepthZeroDoesNotInherit(t *testing.T) {
	lockTestEnv(t)
	ownerLock(t, "/shared", "0")
	if got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0())); len(got.Locks) != 0 {
		t.Errorf("child of a Depth 0 lock shows %+v", got.Locks)
	}
}

func TestLockDiscoveryAfterExpiry(t *testing.T) {
	lockTestEnv(t)
	// Created in the past rather than waiting for a real timeout.
	_, err := userLocks(lockTestOwner).Create(time.Now().Add(-2*time.Second), webdav.LockDetails{
		Root: "/shared/locked.txt", Duration: time.Second, ZeroDepth: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/locked.txt", propLocks, depth0())); len(got.Locks) != 0 {
		t.Errorf("expired lock shows %+v", got.Locks)
	}
}

func TestLockDiscoveryAfterRefreshAndUnlock(t *testing.T) {
	lockTestEnv(t)
	token := ownerLock(t, "/shared/locked.txt", "0")
	w := ownerDo("LOCK", "/shared/locked.txt", "", map[string]string{"If": "(<" + token + ">)", "Timeout": "Infinite"})
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: status %d", w.Code)
	}
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/locked.txt", propLocks, depth0()))
	if len(got.Locks) != 1 || got.Locks[0].Timeout != "Infinite" {
		t.Fatalf("after refresh: %+v", got.Locks)
	}
	ownerDo("UNLOCK", "/shared/locked.txt", "", map[string]string{"Lock-Token": "<" + token + ">"})
	if got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/locked.txt", propLocks, depth0())); len(got.Locks) != 0 {
		t.Errorf("after unlock: %+v", got.Locks)
	}
}

// x/net's temporary lock for a write looks like a LOCK with Depth 0, no owner
// and no timeout, so only the method can tell them apart.
func TestLockDiscoveryTemporaryVersusClientLock(t *testing.T) {
	lockTestEnv(t)
	ownerDo("PUT", "/shared/free.txt", "changed", nil)
	if n := len(userLocks(lockTestOwner).locks); n != 0 {
		t.Errorf("a PUT left %d recorded locks", n)
	}
	w := ownerDo("LOCK", "/shared/free.txt", `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`, depth0())
	if w.Code != http.StatusOK {
		t.Fatalf("LOCK: status %d", w.Code)
	}
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()))
	if len(got.Locks) != 1 || got.Locks[0].Timeout != "Infinite" {
		t.Errorf("client lock shows %+v", got.Locks)
	}
}

func TestSupportedLockContent(t *testing.T) {
	lockTestEnv(t)
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()))
	if len(got.Supported) != 1 {
		t.Fatalf("got %d lock entries, want 1", len(got.Supported))
	}
	e := got.Supported[0]
	if e.Scope.Exclusive == nil || e.Scope.Shared != nil || e.Type.Write == nil {
		t.Errorf("lock entry %+v", e)
	}
	if strings.Contains(strings.Join(got.Status, " "), "404") {
		t.Errorf("a lock property was answered 404:\n%s", ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()).Body)
	}
}

func TestLockPropertiesInAllprop(t *testing.T) {
	lockTestEnv(t)
	for name, body := range map[string]string{
		"empty":   "",
		"allprop": `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>`,
	} {
		w := ownerDo("PROPFIND", "/shared/free.txt", body, depth0())
		for _, prop := range []string{"<d:supportedlock>", "<d:lockdiscovery/>"} {
			if !strings.Contains(w.Body.String(), prop) {
				t.Errorf("%s: %s missing:\n%s", name, prop, w.Body)
			}
		}
	}
}

// The usual client form leaves the D prefix declared outside the owner
// element, which would break the whole multistatus if copied as is.
func TestLockOwnerPrefixStaysDeclared(t *testing.T) {
	lockTestEnv(t)
	ownerLock(t, "/shared/locked.txt", "0")
	body := ownerDo("PROPFIND", "/shared/locked.txt", propLocks, depth0()).Body.String()
	if !strings.Contains(body, `<d:owner xmlns:D="DAV:"><D:href>`) {
		t.Errorf("owner prefix not declared:\n%s", body)
	}
}

func TestSharePropfindHidesLocks(t *testing.T) {
	share := lockTestEnv(t)
	token := ownerLock(t, "/shared/locked.txt", "0")
	for name, body := range map[string]string{"named": propLocks, "allprop": ""} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PROPFIND", "/s/"+share.ID+"/locked.txt", strings.NewReader(body))
		r.Header.Set("Depth", "0")
		serveShare(w, r, share, filepath.Join(userDataRoot(lockTestOwner), "shared"))
		out := w.Body.String()
		if w.Code != http.StatusMultiStatus {
			t.Fatalf("%s: status %d", name, w.Code)
		}
		if !strings.Contains(out, "<d:supportedlock/>") || !strings.Contains(out, "<d:lockdiscovery/>") {
			t.Errorf("%s: lock properties not empty:\n%s", name, out)
		}
		for _, leak := range []string{token, "/shared/", "example.com/alice", "404"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s: response exposes %q:\n%s", name, leak, out)
			}
		}
	}
}

func TestDAVHeader(t *testing.T) {
	share := lockTestEnv(t)
	if got := shareDo(share, http.MethodOptions, "/", "", nil).Header().Get("DAV"); got != "1" {
		t.Errorf("share: DAV %q, want 1", got)
	}
	if got := ownerDo(http.MethodOptions, "/", "", nil).Header().Get("DAV"); got != "1, 2" {
		t.Errorf("user endpoint: DAV %q, want 1, 2", got)
	}
}

func TestReadShareRefusesProppatch(t *testing.T) {
	share := lockTestEnv(t)
	share.Permission = "read"
	body := `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"/>`
	if w := shareDo(share, "PROPPATCH", "/free.txt", body, nil); w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
}

func TestShareAllowHeader(t *testing.T) {
	share := lockTestEnv(t)
	for _, target := range []string{"/", "/free.txt", "/missing.txt"} {
		allow := shareDo(share, http.MethodOptions, target, "", nil).Header().Get("Allow")
		if allow == "" || strings.Contains(allow, "LOCK") {
			t.Errorf("%s: Allow %q", target, allow)
		}
	}
	allow := ownerDo(http.MethodOptions, "/shared/free.txt", "", nil).Header().Get("Allow")
	if !strings.Contains(allow, "LOCK") || !strings.Contains(allow, "UNLOCK") {
		t.Errorf("user endpoint: Allow %q", allow)
	}
}

func TestPropnameReturnsNamesOnly(t *testing.T) {
	share := lockTestEnv(t)
	token := ownerLock(t, "/shared/free.txt", "0")
	body := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:propname/></d:propfind>`
	for name, w := range map[string]*httptest.ResponseRecorder{
		"user file":  ownerDo("PROPFIND", "/shared/free.txt", body, depth0()),
		"share file": shareDo(share, "PROPFIND", "/free.txt", body, depth0()),
	} {
		if w.Code != http.StatusMultiStatus {
			t.Fatalf("%s: status %d", name, w.Code)
		}
		out := w.Body.String()
		for _, prop := range []string{"getlastmodified", "getetag", "getcontentlength", "getcontenttype", "resourcetype", "creationdate", "displayname", "supportedlock", "lockdiscovery"} {
			if !strings.Contains(out, "<d:"+prop+"/>") {
				t.Errorf("%s: %s missing:\n%s", name, prop, out)
			}
		}
		for _, value := range []string{token, "exclusive", "GMT"} {
			if strings.Contains(out, value) {
				t.Errorf("%s: value %q in response:\n%s", name, value, out)
			}
		}
	}
	// A collection has no content length or type.
	out := ownerDo("PROPFIND", "/shared/sub", body, depth0()).Body.String()
	if strings.Contains(out, "getcontentlength") || !strings.Contains(out, "<d:resourcetype/>") {
		t.Errorf("collection:\n%s", out)
	}
}
