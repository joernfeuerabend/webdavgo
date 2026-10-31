// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf16"
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
	serveDAV(w, r, getDavUser(lockTestOwner).handler, filepath.Join(root, filepath.FromSlash(target)), lockTestOwner)
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

// A token is no way past the owner's lock, even the right one: a recipient
// holds no locks.
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
	token := ownerLock(t, "/shared/locked.txt", "0")
	// Expired by hand rather than waiting for a real timeout.
	m := userLocks(lockTestOwner)
	m.mu.Lock()
	m.locks[token].Expiry = time.Now().Add(-time.Second)
	m.mu.Unlock()
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

// A write leaves no lock behind, and a LOCK without a Timeout header is infinite.
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
	if len(got.Supported) != 2 {
		t.Fatalf("got %d lock entries, want 2", len(got.Supported))
	}
	e, s := got.Supported[0], got.Supported[1]
	if e.Scope.Exclusive == nil || e.Scope.Shared != nil || e.Type.Write == nil {
		t.Errorf("exclusive entry %+v", e)
	}
	if s.Scope.Shared == nil || s.Scope.Exclusive != nil || s.Type.Write == nil {
		t.Errorf("shared entry %+v", s)
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
	if !strings.Contains(body, `<D:owner xmlns:D="DAV:"><D:href>`) {
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

// propfindBoth sends a Depth 0 PROPFIND of the same collection through the user
// endpoint and through the share.
func propfindBoth(share *Share, body string) map[string]*httptest.ResponseRecorder {
	return map[string]*httptest.ResponseRecorder{
		"user":  ownerDo("PROPFIND", "/shared", body, depth0()),
		"share": shareDo(share, "PROPFIND", "/", body, depth0()),
	}
}

func TestPropfindInvalidBody(t *testing.T) {
	share := lockTestEnv(t)
	const d = `xmlns="DAV:"`
	tests := []struct{ name, body string }{
		// The two bodies litmus sends in propfind_invalid and propfind_invalid2.
		{"litmus non-well-formed", `<foo>`},
		{"litmus empty prefix", `<propfind xmlns="DAV:"><prop><bar:foo xmlns:bar=""/></prop></propfind>`},
		{"unclosed root", `<propfind ` + d + `><allprop/>`},
		{"mismatched tag", `<propfind ` + d + `><allprop></prop></propfind>`},
		{"trailing text", `<propfind ` + d + `><allprop/></propfind>garbage`},
		{"trailing element", `<propfind ` + d + `><allprop/></propfind><x/>`},
		{"trailing end tag", `<propfind ` + d + `><allprop/></propfind></propfind>`},
		{"trailing directive", `<propfind ` + d + `><allprop/></propfind><!DOCTYPE x>`},
		{"text before root", `garbage<propfind ` + d + `><allprop/></propfind>`},
		{"late XML declaration", ` <?xml version="1.0"?><propfind ` + d + `><allprop/></propfind>`},
		{"comment only", `<!-- nothing -->`},
		{"undeclared prefix on property", `<propfind xmlns="DAV:"><prop><bar:foo/></prop></propfind>`},
		{"undeclared prefix on attribute", `<propfind xmlns="DAV:" bar:a="1"><allprop/></propfind>`},
		{"undeclared prefix inside ignored element", `<propfind ` + d + `><allprop/><x:y xmlns:x="urn:x"><bar:z/></x:y></propfind>`},
		{"prefix declared only on a sibling", `<propfind ` + d + `><allprop/><a xmlns:bar="urn:b"/><bar:c/></propfind>`},
		{"unknown encoding", `<?xml version="1.0" encoding="no-such-charset"?><propfind ` + d + `><allprop/></propfind>`},
		{"bytes invalid in declared encoding", `<?xml version="1.0" encoding="Shift_JIS"?><propfind ` + d + `><allprop/><x>` + "\xff\xff" + `</x></propfind>`},
		{"UTF-16 cut in a character", "\xff\xfe<\x00p\x00>"},
		{"UTF-16 declared without a mark", `<?xml version="1.0" encoding="UTF-16"?><propfind ` + d + `><allprop/></propfind>`},
		{"repeated attribute", `<propfind ` + d + ` a="1" a="2"><allprop/></propfind>`},
		{"error inside ignored element", `<propfind ` + d + `><allprop/><x:y xmlns:x="urn:x"><z></x:y></propfind>`},
		{"empty prefix on root", `<D:propfind xmlns:D="DAV:" xmlns:bar=""><D:allprop/></D:propfind>`},
		{"empty prefix inside ignored element", `<propfind ` + d + `><allprop/><x:y xmlns:x="urn:x"><z xmlns:bar=""/></x:y></propfind>`},
		{"wrong root name", `<propertyupdate ` + d + `><allprop/></propertyupdate>`},
		{"root without namespace", `<propfind><allprop/></propfind>`},
		{"root in other namespace", `<propfind xmlns="urn:x"><allprop/></propfind>`},
		{"no form", `<propfind ` + d + `/>`},
		{"only extension element", `<propfind ` + d + `><x:y xmlns:x="urn:x"/></propfind>`},
		{"form in other namespace", `<propfind ` + d + `><allprop xmlns="urn:x"/></propfind>`},
		{"prop and allprop", `<propfind ` + d + `><prop><getetag/></prop><allprop/></propfind>`},
		{"allprop and propname", `<propfind ` + d + `><allprop/><propname/></propfind>`},
		{"two props", `<propfind ` + d + `><prop/><prop/></propfind>`},
		{"include alone", `<propfind ` + d + `><include><getetag/></include></propfind>`},
		{"include with prop", `<propfind ` + d + `><prop/><include/></propfind>`},
		{"include with propname", `<propfind ` + d + `><propname/><include/></propfind>`},
		{"include before prop", `<propfind ` + d + `><include/><prop/></propfind>`},
		{"include before propname", `<propfind ` + d + `><include/><propname/></propfind>`},
		{"two includes before allprop", `<propfind ` + d + `><include/><include/><allprop/></propfind>`},
		{"two includes", `<propfind ` + d + `><allprop/><include/><include/></propfind>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for endpoint, w := range propfindBoth(share, tt.body) {
				if w.Code != http.StatusBadRequest {
					t.Errorf("%s: status %d, want 400: %s", endpoint, w.Code, w.Body)
				}
			}
		})
	}
}

func TestPropfindRejectionLogsReasonAtDebug(t *testing.T) {
	lockTestEnv(t)
	var buf bytes.Buffer
	old := logger
	t.Cleanup(func() { logger = old })
	logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ownerDo("PROPFIND", "/shared", `<foo>`, depth0())
	out := buf.String()
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "PROPFIND body rejected") || !strings.Contains(out, "reason=") {
		t.Errorf("log output: %q", out)
	}
}

func TestPropfindAcceptedBody(t *testing.T) {
	share := lockTestEnv(t)
	const ext = `<x:y xmlns:x="urn:x" x:a="1"><z>text</z></x:y>`
	tests := []struct {
		name, body string
		want       string // element the response must hold
		unwanted   string
	}{
		{"empty", "", "<d:getetag>", ""},
		{"line break only", "\n", "<d:getetag>", ""},
		{"whitespace only", " \t\r\n", "<d:getetag>", ""},
		{"UTF-16 whitespace only", utf16Body(" \n", binary.LittleEndian), "<d:getetag>", ""},
		{"prefix declared on an ancestor", `<D:propfind xmlns:D="DAV:"><D:prop xmlns:x="urn:x"><x:y><x:z/></x:y><D:displayname/></D:prop></D:propfind>`, "<d:displayname>", "<d:getetag>"},
		{"prefix declared again on a sibling", `<propfind xmlns="DAV:"><allprop/><x:a xmlns:x="urn:x"/><x:b xmlns:x="urn:x"/></propfind>`, "<d:getetag>", ""},
		{"xml prefix needs no declaration", `<propfind xmlns="DAV:" xml:lang="en"><allprop/></propfind>`, "<d:getetag>", ""},
		{"BOM and declaration", "\xef\xbb\xbf" + `<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>`, "<d:getetag>", ""},
		{"comment and whitespace around root", "<!-- a -->\n" + `<propfind xmlns="DAV:"><allprop/></propfind>` + "\n<!-- b -->\n", "<d:getetag>", ""},
		{"unknown extension element", `<propfind xmlns="DAV:">` + ext + `<allprop/>` + ext + `</propfind>`, "<d:getetag>", ""},
		{"unknown DAV element", `<propfind xmlns="DAV:"><allprop/><future><deep/></future></propfind>`, "<d:getetag>", ""},
		{"extension element with prop", `<propfind xmlns="DAV:">` + ext + `<prop><displayname/></prop></propfind>`, "<d:displayname>", "<d:getetag>"},
		{"extension element with propname", `<propfind xmlns="DAV:"><propname/>` + ext + `</propfind>`, "<d:getetag/>", "GMT"},
		{"extension children do not count as properties", `<propfind xmlns="DAV:"><prop><displayname/></prop>` + ext + `</propfind>`, "<d:displayname>", "<d:y/>"},
		{"default namespace undeclared on a child", `<D:propfind xmlns:D="DAV:"><D:allprop/><y xmlns=""/></D:propfind>`, "<d:getetag>", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for endpoint, w := range propfindBoth(share, tt.body) {
				out := w.Body.String()
				if w.Code != http.StatusMultiStatus || !strings.Contains(out, tt.want) {
					t.Errorf("%s: status %d, want 207 with %s: %s", endpoint, w.Code, tt.want, out)
				}
				if tt.unwanted != "" && strings.Contains(out, tt.unwanted) {
					t.Errorf("%s: %s in response: %s", endpoint, tt.unwanted, out)
				}
			}
		})
	}
}

// ---- WebDAV locking ----------------------------------------------------------

func lockBody(scope, owner string) string {
	return `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:` + scope + `/></D:lockscope>` +
		`<D:locktype><D:write/></D:locktype>` + owner + `</D:lockinfo>`
}

// takeLock asserts that a LOCK succeeds and returns its token.
func takeLock(t *testing.T, target, scope, depth string) string {
	t.Helper()
	w := ownerDo("LOCK", target, lockBody(scope, ""), map[string]string{"Depth": depth})
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("LOCK %s %s depth %s: status %d: %s", target, scope, depth, w.Code, w.Body)
	}
	return strings.Trim(w.Header().Get("Lock-Token"), "<>")
}

func ifToken(token string) map[string]string { return map[string]string{"If": "(<" + token + ">)"} }

func ownerFile(name string) string {
	return filepath.Join(userDataRoot(lockTestOwner), filepath.FromSlash(name))
}

func wantStatus(t *testing.T, what string, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("%s: status %d, want %d: %s", what, w.Code, want, w.Body)
	}
}

// x/net's lock system decides nothing.
func TestXNetLockSystemIsNotUsed(t *testing.T) {
	share := lockTestEnv(t)
	if _, ok := getDavUser(lockTestOwner).handler.LockSystem.(noLockSystem); !ok {
		t.Error("user handler has a real lock system")
	}
	token := ownerLock(t, "/shared/locked.txt", "0")
	if !strings.HasPrefix(token, "urn:uuid:") {
		t.Errorf("token %q does not come from webdavgo", token)
	}
	// x/net would answer 412 for an If header of its own evaluation.
	wantStatus(t, "PUT with token", ownerDo("PUT", "/shared/locked.txt", "x", ifToken(token)), http.StatusCreated)
	wantStatus(t, "share PUT", shareDo(share, "PUT", "/free.txt", "x", nil), http.StatusCreated)
}

func TestLockConflicts(t *testing.T) {
	tests := []struct {
		name                string
		first, firstDepth   string
		firstTarget         string
		second, secondDepth string
		secondTarget        string
		want                int
	}{
		{"exclusive then exclusive", "exclusive", "0", "/shared/free.txt", "exclusive", "0", "/shared/free.txt", http.StatusLocked},
		{"exclusive then shared", "exclusive", "0", "/shared/free.txt", "shared", "0", "/shared/free.txt", http.StatusLocked},
		{"shared then exclusive", "shared", "0", "/shared/free.txt", "exclusive", "0", "/shared/free.txt", http.StatusLocked},
		{"shared then shared", "shared", "0", "/shared/free.txt", "shared", "0", "/shared/free.txt", http.StatusOK},
		{"infinity covers member", "exclusive", "infinity", "/shared", "shared", "0", "/shared/free.txt", http.StatusLocked},
		{"shared infinity with shared member", "shared", "infinity", "/shared", "shared", "0", "/shared/free.txt", http.StatusOK},
		{"depth 0 does not cover member", "exclusive", "0", "/shared", "exclusive", "0", "/shared/free.txt", http.StatusOK},
		{"sibling", "exclusive", "0", "/shared/free.txt", "exclusive", "0", "/shared/locked.txt", http.StatusOK},
		{"name prefix is no member", "exclusive", "infinity", "/shared/sub", "exclusive", "0", "/shared/subway", http.StatusCreated},
		{"depth 0 on collection with member lock", "exclusive", "0", "/shared/free.txt", "exclusive", "0", "/shared", http.StatusOK},
		{"infinity on collection with member lock", "exclusive", "0", "/shared/free.txt", "exclusive", "infinity", "/shared", http.StatusMultiStatus},
		{"shared infinity with exclusive member", "exclusive", "0", "/shared/free.txt", "shared", "infinity", "/shared", http.StatusMultiStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockTestEnv(t)
			takeLock(t, tt.firstTarget, tt.first, tt.firstDepth)
			w := ownerDo("LOCK", tt.secondTarget, lockBody(tt.second, ""), map[string]string{"Depth": tt.secondDepth})
			wantStatus(t, "second LOCK", w, tt.want)
		})
	}
}

func TestLockOnCollectionWithLockedMemberReports(t *testing.T) {
	lockTestEnv(t)
	takeLock(t, "/shared/free.txt", "exclusive", "0")
	w := ownerDo("LOCK", "/shared", lockBody("exclusive", ""), map[string]string{"Depth": "infinity"})
	wantStatus(t, "LOCK", w, http.StatusMultiStatus)
	out := w.Body.String()
	for _, want := range []string{"<d:href>/shared/free.txt</d:href><d:status>HTTP/1.1 423 Locked", "<d:href>/shared</d:href><d:status>HTTP/1.1 424 Failed Dependency"} {
		if !strings.Contains(out, want) {
			t.Errorf("%s missing: %s", want, out)
		}
	}
	if w.Header().Get("Lock-Token") != "" {
		t.Error("a refused LOCK returned a token")
	}
	if got := parseLockResponse(t, ownerDo("PROPFIND", "/shared", propLocks, depth0())); len(got.Locks) != 0 {
		t.Errorf("collection is locked: %+v", got.Locks)
	}
}

func TestLockRequestValidation(t *testing.T) {
	lockTestEnv(t)
	for name, tt := range map[string]struct {
		body, depth string
		want        int
	}{
		"depth 1":         {lockBody("exclusive", ""), "1", http.StatusBadRequest},
		"not well-formed": {`<D:lockinfo xmlns:D="DAV:">`, "0", http.StatusBadRequest},
		"wrong root":      {`<D:propfind xmlns:D="DAV:"/>`, "0", http.StatusBadRequest},
		"no scope":        {`<D:lockinfo xmlns:D="DAV:"><D:locktype><D:write/></D:locktype></D:lockinfo>`, "0", http.StatusBadRequest},
		"both scopes":     {`<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`, "0", http.StatusBadRequest},
		"other type":      {`<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:read/></D:locktype></D:lockinfo>`, "0", http.StatusNotImplemented},
	} {
		wantStatus(t, name, ownerDo("LOCK", "/shared/free.txt", tt.body, map[string]string{"Depth": tt.depth}), tt.want)
	}
}

func TestLockOnUnmappedURL(t *testing.T) {
	lockTestEnv(t)
	w := ownerDo("LOCK", "/shared/new.txt", lockBody("exclusive", ""), depth0())
	wantStatus(t, "unmapped", w, http.StatusCreated)
	fi, err := os.Stat(ownerFile("/shared/new.txt"))
	if err != nil || fi.Size() != 0 {
		t.Fatalf("resource: %v, %v", fi, err)
	}
	wantStatus(t, "missing parent", ownerDo("LOCK", "/shared/none/new.txt", lockBody("exclusive", ""), depth0()), http.StatusConflict)
	wantStatus(t, "file as parent", ownerDo("LOCK", "/shared/free.txt/new.txt", lockBody("exclusive", ""), depth0()), http.StatusConflict)
	wantStatus(t, "existing", ownerDo("LOCK", "/shared/free.txt", lockBody("exclusive", ""), depth0()), http.StatusOK)
	data, err := os.ReadFile(ownerFile("/shared/free.txt"))
	if err != nil || string(data) != "original" {
		t.Errorf("existing file holds %q, %v", data, err)
	}
}

func TestUnmappedLockNeedsTokenOfLockedParent(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/sub", "exclusive", "0")
	wantStatus(t, "no token", ownerDo("LOCK", "/shared/sub/new.txt", lockBody("exclusive", ""), depth0()), http.StatusLocked)
	hdr := map[string]string{"If": "</shared/sub> (<" + token + ">)", "Depth": "0"}
	wantStatus(t, "token", ownerDo("LOCK", "/shared/sub/new.txt", lockBody("exclusive", ""), hdr), http.StatusCreated)
}

func TestLockRefresh(t *testing.T) {
	lockTestEnv(t)
	token := ownerLock(t, "/shared/sub", "infinity")
	hdr := func(timeout string) map[string]string {
		return map[string]string{"If": "(<" + token + ">)", "Timeout": timeout}
	}
	for timeout, want := range map[string]string{
		"Second-100":           "Second-100",
		"Second-200, Infinite": "Second-200",
		"Bogus, Second-300":    "Second-300",
		"Infinite, Second-400": "Infinite",
		"infinite":             "Infinite",
		"Second-4294967295":    "Second-4294967295",
	} {
		w := ownerDo("LOCK", "/shared/sub", "", hdr(timeout))
		wantStatus(t, timeout, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<d:timeout>"+want+"</d:timeout>") || !strings.Contains(w.Body.String(), token) {
			t.Errorf("%s: %s", timeout, w.Body)
		}
		if w.Header().Get("Lock-Token") != "" {
			t.Errorf("%s: a refresh creates no token", timeout)
		}
	}
	wantStatus(t, "too long", ownerDo("LOCK", "/shared/sub", "", hdr("Second-4294967296")), http.StatusBadRequest)
	wantStatus(t, "bad timeout", ownerDo("LOCK", "/shared/sub", "", hdr("soon")), http.StatusBadRequest)
	wantStatus(t, "no If", ownerDo("LOCK", "/shared/sub", "", nil), http.StatusBadRequest)
	wantStatus(t, "unknown token", ownerDo("LOCK", "/shared/sub", "", ifToken("urn:uuid:nope")), http.StatusPreconditionFailed)
	wantStatus(t, "no token in the true list", ownerDo("LOCK", "/shared/sub", "", map[string]string{"If": "(Not <DAV:no-lock>)"}), http.StatusPreconditionFailed)
	wantStatus(t, "lock does not apply here", ownerDo("LOCK", "/shared/free.txt", "", ifToken(token)), http.StatusPreconditionFailed)
	// Through a member of the locked collection.
	if err := os.WriteFile(ownerFile("/shared/sub/child.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "member", ownerDo("LOCK", "/shared/sub/child.txt", "", ifToken(token)), http.StatusOK)
}

func TestLockTokenAndResponse(t *testing.T) {
	lockTestEnv(t)
	re := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := range 50 {
		token := newLockToken()
		if !re.MatchString(token) || seen[token] {
			t.Fatalf("token %d: %q", i, token)
		}
		seen[token] = true
	}
	w := ownerDo("LOCK", "/shared/free.txt", exclusiveLock, map[string]string{"Depth": "0", "Timeout": "Second-600"})
	wantStatus(t, "LOCK", w, http.StatusOK)
	header := w.Header().Get("Lock-Token")
	if !strings.HasPrefix(header, "<urn:uuid:") || !strings.HasSuffix(header, ">") {
		t.Errorf("Lock-Token %q", header)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("Content-Type %q", ct)
	}
	var prop struct {
		XMLName xml.Name         `xml:"DAV: prop"`
		Locks   []discoveredLock `xml:"lockdiscovery>activelock"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &prop); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	if len(prop.Locks) != 1 || "<"+prop.Locks[0].Token+">" != header || prop.Locks[0].Root != "/shared/free.txt" ||
		prop.Locks[0].Depth != "0" || prop.Locks[0].Scope.Exclusive == nil || prop.Locks[0].OwnerHref != "https://example.com/alice" {
		t.Errorf("response %+v: %s", prop.Locks, w.Body)
	}
}

// ownerElementNames returns the resolved names of the elements inside DAV:owner.
func ownerElementNames(t *testing.T, doc string) []string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	var names []string
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("not well-formed: %v: %s", err, doc)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if depth > 0 || el.Name == (xml.Name{Space: "DAV:", Local: "owner"}) {
				depth++
				names = append(names, el.Name.Space+" "+el.Name.Local)
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		}
	}
}

func TestLockOwnerKeepsNamespaces(t *testing.T) {
	tests := []struct {
		name, body string
		want       []string
	}{
		{"prefix on the root", `<D:lockinfo xmlns:D="DAV:" xmlns:x="urn:x"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><x:who a="1 &amp; 2">me &amp; you</x:who></D:owner></D:lockinfo>`,
			[]string{"DAV: owner", "urn:x who"}},
		{"default namespace", `<lockinfo xmlns="DAV:"><lockscope><exclusive/></lockscope><locktype><write/></locktype><owner><href>a</href></owner></lockinfo>`,
			[]string{"DAV: owner", "DAV: href"}},
		{"other default inside prefixed owner", `<D:lockinfo xmlns:D="DAV:" xmlns="urn:y"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><who/></D:owner></D:lockinfo>`,
			[]string{"DAV: owner", "urn:y who"}},
		{"our own prefix bound elsewhere", `<D:lockinfo xmlns:D="DAV:" xmlns:d="urn:other"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner><d:who/></D:owner></D:lockinfo>`,
			[]string{"DAV: owner", "urn:other who"}},
		{"declared inside", `<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype><D:owner xmlns:z="urn:z"><z:a><z:b xmlns:z="urn:zz"/></z:a></D:owner></D:lockinfo>`,
			[]string{"DAV: owner", "urn:z a", "urn:zz b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockTestEnv(t)
			w := ownerDo("LOCK", "/shared/free.txt", tt.body, depth0())
			wantStatus(t, "LOCK", w, http.StatusOK)
			for where, doc := range map[string]string{
				"LOCK":     w.Body.String(),
				"PROPFIND": ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()).Body.String(),
			} {
				if got := ownerElementNames(t, doc); !slices.Equal(got, tt.want) {
					t.Errorf("%s: %q, want %q: %s", where, got, tt.want, doc)
				}
			}
		})
	}
}

func TestLockOwnerUndeclaredPrefixRejected(t *testing.T) {
	lockTestEnv(t)
	body := lockBody("exclusive", `<D:owner><nope:who/></D:owner>`)
	wantStatus(t, "LOCK", ownerDo("LOCK", "/shared/free.txt", body, depth0()), http.StatusBadRequest)
}

func TestLockDiscoveryListsAllApplyingLocks(t *testing.T) {
	lockTestEnv(t)
	parent := takeLock(t, "/shared", "shared", "infinity")
	own := takeLock(t, "/shared/free.txt", "shared", "0")
	got := parseLockResponse(t, ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()))
	if len(got.Locks) != 2 {
		t.Fatalf("locks %+v", got.Locks)
	}
	if got.Locks[0].Token != parent || got.Locks[0].Root != "/shared" || got.Locks[1].Token != own {
		t.Errorf("locks %+v", got.Locks)
	}
	if !strings.Contains(ownerDo("PROPFIND", "/shared/free.txt", propLocks, depth0()).Body.String(), "<d:shared/></d:lockscope><d:locktype>") {
		t.Error("scope not reported as shared")
	}
}

func TestIfHeaderEvaluation(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/locked.txt", "exclusive", "0")
	other := takeLock(t, "/shared/sub", "exclusive", "0")
	put := func(name, content string, hdr string) *httptest.ResponseRecorder {
		t.Helper()
		return ownerDo("PUT", name, content, map[string]string{"If": hdr})
	}
	etagOf := func(name string) string {
		t.Helper()
		fi, err := os.Stat(ownerFile(name))
		if err != nil {
			t.Fatal(err)
		}
		return fileETag(fi)
	}
	const free, locked = "/shared/free.txt", "/shared/locked.txt"
	host := "http://example.com"
	tests := []struct {
		name   string
		target string
		hdr    func(etag string) string
		want   int
	}{
		// The header forms litmus sends, on a locked resource.
		{"cond_put", locked, func(e string) string { return "(<" + token + "> [" + e + "])" }, http.StatusCreated},
		{"fail_cond_put", locked, func(e string) string { return "(<DAV:no-lock> [" + e + "])" }, http.StatusPreconditionFailed},
		{"cond_put_with_not", locked, func(string) string { return "(<" + token + ">) (Not <DAV:no-lock>)" }, http.StatusCreated},
		{"cond_put_corrupt_token", locked, func(string) string { return "(<" + token + "x>) (Not <DAV:no-lock>)" }, http.StatusLocked},
		{"complex_cond_put", locked, func(e string) string { return "(<" + token + "> [" + e + "]) (Not <DAV:no-lock> [" + e + "])" }, http.StatusCreated},
		{"fail_complex_cond_put", locked, func(string) string { return "(<" + token + `> ["bad"]) (Not <DAV:no-lock> ["bad"])` }, http.StatusPreconditionFailed},
		// Unlocked resource, so only the header decides.
		{"etag matches", free, func(e string) string { return "([" + e + "])" }, http.StatusCreated},
		{"etag differs", free, func(string) string { return `(["bad"])` }, http.StatusPreconditionFailed},
		{"weak etag never matches", free, func(e string) string { return "([W/" + e + "])" }, http.StatusPreconditionFailed},
		{"Not etag", free, func(string) string { return `(Not ["bad"])` }, http.StatusCreated},
		{"Not of the matching etag", free, func(e string) string { return "(Not [" + e + "])" }, http.StatusPreconditionFailed},
		{"second list true", free, func(e string) string { return `(["bad"]) ([` + e + "])" }, http.StatusCreated},
		{"token of another resource", free, func(string) string { return "(<" + token + ">)" }, http.StatusPreconditionFailed},
		{"lowercase not", free, func(string) string { return "(not <DAV:no-lock>)" }, http.StatusCreated},
		{"tagged, true", free, func(e string) string { return "<" + host + free + "> ([" + e + "])" }, http.StatusCreated},
		{"tagged by path", free, func(e string) string { return "<" + free + "> ([" + e + "])" }, http.StatusCreated},
		{"tagged, other resource true", free, func(string) string { return "<" + host + locked + "> (<" + token + ">)" }, http.StatusCreated},
		{"tagged, false", free, func(string) string { return "<" + host + free + `> (["bad"])` }, http.StatusPreconditionFailed},
		{"tagged, other host", free, func(e string) string { return "<http://example.org" + free + "> ([" + e + "])" }, http.StatusPreconditionFailed},
		// The token is true for its tagged resource, but not the target's token.
		{"tagged token does not open another lock", locked, func(string) string { return "</shared/sub> (<" + other + ">)" }, http.StatusLocked},
		{"untagged list applies to the target only", locked, func(string) string { return "(<" + other + ">)" }, http.StatusPreconditionFailed},
		{"Not of the token is no submission", locked, func(string) string { return "(Not <urn:uuid:other>)" }, http.StatusLocked},
		{"malformed", free, func(string) string { return "(<a>" }, http.StatusBadRequest},
		{"empty list", free, func(string) string { return "()" }, http.StatusBadRequest},
		{"tag without list", free, func(string) string { return "<" + free + ">" }, http.StatusBadRequest},
		{"tagged after untagged", free, func(string) string { return "(Not <a>) </x> (Not <b>)" }, http.StatusBadRequest},
		{"bare word", free, func(string) string { return "token" }, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantStatus(t, tt.name, put(tt.target, "x", tt.hdr(etagOf(tt.target))), tt.want)
		})
	}
	// An unmapped resource has no entity tag and no lock.
	wantStatus(t, "etag of nothing", put("/shared/none.txt", "x", `(["bad"])`), http.StatusPreconditionFailed)
	wantStatus(t, "Not etag of nothing", put("/shared/none.txt", "x", `(Not ["bad"])`), http.StatusCreated)
	// Methods that change nothing evaluate the header as well.
	for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
		hdr := map[string]string{"If": `(["bad"])`, "Depth": "0"}
		wantStatus(t, method, ownerDo(method, free, propLocks, hdr), http.StatusPreconditionFailed)
	}
}

func TestWriteRequiresToken(t *testing.T) {
	proppatch := `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><x:note xmlns:x="urn:example:test">v</x:note></D:prop></D:set></D:propertyupdate>`
	tests := []struct {
		name, method, target, body string
		lock, depth                string
		dest                       string
		want                       int
	}{
		{"PUT", "PUT", "/shared/locked.txt", "x", "/shared/locked.txt", "0", "", http.StatusCreated},
		{"DELETE", "DELETE", "/shared/locked.txt", "", "/shared/locked.txt", "0", "", http.StatusNoContent},
		{"PROPPATCH", "PROPPATCH", "/shared/locked.txt", proppatch, "/shared/locked.txt", "0", "", http.StatusMultiStatus},
		{"MKCOL below infinity", "MKCOL", "/shared/sub/new", "", "/shared/sub", "infinity", "", http.StatusCreated},
		{"MKCOL in depth 0 collection", "MKCOL", "/shared/sub/new", "", "/shared/sub", "0", "", http.StatusCreated},
		{"PUT new member of depth 0 collection", "PUT", "/shared/sub/new.txt", "x", "/shared/sub", "0", "", http.StatusCreated},
		{"DELETE member of depth 0 collection", "DELETE", "/shared/free.txt", "", "/shared", "0", "", http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockTestEnv(t)
			// dead_props references users, so a stored property needs the owner's row.
			if _, err := db.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, 'x', 'user')`, lockTestOwner); err != nil {
				t.Fatal(err)
			}
			token := takeLock(t, tt.lock, "exclusive", tt.depth)
			wantStatus(t, "without token", ownerDo(tt.method, tt.target, tt.body, nil), http.StatusLocked)
			hdr := map[string]string{"If": "<" + tt.lock + "> (<" + token + ">)"}
			wantStatus(t, "with token", ownerDo(tt.method, tt.target, tt.body, hdr), tt.want)
		})
	}
}

func TestLockRefusalNamesRoot(t *testing.T) {
	lockTestEnv(t)
	takeLock(t, "/shared/locked.txt", "exclusive", "0")
	w := ownerDo("PUT", "/shared/locked.txt", "x", nil)
	want := "<d:lock-token-submitted><d:href>/shared/locked.txt</d:href></d:lock-token-submitted>"
	if w.Code != http.StatusLocked || !strings.Contains(w.Body.String(), want) {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
}

func TestOverwriteOfMemberKeepsDepthZeroLockOutOfIt(t *testing.T) {
	lockTestEnv(t)
	takeLock(t, "/shared", "exclusive", "0")
	// The member list stays the same, so §7.4 does not apply.
	wantStatus(t, "overwrite", ownerDo("PUT", "/shared/free.txt", "x", nil), http.StatusCreated)
}

func TestOneOfSeveralSharedTokensIsEnough(t *testing.T) {
	lockTestEnv(t)
	first := takeLock(t, "/shared/free.txt", "shared", "0")
	second := takeLock(t, "/shared/free.txt", "shared", "0")
	wantStatus(t, "no token", ownerDo("PUT", "/shared/free.txt", "x", nil), http.StatusLocked)
	wantStatus(t, "first", ownerDo("PUT", "/shared/free.txt", "x", ifToken(first)), http.StatusCreated)
	wantStatus(t, "second", ownerDo("PUT", "/shared/free.txt", "x", ifToken(second)), http.StatusCreated)
}

func TestMoveAndCopyTokens(t *testing.T) {
	lockTestEnv(t)
	dest := func(name string, extra ...string) map[string]string {
		h := map[string]string{"Destination": "http://example.com" + name, "Overwrite": "T"}
		if len(extra) > 0 {
			h["If"] = extra[0]
		}
		return h
	}
	src := takeLock(t, "/shared/locked.txt", "exclusive", "0")
	dst := takeLock(t, "/shared/free.txt", "exclusive", "0")
	wantStatus(t, "MOVE, no token", ownerDo("MOVE", "/shared/locked.txt", "", dest("/shared/free.txt")), http.StatusLocked)
	wantStatus(t, "MOVE, source token only", ownerDo("MOVE", "/shared/locked.txt", "", dest("/shared/free.txt", "(<"+src+">)")), http.StatusLocked)
	wantStatus(t, "MOVE, destination token only", ownerDo("MOVE", "/shared/locked.txt", "", dest("/shared/free.txt", "</shared/free.txt> (<"+dst+">)")), http.StatusLocked)
	wantStatus(t, "COPY, no token", ownerDo("COPY", "/shared/locked.txt", "", dest("/shared/free.txt")), http.StatusLocked)
	wantStatus(t, "COPY of a locked source to a free name", ownerDo("COPY", "/shared/locked.txt", "", dest("/shared/copy.txt")), http.StatusCreated)
	wantStatus(t, "COPY, destination token", ownerDo("COPY", "/shared/locked.txt", "", dest("/shared/free.txt", "</shared/free.txt> (<"+dst+">)")), http.StatusNoContent)
	both := "</shared/locked.txt> (<" + src + ">) </shared/copy.txt> (Not <DAV:no-lock>)"
	wantStatus(t, "MOVE, both free of destination lock", ownerDo("MOVE", "/shared/locked.txt", "", dest("/shared/moved.txt", both)), http.StatusCreated)
}

func TestLockedMembersGive207(t *testing.T) {
	lockTestEnv(t)
	dest := map[string]string{"Destination": "/shared/moved", "Overwrite": "T"}
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(ownerFile("/shared/sub/"+name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	a := takeLock(t, "/shared/sub/a.txt", "exclusive", "0")
	b := takeLock(t, "/shared/sub/b.txt", "exclusive", "0")
	check := func(what string, w *httptest.ResponseRecorder, members ...string) {
		t.Helper()
		wantStatus(t, what, w, http.StatusMultiStatus)
		for _, m := range members {
			if !strings.Contains(w.Body.String(), "<d:href>/shared/sub/"+m+"</d:href><d:status>HTTP/1.1 423 Locked</d:status>") {
				t.Errorf("%s: %s not listed: %s", what, m, w.Body)
			}
		}
		if _, err := os.Stat(ownerFile("/shared/sub/a.txt")); err != nil {
			t.Errorf("%s: member gone: %v", what, err)
		}
	}
	check("DELETE", ownerDo("DELETE", "/shared/sub", "", nil), "a.txt", "b.txt")
	check("MOVE", ownerDo("MOVE", "/shared/sub", "", dest), "a.txt", "b.txt")
	// A token for one member leaves the other.
	check("DELETE, one token", ownerDo("DELETE", "/shared/sub", "", map[string]string{"If": "</shared/sub/a.txt> (<" + a + ">)"}), "b.txt")
	// COPY over the collection would destroy the members as well.
	check("COPY", ownerDo("COPY", "/shared/free.txt", "", map[string]string{"Destination": "/shared/sub", "Overwrite": "T"}), "a.txt", "b.txt")

	all := "</shared/sub/a.txt> (<" + a + ">) </shared/sub/b.txt> (<" + b + ">)"
	wantStatus(t, "DELETE, all tokens", ownerDo("DELETE", "/shared/sub", "", map[string]string{"If": all}), http.StatusNoContent)
}

func TestLocksGoWithRemovedResources(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/locked.txt", "exclusive", "0")
	wantStatus(t, "DELETE", ownerDo("DELETE", "/shared/locked.txt", "", ifToken(token)), http.StatusNoContent)
	wantStatus(t, "PUT at the old name", ownerDo("PUT", "/shared/locked.txt", "x", nil), http.StatusCreated)

	token = takeLock(t, "/shared/locked.txt", "exclusive", "0")
	hdr := map[string]string{"If": "(<" + token + ">)", "Destination": "/shared/moved.txt"}
	wantStatus(t, "MOVE", ownerDo("MOVE", "/shared/locked.txt", "", hdr), http.StatusCreated)
	if n := len(userLocks(lockTestOwner).locks); n != 0 {
		t.Errorf("%d locks left", n)
	}
	wantStatus(t, "PUT at the new name", ownerDo("PUT", "/shared/moved.txt", "x", nil), http.StatusCreated)
	wantStatus(t, "PUT at the old name", ownerDo("PUT", "/shared/locked.txt", "x", nil), http.StatusCreated)

	// Members go with their collection, a failed request keeps the lock.
	token = takeLock(t, "/shared/sub", "exclusive", "infinity")
	wantStatus(t, "refused", ownerDo("DELETE", "/shared/sub", "", nil), http.StatusLocked)
	if len(userLocks(lockTestOwner).locks) != 1 {
		t.Error("refused DELETE removed the lock")
	}
	wantStatus(t, "DELETE collection", ownerDo("DELETE", "/shared/sub", "", ifToken(token)), http.StatusNoContent)
	if n := len(userLocks(lockTestOwner).locks); n != 0 {
		t.Errorf("%d locks left", n)
	}
}

func TestMovedAndCopiedFallUnderNewParent(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/sub", "exclusive", "infinity")
	for method, source := range map[string]string{"COPY": "/shared/free.txt", "MOVE": "/shared/locked.txt"} {
		target := "/shared/sub/" + method
		hdr := map[string]string{"Destination": target, "If": "</shared/sub> (<" + token + ">)"}
		wantStatus(t, method, ownerDo(method, source, "", hdr), http.StatusCreated)
		got := parseLockResponse(t, ownerDo("PROPFIND", target, propLocks, depth0()))
		if len(got.Locks) != 1 || got.Locks[0].Token != token {
			t.Errorf("%s: %+v", method, got.Locks)
		}
		wantStatus(t, "PUT without token", ownerDo("PUT", target, "x", nil), http.StatusLocked)
	}
}

func TestParallelRequestsWithOneToken(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/sub", "exclusive", "infinity")
	hdr := map[string]string{"If": "(<" + token + ">)"}
	var wg sync.WaitGroup
	statuses := make(chan int, 200)
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("/shared/sub/f%d.txt", i)
			tagged := map[string]string{"If": "<" + name + "> (<" + token + ">)"}
			statuses <- ownerDo("PUT", name, "x", tagged).Code
			statuses <- ownerDo("PUT", "/shared/sub/same.txt", "x", map[string]string{"If": "</shared/sub> (<" + token + ">)"}).Code
			statuses <- ownerDo("LOCK", "/shared/sub", "", hdr).Code
			statuses <- ownerDo("PROPFIND", "/shared/sub", propLocks, map[string]string{"Depth": "0", "If": hdr["If"]}).Code
		}()
	}
	wg.Wait()
	close(statuses)
	for code := range statuses {
		if code != http.StatusCreated && code != http.StatusOK && code != http.StatusMultiStatus {
			t.Errorf("status %d", code)
		}
	}
	wantStatus(t, "UNLOCK", ownerDo("UNLOCK", "/shared/sub", "", map[string]string{"Lock-Token": "<" + token + ">"}), http.StatusNoContent)
}

// startBlockedPut starts a PUT whose body does not end, and returns when it is
// registered as running, with a function that completes it.
func startBlockedPut(t *testing.T, target string, hdr map[string]string) func() *httptest.ResponseRecorder {
	t.Helper()
	pr, pw := io.Pipe()
	r := httptest.NewRequest("PUT", target, pr)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		serveDAV(w, r, getDavUser(lockTestOwner).handler, ownerFile(target), lockTestOwner)
	}()
	m := userLocks(lockTestOwner)
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.writes)
		m.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PUT did not start")
		}
		time.Sleep(time.Millisecond)
	}
	return func() *httptest.ResponseRecorder {
		pw.Close()
		<-finished
		return w
	}
}

func TestLockDuringWriteRefusedAtOnce(t *testing.T) {
	tests := []struct {
		name, put, lock, depth string
		want                   int
	}{
		{"same resource", "/shared/free.txt", "/shared/free.txt", "0", http.StatusServiceUnavailable},
		{"infinity above", "/shared/sub/x.txt", "/shared", "infinity", http.StatusServiceUnavailable},
		{"depth 0 on the parent, new member", "/shared/new.txt", "/shared", "0", http.StatusServiceUnavailable},
		{"depth 0 on the parent, member overwritten", "/shared/free.txt", "/shared", "0", http.StatusOK},
		{"depth 0 two levels up", "/shared/sub/x.txt", "/shared", "0", http.StatusOK},
		{"other resource", "/shared/free.txt", "/shared/locked.txt", "0", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockTestEnv(t)
			finish := startBlockedPut(t, tt.put, nil)
			start := time.Now()
			w := ownerDo("LOCK", tt.lock, lockBody("exclusive", ""), map[string]string{"Depth": tt.depth})
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("LOCK waited %v", took)
			}
			wantStatus(t, "LOCK", w, tt.want)
			if tt.want == http.StatusServiceUnavailable && w.Header().Get("Retry-After") != "1" {
				t.Errorf("Retry-After %q", w.Header().Get("Retry-After"))
			}
			wantStatus(t, "PUT", finish(), http.StatusCreated)
			if tt.want == http.StatusServiceUnavailable {
				wantStatus(t, "LOCK after the write", ownerDo("LOCK", tt.lock, lockBody("exclusive", ""), map[string]string{"Depth": tt.depth}), http.StatusOK)
			}
		})
	}
}

// Only a change of membership conflicts with a Depth 0 lock on the collection.
func TestWriteRunningDepthZeroOnCollection(t *testing.T) {
	tests := []struct {
		name  string
		write writeTarget
		want  bool
	}{
		{"member overwritten", writeTarget{name: "/c/a"}, false},
		{"member overwritten by COPY or MOVE", writeTarget{name: "/c/a", replaces: true, tree: true}, false},
		{"new member", writeTarget{name: "/c/a", member: true}, true},
		{"member removed or moved away", writeTarget{name: "/c/a", member: true, replaces: true, tree: true}, true},
		{"new member further down", writeTarget{name: "/c/d/a", member: true}, false},
		{"the collection itself", writeTarget{name: "/c"}, true},
		{"collection removed above", writeTarget{name: "/", tree: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newLockManager(t.TempDir())
			m.writes = []runningWrite{{name: tt.write.name, tree: tt.write.tree, member: tt.write.member}}
			if got := m.writeRunning("/c", true); got != tt.want {
				t.Errorf("writeRunning = %v, want %v", got, tt.want)
			}
		})
	}
	m := newLockManager(t.TempDir())
	m.writes = []runningWrite{{name: "/a", member: true}}
	if !m.writeRunning("/", true) {
		t.Error("new member of the root does not conflict")
	}
}

func TestLockTokenWorksDuringRunningWrite(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/sub", "exclusive", "infinity")
	finish := startBlockedPut(t, "/shared/sub/x.txt", ifToken(token))
	// A refresh creates no new lock, and UNLOCK does not wait either.
	wantStatus(t, "refresh", ownerDo("LOCK", "/shared/sub", "", ifToken(token)), http.StatusOK)
	wantStatus(t, "other write", ownerDo("PUT", "/shared/sub/y.txt", "x", map[string]string{"If": "</shared/sub> (<" + token + ">)"}), http.StatusCreated)
	wantStatus(t, "UNLOCK", ownerDo("UNLOCK", "/shared/sub", "", map[string]string{"Lock-Token": "<" + token + ">"}), http.StatusNoContent)
	wantStatus(t, "PUT", finish(), http.StatusCreated)
}

func TestUnlock(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/sub", "exclusive", "infinity")
	wantStatus(t, "no header", ownerDo("UNLOCK", "/shared/sub", "", nil), http.StatusBadRequest)
	wantStatus(t, "no brackets", ownerDo("UNLOCK", "/shared/sub", "", map[string]string{"Lock-Token": token}), http.StatusBadRequest)
	wantStatus(t, "bogus", ownerDo("UNLOCK", "/shared/sub", "", map[string]string{"Lock-Token": "<urn:uuid:nope>"}), http.StatusConflict)
	wantStatus(t, "other resource", ownerDo("UNLOCK", "/shared/free.txt", "", map[string]string{"Lock-Token": "<" + token + ">"}), http.StatusConflict)
	if err := os.WriteFile(ownerFile("/shared/sub/child.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "from a member", ownerDo("UNLOCK", "/shared/sub/child.txt", "", map[string]string{"Lock-Token": "<" + token + ">"}), http.StatusNoContent)
}

// Writes wait for each other, on both endpoints, and only a lock created by
// LOCK gives 423.
func TestWritesWaitInsteadOf423(t *testing.T) {
	share := lockTestEnv(t)
	dest := func(name string) map[string]string {
		return map[string]string{"Destination": name, "Overwrite": "T"}
	}
	shareDest := func(name string) map[string]string {
		return map[string]string{"Destination": "/s/" + share.ID + name, "Overwrite": "T"}
	}
	var wg sync.WaitGroup
	codes := make(chan int, 400)
	run := func(f func() *httptest.ResponseRecorder) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- f().Code
		}()
	}
	for range 25 {
		run(func() *httptest.ResponseRecorder { return ownerDo("PUT", "/shared/free.txt", "x", nil) })
		run(func() *httptest.ResponseRecorder { return shareDo(share, "PUT", "/free.txt", "y", nil) })
		run(func() *httptest.ResponseRecorder { return ownerDo("MKCOL", "/shared/dir", "", nil) })
		run(func() *httptest.ResponseRecorder { return shareDo(share, "DELETE", "/dir", "", nil) })
		run(func() *httptest.ResponseRecorder {
			return ownerDo("COPY", "/shared/locked.txt", "", dest("/shared/free.txt"))
		})
		run(func() *httptest.ResponseRecorder {
			return shareDo(share, "MOVE", "/free.txt", "", shareDest("/moved.txt"))
		})
		run(func() *httptest.ResponseRecorder {
			return ownerDo("MOVE", "/shared/moved.txt", "", dest("/shared/free.txt"))
		})
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code == http.StatusLocked {
			t.Error("423 without a lock")
		}
	}
	if m := userLocks(lockTestOwner); len(m.writes) != 0 || len(m.locks) != 0 {
		t.Errorf("left behind: %d writes, %d locks", len(m.writes), len(m.locks))
	}
}

func TestMutatingMethodsWaitForRunningWrite(t *testing.T) {
	lockTestEnv(t)
	for name, do := range map[string]func() *httptest.ResponseRecorder{
		"MKCOL": func() *httptest.ResponseRecorder { return ownerDo("MKCOL", "/shared/busy.txt", "", nil) },
		"MOVE onto": func() *httptest.ResponseRecorder {
			return ownerDo("MOVE", "/shared/free.txt", "", map[string]string{"Destination": "/shared/busy.txt", "Overwrite": "T"})
		},
		"COPY onto": func() *httptest.ResponseRecorder {
			return ownerDo("COPY", "/shared/locked.txt", "", map[string]string{"Destination": "/shared/busy.txt", "Overwrite": "T"})
		},
		"PROPPATCH": func() *httptest.ResponseRecorder {
			return ownerDo("PROPPATCH", "/shared/busy.txt", `<D:propertyupdate xmlns:D="DAV:"/>`, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			lockTestEnv(t)
			finish := startBlockedPut(t, "/shared/busy.txt", nil)
			done := make(chan int, 1)
			go func() { done <- do().Code }()
			select {
			case code := <-done:
				t.Fatalf("did not wait: status %d", code)
			case <-time.After(100 * time.Millisecond):
			}
			finish()
			if code := <-done; code == http.StatusLocked {
				t.Errorf("status %d", code)
			}
		})
	}
}

func TestMoveOntoItselfDoesNotDeadlock(t *testing.T) {
	lockTestEnv(t)
	done := make(chan int, 1)
	go func() {
		done <- ownerDo("MOVE", "/shared/free.txt", "", map[string]string{"Destination": "/shared/free.txt"}).Code
	}()
	select {
	case code := <-done:
		if code != http.StatusForbidden {
			t.Errorf("status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock")
	}
}

func TestConditionalPutWithLock(t *testing.T) {
	lockTestEnv(t)
	token := takeLock(t, "/shared/free.txt", "exclusive", "0")
	w := ownerDo("PUT", "/shared/free.txt", "x", map[string]string{"If": "(<" + token + ">)", "If-Match": `"stale"`})
	wantStatus(t, "If-Match", w, http.StatusPreconditionFailed)
	w = ownerDo("PUT", "/shared/free.txt", "x", map[string]string{"If": "(<" + token + ">)", "If-None-Match": "*"})
	wantStatus(t, "If-None-Match", w, http.StatusPreconditionFailed)
	w = ownerDo("PUT", "/shared/free.txt", "new", ifToken(token))
	wantStatus(t, "PUT", w, http.StatusCreated)
	fi, err := os.Stat(ownerFile("/shared/free.txt"))
	if err != nil || w.Header().Get("ETag") != fileETag(fi) {
		t.Errorf("ETag %q, %v", w.Header().Get("ETag"), err)
	}
}

func TestAbortedPutKeepsFileAndEndsWrite(t *testing.T) {
	lockTestEnv(t)
	r := httptest.NewRequest("PUT", "/shared/free.txt", iotest.ErrReader(errors.New("connection lost")))
	w := httptest.NewRecorder()
	serveDAV(w, r, getDavUser(lockTestOwner).handler, ownerFile("/shared/free.txt"), lockTestOwner)
	if data, err := os.ReadFile(ownerFile("/shared/free.txt")); err != nil || string(data) != "original" {
		t.Errorf("file holds %q, %v", data, err)
	}
	if n := len(userLocks(lockTestOwner).writes); n != 0 {
		t.Errorf("%d writes still registered", n)
	}
}

func TestShareRefusesWithoutExposingOwnerPaths(t *testing.T) {
	share := lockTestEnv(t)
	if err := os.WriteFile(ownerFile("/shared/sub/member.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	takeLock(t, "/shared/sub/member.txt", "exclusive", "0")
	dest := map[string]string{"Destination": "/s/" + share.ID + "/sub", "Overwrite": "T"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"DELETE with locked member": shareDo(share, "DELETE", "/sub", "", nil),
		"MOVE with locked member":   shareDo(share, "MOVE", "/sub", "", map[string]string{"Destination": "/s/" + share.ID + "/moved"}),
		"MOVE over locked member":   shareDo(share, "MOVE", "/free.txt", "", dest),
		"COPY over locked member":   shareDo(share, "COPY", "/free.txt", "", dest),
		"PUT on the locked member":  shareDo(share, "PUT", "/sub/member.txt", "y", nil),
	} {
		wantStatus(t, name, w, http.StatusLocked)
		if strings.Contains(w.Body.String(), "shared") || strings.Contains(w.Body.String(), "href") {
			t.Errorf("%s exposes a path: %s", name, w.Body)
		}
	}
	// A lock above the share root also protects the root's member list.
	takeLock(t, "/shared", "shared", "0")
	wantStatus(t, "new member", shareDo(share, "PUT", "/new.txt", "x", nil), http.StatusLocked)
	wantStatus(t, "overwrite", shareDo(share, "PUT", "/free.txt", "x", nil), http.StatusCreated)
}

func TestShareIfHeaderIs412(t *testing.T) {
	share := lockTestEnv(t)
	dest := map[string]string{"Destination": "/s/" + share.ID + "/x", "If": "(Not <DAV:no-lock>)"}
	ifHdr := map[string]string{"If": "(Not <DAV:no-lock>)"}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"PUT":       shareDo(share, "PUT", "/free.txt", "x", ifHdr),
		"DELETE":    shareDo(share, "DELETE", "/free.txt", "", ifHdr),
		"MKCOL":     shareDo(share, "MKCOL", "/x", "", ifHdr),
		"PROPPATCH": shareDo(share, "PROPPATCH", "/free.txt", `<D:propertyupdate xmlns:D="DAV:"/>`, ifHdr),
		"MOVE":      shareDo(share, "MOVE", "/free.txt", "", dest),
		"COPY":      shareDo(share, "COPY", "/free.txt", "", dest),
	} {
		wantStatus(t, name, w, http.StatusPreconditionFailed)
	}
	wantStatus(t, "malformed", shareDo(share, "PUT", "/free.txt", "x", map[string]string{"If": "nonsense"}), http.StatusBadRequest)
	if data, err := os.ReadFile(ownerFile("/shared/free.txt")); err != nil || string(data) != "original" {
		t.Errorf("file holds %q, %v", data, err)
	}
}

func TestShareWriteLeavesNoRecipientState(t *testing.T) {
	share := lockTestEnv(t)
	wantStatus(t, "PUT", shareDo(share, "PUT", "/free.txt", "x", nil), http.StatusCreated)
	wantStatus(t, "owner LOCK afterwards", ownerDo("LOCK", "/shared/free.txt", lockBody("exclusive", ""), depth0()), http.StatusOK)
}

// utf16Body encodes s as UTF-16 with a byte order mark.
func utf16Body(s string, order binary.AppendByteOrder) string {
	b := order.AppendUint16(nil, 0xFEFF)
	for _, u := range utf16.Encode([]rune(s)) {
		b = order.AppendUint16(b, u)
	}
	return string(b)
}

func TestPropfindEncodings(t *testing.T) {
	share := lockTestEnv(t)
	const prop = `<propfind xmlns="DAV:"><prop><displayname/><größe/></prop></propfind>`
	tests := []struct{ name, body string }{
		{"UTF-8", prop},
		{"UTF-8 with mark and other declaration", "\xef\xbb\xbf" + `<?xml version="1.0" encoding="ISO-8859-1"?>` + prop},
		{"UTF-16 LE", utf16Body(prop, binary.LittleEndian)},
		{"UTF-16 BE", utf16Body(prop, binary.BigEndian)},
		{"UTF-16 with declaration", utf16Body(`<?xml version="1.0" encoding="UTF-16"?>`+prop, binary.LittleEndian)},
		{"ISO-8859-1", `<?xml version="1.0" encoding="ISO-8859-1"?><propfind xmlns="DAV:"><prop><displayname/><gr` + "\xf6\xdf" + `e/></prop></propfind>`},
		{"ISO-8859-1 value in a property element", `<?xml version="1.0" encoding="iso-8859-1"?><propfind xmlns="DAV:"><prop><displayname/><gr` + "\xf6\xdf" + `e>` + "\xc4" + `</gr` + "\xf6\xdf" + `e></prop></propfind>`},
		{"windows-1252", `<?xml version="1.0" encoding="windows-1252"?><propfind xmlns="DAV:"><prop><displayname/><gr` + "\xf6\xdf" + `e/></prop></propfind>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for endpoint, w := range propfindBoth(share, tt.body) {
				out := w.Body.String()
				if w.Code != http.StatusMultiStatus {
					t.Fatalf("%s: status %d: %s", endpoint, w.Code, out)
				}
				// Only a decoded body gives the UTF-8 name in the 404 propstat.
				if !strings.Contains(out, "<d:displayname>") || !strings.Contains(out, "<d:größe/>") {
					t.Errorf("%s: properties missing: %s", endpoint, out)
				}
			}
		})
	}
}

func TestPropfindIncludeInEitherOrder(t *testing.T) {
	share := lockTestEnv(t)
	const include = `<include><quota-available-bytes/></include>`
	for name, body := range map[string]string{
		"before":                 `<propfind xmlns="DAV:">` + include + `<allprop/></propfind>`,
		"after":                  `<propfind xmlns="DAV:"><allprop/>` + include + `</propfind>`,
		"before, with extension": `<propfind xmlns="DAV:">` + include + `<x:y xmlns:x="urn:x"/><allprop/></propfind>`,
	} {
		for endpoint, w := range propfindBoth(share, body) {
			out := w.Body.String()
			if w.Code != http.StatusMultiStatus || !strings.Contains(out, "<d:getetag>") || !strings.Contains(out, "<d:quota-available-bytes>") {
				t.Errorf("%s, %s: status %d: %s", name, endpoint, w.Code, out)
			}
		}
	}
}

func TestPropfindEmptyProp(t *testing.T) {
	share := lockTestEnv(t)
	body := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop/></d:propfind>`
	for endpoint, w := range propfindBoth(share, body) {
		if w.Code != http.StatusMultiStatus {
			t.Fatalf("%s: status %d", endpoint, w.Code)
		}
		want := `<d:propstat><d:prop></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>`
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: no empty prop with 200 OK: %s", endpoint, w.Body)
		}
	}
}

func TestPropfindAllpropInclude(t *testing.T) {
	share := lockTestEnv(t)
	body := `<propfind xmlns="DAV:"><allprop/><include><quota-available-bytes/><quota-used-bytes/><getetag/><lockdiscovery/><nosuchprop/></include></propfind>`
	wantUsed := map[string]bool{"user": true, "share": false}
	for endpoint, w := range propfindBoth(share, body) {
		if w.Code != http.StatusMultiStatus {
			t.Fatalf("%s: status %d", endpoint, w.Code)
		}
		out := w.Body.String()
		for _, prop := range []string{"<d:displayname>", "<d:supportedlock", "<d:quota-available-bytes>", "<d:nosuchprop/>"} {
			if !strings.Contains(out, prop) {
				t.Errorf("%s: %s missing: %s", endpoint, prop, out)
			}
		}
		if got := strings.Contains(out, "<d:quota-used-bytes>"); got != wantUsed[endpoint] {
			t.Errorf("%s: quota-used-bytes value = %v, want %v: %s", endpoint, got, wantUsed[endpoint], out)
		}
		// Named in include and part of allprop: answered once, not as 404.
		for _, prop := range []string{"<d:getetag>", "<d:lockdiscovery"} {
			if n := strings.Count(out, prop); n != 1 {
				t.Errorf("%s: %s appears %d times: %s", endpoint, prop, n, out)
			}
		}
	}
	// On a file the quota properties are not found, as when named in prop.
	out := ownerDo("PROPFIND", "/shared/free.txt", body, depth0()).Body.String()
	if !strings.Contains(out, "<d:quota-available-bytes/>") || !strings.Contains(out, "404 Not Found") {
		t.Errorf("file: %s", out)
	}
	// An empty include adds nothing.
	out = ownerDo("PROPFIND", "/shared", `<propfind xmlns="DAV:"><allprop/><include/></propfind>`, depth0()).Body.String()
	if !strings.Contains(out, "<d:getetag>") || strings.Contains(out, "quota-") || strings.Contains(out, "404 Not Found") {
		t.Errorf("empty include: %s", out)
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
		for _, value := range []string{token, "exclusive", "GMT", "quota-"} {
			if strings.Contains(out, value) {
				t.Errorf("%s: value %q in response:\n%s", name, value, out)
			}
		}
	}
	// A collection has no content length or type, but quota properties. A share
	// does not report the owner's used bytes.
	collections := []struct {
		name     string
		w        *httptest.ResponseRecorder
		wantUsed bool
	}{
		{"user collection", ownerDo("PROPFIND", "/shared/sub", body, depth0()), true},
		{"share collection", shareDo(share, "PROPFIND", "/sub", body, depth0()), false},
	}
	for _, c := range collections {
		if c.w.Code != http.StatusMultiStatus {
			t.Fatalf("%s: status %d", c.name, c.w.Code)
		}
		out := c.w.Body.String()
		if strings.Contains(out, "getcontentlength") || !strings.Contains(out, "<d:resourcetype/>") {
			t.Errorf("%s:\n%s", c.name, out)
		}
		if !strings.Contains(out, "<d:quota-available-bytes/>") {
			t.Errorf("%s: quota-available-bytes missing:\n%s", c.name, out)
		}
		if got := strings.Contains(out, "<d:quota-used-bytes/>"); got != c.wantUsed {
			t.Errorf("%s: quota-used-bytes listed = %v, want %v:\n%s", c.name, got, c.wantUsed, out)
		}
	}
	// allprop stays without quota properties.
	allprop := `<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:allprop/></d:propfind>`
	if out := ownerDo("PROPFIND", "/shared/sub", allprop, depth0()).Body.String(); strings.Contains(out, "quota-") {
		t.Errorf("allprop:\n%s", out)
	}
}
