// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	authTestUser      = "alice"
	authTestUserPass  = "alicepass1"
	authTestAdmin     = "root"
	authTestAdminPass = "rootpass123"
)

// authTestEnv prepares a database with one user and one admin, a fresh
// auth cache and limiter, and returns the WebDAV handler and a buffer that
// receives the log.
func authTestEnv(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.DataDir = dir
	setConf(cfg)
	if err := initLogger("", ""); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := openDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatal(err)
	}
	oldCache, oldLimiter := authCache, limiter
	authCache = newCredCache(time.Minute)
	limiter = newBruteForce(cfg)
	t.Cleanup(func() {
		db.Close()
		authCache, limiter = oldCache, oldLimiter
		davHandlers.Delete(authTestUser)
		storageUsage.mu.Lock()
		delete(storageUsage.m, authTestUser)
		storageUsage.mu.Unlock()
	})
	if err := createUser(authTestUser, authTestUserPass, "user", 0); err != nil {
		t.Fatal(err)
	}
	if err := createUser(authTestAdmin, authTestAdminPass, "admin", 0); err != nil {
		t.Fatal(err)
	}
	return buildWebDAVHandler(), &buf
}

func authDo(h http.Handler, method, target, user, pass string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if method == "PROPFIND" {
		r.Header.Set("Depth", "0")
	}
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// sameResponse fails unless a and b have the same status, headers and body.
func sameResponse(t *testing.T, what string, a, b *httptest.ResponseRecorder) {
	t.Helper()
	if a.Code != b.Code {
		t.Errorf("%s: status %d, want %d", what, a.Code, b.Code)
	}
	if !equalHeaders(a.Header(), b.Header()) {
		t.Errorf("%s: headers %v, want %v", what, a.Header(), b.Header())
	}
	if a.Body.String() != b.Body.String() {
		t.Errorf("%s: body %q, want %q", what, a.Body.String(), b.Body.String())
	}
}

func equalHeaders(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb := b[k]
		if strings.Join(va, "\n") != strings.Join(vb, "\n") {
			return false
		}
	}
	return true
}

func TestAdminRefusedOnWebDAVAndAPI(t *testing.T) {
	h, logBuf := authTestEnv(t)
	for _, tc := range []struct {
		method, target string
		userStatus     int
	}{
		{"PROPFIND", "/", http.StatusMultiStatus},
		{http.MethodGet, "/api/v1/shares", http.StatusOK},
	} {
		if w := authDo(h, tc.method, tc.target, authTestUser, authTestUserPass); w.Code != tc.userStatus {
			t.Fatalf("%s %s as user: status %d, want %d", tc.method, tc.target, w.Code, tc.userStatus)
		}
		right := authDo(h, tc.method, tc.target, authTestAdmin, authTestAdminPass)
		wrong := authDo(h, tc.method, tc.target, authTestAdmin, "wrongpass1")
		if right.Code != http.StatusUnauthorized {
			t.Errorf("%s %s as admin with correct password: status %d, want 401", tc.method, tc.target, right.Code)
		}
		sameResponse(t, tc.method+" "+tc.target+" admin correct vs wrong password", right, wrong)
	}

	log := logBuf.String()
	refused := regexp.MustCompile(`level=WARN msg="webdav auth refused: admin account" username=root client=192\.0\.2\.1 `)
	if n := len(refused.FindAllString(log, -1)); n != 2 {
		t.Errorf("refused admin logins logged %d times, want 2:\n%s", n, log)
	}
	failed := regexp.MustCompile(`msg="webdav auth failed" username=root `)
	if n := len(failed.FindAllString(log, -1)); n != 2 {
		t.Errorf("wrong admin passwords logged %d times as auth failed, want 2", n)
	}
}

func TestAdminRefusalNotCachedAndCounted(t *testing.T) {
	h, _ := authTestEnv(t)
	for range 2 {
		if w := authDo(h, "PROPFIND", "/", authTestAdmin, authTestAdminPass); w.Code != http.StatusUnauthorized {
			t.Fatalf("admin with correct password: status %d, want 401", w.Code)
		}
	}
	if hit, _ := authCache.lookup(authTestAdmin, authTestAdminPass); hit {
		t.Error("refused admin login is in the auth cache")
	}
	limiter.mu.Lock()
	acc, ip := limiter.accounts[authTestAdmin], limiter.ips["192.0.2.1"]
	limiter.mu.Unlock()
	if acc == nil || len(acc.failures) != 2 {
		t.Errorf("account failures after two refused admin logins: %+v, want 2", acc)
	}
	if ip == nil || len(ip.failures) != 2 {
		t.Errorf("client failures after two refused admin logins: %+v, want 2", ip)
	}
	// A user login from the same client must not reset the counters.
	if w := authDo(h, "PROPFIND", "/", authTestUser, authTestUserPass); w.Code != http.StatusMultiStatus {
		t.Fatalf("user login: status %d, want 207", w.Code)
	}
	limiter.mu.Lock()
	n := len(limiter.ips["192.0.2.1"].failures)
	limiter.mu.Unlock()
	if n != 2 {
		t.Errorf("client failures after a user login: %d, want 2", n)
	}
}

func TestPromotedUserLosesAccessAtOnce(t *testing.T) {
	h, _ := authTestEnv(t)
	if w := authDo(h, "PROPFIND", "/", authTestUser, authTestUserPass); w.Code != http.StatusMultiStatus {
		t.Fatalf("user login: status %d, want 207", w.Code)
	}
	if hit, _ := authCache.lookup(authTestUser, authTestUserPass); !hit {
		t.Fatal("user login was not cached")
	}
	if _, err := db.Exec(`UPDATE users SET role = 'admin' WHERE username = ?`, authTestUser); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/", "/api/v1/shares"} {
		method := "PROPFIND"
		if strings.HasPrefix(target, "/api/") {
			method = http.MethodGet
		}
		if w := authDo(h, method, target, authTestUser, authTestUserPass); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s after promotion to admin: status %d, want 401", method, target, w.Code)
		}
	}
	if hit, _ := authCache.lookup(authTestUser, authTestUserPass); hit {
		t.Error("auth cache still holds the promoted account")
	}
}

func TestSuggestPassword(t *testing.T) {
	re := regexp.MustCompile(`^[` + passwordAlphabet + `]{5}(-[` + passwordAlphabet + `]{5}){3}$`)
	if len(passwordAlphabet) != 52 {
		t.Fatalf("alphabet has %d characters, want 52", len(passwordAlphabet))
	}
	if strings.ContainsAny(passwordAlphabet, "01oOlIyYzZ-") {
		t.Fatalf("alphabet %q holds an excluded character", passwordAlphabet)
	}
	seen := map[string]bool{}
	used := map[rune]bool{}
	for range 2000 {
		pw := suggestPassword()
		if len(pw) != 23 || !re.MatchString(pw) {
			t.Fatalf("suggestion %q is not 4 groups of 5 from the alphabet", pw)
		}
		if !passwordLongEnough(pw) {
			t.Fatalf("suggestion %q fails the password check", pw)
		}
		if seen[pw] {
			t.Fatalf("suggestion %q repeated", pw)
		}
		seen[pw] = true
		for _, c := range strings.ReplaceAll(pw, "-", "") {
			used[c] = true
		}
	}
	if len(used) != len(passwordAlphabet) {
		t.Errorf("2000 suggestions used %d of %d characters", len(used), len(passwordAlphabet))
	}
}

func TestPasswordSuggestionEndpoint(t *testing.T) {
	loadTemplates()
	field := regexp.MustCompile(`^<input type="text" name="new_password" value="[` + passwordAlphabet + `-]{23}" required minlength="8"`)
	r := httptest.NewRequest(http.MethodGet, "/admin/users/password-suggestion?field=new_password", nil)
	w := httptest.NewRecorder()
	handlePasswordSuggestion(w, r)
	if w.Code != http.StatusOK || !field.MatchString(w.Body.String()) {
		t.Errorf("suggestion field: status %d, body %q", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/admin/users/password-suggestion?field=username", nil)
	w = httptest.NewRecorder()
	handlePasswordSuggestion(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: status %d, want 400", w.Code)
	}
}
