// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// lineRE matches a line of lineHandler: time, level, then the rest.
var lineRE = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(?:Z|[+-]\d\d:\d\d)) (DEBUG|INFO|WARN|ERROR) (.*)$`)

// countLines returns how many lines of s have the message msg (as
// written, i.e. quoted where needed).
func countLines(s, msg string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if m := lineRE.FindStringSubmatch(l); m != nil && (m[3] == msg || strings.HasPrefix(m[3], msg+" ")) {
			n++
		}
	}
	return n
}

// TestLogLineLayout pins "<time> <LEVEL> <message> <attrs>": everything
// after the level must be exactly what slog's TextHandler writes after
// msg=, so quoting, groups and WithAttrs are unchanged.
func TestLogLineLayout(t *testing.T) {
	old := logLevel.Level()
	defer logLevel.Set(old)
	logLevel.Set(slog.LevelDebug)

	type logFn func(l *slog.Logger)
	tests := []struct {
		name     string
		log      logFn
		wantRest string
	}{
		{"plain message", func(l *slog.Logger) { l.Info("request", "method", "PROPFIND", "path", "/dav/", "status", 207) },
			"request method=PROPFIND path=/dav/ status=207"},
		{"message with spaces", func(l *slog.Logger) { l.Warn("webdav auth failed", "username", "x", "client", "203.0.113.5") },
			`"webdav auth failed" username=x client=203.0.113.5`},
		{"message with quote and equals", func(l *slog.Logger) { l.Error(`say "a=b"`) }, `"say \"a=b\""`},
		{"empty message", func(l *slog.Logger) { l.Debug("", "k", "v") }, `"" k=v`},
		{"no attrs", func(l *slog.Logger) { l.Info("startup") }, "startup"},
		{"with attrs and group", func(l *slog.Logger) {
			l.With("listener", "admin").WithGroup("g").Info("x", "k", "a b")
		}, `x listener=admin g.k="a b"`},
	}
	for _, tt := range tests {
		var got, ref bytes.Buffer
		tt.log(slog.New(newLogHandler(&got, &got, nil, newLogBuffer(10))))
		// The reference: today's TextHandler without time and level.
		tt.log(slog.New(slog.NewTextHandler(&ref, &slog.HandlerOptions{Level: &logLevel,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
					return slog.Attr{}
				}
				return a
			}})))
		line := got.String()
		if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
			t.Errorf("%s: want one line, got %q", tt.name, line)
			continue
		}
		m := lineRE.FindStringSubmatch(strings.TrimSuffix(line, "\n"))
		if m == nil {
			t.Errorf("%s: layout: %q", tt.name, line)
			continue
		}
		if m[3] != tt.wantRest {
			t.Errorf("%s: after level: %q, want %q", tt.name, m[3], tt.wantRest)
		}
		if want := strings.TrimPrefix(strings.TrimSuffix(ref.String(), "\n"), "msg="); m[3] != want {
			t.Errorf("%s: differs from TextHandler: %q, want %q", tt.name, m[3], want)
		}
		ts, err := time.Parse(lineTimeFormat, m[1])
		if err != nil {
			t.Errorf("%s: timestamp %q: %v", tt.name, m[1], err)
			continue
		}
		_, off := ts.Zone()
		_, local := ts.In(time.Local).Zone()
		if off != local || time.Since(ts) > time.Minute {
			t.Errorf("%s: timestamp %q is not the record time in the local zone", tt.name, m[1])
		}
	}
}

// writeRecorder records every Write call separately.
type writeRecorder struct {
	mu     sync.Mutex
	writes []string
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	return len(p), nil
}

// TestLogLineOneWrite: concurrent records on routes that share a writer
// arrive as one Write per complete line. Run with -race.
func TestLogLineOneWrite(t *testing.T) {
	var w writeRecorder
	l := slog.New(newLogHandler(&w, &w, &w, newLogBuffer(10)))
	const goroutines, lines = 8, 500
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range lines {
				msg := "request"
				if i%2 == 1 {
					msg = "other record"
				}
				l.With("g", g).Info(msg, "i", i, "pad", strings.Repeat("x", i))
			}
		}()
	}
	wg.Wait()
	if len(w.writes) != goroutines*lines {
		t.Fatalf("%d writes for %d records", len(w.writes), goroutines*lines)
	}
	for _, p := range w.writes {
		if strings.Count(p, "\n") != 1 || !strings.HasSuffix(p, "\n") || !lineRE.MatchString(strings.TrimSuffix(p, "\n")) {
			t.Fatalf("write is not exactly one line: %q", p)
		}
	}
}

// TestLogRouting pins the nginx-like split: only msg=request reaches the
// access destination, at every level, Error records are copied to errs,
// and the ring buffer gets every record.
func TestLogRouting(t *testing.T) {
	old := logLevel.Level()
	defer logLevel.Set(old)
	logLevel.Set(slog.LevelDebug)

	var access, server, errs bytes.Buffer
	ring := newLogBuffer(100)
	l := slog.New(newLogHandler(&access, &server, &errs, ring)).With("listener", "webdav")
	l.Info("request", "status", 200)
	l.Debug("request", "status", 401)
	l.Info("startup")
	l.Warn("request refused")
	l.Error("server error", "err", "boom")

	if got := countLines(access.String(), "request"); got != 2 || strings.Count(access.String(), "\n") != 2 {
		t.Errorf("access log: want exactly the 2 request lines, got:\n%s", access.String())
	}
	if !strings.Contains(access.String(), "listener=webdav") {
		t.Errorf("access log lost the WithAttrs attribute:\n%s", access.String())
	}
	if countLines(server.String(), "request") != 0 || strings.Count(server.String(), "\n") != 3 {
		t.Errorf("server log: want startup, warn and error only, got:\n%s", server.String())
	}
	if countLines(server.String(), `"request refused"`) != 1 {
		t.Errorf("a message that only starts with request belongs in the server log:\n%s", server.String())
	}
	if strings.Count(errs.String(), "\n") != 1 || countLines(errs.String(), `"server error"`) != 1 ||
		!strings.Contains(errs.String(), " ERROR ") {
		t.Errorf("stderr copy: want the Error record only, got:\n%s", errs.String())
	}
	if _, total, _ := ring.query(slog.LevelDebug, ""); total != 5 {
		t.Errorf("ring buffer holds %d records, want all 5", total)
	}
}

// TestLogRoutingSameDestination covers the default (both on stdout): no
// Error copy, so nothing appears twice.
func TestLogRoutingSameDestination(t *testing.T) {
	var out bytes.Buffer
	l := slog.New(newLogHandler(&out, &out, nil, newLogBuffer(10)))
	l.Info("request", "status", 200)
	l.Error("server error")
	if strings.Count(out.String(), "\n") != 2 {
		t.Errorf("want one line per record, got:\n%s", out.String())
	}
}

// TestLogFileReopenConcurrent rotates the file the way logrotate does
// (rename, then SIGUSR1) while goroutines log; every line must end up in
// exactly one of the files. Run with -race.
func TestLogFileReopenConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	f, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lf := &logFile{path: path, f: f}
	l := slog.New(newLogHandler(lf, lf, nil, newLogBuffer(10)))

	const writers, lines, rotations = 8, 2000, 20
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range lines {
				l.Info("request", "id", fmt.Sprintf("%d-%d", w, i))
			}
		}()
	}
	for r := range rotations {
		if err := os.Rename(path, fmt.Sprintf("%s.%d", path, r)); err != nil {
			t.Fatal(err)
		}
		if err := lf.reopen(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	lf.f.Close()

	seen := map[string]bool{}
	files, _ := filepath.Glob(path + "*")
	for _, name := range files {
		fh, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			_, id, ok := strings.Cut(sc.Text(), " id=")
			if !ok || seen[id] {
				t.Errorf("%s: broken or duplicate line %q", name, sc.Text())
			}
			seen[id] = true
		}
		fh.Close()
	}
	if len(seen) != writers*lines {
		t.Errorf("found %d of %d lines in %d files", len(seen), writers*lines, len(files))
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&^0640 != 0 {
		t.Errorf("log file mode %v, want at most 0640", st.Mode().Perm())
	}
}

// TestLogFileReopenFailure keeps writing to the old file when the new one
// cannot be created.
func TestLogFileReopenFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only directory")
	}
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(logs, "webdavgo.log")
	f, err := openLogFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lf := &logFile{path: path, f: f}
	defer lf.f.Close()
	moved := filepath.Join(logs, "webdavgo.log.1")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(logs, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(logs, 0750)

	if err := lf.reopen(); err == nil {
		t.Fatal("reopen in a read-only directory succeeded")
	}
	if _, err := lf.Write([]byte("after\n")); err != nil {
		t.Fatalf("write after failed reopen: %v", err)
	}
	if b, _ := os.ReadFile(moved); string(b) != "after\n" {
		t.Errorf("old file has %q, want the line written after the failed reopen", b)
	}
}

// TestInitLoggerOpenError leaves the stdout logger in place and reports
// the failure, so main can exit instead of logging nowhere.
func TestInitLoggerOpenError(t *testing.T) {
	before := logger
	defer func() { logger = before }()
	missing := filepath.Join(t.TempDir(), "no-such-dir", "access.log")
	if err := initLogger(missing, ""); err == nil {
		t.Fatal("initLogger with an unopenable access_log returned no error")
	}
	if logger != before {
		t.Error("initLogger replaced the logger although it failed")
	}
}

func TestConfigLogPaths(t *testing.T) {
	tests := []struct {
		access, server string
		ok             bool
	}{
		{"", "", true},
		{"/var/log/webdavgo/access.log", "/var/log/webdavgo/webdavgo.log", true},
		{"/var/log/webdavgo/all.log", "/var/log/webdavgo/all.log", true},
		{"/var/log/webdavgo/access.log", "", true},
		{"access.log", "", false},
		{"", "./webdavgo.log", false},
	}
	for _, tt := range tests {
		c := defaultConfig()
		c.AccessLog, c.ServerLog = tt.access, tt.server
		err := c.validate()
		if (err == nil) != tt.ok {
			t.Errorf("access_log=%q server_log=%q: err=%v, want ok=%v", tt.access, tt.server, err, tt.ok)
		}
	}
}
