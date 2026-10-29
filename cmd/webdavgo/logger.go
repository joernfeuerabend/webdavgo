// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

var logger *slog.Logger

// logLevel starts at Info so that config errors can be logged before the
// configured level is known; main sets it once the config is loaded.
var logLevel slog.LevelVar

// logRing keeps the newest records for the admin Live Log page. It starts with
// the default size so that startup lines are kept; main resizes it to
// log_buffer_entries once the config is loaded.
var logRing = newLogBuffer(2000)

// initLogger is the single place that decides where log output goes.
// accessLog gets the "request" records and serverLog every other record,
// like nginx's access and error logs; an empty path means stdout. main
// calls it once without paths at start, so that records before the config
// is loaded reach stdout, and once more with the configured paths, for the
// service only: CLI commands keep logging to the terminal. The ring buffer
// always gets a copy of every record.
//
// A log file that cannot be opened is reported on stderr and returned as
// error; the caller exits instead of logging somewhere the operator does
// not look.
func initLogger(accessLog, serverLog string) error {
	if accessLog == "" && serverLog == "" {
		logger = slog.New(newLogHandler(os.Stdout, os.Stdout, nil, logRing))
		return nil
	}
	// Registered before any file is open: a SIGUSR1 that arrives after a
	// file was opened then waits in the channel instead of being dropped,
	// so a rotation in that gap still gets its reopen.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)

	var files []*logFile
	open := func(path string) (io.Writer, error) {
		if path == "" {
			return os.Stdout, nil
		}
		for _, f := range files {
			if f.path == path {
				return f, nil
			}
		}
		f, err := openLogFile(path)
		if err != nil {
			return nil, err
		}
		lf := &logFile{path: path, f: f}
		files = append(files, lf)
		return lf, nil
	}
	access, err := open(accessLog)
	var server io.Writer
	if err == nil {
		server, err = open(serverLog)
	}
	if err != nil {
		signal.Stop(usr1)
		for _, f := range files {
			f.f.Close()
		}
		slog.New(newLineHandler(&lineWriter{w: os.Stderr})).Error("cannot open log file", "err", err)
		return err
	}

	// systemd shows stderr in the journal and in systemctl status, which
	// is where an operator looks first when the service does not come up.
	var errs io.Writer
	if serverLog != "" {
		errs = os.Stderr
	}
	logger = slog.New(newLogHandler(access, server, errs, logRing))

	go func() {
		for range usr1 {
			reopened := true
			for _, f := range files {
				if err := f.reopen(); err != nil {
					reopened = false
					logger.Warn("cannot reopen log file; still writing to the old one", "path", f.path, "err", err)
				}
			}
			if reopened {
				logger.Info("log files reopened", "access_log", accessLog, "server_log", serverLog)
			}
		}
	}()
	return nil
}

// newLogHandler builds the handler initLogger installs; errs, if not nil,
// gets a copy of every Error record. Destinations that are the same writer
// share one lineWriter, so their lines never interleave.
func newLogHandler(access, server, errs io.Writer, ring *logBuffer) slog.Handler {
	writers := map[io.Writer]*lineWriter{}
	lineTo := func(w io.Writer) slog.Handler {
		lw, ok := writers[w]
		if !ok {
			lw = &lineWriter{w: w}
			writers[w] = lw
		}
		return newLineHandler(lw)
	}
	h := routeHandler{access: lineTo(access), server: lineTo(server)}
	if errs != nil {
		h.errs = lineTo(errs)
	}
	return teeHandler{out: h, ring: ring.handler()}
}

// lineTimeFormat is the layout slog's TextHandler uses for time=.
const lineTimeFormat = "2006-01-02T15:04:05.000Z07:00"

// lineWriter is the destination of one or more lineHandlers. The scratch
// buffer and the line are used by one record at a time, under mu, and
// each line reaches w in a single Write: O_APPEND keeps it whole even when
// another process appends to the same file.
type lineWriter struct {
	mu      sync.Mutex
	w       io.Writer
	scratch bytes.Buffer // TextHandler output of the record being written
	line    []byte
}

// lineHandler writes "<time> <LEVEL> <message> <attrs>", the layout of
// classic service logs, so that a line can be read and sorted by its
// start. A TextHandler without time and level renders the rest, so the
// message is quoted exactly like a value and the attributes, groups and
// WithAttrs read as before.
type lineHandler struct {
	out  *lineWriter
	text slog.Handler // writes "msg=<message> <attrs>\n" into out.scratch
}

func newLineHandler(lw *lineWriter) slog.Handler {
	return lineHandler{out: lw, text: slog.NewTextHandler(&lw.scratch, &slog.HandlerOptions{
		Level: &logLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
				return slog.Attr{}
			}
			return a
		},
	})}
}

func (h lineHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.text.Enabled(ctx, l)
}

func (h lineHandler) Handle(ctx context.Context, r slog.Record) error {
	o := h.out
	o.mu.Lock()
	defer o.mu.Unlock()
	o.scratch.Reset()
	if err := h.text.Handle(ctx, r); err != nil {
		return err
	}
	o.line = r.Time.AppendFormat(o.line[:0], lineTimeFormat)
	o.line = append(o.line, ' ')
	o.line = append(o.line, r.Level.String()...)
	o.line = append(o.line, ' ')
	// With time and level removed, the message is the first thing the
	// TextHandler writes; only its key goes.
	o.line = append(o.line, bytes.TrimPrefix(o.scratch.Bytes(), []byte(slog.MessageKey+"="))...)
	_, err := o.w.Write(o.line)
	return err
}

func (h lineHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return lineHandler{out: h.out, text: h.text.WithAttrs(as)}
}

func (h lineHandler) WithGroup(name string) slog.Handler {
	return lineHandler{out: h.out, text: h.text.WithGroup(name)}
}

// accessMsg is the message of the per-request line, the only record that
// goes to the access log.
const accessMsg = "request"

// routeHandler sends accessMsg records to access and every other record to
// server. All three handlers share logLevel, so Enabled asks only one.
type routeHandler struct {
	access, server slog.Handler
	errs           slog.Handler // nil: no copy of Error records
}

func (h routeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.server.Enabled(ctx, l)
}

func (h routeHandler) Handle(ctx context.Context, r slog.Record) error {
	dst := h.server
	if r.Message == accessMsg {
		dst = h.access
	}
	err := dst.Handle(ctx, r)
	if h.errs != nil && r.Level >= slog.LevelError {
		h.errs.Handle(ctx, r)
	}
	return err
}

func (h routeHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := routeHandler{access: h.access.WithAttrs(as), server: h.server.WithAttrs(as)}
	if h.errs != nil {
		out.errs = h.errs.WithAttrs(as)
	}
	return out
}

func (h routeHandler) WithGroup(name string) slog.Handler {
	out := routeHandler{access: h.access.WithGroup(name), server: h.server.WithGroup(name)}
	if h.errs != nil {
		out.errs = h.errs.WithGroup(name)
	}
	return out
}

// logFile is a log file that logrotate can move away: reopen switches to
// a new file at path while other goroutines keep writing.
type logFile struct {
	path string
	mu   sync.Mutex // held for every write, so no write hits a closed file
	f    *os.File
}

func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if err != nil {
		return nil, fmt.Errorf("log file: %w", err)
	}
	return f, nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Write(p)
}

// reopen opens the new file before it takes the lock, so a failure leaves
// the old file in use and writers wait only for the swap.
func (l *logFile) reopen() error {
	f, err := openLogFile(l.path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.f
	l.f = f
	l.mu.Unlock()
	// Writes are unbuffered, so a failed close loses nothing.
	old.Close()
	return nil
}

// newServerErrorLog returns an http.Server ErrorLog that feeds net/http's
// own messages into logger, so they reach the Live Log page and obey
// log_level. TLS handshake errors are Debug: on a public port they are
// mostly scanners and would drown the journal at Info. They are counted for
// the Status page whatever the level.
func newServerErrorLog(listener string) *log.Logger {
	return log.New(serverErrorWriter{listener: listener}, "", 0)
}

type serverErrorWriter struct{ listener string }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	level := slog.LevelWarn
	switch {
	case strings.Contains(msg, "TLS handshake error"):
		level = slog.LevelDebug
		stats.tlsError(statListenerIndex(w.listener))
	case strings.Contains(msg, "http2: received GOAWAY"):
		// A browser closing its HTTP/2 connection, not a fault.
		level = slog.LevelDebug
	}
	logger.Log(context.Background(), level, msg, "listener", w.listener)
	return len(p), nil
}

// teeHandler passes every record to out and then to the ring buffer.
// Enabled follows out, so the buffer holds exactly what the log
// destinations get.
type teeHandler struct {
	out  slog.Handler
	ring slog.Handler
}

func (h teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.out.Enabled(ctx, l)
}

func (h teeHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.out.Handle(ctx, r)
	h.ring.Handle(ctx, r)
	return err
}

func (h teeHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return teeHandler{out: h.out.WithAttrs(as), ring: h.ring.WithAttrs(as)}
}

func (h teeHandler) WithGroup(name string) slog.Handler {
	return teeHandler{out: h.out.WithGroup(name), ring: h.ring.WithGroup(name)}
}

// logEntry is one record in the ring buffer. Attrs is rendered by a
// TextHandler, so it reads like the journal line.
type logEntry struct {
	Time  time.Time
	Level slog.Level
	Msg   string
	Attrs string
}

// logBuffer is a fixed-size ring of the newest log records.
type logBuffer struct {
	mu      sync.Mutex
	entries []logEntry
	next    int // index of the slot to write next
	full    bool
	scratch bytes.Buffer // TextHandler output of the record being added
}

func newLogBuffer(n int) *logBuffer {
	return &logBuffer{entries: make([]logEntry, n)}
}

// handler returns a slog handler that adds records to b.
func (b *logBuffer) handler() slog.Handler {
	return ringHandler{buf: b, text: slog.NewTextHandler(&b.scratch, &slog.HandlerOptions{
		Level: &logLevel,
		// Time, level and message have their own columns.
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
				return slog.Attr{}
			}
			return a
		},
	})}
}

type ringHandler struct {
	buf  *logBuffer
	text slog.Handler // writes into buf.scratch, only while buf.mu is held
}

func (h ringHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.text.Enabled(ctx, l)
}

func (h ringHandler) Handle(ctx context.Context, r slog.Record) error {
	b := h.buf
	b.mu.Lock()
	defer b.mu.Unlock()
	b.scratch.Reset()
	h.text.Handle(ctx, r)
	b.entries[b.next] = logEntry{
		Time:  r.Time,
		Level: r.Level,
		Msg:   capBytes(r.Message, logEntryMsgMax),
		Attrs: capBytes(strings.TrimSpace(b.scratch.String()), logEntryAttrsMax),
	}
	b.next++
	if b.next == len(b.entries) {
		b.next, b.full = 0, true
	}
	return nil
}

// A path or username in a log record is the client's string and may be up
// to MaxHeaderBytes (64 KiB) long; uncapped, log_buffer_entries of those
// would hold over 100 MiB. The journal or log file keeps the full line.
const (
	logEntryMsgMax   = 256
	logEntryAttrsMax = 1024
)

// capBytes cuts s to at most n bytes at a UTF-8 boundary and says how much
// was cut.
func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("…(+%d bytes)", len(s)-cut)
}

func (h ringHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return ringHandler{buf: h.buf, text: h.text.WithAttrs(as)}
}

func (h ringHandler) WithGroup(name string) slog.Handler {
	return ringHandler{buf: h.buf, text: h.text.WithGroup(name)}
}

// resize changes the capacity to n, keeping the newest entries.
func (b *logBuffer) resize(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n == len(b.entries) {
		return
	}
	old := b.newestLocked()
	if len(old) > n {
		old = old[:n]
	}
	b.entries = make([]logEntry, n)
	// old is newest first; the ring stores oldest first.
	for i := range old {
		b.entries[i] = old[len(old)-1-i]
	}
	b.next, b.full = len(old)%n, len(old) == n
}

// newestLocked returns a copy of all entries, newest first.
func (b *logBuffer) newestLocked() []logEntry {
	n := b.next
	if b.full {
		n = len(b.entries)
	}
	out := make([]logEntry, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, b.entries[(b.next-i+len(b.entries))%len(b.entries)])
	}
	return out
}

// query returns the entries at minLevel or above whose level, message or
// attributes contain text (case-insensitive), newest first, and how many
// entries the buffer holds in total.
func (b *logBuffer) query(minLevel slog.Level, text string) (matches []logEntry, total, capacity int) {
	b.mu.Lock()
	all := b.newestLocked()
	capacity = len(b.entries)
	b.mu.Unlock()
	text = strings.ToLower(text)
	for _, e := range all {
		if e.Level < minLevel {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.Level.String()+" "+e.Msg+" "+e.Attrs), text) {
			continue
		}
		matches = append(matches, e)
	}
	return matches, len(all), capacity
}
