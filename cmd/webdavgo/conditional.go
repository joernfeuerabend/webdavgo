// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// conditional.go – ETags, conditional writes (RFC 9110 §13), atomic PUT,
// quota enforcement for writes and safe headers for downloads.
//
// x/net/webdav ignores If-Match / If-None-Match on PUT and writes in place
// with O_TRUNC. Sync clients need both: a precondition that is evaluated
// atomically with the write, and a write that is never observed half-done.
// Everything here wraps x/net instead of replacing its PUT/DELETE handling,
// so status codes stay exactly as x/net produces them. Lock decisions are made
// here and in locks.go before x/net runs.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/webdav"
)

// tmpPrefix marks in-flight PUT bodies. Names with this prefix are hidden
// from every listing and cannot be addressed by clients.
const tmpPrefix = ".webdavgo-tmp-"

// fileETag is the only ETag function. It uses x/net's own format so that any
// ETag x/net might compute itself is identical to ours by construction.
// Nanosecond mtime makes the tag change on every write, even within the same
// second, on filesystems that store sub-second mtimes (ext4, APFS).
func fileETag(fi os.FileInfo) string {
	return fmt.Sprintf(`"%x%x"`, fi.ModTime().UnixNano(), fi.Size())
}

// isReservedPath reports whether any segment of a slash path names a
// temporary upload file.
func isReservedPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, tmpPrefix) {
			return true
		}
	}
	return false
}

// requestTouchesReserved reports whether the request URL or its Destination
// header (MOVE/COPY) refers to a temporary upload file.
func requestTouchesReserved(r *http.Request) bool {
	if isReservedPath(r.URL.Path) {
		return true
	}
	if dst := r.Header.Get("Destination"); dst != "" {
		if u, err := url.Parse(dst); err == nil && isReservedPath(u.Path) {
			return true
		}
	}
	return false
}

// ---- per-path locking -------------------------------------------------------

// pathLocks serialises writes per absolute filesystem path. The user and the
// share endpoint can reach the same file, so the key must be the resolved path,
// not the URL. Entries are reference-counted and removed when idle so the map
// does not grow with every path ever written.
var pathLocks = struct {
	mu sync.Mutex
	m  map[string]*pathLock
}{m: map[string]*pathLock{}}

type pathLock struct {
	sync.Mutex
	refs int
}

// lockPath blocks until the caller holds the lock for absPath and returns the
// matching unlock function.
func lockPath(absPath string) func() {
	pathLocks.mu.Lock()
	l := pathLocks.m[absPath]
	if l == nil {
		l = &pathLock{}
		pathLocks.m[absPath] = l
	}
	l.refs++
	pathLocks.mu.Unlock()

	l.Lock()
	return func() {
		l.Unlock()
		pathLocks.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(pathLocks.m, absPath)
		}
		pathLocks.mu.Unlock()
	}
}

// lockPaths holds the path locks of several keys. They are taken in sorted order
// so that two requests naming the same paths cannot deadlock, and a key named
// twice (MOVE onto itself) is taken once.
func lockPaths(keys ...string) func() {
	sorted := slices.Clone(keys)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	unlocks := make([]func(), len(sorted))
	for i, key := range sorted {
		unlocks[i] = lockPath(key)
	}
	return func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
}

// ---- preconditions (RFC 9110 §13.1.1, §13.1.2, §13.2.2) ---------------------

// entityTag is one parsed member of an If-Match / If-None-Match list.
type entityTag struct {
	weak   bool
	opaque string // including the surrounding quotes
}

// parseETagList parses a comma-separated entity-tag list. star is true for
// the "*" form. Malformed members are dropped: they can never match, which is
// the safe outcome for If-Match and harmless for If-None-Match.
func parseETagList(h string) (tags []entityTag, star bool) {
	s := strings.TrimSpace(h)
	if s == "*" {
		return nil, true
	}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		weak := false
		if strings.HasPrefix(s, "W/") {
			weak = true
			s = s[2:]
		}
		if !strings.HasPrefix(s, `"`) {
			// Skip to the next member.
			if i := strings.IndexByte(s, ','); i >= 0 {
				s = s[i+1:]
				continue
			}
			break
		}
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			break
		}
		tags = append(tags, entityTag{weak: weak, opaque: s[:end+2]})
		s = s[end+2:]
	}
	return tags, false
}

// checkPreconditions evaluates If-Match and then If-None-Match against the
// current state of absPath. It returns false when the request must be
// answered with 412. Weak tags never satisfy If-Match (strong comparison),
// but do satisfy If-None-Match (weak comparison).
func checkPreconditions(r *http.Request, absPath string, withIfNoneMatch bool) (bool, error) {
	ifMatch, hasIfMatch := r.Header["If-Match"]
	ifNoneMatch, hasIfNoneMatch := r.Header["If-None-Match"]
	if !withIfNoneMatch {
		hasIfNoneMatch = false
	}
	if !hasIfMatch && !hasIfNoneMatch {
		return true, nil
	}

	exists := true
	current := ""
	fi, err := os.Stat(absPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		exists = false
	case err != nil:
		return false, fmt.Errorf("stat %s for precondition: %w", absPath, err)
	default:
		current = fileETag(fi)
	}

	if hasIfMatch {
		tags, star := parseETagList(strings.Join(ifMatch, ","))
		if !exists {
			return false, nil
		}
		if !star {
			matched := false
			for _, t := range tags {
				if !t.weak && t.opaque == current {
					matched = true
					break
				}
			}
			if !matched {
				return false, nil
			}
		}
	}

	if hasIfNoneMatch {
		tags, star := parseETagList(strings.Join(ifNoneMatch, ","))
		if star && exists {
			return false, nil
		}
		if exists {
			for _, t := range tags {
				if t.opaque == current {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// davStatusKey carries the request's statusRecorder to the Logger of a
// webdav.Handler: x/net calls it after writing the status, but passes only
// the request and the error.
type davStatusKey struct{}

// davStatus is the status x/net answered r with; 0 if unknown.
func davStatus(r *http.Request) int {
	if sr, ok := r.Context().Value(davStatusKey{}).(*statusRecorder); ok {
		return sr.status
	}
	return 0
}

// localFaults are errors of this host's storage. x/net answers some of them
// with a 4xx (a PUT that fails on a full disk gets 405, an OpenFile denied
// by permissions 404), but they are faults of the server, not the client.
// EDQUOT may not exist on every platform; it does on all make dist targets
// (linux and darwin, amd64 and arm64), so a new target without it fails to
// build here instead of silently losing the check.
var localFaults = []syscall.Errno{
	syscall.ENOSPC, syscall.EDQUOT, syscall.EIO, syscall.EROFS, syscall.EACCES, syscall.EPERM,
}

// davErrorLevel is the log level of an error x/net reports for a request
// answered with status. x/net reports every failed request, also client
// errors such as MKCOL on an existing collection (405) or a missing file
// (404); those are Debug. A 5xx or a local storage fault is Warn.
func davErrorLevel(status int, err error) slog.Level {
	// A full quota is the user's limit, not a server fault, and is logged
	// once by logQuotaExceeded.
	if errors.Is(err, errQuotaExceeded) {
		return slog.LevelDebug
	}
	if status >= 500 {
		return slog.LevelWarn
	}
	for _, e := range localFaults {
		if errors.Is(err, e) {
			return slog.LevelWarn
		}
	}
	return slog.LevelDebug
}

// serveDAV hands a request to x/net/webdav. A write first takes the per-path
// lock, evaluates the preconditions and passes the lock check, and keeps the
// path lock until x/net has finished, so check and write are atomic against
// other writers. absPath is the filesystem path the request URL resolves to.
// owner is the user whose quota the request is charged to and whose locks apply.
func serveDAV(w http.ResponseWriter, r *http.Request, h *webdav.Handler, absPath, owner string) {
	sr, recorded := w.(*statusRecorder)
	if !recorded {
		sr = &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w = sr
	}
	r = r.WithContext(context.WithValue(r.Context(), davStatusKey{}, sr))
	locks := userLocks(owner)
	// Only the user handler is rooted at "/", a share at its /s/ prefix.
	isShare := h.Prefix != "/"
	name := locks.nameOf(absPath)
	if isShareWriteMethod(r.Method) {
		syncUsageEpoch()
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
		// A share accepts no lock tokens, and an If header on a read never
		// mattered there.
		if !isShare && !locks.checkRead(w, r, name) {
			return
		}
		// x/net answers POST like GET, with the file's content.
		setContentHeaders(w.Header(), absPath)
		h.ServeHTTP(w, r)
		return
	case "LOCK":
		serveLock(w, r, locks, absPath)
		return
	case "UNLOCK":
		serveUnlock(w, r, locks, absPath)
		return
	case "COPY", "MOVE":
		serveCopyMove(w, r, h, absPath, owner)
		return
	case "MKCOL", "PROPPATCH":
		key, err := filepath.Abs(absPath)
		if err != nil {
			logger.Error("cannot resolve absolute path", "path", absPath, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer lockPaths(key)()
		done, ok := locks.admitWrite(w, r, isShare, name, []writeTarget{{name: name, member: r.Method == "MKCOL" && !pathExists(key)}})
		if !ok {
			return
		}
		defer done()
		if r.Method == "PROPPATCH" {
			servePropPatch(w, r, owner, name, key)
			return
		}
		h.ServeHTTP(w, r)
		return
	case http.MethodPut, http.MethodDelete:
	default:
		h.ServeHTTP(w, r)
		return
	}

	key, err := filepath.Abs(absPath)
	if err != nil {
		logger.Error("cannot resolve absolute path", "path", absPath, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	unlock := lockPath(key)
	defer unlock()

	// If-None-Match on DELETE is not part of the supported contract; only
	// If-Match guards deletes.
	ok, err := checkPreconditions(r, key, r.Method == http.MethodPut)
	if err != nil {
		logger.Error("precondition evaluation failed", "path", key, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		logger.Debug("precondition failed", "method", r.Method, "path", r.URL.Path,
			"if_match", r.Header.Get("If-Match"), "if_none_match", r.Header.Get("If-None-Match"))
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return
	}

	if r.Method == http.MethodDelete {
		done, ok := locks.admitWrite(w, r, isShare, name, []writeTarget{{name: name, member: true, replaces: true, tree: true}})
		if !ok {
			return
		}
		var removed []string
		defer func() { done(removed...) }()
		defer locks.beginTreeOp(name)()
		before := treeSize(key)
		h.ServeHTTP(w, r)
		// Measured rather than derived from the status: a failed recursive
		// delete may still have removed part of the tree.
		delta := treeSize(key) - before
		if sr.status == http.StatusNoContent {
			removed = []string{name}
			delta -= removeDeadProps(owner, name)
		} else {
			delta -= pruneGoneDeadProps(owner, name)
		}
		settleQuota(owner, 0, delta)
		return
	}

	done, ok := locks.admitWrite(w, r, isShare, name, []writeTarget{{name: name, member: !pathExists(key)}})
	if !ok {
		return
	}
	defer done()

	// A declared body is checked before any of it is read; a chunked one is
	// checked chunk by chunk in atomicFile.Write. Only the growth counts, so
	// overwriting a file with one of the same size always passes.
	if r.ContentLength > 0 {
		var old int64
		if fi, err := os.Stat(key); err == nil && fi.Mode().IsRegular() {
			old = fi.Size()
		}
		if grow := r.ContentLength - old; grow > 0 {
			if err := reserveQuota(owner, grow); err != nil {
				quotaRefused(w, r, owner, err)
				return
			}
			settleQuota(owner, grow, 0)
		}
	}

	// x/net reads r.Body itself and passes r.Context() to OpenFile; the
	// tracker travels through the context so davFS can tell a complete
	// upload from an aborted one when the file is closed.
	body := &putBody{ReadCloser: r.Body, owner: owner}
	r = r.WithContext(context.WithValue(r.Context(), putBodyKey{}, body))
	r.Body = body
	h.ServeHTTP(&quotaWriter{ResponseWriter: w, r: r, body: body}, r)
}

// ---- download headers ---------------------------------------------------------

// setContentHeaders marks a response that carries a stored file as a
// download. Files are uploaded by users and shared with others, so a browser
// must never render one as a page of this origin (stored XSS): it is saved
// instead (Content-Disposition), its type is not guessed (nosniff), and the
// CSP sandbox disarms it should it be rendered anyway. Directories and
// missing paths are left alone; x/net answers those with an error.
func setContentHeaders(h http.Header, absPath string) {
	fi, err := os.Stat(absPath)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	h.Set("Content-Disposition", "attachment; filename*=UTF-8''"+rfc5987Escape(filepath.Base(absPath)))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
}

// rfc5987Escape percent-encodes s as an ext-value (RFC 8187 §3.2.1): every
// byte outside attr-char is encoded, so any file name survives the header.
func rfc5987Escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("!#$&+-.^_`|~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

// ---- quota ------------------------------------------------------------------

// quotaRefused answers a write the quota check refused: 507 when the quota
// is full, 503 when it could not be read.
func quotaRefused(w http.ResponseWriter, r *http.Request, owner string, err error) {
	if !errors.Is(err, errQuotaExceeded) {
		serviceUnavailable(w, r, "quota lookup failed", err)
		return
	}
	logQuotaExceeded(r, owner)
	writeQuotaExceeded(w)
}

// writeQuotaExceeded writes 507 (RFC 4918 §11.5) with the precondition code
// RFC 4331 §6 defines for a write that would exceed the quota.
func writeQuotaExceeded(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusInsufficientStorage)
	io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:"><d:quota-not-exceeded/></d:error>`)
}

func logQuotaExceeded(r *http.Request, owner string) {
	logger.Warn("write rejected: quota exceeded", "user", owner, "method", r.Method,
		"path", r.URL.Path, "client", remoteIP(r))
}

// quotaWriter answers a PUT that ran out of quota while streaming with 507.
// x/net maps every error of copying the body to 405, which would tell the
// client the method is not allowed rather than that the space is used up.
type quotaWriter struct {
	http.ResponseWriter
	r         *http.Request
	body      *putBody
	rewritten bool
}

func (q *quotaWriter) WriteHeader(code int) {
	if code < 400 || !q.body.quotaExceeded {
		q.ResponseWriter.WriteHeader(code)
		return
	}
	logQuotaExceeded(q.r, q.body.owner)
	q.rewritten = true
	writeQuotaExceeded(q.ResponseWriter)
}

// Write drops x/net's own status text once the response became a 507.
func (q *quotaWriter) Write(p []byte) (int, error) {
	if q.rewritten {
		return len(p), nil
	}
	return q.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the connection behind the
// writer.
func (q *quotaWriter) Unwrap() http.ResponseWriter {
	return q.ResponseWriter
}

// serveCopyMove runs COPY or MOVE and books the change in usage. Only the
// destination changes size: COPY adds the copied tree and MOVE frees what an
// overwritten destination held, the moved bytes stay with the same owner.
// Only COPY can grow usage, so only COPY is checked against the quota; a user
// over quota can still move.
//
// RFC 4918 §7.5: COPY needs no token for its source, only MOVE removes it. A
// COPY or MOVE over an existing destination deletes it first (§9.8.4, §9.9.3),
// so the locks there go with it. A moved resource keeps no lock, and the lock
// of a new parent applies by its name alone.
func serveCopyMove(w http.ResponseWriter, r *http.Request, h *webdav.Handler, absPath, owner string) {
	dst := davDestination(r, h)
	if dst == "" {
		// x/net rejects the request; nothing is written.
		r.Header.Del("If")
		h.ServeHTTP(w, r)
		return
	}
	srcKey, err := filepath.Abs(absPath)
	dstKey, dstErr := filepath.Abs(dst)
	if err != nil || dstErr != nil {
		logger.Error("cannot resolve absolute path", "path", absPath, "destination", dst, "err", errors.Join(err, dstErr))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	locks := userLocks(owner)
	isShare := h.Prefix != "/"
	srcName, dstName := locks.nameOf(absPath), locks.nameOf(dst)
	var targets []writeTarget
	if r.Method == "MOVE" {
		defer lockPaths(srcKey, dstKey)()
		targets = append(targets, writeTarget{name: srcName, member: true, replaces: true, tree: true})
	} else {
		defer lockPaths(dstKey)()
	}
	dstExists := pathExists(dstKey)
	targets = append(targets, writeTarget{name: dstName, member: !dstExists, replaces: dstExists, tree: true})
	done, ok := locks.admitWrite(w, r, isShare, srcName, targets)
	if !ok {
		return
	}
	var removed []string
	defer func() { done(removed...) }()
	defer locks.beginTreeOp(srcName, dstName)()
	dstBefore := treeSize(dst)

	if r.Method == "MOVE" {
		h.ServeHTTP(w, r)
		if s := davStatus(r); s == http.StatusCreated || s == http.StatusNoContent {
			settleQuota(owner, 0, -dstBefore+relocateDeadProps(owner, srcName, dstName, false, true))
			removed = []string{srcName, dstName}
		} else {
			// x/net removes an overwritten destination before the rename.
			settleQuota(owner, 0, -pruneGoneDeadProps(owner, srcName, dstName))
		}
		return
	}

	zeroDepth := r.Header.Get("Depth") == "0"
	var src int64
	if fi, err := os.Stat(absPath); err == nil && (!fi.IsDir() || !zeroDepth) {
		src = treeSize(absPath)
	}
	srcDead, err := deadPropsSize(owner, srcName, zeroDepth)
	var dstDead int64
	if err == nil {
		dstDead, err = deadPropsSize(owner, dstName, false)
	}
	if err != nil {
		serviceUnavailable(w, r, "dead property lookup failed", err)
		return
	}
	var reserved int64
	if grow := src + srcDead - dstBefore - dstDead; grow > 0 {
		if err := reserveQuota(owner, grow); err != nil {
			quotaRefused(w, r, owner, err)
			return
		}
		reserved = grow
	}
	h.ServeHTTP(w, r)
	delta := treeSize(dst) - dstBefore
	if s := davStatus(r); s == http.StatusCreated || s == http.StatusNoContent {
		removed = []string{dstName}
		delta += relocateDeadProps(owner, srcName, dstName, zeroDepth, false)
	} else {
		delta -= pruneGoneDeadProps(owner, dstName)
	}
	settleQuota(owner, reserved, delta)
}

// pathExists reports whether something is at absPath. An error other than a
// missing file counts as existing, which asks for the stricter lock check.
func pathExists(absPath string) bool {
	_, err := os.Stat(absPath)
	return !errors.Is(err, fs.ErrNotExist)
}

// davDestination resolves the Destination header of a COPY or MOVE to a
// filesystem path the way x/net does, or returns "" where x/net will refuse
// the request.
func davDestination(r *http.Request, h *webdav.Handler) string {
	fsys, ok := h.FileSystem.(davFS)
	if !ok {
		return ""
	}
	u, err := url.Parse(r.Header.Get("Destination"))
	if err != nil || u.Path == "" {
		return ""
	}
	name, found := strings.CutPrefix(u.Path, h.Prefix)
	if !found {
		return ""
	}
	return fsys.resolve(name)
}

// ---- atomic PUT -------------------------------------------------------------

type putBodyKey struct{}

// putBody records whether the request body was read to a clean EOF, and
// carries the upload's quota owner to atomicFile.
type putBody struct {
	io.ReadCloser
	eof           bool
	err           error
	owner         string
	quotaExceeded bool
}

func (b *putBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.eof = true
	} else if err != nil && b.err == nil {
		b.err = err
	}
	return n, err
}

// davFS wraps webdav.Dir to make PUT atomic, to report ETags through the
// single fileETag function, and to hide temporary upload files.
type davFS struct {
	webdav.Dir
}

// resolve mirrors webdav.Dir's own name resolution, which is unexported.
func (d davFS) resolve(name string) string {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) ||
		strings.Contains(name, "\x00") {
		return ""
	}
	dir := string(d.Dir)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, filepath.FromSlash(path.Clean("/"+name)))
}

func (d davFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	body, isPut := ctx.Value(putBodyKey{}).(*putBody)
	if isPut && flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0 {
		target := d.resolve(name)
		if target == "" {
			return nil, os.ErrNotExist
		}
		// Writing over a directory must fail exactly as before; let x/net's
		// Dir produce that error.
		mode := os.FileMode(0644)
		var oldSize int64
		if fi, err := os.Stat(target); err == nil {
			if fi.IsDir() {
				return d.Dir.OpenFile(ctx, name, flag, perm)
			}
			mode = fi.Mode().Perm()
			oldSize = fi.Size()
		}
		tmp, err := os.CreateTemp(filepath.Dir(target), tmpPrefix+"*")
		if err != nil {
			return nil, err
		}
		// CreateTemp uses 0600; keep the mode an in-place write would have had.
		if err := tmp.Chmod(mode); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("chmod temp file: %w", err)
		}
		return &atomicFile{f: tmp, target: target, body: body, oldSize: oldSize}, nil
	}

	f, err := d.Dir.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	return davFile{f}, nil
}

func (d davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, err := d.Dir.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	return etagInfo{fi}, nil
}

// etagInfo makes x/net's findETag use fileETag (via webdav.ETager).
type etagInfo struct {
	os.FileInfo
}

func (fi etagInfo) ETag(context.Context) (string, error) {
	return fileETag(fi.FileInfo), nil
}

// davFile adds ETag reporting and temp-file filtering to a regular file.
type davFile struct {
	webdav.File
}

func (f davFile) Stat() (os.FileInfo, error) {
	fi, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return etagInfo{fi}, nil
}

func (f davFile) Readdir(count int) ([]os.FileInfo, error) {
	infos, err := f.File.Readdir(count)
	kept := infos[:0]
	for _, fi := range infos {
		if !strings.HasPrefix(fi.Name(), tmpPrefix) {
			kept = append(kept, fi)
		}
	}
	return kept, err
}

// atomicFile collects a PUT body in a temp file next to the target and only
// renames it over the target on Close if the body was read to a clean EOF and
// every write succeeded. Otherwise the temp file is removed and the existing
// target stays untouched. Methods are spelled out instead of embedding
// *os.File so io.Copy cannot bypass Write via (*os.File).ReadFrom, which
// would also bypass the quota check.
type atomicFile struct {
	f        *os.File
	target   string
	body     *putBody
	writeErr error
	oldSize  int64 // size of the target being replaced; 0 for a new file
	written  int64
	reserved int64 // quota claimed so far: the growth past oldSize
}

func (a *atomicFile) Write(p []byte) (int, error) {
	if a.writeErr != nil {
		return 0, a.writeErr
	}
	// Claimed per chunk so that a chunked upload stops as soon as it passes
	// the quota, not after the whole body is on disk.
	if need := a.written + int64(len(p)) - a.oldSize - a.reserved; need > 0 {
		if err := reserveQuota(a.body.owner, need); err != nil {
			if errors.Is(err, errQuotaExceeded) {
				a.body.quotaExceeded = true
			}
			a.writeErr = err
			return 0, err
		}
		a.reserved += need
	}
	n, err := a.f.Write(p)
	a.written += int64(n)
	if err != nil && a.writeErr == nil {
		a.writeErr = err
	}
	return n, err
}

func (a *atomicFile) Read(p []byte) (int, error)                { return a.f.Read(p) }
func (a *atomicFile) Seek(off int64, whence int) (int64, error) { return a.f.Seek(off, whence) }
func (a *atomicFile) Readdir(count int) ([]os.FileInfo, error)  { return a.f.Readdir(count) }

// Stat reports the temp file. rename(2) keeps mtime and size, so the ETag x/net
// derives from it equals the ETag of the target after the commit.
func (a *atomicFile) Stat() (os.FileInfo, error) {
	fi, err := a.f.Stat()
	if err != nil {
		return nil, err
	}
	return etagInfo{fi}, nil
}

func (a *atomicFile) Close() error {
	tmpName := a.f.Name()
	complete := a.body.eof && a.body.err == nil && a.writeErr == nil
	var err error
	if complete {
		// Without fsync a crash right after rename could leave an empty
		// target, which is exactly what atomic PUT is meant to prevent.
		err = a.f.Sync()
	}
	if cerr := a.f.Close(); err == nil {
		err = cerr
	}
	if !complete || err != nil {
		os.Remove(tmpName)
		settleQuota(a.body.owner, a.reserved, 0)
		if err != nil {
			return fmt.Errorf("finish temp file %s: %w", tmpName, err)
		}
		return fmt.Errorf("upload to %s incomplete, discarded", a.target)
	}
	if err := os.Rename(tmpName, a.target); err != nil {
		os.Remove(tmpName)
		settleQuota(a.body.owner, a.reserved, 0)
		return fmt.Errorf("commit %s: %w", a.target, err)
	}
	settleQuota(a.body.owner, a.reserved, a.written-a.oldSize)
	return nil
}
