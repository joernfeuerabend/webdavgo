// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// props.go – shared property resolution for PROPFIND and SEARCH responses.
// Both handlers build their 207 Multi-Status bodies through the helpers here
// so property values (and in particular getetag and getlastmodified) cannot
// drift apart between the two. Dead properties and PROPPATCH (RFC 4918 §9.2)
// live here too: x/net would only keep them in memory.

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const davNamespace = "DAV:"

// knownProps is the full set of property local-names this server can resolve.
var knownProps = map[string]bool{
	"getlastmodified":  true,
	"getetag":          true,
	"getcontentlength": true,
	"getcontenttype":   true,
	"resourcetype":     true,
	"creationdate":     true,
	"displayname":      true,
}

// allPropNames is the ordered list used when <d:select> is absent or empty.
var allPropNames = []string{
	"getlastmodified", "getetag", "getcontentlength",
	"getcontenttype", "resourcetype", "creationdate", "displayname",
}

// FileProps holds every computable property for one filesystem entry.
type FileProps struct {
	// Href is the decoded slash path including any share prefix. It stays
	// decoded so sorting and logging see the stored name; hrefXML encodes it
	// only when the response is written.
	Href         string
	LastModified string // HTTP-date (RFC 9110 §5.6.7), always "GMT"
	// ModTime is kept as a time value so SEARCH can compare and sort without
	// re-parsing the formatted string.
	ModTime       time.Time
	ETag          string
	ContentLength int64
	ContentType   string // empty for directories
	IsDir         bool
	// creationdate is returned as the file's mtime (best-effort fallback).
	// A precise birthtime requires platform-specific syscalls
	// (statx on Linux, Birthtimespec on Darwin) and is deferred to a later task.
	CreationDate string // ISO 8601 / RFC3339
	DisplayName  string
	// DisplayNameProp is the value PROPPATCH set, written instead of the
	// derived name. DisplayName then holds its text, for SEARCH to compare.
	DisplayNameProp *deadProp
}

// setDisplayName makes a stored DAV:displayname the value of the entry.
func (fp *FileProps) setDisplayName(p deadProp) {
	fp.DisplayName = deadPropText(p.Value)
	fp.DisplayNameProp = &p
}

// buildFileProps computes a FileProps from a stat result and absolute paths.
// dataDir is the user's data root; path is the absolute path to the entry.
func buildFileProps(dataDir, path string, fi os.FileInfo) FileProps {
	rel, _ := filepath.Rel(dataDir, path)
	rel = filepath.ToSlash(rel)
	var href string
	if rel == "." {
		href = "/"
	} else {
		href = "/" + rel
		if fi.IsDir() {
			href += "/"
		}
	}
	mtime := fi.ModTime().UTC()

	ct := ""
	if !fi.IsDir() {
		ct = mime.TypeByExtension(filepath.Ext(fi.Name()))
		if ct == "" {
			ct = "application/octet-stream"
		}
	}

	return FileProps{
		Href:          href,
		LastModified:  mtime.Format(http.TimeFormat),
		ModTime:       mtime,
		CreationDate:  mtime.Format(time.RFC3339),
		ETag:          fileETag(fi),
		ContentLength: fi.Size(),
		ContentType:   ct,
		IsDir:         fi.IsDir(),
		DisplayName:   fi.Name(),
	}
}

// getPropValue returns the string value of a single property.
// For resourcetype, the empty string signals "needs special XML handling".
// Returns ("", false) when the property is not applicable (e.g. content-length
// on a directory).
func getPropValue(fp FileProps, name string) (string, bool) {
	switch name {
	case "getlastmodified":
		return fp.LastModified, true
	case "getetag":
		return fp.ETag, true
	case "getcontentlength":
		if fp.IsDir {
			return "", false
		}
		return fmt.Sprintf("%d", fp.ContentLength), true
	case "getcontenttype":
		if fp.IsDir || fp.ContentType == "" {
			return "", false
		}
		return fp.ContentType, true
	case "resourcetype":
		return "", true // written by writePropElem
	case "creationdate":
		return fp.CreationDate, true
	case "displayname":
		return fp.DisplayName, true
	}
	return "", false
}

// ---- XML helpers ------------------------------------------------------------

// xmlEsc escapes the five XML special characters in a string value.
func xmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// hrefXML turns a decoded slash path into the text of a <d:href> element.
// RFC 4918 §8.3 requires a URI reference, so every segment is
// percent-encoded; macOS Finder cuts names at the first raw non-ASCII byte
// otherwise. "/" separators and a collection's trailing "/" are kept.
// Characters such as "&" are legal in a path, so XML escaping is still
// needed afterwards. The name is not Unicode-normalized: the href carries
// exactly the bytes stored on disk, so it works unchanged as a request path.
// Every href webdavgo writes goes through here so the forms cannot diverge.
func hrefXML(p string) string {
	return xmlEsc((&url.URL{Path: p}).EscapedPath())
}

// writePropElem writes one <d:propname>value</d:propname> element.
// resourcetype is written as a complex element; absent values are skipped.
func writePropElem(b *strings.Builder, name string, fp FileProps) {
	if name == "displayname" && fp.DisplayNameProp != nil {
		writeDeadProp(b, *fp.DisplayNameProp)
		return
	}
	if name == "resourcetype" {
		if fp.IsDir {
			b.WriteString("<d:resourcetype><d:collection/></d:resourcetype>")
		} else {
			b.WriteString("<d:resourcetype/>")
		}
		return
	}
	val, ok := getPropValue(fp, name)
	if !ok {
		return // property not applicable for this entry — omit silently
	}
	b.WriteString("<d:" + name + ">")
	b.WriteString(xmlEsc(val))
	b.WriteString("</d:" + name + ">")
}

// writePropstatOK writes a <d:propstat> block with HTTP/1.1 200 OK.
func writePropstatOK(b *strings.Builder, props []string, fp FileProps) {
	b.WriteString("<d:propstat><d:prop>")
	for _, name := range props {
		writePropElem(b, name, fp)
	}
	b.WriteString("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>")
}

// writePropstatNotFound writes a <d:propstat> block with HTTP/1.1 404 Not Found
// for properties that were requested but are unknown.
func writePropstatNotFound(b *strings.Builder, unknowns []string) {
	if len(unknowns) == 0 {
		return
	}
	b.WriteString("<d:propstat><d:prop>")
	for _, name := range unknowns {
		b.WriteString("<d:" + xmlEsc(name) + "/>")
	}
	b.WriteString("</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>")
}

// writeFileResponse writes one full <d:response> block for a live file.
// requested is split into known and unknown lists before calling.
func writeFileResponse(b *strings.Builder, fp FileProps, known, unknown []string) {
	b.WriteString("<d:response>")
	b.WriteString("<d:href>" + hrefXML(fp.Href) + "</d:href>")
	writePropstatOK(b, known, fp)
	writePropstatNotFound(b, unknown)
	b.WriteString("</d:response>")
}

// writeTombstoneResponse writes a <d:response> with status 404 for a deleted path.
func writeTombstoneResponse(b *strings.Builder, href string) {
	b.WriteString("<d:response>")
	b.WriteString("<d:href>" + hrefXML(href) + "</d:href>")
	b.WriteString("<d:status>HTTP/1.1 404 Not Found</d:status>")
	b.WriteString("</d:response>")
}

// splitRequested partitions a list of requested property names into those this
// server knows and those it does not.
func splitRequested(requested []string) (known, unknown []string) {
	for _, name := range requested {
		if knownProps[name] {
			known = append(known, name)
		} else {
			unknown = append(unknown, name)
		}
	}
	return
}

// splitRequestedNames is splitRequested for PROPFIND, which tells properties
// apart by namespace and local name: only a name in DAV: can be a live property.
func splitRequestedNames(requested []xml.Name) (known []string, unknown []xml.Name) {
	for _, name := range requested {
		if name.Space == davNamespace && knownProps[name.Local] {
			known = append(known, name.Local)
		} else {
			unknown = append(unknown, name)
		}
	}
	return
}

// writePropstatNotFoundNames is writePropstatNotFound for names with a namespace.
func writePropstatNotFoundNames(b *strings.Builder, names []xml.Name) {
	if len(names) == 0 {
		return
	}
	b.WriteString("<d:propstat><d:prop>")
	for _, name := range names {
		writeDeadPropName(b, name)
	}
	b.WriteString("</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>")
}

// ---- dead properties ---------------------------------------------------------

// deadProp is one dead property (RFC 4918 §4.1). Value is the XML content of the
// property element, with every namespace its elements use declared inside it, so
// it can be written under any prefix. Lang is the xml:lang in scope (§4.3).
type deadProp struct {
	Name  xml.Name
	Lang  string
	Value string
}

// size is what the property counts toward the quota and max_dead_props_size.
func (p deadProp) size() int64 {
	return int64(len(p.Name.Space) + len(p.Name.Local) + len(p.Lang) + len(p.Value))
}

// deadPropsView is what one PROPFIND needs of the dead properties. all is set
// for allprop and propname. root is the owner path of the directory the response
// hrefs are relative to, which on a share is the shared directory.
type deadPropsView struct {
	all    bool
	root   string
	byPath map[string][]deadProp
}

// protectedProps are the live properties in DAV: besides knownProps. The server
// computes all of them, so PROPPATCH cannot change them.
var protectedProps = map[string]bool{
	"supportedlock":         true,
	"lockdiscovery":         true,
	"quota-available-bytes": true,
	"quota-used-bytes":      true,
}

// isProtectedProp reports whether PROPPATCH must refuse name. DAV:displayname is
// not protected (RFC 4918 §15.2): it is stored like a dead property, and only
// without a stored value does PROPFIND derive it from the file name.
func isProtectedProp(name xml.Name) bool {
	if name.Space != davNamespace || name.Local == "displayname" {
		return false
	}
	return knownProps[name.Local] || protectedProps[name.Local]
}

func isDisplayNameProp(p deadProp) bool {
	return p.Name.Space == davNamespace && p.Name.Local == "displayname"
}

// deadPropText returns the character data of a stored value. A value that does not
// parse, which the server never stores, is returned as it is.
func deadPropText(value string) string {
	dec := xml.NewDecoder(strings.NewReader("<v>" + value + "</v>"))
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return b.String()
		}
		if err != nil {
			return value
		}
		if t, ok := tok.(xml.CharData); ok {
			b.Write(t)
		}
	}
}

// loadDisplayNames returns the DAV:displayname values stored at or below name, by
// path.
func loadDisplayNames(owner, name string) (map[string]deadProp, error) {
	where, args := deadPropScope(owner, name, false)
	rows, err := db.Query(`SELECT path, lang, value FROM dead_props WHERE `+where+
		` AND namespace = ? AND name = 'displayname'`, append(args, davNamespace)...)
	if err != nil {
		return nil, fmt.Errorf("load display names below %q: %w", name, err)
	}
	defer rows.Close()
	found := map[string]deadProp{}
	for rows.Next() {
		var p string
		dp := deadProp{Name: xml.Name{Space: davNamespace, Local: "displayname"}}
		if err := rows.Scan(&p, &dp.Lang, &dp.Value); err != nil {
			return nil, fmt.Errorf("read display names below %q: %w", name, err)
		}
		found[p] = dp
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read display names below %q: %w", name, err)
	}
	return found, nil
}

// deadPropTag returns the name to open a property element with, including the
// declaration its namespace needs, and the name to close it with. "d" is declared
// on the multistatus root. A name without a namespace must not inherit one.
func deadPropTag(name xml.Name) (open, closing string) {
	switch name.Space {
	case davNamespace:
		return "d:" + name.Local, "d:" + name.Local
	case "":
		return name.Local + ` xmlns=""`, name.Local
	}
	return "p:" + name.Local + ` xmlns:p="` + xmlEsc(name.Space) + `"`, "p:" + name.Local
}

func writeDeadPropName(b *strings.Builder, name xml.Name) {
	open, _ := deadPropTag(name)
	b.WriteString("<" + open + "/>")
}

func writeDeadProp(b *strings.Builder, p deadProp) {
	open, closing := deadPropTag(p.Name)
	b.WriteString("<" + open)
	if p.Lang != "" {
		b.WriteString(` xml:lang="` + xmlEsc(p.Lang) + `"`)
	}
	if p.Value == "" {
		b.WriteString("/>")
		return
	}
	b.WriteString(">" + p.Value + "</" + closing + ">")
}

// deadPropTreeSQL selects a path and everything below it. It takes the arguments
// of deadPropTreeArgs. A range instead of LIKE, because paths may hold wildcards,
// and it can use the primary key. "0" is the byte after "/".
const deadPropTreeSQL = `(path = ? OR (path >= ? AND path < ?))`

func deadPropTreeArgs(name string) (string, string, string) {
	base := strings.TrimSuffix(name, "/")
	return name, base + "/", base + "0"
}

// deadPropScope returns the condition and arguments for name alone or for name
// and everything below it.
func deadPropScope(owner, name string, zeroDepth bool) (string, []any) {
	if zeroDepth {
		return `username = ? AND path = ?`, []any{owner, name}
	}
	self, lo, hi := deadPropTreeArgs(name)
	return `username = ? AND ` + deadPropTreeSQL, []any{owner, self, lo, hi}
}

// loadDeadProps returns the properties of name, and with zeroDepth false of
// everything below it, by path and sorted by name.
func loadDeadProps(owner, name string, zeroDepth bool) (map[string][]deadProp, error) {
	where, args := deadPropScope(owner, name, zeroDepth)
	rows, err := db.Query(`SELECT path, namespace, name, lang, value FROM dead_props WHERE `+where+
		` ORDER BY path, namespace, name`, args...)
	if err != nil {
		return nil, fmt.Errorf("load dead properties of %q: %w", name, err)
	}
	defer rows.Close()
	found := map[string][]deadProp{}
	for rows.Next() {
		var p string
		var dp deadProp
		if err := rows.Scan(&p, &dp.Name.Space, &dp.Name.Local, &dp.Lang, &dp.Value); err != nil {
			return nil, fmt.Errorf("read dead properties of %q: %w", name, err)
		}
		found[p] = append(found[p], dp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read dead properties of %q: %w", name, err)
	}
	return found, nil
}

// deadPropsSize sums the sizes of the properties of name, and with zeroDepth
// false of everything below it.
func deadPropsSize(owner, name string, zeroDepth bool) (int64, error) {
	where, args := deadPropScope(owner, name, zeroDepth)
	var n int64
	if err := db.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM dead_props WHERE `+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("sum dead properties of %q: %w", name, err)
	}
	return n, nil
}

// deadPropsTotals returns the size of all dead properties per user.
func deadPropsTotals() (map[string]int64, error) {
	rows, err := db.Query(`SELECT username, SUM(size) FROM dead_props GROUP BY username`)
	if err != nil {
		return nil, fmt.Errorf("query dead property totals: %w", err)
	}
	defer rows.Close()
	totals := map[string]int64{}
	for rows.Next() {
		var user string
		var n int64
		if err := rows.Scan(&user, &n); err != nil {
			return nil, fmt.Errorf("read dead property totals: %w", err)
		}
		totals[user] = n
	}
	return totals, rows.Err()
}

func insertDeadProp(exec func(string, ...any) error, owner, name string, p deadProp) error {
	return exec(`INSERT INTO dead_props (username, path, namespace, name, lang, value, size) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		owner, name, p.Name.Space, p.Name.Local, p.Lang, p.Value, p.size())
}

// deleteDeadPropsTree removes name and everything below it and returns the bytes
// freed, all in one transaction.
func deleteDeadPropsTree(owner, name string) (int64, error) {
	where, args := deadPropScope(owner, name, false)
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin dead property delete: %w", err)
	}
	defer tx.Rollback()
	var freed int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM dead_props WHERE `+where, args...).Scan(&freed); err != nil {
		return 0, fmt.Errorf("sum dead properties of %q: %w", name, err)
	}
	if _, err := tx.Exec(`DELETE FROM dead_props WHERE `+where, args...); err != nil {
		return 0, fmt.Errorf("delete dead properties of %q: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit dead property delete: %w", err)
	}
	return freed, nil
}

// removeDeadProps removes the entries of a deleted resource and returns the bytes
// freed. The file operation has already succeeded, so a failure is only logged:
// prune-props removes what is left once the path is gone.
func removeDeadProps(owner, name string) int64 {
	freed, err := deleteDeadPropsTree(owner, name)
	if err != nil {
		logger.Error("cannot remove dead properties", "user", owner, "path", name, "err", err)
	}
	return freed
}

// relocateDeadProps follows a successful COPY or MOVE: the entries of an
// overwritten destination go, those of the source are written at the destination,
// and MOVE removes the source's. It returns the change in bytes. The rows are read
// first, because source and destination may lie inside each other. A failure is
// only logged, as in removeDeadProps.
func relocateDeadProps(owner, src, dst string, zeroDepth, move bool) int64 {
	delta, err := relocateDeadPropsTx(owner, src, dst, zeroDepth, move)
	if err != nil {
		logger.Error("cannot relocate dead properties", "user", owner, "source", src, "destination", dst, "err", err)
	}
	return delta
}

func relocateDeadPropsTx(owner, src, dst string, zeroDepth, move bool) (int64, error) {
	rows, err := loadDeadProps(owner, src, zeroDepth)
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin dead property relocation: %w", err)
	}
	defer tx.Rollback()
	where, args := deadPropScope(owner, dst, false)
	var freed int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM dead_props WHERE `+where, args...).Scan(&freed); err != nil {
		return 0, fmt.Errorf("sum dead properties of %q: %w", dst, err)
	}
	if _, err := tx.Exec(`DELETE FROM dead_props WHERE `+where, args...); err != nil {
		return 0, fmt.Errorf("delete dead properties of %q: %w", dst, err)
	}
	if move {
		where, args := deadPropScope(owner, src, false)
		if _, err := tx.Exec(`DELETE FROM dead_props WHERE `+where, args...); err != nil {
			return 0, fmt.Errorf("delete dead properties of %q: %w", src, err)
		}
	}
	exec := func(query string, args ...any) error {
		_, err := tx.Exec(query, args...)
		return err
	}
	srcBase, dstBase := strings.TrimSuffix(src, "/"), strings.TrimSuffix(dst, "/")
	var added int64
	for p, props := range rows {
		target := dst
		if p != src {
			target = dstBase + strings.TrimPrefix(p, srcBase)
		}
		for _, dp := range props {
			if err := insertDeadProp(exec, owner, target, dp); err != nil {
				return 0, fmt.Errorf("write dead property of %q: %w", target, err)
			}
			added += dp.size()
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit dead property relocation: %w", err)
	}
	if move {
		return -freed, nil
	}
	return added - freed, nil
}

// pruneDeadProps deletes the entries at or below name whose path no longer exists
// in the owner's data root. It returns how many paths went and the bytes freed.
func pruneDeadProps(owner, name string) (paths, freed int64, err error) {
	where, args := deadPropScope(owner, name, false)
	rows, err := db.Query(`SELECT DISTINCT path FROM dead_props WHERE `+where, args...)
	if err != nil {
		return 0, 0, fmt.Errorf("list dead property paths: %w", err)
	}
	var gone []string
	root := userDataRoot(owner)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("read dead property path: %w", err)
		}
		// Lstat, because a dangling symlink still is an entry of its directory.
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(p))); errors.Is(err, fs.ErrNotExist) {
			gone = append(gone, p)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, 0, fmt.Errorf("read dead property paths: %w", err)
	}
	if len(gone) == 0 {
		return 0, 0, nil
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, 0, fmt.Errorf("begin dead property prune: %w", err)
	}
	defer tx.Rollback()
	for _, p := range gone {
		var n int64
		if err := tx.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM dead_props WHERE username = ? AND path = ?`, owner, p).Scan(&n); err != nil {
			return 0, 0, fmt.Errorf("sum dead properties of %q: %w", p, err)
		}
		if _, err := tx.Exec(`DELETE FROM dead_props WHERE username = ? AND path = ?`, owner, p); err != nil {
			return 0, 0, fmt.Errorf("delete dead properties of %q: %w", p, err)
		}
		freed += n
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit dead property prune: %w", err)
	}
	return int64(len(gone)), freed, nil
}

// pruneGoneDeadProps follows a failed DELETE, COPY or MOVE, which may have removed
// part of a tree. It returns the bytes freed and only logs a failure, as in
// removeDeadProps.
func pruneGoneDeadProps(owner string, names ...string) int64 {
	var total int64
	for _, name := range names {
		_, freed, err := pruneDeadProps(owner, name)
		if err != nil {
			logger.Error("cannot prune dead properties", "user", owner, "path", name, "err", err)
		}
		total += freed
	}
	return total
}

// ---- PROPPATCH (RFC 4918 §9.2) -----------------------------------------------

// propPatchOp is one property of a set or remove instruction.
type propPatchOp struct {
	prop   deadProp
	remove bool
}

// servePropPatch handles PROPPATCH on the resource at absPath, which the owner
// path name identifies. The caller holds the path lock and has passed the lock
// check. §9.2: instructions apply in document order and all or none of them do,
// so everything is decided on a copy and written in one transaction.
//
// The body is read before enterPropPatch, so a slow client cannot hold up a
// DELETE, COPY or MOVE of an ancestor. The resource may be gone once the wait is
// over, so it is checked again: an entry for a missing path must not be written.
func servePropPatch(w http.ResponseWriter, r *http.Request, owner, name, absPath string) {
	if _, ok := statPropPatchTarget(w, r, absPath); !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "cannot read request body", http.StatusBadRequest)
		}
		return
	}
	ops, err := parsePropertyUpdate(body)
	if err != nil {
		logger.Debug("PROPPATCH body rejected", "path", r.URL.Path, "reason", err)
		http.Error(w, "invalid PROPPATCH body", http.StatusBadRequest)
		return
	}
	defer userLocks(owner).enterPropPatch(name)()
	fi, ok := statPropPatchTarget(w, r, absPath)
	if !ok {
		return
	}
	href := path.Clean(r.URL.Path)
	if fi.IsDir() && href != "/" {
		href += "/"
	}
	if slices.ContainsFunc(ops, func(op propPatchOp) bool { return isProtectedProp(op.prop.Name) }) {
		writePropPatchFailure(w, href, ops, func(op propPatchOp) bool { return isProtectedProp(op.prop.Name) },
			"403 Forbidden", "<d:error><d:cannot-modify-protected-property/></d:error>")
		return
	}

	stored, err := loadDeadProps(owner, name, true)
	if err != nil {
		serviceUnavailable(w, r, "dead property lookup failed", err)
		return
	}
	next := map[xml.Name]deadProp{}
	storedSize := map[xml.Name]int64{}
	var oldSize, newSize int64
	for _, p := range stored[name] {
		next[p.Name] = p
		storedSize[p.Name] = p.size()
		oldSize += p.size()
	}
	for _, op := range ops {
		// §14.23: removing a property that does not exist is not an error.
		if op.remove {
			delete(next, op.prop.Name)
		} else {
			next[op.prop.Name] = op.prop
		}
	}
	for _, p := range next {
		newSize += p.size()
	}
	// §9.2.1: 507 goes to the properties that could not be stored, which are the
	// sets that would take more room than the property holds now. The total only
	// grows through such a set, so a refused request always names one. Only growth
	// is refused, so a lowered limit or a full quota never keeps a client from
	// removing properties.
	grows := func(op propPatchOp) bool { return !op.remove && op.prop.size() > storedSize[op.prop.Name] }
	if limit := conf().MaxDeadPropsSize; limit > 0 && newSize > limit && newSize > oldSize {
		logger.Warn("PROPPATCH rejected: dead property limit exceeded", "user", owner, "path", r.URL.Path,
			"size", newSize, "limit", limit, "client", remoteIP(r))
		writePropPatchFailure(w, href, ops, grows, "507 Insufficient Storage", "")
		return
	}
	delta := newSize - oldSize
	var reserved int64
	if delta > 0 {
		if err := reserveQuota(owner, delta); err != nil {
			if !errors.Is(err, errQuotaExceeded) {
				serviceUnavailable(w, r, "quota lookup failed", err)
				return
			}
			logQuotaExceeded(r, owner)
			writePropPatchFailure(w, href, ops, grows, "507 Insufficient Storage", "<d:error><d:quota-not-exceeded/></d:error>")
			return
		}
		reserved = delta
	}
	if err := storeDeadProps(owner, name, next); err != nil {
		settleQuota(owner, reserved, 0)
		logger.Error("cannot store dead properties", "user", owner, "path", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	settleQuota(owner, reserved, delta)

	names := make([]xml.Name, 0, len(ops))
	for _, op := range ops {
		if !slices.Contains(names, op.prop.Name) {
			names = append(names, op.prop.Name)
		}
	}
	var b strings.Builder
	writePropPatchStat(&b, names, "200 OK", "")
	writePropPatchResponse(w, href, b.String())
}

// storeDeadProps replaces the entries of name with props. A resource without
// properties keeps no row.
func storeDeadProps(owner, name string, props map[xml.Name]deadProp) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin dead property write: %w", err)
	}
	defer tx.Rollback()
	exec := func(query string, args ...any) error {
		_, err := tx.Exec(query, args...)
		return err
	}
	if err := exec(`DELETE FROM dead_props WHERE username = ? AND path = ?`, owner, name); err != nil {
		return fmt.Errorf("clear dead properties: %w", err)
	}
	for _, p := range props {
		if err := insertDeadProp(exec, owner, name, p); err != nil {
			return fmt.Errorf("write dead property: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dead property write: %w", err)
	}
	return nil
}

// statPropPatchTarget returns the resource's file info, or answers the request
// and returns false.
func statPropPatchTarget(w http.ResponseWriter, r *http.Request, absPath string) (os.FileInfo, bool) {
	fi, err := os.Stat(absPath)
	if err == nil {
		return fi, true
	}
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return nil, false
	}
	logger.Error("cannot stat PROPPATCH target", "path", absPath, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
	return nil, false
}

// writePropPatchFailure answers a request that changed nothing (§9.2.1). The
// properties of the instructions failed selects get status with extra in their
// propstat. Since nothing is applied, every other one gets 424. A property named
// by several instructions is listed once, under the failure if one of them failed.
func writePropPatchFailure(w http.ResponseWriter, href string, ops []propPatchOp, failed func(propPatchOp) bool, status, extra string) {
	var failing, others []xml.Name
	for _, op := range ops {
		if failed(op) && !slices.Contains(failing, op.prop.Name) {
			failing = append(failing, op.prop.Name)
		}
	}
	for _, op := range ops {
		if n := op.prop.Name; !slices.Contains(failing, n) && !slices.Contains(others, n) {
			others = append(others, n)
		}
	}
	var b strings.Builder
	writePropPatchStat(&b, failing, status, extra)
	writePropPatchStat(&b, others, "424 Failed Dependency", "")
	writePropPatchResponse(w, href, b.String())
}

func writePropPatchStat(b *strings.Builder, names []xml.Name, status, extra string) {
	if len(names) == 0 {
		return
	}
	b.WriteString("<d:propstat><d:prop>")
	for _, n := range names {
		writeDeadPropName(b, n)
	}
	b.WriteString("</d:prop><d:status>HTTP/1.1 " + status + "</d:status>" + extra + "</d:propstat>")
}

func writePropPatchResponse(w http.ResponseWriter, href, propstats string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href>%s</d:response></d:multistatus>`,
		hrefXML(href), propstats)
}

// parsePropertyUpdate parses a PROPPATCH body (§14.19) as strictly as a PROPFIND
// body. Elements it does not know are ignored (§17). §14.19 requires at least one
// set or remove, and one that names no property has nothing to apply, so a body
// without any property is an error.
func parsePropertyUpdate(body []byte) ([]propPatchOp, error) {
	text, hasBOM, err := stripPropfindBOM(body)
	if err != nil {
		return nil, err
	}
	if err := checkPropertyUpdate(newXMLBodyDecoder(text, hasBOM)); err != nil {
		return nil, err
	}
	if err := checkPropfindPrefixes(newXMLBodyDecoder(text, hasBOM)); err != nil {
		return nil, err
	}
	ops, err := extractPropPatchOps(newXMLBodyDecoder(text, hasBOM))
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, errors.New("no property in <propertyupdate>")
	}
	return ops, nil
}

// checkPropertyUpdate checks that the body is well-formed and has the right root.
func checkPropertyUpdate(dec *xml.Decoder) error {
	depth, sawRoot := 0, false
	for {
		offset := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := checkPropfindAttrs(t.Attr); err != nil {
				return err
			}
			if depth == 0 {
				if sawRoot {
					return fmt.Errorf("second root element <%s>", t.Name.Local)
				}
				if t.Name.Space != davNamespace || t.Name.Local != "propertyupdate" {
					return fmt.Errorf("root element {%s}%s is not {DAV:}propertyupdate", t.Name.Space, t.Name.Local)
				}
				sawRoot = true
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(strings.Trim(string(t), " \t\r\n")) > 0 {
				return errors.New("text outside the root element")
			}
		case xml.ProcInst:
			if strings.EqualFold(t.Target, "xml") && offset != 0 {
				return errors.New("XML declaration not at the start of the body")
			}
		case xml.Directive:
			if sawRoot || depth > 0 {
				return errors.New("directive after the start of the root element")
			}
		}
	}
	if !sawRoot {
		return errors.New("no root element")
	}
	return nil
}

// extractPropPatchOps returns the instructions in document order. It works on raw
// tokens, because a value must keep its prefixes and Token replaces them. The
// caller has already checked the body.
func extractPropPatchOps(dec *xml.Decoder) ([]propPatchOp, error) {
	var (
		ops    []propPatchOp
		scopes []map[string]string
		langs  []string
		remove bool
		inSet  bool // inside a DAV:set or DAV:remove
		inProp bool // inside the DAV:prop of one
	)
	lookup := func(prefix string) string {
		if prefix == "xml" {
			return "http://www.w3.org/XML/1998/namespace"
		}
		for i := len(scopes) - 1; i >= 0; i-- {
			if uri, ok := scopes[i][prefix]; ok {
				return uri
			}
		}
		return ""
	}
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			return ops, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			scope := map[string]string{}
			lang := ""
			if len(langs) > 0 {
				lang = langs[len(langs)-1]
			}
			for _, a := range t.Attr {
				switch {
				case a.Name.Space == "xmlns":
					scope[a.Name.Local] = a.Value
				case a.Name.Space == "" && a.Name.Local == "xmlns":
					scope[""] = a.Value
				case a.Name.Space == "xml" && a.Name.Local == "lang":
					lang = a.Value
				}
			}
			scopes = append(scopes, scope)
			langs = append(langs, lang)
			isDAV := lookup(t.Name.Space) == davNamespace
			switch len(scopes) {
			case 2:
				inSet = isDAV && (t.Name.Local == "set" || t.Name.Local == "remove")
				remove = t.Name.Local == "remove"
			case 3:
				inProp = inSet && isDAV && t.Name.Local == "prop"
			case 4:
				if !inProp {
					break
				}
				value, err := readPropValue(dec, lookup)
				if err != nil {
					return nil, err
				}
				prop := deadProp{Name: xml.Name{Space: lookup(t.Name.Space), Local: t.Name.Local}, Lang: lang, Value: value}
				ops = append(ops, propPatchOp{prop: prop, remove: remove})
				// The end tag went with the value.
				scopes, langs = scopes[:len(scopes)-1], langs[:len(langs)-1]
			}
		case xml.EndElement:
			scopes, langs = scopes[:len(scopes)-1], langs[:len(langs)-1]
		}
	}
}

// readPropValue reads the content of a property element up to and including its
// end tag. §4.3 and §4.4 ask for the value to survive with its namespaces and its
// mixed content, so each child is written self-contained.
func readPropValue(dec *xml.Decoder, lookup func(string) string) (string, error) {
	var b strings.Builder
	for {
		tok, err := dec.RawToken()
		if err != nil {
			return "", fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			el, err := serializeElement(dec, t, lookup)
			if err != nil {
				return "", err
			}
			b.WriteString(el)
		case xml.EndElement:
			return b.String(), nil
		case xml.CharData:
			if err := xml.EscapeText(&b, t); err != nil {
				return "", fmt.Errorf("escape property value: %w", err)
			}
		case xml.Comment:
			b.WriteString("<!--" + string(t) + "-->")
		case xml.ProcInst:
			b.WriteString("<?" + t.Target + " " + string(t.Inst) + "?>")
		}
	}
}

// ---- prune-props command -----------------------------------------------------

// runPruneProps implements "webdavgo prune-props [directory]". Files removed
// outside webdavgo leave their entries behind, which keep counting toward the
// owner's quota. The running service keeps usage in memory, which this process
// cannot reach, so it bumps the usage epoch, as reset-totp does for sessions. It
// returns the process exit code.
func runPruneProps(args []string) int {
	if len(args) > 1 {
		logger.Error("usage: webdavgo prune-props [-config file] [-data-dir dir] [directory]")
		return 2
	}
	owner, name := "", "/"
	if len(args) == 1 {
		var err error
		if owner, name, err = prunePropsTarget(args[0]); err != nil {
			logger.Error("invalid directory", "directory", args[0], "err", err)
			return 2
		}
	}
	if code, done := reexecAsServiceUser(); done {
		return code
	}
	dbPath := filepath.Join(conf().DataDir, "webdavgo.db")
	// sql.Open would silently create an empty database under a wrong data_dir.
	if _, err := os.Stat(dbPath); err != nil {
		logger.Error("cannot open database", "path", dbPath, "err", err)
		return 1
	}
	if err := openDBNoMigrate(dbPath); err != nil {
		logger.Error("cannot open database", "path", dbPath, "err", err)
		return 1
	}
	defer db.Close()
	owners := []string{owner}
	if owner == "" {
		totals, err := deadPropsTotals()
		if err != nil {
			logger.Error("prune-props failed", "err", err)
			return 1
		}
		owners = slices.Sorted(maps.Keys(totals))
	}
	var paths, freed int64
	for _, u := range owners {
		p, f, err := pruneDeadProps(u, name)
		if err != nil {
			logger.Error("prune-props failed", "user", u, "err", err)
			return 1
		}
		settleQuota(u, 0, -f)
		paths += p
		freed += f
	}
	if freed > 0 {
		if err := bumpUsageEpoch(); err != nil {
			logger.Error("prune-props: the running service keeps the old usage until its next restart", "err", err)
			return 1
		}
	}
	logger.Info("dead properties pruned", "users", len(owners), "paths", paths, "bytes", freed)
	return 0
}

// prunePropsTarget splits a directory into its owner and owner path. It need not
// exist any more, since a removed directory is what the command is for. A relative
// path starts at data_dir/users, the first segment being the user.
func prunePropsTarget(dir string) (owner, name string, err error) {
	root, err := filepath.Abs(filepath.Join(conf().DataDir, "users"))
	if err != nil {
		return "", "", fmt.Errorf("resolve data directory: %w", err)
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	rel, err := filepath.Rel(root, filepath.Clean(dir))
	if err != nil {
		return "", "", fmt.Errorf("resolve directory: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("not below %s", root)
	}
	if rel == "." {
		return "", "/", nil
	}
	owner, sub, _ := strings.Cut(filepath.ToSlash(rel), "/")
	return owner, "/" + sub, nil
}
