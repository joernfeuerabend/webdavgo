// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// props.go – shared property resolution for PROPFIND and SEARCH responses.
// Both handlers build their 207 Multi-Status bodies through the helpers here
// so property values (and in particular getetag and getlastmodified) cannot
// drift apart between the two.

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
