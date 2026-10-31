// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// propfind.go – WebDAV PROPFIND handler.
// golang.org/x/net/webdav does not expose creationdate; we handle PROPFIND
// ourselves so all standard properties including creationdate are returned.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html/charset"
)

// handlePropfind handles WebDAV PROPFIND requests, including the creationdate
// property not supported by golang.org/x/net/webdav.
// urlPrefix is prepended to every href in the multistatus response; pass ""
// for the normal user endpoint and "/s/{share_id}" for the share endpoint.
// owner is the user whose quota the RFC 4331 properties report; a share
// reports only quota-available-bytes. locks is the user's lock state, nil on
// a share, which must not expose the owner's locks to a recipient.
func handlePropfind(w http.ResponseWriter, r *http.Request, dataDir, urlPrefix, owner string, locks *lockManager) {
	if locks != nil && !locks.checkRead(w, r, path.Clean("/"+r.URL.Path)) {
		return
	}
	// RFC 4918 §10.2: a missing Depth header means infinity.
	depth := strings.ToLower(strings.TrimSpace(r.Header.Get("Depth")))
	if depth == "" {
		depth = "infinity"
	}
	switch depth {
	case "0", "1":
	case "infinity":
		// A single infinite PROPFIND walks the whole tree and buffers the
		// response in memory, so it is opt-in (RFC 4918 §9.1 allows refusing).
		if !conf().AllowPropfindInfinity {
			writePropfindFiniteDepth(w)
			return
		}
	default:
		http.Error(w, "invalid Depth header", http.StatusBadRequest)
		return
	}

	// Resolve the requested path within the user's data root.
	cleanURL := path.Clean("/" + r.URL.Path)
	absPath := filepath.Join(dataDir, filepath.FromSlash(cleanURL))

	fi, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Parse request body to determine which properties to return.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isBodyTooLarge(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "cannot read request body", http.StatusBadRequest)
		}
		return
	}
	known, unknown, all, namesOnly, err := parsePropfindProps(body)
	if err != nil {
		logger.Debug("PROPFIND body rejected", "path", r.URL.Path, "reason", err)
		http.Error(w, "invalid PROPFIND body", http.StatusBadRequest)
		return
	}
	// RFC 4918 §9.1: allprop includes the live properties of that document,
	// and these two are defined there. They stay out of allPropNames because
	// that list also serves SEARCH.
	l := lockProps{locks: locks, now: time.Now(), supported: all, discovery: all}
	unknown = slices.DeleteFunc(unknown, func(name xml.Name) bool {
		if name.Space != davNamespace {
			return false
		}
		switch name.Local {
		case "supportedlock":
			l.supported = true
		case "lockdiscovery":
			l.discovery = true
		default:
			return false
		}
		return true
	})
	q := quotaProps{}
	// On a share, quota-used-bytes stays unknown (404): it is the owner's
	// account-wide usage, which is none of the recipient's business. The
	// available bytes are kept, so clients can still tell a full quota.
	isShare := urlPrefix != ""
	unknown = slices.DeleteFunc(unknown, func(name xml.Name) bool {
		if name.Space == davNamespace && (name.Local == "quota-available-bytes" || name.Local == "quota-used-bytes" && !isShare) {
			q.names = append(q.names, name.Local)
			return true
		}
		return false
	})
	if len(q.names) > 0 {
		if q.available, q.used, err = quotaStatus(owner); err != nil {
			serviceUnavailable(w, r, "quota lookup failed", err)
			return
		}
	}

	// A share reads the owner's entries, so the names start at the owner's root.
	dead := deadPropsView{all: all, root: userLocks(owner).nameOf(dataDir)}
	if all || len(unknown) > 0 || slices.Contains(known, "displayname") {
		dead.byPath, err = loadDeadProps(owner, path.Join(dead.root, cleanURL), depth == "0")
		if err != nil {
			serviceUnavailable(w, r, "dead property lookup failed", err)
			return
		}
	}

	var out strings.Builder

	switch depth {
	case "0":
		writePropfindEntry(&out, dataDir, absPath, fi, known, unknown, urlPrefix, q, l, dead, namesOnly)
	case "1":
		writePropfindEntry(&out, dataDir, absPath, fi, known, unknown, urlPrefix, q, l, dead, namesOnly)
		if fi.IsDir() {
			entries, _ := os.ReadDir(absPath)
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), tmpPrefix) {
					continue
				}
				childPath := filepath.Join(absPath, entry.Name())
				childFI, err := entry.Info()
				if err != nil {
					continue
				}
				writePropfindEntry(&out, dataDir, childPath, childFI, known, unknown, urlPrefix, q, l, dead, namesOnly)
			}
		}
	default: // infinity
		filepath.Walk(absPath, func(walkPath string, wfi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if strings.HasPrefix(wfi.Name(), tmpPrefix) {
				return nil
			}
			writePropfindEntry(&out, dataDir, walkPath, wfi, known, unknown, urlPrefix, q, l, dead, namesOnly)
			return nil
		})
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprintf(w,
		`<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">%s</d:multistatus>`,
		out.String(),
	)
}

// writePropfindFiniteDepth answers a refused Depth: infinity PROPFIND with
// the precondition code from RFC 4918 §9.1 so clients can retry with Depth 1.
func writePropfindFiniteDepth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><d:error xmlns:d="DAV:"><d:propfind-finite-depth/></d:error>`)
}

// quotaProps holds the RFC 4331 properties a PROPFIND asked for by name, and
// their values. They are never part of allprop (RFC 4331 §3, §4) and describe
// the owner's quota, so they are the same for every collection in a response.
type quotaProps struct {
	names           []string
	available, used int64
}

// lockProps holds which lock properties a PROPFIND asked for and the state to
// answer them from. locks is nil on a share, where both properties are empty.
type lockProps struct {
	supported, discovery bool
	locks                *lockManager
	now                  time.Time
}

func writePropfindEntry(b *strings.Builder, dataDir, absPath string, fi os.FileInfo, known []string, unknown []xml.Name, urlPrefix string, q quotaProps, l lockProps, dead deadPropsView, namesOnly bool) {
	fp := buildFileProps(dataDir, absPath, fi)
	// The lock name is relative to the user root, so taken before the prefix.
	lockName := fp.Href
	deadProps := dead.byPath[path.Join(dead.root, fp.Href)]
	// A stored displayname takes the place of the derived one, so it must not be
	// written a second time among the dead properties.
	if i := slices.IndexFunc(deadProps, isDisplayNameProp); i >= 0 {
		fp.setDisplayName(deadProps[i])
		deadProps = slices.Delete(slices.Clone(deadProps), i, i+1)
	}
	if urlPrefix != "" {
		fp.Href = urlPrefix + fp.Href
	}
	// RFC 4918 §9.1: propname lists the names of the properties the resource
	// has, without values.
	if namesOnly {
		b.WriteString("<d:response><d:href>" + hrefXML(fp.Href) + "</d:href><d:propstat><d:prop>")
		for _, name := range known {
			if _, ok := getPropValue(fp, name); ok {
				b.WriteString("<d:" + name + "/>")
			}
		}
		b.WriteString("<d:supportedlock/><d:lockdiscovery/>")
		// RFC 4331 §2: propname must list the quota properties, unlike
		// allprop. Only collections have them, and a share has no used bytes.
		if fi.IsDir() {
			b.WriteString("<d:quota-available-bytes/>")
			if urlPrefix == "" {
				b.WriteString("<d:quota-used-bytes/>")
			}
		}
		for _, p := range deadProps {
			writeDeadPropName(b, p.Name)
		}
		b.WriteString("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")
		return
	}
	b.WriteString("<d:response><d:href>" + hrefXML(fp.Href) + "</d:href><d:propstat><d:prop>")
	for _, name := range known {
		writePropElem(b, name, fp)
	}
	if fi.IsDir() {
		for _, name := range q.names {
			v := q.available
			if name == "quota-used-bytes" {
				v = q.used
			}
			fmt.Fprintf(b, "<d:%s>%d</d:%s>", name, v, name)
		}
	}
	if l.supported {
		writeSupportedLock(b, l.locks == nil)
	}
	if l.discovery {
		var active []activeLock
		if l.locks != nil {
			active = l.locks.locksOn(l.now, lockName)
		}
		writeLockDiscovery(b, active, l.now)
	}
	if dead.all {
		for _, p := range deadProps {
			writeDeadProp(b, p)
		}
	}
	var notFound []xml.Name
	for _, name := range unknown {
		i := slices.IndexFunc(deadProps, func(p deadProp) bool { return p.Name == name })
		switch {
		case i < 0:
			notFound = append(notFound, name)
		case !dead.all:
			writeDeadProp(b, deadProps[i])
		}
	}
	// RFC 4331 §3, §4 define the properties for collections. A file reports
	// them as not found.
	if !fi.IsDir() {
		for _, name := range q.names {
			notFound = append(notFound, xml.Name{Space: davNamespace, Local: name})
		}
	}
	b.WriteString("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>")
	writePropstatNotFoundNames(b, notFound)
	b.WriteString("</d:response>")
}

// parsePropfindProps parses the PROPFIND body and returns the known/unknown
// property split. An empty or allprop body returns all known properties and
// sets all. A propname body does the same and also sets namesOnly. A body that
// is not acceptable returns an error, which the caller answers with 400
// (RFC 4918 §8.2).
//
// The body is walked token by token because xml.Unmarshal stops at the end of
// the root element and skips what it has no field for, so it would miss
// trailing content and errors inside ignored elements.
func parsePropfindProps(body []byte) (known []string, unknown []xml.Name, all, namesOnly bool, err error) {
	text, hasBOM, err := stripPropfindBOM(body)
	if err != nil {
		return nil, nil, false, false, err
	}
	// RFC 4918 §9.1: an empty body is an allprop request. Whitespace alone
	// carries no request either, so it is treated the same.
	if len(bytes.Trim(text, " \t\r\n")) == 0 {
		return allPropNames, nil, true, false, nil
	}
	dec := newXMLBodyDecoder(text, hasBOM)
	var (
		depth           int
		sawRoot         bool
		form            string
		sawInclude      bool
		props, included []xml.Name
		collect         *[]xml.Name // receives the children of the current depth 1 element
	)
	for {
		offset := dec.InputOffset()
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, false, false, fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := checkPropfindAttrs(t.Attr); err != nil {
				return nil, nil, false, false, err
			}
			switch depth {
			case 0:
				if sawRoot {
					return nil, nil, false, false, fmt.Errorf("second root element <%s>", t.Name.Local)
				}
				if t.Name.Space != "DAV:" || t.Name.Local != "propfind" {
					return nil, nil, false, false, fmt.Errorf("root element {%s}%s is not {DAV:}propfind", t.Name.Space, t.Name.Local)
				}
				sawRoot = true
			case 1:
				collect = nil
				// Anything else is ignored as an extension (RFC 4918 §17).
				if t.Name.Space != "DAV:" {
					break
				}
				switch t.Name.Local {
				case "prop", "allprop", "propname":
					if form != "" {
						return nil, nil, false, false, fmt.Errorf("<%s> after <%s>", t.Name.Local, form)
					}
					form = t.Name.Local
					if form == "prop" {
						collect = &props
					}
				case "include":
					if sawInclude {
						return nil, nil, false, false, fmt.Errorf("second <include>")
					}
					sawInclude = true
					collect = &included
				}
			case 2:
				if collect != nil {
					*collect = append(*collect, t.Name)
				}
			}
			depth++
		case xml.EndElement:
			depth--
		case xml.CharData:
			// encoding/xml accepts text outside the root element.
			if depth == 0 && len(bytes.Trim(t, " \t\r\n")) > 0 {
				return nil, nil, false, false, fmt.Errorf("text outside the root element")
			}
		case xml.ProcInst:
			// encoding/xml accepts an XML declaration anywhere.
			if strings.EqualFold(t.Target, "xml") && offset != 0 {
				return nil, nil, false, false, fmt.Errorf("XML declaration not at the start of the body")
			}
		case xml.Directive:
			if sawRoot || depth > 0 {
				return nil, nil, false, false, fmt.Errorf("directive after the start of the root element")
			}
		}
	}
	if !sawRoot {
		return nil, nil, false, false, fmt.Errorf("no root element")
	}
	if err := checkPropfindPrefixes(newXMLBodyDecoder(text, hasBOM)); err != nil {
		return nil, nil, false, false, err
	}
	// RFC 4918 §17: element order is irrelevant, so include is only checked
	// once all siblings are known.
	if sawInclude && form != "allprop" {
		return nil, nil, false, false, fmt.Errorf("<include> without <allprop>")
	}
	switch form {
	case "prop":
		// An empty prop names no properties, so unlike a missing body it is
		// not allprop. Each response then carries an empty prop with 200 OK,
		// since RFC 4918 §14.24 requires at least one propstat.
		known, unknown = splitRequestedNames(props)
		return known, unknown, false, false, nil
	case "allprop":
		// RFC 4918 §9.1: include adds to allprop. Every known property is
		// already in allprop, so only the others are left to answer.
		_, unknown = splitRequestedNames(included)
		return allPropNames, unknown, true, false, nil
	case "propname":
		return allPropNames, nil, true, true, nil
	}
	return nil, nil, false, false, fmt.Errorf("none of <prop>, <allprop> or <propname> in <propfind>")
}

// newXMLBodyDecoder returns a decoder for a request body that went through
// stripPropfindBOM.
func newXMLBodyDecoder(text []byte, hasBOM bool) *xml.Decoder {
	d := xml.NewDecoder(bytes.NewReader(text))
	d.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		// The mark decided the encoding and text is already UTF-8, so a
		// declaration such as encoding="UTF-16" must not decode it again.
		if hasBOM {
			return input, nil
		}
		data, err := io.ReadAll(input)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}
		decoded, err := decodePropfindCharset(label, data)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(decoded), nil
	}
	return d
}

// stripPropfindBOM removes a byte order mark and returns the body as UTF-8 if
// there was one. The mark takes precedence over a declared encoding. Without a
// mark the body is returned unchanged, since a UTF-16 body cannot be read far
// enough to find its declaration.
func stripPropfindBOM(body []byte) (text []byte, hasBOM bool, err error) {
	switch {
	case bytes.HasPrefix(body, []byte("\xef\xbb\xbf")):
		return body[3:], true, nil
	case bytes.HasPrefix(body, []byte("\xff\xfe")):
		text, err = decodePropfindCharset("utf-16le", body[2:])
	case bytes.HasPrefix(body, []byte("\xfe\xff")):
		text, err = decodePropfindCharset("utf-16be", body[2:])
	default:
		return body, false, nil
	}
	return text, true, err
}

// decodePropfindCharset converts data to UTF-8. The decoders replace bytes they
// cannot decode with U+FFFD instead of failing, so that character counts as
// undecodable. A genuine U+FFFD in a non-UTF-8 body is rejected with it, which
// no property name needs.
func decodePropfindCharset(label string, data []byte) ([]byte, error) {
	enc, _ := charset.Lookup(label)
	if enc == nil {
		return nil, fmt.Errorf("unknown encoding %q", label)
	}
	text, err := enc.NewDecoder().Bytes(data)
	if err != nil {
		return nil, fmt.Errorf("decode %q: %w", label, err)
	}
	if bytes.ContainsRune(text, utf8.RuneError) {
		return nil, fmt.Errorf("bytes not valid in encoding %q", label)
	}
	return text, nil
}

// checkPropfindPrefixes rejects a prefix that is not in scope where it is used
// (XML Namespaces 1.0 §5). It needs raw tokens because Token leaves an unknown
// prefix in Name.Space, where it looks like a namespace of the same name. The
// caller has already checked that the tags balance.
func checkPropfindPrefixes(dec *xml.Decoder) error {
	declared := map[string]int{"xml": 1, "xmlns": 1}
	var scopes [][]string
	for {
		tok, err := dec.RawToken()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var scope []string
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" {
					declared[a.Name.Local]++
					scope = append(scope, a.Name.Local)
				}
			}
			scopes = append(scopes, scope)
			if t.Name.Space != "" && declared[t.Name.Space] == 0 {
				return fmt.Errorf("undeclared namespace prefix %q on element", t.Name.Space)
			}
			for _, a := range t.Attr {
				if a.Name.Space != "" && declared[a.Name.Space] == 0 {
					return fmt.Errorf("undeclared namespace prefix %q on attribute", a.Name.Space)
				}
			}
		case xml.EndElement:
			for _, prefix := range scopes[len(scopes)-1] {
				declared[prefix]--
			}
			scopes = scopes[:len(scopes)-1]
		}
	}
}

// checkPropfindAttrs rejects what encoding/xml lets pass in a start tag: a
// prefix bound to the empty string, which XML Namespaces 1.0 §3 forbids, and a
// repeated attribute, which XML 1.0 §3.1 and Namespaces 1.0 §6.3 forbid.
func checkPropfindAttrs(attrs []xml.Attr) error {
	seen := make(map[xml.Name]bool, len(attrs))
	for _, a := range attrs {
		if a.Name.Space == "xmlns" && a.Value == "" {
			return fmt.Errorf("namespace prefix %q bound to the empty string", a.Name.Local)
		}
		if seen[a.Name] {
			return fmt.Errorf("repeated attribute %q", a.Name.Local)
		}
		seen[a.Name] = true
	}
	return nil
}
