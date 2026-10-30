// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// propfind.go – WebDAV PROPFIND handler.
// golang.org/x/net/webdav does not expose creationdate; we handle PROPFIND
// ourselves so all standard properties including creationdate are returned.

import (
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
)

// propfindReq is the request body structure for PROPFIND.
type propfindReq struct {
	XMLName  xml.Name  `xml:"propfind"`
	Allprop  *struct{} `xml:"allprop"`
	Propname *struct{} `xml:"propname"`
	Prop     struct {
		Props []anyElem `xml:",any"`
	} `xml:"prop"`
}

// handlePropfind handles WebDAV PROPFIND requests, including the creationdate
// property not supported by golang.org/x/net/webdav.
// urlPrefix is prepended to every href in the multistatus response; pass ""
// for the normal user endpoint and "/s/{share_id}" for the share endpoint.
// owner is the user whose quota the RFC 4331 properties report; a share
// reports only quota-available-bytes. locks is the user's lock state, nil on
// a share, which must not expose the owner's locks to a recipient.
func handlePropfind(w http.ResponseWriter, r *http.Request, dataDir, urlPrefix, owner string, locks *lockTracker) {
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
	known, unknown, all, namesOnly := parsePropfindProps(body)
	// RFC 4918 §9.1: allprop includes the live properties of that document,
	// and these two are defined there. They stay out of allPropNames because
	// that list also serves SEARCH.
	l := lockProps{locks: locks, now: time.Now(), supported: all, discovery: all}
	unknown = slices.DeleteFunc(unknown, func(name string) bool {
		switch name {
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
	unknown = slices.DeleteFunc(unknown, func(name string) bool {
		if name == "quota-available-bytes" || name == "quota-used-bytes" && !isShare {
			q.names = append(q.names, name)
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

	var out strings.Builder

	switch depth {
	case "0":
		writePropfindEntry(&out, dataDir, absPath, fi, known, unknown, urlPrefix, q, l, namesOnly)
	case "1":
		writePropfindEntry(&out, dataDir, absPath, fi, known, unknown, urlPrefix, q, l, namesOnly)
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
				writePropfindEntry(&out, dataDir, childPath, childFI, known, unknown, urlPrefix, q, l, namesOnly)
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
			writePropfindEntry(&out, dataDir, walkPath, wfi, known, unknown, urlPrefix, q, l, namesOnly)
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
	locks                *lockTracker
	now                  time.Time
}

func writePropfindEntry(b *strings.Builder, dataDir, absPath string, fi os.FileInfo, known, unknown []string, urlPrefix string, q quotaProps, l lockProps, namesOnly bool) {
	fp := buildFileProps(dataDir, absPath, fi)
	// The lock name is relative to the user root, so taken before the prefix.
	lockName := fp.Href
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
		b.WriteString("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")
		return
	}
	// RFC 4331 §3, §4 define the properties for collections. A file reports
	// them as not found.
	if !fi.IsDir() && len(q.names) > 0 {
		unknown = append(slices.Clone(unknown), q.names...)
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
	b.WriteString("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>")
	writePropstatNotFound(b, unknown)
	b.WriteString("</d:response>")
}

// parsePropfindProps parses the PROPFIND body and returns the known/unknown
// property split. An empty or allprop body returns all known properties and
// sets all. A propname body does the same and also sets namesOnly.
func parsePropfindProps(body []byte) (known, unknown []string, all, namesOnly bool) {
	if len(body) == 0 {
		return allPropNames, nil, true, false
	}
	var pf propfindReq
	if err := xml.Unmarshal(body, &pf); err != nil {
		return allPropNames, nil, true, false
	}
	if pf.Allprop != nil || len(pf.Prop.Props) == 0 {
		return allPropNames, nil, true, pf.Allprop == nil && pf.Propname != nil
	}
	var requested []string
	for _, p := range pf.Prop.Props {
		requested = append(requested, p.XMLName.Local)
	}
	known, unknown = splitRequested(requested)
	return known, unknown, false, false
}
