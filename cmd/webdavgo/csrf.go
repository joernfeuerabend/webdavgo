// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// csrf.go – cross-site request protection and security headers for the
// admin listener.
//
// Three independent layers, because each one alone has gaps:
//   - SameSite=Strict on the session cookie keeps it off cross-site requests
//     in current browsers.
//   - A per-session token on every POST covers browsers and situations where
//     SameSite does not apply (e.g. a sibling subdomain counts as same-site).
//   - The Origin check also covers the POSTs that have no session yet
//     (login, setup), where a token cannot exist.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

const (
	csrfField  = "csrf_token"
	csrfHeader = "X-CSRF-Token"

	// No inline script or style anywhere: an injected <script> or event
	// attribute then has no effect even if escaping fails somewhere. data:
	// images are needed for the inline TOTP QR code.
	adminCSP = "default-src 'self'; img-src 'self' data:; object-src 'none'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

func newCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// setAdminHeaders sets the headers every admin response carries.
func setAdminHeaders(h http.Header) {
	h.Set("Content-Security-Policy", adminCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	// same-origin rather than no-referrer: browsers then send a real Origin
	// on the admin UI's own POSTs, while no URL leaks to other sites.
	h.Set("Referrer-Policy", "same-origin")
}

// validCSRF reports whether r carries the session's token, as the header
// HTMX sends or as the hidden form field of a plain form. Either one is
// enough: both are bound to the session, and a boosted page can keep the
// header of an older session in its <body> attributes while the form field
// is always rendered fresh. If the check fails, reason says why, for the log.
func validCSRF(r *http.Request, token string) (ok bool, reason string) {
	if token == "" {
		return false, "session has no token"
	}
	header := r.Header.Get(csrfHeader)
	if header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(token)) == 1 {
		return true, ""
	}
	form := r.PostFormValue(csrfField)
	if form != "" && subtle.ConstantTimeCompare([]byte(form), []byte(token)) == 1 {
		return true, ""
	}
	switch {
	case header == "" && form == "":
		return false, "no token"
	case header != "" && form != "":
		return false, "header and form token wrong"
	case header != "":
		return false, "header token wrong"
	default:
		return false, "form token wrong"
	}
}

// sameOrigin reports whether a state-changing request was sent by a page of
// this listener. Some browsers and privacy settings still send
// "Origin: null" and no Referer for same-origin form posts despite
// Referrer-Policy: same-origin, so for that case Sec-Fetch-Site decides. A request with none of the three headers
// cannot come from a current browser and therefore cannot be a cross-site
// forgery; it is let through (the CSRF token still applies).
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin != "" && origin != "null" {
		return urlMatchesHost(origin, r.Host)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return urlMatchesHost(ref, r.Host)
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "":
		// An explicit opaque origin without fetch metadata may be a
		// sandboxed frame in an older browser.
		return origin == ""
	default:
		return false
	}
}

func urlMatchesHost(raw, host string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.EqualFold(u.Host, host)
}
