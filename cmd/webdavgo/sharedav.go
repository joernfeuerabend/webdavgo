// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// sharedav.go – /s/{share_id}/... routing, ShareAuth, per-share WebDAV handler,
// method gate, and MOVE/COPY destination scope validation.
//
// Recipient authentication uses Basic Auth where the username is the recipient's
// email and the password is the raw share token ("shr_tok_<64hex>"). This is
// intentionally separate from the owner/user auth in users.go.

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/webdav"
)

// handleShareRequest is the dispatcher for all /s/{share_id}/... requests.
// It authenticates the recipient, then delegates to serveShare. rl receives
// the authentication outcome for the request log line.
func handleShareRequest(w http.ResponseWriter, r *http.Request, rl *requestLog) {
	// Extract share_id: the segment between "/s/" and the next "/".
	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	slash := strings.IndexByte(rest, '/')
	var shareID string
	if slash < 0 {
		shareID = rest
	} else {
		shareID = rest[:slash]
	}

	// Missing or empty share_id is treated the same as a wrong-credentials
	// response to avoid leaking whether share IDs are valid.
	if shareID == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="webdavgo-share"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	claimedEmail, rawToken, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="webdavgo-share"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Always fetch the share before comparing credentials so timing is
	// consistent whether the ID exists or not.
	authStart := time.Now()
	share, err := getShareByID(shareID)
	rl.authDone("token", authStart)
	if err != nil {
		serviceUnavailable(w, r, "share lookup failed", fmt.Errorf("share %s: %w", shareID, err))
		return
	}
	// On miss: 401 — do not distinguish "no such share" from "wrong credentials"
	// to prevent share-ID enumeration.
	if share == nil {
		// Both values are the client's own strings here, of any length.
		logger.Warn("share auth failure", "share_id", truncateKey(shareID),
			"claimed_email", truncateKey(claimedEmail), "client", remoteIP(r))
		shareAuthFailed(w, r)
		return
	}

	// The token check is cheap and the token has 256 bits, so a correct one
	// passes even while the client is locked out (see bruteforce.go).
	if strings.ToLower(claimedEmail) != share.RecipientEmail ||
		shareTokenHash(rawToken) != share.TokenHash {
		logger.Warn("share auth failure", "share_id", truncateKey(shareID),
			"claimed_email", truncateKey(claimedEmail), "client", remoteIP(r))
		shareAuthFailed(w, r)
		return
	}

	if share.ExpiresAt != "" {
		exp, parseErr := time.Parse(time.RFC3339, share.ExpiresAt)
		if parseErr == nil && !time.Now().Before(exp) {
			logger.Warn("share token expired", "share_id", truncateKey(shareID), "client", remoteIP(r))
			stats.shareExpired()
			w.Header().Set("WWW-Authenticate", `Basic realm="webdavgo-share"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	rl.shareID = shareID
	noteIdentity(r, "share "+shareID)
	stats.shareActive(shareID)

	// Auth passed — async-update last_used_at (fire-and-forget).
	go touchShare(shareID)

	shareRoot := filepath.Join(userDataRoot(share.OwnerUsername), filepath.FromSlash(share.Path))
	serveShare(w, r, share, shareRoot)
}

// shareAuthFailed answers wrong share credentials. The failure counts toward
// the client's lockout. During a lockout the answer is 429 instead of 401, so
// a share client on a NAT address shared with an attacker never receives the
// revocation signal.
func shareAuthFailed(w http.ResponseWriter, r *http.Request) {
	ip := clientKey(r)
	if locked, wait := limiter.ipLocked(ip); locked {
		logAuthRefused(r, authSrcShare, "", "client", wait)
		tooManyAttempts(w, wait)
		return
	}
	stats.authFailed(r, failShare, "")
	limiter.fail(ip, "", authSrcShare)
	w.Header().Set("WWW-Authenticate", `Basic realm="webdavgo-share"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// serveShare applies the method gate and delegates to the appropriate handler.
// shareRoot is the filesystem path corresponding to the share's root directory.
func serveShare(w http.ResponseWriter, r *http.Request, share *Share, shareRoot string) {
	method := r.Method
	sharePrefix := "/s/" + share.ID

	// LOCK and UNLOCK are always rejected: recipients only ever run into the
	// owner's locks, they cannot create, refresh or remove any.
	if method == "LOCK" || method == "UNLOCK" {
		http.Error(w, "not implemented", http.StatusNotImplemented)
		return
	}

	if requestTouchesReserved(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Write methods require read-write permission.
	if isShareWriteMethod(method) && share.Permission == "read" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Validate Destination for MOVE/COPY before calling the webdav handler.
	if method == "MOVE" || method == "COPY" {
		if err := validateShareDestination(r, share, shareRoot); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	// Compute the sub-path within the share by stripping the share prefix.
	stripped := strings.TrimPrefix(r.URL.Path, sharePrefix)
	if stripped == "" {
		stripped = "/"
	}
	subPath := path.Clean(stripped)
	if !strings.HasPrefix(subPath, "/") {
		subPath = "/"
	}

	// Defence-in-depth: the resolved server path must remain within shareRoot.
	relSub := strings.TrimLeft(subPath, "/")
	absPath := filepath.Clean(filepath.Join(shareRoot, relSub))
	shareRootClean := filepath.Clean(shareRoot)
	if absPath != shareRootClean && !strings.HasPrefix(absPath, shareRootClean+string(filepath.Separator)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch method {
	case "SEARCH":
		r2 := r.Clone(r.Context())
		r2.URL.Path = subPath
		handleSearch(w, r2, shareRoot, sharePrefix)
	case "PROPFIND":
		r2 := r.Clone(r.Context())
		r2.URL.Path = subPath
		handlePropfind(w, r2, shareRoot, sharePrefix, share.OwnerUsername, nil)
	default:
		h := &webdav.Handler{
			Prefix:     sharePrefix,
			FileSystem: davFS{webdav.Dir(shareRoot)},
			LockSystem: shareLocks{owner: userLocks(share.OwnerUsername).temporary(), root: share.Path},
			Logger: func(req *http.Request, err error) {
				if err != nil {
					status := davStatus(req)
					logger.Log(req.Context(), davErrorLevel(status, err), "share webdav error",
						"share_id", share.ID, "method", req.Method,
						"path", req.URL.Path, "status", status, "err", err)
				}
			},
		}
		// Writes through a share are charged to the owner; recipients have
		// no quota of their own.
		serveDAV(w, r, h, absPath, share.OwnerUsername)
		// A share has no locking, so it is not class 2 (RFC 4918 §18.2). x/net
		// always sends "1, 2" and writes nothing for OPTIONS, so the header
		// can still be replaced here.
		if method == http.MethodOptions {
			w.Header().Set("DAV", "1")
		}
	}
}

// isShareWriteMethod reports whether the HTTP method modifies state.
func isShareWriteMethod(method string) bool {
	switch method {
	case "PUT", "DELETE", "MKCOL", "MOVE", "COPY":
		return true
	}
	return false
}

// validateShareDestination checks that the Destination header (for MOVE/COPY)
// starts with the current share's URL prefix and does not escape shareRoot.
func validateShareDestination(r *http.Request, share *Share, shareRoot string) error {
	dst := r.Header.Get("Destination")
	if dst == "" {
		// Missing Destination will be caught by the webdav handler.
		return nil
	}

	dstURL, err := url.Parse(dst)
	if err != nil {
		return fmt.Errorf("invalid Destination URL: %w", err)
	}

	dstPath := path.Clean(dstURL.Path)
	sharePrefix := "/s/" + share.ID

	if dstPath != sharePrefix && !strings.HasPrefix(dstPath, sharePrefix+"/") {
		return fmt.Errorf("destination outside share scope")
	}

	// Defence-in-depth: resolved filesystem path must stay inside shareRoot.
	rel := strings.TrimLeft(strings.TrimPrefix(dstPath, sharePrefix), "/")
	absPath := filepath.Clean(filepath.Join(shareRoot, rel))
	shareRootClean := filepath.Clean(shareRoot)
	if absPath != shareRootClean && !strings.HasPrefix(absPath, shareRootClean+string(filepath.Separator)) {
		return fmt.Errorf("destination escapes share root")
	}
	return nil
}
