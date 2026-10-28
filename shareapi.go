// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// shareapi.go – REST API handlers for /api/v1/shares.
// All endpoints require Basic Auth with the owner's username and password.
// The authenticated user becomes the owner for create operations, and can
// only read/delete their own shares.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// shareResponse is the public JSON shape for one share. Every read
// endpoint (list and detail) goes through toShareResponse so the two
// paths can never diverge.
type shareResponse struct {
	ShareID        string     `json:"share_id"`
	OwnerUsername  string     `json:"owner_username"`
	Path           string     `json:"path"`
	RecipientEmail string     `json:"recipient_email"`
	Permission     string     `json:"permission"`
	ShareURL       string     `json:"share_url"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

// toShareResponse converts a Share DB row into its public API form.
// Nullable timestamp fields become nil pointers so JSON emits null rather
// than the zero value.
func toShareResponse(s *Share) shareResponse {
	r := shareResponse{
		ShareID:        s.ID,
		OwnerUsername:  s.OwnerUsername,
		Path:           s.Path,
		RecipientEmail: s.RecipientEmail,
		Permission:     s.Permission,
		ShareURL:       "/s/" + s.ID + "/",
	}
	if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
		r.CreatedAt = t
	}
	if s.LastUsedAt != "" {
		if t, err := time.Parse(time.RFC3339, s.LastUsedAt); err == nil {
			r.LastUsedAt = &t
		}
	}
	if s.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, s.ExpiresAt); err == nil {
			r.ExpiresAt = &t
		}
	}
	return r
}

// handleAPIRequest is the entry-point for all /api/v1/... routes.
// It performs UserAuth before dispatching to the appropriate handler.
// rl receives the authentication outcome for the request log line.
func handleAPIRequest(w http.ResponseWriter, r *http.Request, rl *requestLog) {
	username, password, ok := r.BasicAuth()
	res := authBad
	if ok {
		authStart := time.Now()
		var method string
		var wait time.Duration
		var err error
		res, method, wait, err = authenticateUserLimited(r, username, password)
		rl.authDone(method, authStart)
		if err != nil {
			logger.Error("api auth lookup failed", "method", r.Method, "path", r.URL.Path, "err", err)
			w.Header().Set("Retry-After", "30")
			writeJSONError(w, "service temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if res == authThrottled {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
			writeJSONError(w, "too many failed logins, try again later", http.StatusTooManyRequests)
			return
		}
	}
	if res != authOK {
		w.Header().Set("WWW-Authenticate", `Basic realm="webdavgo"`)
		writeJSONError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rl.user = username
	noteIdentity(r, username)
	stats.userActive(username)

	p := r.URL.Path

	switch {
	case r.Method == http.MethodPost && p == "/api/v1/shares":
		apiShareCreate(w, r, username)
	case r.Method == http.MethodGet && p == "/api/v1/shares":
		apiShareList(w, r, username)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/api/v1/shares/"):
		id := strings.TrimPrefix(p, "/api/v1/shares/")
		if id == "" || strings.ContainsRune(id, '/') {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		apiShareGet(w, r, username, id)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/api/v1/shares/"):
		id := strings.TrimPrefix(p, "/api/v1/shares/")
		if id == "" || strings.ContainsRune(id, '/') {
			writeJSONError(w, "not found", http.StatusNotFound)
			return
		}
		apiShareDelete(w, r, username, id)
	default:
		writeJSONError(w, "not found", http.StatusNotFound)
	}
}

// writeJSONError writes a JSON {"error": msg} body with the given status code.
func writeJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// apiShareCreate handles POST /api/v1/shares.
func apiShareCreate(w http.ResponseWriter, r *http.Request, ownerUsername string) {
	var req struct {
		Path           string  `json:"path"`
		RecipientEmail string  `json:"recipient_email"`
		Permission     string  `json:"permission"`
		ExpiresAt      *string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isBodyTooLarge(err) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	share, rawToken, err := createShare(ownerUsername, req.Path, req.RecipientEmail, req.Permission, req.ExpiresAt)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		shareResponse
		AccessToken string `json:"access_token"`
	}{toShareResponse(share), rawToken})
}

// apiShareList handles GET /api/v1/shares.
func apiShareList(w http.ResponseWriter, r *http.Request, ownerUsername string) {
	shares, err := listSharesByOwner(ownerUsername)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := make([]shareResponse, 0, len(shares))
	for _, s := range shares {
		resp = append(resp, toShareResponse(s))
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

// apiShareGet handles GET /api/v1/shares/{share_id}.
func apiShareGet(w http.ResponseWriter, r *http.Request, ownerUsername, shareID string) {
	share, err := getShareByIDForOwner(shareID, ownerUsername)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if share == nil {
		writeJSONError(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(toShareResponse(share))
}

// apiShareDelete handles DELETE /api/v1/shares/{share_id}.
func apiShareDelete(w http.ResponseWriter, r *http.Request, ownerUsername, shareID string) {
	deleted, err := deleteShareForOwner(shareID, ownerUsername)
	if err != nil {
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !deleted {
		writeJSONError(w, "not found", http.StatusNotFound)
		return
	}
	logger.Info("share deleted via API", "share_id", shareID, "owner", ownerUsername)
	w.WriteHeader(http.StatusNoContent)
}
