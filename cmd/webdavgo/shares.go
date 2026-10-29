// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// shares.go – Share CRUD, validation, canonicalisation, and token generation.
// Each share gives one external recipient (identified by email) a scoped
// WebDAV view of a subtree of an owner's data. The raw share token is shown
// exactly once at creation time; only its sha256 hex hash is stored.

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// emailRE is the basic structural check used for recipient_email.
// Deliberate simplicity: more complex RFC 5322 validation is out of scope.
var emailRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Share holds one row from the shares table.
type Share struct {
	ID             string
	OwnerUsername  string
	Path           string
	RecipientEmail string
	Permission     string
	TokenHash      string
	CreatedAt      string
	LastUsedAt     string // empty string when NULL in DB
	ExpiresAt      string // empty string when NULL in DB
}

// generateShareID returns a new "shr_<16-hex>" identifier.
func generateShareID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "shr_" + hex.EncodeToString(b)
}

// generateShareToken returns a new "shr_tok_<64-hex>" raw token and its
// sha256 hex hash. The raw token is shown once and never stored.
func generateShareToken() (raw, hash string) {
	b := make([]byte, 32)
	rand.Read(b)
	raw = "shr_tok_" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return
}

// shareTokenHash returns hex(sha256(raw)) for a given raw share token.
func shareTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// canonicaliseSharePath cleans and validates a path submitted at share-create time.
// Rejects any input containing ".." before or after clean. Returns a canonical
// path with a leading slash and no trailing slash.
func canonicaliseSharePath(p string) (string, error) {
	// Reject ".." in the raw input before any cleaning.
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path must not contain '..'")
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	// Second guard after clean (should never trigger given the pre-check above,
	// but we keep it as defence-in-depth).
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("path traversal detected after clean")
	}
	return cleaned, nil
}

// validateSharePath verifies that cleanPath exists, is a directory, and lies
// within the owner's data root. Requires a pre-canonicalised path.
func validateSharePath(ownerUsername, cleanPath string) error {
	root := filepath.Clean(userDataRoot(ownerUsername))
	full := filepath.Clean(filepath.Join(root, filepath.FromSlash(cleanPath)))
	if full != root && !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return fmt.Errorf("path escapes user data root")
	}
	fi, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("path does not exist")
		}
		return fmt.Errorf("stat share path: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("path is not a directory")
	}
	return nil
}

// createShare validates all fields, generates a share ID and token, inserts a
// row, and returns the new Share together with the raw (unhashed) token.
// expiresAt may be nil (no expiry) or a pointer to an ISO 8601 string.
func createShare(ownerUsername, sharePath, recipientEmail, permission string, expiresAt *string) (*Share, string, error) {
	if permission != "read" && permission != "read-write" {
		return nil, "", fmt.Errorf("permission must be 'read' or 'read-write'")
	}

	cleanPath, err := canonicaliseSharePath(sharePath)
	if err != nil {
		return nil, "", fmt.Errorf("invalid path: %w", err)
	}

	if err := validateSharePath(ownerUsername, cleanPath); err != nil {
		return nil, "", err
	}

	email := strings.ToLower(strings.TrimSpace(recipientEmail))
	if !emailRE.MatchString(email) {
		return nil, "", fmt.Errorf("invalid recipient_email")
	}

	var expVal interface{}
	if expiresAt != nil && *expiresAt != "" {
		t, parseErr := time.Parse(time.RFC3339, *expiresAt)
		if parseErr != nil {
			return nil, "", fmt.Errorf("invalid expires_at: must be ISO 8601 (RFC 3339)")
		}
		if !t.After(time.Now()) {
			return nil, "", fmt.Errorf("expires_at must be in the future")
		}
		expVal = *expiresAt
	}

	id := generateShareID()
	rawToken, hash := generateShareToken()
	now := time.Now().UTC().Format(time.RFC3339)

	if _, err := db.Exec(`
		INSERT INTO shares (id, owner_username, path, recipient_email, permission, token_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ownerUsername, cleanPath, email, permission, hash, now, expVal,
	); err != nil {
		return nil, "", fmt.Errorf("insert share: %w", err)
	}

	logger.Info("share created", "share_id", id, "owner", ownerUsername, "path", cleanPath, "recipient", email)

	s := &Share{
		ID:             id,
		OwnerUsername:  ownerUsername,
		Path:           cleanPath,
		RecipientEmail: email,
		Permission:     permission,
		TokenHash:      hash,
		CreatedAt:      now,
	}
	if expVal != nil {
		s.ExpiresAt = *expiresAt
	}
	return s, rawToken, nil
}

// getShareByID fetches a share by its ID regardless of owner.
// Returns (nil, nil) when the ID is not found.
func getShareByID(id string) (*Share, error) {
	s := &Share{}
	var lastUsed, expires sql.NullString
	err := db.QueryRow(`
		SELECT id, owner_username, path, recipient_email, permission, token_hash,
		       created_at, last_used_at, expires_at
		FROM shares WHERE id = ?`, id,
	).Scan(&s.ID, &s.OwnerUsername, &s.Path, &s.RecipientEmail, &s.Permission,
		&s.TokenHash, &s.CreatedAt, &lastUsed, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query share by id: %w", err)
	}
	if lastUsed.Valid {
		s.LastUsedAt = lastUsed.String
	}
	if expires.Valid {
		s.ExpiresAt = expires.String
	}
	return s, nil
}

// getShareByIDForOwner fetches a share by ID only when it is owned by ownerUsername.
// Returns (nil, nil) when the share does not exist or belongs to a different user.
func getShareByIDForOwner(id, ownerUsername string) (*Share, error) {
	s := &Share{}
	var lastUsed, expires sql.NullString
	err := db.QueryRow(`
		SELECT id, owner_username, path, recipient_email, permission, token_hash,
		       created_at, last_used_at, expires_at
		FROM shares WHERE id = ? AND owner_username = ?`, id, ownerUsername,
	).Scan(&s.ID, &s.OwnerUsername, &s.Path, &s.RecipientEmail, &s.Permission,
		&s.TokenHash, &s.CreatedAt, &lastUsed, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query share for owner: %w", err)
	}
	if lastUsed.Valid {
		s.LastUsedAt = lastUsed.String
	}
	if expires.Valid {
		s.ExpiresAt = expires.String
	}
	return s, nil
}

// listSharesByOwner returns all shares whose owner_username matches, newest first.
func listSharesByOwner(ownerUsername string) ([]*Share, error) {
	rows, err := db.Query(`
		SELECT id, owner_username, path, recipient_email, permission,
		       created_at, last_used_at, expires_at
		FROM shares WHERE owner_username = ? ORDER BY created_at DESC`, ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}
	defer rows.Close()
	var out []*Share
	for rows.Next() {
		s := &Share{}
		var lastUsed, expires sql.NullString
		if err := rows.Scan(&s.ID, &s.OwnerUsername, &s.Path, &s.RecipientEmail, &s.Permission,
			&s.CreatedAt, &lastUsed, &expires); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			s.LastUsedAt = lastUsed.String
		}
		if expires.Valid {
			s.ExpiresAt = expires.String
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// listAllShares returns every share in the database, newest first (admin view).
func listAllShares() ([]*Share, error) {
	rows, err := db.Query(`
		SELECT id, owner_username, path, recipient_email, permission,
		       created_at, last_used_at, expires_at
		FROM shares ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all shares: %w", err)
	}
	defer rows.Close()
	var out []*Share
	for rows.Next() {
		s := &Share{}
		var lastUsed, expires sql.NullString
		if err := rows.Scan(&s.ID, &s.OwnerUsername, &s.Path, &s.RecipientEmail, &s.Permission,
			&s.CreatedAt, &lastUsed, &expires); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			s.LastUsedAt = lastUsed.String
		}
		if expires.Valid {
			s.ExpiresAt = expires.String
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// deleteShareForOwner deletes a share only if owned by ownerUsername.
// Returns (false, nil) when the share does not exist or belongs to another user.
func deleteShareForOwner(id, ownerUsername string) (bool, error) {
	res, err := db.Exec(`DELETE FROM shares WHERE id = ? AND owner_username = ?`, id, ownerUsername)
	if err != nil {
		return false, fmt.Errorf("delete share for owner: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// deleteShareAdmin deletes any share by ID regardless of owner (admin revoke).
func deleteShareAdmin(id string) (bool, error) {
	res, err := db.Exec(`DELETE FROM shares WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete share (admin): %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// touchShare records the current timestamp as last_used_at for the given share.
// Intended to be called asynchronously (fire-and-forget).
func touchShare(id string) {
	db.Exec(`UPDATE shares SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
}

// countShares returns the total number of share rows in the database.
func countShares() (int, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM shares`).Scan(&n)
	return n, err
}
