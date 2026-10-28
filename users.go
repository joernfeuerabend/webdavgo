// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// User holds the displayable fields from a users row.
type User struct {
	Username   string
	Role       string
	TOTP       bool  // admins only: enrolment confirmed
	QuotaBytes int64 // 0 = unlimited
	UsedBytes  int64
}

// UsageLabel is the Users page's storage column, e.g. "0.42 GB / 1 GB".
func (u User) UsageLabel() string {
	q := "unlimited"
	if u.QuotaBytes > 0 {
		q = u.QuotaGB() + " GB"
	}
	return formatGB(u.UsedBytes) + " / " + q
}

// QuotaGB is the quota in decimal gigabytes as the edit form shows it.
func (u User) QuotaGB() string {
	return strconv.FormatFloat(float64(u.QuotaBytes)/1e9, 'f', -1, 64)
}

// formatGB formats a byte count in decimal gigabytes, the unit of the quota.
func formatGB(n int64) string {
	return fmt.Sprintf("%.2f GB", float64(n)/1e9)
}

func userDataRoot(username string) string {
	return filepath.Join(conf().DataDir, "users", username)
}

// createUser adds a user with a storage quota in bytes (0 = unlimited).
func createUser(username, password, role string, quota int64) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin create user: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
		username, string(hash), role); err != nil {
		return fmt.Errorf("insert user %q: %w", username, err)
	}
	if _, err := tx.Exec(`INSERT INTO user_quota (username, quota_bytes) VALUES (?, ?)`,
		username, quota); err != nil {
		return fmt.Errorf("insert quota of %q: %w", username, err)
	}
	return tx.Commit()
}

// dummyHash is compared against for unknown usernames so that they take as
// long as a wrong password for a known user; otherwise the response time
// tells an attacker which usernames exist. It must use bcryptCost.
const dummyHash = "$2a$12$j8YBqbAukXpuHCmn6t.zjOp5PX0HQzFtKhFMeLeYjwzbYTwSWcQ/W"

// checkPassword reports whether username/password are valid. A non-nil
// error means the lookup itself failed and the answer is unknown; callers
// must not treat that as wrong credentials.
func checkPassword(username, password string) (bool, error) {
	var hash string
	err := db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up user %q: %w", username, err)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

// ---- authentication cache ----------------------------------------------------

// authCacheMaxEntries bounds memory use when many distinct users log in.
const authCacheMaxEntries = 10000

// authCache remembers successful user logins for a short time so that clients
// sending many small requests (Finder, sync apps) do not pay for bcrypt on
// every one of them. Entries hold an HMAC of the password under a random
// per-process key instead of the password, so the cache never reveals a
// password and its contents are worthless outside this process.
var authCache = newCredCache(0)

type credCache struct {
	mu      sync.Mutex
	key     []byte
	ttl     atomic.Int64 // nanoseconds; Apply on the Settings page changes it
	entries map[string]credEntry
	// epoch changes on every invalidation; a bcrypt check that started
	// before a password reset must not store the old password afterwards.
	epoch uint64
}

type credEntry struct {
	mac     []byte
	expires time.Time
	added   time.Time
}

// newCredCache returns a cache with the given TTL; a TTL of 0 disables it.
func newCredCache(ttl time.Duration) *credCache {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand does not fail on supported platforms; without a key
		// the cache must not run at all.
		ttl = 0
	}
	c := &credCache{key: key, entries: map[string]credEntry{}}
	c.ttl.Store(int64(ttl))
	return c
}

// setTTL applies a changed auth_cache_ttl. Entries stored under the old one
// are dropped, so none outlives the new TTL.
func (c *credCache) setTTL(ttl time.Duration) {
	if c.ttl.Swap(int64(ttl)) == int64(ttl) {
		return
	}
	c.mu.Lock()
	clear(c.entries)
	c.epoch++
	c.mu.Unlock()
}

func (c *credCache) mac(username, password string) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(username))
	m.Write([]byte{0})
	m.Write([]byte(password))
	return m.Sum(nil)
}

// lookup reports whether username/password matches a live entry, and returns
// the epoch to pass to store after a successful bcrypt check.
func (c *credCache) lookup(username, password string) (hit bool, epoch uint64) {
	if c.ttl.Load() <= 0 {
		return false, 0
	}
	sum := c.mac(username, password)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[username]
	if ok && time.Now().Before(e.expires) && hmac.Equal(e.mac, sum) {
		return true, c.epoch
	}
	return false, c.epoch
}

func (c *credCache) store(username, password string, epoch uint64) {
	ttl := time.Duration(c.ttl.Load())
	if ttl <= 0 {
		return
	}
	sum := c.mac(username, password)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch != c.epoch {
		return
	}
	if _, exists := c.entries[username]; !exists && len(c.entries) >= authCacheMaxEntries {
		c.evictLocked(now)
	}
	c.entries[username] = credEntry{mac: sum, expires: now.Add(ttl), added: now}
}

// evictLocked drops expired entries and, if that frees nothing, the oldest.
func (c *credCache) evictLocked(now time.Time) {
	var oldest string
	var oldestAt time.Time
	for u, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, u)
			continue
		}
		if oldest == "" || e.added.Before(oldestAt) {
			oldest, oldestAt = u, e.added
		}
	}
	if len(c.entries) >= authCacheMaxEntries && oldest != "" {
		delete(c.entries, oldest)
	}
}

func (c *credCache) invalidate(username string) {
	c.mu.Lock()
	delete(c.entries, username)
	c.epoch++
	c.mu.Unlock()
}

const userSelect = `SELECT u.username, u.role, COALESCE(t.enabled, 0),
		COALESCE(q.quota_bytes, ?), COALESCE(q.used_bytes, 0)
	FROM users u LEFT JOIN totp t ON t.username = u.username
	LEFT JOIN user_quota q ON q.username = u.username`

func listUsers() ([]User, error) {
	return queryUsers(userSelect+` ORDER BY u.username`, conf().DefaultQuota)
}

// listUsersPage returns at most limit users from offset on, sorted by
// username, whose username contains q (case-insensitive; "" matches all),
// and how many users match in total. instr instead of LIKE, because "_",
// allowed in usernames, would be a LIKE wildcard.
func listUsersPage(q string, offset, limit int) ([]User, int, error) {
	q = strings.ToLower(q)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE instr(lower(username), ?) > 0`, q).Scan(&total); err != nil {
		return nil, 0, err
	}
	users, err := queryUsers(userSelect+` WHERE instr(lower(u.username), ?) > 0 ORDER BY u.username LIMIT ? OFFSET ?`,
		conf().DefaultQuota, q, limit, offset)
	return users, total, err
}

// totalUsedBytes is the storage used by all users together.
func totalUsedBytes() (int64, error) {
	var n int64
	err := db.QueryRow(`SELECT COALESCE(SUM(used_bytes), 0) FROM user_quota`).Scan(&n)
	return n, err
}

func queryUsers(query string, args ...any) ([]User, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Role, &u.TOTP, &u.QuotaBytes, &u.UsedBytes); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func deleteUser(username string) error {
	_, err := db.Exec(`DELETE FROM users WHERE username = ?`, username)
	if err == nil {
		davHandlers.Delete(username)
		authCache.invalidate(username)
		storageUsage.mu.Lock()
		delete(storageUsage.m, username)
		storageUsage.mu.Unlock()
	}
	return err
}

func resetPassword(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = db.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, string(hash), username)
	if err == nil {
		authCache.invalidate(username)
	}
	return err
}

// userRole returns the role of username, or "" if there is no such user.
func userRole(username string) (string, error) {
	var role string
	err := db.QueryRow(`SELECT role FROM users WHERE username = ?`, username).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("look up role of %q: %w", username, err)
	}
	return role, nil
}

func adminExists() (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&count)
	return count > 0, err
}

func adminCount() (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&count)
	return count, err
}

func userExists(username string) bool {
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&count)
	return count > 0
}

// ---- storage quota -----------------------------------------------------------

// errQuotaExceeded fails a write that would take its owner past the quota.
var errQuotaExceeded = errors.New("storage quota exceeded")

// storageUsage mirrors user_quota in memory and adds the bytes claimed by writes
// still in progress. A streaming upload checks the quota on every chunk, and
// two uploads running at once must not both fit into the same free space;
// neither works with the database row alone.
var storageUsage = struct {
	mu sync.Mutex
	m  map[string]*userUsage
}{m: map[string]*userUsage{}}

type userUsage struct {
	quota    int64 // 0 = unlimited
	used     int64
	reserved int64
}

// usageLocked returns the entry of username, loading it on first use. A user
// without a user_quota row gets the default quota rather than none.
func usageLocked(username string) (*userUsage, error) {
	if u := storageUsage.m[username]; u != nil {
		return u, nil
	}
	u := &userUsage{quota: conf().DefaultQuota}
	err := db.QueryRow(`SELECT quota_bytes, used_bytes FROM user_quota WHERE username = ?`, username).
		Scan(&u.quota, &u.used)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("load quota of %q: %w", username, err)
	}
	storageUsage.m[username] = u
	return u, nil
}

// reserveQuota claims n more bytes for a write in progress. It fails with
// errQuotaExceeded when committed plus reserved usage would pass the quota,
// so a user already over quota can still write anything that does not grow.
func reserveQuota(username string, n int64) error {
	storageUsage.mu.Lock()
	defer storageUsage.mu.Unlock()
	u, err := usageLocked(username)
	if err != nil {
		return err
	}
	if u.quota > 0 && u.used+u.reserved+n > u.quota {
		return errQuotaExceeded
	}
	u.reserved += n
	return nil
}

// settleQuota releases a reservation and books the change a write actually
// made, which may be negative. The database is updated by increment, so
// concurrent writers cannot overwrite each other's change.
func settleQuota(username string, reserved, delta int64) {
	storageUsage.mu.Lock()
	if u := storageUsage.m[username]; u != nil {
		u.reserved -= reserved
		u.used = max(u.used+delta, 0)
	}
	storageUsage.mu.Unlock()
	if delta == 0 {
		return
	}
	if _, err := db.Exec(`UPDATE user_quota SET used_bytes = MAX(used_bytes + ?, 0) WHERE username = ?`,
		delta, username); err != nil {
		// Only the stored copy is off; reconcileUsage fixes it at the next start.
		logger.Error("cannot store storage usage", "user", username, "delta", delta, "err", err)
	}
}

// setUserQuota changes the quota of username in bytes; 0 means unlimited.
func setUserQuota(username string, quota int64) error {
	if _, err := db.Exec(`INSERT INTO user_quota (username, quota_bytes) VALUES (?, ?)
		ON CONFLICT(username) DO UPDATE SET quota_bytes = excluded.quota_bytes`, username, quota); err != nil {
		return fmt.Errorf("set quota of %q: %w", username, err)
	}
	storageUsage.mu.Lock()
	if u := storageUsage.m[username]; u != nil {
		u.quota = quota
	}
	storageUsage.mu.Unlock()
	return nil
}

// quotaStatus returns the RFC 4331 values of username: bytes used, and bytes
// still available. For an unlimited user the available bytes are the free
// space of the filesystem holding the data directory.
func quotaStatus(username string) (available, used int64, err error) {
	storageUsage.mu.Lock()
	u, err := usageLocked(username)
	var quota int64
	if err == nil {
		quota, used = u.quota, u.used
	}
	storageUsage.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	if quota > 0 {
		return max(quota-used, 0), used, nil
	}
	_, free, err := fsSpace(conf().DataDir)
	if err != nil {
		return 0, 0, err
	}
	return int64(min(free, math.MaxInt64)), used, nil
}

// reconcileUsage recounts every user's storage from disk and stores it, so a
// counter that drifted (a crash between write and update, files changed
// outside webdavgo) is right again after each start. It must run before the
// listeners open and after removeStaleTempFiles.
func reconcileUsage() error {
	start := time.Now()
	users, err := listUsers()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	corrected := 0
	for _, u := range users {
		n := treeSize(userDataRoot(u.Username))
		if n == u.UsedBytes {
			continue
		}
		if _, err := db.Exec(`INSERT INTO user_quota (username, quota_bytes, used_bytes) VALUES (?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET used_bytes = excluded.used_bytes`,
			u.Username, u.QuotaBytes, n); err != nil {
			return fmt.Errorf("store usage of %q: %w", u.Username, err)
		}
		logger.Debug("storage usage corrected", "user", u.Username, "stored", u.UsedBytes, "actual", n)
		corrected++
	}
	storageUsage.mu.Lock()
	clear(storageUsage.m)
	storageUsage.mu.Unlock()
	logger.Info("storage usage reconciled", "users", len(users), "corrected", corrected,
		"duration", fmt.Sprintf("%dms", time.Since(start).Milliseconds()))
	return nil
}

// treeSize is the total size of the regular files at or below root, the
// measure the quota is charged in. Upload temp files are left out: they are
// charged through their reservation until they are committed. Unreadable
// entries are skipped; the next reconcileUsage counts them again.
func treeSize(root string) int64 {
	var total int64
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				logger.Warn("storage scan: cannot read", "path", p, "err", err)
			}
			return nil
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), tmpPrefix) {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// fsSpace returns the size and the free space, in bytes, of the filesystem
// holding path. Free is what an unprivileged process can still write.
func fsSpace(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil
}
