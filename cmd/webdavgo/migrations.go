// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

// migrations.go – JSON-driven schema migration for the SQLite database.
// Migrations are stored in migrations.json (embedded at compile time).
// Schema version is tracked via SQLite's PRAGMA user_version — no extra table.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

//go:embed migrations.json
var migrationsJSON []byte

type migrationEntry struct {
	Version     int      `json:"version"`
	Description string   `json:"description"`
	Statements  []string `json:"statements"`
}

type migrationsFile struct {
	TargetVersion int              `json:"target_version"`
	Migrations    []migrationEntry `json:"migrations"`
}

// loadMigrations parses and validates migrations.json.
// It enforces that versions are contiguous starting at 1 and that the last
// migration's version matches target_version.
func loadMigrations() (*migrationsFile, error) {
	var mf migrationsFile
	if err := json.Unmarshal(migrationsJSON, &mf); err != nil {
		return nil, fmt.Errorf("parse migrations.json: %w", err)
	}
	if len(mf.Migrations) == 0 {
		return nil, fmt.Errorf("migrations.json: no migrations defined")
	}
	for i, m := range mf.Migrations {
		if m.Version != i+1 {
			return nil, fmt.Errorf("migrations.json: version gap at index %d: expected %d, got %d", i, i+1, m.Version)
		}
	}
	if last := mf.Migrations[len(mf.Migrations)-1]; last.Version != mf.TargetVersion {
		return nil, fmt.Errorf("migrations.json: last migration version %d != target_version %d", last.Version, mf.TargetVersion)
	}
	return &mf, nil
}

// migrate runs any pending migrations against the open database.
// dbPath is the filesystem path of the database file; it is used only for
// naming the pre-migration backup copy — the actual writes go through db.
func migrate(dbPath string) error {
	mf, err := loadMigrations()
	if err != nil {
		return err
	}

	var current int
	if err := db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}

	target := mf.TargetVersion

	switch {
	case current > target:
		return errSchemaNewer(current, target)
	case current == target:
		logger.Debug("db schema up to date", "version", current)
		return nil
	}

	// Back up the database before any changes so a failed migration can be
	// diagnosed from the pre-migration state. VACUUM INTO goes through the
	// open connection, so the copy also holds commits still in the -wal
	// file, which a plain file copy of dbPath would miss.
	backupPath := fmt.Sprintf("%s.bak-v%d-%d", dbPath, current, time.Now().Unix())
	if _, err := db.Exec("VACUUM INTO " + sqlQuote(backupPath)); err != nil {
		return fmt.Errorf("create db backup: %w", err)
	}
	logger.Info("db backup created", "path", backupPath)

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}

	for _, m := range mf.Migrations {
		if m.Version <= current {
			continue
		}
		for _, stmt := range m.Statements {
			if _, err := tx.Exec(stmt); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("migration v%d %q: %w", m.Version, m.Description, err)
			}
		}
		logger.Info("applied migration", "version", m.Version, "description", m.Description)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}

	// PRAGMA user_version writes to the database header and is not reliably
	// transactional with modernc.org/sqlite in WAL mode; set it after commit.
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", target)); err != nil {
		return fmt.Errorf("set user_version to %d: %w", target, err)
	}

	return nil
}

// schemaPendingHint ends the error of a CLI command run against a database
// the service has not migrated yet. install recognises a pending migration
// by it in setup-info's output: setup-info's exit code for this case is 1,
// like any other failure, and is fixed.
const schemaPendingHint = "restart the service first so it migrates the database"

func errSchemaNewer(current, target int) error {
	return fmt.Errorf("db schema version %d is newer than binary target %d; refusing to start", current, target)
}

// checkSchemaVersion fails unless the open database has exactly the schema
// this binary expects. It never changes the schema; see openDBNoMigrate.
func checkSchemaVersion() error {
	mf, err := loadMigrations()
	if err != nil {
		return err
	}
	var current int
	if err := db.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	switch target := mf.TargetVersion; {
	case current > target:
		return errSchemaNewer(current, target)
	case current < target:
		return fmt.Errorf("db schema version %d is older than binary target %d; %s", current, target, schemaPendingHint)
	}
	return nil
}

// sqlQuote makes s an SQL string literal. VACUUM INTO takes no bound
// parameter for its file name, so a quote in the path must be doubled.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
