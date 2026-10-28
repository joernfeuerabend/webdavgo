// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jörn Feuerabend

package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// openDB opens the database and migrates its schema. Only the service
// calls it, at startup.
func openDB(path string) error {
	if err := openConn(path); err != nil {
		return err
	}
	return migrate(path)
}

// openDBNoMigrate opens the database for the CLI commands (reset-totp,
// setup-info). They run next to the service, so a schema change from them
// would race the service and could leave a migration backup owned by
// whoever ran the command. A schema of another version is refused instead.
func openDBNoMigrate(path string) error {
	if err := openConn(path); err != nil {
		return err
	}
	if err := checkSchemaVersion(); err != nil {
		db.Close()
		return err
	}
	return nil
}

func openConn(path string) error {
	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	// Single-connection setup: SQLite serialises writes anyway and the
	// in-process pool just adds overhead.
	db.SetMaxOpenConns(1)

	for _, p := range []string{
		// The service and the CLI commands (reset-totp, setup-info) may write
		// at the same time; wait for the other's lock instead of failing
		// with SQLITE_BUSY at once.
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err = db.Exec(p); err != nil {
			return fmt.Errorf("apply pragma %q: %w", p, err)
		}
	}
	return nil
}
