// Package db is the job store: jobs, findings and reports in SQLite.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	_ "modernc.org/sqlite" // pure Go, because the images build with CGO_ENABLED=0
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// ErrNotFound means no such job, or no report for it yet.
var ErrNotFound = errors.New("not found")

// DB is the job store.
type DB struct {
	sql *sql.DB
	now func() time.Time
}

// Open opens the database at path, creating it if needed, and brings its schema up to date.
func Open(ctx context.Context, path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// Pragmas belong in the DSN because they are per connection and database/sql pools
	// connections: an Exec after opening would leave foreign keys off on the others.
	// Immediate transactions take the write lock up front, so busy_timeout applies to them
	// instead of a transaction failing when it tries to upgrade its lock.
	query := url.Values{}
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(10000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Set("_txlock", "immediate")
	dsn := url.URL{Scheme: "file", Path: abs, RawQuery: query.Encode()}

	conn, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := migrate(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &DB{sql: conn, now: time.Now}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// migrate applies embedded migrations in name order, tracking progress in user_version. Each
// one is atomic, and the version is read inside the transaction so that two processes
// opening a new database at once cannot both apply it.
func migrate(ctx context.Context, conn *sql.DB) error {
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	slices.Sort(names)

	for i, name := range names {
		target := i + 1
		script, err := migrationFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if err := applyMigration(ctx, conn, target, string(script), len(names)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	if len(names) == 0 {
		return errors.New("no migrations embedded")
	}
	return nil
}

func applyMigration(ctx context.Context, conn *sql.DB, target int, script string, latest int) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var current int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > latest {
		return fmt.Errorf("database schema %d is newer than this binary's %d", current, latest)
	}
	if current >= target {
		return nil
	}
	if _, err := tx.ExecContext(ctx, script); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	// PRAGMA takes no bound parameters. target is an int from our own loop.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", target)); err != nil {
		return fmt.Errorf("record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
