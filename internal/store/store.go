// Package store owns the database connection and schema migrations. It supports
// two interchangeable backends selected at startup: PostgreSQL (external) and
// SQLite (embedded, file-backed). Both are accessed through database/sql behind
// a thin dialect-aware wrapper so the repositories stay backend-agnostic.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" database/sql driver
)

//go:embed migrations/postgres/*.sql migrations/sqlite/*.sql
var migrationsFS embed.FS

// Dialect identifies the SQL flavor in use.
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectSQLite   Dialect = "sqlite"
)

// ErrNoRows is returned by QueryRow scans when no row matches. It is an alias of
// sql.ErrNoRows so repositories can compare against a single store-level error
// regardless of backend.
var ErrNoRows = sql.ErrNoRows

// backend maps a Dialect to the concrete database/sql driver name and the goose
// dialect used for migrations.
func backend(d Dialect) (sqlDriver, gooseDialect, migrationsDir string, err error) {
	switch d {
	case DialectPostgres:
		return "pgx", "postgres", "migrations/postgres", nil
	case DialectSQLite:
		return "sqlite", "sqlite3", "migrations/sqlite", nil
	default:
		return "", "", "", fmt.Errorf("unknown dialect %q", d)
	}
}

// Store wraps the database handle and the dialect in use.
type Store struct {
	DB      *DB
	sqlDB   *sql.DB
	Dialect Dialect
}

// Open connects to the database, verifies connectivity, and returns a Store.
func Open(ctx context.Context, dialect Dialect, dsn string) (*Store, error) {
	driver, _, _, err := backend(dialect)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// SQLite tolerates only one writer; serialize all access to avoid SQLITE_BUSY
	// under the app's concurrent HTTP handlers. This is a single-user local tool,
	// so the throughput cost is irrelevant.
	if dialect == DialectSQLite {
		db.SetMaxOpenConns(1)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{DB: &DB{sql: db, dialect: dialect}, sqlDB: db, Dialect: dialect}, nil
}

// Close releases the database handle.
func (s *Store) Close() { _ = s.sqlDB.Close() }

// Ping verifies connectivity (used by the health endpoint).
func (s *Store) Ping(ctx context.Context) error { return s.sqlDB.PingContext(ctx) }

// Migrate applies all embedded goose migrations for the given dialect. It uses a
// short-lived connection separate from the app's handle.
func Migrate(ctx context.Context, dialect Dialect, dsn string) error {
	driver, gooseDialect, dir, err := backend(dialect)
	if err != nil {
		return err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return fmt.Errorf("open sql: %w", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect(gooseDialect); err != nil {
		return fmt.Errorf("set dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, dir); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// DB is a dialect-aware wrapper over *sql.DB. It rewrites the $N placeholder
// style (written in the queries) to the driver's expected form and exposes the
// small query surface the repositories need.
type DB struct {
	sql     *sql.DB
	dialect Dialect
}

// ExecContext runs a statement that returns no rows.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	q, a := rebind(d.dialect, query, args)
	return d.sql.ExecContext(ctx, q, a...)
}

// QueryContext runs a query returning multiple rows.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	q, a := rebind(d.dialect, query, args)
	return d.sql.QueryContext(ctx, q, a...)
}

// QueryRowContext runs a query returning at most one row.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	q, a := rebind(d.dialect, query, args)
	return d.sql.QueryRowContext(ctx, q, a...)
}

// WithTx runs fn inside a transaction, committing on success and rolling back on
// error. The Tx passed to fn rebinds placeholders like DB does.
func (d *DB) WithTx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Tx{tx: tx, dialect: d.dialect}); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Tx is a dialect-aware wrapper over *sql.Tx.
type Tx struct {
	tx      *sql.Tx
	dialect Dialect
}

// ExecContext runs a statement within the transaction.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	q, a := rebind(t.dialect, query, args)
	return t.tx.ExecContext(ctx, q, a...)
}

// rebind rewrites $N placeholders to the form the dialect expects. PostgreSQL
// accepts $N natively, so it is returned unchanged. SQLite uses positional "?"
// bound by textual order, so placeholders are replaced with "?" and args are
// reordered to match the order the placeholders appear in the query (queries in
// this codebase sometimes reference $1 after $2, e.g. "... WHERE id = $1").
func rebind(dialect Dialect, query string, args []any) (string, []any) {
	if dialect != DialectSQLite {
		return query, args
	}
	var b strings.Builder
	b.Grow(len(query))
	newArgs := make([]any, 0, len(args))
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '$' && i+1 < len(query) && query[i+1] >= '1' && query[i+1] <= '9' {
			j := i + 1
			for j < len(query) && query[j] >= '0' && query[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(query[i+1 : j])
			if err == nil && n >= 1 && n <= len(args) {
				newArgs = append(newArgs, args[n-1])
				b.WriteByte('?')
				i = j - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String(), newArgs
}
