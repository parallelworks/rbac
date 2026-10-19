// Package pgtest gives tests a fresh schema in the database RBAC_TEST_DATABASE_URL names.
package pgtest

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// URLEnv names the database the tests run against; without it they are skipped.
const URLEnv = "RBAC_TEST_DATABASE_URL"

// Open returns a pool whose connections use a fresh, empty schema, dropped when the test ends.
// params are added to the URL's query, such as "pool_max_conns=1".
func Open(tb testing.TB, params string) *pgxpool.Pool {
	tb.Helper()
	return OpenIn(tb, testURL(tb), params)
}

// OpenIn is Open in the database that database, a URL, names.
func OpenIn(tb testing.TB, database, params string) *pgxpool.Pool {
	tb.Helper()
	ctx := tb.Context()
	schema := pgx.Identifier{"test_" + strings.ToLower(rand.Text())}.Sanitize()
	conn, err := pgx.Connect(ctx, database)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		// tb.Context is already canceled during cleanup.
		ctx := context.WithoutCancel(ctx)
		conn, err := pgx.Connect(ctx, database)
		if err != nil {
			tb.Errorf("drop schema %s: %v", schema, err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			tb.Errorf("drop schema %s: %v", schema, err)
		}
	})
	poolURL := database
	if params != "" {
		sep := "?"
		if strings.Contains(database, "?") {
			sep = "&"
		}
		poolURL += sep + params
	}
	cfg, err := pgxpool.ParseConfig(poolURL)
	if err != nil {
		tb.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(pool.Close)
	return pool
}

// Database makes a database in the test database's cluster, with options as CREATE DATABASE
// takes them, such as "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE 'C'", drops it when the test
// ends, and returns its name, quoted, and its URL. It skips the test where the test database's role
// can't make one.
func Database(tb testing.TB, options string) (name, database string) {
	tb.Helper()
	ctx := tb.Context()
	base := testURL(tb)
	id := "rbac_test_" + strings.ToLower(rand.Text())
	name = pgx.Identifier{id}.Sanitize()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name+" "+options); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			tb.Skip("the test database's role can't create databases")
		}
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			tb.Errorf("drop database %s: %v", name, err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			tb.Errorf("drop database %s: %v", name, err)
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		tb.Fatal(err)
	}
	u.Path = "/" + id
	return name, u.String()
}

// testURL is the test database's URL, or skips the test without one.
func testURL(tb testing.TB) string {
	tb.Helper()
	database := os.Getenv(URLEnv)
	if database == "" {
		tb.Skip(URLEnv + " not set")
	}
	return database
}
