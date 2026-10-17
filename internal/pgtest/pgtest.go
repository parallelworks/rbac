// Package pgtest gives tests a fresh schema in the database RBAC_TEST_DATABASE_URL names.
package pgtest

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// URLEnv names the database the tests run against; without it they are skipped.
const URLEnv = "RBAC_TEST_DATABASE_URL"

// Open returns a pool whose connections use a fresh, empty schema, dropped when the test ends.
// params are added to the URL's query, such as "pool_max_conns=1".
func Open(tb testing.TB, params string) *pgxpool.Pool {
	tb.Helper()
	url := os.Getenv(URLEnv)
	if url == "" {
		tb.Skip(URLEnv + " not set")
	}
	ctx := tb.Context()
	schema := pgx.Identifier{"test_" + strings.ToLower(rand.Text())}.Sanitize()
	conn, err := pgx.Connect(ctx, url)
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
		conn, err := pgx.Connect(ctx, url)
		if err != nil {
			tb.Errorf("drop schema %s: %v", schema, err)
			return
		}
		defer func() { _ = conn.Close(ctx) }()
		if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			tb.Errorf("drop schema %s: %v", schema, err)
		}
	})
	poolURL := url
	if params != "" {
		sep := "?"
		if strings.Contains(url, "?") {
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
