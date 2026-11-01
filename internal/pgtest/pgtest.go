// Package pgtest gives tests a fresh schema in the database RBAC_TEST_DATABASE_URL names.
package pgtest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
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
	return OpenIn(tb, URL(tb), params)
}

// OpenIn is Open in the database that database, a URL, names.
func OpenIn(tb testing.TB, database, params string) *pgxpool.Pool {
	tb.Helper()
	ctx := tb.Context()
	schema := pgx.Identifier{newSchema()}.Sanitize()
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
	pool, err := poolIn(ctx, database, schema, params)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(pool.Close)
	return pool
}

func newSchema() string {
	return "test_" + strings.ToLower(rand.Text())
}

// poolIn is a pool of database whose connections use schema, quoted.
func poolIn(ctx context.Context, database, schema, params string) (*pgxpool.Pool, error) {
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
		return nil, err
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	return pgxpool.NewWithConfig(ctx, cfg)
}

// Database makes a database in the test database's cluster, with options as CREATE DATABASE
// takes them, such as "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE 'C'", drops it when the test
// ends, and returns its name, quoted, and its URL. It skips the test where the test database's role
// can't make one, as Skip does.
func Database(tb testing.TB, options string) (name, database string) {
	tb.Helper()
	ctx := tb.Context()
	base := URL(tb)
	id := "rbac_test_" + strings.ToLower(rand.Text())
	name = pgx.Identifier{id}.Sanitize()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name+" "+options); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			Skip(tb, "the test database's role can't create databases")
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

// URL is the test database's URL, or skips the test without one, as Skip does.
func URL(tb testing.TB) string {
	tb.Helper()
	database := os.Getenv(URLEnv)
	if database == "" {
		Skip(tb, URLEnv+" not set")
	}
	return database
}

// Skip skips the test for why, as what it needs isn't there, but in CI fails it: CI gives each run
// a database of its own, set up for every test, so one that skipped there would pass the run
// without testing what it is for.
func Skip(tb testing.TB, why string) {
	tb.Helper()
	if os.Getenv("CI") != "" {
		tb.Fatal(why + ", in CI")
	}
	tb.Skip(why)
}

var templates struct {
	sync.Mutex
	database string
	schemas  map[string]string
}

// Template is a schema of the test database that lasts until DropTemplates, filled by fill on a
// pool whose connections use it the first time a test asks for it by name, for Copy to copy into a
// test's own: what takes seconds to write, as through a trigger on each row, takes a moment to copy.
func Template(tb testing.TB, name string, fill func(context.Context, *pgxpool.Pool) error) string {
	tb.Helper()
	database := URL(tb)
	templates.Lock()
	defer templates.Unlock()
	if schema, ok := templates.schemas[name]; ok {
		return schema
	}
	if templates.database != "" && templates.database != database {
		tb.Fatalf("template %s: the test database is no longer %s", name, templates.database)
	}
	ctx := tb.Context()
	schema := pgx.Identifier{newSchema()}.Sanitize()
	conn, err := pgx.Connect(ctx, database)
	if err != nil {
		tb.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		tb.Fatal(err)
	}
	pool, err := poolIn(ctx, database, schema, "")
	if err == nil {
		err = fill(ctx, pool)
		pool.Close()
	}
	if err != nil {
		// The schema outlives the test, so a failure drops it even once the test's context ends.
		if _, dropErr := conn.Exec(context.WithoutCancel(ctx), "DROP SCHEMA "+schema+" CASCADE"); dropErr != nil {
			err = errors.Join(err, dropErr)
		}
		tb.Fatalf("template %s: %v", name, err)
	}
	if templates.schemas == nil {
		templates.schemas = map[string]string{}
	}
	templates.database, templates.schemas[name] = database, schema
	return schema
}

// DropTemplates drops the schemas Template made, as TestMain does once the tests have run.
func DropTemplates(ctx context.Context) error {
	templates.Lock()
	defer templates.Unlock()
	if len(templates.schemas) == 0 {
		return nil
	}
	conn, err := pgx.Connect(ctx, templates.database)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	for name, schema := range templates.schemas {
		if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		delete(templates.schemas, name)
	}
	return nil
}

// Copy fills tables, empty in the schema of pool's connections, with the rows of those of template,
// a schema Template made, each as it was written: in the order of its identity column, which
// numbered its rows as they were written, or else of their places, with its identities and its
// sequences as they are there, and with none of its triggers fired, as the tables copied hold what
// they wrote. So each table's pages and indexes are laid out as writing them did, and as nothing
// has vacuumed or analyzed them, they have no statistics and no row is visible to all. Each table is
// copied in a transaction and on a connection of its own, at once, but after the tables its
// foreign keys name.
func Copy(tb testing.TB, pool *pgxpool.Pool, template string, tables ...string) {
	tb.Helper()
	ctx := tb.Context()
	copied := make(map[string]chan struct{}, len(tables))
	for _, table := range tables {
		copied[table] = make(chan struct{})
	}
	errs := make([]error, len(tables))
	var wg sync.WaitGroup
	for i, table := range tables {
		wg.Go(func() {
			defer close(copied[table])
			if err := copyTable(ctx, pool.Config().ConnConfig, template, table, copied); err != nil {
				errs[i] = fmt.Errorf("%s: %w", table, err)
			}
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		tb.Fatalf("copy template %s: %v", template, err)
	}
}

// copyTable is Copy of one table, once those of copied its foreign keys name are.
func copyTable(ctx context.Context, cfg *pgx.ConnConfig, template, table string, copied map[string]chan struct{}) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	to, from := pgx.Identifier{table}.Sanitize(), template+"."+pgx.Identifier{table}.Sanitize()
	var columns string
	var identities, references []string
	if err := conn.QueryRow(ctx, `SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum),
		  coalesce(array_agg(attname::text ORDER BY attnum) FILTER (WHERE attidentity <> ''), '{}'),
		  ARRAY(SELECT relname::text FROM pg_constraint JOIN pg_class ON pg_class.oid = confrelid WHERE conrelid = $1::regclass AND contype = 'f')
		FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = ''`,
		to).Scan(&columns, &identities, &references); err != nil {
		return err
	}
	for _, referenced := range references {
		if done, ok := copied[referenced]; ok && referenced != table {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	order := "ctid"
	if len(identities) > 0 {
		order = pgx.Identifier{identities[0]}.Sanitize()
	}
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tgname::text, tgenabled::text FROM pg_trigger
			WHERE tgrelid = $1::regclass AND NOT tgisinternal AND tgenabled <> 'D' ORDER BY tgname`, to)
		if err != nil {
			return err
		}
		triggers, err := pgx.CollectRows(rows, pgx.RowToStructByPos[trigger])
		if err != nil {
			return err
		}
		for _, tg := range triggers {
			if _, err := tx.Exec(ctx, "ALTER TABLE "+to+" DISABLE TRIGGER "+pgx.Identifier{tg.Name}.Sanitize()); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO "+to+" ("+columns+") OVERRIDING SYSTEM VALUE SELECT "+columns+" FROM "+from+" ORDER BY "+order); err != nil {
			return err
		}
		for _, column := range identities {
			var sequence string
			if err := tx.QueryRow(ctx, `SELECT pg_get_serial_sequence($1, $2)`, from, column).Scan(&sequence); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT setval(pg_get_serial_sequence($1, $2), last_value, is_called) FROM `+sequence, to, column); err != nil {
				return err
			}
		}
		for _, tg := range triggers {
			if _, err := tx.Exec(ctx, "ALTER TABLE "+to+" ENABLE "+tg.mode()+"TRIGGER "+pgx.Identifier{tg.Name}.Sanitize()); err != nil {
				return err
			}
		}
		return nil
	})
}

type trigger struct{ Name, Enabled string }

// mode is how ALTER TABLE enables the trigger as it was: always, on a replica only, or by default.
func (tg trigger) mode() string {
	switch tg.Enabled {
	case "A":
		return "ALWAYS "
	case "R":
		return "REPLICA "
	default:
		return ""
	}
}
