// Package pgtest gives tests a fresh schema in the database RBAC_TEST_DATABASE_URL names.
package pgtest

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"maps"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// URLEnv names the database the tests run against; without it they are skipped.
const URLEnv = "RBAC_TEST_DATABASE_URL"

// ShardEnv names the shard of the tests that need the database to run, as "i/n", the ith of n, so
// that n runs, each against a database of its own, run each of them once between them. A test is in
// its top-level test's shard, so its subtests run together.
const ShardEnv = "RBAC_TEST_SHARD"

// TimingsEnv names go test -json output of an earlier run, or of every shard of one, whose times
// balance the shards. A test it doesn't time is placed by a hash of its name.
const TimingsEnv = "RBAC_TEST_TIMINGS"

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
// can't make one.
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

// URL is the test database's URL, or skips the test without one, or where ShardEnv puts its
// top-level test in another shard.
func URL(tb testing.TB) string {
	tb.Helper()
	database := os.Getenv(URLEnv)
	if database == "" {
		tb.Skip(URLEnv + " not set")
	}
	if spec := os.Getenv(ShardEnv); spec != "" {
		index, count, err := parseShard(spec)
		if err != nil {
			tb.Fatal(err)
		}
		s, err := shardsOf(os.Getenv(TimingsEnv), count)
		if err != nil {
			tb.Fatal(err)
		}
		test, _, _ := strings.Cut(tb.Name(), "/")
		if in := s.of(test); in != index {
			// internal/shardcheck reads this message to tell which shard each test was left to.
			tb.Skipf("%s is in shard %d of %d", test, in, count)
		}
	}
	return database
}

// parseShard reads "i/n", the ith of n shards, counting from 1.
func parseShard(spec string) (index, count int, err error) {
	i, n, ok := strings.Cut(spec, "/")
	index, errIndex := strconv.Atoi(i)
	count, errCount := strconv.Atoi(n)
	if !ok || errIndex != nil || errCount != nil || count < 1 || index < 1 || index > count {
		return 0, 0, fmt.Errorf("%s=%q: want i/n, the ith of n shards, counting from 1", ShardEnv, spec)
	}
	return index, count, nil
}

// shards places top-level tests in count shards, numbered from 1.
type shards struct {
	count int
	timed map[string]int
}

// newShards places the tests timings times, in seconds, longest first, each in the shard with the
// least so far, which leaves the longest shard at most a third longer than the least it could be;
// a hash leaves the few tests that take a minute wherever it happens to put them.
func newShards(count int, timings map[string]float64) shards {
	tests := slices.SortedFunc(maps.Keys(timings), func(a, b string) int {
		return cmp.Or(cmp.Compare(timings[b], timings[a]), strings.Compare(a, b))
	})
	loads := make([]float64, count)
	timed := make(map[string]int, len(tests))
	for _, test := range tests {
		least := 0
		for i := range loads {
			if loads[i] < loads[least] {
				least = i
			}
		}
		loads[least] += timings[test]
		timed[test] = least + 1
	}
	return shards{count: count, timed: timed}
}

// of is the shard of the top-level test named test.
func (s shards) of(test string) int {
	if i, ok := s.timed[test]; ok {
		return i
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(test))
	return int(h.Sum64()%uint64(s.count)) + 1 //nolint:gosec // count is positive, so neither conversion overflows
}

var shardCache struct {
	sync.Mutex
	m map[shardKey]shards
}

type shardKey struct {
	timings string
	count   int
}

// shardsOf is newShards of the times in the file timings names, if any, read once.
func shardsOf(timings string, count int) (shards, error) {
	shardCache.Lock()
	defer shardCache.Unlock()
	key := shardKey{timings, count}
	if s, ok := shardCache.m[key]; ok {
		return s, nil
	}
	var times map[string]float64
	if timings != "" {
		f, err := os.Open(timings) //nolint:gosec // the person running the tests names the file
		if err != nil {
			return shards{}, fmt.Errorf("%s: %w", TimingsEnv, err)
		}
		defer func() { _ = f.Close() }()
		if times, err = readTimings(f); err != nil {
			return shards{}, fmt.Errorf("%s: %w", TimingsEnv, err)
		}
	}
	s := newShards(count, times)
	if shardCache.m == nil {
		shardCache.m = map[shardKey]shards{}
	}
	shardCache.m[key] = s
	return s, nil
}

// readTimings reads the seconds each top-level test took from go test -json output: the longest of
// its runs, as a test that needs no database runs in every shard, and one that does, in its own,
// skipped in a moment in the others. Lines that aren't JSON, such as a build's, are passed over.
func readTimings(r io.Reader) (map[string]float64, error) {
	times := map[string]float64{}
	lines := bufio.NewReader(r)
	for {
		line, err := lines.ReadBytes('\n')
		var event struct {
			Action, Test string
			Elapsed      float64
		}
		if json.Unmarshal(line, &event) == nil && event.Test != "" && !strings.Contains(event.Test, "/") &&
			(event.Action == "pass" || event.Action == "fail") {
			times[event.Test] = max(times[event.Test], event.Elapsed)
		}
		if errors.Is(err, io.EOF) {
			return times, nil
		}
		if err != nil {
			return nil, err
		}
	}
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
