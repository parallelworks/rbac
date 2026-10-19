package rbac_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// drain reads n records of history from cursor, as an exporter would, moves cursor past them, and
// checks nothing follows. A transaction running anywhere in the cluster, as another run's of these
// tests, holds them back until it ends.
func drain(t *testing.T, h *harness, cursor *rbac.Cursor, n int) []rbac.Record {
	t.Helper()
	var all []rbac.Record
	for deadline := time.Now().Add(10 * time.Second); len(all) < n; {
		got, next, err := h.authz.History(t.Context(), *cursor, min(2, n-len(all)))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("read %d of %d records: %+v", len(all), n, all)
			}
			time.Sleep(10 * time.Millisecond)
		}
		all, *cursor = append(all, got...), next
	}
	if more, _, err := h.authz.History(t.Context(), *cursor, 1); err != nil || len(more) != 0 {
		t.Fatalf("read past %d records: %+v, %v", n, more, err)
	}
	return all
}

func principals(records []rbac.Record) []rbac.Principal {
	ps := make([]rbac.Principal, len(records))
	for i, r := range records {
		ps[i] = r.Principal
	}
	return ps
}

func TestHistorySkipsNoTransactionThatCommitsLate(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	late, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = late.Rollback(ctx) }()
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	if _, err := late.Exec(ctx, insert, "late"); err != nil {
		t.Fatal(err)
	}
	// A transaction begun after it commits first; reading it now would move the cursor past the
	// first one's record, which commits after.
	if _, err := h.pool.Exec(ctx, insert, "early"); err != nil {
		t.Fatal(err)
	}
	if got, _, err := h.authz.History(ctx, cursor, 10); err != nil || len(got) != 0 {
		t.Fatalf("read past a transaction still running: %+v, %v", got, err)
	}
	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 2)
	if want := []rbac.Principal{{Kind: rbac.User, ID: "late"}, {Kind: rbac.User, ID: "early"}}; !slices.Equal(principals(got), want) {
		t.Fatalf("History = %+v, want %v", got, want)
	}
}

func TestHistoryRecordsEveryWrite(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// Written around the package, as by hand: recorded, with who wrote it in the database.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'why' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 3)
	for i, op := range []string{"create", "update", "delete"} {
		r := got[i]
		if r.Op != op || r.Entity != "grant" || r.Tenant != "t1" || r.Principal != (rbac.Principal{Kind: rbac.User, ID: "u"}) ||
			r.Role != "cluster.login" || r.Scope != cluster.Scope() || r.Actor != (rbac.Principal{}) || r.DBUser == "" || r.Key != got[0].Key {
			t.Errorf("%s: %+v", op, r)
		}
		if (r.Before == nil) != (op == "create") || (r.After == nil) != (op == "delete") {
			t.Errorf("%s: before %s, after %s", op, r.Before, r.After)
		}
	}
	// History is appended to only, and a table it records is deleted from, never truncated, so
	// nothing changes it unrecorded.
	for _, sql := range []string{
		`UPDATE rbac_history SET actor = 'user:x'`, `DELETE FROM rbac_history`, `TRUNCATE rbac_history`, `TRUNCATE rbac_grants`,
	} {
		if _, err := h.pool.Exec(ctx, sql); err == nil {
			t.Errorf("%s: allowed", sql)
		}
	}
}

// The change's context says whether a delete is an expiry, and nothing more about what was done.
func TestHistoryRecordsADeleteAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// `expired` expires after it is made, as its statement runs, and before it is deleted.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'create', 'cluster.login', NULL),
		  ('t1', 'cluster', 'c1', 'user', 'early', 'cluster.login', now() + interval '1 hour'),
		  ('t1', 'cluster', 'c1', 'user', 'expired', 'cluster.login', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	// Whoever sets the context can call a delete an expiry, which only one of a row that expired is.
	for id, op := range map[string]string{"create": "create", "early": "expire", "expired": "expire"} {
		if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('rbac.change', json_build_object('op', $1::text)::text, true)`, op); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM rbac_grants WHERE principal_id = $1`, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := drain(t, h, &cursor, 6)
	ops := map[string]rbac.Record{}
	for _, r := range got[3:] {
		ops[r.Principal.ID] = r
	}
	if ops["create"].Op != "delete" || ops["early"].Op != "delete" || ops["expired"].Op != "expire" ||
		!ops["expired"].EffectiveAt.Equal(ops["expired"].ExpiresAt) {
		t.Fatalf("History = %+v", got[3:])
	}
}

// An expiry is dated when its row expired, but never before the row's last change, which can have
// moved its expiry back to before it: the grant was held until then.
func TestHistoryDatesNoExpiryBeforeItsRowsLastChange(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		for _, sql := range []string{
			`UPDATE rbac_grants SET expires_at = '2000-01-01' WHERE principal_id = 'standing'`,
			`SELECT set_config('rbac.change', '{"op": "expire"}', true)`,
			`DELETE FROM rbac_grants WHERE principal_id = 'standing'`,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 3)
	if got[2].Op != "expire" || !got[2].EffectiveAt.Equal(got[1].EffectiveAt) {
		t.Fatalf("History = %+v", got)
	}
}

// A change is dated by its statement, but never before its row's last change: a statement that
// waited for another transaction's lock on the row began before that one changed it.
func TestHistoryDatesNoChangeBeforeItsRowsLastChange(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	holder, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	var pid int
	if err := holder.QueryRow(ctx, `SELECT pg_backend_pid() FROM rbac_grants WHERE principal = 'user:owner' FOR UPDATE`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'waited' WHERE principal = 'user:owner'`)
		waited <- err
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var blocked bool
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the update never waited for the lock")
		}
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := holder.Exec(ctx, `UPDATE rbac_grants SET note = 'held' WHERE principal = 'user:owner'`); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-waited; err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, `SELECT effective_at FROM rbac_history WHERE principal = 'user:owner' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	dates, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil || len(dates) != 3 || !slices.IsSortedFunc(dates, time.Time.Compare) {
		t.Fatalf("dated %v, %v", dates, err)
	}
}

// rbac_record runs as its owner, so an overload of what it calls, made in its schema by any role
// that may create there, can't stand in for pg_catalog's.
func TestHistoryRecordsRowsWhateverItsSchemaHolds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, sql := range []string{
		`CREATE FUNCTION to_jsonb(rbac_grants) RETURNS jsonb LANGUAGE sql
			AS $$ SELECT pg_catalog.to_jsonb($1) || '{"principal": "user:forged"}' $$`,
		`CREATE FUNCTION jsonb_build_array(text, text, text) RETURNS jsonb LANGUAGE sql AS $$ SELECT '["forged"]'::jsonb $$`,
	} {
		if _, err := h.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	// A connection of its own, which hasn't planned rbac_record before the overloads were made.
	conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, sql := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'real', 'cluster.login')`,
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'g')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g', 'user', 'real')`,
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var forged int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE principal = 'user:forged' OR key LIKE '%forged%'`).Scan(&forged); err != nil || forged != 0 {
		t.Fatalf("recorded %d forged, %v", forged, err)
	}
}

// History is written by its triggers alone: a role that may write the package's tables but not
// history still records what it writes, a session's own table named as history's takes none of
// it, and no one may attach the function that writes it to a table of their own.
func TestHistoryIsWrittenByItsTriggersAlone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var public bool
	if err := h.pool.QueryRow(ctx, `SELECT has_function_privilege('public', 'rbac_record()', 'EXECUTE')`).Scan(&public); err != nil || public {
		t.Fatalf("anyone may attach rbac_record to a table: %v, %v", public, err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	writer, schema := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + writer,
		`GRANT INSERT ON rbac_grants TO ` + writer,
		// pg_temp comes first in a search_path that doesn't name it.
		`CREATE TEMP TABLE rbac_history (LIKE rbac_history INCLUDING ALL)`,
		`SET LOCAL ROLE ` + writer,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'writer', 'cluster.login')`,
		`RESET ROLE`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{schema, "rbac_history"}.Sanitize()+` WHERE principal = 'user:writer'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recorded %d, %v", n, err)
	}
}

// role makes a role with tx, dropped with it, as roles are the cluster's, and returns it, quoted,
// and tx's schema.
func role(t *testing.T, tx pgx.Tx) (name, schema string) {
	t.Helper()
	if err := tx.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	name = pgx.Identifier{"rbac_test_" + strings.ToLower(rand.Text())}.Sanitize()
	if _, err := tx.Exec(t.Context(), `CREATE ROLE `+name); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			t.Skip("the test database's role can't create roles")
		}
		t.Fatal(err)
	}
	return name, schema
}

func TestHistoryKeysTellMembersApart(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'a'), ('t1', 'a user:b')`); err != nil {
		t.Fatal(err)
	}
	// Joined with spaces, each member's group, principal and source would be `a user:b user:c `.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		VALUES ('t1', 'a user:b', 'user', 'c'), ('t1', 'a', 'user', 'b user:c')`); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 4)
	if got[2].Entity != "member" || got[2].Key == got[3].Key {
		t.Fatalf("History = %+v", got[2:])
	}
}

// A time.Time holds no infinity, which a record written before the tables refused one, or by
// history's owner, can: History reads it as an instant PostgreSQL can't hold, and reads and
// exports on past it.
func TestHistoryReadsPastAnInfiniteTime(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	latest := time.Date(294277, time.January, 1, 0, 0, 0, 0, time.UTC)
	earliest := time.Date(-4713, time.November, 24, 0, 0, 0, 0, time.UTC).Add(-time.Microsecond)
	var got []rbac.Record
	// Each the last record read, so the next read follows a cursor at it.
	for _, at := range []string{"-infinity", "infinity"} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (recorded_at, effective_at, tenant, entity, key, op, expires_at)
			VALUES ($1, $1, 't1', 'grant', 'k', 'create', $1)`, at); err != nil {
			t.Fatal(err)
		}
		got = append(got, drain(t, h, &cursor, 1)...)
	}
	for i, want := range []time.Time{earliest, latest} {
		if r := got[i]; !r.RecordedAt.Equal(want) || !r.EffectiveAt.Equal(want) || !r.ExpiresAt.Equal(want) {
			t.Errorf("record %d: %+v, want its times at %v", i, r, want)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records, checkpoints := exportAll(t, h, key)
	last := checkpoints[len(checkpoints)-1]
	if err := rbac.VerifyChain(rbac.Genesis(last.Cursor.Generation), records, last, key.Public()); err != nil {
		t.Fatal(err)
	}
}

// History's times are in UTC, whatever the host's time zone, so an expiry at the end of 9999,
// which the tables hold, writes as JSON: east of UTC, it is in 10000.
func TestHistoryWritesAsJSONInAnyTimeZone(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.ExpiresAt = time.Date(9999, time.December, 31, 23, 59, 59, 999999000, time.UTC)
	h.seed(t, g)
	var n int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM rbac_history`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	var cursor rbac.Cursor
	for _, r := range drain(t, h, &cursor, n) {
		for _, at := range []time.Time{r.RecordedAt, r.EffectiveAt, r.ExpiresAt} {
			if !at.IsZero() && at.Location() != time.UTC {
				t.Errorf("record %d: a time in %v", r.ID, at.Location())
			}
		}
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("record %d as JSON: %v", r.ID, err)
		}
	}
}

// The tables refuse an expiry a time.Time or JSON can't hold, which a role that may write them can
// try.
func TestNoExpiryIsInfinite(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g")
	for _, sql := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login', $1)`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 60, $1)`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at) VALUES ('t1', 'user', 'u', $1)`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at) VALUES ('t1', 'g', 'user', 'u', $1)`,
	} {
		for _, at := range []string{"infinity", "-infinity", "10000-01-01 00:00:00+00", "0001-12-31 23:59:59+00 BC"} {
			_, err := h.pool.Exec(ctx, sql, at)
			if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Errorf("%s, expiring at %s: %v", sql, at, err)
			}
		}
	}
}

// Migrating a database whose tables hold an infinite expiry, or one outside the years 1 to 9999, as
// before they refused one, ends none early or late: one at infinity never expires, one past 9999
// expires at its end, and one at -infinity or before year 1 has expired.
func TestMigratingKeepsWhatAnInfiniteExpiryMeant(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	// As a host's own migration tool would, up to the one that refuses them.
	apply := func(newer bool) {
		t.Helper()
		files, err := fs.Glob(rbac.Migrations(), "*.sql")
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if (name >= "0006") != newer {
				continue
			}
			sql, err := fs.ReadFile(rbac.Migrations(), name)
			if err != nil {
				t.Fatal(err)
			}
			if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, string(sql))
				return err
			}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	apply(false)
	for _, sql := range []string{
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'g')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.login', 'infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'ended', 'cluster.login', '-infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.login', '10000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.login', '20000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', '0044-03-15 12:00:00+00 BC'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', '0100-01-01 00:00:00+00 BC'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', 'epoch')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.sudo', 60, 'infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'ended', 'cluster.sudo', 60, '-infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.sudo', 60, '10000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.sudo', 60, '0044-03-15 12:00:00+00 BC')`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		 VALUES ('t1', 'user', 'standing', 'infinity'), ('t1', 'user', 'ended', '-infinity'),
		   ('t1', 'user', 'far', '10000-01-01 00:00:00+00'), ('t1', 'user', 'ancient', '0044-03-15 12:00:00+00 BC')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		 VALUES ('t1', 'g', 'user', 'standing', 'infinity'), ('t1', 'g', 'user', 'ended', '-infinity'),
		   ('t1', 'g', 'user', 'far', '10000-01-01 00:00:00+00'), ('t1', 'g', 'user', 'ancient', '0044-03-15 12:00:00+00 BC')`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	apply(true)
	var wrong []string
	for _, table := range []string{"rbac_grants", "rbac_eligibilities", "rbac_memberships", "rbac_members"} {
		rows, err := pool.Query(ctx, `SELECT principal || ' ' || coalesce(expires_at::text, 'never') FROM `+table+`
			WHERE NOT (principal = 'user:standing' AND expires_at IS NULL
			  OR principal IN ('user:ended', 'user:ancient') AND expires_at = 'epoch'
			  OR principal = 'user:far' AND expires_at = '9999-12-31 23:59:59.999999+00')`)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		wrong = append(wrong, got...)
	}
	if len(wrong) != 0 {
		t.Fatalf("after migrating: %v", wrong)
	}
	// Grants that differed only in expiries that became one are one grant: the far one past the
	// first is revoked, and the ancient ones before year 1 expire, as the one at the epoch has.
	gone, err := pool.Query(ctx, `SELECT principal || ' ' || op || ' ' || how FROM rbac_history
		WHERE entity = 'grant' AND op IN ('delete', 'expire') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(gone, pgx.RowTo[string]); err != nil ||
		!slices.Equal(got, []string{"user:ancient expire Migrate", "user:ancient expire Migrate", "user:far delete Migrate"}) {
		t.Fatalf("grants ended by migrating: %v, %v", got, err)
	}
	rows, err := pool.Query(ctx, `SELECT DISTINCT how FROM rbac_history WHERE op = 'update'`)
	if err != nil {
		t.Fatal(err)
	}
	if how, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(how, []string{"Migrate"}) {
		t.Fatalf("recorded by %v, %v", how, err)
	}
	// Checked by a host whose clock is behind the database's, and as of before migrating, the
	// grant at -infinity is held by neither and the one at infinity by both. The ended identity's
	// membership stands from here, so its grant's expiry alone decides.
	if _, err := pool.Exec(ctx, `UPDATE rbac_memberships SET expires_at = NULL WHERE principal = 'user:ended'`); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	authz, err := rbac.New(pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
		Now:           func() time.Time { return now.Add(-time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	standing, ended := rbac.Principal{Kind: rbac.User, ID: "standing"}, rbac.Principal{Kind: rbac.User, ID: "ended"}
	for _, p := range []rbac.Principal{standing, ended} {
		err := authz.Authorize(ctx, rbac.Subject{Principal: p}, login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		if (err == nil) != (p == standing) {
			t.Errorf("with the host's clock behind, Authorize(%s) = %v", p.ID, err)
		}
	}
	if err := authz.AsOf(ctx, "t1", before, func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{standing, ended}})
		if err == nil && (len(grants) != 1 || grants[0].Principal != standing || !grants[0].ExpiresAt.IsZero()) {
			t.Errorf("as of before migrating: %+v", grants)
		}
		return err
	}); err != nil {
		t.Fatalf("as of before migrating: %v", err)
	}
}

func TestHistoryRefusesACursorItCantFollow(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if cursor.Generation == "" || cursor.RecordedAt.IsZero() {
		t.Fatalf("cursor = %+v", cursor)
	}
	// Read on with the cursor it gave, or one a read that found nothing gave.
	for _, c := range []rbac.Cursor{cursor, {Generation: cursor.Generation}} {
		if _, _, err := h.authz.History(ctx, c, 1); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	// Refused one another generation gave, as before a failover, and one whose last record this
	// database doesn't hold, as after a restore that started no generation: either may number
	// records past what this one kept anew.
	old := cursor
	old.Generation = "1/1"
	if _, _, err := h.authz.History(ctx, old, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a cursor of another generation: %v", err)
	}
	lost := cursor
	lost.RecordedAt = lost.RecordedAt.Add(time.Microsecond)
	if _, _, err := h.authz.History(ctx, lost, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a cursor of a record the database doesn't hold: %v", err)
	}
	if _, _, err := h.authz.History(ctx, rbac.Cursor{}, rbac.MaxHistory+1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("too many: %v", err)
	}
}

// A pool's connections can reach different servers, as an old primary and the new one after a
// failover: History checks the cursor on the server it reads, which here doesn't hold its record.
func TestHistoryChecksTheCursorWhereItReads(t *testing.T) {
	h, other := setup(t), setup(t)
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	authz, err := rbac.New(servers{DB: other.pool, alone: h.pool}, rbac.Config{
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := authz.History(t.Context(), cursor, 10); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("History = %+v, %v", got, err)
	}
}

// servers runs a query of one row outside a transaction on alone, and everything else on DB.
type servers struct {
	rbac.DB
	alone rbac.DB
}

func (s servers) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.alone.QueryRow(ctx, sql, args...)
}

// Each installation in a database cluster, in a schema or a database of its own, is a generation of
// its own: their exports chain from geneses of their own, so one's never verifies as another's,
// even with one key, and a cursor of one is refused by another.
func TestEachInstallationIsAGenerationOfItsOwn(t *testing.T) {
	ctx := t.Context()
	generation := func(h *harness) rbac.Cursor {
		t.Helper()
		_, c, err := h.authz.History(ctx, rbac.Cursor{}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// Two schemas in one database, and one schema in two databases, the second made from the
	// first as its template, which gives its schema the first's OID.
	first, second := generation(setup(t)), generation(setup(t))
	template, url := pgtest.Database(t, "TEMPLATE template0")
	pool := pgtest.OpenIn(t, url, "")
	original := setupOn(t, pool)
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	inTemplate := generation(original)
	pool.Close()
	_, url = pgtest.Database(t, "TEMPLATE "+template)
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	authz, err := rbac.New(pool, original.cfg)
	if err != nil {
		t.Fatal(err)
	}
	copied := &harness{pool: pool, authz: authz}
	inCopy := generation(copied)
	for what, c := range map[string][2]rbac.Cursor{"another schema": {first, second}, "another database": {inTemplate, inCopy}} {
		if c[0].Generation == c[1].Generation {
			t.Errorf("in %s: generation %s", what, c[0].Generation)
		}
	}
	if _, _, err := copied.authz.History(ctx, inTemplate, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a cursor of the template's history in its copy: %v", err)
	}
}

func TestHistoryRecordsAReplicasWrites(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// A session in replica mode, as a subscription's apply worker is, fires only triggers enabled
	// always.
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'cluster', 'c1', 'user', 'replicated', 'cluster.login')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE principal = 'user:replicated' AND op = 'create'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recorded %d, %v", n, err)
	}
	// Nor does replica mode let history be changed.
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM rbac_history`)
		return err
	}); err == nil {
		t.Fatal("deleted history in replica mode")
	}
}

// recorded is a change's context as history recorded it.
type recorded struct{ actor, onBehalfOf, how, request, reason, op string }

// recordedSince reads the records after *last directly, in id order, and moves *last past them:
// each change has committed, and History would wait on transactions other sessions hold open.
func recordedSince(t *testing.T, h *harness, last *int64) []recorded {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), `SELECT id, actor, on_behalf_of, how, request, reason, op FROM rbac_history
		WHERE id > $1 ORDER BY id`, *last)
	if err != nil {
		t.Fatal(err)
	}
	var got []recorded
	var r recorded
	if _, err := pgx.ForEachRow(rows, []any{last, &r.actor, &r.onBehalfOf, &r.how, &r.request, &r.reason, &r.op}, func() error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestHistoryRecordsWhoMadeEachChangeAndHow(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "groups"))
	owner, groups, u := h.as(t, "owner"), h.as(t, "groups"), h.as(t, "u")
	h.join(t, "v", "w")
	// One that expired before the clock, which DeleteExpired removes, and grants in t2, w's of which
	// DeletePrincipalEverywhere removes and the rest DeleteTenant.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'workspace', 'w1', 'user', 'gone', 'cluster.login', $1)`, h.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Import(ctx, host, "t2", []rbac.Grant{
		grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "w"), grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "y"),
	}); err != nil {
		t.Fatal(err)
	}
	var last int64
	recordedSince(t, h, &last)
	boss := identity("boss")
	login := rbac.Binding{Role: "cluster.login", Principal: identity("v")}
	custom := rbac.RoleDefinition{ID: "custom.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	sudo := rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}
	for _, step := range []struct {
		how   string
		actor rbac.Principal
		do    func(ctx context.Context) error
	}{
		{"SetMemberships", host, func(ctx context.Context) error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("x")}})
		}},
		{"ImportGroups", host, func(ctx context.Context) error {
			return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}})
		}},
		{"SetGroup", groups.Principal, func(ctx context.Context) error {
			return h.authz.SetGroup(ctx, groups, "t1", rbac.GroupDefinition{ID: "devs"})
		}},
		{"ImportMembers", host, func(ctx context.Context) error {
			return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("v")}})
		}},
		{"ChangeMembers", groups.Principal, func(ctx context.Context) error {
			return h.authz.ChangeMembers(ctx, groups, "t1", []rbac.Member{{Group: "devs", Principal: identity("v")}}, nil)
		}},
		{"DeleteMembers", host, func(ctx context.Context) error {
			return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("v")}})
		}},
		{"Apply", owner.Principal, func(ctx context.Context) error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{login}})
		}},
		{"Import", host, func(ctx context.Context) error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"DeleteGrants", host, func(ctx context.Context) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"SetRole", admin.Principal, func(ctx context.Context) error { return h.authz.SetRole(ctx, admin, "t1", custom) }},
		{"DeleteRole", admin.Principal, func(ctx context.Context) error { return h.authz.DeleteRole(ctx, admin, "t1", custom.ID) }},
		{"SetDeny", owner.Principal, func(ctx context.Context) error {
			return h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("x")}, Permissions: []rbac.Permission{root}})
		}},
		{"DeleteDeny", owner.Principal, func(ctx context.Context) error { return h.authz.DeleteDeny(ctx, owner, cluster, "d") }},
		{"SetEligibility", owner.Principal, func(ctx context.Context) error { return h.authz.SetEligibility(ctx, owner, cluster, sudo) }},
		{"Activate", u.Principal, func(ctx context.Context) error {
			_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"})
			return err
		}},
		{"Deactivate", u.Principal, func(ctx context.Context) error { return h.authz.Deactivate(ctx, u, cluster, "cluster.sudo") }},
		{"DeleteEligibility", owner.Principal, func(ctx context.Context) error {
			return h.authz.DeleteEligibility(ctx, owner, cluster, "cluster.sudo", u.Principal)
		}},
		{"DeleteGroup", groups.Principal, func(ctx context.Context) error { return h.authz.DeleteGroup(ctx, groups, "t1", "devs") }},
		{"DeleteGroups", host, func(ctx context.Context) error { return h.authz.DeleteGroups(ctx, host, "t1", []string{"ops"}) }},
		{"DeleteScopes", host, func(ctx context.Context) error {
			return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope()})
		}},
		{"DeleteScope", host, func(ctx context.Context) error { return h.authz.DeleteScope(ctx, host, "t1", rbac.TenantRoot("t1")) }},
		{"DeletePrincipal", host, func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("x")) }},
		{"DeletePrincipalEverywhere", host, func(ctx context.Context) error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, identity("w"))
		}},
		{"DeleteTenant", host, func(ctx context.Context) error { return h.authz.DeleteTenant(ctx, host, "t2") }},
	} {
		audit := rbac.Audit{OnBehalfOf: boss, Request: "req-" + step.how, Reason: "because"}
		if err := step.do(rbac.WithAudit(ctx, audit)); err != nil {
			t.Fatalf("%s: %v", step.how, err)
		}
		got := recordedSince(t, h, &last)
		if len(got) == 0 {
			t.Errorf("%s recorded nothing", step.how)
		}
		want := recorded{actor: "user:" + step.actor.ID, onBehalfOf: "user:boss", how: step.how, request: audit.Request, reason: "because"}
		for _, r := range got {
			if r.op = ""; r != want {
				t.Errorf("%s recorded %+v, want %+v", step.how, r, want)
			}
		}
	}
	// An expiry is no one's, and is recorded as one.
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{how: "DeleteExpired", op: "expire"}) {
		t.Fatalf("DeleteExpired recorded %+v", got)
	}
}

func TestAHostsOwnWritesAreNotRecordedAsAChangesUnderWithTx(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).Import(rbac.WithAudit(ctx, rbac.Audit{Request: "req-1"}), host, "t1",
		[]rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := recordedSince(t, h, &last)
	if len(got) != 2 || got[0].how != "Import" || got[0].request != "req-1" || got[1] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAChangeRefusesWhatItCantRecord(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	g := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}
	for name, a := range map[string]rbac.Audit{
		"on behalf of a group": {OnBehalfOf: rbac.Principal{Kind: rbac.Group, ID: "ops"}},
		// JSON would record it as someone else, with U+FFFD for the byte.
		"on behalf of an id that isn't UTF-8": {OnBehalfOf: identity("a\xffb")},
		"a long request":                      {Request: strings.Repeat("r", rbac.MaxRequest+1)},
		"a long reason":                       {Reason: strings.Repeat("r", rbac.MaxNote+1)},
		"a NUL":                               {Request: "a\x00b"},
	} {
		if err := h.authz.Import(rbac.WithAudit(ctx, a), host, "t1", g); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := h.authz.DeleteExpired(rbac.WithAudit(ctx, a)); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteExpired, %s: %v", name, err)
		}
	}
	// DeleteGrants stores nothing that names its actor, so history alone would take it, as someone else.
	if err := h.authz.DeleteGrants(ctx, identity("h\xff"), "t1", g); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("an actor whose id isn't UTF-8: %v", err)
	}
}

// What OnChange writes is its host's: through the package, as the call it makes; by hand, as no
// one's. Neither is recorded as the change it is told of, and a call it makes ends no context
// that change still writes with.
func TestHistoryRecordsOnChangesWritesAsItsOwn(t *testing.T) {
	var h *harness
	h = setup(t, func(c *rbac.Config) {
		c.OnChange = func(ctx context.Context, tx pgx.Tx, e rbac.ChangeEvent) error {
			switch e.Tenant {
			case "t1":
				_, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', 'c1', 'user', 'by-hook', 'cluster.login')`)
				return err
			case "t2":
				return h.authz.WithTx(tx).Import(ctx, host, "t9", []rbac.Grant{grant(rbac.TenantRoot("t9"), "cluster.login", rbac.User, "z")})
			}
			return nil
		}
	})
	ctx := t.Context()
	// w's grants in t2 and t3, which DeletePrincipalEverywhere removes in one transaction, telling
	// OnChange of t2's first.
	for _, tenant := range []string{"t2", "t3"} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ($1, 'cluster', 'c1', 'user', 'w', 'cluster.login')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var last int64
	recordedSince(t, h, &last)
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 2 || got[0] != (recorded{actor: "user:host", how: "Import", op: "create"}) ||
		got[1] != (recorded{op: "create"}) {
		t.Errorf("Import recorded %+v", got)
	}
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, identity("w")); err != nil {
		t.Fatal(err)
	}
	removal := recorded{actor: "user:host", how: "DeletePrincipalEverywhere", op: "delete"}
	if got := recordedSince(t, h, &last); len(got) != 3 || got[0] != removal || got[1] != removal ||
		got[2] != (recorded{actor: "user:host", how: "Import", op: "create"}) {
		t.Errorf("DeletePrincipalEverywhere recorded %+v", got)
	}
}

// A change that fails under WithTx leaves nothing in the host's transaction, though its context is
// done: neither what it wrote nor its context for history, which would record the host's own
// writes as the change's.
func TestAFailedChangeLeavesNothingInTheHostsTransaction(t *testing.T) {
	var cancel context.CancelFunc
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error {
			cancel()
			return context.Canceled
		}
	})
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	call, c := context.WithCancel(ctx)
	cancel = c
	if err := h.authz.WithTx(tx).Import(call, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAnExpiryInAnOlderTransactionIsRecordedAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A host's transaction begun before the grant expires, which DeleteExpired, under it, removes.
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'brief', 'cluster.login', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	h.now = time.Now().Add(time.Second)
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var op string
	if err := h.pool.QueryRow(ctx, `SELECT op FROM rbac_history WHERE principal = 'user:brief' AND after IS NULL`).Scan(&op); err != nil || op != "expire" {
		t.Fatalf("op = %q, %v", op, err)
	}
}

// A change under WithTx that runs past a savepoint's bound still ends its savepoint: the bound
// runs from when the change is done, so a slow one neither fails once written nor leaves its
// writes in the host's transaction once refused.
func TestASlowChangeUnderWithTxEndsItsSavepoint(t *testing.T) {
	rbac.SetSavepointEnd(t, 200*time.Millisecond)
	errRefused := errors.New("refused")
	var refuse bool
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error {
			time.Sleep(400 * time.Millisecond)
			if refuse {
				return errRefused
			}
			return nil
		}
	})
	ctx := t.Context()
	for _, id := range []string{"kept", "refused"} {
		refuse = id == "refused"
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, id)})
		if want := map[bool]error{true: errRefused}[refuse]; !errors.Is(err, want) {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: %v", id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := h.pool.Query(ctx, `SELECT principal_id FROM rbac_grants WHERE principal_id IN ('kept', 'refused')`)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(held, []string{"kept"}) {
		t.Fatalf("held %v, %v", held, err)
	}
}

// hostTx is a host's own handle on its transaction, as one that traces its queries is: a DB, but
// not a pgx.Tx.
type hostTx struct{ tx pgx.Tx }

func (h hostTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return h.tx.Exec(ctx, sql, args...)
}

func (h hostTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return h.tx.Query(ctx, sql, args...)
}

func (h hostTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return h.tx.QueryRow(ctx, sql, args...)
}

func (h hostTx) Begin(ctx context.Context) (pgx.Tx, error) { return h.tx.Begin(ctx) }

// A change on a DB that begins only savepoints, though not a pgx.Tx, ends its context with it, so
// the host's own writes after it aren't recorded as the change's.
func TestAChangeInAHostsTransactionEndsItsContext(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authz, err := rbac.New(hostTx{tx}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 2 || got[0] != (recorded{actor: "user:host", how: "Import", op: "create"}) ||
		got[1] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

// The host's clock can run ahead of the database's, which history records an expiry by: what
// DeleteExpired removes has expired by both, so it is recorded as an expiry.
func TestAnExpiryAheadOfTheDatabasesClockIsRecordedAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.now = time.Now().Add(time.Hour)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'past', 'cluster.login', clock_timestamp() - interval '1 second'),
		  ('t1', 'cluster', 'c1', 'user', 'soon', 'cluster.login', clock_timestamp() + interval '30 minutes')`); err != nil {
		t.Fatal(err)
	}
	var last int64
	recordedSince(t, h, &last)
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{how: "DeleteExpired", op: "expire"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAnUpdateThatMovesARowIsRecordedAsItsEndAndStart(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u", "ops")
	var last int64
	recordedSince(t, h, &last)
	// By hand, as a write around the package can: Activate moves only an activation that ended.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET source = 'sync' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	got := recordedSince(t, h, &last)
	if len(got) != 2 || got[0].op != "delete" || got[1].op != "create" {
		t.Fatalf("recorded %+v", got)
	}
	rows, err := h.pool.Query(ctx, `SELECT key FROM rbac_history WHERE entity = 'member' AND id > $1 - 2 ORDER BY id`, last)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("keys = %v, %v", keys, err)
	}
}

// Activating again once an activation has ended moves its grant to a new id: the ended one is
// recorded as the expiry it was, when it expired, not as a revoke by whoever activated again.
func TestAnActivationMadeAnewRecordsTheEndedOneAsItsExpiry(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// On the database's clock, which dates an expiry no earlier than the change before it, so the
	// activation ends after it is made, and ends by both clocks before it is made anew.
	h.now = time.Now()
	activate := rbac.Activation{Role: "cluster.sudo", Duration: 250 * time.Millisecond, Justification: "INC-1"}
	first, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `SELECT pg_sleep(extract(epoch FROM $1 - clock_timestamp()))`, first.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	h.now = first.ExpiresAt
	again, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil || again.ID == first.ID {
		t.Fatalf("activated anew %+v, %v", again, err)
	}
	rows, err := h.pool.Query(ctx, `SELECT key || ' ' || op FROM rbac_history WHERE entity = 'grant' AND key IN ($1, $2) ORDER BY id`,
		first.ID, again.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if want := []string{first.ID + " create", first.ID + " expire", again.ID + " create"}; err != nil || !slices.Equal(got, want) {
		t.Fatalf("recorded %v, %v, want %v", got, err, want)
	}
	var expired time.Time
	if err := h.pool.QueryRow(ctx, `SELECT effective_at FROM rbac_history WHERE entity = 'grant' AND key = $1 AND op = 'expire'`,
		first.ID).Scan(&expired); err != nil || !expired.Equal(first.ExpiresAt) {
		t.Fatalf("expired at %v, %v, want %v", expired, err, first.ExpiresAt)
	}
}

// The host's clock can run ahead of the database's, which history records an expiry by: an
// activation ended by Config.Now alone is extended, not made anew, so the one before isn't recorded
// as revoked by whoever activated again.
func TestAnActivationEndedAheadOfTheDatabasesClockIsExtended(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.now = time.Now().Add(time.Hour)
	activate := rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}
	first, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Minute)
	again, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil || again.ID != first.ID {
		t.Fatalf("activated %+v, %v, want %s extended", again, err, first.ID)
	}
	rows, err := h.pool.Query(ctx, `SELECT op FROM rbac_history WHERE entity = 'grant' AND key = $1 ORDER BY id`, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(got, []string{"create", "update"}) {
		t.Fatalf("recorded %v, %v", got, err)
	}
}

func TestEveryRefusedChangeIsReported(t *testing.T) {
	var refused []rbac.Refusal
	h := setup(t, func(c *rbac.Config) {
		c.OnRefused = func(_ context.Context, r rbac.Refusal) { refused = append(refused, r) }
	})
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Request: "req-1"})
	actor := h.as(t, "actor")
	none := rbac.Resource{}
	// Each refused as invalid, for want of a tenant or a resource.
	for _, c := range []struct {
		how string
		do  func() error
	}{
		{"Apply", func() error { return h.authz.Apply(ctx, actor, none, rbac.Change{}) }},
		{"Import", func() error { return h.authz.Import(ctx, host, "", nil) }},
		{"DeleteGrants", func() error { return h.authz.DeleteGrants(ctx, host, "", nil) }},
		{"DeleteScope", func() error { return h.authz.DeleteScope(ctx, host, "", cluster.Scope()) }},
		{"DeleteScopes", func() error { return h.authz.DeleteScopes(ctx, host, "", []rbac.Scope{cluster.Scope()}) }},
		{"DeletePrincipal", func() error { return h.authz.DeletePrincipal(ctx, host, "", actor.Principal) }},
		{"DeletePrincipalEverywhere", func() error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, rbac.TenantMembers("t1"))
		}},
		{"DeleteTenant", func() error { return h.authz.DeleteTenant(ctx, host, "") }},
		{"DeleteExpired", func() error {
			_, err := h.authz.DeleteExpired(rbac.WithAudit(ctx, rbac.Audit{OnBehalfOf: rbac.TenantMembers("t1")}))
			return err
		}},
		{"SetMemberships", func() error { return h.authz.SetMemberships(ctx, host, "", nil) }},
		{"SetGroup", func() error { return h.authz.SetGroup(ctx, actor, "", rbac.GroupDefinition{}) }},
		{"ImportGroups", func() error { return h.authz.ImportGroups(ctx, host, "", nil) }},
		{"DeleteGroup", func() error { return h.authz.DeleteGroup(ctx, actor, "", "g") }},
		{"DeleteGroups", func() error { return h.authz.DeleteGroups(ctx, host, "", []string{"g"}) }},
		{"ImportMembers", func() error { return h.authz.ImportMembers(ctx, host, "", nil) }},
		{"ChangeMembers", func() error { return h.authz.ChangeMembers(ctx, actor, "", nil, nil) }},
		{"DeleteMembers", func() error { return h.authz.DeleteMembers(ctx, host, "", nil) }},
		{"SetRole", func() error { return h.authz.SetRole(ctx, actor, "", rbac.RoleDefinition{}) }},
		{"DeleteRole", func() error { return h.authz.DeleteRole(ctx, actor, "", "custom.x") }},
		{"SetDeny", func() error { return h.authz.SetDeny(ctx, actor, none, rbac.Deny{}) }},
		{"DeleteDeny", func() error { return h.authz.DeleteDeny(ctx, actor, none, "d") }},
		{"SetEligibility", func() error { return h.authz.SetEligibility(ctx, actor, none, rbac.Eligibility{}) }},
		{"DeleteEligibility", func() error { return h.authz.DeleteEligibility(ctx, actor, none, "cluster.sudo", actor.Principal) }},
		{"Activate", func() error {
			_, err := h.authz.Activate(ctx, actor, none, rbac.Activation{})
			return err
		}},
		{"Deactivate", func() error { return h.authz.Deactivate(ctx, actor, none, "cluster.sudo") }},
	} {
		refused = nil
		if err := c.do(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", c.how, err)
			continue
		}
		if len(refused) != 1 || refused[0].How != c.how || !errors.Is(refused[0].Err, rbac.ErrInvalid) || refused[0].At.IsZero() {
			t.Errorf("%s reported %+v", c.how, refused)
		}
	}
	// One denied is too, with its actor and the host's audit; one made isn't.
	refused = nil
	grant := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: actor.Principal}}}
	if err := h.authz.Apply(ctx, actor, cluster, grant); !errors.Is(err, rbac.ErrDenied) {
		t.Fatal(err)
	}
	if len(refused) != 1 || refused[0].Actor != actor.Principal || refused[0].Tenant != "t1" || refused[0].Audit.Request != "req-1" ||
		!errors.Is(refused[0].Err, rbac.ErrDenied) {
		t.Fatalf("reported %+v", refused)
	}
	refused = nil
	owner := h.as(t, "owner")
	if err := h.authz.Apply(ctx, owner, cluster, grant); err != nil || len(refused) != 0 {
		t.Fatalf("a change made: %v, reported %+v", err, refused)
	}
	// Nor is one that failed for another reason, as the host's lookup failing.
	unreachable := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "unreachable"}}}}
	if err := h.authz.Apply(ctx, owner, cluster, unreachable); !errors.Is(err, errLookup) || len(refused) != 0 {
		t.Fatalf("a change failed: %v, reported %+v", err, refused)
	}
}

func TestAChangeAsOfATimeIsNotReportedRefused(t *testing.T) {
	var refused []rbac.Refusal
	h := setup(t, func(c *rbac.Config) {
		c.OnRefused = func(_ context.Context, r rbac.Refusal) { refused = append(refused, r) }
	})
	ctx := t.Context()
	owner, actor := h.as(t, "owner"), h.as(t, "actor")
	grant := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: actor.Principal}}}
	// Refused as reading the past, whether the actor could make it then or not: no actor's attempt.
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		if err := a.Apply(ctx, owner, cluster, grant); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply by the owner: %v", err)
		}
		if err := a.Apply(ctx, actor, cluster, grant); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("Apply by another: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(refused) != 0 {
		t.Fatalf("reported %+v", refused)
	}
}

// cursorAt is a cursor at the record query finds, as an export that read up to it. Not one History
// gives, which a transaction running anywhere in the cluster holds back.
func cursorAt(t *testing.T, h *harness, query string, args ...any) rbac.Cursor {
	t.Helper()
	_, c, err := h.authz.History(t.Context(), rbac.Cursor{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(t.Context(), query, args...).Scan(&c.TxID, &c.ID, &c.RecordedAt); err != nil {
		t.Fatal(err)
	}
	return c
}

// exported is a cursor at the last record history holds now, as an export that read it all.
func exported(t *testing.T, h *harness) rbac.Cursor {
	t.Helper()
	return cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history ORDER BY txid DESC, id DESC LIMIT 1`)
}

// notesAt is the note of each grant on the cluster in t1 as of at, by its principal's id.
func notesAt(t *testing.T, h *harness, at time.Time) (map[string]string, error) {
	t.Helper()
	ctx := t.Context()
	got := map[string]string{}
	err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
		for _, g := range grants {
			got[g.Principal.ID] = g.Note
		}
		return err
	})
	return got, err
}

func TestPruningHistoryKeepsWhatAsOfReads(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	h.as(t, "d")
	start := dbNow(t, h)
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login', $2)`
	for _, q := range []struct{ sql, arg string }{
		{insert, "u"},
		{`UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:u'`, ""},
		{insert, "d"},
		{`DELETE FROM rbac_grants WHERE principal = 'user:d'`, ""},
	} {
		args := []any{}
		if q.arg != "" {
			args = []any{q.arg, "first"}
		}
		if _, err := h.pool.Exec(ctx, q.sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	then := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'third' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	notes := func(at time.Time) map[string]string {
		t.Helper()
		got, err := notesAt(t, h, at)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	notes(start)
	before, now := notes(then), notes(dbNow(t, h))
	through := exported(t, h)
	// Only what an export read past goes: nothing at or past the cursor.
	first := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history ORDER BY txid, id LIMIT 1`)
	if n, err := rbac.PruneHistory(ctx, h.pool, then, first); err != nil || n != 0 {
		t.Fatalf("pruning through the first record: %d, %v", n, err)
	}
	// u's first version, which its second superseded before then, and d, whose delete ended it.
	if n, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil || n != 3 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if got := notes(then); !maps.Equal(got, before) || got["u"] != "second" || got["d"] != "" {
		t.Errorf("as of then: %v, before pruning %v", got, before)
	}
	if got := notes(dbNow(t, h)); !maps.Equal(got, now) || got["u"] != "third" {
		t.Errorf("as of now: %v, before pruning %v", got, now)
	}
	// Before then, u held no grant, which history no longer says.
	if got, err := notesAt(t, h, start); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("as of before the prune's time: %v, %v", got, err)
	}
	// The export goes on from its cursor, and reads both prunes, each with what it deleted.
	cursor := through
	for i, r := range drain(t, h, &cursor, 2) {
		deleted := []string{`"deleted": 0`, `"deleted": 3`}[i]
		if r.Entity != "history" || r.Op != "prune" || r.How != "PruneHistory" || !strings.Contains(string(r.After), deleted) ||
			r.Key != then.UTC().Format("2006-01-02T15:04:05.000000Z") {
			t.Errorf("prune %d: %+v", i, r)
		}
	}
	// A prune needs an export's cursor, of this generation, and a time that has passed: AsOf would
	// refuse the present until one to come.
	if _, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h).Add(time.Hour), through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a prune of history up to a time to come: %v", err)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, then, rbac.Cursor{}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a prune with no cursor: %v", err)
	}
	other := through
	other.Generation = "1/1"
	if _, err := rbac.PruneHistory(ctx, h.pool, then, other); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a prune through another generation's cursor: %v", err)
	}
}

// A row's end, its last version at the time, stays while a version before it does, which would
// otherwise be the last AsOf finds: one the export hasn't read, or one dated after the time but
// written first, by a transaction that began after the end's.
func TestPruningHistoryKeepsAnEndWhileAVersionBeforeItStays(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, id := range []string{"early", "late", "mark"} {
		h.as(t, id)
	}
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	// The revoke takes its transaction's id first, and early's grant begins before then but takes
	// its id after the record the export read to.
	revoke, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(ctx) }()
	if _, err := revoke.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	early, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = early.Rollback(ctx) }()
	then := dbNow(t, h)
	for _, id := range []string{"late", "mark"} {
		if _, err := h.pool.Exec(ctx, insert, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := early.Exec(ctx, insert, "early"); err != nil {
		t.Fatal(err)
	}
	if err := early.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := revoke.Exec(ctx, `DELETE FROM rbac_grants WHERE principal IN ('user:early', 'user:late')`); err != nil {
		t.Fatal(err)
	}
	if err := revoke.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	now := dbNow(t, h)
	want, err := notesAt(t, h, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := want["mark"]; !ok || len(want) == 0 {
		t.Fatalf("as of now: %v", want)
	}
	through := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:mark'`)
	if _, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil {
		t.Fatal(err)
	}
	if got, err := notesAt(t, h, now); err != nil || !maps.Equal(got, want) {
		t.Errorf("as of now: %v, %v, before pruning %v", got, err, want)
	}
}

// With changes dated by their statements, in their rows' order: an end at the time stays while a
// version before it stays, as one the export hasn't read, or one dated after the time, which
// history recorded before then can hold.
func TestPruningHistoryKeepsAnEndWhileAnUnreadOrLaterVersionStays(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, id := range []string{"unread", "mark"} {
		h.as(t, id)
	}
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	// The revoke takes its transaction's id first, the grant the export read to the next, and the
	// grant it revokes the last.
	revoke, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(ctx) }()
	if _, err := revoke.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"mark", "unread"} {
		if _, err := h.pool.Exec(ctx, insert, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := revoke.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:unread'`); err != nil {
		t.Fatal(err)
	}
	if err := revoke.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	then := dbNow(t, h)
	time.Sleep(10 * time.Millisecond)
	want, err := notesAt(t, h, dbNow(t, h))
	if err != nil || !maps.Equal(want, map[string]string{"owner": "", "mark": ""}) {
		t.Fatalf("as of now: %v, %v", want, err)
	}
	through := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'grant' AND principal = $1`, "user:mark")
	if _, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil {
		t.Fatal(err)
	}
	if got, err := notesAt(t, h, dbNow(t, h)); err != nil || !maps.Equal(got, want) {
		t.Errorf("as of now, after pruning what the export read: %v, %v", got, err)
	}
	// A grant dated after the time and its revoke before it, as history dated a revoke made in a
	// transaction older than the grant before changes were dated by their statements, written here
	// as history's owner.
	var row string
	if err := h.pool.QueryRow(ctx, `SELECT to_jsonb(g) || jsonb_build_object('id', gen_random_uuid(), 'principal_id', 'dated', 'principal', 'user:dated')
		FROM rbac_grants g WHERE principal = 'user:mark'`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		at time.Time
		op string
	}{{then.Add(time.Millisecond), "create"}, {then.Add(-time.Second), "delete"}} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, before, after)
			SELECT $1, 't1', 'grant', r->>'id', $2, r->>'principal', r->>'role', r->>'scope',
			  CASE $2 WHEN 'delete' THEN r END, CASE $2 WHEN 'create' THEN r END
			FROM (SELECT $3::jsonb r) x`, r.at, r.op, row); err != nil {
			t.Fatal(err)
		}
	}
	// A change since, so the export's cursor is past them.
	h.as(t, "since")
	if _, err := rbac.PruneHistory(ctx, h.pool, then, exported(t, h)); err != nil {
		t.Fatal(err)
	}
	if got, err := notesAt(t, h, dbNow(t, h)); err != nil || !maps.Equal(got, want) {
		t.Errorf("as of now, after pruning what history dated out of its order: %v, %v", got, err)
	}
}

// Under a host's transaction, history is append only again for what the host writes after a prune.
func TestPruningHistoryOnAHostsTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	through := exported(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := rbac.PruneHistory(ctx, tx, dbNow(t, h), through); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM rbac_history WHERE id = (SELECT min(id) FROM rbac_history)`)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a delete from history after the prune: %v", err)
	}
}

// Under a host's transaction, at READ COMMITTED, each of read's queries reads what has committed
// by then: a prune past the time that commits while read runs fails it.
func TestAsOfFailsOnAPruneWhileItReads(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "d")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'd', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	then := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:d'`); err != nil {
		t.Fatal(err)
	}
	through, now := exported(t, h), dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var held []bool
	err = h.authz.WithTx(tx).AsOf(ctx, "t1", then, func(a *rbac.Authorizer) error {
		for range 2 {
			grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
			if err != nil {
				return err
			}
			held = append(held, slices.ContainsFunc(grants, func(g rbac.Grant) bool { return g.Principal.ID == "d" }))
			if len(held) == 1 {
				if _, err := rbac.PruneHistory(ctx, h.pool, now, through); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf while a prune past its time commits: %v, held %v", err, held)
	}
}

// Any session can set what PruneHistory sets, so it lets a delete through only for a role with the
// rights of history's owner, which can disable the trigger anyway: one granted DELETE alone isn't.
func TestHistoryIsPrunedOnlyWithItsOwnersRights(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	deleter, schema := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + deleter,
		`GRANT DELETE ON rbac_history TO ` + deleter,
		`SET LOCAL ROLE ` + deleter,
		`SELECT set_config('rbac.prune', 'on', true)`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	_, err = tx.Exec(ctx, `DELETE FROM rbac_history`)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a delete from history by a role granted DELETE: %v", err)
	}
}

// The trigger runs as whoever deletes, but on a search_path of its own: an = of the deleter's,
// first on its search_path, that finds a table the deleter owns as history's, lets nothing through.
func TestHistoryIsPrunedOnlyWithItsOwnersRightsWhateverTheSearchPath(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	deleter, schema := role(t, tx)
	own := pgx.Identifier{"rbac_test_" + strings.ToLower(rand.Text())}.Sanitize()
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + deleter,
		`GRANT DELETE ON rbac_history TO ` + deleter,
		`CREATE SCHEMA ` + own + ` AUTHORIZATION ` + deleter,
		`SET LOCAL ROLE ` + deleter,
		`CREATE TABLE ` + own + `.mine ()`,
		`CREATE FUNCTION ` + own + `.eq(oid, oid) RETURNS boolean LANGUAGE sql
			AS $$ SELECT $1 OPERATOR(pg_catalog.=) '` + own + `.mine'::pg_catalog.regclass::pg_catalog.oid $$`,
		`CREATE OPERATOR ` + own + `.= (LEFTARG = oid, RIGHTARG = oid, FUNCTION = ` + own + `.eq)`,
		`SELECT set_config('search_path', '` + own + `, pg_catalog', true)`,
		`SELECT set_config('rbac.prune', 'on', true)`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	_, err = tx.Exec(ctx, `DELETE FROM `+pgx.Identifier{schema, "rbac_history"}.Sanitize())
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a delete from history by a role granted DELETE, with an = of its own: %v", err)
	}
}

func TestPruningHistoryInBatchesKeepsWhatAsOfReadsBetweenThem(t *testing.T) {
	rbac.SetMaxPrune(t, 1)
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	h.as(t, "d")
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login', 'first')`
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{insert, []any{"u"}},
		{`UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:u'`, nil},
		{insert, []any{"d"}},
		{`DELETE FROM rbac_grants WHERE principal = 'user:d'`, nil},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	then := dbNow(t, h)
	// A change since, so the export's cursor is past every record the prune may take.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'third' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	through := exported(t, h)
	want, err := notesAt(t, h, then)
	if err != nil || !maps.Equal(want, map[string]string{"u": "second", "owner": ""}) {
		t.Fatalf("as of then = %v, %v", want, err)
	}
	// One record a call, oldest first: d's grant before its revoke, which still reads as its end.
	total := 0
	for range 10 {
		n, err := rbac.PruneHistory(ctx, h.pool, then, through)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := notesAt(t, h, then); err != nil || !maps.Equal(got, want) {
			t.Fatalf("after %d pruned: as of then %v, %v", total+int(n), got, err)
		}
		if n == 0 {
			break
		}
		total += int(n)
	}
	if total != 3 {
		t.Fatalf("pruned %d", total)
	}
}

// A prune's next call goes on from where the last stopped, so it reads its own batch, not again
// the rows its first call kept ahead of it.
func TestPruningGoesOnFromWhereItStopped(t *testing.T) {
	rbac.SetMaxPrune(t, 100)
	// The pages of history the second call reads, behind rows kept from before.
	second := func(t *testing.T, kept int) int64 {
		t.Helper()
		h := setup(t)
		ctx := t.Context()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', 'c1', 'user', 'kept-' || i, 'cluster.login' FROM generate_series(1, $1) i`, []any{kept}},
			{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', 'c1', 'user', 'changed-' || i, 'cluster.login' FROM generate_series(1, 300) i`, nil},
			{`UPDATE rbac_grants SET note = 'changed' WHERE principal LIKE 'user:changed-%'`, nil},
		} {
			if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
		then, through := dbNow(t, h), exported(t, h)
		// The first versions go oldest first, and the call records the last it deleted.
		var last, reached int64
		if err := h.pool.QueryRow(ctx, `SELECT max(id) FROM (SELECT id FROM rbac_history
			WHERE principal LIKE 'user:changed-%' AND op = 'create' ORDER BY id LIMIT 100) d`).Scan(&last); err != nil {
			t.Fatal(err)
		}
		if n, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil || n != 100 {
			t.Fatalf("PruneHistory = %d, %v", n, err)
		}
		if err := h.pool.QueryRow(ctx, `SELECT (after->>'reached')::bigint FROM rbac_history WHERE entity = 'history'`).Scan(&reached); err != nil || reached != last {
			t.Fatalf("the prune reached %d, %v, having deleted up to %d", reached, err, last)
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := historyPages(ctx, t, tx)
		if n, err := rbac.PruneHistory(ctx, tx, then, through); err != nil || n != 100 {
			t.Fatalf("PruneHistory again = %d, %v", n, err)
		}
		return historyPages(ctx, t, tx) - start
	}
	// About as deep in history's indexes either way.
	if few, many := second(t, 500), second(t, 4000); many > few*11/10 {
		t.Fatalf("a prune's second call read %d pages of history behind 500 kept rows, and %d behind 4000", few, many)
	}
}

// A prune of another time or cursor starts from history's oldest record again. Versions the last
// prune kept, which a later time or cursor can find superseded, would otherwise stay behind the end
// of their row, which it deletes, and read as the row's.
func TestAPruneOfAnotherTimeOrCursorStartsAgain(t *testing.T) {
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	// prune prunes as of then through a cursor, a record a call, until a call prunes none.
	prune := func(t *testing.T, h *harness, then time.Time, through rbac.Cursor) int64 {
		t.Helper()
		var total int64
		for {
			n, err := rbac.PruneHistory(t.Context(), h.pool, then, through)
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				return total
			}
			total += n
		}
	}
	t.Run("a later time", func(t *testing.T) {
		rbac.SetMaxPrune(t, 1)
		h := setup(t)
		ctx := t.Context()
		exec := func(sql string, args ...any) {
			t.Helper()
			if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
				t.Fatal(err)
			}
		}
		exec(insert, "a")
		exec(insert, "b")
		exec(`UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:b'`)
		first := dbNow(t, h)
		exec(`DELETE FROM rbac_grants WHERE principal = 'user:a'`)
		then := dbNow(t, h)
		// A change since, so the export's cursor is past every record the prunes may take.
		exec(`UPDATE rbac_grants SET note = 'again' WHERE principal = 'user:b'`)
		through := exported(t, h)
		// As of first, b's first version alone, which comes after a's.
		if n := prune(t, h, first, through); n != 1 {
			t.Fatalf("pruned %d as of first", n)
		}
		// a's grant, which was revoked, is gone.
		prune(t, h, then, through)
		if got, err := notesAt(t, h, then); err != nil || !maps.Equal(got, map[string]string{"b": "changed", "owner": ""}) {
			t.Fatalf("as of then = %v, %v", got, err)
		}
	})
	t.Run("a later cursor", func(t *testing.T) {
		rbac.SetMaxPrune(t, 1)
		h := setup(t)
		ctx := t.Context()
		exec := func(q pgx.Tx, sql string, args ...any) {
			t.Helper()
			var err error
			if q == nil {
				_, err = h.pool.Exec(ctx, sql, args...)
			} else {
				_, err = q.Exec(ctx, sql, args...)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		// A transaction writing before a's grant is, and b's grant and its change after, so a's
		// records have lower ids than b's but a later transaction, which an export reads after.
		other, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Rollback(ctx) }()
		exec(other, insert, "early")
		exec(nil, insert, "a")
		exec(other, insert, "b")
		exec(other, `UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:b'`)
		if err := other.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		// An export that has read the other transaction's records, and not a's yet.
		first := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:b' ORDER BY id DESC LIMIT 1`)
		exec(nil, `DELETE FROM rbac_grants WHERE principal = 'user:a'`)
		then := dbNow(t, h)
		exec(nil, `UPDATE rbac_grants SET note = 'again' WHERE principal = 'user:early'`)
		through := exported(t, h)
		// Through first, b's first version alone, which comes after a's.
		if n := prune(t, h, then, first); n != 1 {
			t.Fatalf("pruned %d through first", n)
		}
		prune(t, h, then, through)
		if got, err := notesAt(t, h, then); err != nil || !maps.Equal(got, map[string]string{"b": "changed", "early": "", "owner": ""}) {
			t.Fatalf("as of then = %v, %v", got, err)
		}
	})
}

// A prune on a host's transaction whose snapshot is older than the export's reads no record
// committed between them, though the export read it: a revoke among them, which the next call
// finds, stays while the grant's version before it, which the first kept and the next goes on
// past, stays, or the grant would read as held again.
func TestPruningGoesOnPastNoVersionAnOlderSnapshotKept(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "revoked")
	h.as(t, "changed")
	exec := func(q pgx.Tx, sql string, args ...any) {
		t.Helper()
		var err error
		if q == nil {
			_, err = h.pool.Exec(ctx, sql, args...)
		} else {
			_, err = q.Exec(ctx, sql, args...)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	// revoked's grant, then changed's, whose first version the first call deletes past the grant's.
	exec(nil, insert, "revoked")
	exec(nil, insert, "changed")
	exec(nil, `UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:changed'`)
	// The revoke takes its transaction's id before the change the export reads to, and commits after
	// the host's snapshot.
	revoke, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(ctx) }()
	exec(revoke, `DELETE FROM rbac_grants WHERE principal = 'user:revoked'`)
	h.as(t, "mark")
	host, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Rollback(ctx) }()
	exec(host, `SELECT 1`)
	if err := revoke.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	then, through := dbNow(t, h), exported(t, h)
	want, err := notesAt(t, h, then)
	if _, held := want["revoked"]; err != nil || held {
		t.Fatalf("as of then: %v, %v", want, err)
	}
	if n, err := rbac.PruneHistory(ctx, host, then, through); err != nil || n != 1 {
		t.Fatalf("PruneHistory on the older snapshot = %d, %v", n, err)
	}
	if err := host.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil {
		t.Fatal(err)
	}
	if got, err := notesAt(t, h, then); err != nil || !maps.Equal(got, want) {
		t.Errorf("as of then, after pruning: %v, %v, before %v", got, err, want)
	}
}

// historyPages is how many pages of history and its indexes tx's session has read since it last
// reported its statistics, which it doesn't in a transaction: what tx reads between two calls.
func historyPages(ctx context.Context, t *testing.T, tx pgx.Tx) int64 {
	t.Helper()
	var n int64
	if err := tx.QueryRow(ctx, `SELECT sum(pg_stat_get_xact_blocks_fetched(oid)) FROM pg_class
		WHERE oid = 'rbac_history'::regclass OR oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = 'rbac_history'::regclass)`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// One call reads as far into history as its batch reaches, and no further: what comes after it,
// which the call doesn't delete, costs it nothing.
func TestPruningHistoryReadsOnlyAsFarAsItsBatch(t *testing.T) {
	rbac.SetMaxPrune(t, 100)
	h := setup(t)
	ctx := t.Context()
	grants := func(n int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', 'c1', 'user', gen_random_uuid()::text, 'cluster.login' FROM generate_series(1, $1)`, n); err != nil {
			t.Fatal(err)
		}
	}
	// Grants changed since they were made, whose first versions go, a batch at a time.
	grants(300)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'changed'`); err != nil {
		t.Fatal(err)
	}
	then := dbNow(t, h)
	through := exported(t, h)
	// The pages of history and its indexes the call reads, in a transaction it rolls back, so each
	// deletes the same records: the oldest first versions.
	read := func() int64 {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := historyPages(ctx, t, tx)
		if n, err := rbac.PruneHistory(ctx, tx, then, through); err != nil || n != 100 {
			t.Fatalf("PruneHistory = %d, %v", n, err)
		}
		return historyPages(ctx, t, tx) - start
	}
	// Each time as deep in history's indexes, but for the few pages of where the last prune
	// stopped, so a call reads about as many pages unless it reads what follows.
	grants(1000)
	few := read()
	grants(4000)
	if many := read(); many > few*11/10 {
		t.Fatalf("a call read %d pages of history, and %d once 4000 more records followed what it deleted", few, many)
	}
}
