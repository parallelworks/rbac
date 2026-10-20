package rbac_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
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

// Any role may make a temporary table or type, which a search_path that doesn't name pg_temp reads
// before any schema's, pg_catalog's too, and a pool keeps it on its connection: one named as
// history's, empty or holding records history never held, as a catalog its generation is read
// from, or as a type its reads name, stands in for none of it, to History, its generation and
// cursor, PruneHistory, or AsOf's check of what a prune removed. A search_path naming pg_temp
// first, which makes it the current schema, is refused.
func TestHistoryReadsItselfWhateverTablesASessionMakes(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:owner'`); err != nil {
		t.Fatal(err)
	}
	var through rbac.Cursor
	want := drain(t, h, &through, 2)
	before := dbNow(t, h)
	// Types named as those history's reads cast to: as a date, a time compares by its day, so a
	// prune's time, and AsOf's check of it, would be its day's start.
	const types = `CREATE DOMAIN pg_temp.xid8 AS pg_catalog.xid8 CHECK (VALUE <> '0');
		 CREATE DOMAIN pg_temp.text AS pg_catalog.varchar(1);
		 CREATE DOMAIN pg_temp.regclass AS pg_catalog.oid;
		 CREATE DOMAIN pg_temp.timestamptz AS pg_catalog.date;`
	for _, shadow := range []string{
		`CREATE TEMP TABLE rbac_history (LIKE rbac_history INCLUDING ALL)`,
		`CREATE TEMP TABLE pg_class AS SELECT oid, 0::oid AS relnamespace FROM pg_catalog.pg_class;
		 CREATE TEMP TABLE pg_database AS SELECT 0::oid AS oid, datname FROM pg_catalog.pg_database`,
		types,
		// The last, beside which history is pruned.
		types + `CREATE TEMP TABLE rbac_history AS SELECT * FROM rbac_history;
		 INSERT INTO pg_temp.rbac_history (id, txid, recorded_at, effective_at, tenant, entity, key, op)
		 VALUES (0, '1', now(), now(), 't1', 'grant', 'forged', 'create')`,
	} {
		// Each on a session of its own, which has planned none of History's statements.
		h.pool.Reset()
		if _, err := h.pool.Exec(ctx, shadow); err != nil {
			t.Fatal(err)
		}
		got, cursor, err := h.authz.History(ctx, rbac.Cursor{}, rbac.MaxHistory)
		if err != nil || !reflect.DeepEqual(got, want) || cursor.Generation != through.Generation || cursor.ID != through.ID {
			t.Errorf("History beside a session's own history = %+v, %+v, %v", got, cursor, err)
		}
		if more, _, err := h.authz.History(ctx, through, 1); err != nil || len(more) != 0 {
			t.Errorf("History after its cursor, beside a session's own history = %+v, %v", more, err)
		}
	}
	// The owner's grant's first version, which its second supersedes.
	if n, err := rbac.PruneHistory(ctx, h.pool, before, through); err != nil || n != 1 {
		t.Errorf("PruneHistory beside a session's own history = %d, %v", n, err)
	}
	var pruned, prunes int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE id = $1), count(*) FILTER (WHERE entity = 'history')
		FROM `+pgx.Identifier{schema, "rbac_history"}.Sanitize(), want[0].ID).Scan(&pruned, &prunes); err != nil || pruned != 0 || prunes != 1 {
		t.Errorf("history holds %d of the version pruned and %d prunes, %v", pruned, prunes, err)
	}
	if err := h.authz.AsOf(ctx, "t1", before.Add(-time.Microsecond), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf just before the prune's time, beside a session's own types: %v", err)
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error { return nil }); err != nil {
		t.Errorf("AsOf now, beside a session's own types: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `SELECT set_config('search_path', 'pg_temp, ' || quote_ident(current_schema()), false)`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.authz.History(ctx, rbac.Cursor{}, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History with pg_temp first in the search_path: %v", err)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, before, through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("PruneHistory with pg_temp first in the search_path: %v", err)
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf with pg_temp first in the search_path: %v", err)
	}
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

// History's times are in UTC, whatever the host's time zone or its session's, and the latest expiry
// the tables hold writes as JSON in any time zone, its row's too.
func TestHistoryWritesAsJSONInAnyTimeZone(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "timezone=Asia/Kolkata"))
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.ExpiresAt = time.Date(9999, time.December, 30, 23, 59, 59, 999999000, time.UTC)
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
		for _, row := range []json.RawMessage{r.Before, r.After} {
			var times struct {
				ExpiresAt *time.Time `json:"expires_at"`
			}
			if row != nil {
				if err := json.Unmarshal(row, &times); err != nil {
					t.Errorf("record %d's row: %v", r.ID, err)
				}
			}
		}
	}
}

// The tables refuse an expiry a time.Time or JSON can't hold, or one a time.Time holds as its zero,
// which a Record reads as none, which a role that may write them can try.
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
		for _, at := range []string{"infinity", "-infinity", "10000-01-01 00:00:00+00", "0001-12-31 23:59:59+00 BC", "0001-01-01 00:00:00+00"} {
			_, err := h.pool.Exec(ctx, sql, at)
			if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
				t.Errorf("%s, expiring at %s: %v", sql, at, err)
			}
		}
	}
}

// longestNames are n names of the longest a type or verb is, 63 characters, each prefix and a
// number.
func longestNames(prefix string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s%0*d", prefix, 63-len(prefix), i)
	}
	return names
}

// longestPermissions are n permissions of the longest names, on longestNames("t", n).
func longestPermissions(n int) []string {
	ps := longestNames("t", n)
	for i := range ps {
		ps[i] += ":v" + strings.Repeat("x", 62)
	}
	return ps
}

// longestKeys are n keys of kind of the longest ids, MaxID characters.
func longestKeys(kind string, n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("%s:%0*d", kind, rbac.MaxID, i)
	}
	return keys
}

// The tables refuse what the package never writes, as a role that may write them can try: an id of
// more than MaxID bytes, an actor's key that is no key, a role that is no role's id, and a list past
// its bound or holding what is no element of it. Unbounded, one row a hundred megabytes long, built
// on the server, was recorded as JSON no read of history could return, and every export stopped
// there.
func TestTheTablesRefuseWhatThePackageNeverWrites(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g")
	rows := map[string]map[string]any{
		"rbac_grants": {"tenant": "t1", "scope_type": "cluster", "scope_id": "c1", "principal_kind": "user", "principal_id": "u", "role": "cluster.login"},
		"rbac_roles":  {"tenant": "t1", "id": "custom.r", "permissions": []string{"cluster:view"}, "resource_types": []string{"cluster"}},
		"rbac_denies": {"tenant": "t1", "scope_type": "cluster", "scope_id": "c1", "id": "d", "principals": []string{"public:"}, "permissions": []string{"cluster:login"}},
		"rbac_eligibilities": {
			"tenant": "t1", "scope_type": "cluster", "scope_id": "c1", "principal_kind": "user", "principal_id": "u",
			"role": "cluster.sudo", "max_seconds": 60,
		},
		"rbac_memberships": {"tenant": "t1", "principal_kind": "user", "principal_id": "u"},
		"rbac_groups":      {"tenant": "t1", "id": "g2"},
		"rbac_members":     {"tenant": "t1", "group_id": "g", "principal_kind": "user", "principal_id": "u"},
	}
	// Each in a transaction of its own, rolled back, so none stands in another's way.
	insert := func(table, column string, v any) error {
		row := maps.Clone(rows[table])
		row[column] = v
		columns := slices.Sorted(maps.Keys(row))
		params, args := make([]string, len(columns)), make([]any, len(columns))
		for i, c := range columns {
			params[i], args[i] = fmt.Sprintf("$%d", i+1), row[c]
		}
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s)`, table, strings.Join(columns, ", "), strings.Join(params, ", ")), args...)
		return err
	}
	type bound struct {
		table, column string
		ok, bad       []any
	}
	var bounds []bound
	// MaxID bytes, of characters of two bytes each.
	id := strings.Repeat("é", rbac.MaxID/2)
	for _, table := range []string{"rbac_grants", "rbac_roles", "rbac_denies", "rbac_eligibilities", "rbac_memberships", "rbac_groups"} {
		bounds = append(bounds, bound{table, "tenant", []any{id}, []any{id + "x"}})
	}
	for _, c := range [][2]string{
		{"rbac_grants", "scope_id"},
		{"rbac_denies", "scope_id"},
		{"rbac_eligibilities", "scope_id"},
		{"rbac_grants", "principal_id"},
		{"rbac_eligibilities", "principal_id"},
		{"rbac_memberships", "principal_id"},
		{"rbac_members", "principal_id"},
	} {
		bounds = append(bounds, bound{c[0], c[1], []any{id}, []any{id + "x"}})
	}
	kind := "k" + strings.Repeat("x", 62)
	actors := []any{"", "user:" + id, kind + ":" + id, "user:a:b"}
	notActors := []any{"user:" + id + "x", "user", "user:", ":u", "User:u", "user\n:u", strings.Repeat("\x01", 600)}
	for _, c := range [][2]string{
		{"rbac_grants", "approved_by"},
		{"rbac_grants", "created_by"},
		{"rbac_grants", "updated_by"},
		{"rbac_roles", "updated_by"},
		{"rbac_denies", "created_by"},
		{"rbac_denies", "updated_by"},
		{"rbac_eligibilities", "created_by"},
		{"rbac_memberships", "created_by"},
		{"rbac_memberships", "updated_by"},
		{"rbac_groups", "created_by"},
		{"rbac_groups", "updated_by"},
		{"rbac_members", "created_by"},
		{"rbac_members", "updated_by"},
	} {
		bounds = append(bounds, bound{c[0], c[1], actors, notActors})
	}
	roles := []any{"c" + strings.Repeat("x", 127), "custom.x"}
	notRoles := []any{"c" + strings.Repeat("x", 128), "Cluster.login", "", "1x", "cluster login"}
	bounds = append(bounds, bound{"rbac_grants", "role", roles, notRoles}, bound{"rbac_eligibilities", "role", roles, notRoles})
	null := func(ss ...string) []*string {
		out := make([]*string, len(ss)+1)
		for i := range ss {
			out[i] = &ss[i]
		}
		return out
	}
	grantable := longestNames("r", rbac.MaxGrantableRoles+1)
	for i := range grantable {
		grantable[i] += strings.Repeat("x", 65)
	}
	keys := []any{longestKeys("user", rbac.MaxDenyEntries), []string{"public:", "members:t1", "user:" + id, "group:a:b\nc"}}
	notKeys := func(n int) []any {
		return []any{longestKeys("user", n+1), []string{"user:" + strings.Repeat("x", rbac.MaxID+1)}, []string{"user"}, []string{"User:u"}, null("public:")}
	}
	bounds = append(bounds,
		bound{
			"rbac_roles", "permissions",
			[]any{longestPermissions(rbac.MaxRoleEntries)},
			[]any{longestPermissions(rbac.MaxRoleEntries + 1), []string{"cluster"}, []string{"cluster:View"}, null("cluster:view")},
		},
		bound{
			"rbac_roles", "resource_types",
			[]any{longestNames("t", rbac.MaxRoleEntries)},
			[]any{longestNames("t", rbac.MaxRoleEntries+1), []string{"Cluster"}, []string{"t" + strings.Repeat("x", 63)}, null("cluster")},
		},
		bound{
			"rbac_roles", "grantable_roles",
			[]any{[]string{}, grantable[:rbac.MaxGrantableRoles]},
			[]any{grantable, []string{"custom.X"}, null()},
		},
		bound{"rbac_denies", "principals", keys, notKeys(rbac.MaxDenyEntries)},
		bound{"rbac_denies", "exempt", append([]any{[]string{}}, keys...), notKeys(rbac.MaxDenyEntries)},
		bound{"rbac_eligibilities", "approvers", []any{[]string{}, longestKeys("group", rbac.MaxApprovers)}, notKeys(rbac.MaxApprovers)},
	)
	for _, b := range bounds {
		for i, v := range b.ok {
			if err := insert(b.table, b.column, v); err != nil {
				t.Errorf("%s.%s, value %d the package can write: %v", b.table, b.column, i, err)
			}
		}
		for i, v := range b.bad {
			if pgErr := (*pgconn.PgError)(nil); !errors.As(insert(b.table, b.column, v), &pgErr) || pgErr.Code != "23514" {
				t.Errorf("%s.%s, value %d the package never writes: stored", b.table, b.column, i)
			}
		}
	}
}

// A row written around the package that the tables refuse now, as one migrating finds, stops it,
// with a message that names the check and a query that finds the row; deleted, migrating goes on. A
// check left unchecked before, as 0012's, stays so, whatever the rows hold.
func TestMigratingNamesARowTheTablesRefuse(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0013")
	for _, sql := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'kept', 'cluster.login', 'unchecked')`,
		`ALTER TABLE rbac_grants ADD CONSTRAINT rbac_grants_host_check CHECK (note <> 'unchecked') NOT VALID`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, created_by)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login', repeat(chr(1), 600))`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	err := applyMigrations(ctx, pool, pgx.ReadCommitted, "0013", "")
	_, query, found := strings.Cut(fmt.Sprint(err), "find it with ")
	query, _, _ = strings.Cut(query, ", correct or delete it")
	if !found || !strings.Contains(fmt.Sprint(err), "rbac_grants_created_by_check") {
		t.Fatalf("migrating past a row the package never wrote: %v", err)
	}
	var principal string
	if err := pool.QueryRow(ctx, strings.Replace(query, "SELECT *", "SELECT principal", 1)).Scan(&principal); err != nil || principal != "user:u" {
		t.Fatalf("%s found %q, %v", query, principal, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	migrateFiles(t, pool, "0013", "")
	var checked bool
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid = 'rbac_grants'::regclass
		AND conname = 'rbac_grants_host_check'`).Scan(&checked); err != nil || checked {
		t.Fatalf("a check left unchecked: checked %t, %v", checked, err)
	}
}

// Migrating a schema whose name needs quoting checks its own rows, not those of a schema named as
// it reads unquoted: here one that exists beside it, holding none of the tables.
func TestMigratingASchemaNamedWithCapitalsChecksItsRows(t *testing.T) {
	twin := pgtest.Open(t, "")
	ctx := t.Context()
	var lower string
	if err := twin.QueryRow(ctx, `SELECT current_schema()`).Scan(&lower); err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{strings.ToUpper(lower)}.Sanitize()
	if _, err := twin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = twin.Exec(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`) })
	cfg := twin.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	migrateFiles(t, pool, "", "0013")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, created_by)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login', repeat(chr(1), 600))`); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(ctx, pool, pgx.ReadCommitted, "0013", ""); !strings.Contains(fmt.Sprint(err), "rbac_grants_created_by_check") {
		t.Fatalf("migrating past a row the package never wrote: %v", err)
	}
}

// History records no row or change it couldn't return, as one of a column no check bounds, or a
// context the writing session sets: past a mebibyte, its write fails, and History reads on past it.
func TestHistoryRecordsNoRowOrChangeTooLargeToRead(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// As a column a later migration adds might be.
	if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_grants DROP CONSTRAINT rbac_grants_note_check`); err != nil {
		t.Fatal(err)
	}
	write := func(id string, note int, change string) error {
		return pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('rbac.change', $1, true)`, change); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
				VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login', repeat('x', $2))`, id, note)
			return err
		})
	}
	reason, err := json.Marshal(map[string]string{"reason": strings.Repeat("r", 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"a row":    write("long", 1<<20, ""),
		"a change": write("told", 0, string(reason)),
	} {
		if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "54000" {
			t.Errorf("%s of more than a mebibyte: %v", name, err)
		}
	}
	if err := write("within", 1<<20-1024, `{"reason": "r"}`); err != nil {
		t.Fatalf("a row within the bound: %v", err)
	}
	if got := drain(t, h, &cursor, 1); got[0].Principal != identity("within") {
		t.Fatalf("read %+v", got[0])
	}
}

// The largest rows the package writes, every id, key, list and text as long as it may be, are
// recorded, and History returns them: history's bound is well above them.
func TestHistoryRecordsTheLargestRowsThePackageWrites(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// Text of n characters of four bytes each, the most a character takes.
	text := func(n int) string { return strings.Repeat("😀", n) }
	id := text(rbac.MaxID / 4)
	keys := func(n int) []string {
		ks := make([]string, n)
		for i := range ks {
			ks[i] = fmt.Sprintf("k%062d:%s", i, id)
		}
		return ks
	}
	actor, name, typ, source := keys(1)[0], text(rbac.MaxName), "t"+strings.Repeat("x", 62), "s"+strings.Repeat("x", 62)
	grantable := longestNames("r", rbac.MaxGrantableRoles)
	for i := range grantable {
		grantable[i] += strings.Repeat("x", 65)
	}
	for _, w := range []struct {
		sql  string
		args []any
	}{
		{
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, condition_title,
			condition_description, condition, note, approved_by, created_by, updated_by)
			VALUES ($1, $2, $1, $3, $1, $4, $5, $6, $7, $8, $7, $9, $9, $9)`,
			[]any{id, typ, "k" + strings.Repeat("x", 62), "c" + strings.Repeat("x", 127), source, name, text(rbac.MaxNote), text(rbac.MaxExpression / 4), actor},
		},
		{
			`INSERT INTO rbac_roles (tenant, id, name, description, permissions, resource_types, grantable_roles, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			[]any{
				id, "custom." + strings.Repeat("x", 121), name, text(rbac.MaxDescription), longestPermissions(rbac.MaxRoleEntries),
				longestNames("t", rbac.MaxRoleEntries), grantable, actor,
			},
		},
		{
			`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, name, principals, exempt, permissions, condition_title,
			condition_description, condition, created_by, updated_by)
			VALUES ($1, $2, $1, $3, $4, $5, $6, $7, $4, $8, $9, $10, $10)`,
			[]any{
				id, typ, "d" + strings.Repeat("x", 127), name, keys(rbac.MaxDenyEntries), keys(2 * rbac.MaxDenyEntries)[rbac.MaxDenyEntries:],
				longestPermissions(rbac.MaxDenyEntries), text(rbac.MaxDescription), text(rbac.MaxExpression / 4), actor,
			},
		},
		{
			`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, requires,
			approvers, note, created_by)
			VALUES ($1, $2, $1, $3, $1, $4, 60, $5, $6, $7, $8)`,
			[]any{
				id, typ, "k" + strings.Repeat("x", 62), "c" + strings.Repeat("x", 127), text(rbac.MaxExpression / 4), keys(rbac.MaxApprovers),
				text(rbac.MaxNote), actor,
			},
		},
		{`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, source, note, created_by, updated_by)
			VALUES ($1, $2, $1, $3, $4, $5, $5)`, []any{id, "k" + strings.Repeat("x", 62), source, text(rbac.MaxNote), actor}},
		{`INSERT INTO rbac_groups (tenant, id, name, description, source, created_by, updated_by)
			VALUES ($1, $2, $2, $3, $4, $5, $5)`, []any{id, name, text(rbac.MaxDescription), source, actor}},
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, note, created_by, updated_by)
			VALUES ($1, $2, $3, $1, $4, $5, $6, $6)`, []any{id, name, "k" + strings.Repeat("x", 62), source, text(rbac.MaxNote), actor}},
	} {
		if _, err := h.pool.Exec(ctx, w.sql, w.args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(w.sql)[2], err)
		}
	}
	// Recorded as they were and as they are.
	for _, table := range []string{"rbac_grants", "rbac_roles", "rbac_denies", "rbac_eligibilities", "rbac_memberships", "rbac_groups", "rbac_members"} {
		if _, err := h.pool.Exec(ctx, `UPDATE `+table+` SET tenant = tenant WHERE tenant = $1`, id); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
	}
	largest := 0
	for _, r := range drain(t, h, &cursor, 14) {
		largest = max(largest, len(r.Before)+len(r.After))
	}
	t.Logf("the largest record's rows are %d bytes of JSON", largest)
}

// migrateFiles applies the migrations named from from up to to, or past the last when to is empty,
// as a host's own migration tool would: each once, in order, in a transaction of its own.
func migrateFiles(t *testing.T, pool *pgxpool.Pool, from, to string) {
	t.Helper()
	if err := applyMigrations(t.Context(), pool, pgx.ReadCommitted, from, to); err != nil {
		t.Fatal(err)
	}
}

// applyMigrations is migrateFiles, each in a transaction at iso, returning why it failed, for a
// test's goroutine.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool, iso pgx.TxIsoLevel, from, to string) error {
	files, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		return err
	}
	for _, name := range files {
		if name < from || to != "" && name >= to {
			continue
		}
		sql, err := fs.ReadFile(rbac.Migrations(), name)
		if err != nil {
			return err
		}
		if err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: iso}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, string(sql))
			return err
		}); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// migrated is a harness on pool, which migrateFiles migrated.
func migrated(t *testing.T, pool *pgxpool.Pool) *harness {
	t.Helper()
	authz, err := rbac.New(pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{ctx: t.Context(), pool: pool, authz: authz}
}

// Migrating a database whose tables hold an infinite expiry, or one outside the years 1 to 9999 or
// at the first instant of year 1, which a time.Time holds as its zero, as before they refused one,
// ends none early or late: one at infinity never expires, one past 9999 expires at its end, and one
// at -infinity, before year 1 or at its first instant has expired.
func TestMigratingKeepsWhatAnInfiniteExpiryMeant(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	// Up to the first that refuses them.
	migrateFiles(t, pool, "", "0006")
	for _, sql := range []string{
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'g')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.login', 'infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'ended', 'cluster.login', '-infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.login', '10000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.login', '20000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', '0044-03-15 12:00:00+00 BC'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', '0100-01-01 00:00:00+00 BC'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.login', 'epoch'),
		   ('t1', 'cluster', 'c1', 'user', 'first', 'cluster.login', '0001-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'first', 'cluster.login', 'epoch')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.sudo', 60, 'infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'ended', 'cluster.sudo', 60, '-infinity'),
		   ('t1', 'cluster', 'c1', 'user', 'far', 'cluster.sudo', 60, '10000-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'user', 'ancient', 'cluster.sudo', 60, '0044-03-15 12:00:00+00 BC'),
		   ('t1', 'cluster', 'c1', 'user', 'first', 'cluster.sudo', 60, '0001-01-01 00:00:00+00')`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		 VALUES ('t1', 'user', 'standing', 'infinity'), ('t1', 'user', 'ended', '-infinity'),
		   ('t1', 'user', 'far', '10000-01-01 00:00:00+00'), ('t1', 'user', 'ancient', '0044-03-15 12:00:00+00 BC'),
		   ('t1', 'user', 'first', '0001-01-01 00:00:00+00')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		 VALUES ('t1', 'g', 'user', 'standing', 'infinity'), ('t1', 'g', 'user', 'ended', '-infinity'),
		   ('t1', 'g', 'user', 'far', '10000-01-01 00:00:00+00'), ('t1', 'g', 'user', 'ancient', '0044-03-15 12:00:00+00 BC'),
		   ('t1', 'g', 'user', 'first', '0001-01-01 00:00:00+00')`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	migrateFiles(t, pool, "0006", "")
	var wrong []string
	for _, table := range []string{"rbac_grants", "rbac_eligibilities", "rbac_memberships", "rbac_members"} {
		rows, err := pool.Query(ctx, `SELECT principal || ' ' || coalesce(expires_at::text, 'never') FROM `+table+`
			WHERE NOT (principal = 'user:standing' AND expires_at IS NULL
			  OR principal IN ('user:ended', 'user:ancient', 'user:first') AND expires_at = 'epoch'
			  OR principal = 'user:far' AND expires_at = '9999-12-30 23:59:59.999999+00')`)
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
	// first is revoked, and the ancient ones before year 1, and the first one at it, expire, as the
	// one at the epoch has.
	gone, err := pool.Query(ctx, `SELECT principal || ' ' || op || ' ' || how FROM rbac_history
		WHERE entity = 'grant' AND op IN ('delete', 'expire') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(gone, pgx.RowTo[string]); err != nil ||
		!slices.Equal(got, []string{"user:ancient expire Migrate", "user:ancient expire Migrate", "user:far delete Migrate", "user:first expire Migrate"}) {
		t.Fatalf("grants ended by migrating: %v, %v", got, err)
	}
	// What migrating records holds no time the tables refuse, which JSON can't write, or a Record
	// reads as none.
	var outside int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE how = 'Migrate'
		AND (expires_at <= '0001-01-01 00:00:00+00' OR expires_at > '9999-12-30 23:59:59.999999+00'
		  OR effective_at <= '0001-01-01 00:00:00+00' OR effective_at > '9999-12-30 23:59:59.999999+00')`).Scan(&outside); err != nil || outside != 0 {
		t.Fatalf("migrating recorded %d times outside the years 1 to 9999, %v", outside, err)
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

// A row written before history was installed, as by a host that applied the first migrations on
// their own, has no record, so migrating records each as it found it, as rbac_record records a
// row, dated when it was created, or a role, when it last changed: AsOf reads it from then, and a
// prune keeps it until a later version supersedes it. A row history has recorded gets none.
func TestMigratingRecordsARowWrittenBeforeHistory(t *testing.T) {
	// In a time zone of its own, as rbac_record writes a row's times in UTC whatever the session's.
	pool := pgtest.Open(t, "timezone=Asia/Kolkata")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0003")
	for _, sql := range []string{
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, created_at) VALUES ('t1', 'user', 'old', '2020-01-01 00:00:00+00')`,
		`INSERT INTO rbac_groups (tenant, id, created_at) VALUES ('t1', 'g', '2020-01-01 00:00:00+00')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, expires_at, created_at)
		 VALUES ('t1', 'g', 'user', 'old', 'sync', '9999-01-01 00:00:00+00', '2020-01-01 00:00:00+00')`,
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, updated_at)
		 VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}', '2021-01-01 00:00:00+00')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note, created_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'old', 'cluster.login', 'first', '2020-01-01 00:00:00+00'),
		   ('t1', 'cluster', 'c1', 'group', 'g', 'custom.viewer', '', '2021-01-01 00:00:00+00')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, created_at)
		 VALUES ('t1', 'cluster', 'c1', 'd', '{user:x}', '{cluster:root}', '2020-01-01 00:00:00+00')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, created_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'old', 'cluster.sudo', 3600, '2020-01-01 00:00:00+00')`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	migrateFiles(t, pool, "0003", "0008")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'new')`); err != nil {
		t.Fatal(err)
	}
	migrateFiles(t, pool, "0008", "")
	h := migrated(t, pool)
	var cursor rbac.Cursor
	var baselines []rbac.Record
	for _, r := range drain(t, h, &cursor, 9) {
		if r.Key == "user:new" {
			if r.Op != "create" {
				t.Errorf("a row history recorded: %+v", r)
			}
			continue
		}
		var row struct {
			CreatedAt *time.Time `json:"created_at"`
			UpdatedAt *time.Time `json:"updated_at"`
		}
		if err := json.Unmarshal(r.After, &row); err != nil {
			t.Fatal(err)
		}
		dated := row.CreatedAt
		if r.Entity == "role" {
			dated = row.UpdatedAt
		}
		if r.Op != "baseline" || r.How != "Migrate" || r.Actor != (rbac.Principal{}) || r.Before != nil || dated == nil || !r.EffectiveAt.Equal(*dated) {
			t.Errorf("a row written before history: %+v", r)
		}
		baselines = append(baselines, r)
	}
	old := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "old"}}
	for _, c := range []struct {
		at   time.Time
		want bool
	}{{time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), false}, {time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC), true}} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			err := a.Authorize(ctx, old, login, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				return err
			}
			if (err == nil) != c.want {
				t.Errorf("as of %v, Authorize(old) = %v", c.at, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt(t, h, dbNow(t, h))
	// The grant's next version supersedes its baseline, which a prune past both deletes, alone.
	if _, err := pool.Exec(ctx, `UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:old'`); err != nil {
		t.Fatal(err)
	}
	if n, err := rbac.PruneHistory(ctx, pool, dbNow(t, h), exported(t, h)); err != nil || n != 1 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if notes, err := notesAt(t, h, dbNow(t, h)); err != nil || !maps.Equal(notes, map[string]string{"old": "second", "g": ""}) {
		t.Fatalf("as of after the prune: %v, %v", notes, err)
	}
	// Each holds what rbac_record records of its row: the record of the row's next change holds as
	// Before what the baseline holds as After, beside the same columns, and the columns a later
	// migration added, null.
	for _, table := range []string{"rbac_members", "rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_roles", "rbac_memberships", "rbac_groups"} {
		if _, err := pool.Exec(ctx, `DELETE FROM `+table); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE (txid, id) > ($1::xid8, $2)`, cursor.TxID, cursor.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	next := map[[3]string]rbac.Record{}
	for _, r := range drain(t, h, &cursor, n) {
		if k := [3]string{r.Tenant, r.Entity, r.Key}; next[k].ID == 0 {
			next[k] = r
		}
	}
	for _, b := range baselines {
		r := next[[3]string{b.Tenant, b.Entity, b.Key}]
		if r.Principal != b.Principal || r.Role != b.Role || r.Scope != b.Scope || r.Group != b.Group ||
			!r.ExpiresAt.Equal(b.ExpiresAt) || !sameRow(t, b.After, r.Before) {
			t.Errorf("%s %s: baseline %+v, next record %+v", b.Entity, b.Key, b, r)
		}
	}
}

// sameRow reports whether two records hold a row alike, but for the columns later holds that were
// added since, null in it.
func sameRow(t *testing.T, earlier, later json.RawMessage) bool {
	t.Helper()
	var was, is map[string]any
	if err := json.Unmarshal(earlier, &was); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(later, &is); err != nil {
		t.Fatal(err)
	}
	maps.DeleteFunc(is, func(k string, v any) bool {
		_, held := was[k]
		return !held && v == nil
	})
	return reflect.DeepEqual(was, is)
}

// No table bounds when a row was created, so one written before history can say -infinity, before
// year 1 or its first instant, times JSON can't write or a Record reads as none: migrating dates
// its baseline at the epoch, as such an expiry, and AsOf reads the row from then.
func TestMigratingDatesARowCreatedBeforeYearOneAtTheEpoch(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0003")
	for _, sql := range []string{
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, created_at)
		 VALUES ('t1', 'user', 'a', '-infinity'), ('t1', 'user', 'b', '0044-03-15 12:00:00+00 BC'), ('t1', 'user', 'c', '0001-01-01 00:00:00+00')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, created_at)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'a', 'cluster.login', '0001-01-01 00:00:00+00')`,
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, updated_at)
		 VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}', '-infinity')`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	migrateFiles(t, pool, "0003", "")
	h := migrated(t, pool)
	var cursor rbac.Cursor
	for _, r := range drain(t, h, &cursor, 5) {
		if _, err := json.Marshal(r); err != nil || r.Op != "baseline" || !r.EffectiveAt.Equal(time.Unix(0, 0)) {
			t.Errorf("%s %s, dated %v: %v", r.Entity, r.Key, r.EffectiveAt, err)
		}
	}
	a := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "a"}}
	if err := h.authz.AsOf(ctx, "t1", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), func(b *rbac.Authorizer) error {
		return b.Authorize(ctx, a, login, cluster)
	}); err != nil {
		t.Errorf("as of 2000: %v", err)
	}
}

// A change in flight to a row written before history, as migrating records the row, is the row's
// record: migrating waits for it rather than record the row as it was before, after the change,
// in a transaction of its own at any isolation.
func TestMigratingRecordsNoRowAsItWasBeforeAChangeInFlight(t *testing.T) {
	for _, iso := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		t.Run(string(iso), func(t *testing.T) {
			pool := pgtest.Open(t, "")
			ctx := t.Context()
			migrateFiles(t, pool, "", "0003")
			if _, err := pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
				VALUES ('t1', 'cluster', 'c1', 'user', 'old', 'cluster.login', 'first')`); err != nil {
				t.Fatal(err)
			}
			migrateFiles(t, pool, "0003", "0008")
			h := migrated(t, pool)
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(ctx) }()
			var pid int
			if err := writer.QueryRow(ctx, `UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:old' RETURNING pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- applyMigrations(ctx, pool, iso, "0008", "") }()
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
				var blocked bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("migrating never waited for the write")
				}
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if notes, err := notesAt(t, h, dbNow(t, h)); err != nil || notes["old"] != "second" {
				t.Fatalf("as of now: %v, %v", notes, err)
			}
		})
	}
}

// On a host's transaction, whose snapshot an earlier statement took at REPEATABLE READ or
// SERIALIZABLE, migrating would record a row written before history as it was before a change that
// has committed since, and AsOf would read it so: Migrate refuses it, and at READ COMMITTED reads
// the change.
func TestMigratingOnAHostsTransactionRecordsWhatHasCommitted(t *testing.T) {
	for _, iso := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
		t.Run(string(iso), func(t *testing.T) {
			pool := pgtest.Open(t, "")
			ctx := t.Context()
			migrateFiles(t, pool, "", "0003")
			if _, err := pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
				VALUES ('t1', 'cluster', 'c1', 'user', 'old', 'cluster.login', 'first')`); err != nil {
				t.Fatal(err)
			}
			migrateFiles(t, pool, "0003", "0008")
			// As Migrate records what it applied.
			if _, err := pool.Exec(ctx, `CREATE TABLE rbac_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
				INSERT INTO rbac_migrations (version) SELECT generate_series(1, 7)`); err != nil {
				t.Fatal(err)
			}
			host, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: iso})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = host.Rollback(ctx) }()
			if _, err := host.Exec(ctx, `SELECT FROM rbac_grants`); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:old'`); err != nil {
				t.Fatal(err)
			}
			err = rbac.Migrate(ctx, host)
			if iso != pgx.ReadCommitted {
				if err == nil || !strings.Contains(err.Error(), "READ COMMITTED") {
					t.Fatalf("Migrate on a host's transaction at %s: %v", strings.ToUpper(string(iso)), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := host.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			h := migrated(t, pool)
			if notes, err := notesAt(t, h, dbNow(t, h)); err != nil || notes["old"] != "second" {
				t.Fatalf("as of now: %v, %v", notes, err)
			}
		})
	}
}

// Migrating records an activation stored before Activate recorded what it was made through as made
// through the one eligibility for its role on its scope whose principal its holder reaches, in its
// tenant, by its membership and the places in groups in force; one whose holder reaches several, or
// none, records nothing, and the first change ending a place of its holder's ends it. An activation
// that has ended is left as it is.
func TestMigratingTiesAnActivationToTheEligibilityItWasMadeThrough(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0012")
	// In t1, u1 is in oncall, u3 in inner, which is in oncall, u4 in oncall and team, u5 in other,
	// u6 in team and, no longer, in oncall, and u7, in oncall, has left; u2 is eligible itself, and
	// oncall and team are. In t2, u1 is in team, which is eligible there.
	for _, sql := range []string{
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'oncall'), ('t1', 'team'), ('t1', 'inner'), ('t1', 'other'), ('t2', 'team')`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		 SELECT 't1', 'user', 'u' || i, CASE WHEN i = 7 THEN now() - interval '1 hour' END FROM generate_series(1, 8) i
		 UNION ALL SELECT 't2', 'user', 'u1', NULL`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		 VALUES ('t1', 'oncall', 'user', 'u1', NULL), ('t1', 'other', 'user', 'u1', NULL), ('t1', 'inner', 'user', 'u3', NULL),
		   ('t1', 'oncall', 'group', 'inner', NULL), ('t1', 'oncall', 'user', 'u4', NULL), ('t1', 'team', 'user', 'u4', NULL),
		   ('t1', 'other', 'user', 'u5', NULL), ('t1', 'team', 'user', 'u6', NULL), ('t1', 'oncall', 'user', 'u6', now() - interval '1 minute'),
		   ('t1', 'oncall', 'user', 'u7', NULL), ('t1', 'oncall', 'user', 'u8', NULL), ('t2', 'team', 'user', 'u1', NULL)`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		 VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.sudo', 28800), ('t1', 'cluster', 'c1', 'group', 'team', 'cluster.sudo', 28800),
		   ('t1', 'cluster', 'c1', 'user', 'u2', 'cluster.sudo', 28800), ('t1', 'cluster', 'c1', 'group', 'other', 'cluster.login', 28800),
		   ('t2', 'cluster', 'c1', 'group', 'team', 'cluster.sudo', 28800)`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at)
		 SELECT 't1', 'cluster', 'c1', 'user', 'u' || i, 'cluster.sudo', 'activation', now() + CASE WHEN i = 8 THEN interval '-1 hour' ELSE interval '1 hour' END
		 FROM generate_series(1, 8) i`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	migrateFiles(t, pool, "0012", "")
	rows, err := pool.Query(ctx, `SELECT g.principal || ' ' || coalesce(g.activated_through, 'none') || ' ' || coalesce((g.eligibility_id = e.id)::text, 'none')
		FROM rbac_grants g LEFT JOIN rbac_eligibilities e ON e.tenant = g.tenant AND e.scope = g.scope AND e.role = g.role AND e.principal = g.activated_through
		ORDER BY g.principal`)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(got, []string{
		"user:u1 group:oncall true", "user:u2 user:u2 true", "user:u3 group:oncall true", "user:u4 none none",
		"user:u5 none none", "user:u6 group:team true", "user:u7 none none", "user:u8 none none",
	}) {
		t.Fatalf("activations made through: %v, %v", got, err)
	}
	// History records what each is made through, as migrating found it.
	var recorded int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE entity = 'grant' AND op = 'update' AND how = 'Migrate'
		AND after->>'activated_through' IS NOT NULL AND after->'eligibility_id' IS NOT NULL`).Scan(&recorded); err != nil || recorded != 4 {
		t.Fatalf("migrating recorded %d activations' eligibilities, %v", recorded, err)
	}
	h := migrated(t, pool)
	leave := func(group string, ids ...string) {
		t.Helper()
		var ms []rbac.Member
		for _, id := range ids {
			ms = append(ms, rbac.Member{Group: group, Principal: identity(id)})
		}
		if err := h.authz.DeleteMembers(ctx, host, "t1", ms); err != nil {
			t.Fatal(err)
		}
	}
	held := func() []string {
		t.Helper()
		grants, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, g := range grants {
			ids = append(ids, g.Principal.ID)
		}
		return ids
	}
	// u1 leaving a group its activation doesn't rest on keeps it, u4 leaving one ends what records
	// nothing, and u1 leaving oncall ends its own.
	leave("other", "u1", "u5")
	leave("team", "u4")
	if got := held(); !slices.Equal(got, []string{"u1", "u2", "u3", "u6", "u7"}) {
		t.Fatalf("activations held once u1 and u5 left other and u4 team: %v", got)
	}
	leave("oncall", "u1")
	if got := held(); slices.Contains(got, "u1") {
		t.Fatalf("activations held once u1 left oncall: %v", got)
	}
}

// An activation records the principal it was made through as a key the package could make, a kind
// it names and an id of 1 to MaxID bytes, so a row written around the package holds no more.
func TestAnActivationRecordsAPrincipalsKeyAlone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	n := 0
	insert := func(through *string) error {
		n++
		_, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source,
			expires_at, activated_through) VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.sudo', 'activation', now() + interval '1 hour', $2)`,
			fmt.Sprintf("u%d", n), through)
		return err
	}
	for _, k := range []string{
		"user:" + strings.Repeat("x", rbac.MaxID+1), "user:" + strings.Repeat("é", rbac.MaxID/2) + "x", "user:", "user", ":u", "User:u",
		"1user:u", "user :u", strings.Repeat("k", 64) + ":u", "",
	} {
		var pg *pgconn.PgError
		if err := insert(&k); !errors.As(err, &pg) || pg.Code != "23514" {
			t.Errorf("an activation through %.20q… stored: %v", k, err)
		}
	}
	for _, k := range []string{
		"user:" + strings.Repeat("x", rbac.MaxID), "group:" + strings.Repeat("é", rbac.MaxID/2), "service_account:a:b", strings.Repeat("k", 63) + ":u",
	} {
		if err := insert(&k); err != nil {
			t.Errorf("an activation through %.20q…: %v", k, err)
		}
	}
	if err := insert(nil); err != nil {
		t.Errorf("an activation through none: %v", err)
	}
}

// Migrating records no principal past the bound: an eligibility whose principal's id, written around
// the package, is longer than MaxID is none an activation was made through, and records nothing,
// where one at the bound records its key.
func TestMigratingRecordsNoPrincipalPastTheBound(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0012")
	long, longest := strings.Repeat("x", rbac.MaxID+1), strings.Repeat("y", rbac.MaxID)
	for _, id := range []string{long, longest} {
		for _, sql := range []string{
			`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', $1)`,
			`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
			 VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.sudo', 28800)`,
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at)
			 VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.sudo', 'activation', now() + interval '1 hour')`,
		} {
			if _, err := pool.Exec(ctx, sql, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 0012 alone: 0013 refuses an id past the bound.
	migrateFiles(t, pool, "0012", "0013")
	for id, want := range map[string]string{long: "none", longest: "user:" + longest} {
		var through string
		if err := pool.QueryRow(ctx, `SELECT coalesce(activated_through, 'none') FROM rbac_grants WHERE principal_id = $1`, id).Scan(&through); err != nil ||
			through != want {
			t.Errorf("the activation of an id of %d bytes is made through %.20q…, %v", len(id), through, err)
		}
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

// A read of history stops short of the record that would bring what it read past MaxHistoryBytes,
// but reads the first however large, so an export of the largest records holds no more than about
// that in memory, and always goes on.
func TestHistoryReadsAboutMaxHistoryBytesAtOnce(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	var grants []rbac.Grant
	for _, id := range []string{"a", "b", "c"} {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, id)
		g.Note = strings.Repeat("n", rbac.MaxNote)
		grants = append(grants, g)
	}
	if err := h.authz.Import(ctx, host, "t1", grants); err != nil {
		t.Fatal(err)
	}
	// And one whose bytes no trigger counted, as one written before they were, counted by its row.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, after)
		VALUES (now(), 't1', 'grant', 'd', 'create', 'user:d', jsonb_build_object('note', repeat('n', $1)))`, rbac.MaxNote); err != nil {
		t.Fatal(err)
	}
	all := []rbac.Principal{identity("a"), identity("b"), identity("c"), identity("d")}
	// Each record more than half of it, then each more than all of it.
	for _, bytes := range []int{4 << 10, 1 << 10} {
		rbac.SetMaxHistoryBytes(t, bytes)
		from := cursor
		var read []rbac.Principal
		for deadline := time.Now().Add(10 * time.Second); len(read) < len(all); {
			got, next, err := h.authz.History(ctx, from, rbac.MaxHistory)
			switch {
			case err != nil:
				t.Fatal(err)
			case len(got) > 1:
				t.Fatalf("%d records of %d bytes at most", len(got), bytes)
			case len(got) == 0 && time.Now().After(deadline):
				t.Fatalf("read %v", read)
			case len(got) == 0:
				time.Sleep(10 * time.Millisecond)
			}
			read, from = append(read, principals(got)...), next
		}
		slices.SortFunc(read, func(p, q rbac.Principal) int { return strings.Compare(p.ID, q.ID) })
		if !slices.Equal(read, all) {
			t.Fatalf("read %v", read)
		}
	}
	// Within it, as many as the limit allows.
	rbac.SetMaxHistoryBytes(t, rbac.MaxHistoryBytes)
	if got, _, err := h.authz.History(ctx, cursor, rbac.MaxHistory); err != nil || len(got) != len(all) {
		t.Fatalf("read %d, %v", len(got), err)
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

// History records the eligibility each version of an activation was made through, by its principal
// and its id, which keys the eligibility's own records, and AsOf reads each version so.
func TestHistoryRecordsWhatAnActivationWasMadeThrough(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "oncall", "team")
	u := h.as(t, "u", "oncall", "team")
	for _, g := range []string{"oncall", "team"} {
		if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf(g), MaxDuration: 8 * time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	act := func(d time.Duration) rbac.Grant {
		t.Helper()
		g, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: d, Justification: "incident"})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := act(time.Hour)
	between := dbNow(t, h)
	// Through team, once oncall's is gone, for longer.
	if err := h.authz.DeleteEligibility(ctx, h.as(t, "owner"), cluster, "cluster.sudo", groupOf("oncall")); err != nil {
		t.Fatal(err)
	}
	act(2 * time.Hour)
	rows, err := h.pool.Query(ctx, `SELECT g.op || ' ' || (g.after->>'activated_through') || ' ' || (g.after->>'eligibility_id' = e.key)::text
		FROM rbac_history g JOIN rbac_history e ON e.tenant = g.tenant AND e.entity = 'eligibility' AND e.op = 'create' AND e.principal = g.after->>'activated_through'
		WHERE g.entity = 'grant' AND g.key = $1 ORDER BY g.id`, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(got, []string{"create group:oncall true", "update group:team true"}) {
		t.Fatalf("recorded %v, %v", got, err)
	}
	rebuilt(t, h, dbNow(t, h))
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", between, func(*rbac.Authorizer) error {
		var through string
		var id int64
		if err := tx.QueryRow(ctx, `SELECT g.activated_through, g.eligibility_id - e.id FROM rbac_grants g
			JOIN rbac_eligibilities e ON e.principal = g.activated_through`).Scan(&through, &id); err != nil || through != "group:oncall" || id != 0 {
			t.Errorf("as of the first activation, made through %q, %d from its id, %v", through, id, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
	early, before, now := notes(start), notes(then), notes(dbNow(t, h))
	through := exported(t, h)
	// Only what an export read past goes: nothing at or past the cursor.
	first := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history ORDER BY txid, id LIMIT 1`)
	if n, err := rbac.PruneHistory(ctx, h.pool, then, first); err != nil || n != 0 {
		t.Fatalf("pruning through the first record: %d, %v", n, err)
	}
	// Which deleted nothing, so history still reads as of before then.
	if got, err := notesAt(t, h, start); err != nil || !maps.Equal(got, early) {
		t.Errorf("as of before a prune that deleted nothing: %v, %v", got, err)
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
	// The export goes on from its cursor, and reads the prune that deleted, with what it deleted.
	cursor := through
	if r := drain(t, h, &cursor, 1)[0]; r.Entity != "history" || r.Op != "prune" || r.How != "PruneHistory" ||
		!strings.Contains(string(r.After), `"deleted": 3`) || r.Key != then.UTC().Format("2006-01-02T15:04:05.000000Z") {
		t.Errorf("prune: %+v", r)
	}
	// A prune needs an export's cursor, of this generation, and a time that has passed: AsOf would
	// refuse the present until one to come.
	if _, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h).Add(time.Hour), through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a prune of history up to a time to come: %v", err)
	}
	// Nor one before year 1, which history dates nothing at, and whose record's key would write its
	// year BC as the year AD of the same number, which AsOf would read it as.
	if _, err := rbac.PruneHistory(ctx, h.pool, time.Date(-43, time.March, 15, 0, 0, 0, 0, time.UTC), through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a prune of history up to a time before year 1: %v", err)
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
		// The first versions go oldest first, and the call's records, one for each of its
		// transactions that deleted any, reach the last it deleted.
		var last, reached int64
		if err := h.pool.QueryRow(ctx, `SELECT max(id) FROM (SELECT id FROM rbac_history
			WHERE principal LIKE 'user:changed-%' AND op = 'create' ORDER BY id LIMIT 100) d`).Scan(&last); err != nil {
			t.Fatal(err)
		}
		if n, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil || n != 100 {
			t.Fatalf("PruneHistory = %d, %v", n, err)
		}
		if err := h.pool.QueryRow(ctx, `SELECT max((after->>'reached')::bigint) FROM rbac_history WHERE entity = 'history'`).Scan(&reached); err != nil || reached != last {
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

// A prune's window whose batch another prune of the same deletes some of meanwhile goes on from the
// last record it picked, not from the window's end: the records after its batch, which it never
// judged, are deleted by what follows, and none stays behind where the prune recorded it reached.
func TestPruningGoesOnFromTheLastRecordItPicked(t *testing.T) {
	rbac.SetMaxPrune(t, 2)
	h := setup(t)
	ctx := t.Context()
	// After the creator's grant, four whose first versions go once they changed.
	for _, sql := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		 SELECT 't1', 'cluster', 'c1', 'user', 'g' || i, 'cluster.login' FROM generate_series(1, 4) i`,
		`UPDATE rbac_grants SET note = 'changed' WHERE principal_id LIKE 'g_'`,
	} {
		if _, err := h.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	firsts := func() []int64 {
		t.Helper()
		rows, err := h.pool.Query(ctx, `SELECT id FROM rbac_history WHERE op = 'create' AND principal LIKE 'user:g_' ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	ids := firsts()
	then, through := dbNow(t, h), exported(t, h)
	// The first window, the creator's grant and g1's first version, deletes one; the second, g2's and
	// g3's, picks one, g2's, which the other prune deletes while the window waits for it.
	other, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	var pid int
	if err := other.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	committed := make(chan error, 1)
	windows := 0
	rbac.SetPrunedWindow(t, func(pgx.Tx) {
		if windows++; windows != 1 {
			return
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{{`SELECT set_config('rbac.prune', 'on', true)`, nil}, {`DELETE FROM rbac_history WHERE id = $1`, []any{ids[1]}}} {
			if _, err := other.Exec(ctx, q.sql, q.args...); err != nil {
				committed <- err
				return
			}
		}
		go func() {
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				var waiting bool
				if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY (pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
					committed <- err
					return
				}
				if waiting {
					committed <- other.Commit(ctx)
					return
				}
			}
			committed <- errors.New("the second window never waited for the other prune")
		}()
	})
	if n, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil || n != 2 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	for {
		n, err := rbac.PruneHistory(ctx, h.pool, then, through)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	if left := firsts(); len(left) != 0 {
		t.Fatalf("first versions %v left of %v", left, ids)
	}
}

// A prune reads history a window at a time, each in a transaction of its own, which reads as much
// of history however long it is, so a call that finds little to delete in a long history holds no
// export back for long; and it deletes what one transaction reading all of it would.
func TestPruningALongHistoryReadsAsMuchInEachTransaction(t *testing.T) {
	rbac.SetMaxPrune(t, 100)
	// The most pages of history and its indexes one of the prune's transactions reads, behind as
	// many grants of which three changed.
	most := func(t *testing.T, grants int) int64 {
		t.Helper()
		h := setup(t)
		ctx := t.Context()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', 'c1', 'user', 'u' || i, 'cluster.login' FROM generate_series(1, $1::int) i`, grants); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'changed' WHERE principal_id IN ('u1', 'u2', 'u3')`); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
		then, through := dbNow(t, h), exported(t, h)
		// On a connection of its own, whose session counts what each transaction reads on from the
		// last, until it reports them and counts from none.
		conn, err := h.pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		var last, pages int64
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			last = historyPages(ctx, t, tx)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		transactions := 0
		rbac.SetPrunedWindow(t, func(tx pgx.Tx) {
			read := historyPages(ctx, t, tx)
			if read >= last {
				read, last = read-last, read
			} else {
				last = read
			}
			pages, transactions = max(pages, read), transactions+1
		})
		if n, err := rbac.PruneHistory(ctx, conn.Conn(), then, through); err != nil || n != 3 {
			t.Fatalf("PruneHistory = %d, %v", n, err)
		}
		if transactions < grants/100 {
			t.Fatalf("read %d records of history in %d transactions", grants, transactions)
		}
		if got, err := notesAt(t, h, then); err != nil || len(got) != grants+1 || got["u1"] != "changed" {
			t.Fatalf("as of then, after pruning: %d grants, u1 %q, %v", len(got), got["u1"], err)
		}
		return pages
	}
	if few, many := most(t, 1000), most(t, 4000); many > few*11/10 {
		t.Fatalf("a prune's transactions read up to %d pages of history behind 1000 grants, and %d behind 4000", few, many)
	}
}

// AsOf reads the latest prune's time from one record, which history's index finds by its key: what
// it reads of history doesn't grow with the prunes recorded, which no prune removes, and a prune
// recorded later can be of an earlier time.
func TestAsOfReadsOnlyTheLatestPrune(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// As many prunes, of times in the year before last, recorded as history's owner writes them.
	prunes := func(n int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
			SELECT now(), '', 'history', to_char(b AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'prune',
			  jsonb_build_object('before', b, 'through', jsonb_build_object('txid', '1', 'id', 1), 'deleted', 1, 'reached', 1), 'PruneHistory'
			FROM (SELECT now() - interval '2 years' + random() * interval '1 year' AS b FROM generate_series(1, $1)) p`, n); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
	}
	// The pages of history and its indexes an AsOf as of at reads, under a transaction of the test's.
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := historyPages(ctx, t, tx)
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); err != nil {
			t.Fatal(err)
		}
		return historyPages(ctx, t, tx) - start
	}
	prunes(1)
	few := read(dbNow(t, h))
	prunes(20000)
	if many := read(dbNow(t, h)); many > few+10 {
		t.Fatalf("AsOf read %d pages of history beside a prune's record, and %d beside 20,000", few, many)
	}
	var latest time.Time
	if err := h.pool.QueryRow(ctx, `SELECT max((after->>'before')::timestamptz) FROM rbac_history WHERE entity = 'history'`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", latest.Add(-time.Microsecond), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf just before the latest prune's time: %v", err)
	}
	if err := h.authz.AsOf(ctx, "t1", latest, func(*rbac.Authorizer) error { return nil }); err != nil {
		t.Errorf("AsOf at the latest prune's time: %v", err)
	}
}
