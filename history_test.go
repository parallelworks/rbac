package rbac_test

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	mrand "math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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

// History reads records in the order of the transactions that wrote them, by the id each takes at
// its first write, not in the order of each row's changes: a transaction that took its id first and
// changed a row after another committed a change to it is read first, though its change came after.
// A row's versions order by their records' ids, as AsOf reads them.
func TestHistoryReadsTransactionsInOrderNotEachRowsChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	h.as(t, "v")
	if _, err := h.pool.Exec(ctx, grantLogin, "u"); err != nil {
		t.Fatal(err)
	}
	cursor := exported(t, h)
	first, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Rollback(ctx) }()
	const note = `UPDATE rbac_grants SET note = $1 WHERE principal = 'user:u'`
	if _, err := first.Exec(ctx, `UPDATE rbac_memberships SET note = 'first' WHERE principal = 'user:v'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, note, "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Exec(ctx, note, "last"); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var changes []rbac.Record
	for _, r := range drain(t, h, &cursor, 3) {
		if r.Entity == "grant" {
			changes = append(changes, r)
		}
	}
	if len(changes) != 2 || !strings.Contains(string(changes[0].After), `"last"`) || !strings.Contains(string(changes[1].After), `"second"`) ||
		changes[0].ID < changes[1].ID {
		t.Fatalf("History reads the grant's changes %+v", changes)
	}
	if got, err := notesAt(t, h, dbNow(t, h)); err != nil || got["u"] != "last" {
		t.Errorf("as of now: %v, %v", got, err)
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

// Recording a row reads its key's last record: a plan its session keeps, made while history was
// small, as a new deployment's first rows are recorded, scans history, and one made for each row
// reads, until history is analyzed, all of the tenant's records of the entity, so a statement
// writing many rows would read nearly all of history for each. A statement writing many rows reads
// as much of history for each as one writing few, however a session plans its statements.
func TestRecordingARowReadsAsMuchOfHistoryHoweverManyItsStatementWrites(t *testing.T) {
	for _, mode := range []string{"auto", "force_generic_plan", "force_custom_plan"} {
		t.Run(mode, func(t *testing.T) {
			// The pages of history and its indexes read for each row a statement writes then
			// deletes, all in one tenant, in a session of its own that has recorded only the harness's
			// one grant until then.
			perRow := func(n int) float64 {
				t.Helper()
				h := setupOn(t, pgtest.Open(t, "pool_max_conns=1&plan_cache_mode="+mode))
				ctx := t.Context()
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				start := pagesRead(ctx, t, tx, "rbac_history")
				for _, sql := range []string{
					`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					 SELECT 't1', 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.admin' FROM generate_series(1, $1) i`,
					`DELETE FROM rbac_grants WHERE $1 > 0`,
				} {
					if _, err := tx.Exec(ctx, sql, n); err != nil {
						t.Fatal(err)
					}
				}
				return float64(pagesRead(ctx, t, tx, "rbac_history")-start) / float64(n)
			}
			few, many := perRow(500), perRow(5000)
			// Both ways: another session making or dropping a schema, as each test does, has every
			// session plan its statements anew, so a plan that scans history, made again partway
			// through the larger statement by history's size then, reads less for each of its rows
			// than the smaller statement's.
			if many > few*3/2 || few > many*3/2 {
				t.Errorf("writing 500 grants then deleting them read %.0f pages of history for each, and %.0f for 5,000", few, many)
			}
		})
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

// readmeRoles are the README's database roles, made for a test and dropped when it ends: the
// administrator's, which owns a schema of its own and the one beside it for AsOf's views, made for
// it as it may make no schema, and is a member of history's; and the application's, each with a
// pool on that schema.
type readmeRoles struct {
	admin, history, app, schema string
	super                       *pgx.Conn
	adminPool, appPool          *pgxpool.Pool
}

func newReadmeRoles(t *testing.T) *readmeRoles {
	t.Helper()
	return newReadmeRolesIn(t, pgtest.URL(t))
}

// newReadmeRolesIn is newReadmeRoles in the database base, a URL, names: a test's own database, as
// one that changes a database-wide privilege needs.
func newReadmeRolesIn(t *testing.T, base string) *readmeRoles {
	t.Helper()
	ctx := t.Context()
	suffix := strings.ToLower(rand.Text())
	r := &readmeRoles{admin: "rbac_admin_" + suffix, history: "rbac_history_" + suffix, app: "rbac_app_" + suffix, schema: "rbac_" + suffix}
	super, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	r.super = super
	t.Cleanup(func() { _ = super.Close(context.WithoutCancel(ctx)) })
	if err := pgx.BeginFunc(ctx, super, func(tx pgx.Tx) error {
		for _, sql := range []string{
			`CREATE ROLE ` + r.admin + ` LOGIN`, `CREATE ROLE ` + r.history, `CREATE ROLE ` + r.app + ` LOGIN`,
			`GRANT ` + r.history + ` TO ` + r.admin,
			`CREATE SCHEMA ` + r.schema + ` AUTHORIZATION ` + r.admin,
			`CREATE SCHEMA ` + r.schema + `_as_of AUTHORIZATION ` + r.admin,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return fmt.Errorf("%s: %w", sql, err)
			}
		}
		return nil
	}); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			pgtest.Skip(t, "the test database's role can't create roles")
		}
		t.Fatal(err)
	}
	// Before the pools close, as cleanups run last first.
	t.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		for _, sql := range []string{
			`DROP SCHEMA ` + pgtest.WithViews(r.schema) + ` CASCADE`,
			`DROP OWNED BY ` + r.admin + `, ` + r.history + `, ` + r.app + ` CASCADE`,
			`DROP ROLE ` + r.app + `, ` + r.admin + `, ` + r.history,
		} {
			if _, err := super.Exec(ctx, sql); err != nil {
				t.Errorf("%s: %v", sql, err)
			}
		}
	})
	for _, p := range []struct {
		pool **pgxpool.Pool
		user string
	}{{&r.adminPool, r.admin}, {&r.appPool, r.app}} {
		cfg, err := pgxpool.ParseConfig(base)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ConnConfig.User = p.user
		cfg.ConnConfig.RuntimeParams["search_path"] = r.schema
		if *p.pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		t.Cleanup((*p.pool).Close)
	}
	return r
}

// harden gives history to history's role, and the application's role its privileges, exactly as
// the README's steps 2 and 3 say, with no role executing a function of the package's that they
// don't list, as every role may unless it is revoked. The application's makes no schema and
// creates in none, as step 4 says, unless the database's owner or a grant lets it. Hardened before
// the migration that makes AsOf's views, the application's role is given none of them, as that
// migration gives them, and their schema, to each role that may read history.
func (r *readmeRoles) harden(t *testing.T) {
	t.Helper()
	s := r.schema
	var views bool
	if err := r.super.QueryRow(t.Context(), `SELECT to_regclass($1 || '_as_of.rbac_grants') IS NOT NULL`, s).Scan(&views); err != nil {
		t.Fatal(err)
	}
	// Of those step 3 lists, the functions made by now: hardened before a later migration made one,
	// the schema gets it as every role does, from PUBLIC.
	var made []string
	if err := r.super.QueryRow(t.Context(), `SELECT array_agg($1 || '.' || proname ORDER BY proname) FROM pg_proc
		WHERE pronamespace = $1::regnamespace AND proname = ANY($2::text[])`,
		s, []string{"rbac_group_members", "rbac_tenant_keys", "rbac_text_array", "rbac_changes_grants", "rbac_expired_through"}).Scan(&made); err != nil {
		t.Fatal(err)
	}
	// Where a migration has made the function DeleteExpired records its times through, the
	// application's role writes rbac_expired only through it.
	through := slices.Contains(made, s+".rbac_expired_through")
	// Of the functions step 2 lists, the commit record's, where a migration has made it.
	var commit bool
	if err := r.super.QueryRow(t.Context(), `SELECT to_regprocedure($1 || '.rbac_history_commit()') IS NOT NULL`, s).Scan(&commit); err != nil {
		t.Fatal(err)
	}
	owned := []string{`ALTER FUNCTION ` + s + `.rbac_record() OWNER TO ` + r.history}
	if commit {
		owned = append(owned, `ALTER FUNCTION `+s+`.rbac_history_commit() OWNER TO `+r.history)
	}
	grants := slices.Concat([]string{
		`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ` + s + ` FROM PUBLIC`,
		// 2. History's role owns history, rbac_record and rbac_history_commit, given them by a
		// superuser, and needs USAGE on the schema and EXECUTE on rbac_tenant_keys and
		// rbac_text_array.
		`ALTER TABLE ` + s + `.rbac_history OWNER TO ` + r.history,
	}, owned, []string{
		`GRANT USAGE ON SCHEMA ` + s + ` TO ` + r.history,
		`GRANT EXECUTE ON FUNCTION ` + s + `.rbac_tenant_keys, ` + s + `.rbac_text_array TO ` + r.history,
		// 3. The application's role has USAGE on the schema, SELECT, INSERT, UPDATE and DELETE on
		// its tables but rbac_history and rbac_migrations, EXECUTE on rbac_group_members,
		// rbac_tenant_keys, rbac_text_array, rbac_changes_grants and rbac_expired_through, only
		// SELECT on rbac_history and rbac_expired, and USAGE on the schema of AsOf's views and SELECT
		// on them.
		`GRANT USAGE ON SCHEMA ` + s + ` TO ` + r.app,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ` + s + ` TO ` + r.app,
		`REVOKE ALL ON ` + s + `.rbac_migrations FROM ` + r.app,
		`GRANT EXECUTE ON FUNCTION ` + strings.Join(made, ", ") + ` TO ` + r.app,
		`REVOKE INSERT, UPDATE, DELETE ON ` + s + `.rbac_history FROM ` + r.app,
	})
	if through {
		grants = append(grants, `REVOKE INSERT, UPDATE, DELETE ON `+s+`.rbac_expired FROM `+r.app)
	}
	if views {
		grants = append(grants, `GRANT USAGE ON SCHEMA `+s+`_as_of TO `+r.app, `GRANT SELECT ON ALL TABLES IN SCHEMA `+s+`_as_of TO `+r.app)
	}
	for _, sql := range grants {
		if _, err := r.super.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
}

// expiredRecord is a record of a row of rbac_expired's: its key, the row's time, as JSON writes it
// in UTC, as the row became or, where it was deleted, as it was, its op, how, and the database role
// that wrote it.
type expiredRecord struct{ key, until, op, how, dbUser string }

// expiredRecords is history's records of rbac_expired's rows, in the order written, each of which
// is in no tenant and keyed by its row's id.
func expiredRecords(t *testing.T, q rbac.DB) []expiredRecord {
	t.Helper()
	rows, err := q.Query(t.Context(), `SELECT tenant, coalesce(after, before)->>'id', key, coalesce(after, before)->>'until', op, how, db_user
		FROM rbac_history WHERE entity = 'expired' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []expiredRecord
	var r expiredRecord
	var tenant, id string
	if _, err := pgx.ForEachRow(rows, []any{&tenant, &id, &r.key, &r.until, &r.op, &r.how, &r.dbUser}, func() error {
		if tenant != "" || r.key != id {
			t.Errorf("history records rbac_expired's row %s in tenant %q, keyed by %q", id, tenant, r.key)
		}
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

// expiredTime is a time of rbac_expired's as JSON writes it, in UTC, as history's records hold it.
func expiredTime(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05.999999-07:00") }

// expiredID is the id of the row of rbac_expired holding until, of which there must be one.
func expiredID(t *testing.T, q rbac.DB, until time.Time) string {
	t.Helper()
	var ids []string
	if err := q.QueryRow(t.Context(), `SELECT array_agg(id::text) FROM rbac_expired WHERE until = $1`, until).Scan(&ids); err != nil || len(ids) != 1 {
		t.Fatalf("rbac_expired holds %v rows of %v: %v", ids, until, err)
	}
	return ids[0]
}

// Under the README's roles, DeleteExpired, on the application's role, records the time it deleted
// by, which that role otherwise writes only through rbac_expired_through, as DeleteExpired does: it
// may insert, update, delete or truncate no time, so it can't move the latest back, and through the
// function it records none past the database's clock, nor moves the latest back. History records
// each write as that role's.
func TestTheApplicationsRoleWritesExpiredOnlyAsDeleteExpiredDoes(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatal(err)
	}
	r.harden(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	authz, err := rbac.New(r.appPool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
		Now:           func() time.Time { return base },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.appPool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'y', 'cluster.login', $1)`, base.Add(-30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n, err := authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired on the application's role removed %d rows: %v", n, err)
	}
	for _, w := range []struct{ sql, code string }{
		{`INSERT INTO rbac_expired (until) VALUES ('2026-01-01 11:45:00+00')`, "42501"},
		{`UPDATE rbac_expired SET until = until - interval '1 hour'`, "42501"},
		{`DELETE FROM rbac_expired`, "42501"},
		{`TRUNCATE rbac_expired`, "42501"},
		{`SELECT rbac_expired_through(clock_timestamp() + interval '1 hour')`, "23514"},
		{`SELECT rbac_expired_through('2026-01-01 11:00:00+00')`, ""},
	} {
		if _, err := r.appPool.Exec(ctx, w.sql); sqlState(err) != w.code {
			t.Errorf("the application's role: %s = %v, not %q", w.sql, err, w.code)
		}
	}
	var latest time.Time
	if err := r.appPool.QueryRow(ctx, `SELECT max(until) FROM rbac_expired`).Scan(&latest); err != nil || !latest.Equal(base.Add(-30*time.Minute)) {
		t.Errorf("the latest time DeleteExpired deleted by is %v: %v", latest, err)
	}
	recorded, written := base.Add(-30*time.Minute), base.Add(-time.Hour)
	want := []expiredRecord{
		{expiredID(t, r.appPool, recorded), expiredTime(recorded), "create", "DeleteExpired", r.app},
		{expiredID(t, r.appPool, written), expiredTime(written), "create", "", r.app},
	}
	if got := expiredRecords(t, r.appPool); !slices.Equal(got, want) {
		t.Errorf("history records rbac_expired's writes as %q, want %q", got, want)
	}
}

// The commit record's function, which writes history as its owner, is given as it is made to the
// owner of rbac_record, history's role where the README's roles are set up: where history's role may
// create in the schema; where it may not but the role migrating owns the schema, which lends it
// CREATE for the migration alone; and where neither holds, or the role migrating may not SET ROLE to
// history's role, migrating fails, saying which to fix, and lending nothing, and once fixed gives it.
// A superuser's migration fails alike, as it migrates as the role owning the tables, so the hint
// offers none. Whatever the schema's default privileges grant, no role may execute it, nor rbac_record, which
// writes history as its owner too, and a change by the application's role commits with its commit
// record.
func TestMigratingGivesTheCommitRecordsFunctionToHistorysRole(t *testing.T) {
	var made string
	sqls := migrationSQL(t)
	for _, name := range slices.Sorted(maps.Keys(sqls)) {
		if strings.Contains(sqls[name], "CREATE FUNCTION rbac_history_commit()") {
			made = name
			break
		}
	}
	if made == "" {
		t.Fatal("no migration makes the commit record's function")
	}
	for _, c := range []string{"history's role creates", "the schema's owner lends", "no one lends", "the role migrating may not SET ROLE"} {
		t.Run(c, func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			super := func(sqls ...string) {
				t.Helper()
				for _, sql := range sqls {
					if _, err := r.super.Exec(ctx, sql); err != nil {
						t.Fatalf("%s: %v", sql, err)
					}
				}
			}
			// As a host's own default privileges might, for the functions it makes there, rbac_record
			// among them.
			super(`ALTER DEFAULT PRIVILEGES FOR ROLE ` + r.admin + ` IN SCHEMA ` + r.schema + ` GRANT EXECUTE ON FUNCTIONS TO ` + r.app)
			if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", made); err != nil {
				t.Fatal(err)
			}
			recordMigrations(t, r.adminPool, made)
			r.harden(t)
			// Migrating fails, with hint, and leaves history's role no CREATE it was lent: as a superuser
			// too, which migrates as the administrator's role, owning the tables, so the hint offers no
			// superuser's migration.
			superuser := superuserOn(t, r.schema)
			refused := func(where, hint string) {
				t.Helper()
				for _, db := range []rbac.DB{r.adminPool, superuser} {
					err := rbac.Migrate(ctx, db)
					if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" ||
						!strings.Contains(pgErr.Message, "rbac_history_commit") || !strings.Contains(pgErr.Hint, hint) || strings.Contains(pgErr.Hint, "superuser") {
						t.Fatalf("migrating where %s: %v", where, err)
					}
					var creates bool
					if err := r.super.QueryRow(ctx, `SELECT has_schema_privilege($1, $2, 'CREATE')`, r.history, r.schema).Scan(&creates); err != nil || creates {
						t.Fatalf("history's role may create in the schema after migrating failed: %t, %v", creates, err)
					}
				}
			}
			switch c {
			case "history's role creates":
				super(`GRANT CREATE ON SCHEMA ` + r.schema + ` TO ` + r.history)
			case "no one lends":
				super(`ALTER SCHEMA `+r.schema+` OWNER TO CURRENT_USER`, `GRANT USAGE, CREATE ON SCHEMA `+r.schema+` TO `+r.admin)
				refused("no role may give history's role CREATE on the schema", "Grant "+r.history+" CREATE on schema "+r.schema)
				super(`GRANT CREATE ON SCHEMA ` + r.schema + ` TO ` + r.history)
			case "the role migrating may not SET ROLE":
				// A member still, with the rights of history's owner.
				super(`GRANT ` + r.history + ` TO ` + r.admin + ` WITH SET FALSE`)
				refused("the role migrating may not SET ROLE to history's role", "Grant "+r.history+" to "+r.admin+" with the SET option")
				super(`GRANT ` + r.history + ` TO ` + r.admin + ` WITH SET TRUE`)
			}
			if err := rbac.Migrate(ctx, r.adminPool); err != nil {
				t.Fatal(err)
			}
			var owner string
			var executes, records, creates bool
			if err := r.super.QueryRow(ctx, `SELECT p.proowner::regrole::text, has_function_privilege($2, p.oid, 'EXECUTE'),
				has_function_privilege($2, ($1 || '.rbac_record()')::regprocedure, 'EXECUTE'), has_schema_privilege($3, $1, 'CREATE')
				FROM pg_proc p WHERE p.oid = ($1 || '.rbac_history_commit()')::regprocedure`, r.schema, r.app, r.history).Scan(&owner, &executes, &records, &creates); err != nil {
				t.Fatal(err)
			}
			if owner != r.history || executes || records {
				t.Errorf("the commit record's function is %s's, not %s's, and the application's role may execute it: %t, and rbac_record: %t", owner, r.history, executes, records)
			}
			if lent := c == "the schema's owner lends" || c == "the role migrating may not SET ROLE"; creates == lent {
				t.Errorf("history's role may create in the schema after migrating: %t", creates)
			}
			var commits int
			if _, err := r.appPool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'u')`); err != nil {
				t.Fatal(err)
			}
			if err := r.appPool.QueryRow(ctx, `SELECT count(*) FROM rbac_history c WHERE c.entity = 'commit'
				AND c.txid = (SELECT m.txid FROM rbac_history m WHERE m.entity = 'membership' AND m.key = 'user:u')`).Scan(&commits); err != nil || commits != 1 {
				t.Errorf("the application's change has %d commit records: %v", commits, err)
			}
		})
	}
}

// strangers are the package's schema and the views', and the objects in them, that neither the
// administrator's role nor history's owns: what a migration made as another role.
func (r *readmeRoles) strangers(t *testing.T) []string {
	t.Helper()
	return notOwned(t, r.super, r.schema, r.admin, r.history)
}

// notOwned are schema and the schema of AsOf's views beside it, and the objects in them, that none
// of roles owns, as db reads them.
func notOwned(t *testing.T, db rbac.DB, schema string, roles ...string) []string {
	t.Helper()
	var got []string
	if err := db.QueryRow(t.Context(), `WITH ours AS (SELECT oid FROM pg_roles WHERE rolname = ANY ($2::text[])),
		  s AS (SELECT oid, nspname, nspowner FROM pg_namespace WHERE nspname::text IN ($1::text, $1::text || '_as_of'))
		SELECT ARRAY(SELECT 'schema ' || s.nspname FROM s WHERE s.nspowner NOT IN (SELECT oid FROM ours)
		  UNION ALL SELECT c.oid::regclass::text FROM pg_class c JOIN s ON s.oid = c.relnamespace WHERE c.relowner NOT IN (SELECT oid FROM ours)
		  UNION ALL SELECT p.oid::regprocedure::text FROM pg_proc p JOIN s ON s.oid = p.pronamespace WHERE p.proowner NOT IN (SELECT oid FROM ours)
		  ORDER BY 1)`, schema, roles).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

// asOf reads as of now as the application's role.
func (r *readmeRoles) asOf(ctx context.Context, t *testing.T) error {
	t.Helper()
	authz, err := rbac.New(r.appPool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err := r.appPool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return authz.AsOf(ctx, "t1", now, func(a *rbac.Authorizer) error {
		_, err := a.Permissions(ctx, rbac.Subject{Principal: identity("u")}, cluster)
		return err
	})
}

// readsAsOf fails t unless the application's role reads as of a time, and the administrator's makes
// AsOf's views again.
func (r *readmeRoles) readsAsOf(t *testing.T) {
	t.Helper()
	if err := r.asOf(t.Context(), t); err != nil {
		t.Errorf("AsOf as the application's role: %v", err)
	}
	if _, err := r.adminPool.Exec(t.Context(), `SELECT rbac_as_of_views()`); err != nil {
		t.Errorf("rbac_as_of_views() as the administrator's role: %v", err)
	}
}

// madeViews is the migration that makes AsOf's views, and its version.
func madeViews(t *testing.T) (string, int) {
	t.Helper()
	sqls := migrationSQL(t)
	for _, name := range slices.Sorted(maps.Keys(sqls)) {
		if strings.Contains(sqls[name], "CREATE FUNCTION rbac_as_of_views()") {
			var v int
			if _, err := fmt.Sscanf(name, "%04d_", &v); err != nil {
				t.Fatal(err)
			}
			return name, v
		}
	}
	t.Fatal("no migration makes AsOf's views")
	return "", 0
}

// Only the role owning the package's tables migrates them, as a migration makes what it makes its
// maker's, and from 0028_as_of_views on checks the schema of AsOf's views against it: a superuser
// migrates as that role. Where the README's administrator's role migrated part of the way, from
// where it had made only the first tables, from before AsOf's views or after them, or with one
// migration pending, a superuser's migration, on transactions of its own or a host's, leaves the
// package's schema and the views', and every object in them, that role's or history's, and the
// host's transaction running as the superuser it set its role to before, not as the session's; and
// the application's role reads as of a time, and the
// administrator's makes the views again. Migrating as itself, a superuser made what it migrated
// its own, and failed at the first migration making AsOf's views, whose schema was the
// administrator's: 0028 where that was pending, and 0033 after it, having made rbac_expired and
// rbac_expired_through its own.
func TestASuperuserMigratesTheTablesAsTheirOwner(t *testing.T) {
	names, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	made, _ := madeViews(t)
	after := names[slices.Index(names, made)+1]
	for _, c := range []struct {
		from string
		host bool
	}{{names[1], false}, {made, false}, {after, false}, {after, true}, {names[len(names)-1], false}} {
		t.Run(fmt.Sprintf("from %s, on a host's transaction %t", c.from, c.host), func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", c.from); err != nil {
				t.Fatal(err)
			}
			recordMigrations(t, r.adminPool, c.from)
			// History's role takes history over once it is made.
			var history bool
			if err := r.super.QueryRow(ctx, `SELECT to_regclass($1 || '.rbac_history') IS NOT NULL`, r.schema).Scan(&history); err != nil {
				t.Fatal(err)
			}
			if history {
				r.harden(t)
			}
			superuser := superuserOn(t, r.schema)
			if c.host {
				// The host's transaction runs as another superuser, by SET LOCAL ROLE, which it runs as again
				// after, and not as the session's.
				other := "rbac_super_" + strings.TrimPrefix(r.schema, "rbac_")
				if _, err := r.super.Exec(ctx, `CREATE ROLE `+other+` SUPERUSER`); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := r.super.Exec(context.WithoutCancel(ctx), `DROP ROLE `+other); err != nil {
						t.Errorf("DROP ROLE %s: %v", other, err)
					}
				})
				err = pgx.BeginFunc(ctx, superuser, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+other); err != nil {
						return err
					}
					if err := rbac.Migrate(ctx, tx); err != nil {
						return err
					}
					var current string
					if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil {
						return err
					}
					if current != other {
						return fmt.Errorf("the host's transaction runs as %s after Migrate, not as %s", current, other)
					}
					return nil
				})
			} else {
				err = rbac.Migrate(ctx, superuser)
			}
			if err != nil {
				t.Fatalf("Migrate as a superuser: %v", err)
			}
			if v := migratedTo(t, r.adminPool); v != latestMigration(t) {
				t.Errorf("migrated to %d", v)
			}
			if !history {
				r.harden(t)
			}
			if s := r.strangers(t); len(s) > 0 {
				t.Errorf("a superuser's migration left %v another role's", s)
			}
			r.readsAsOf(t)
		})
	}
}

// Where the schema of AsOf's views isn't made, as the README has a superuser make it for the
// administrator's role, a superuser's migration from before 0028_as_of_views fails there, as that
// role's does, saying so, and having made nothing its own, and once the schema is made, migrates.
// Migrating as itself, it made the schema and the views its own, and AsOf, which reads the views of
// the role owning the tables, refused every read, saying to migrate to a migration recorded.
func TestASuperuserMakesAsOfsViewsAsTheTablesOwner(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	views := r.schema + "_as_of"
	if _, err := r.super.Exec(ctx, `DROP SCHEMA `+views); err != nil {
		t.Fatal(err)
	}
	made, version := madeViews(t)
	if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", made); err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, r.adminPool, made)
	r.harden(t)
	superuser := superuserOn(t, r.schema)
	err := rbac.Migrate(ctx, superuser)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" ||
		!strings.Contains(pgErr.Hint, "CREATE SCHEMA "+views+" AUTHORIZATION "+r.admin) {
		t.Fatalf("Migrate as a superuser where the views' schema isn't made: %v", err)
	}
	if v := migratedTo(t, r.adminPool); v != version-1 {
		t.Errorf("migrated to %d", v)
	}
	if s := r.strangers(t); len(s) > 0 {
		t.Errorf("a superuser's migration that failed left %v another role's", s)
	}
	if _, err := r.super.Exec(ctx, `CREATE SCHEMA `+views+` AUTHORIZATION `+r.admin); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(ctx, superuser); err != nil {
		t.Fatalf("Migrate as a superuser once the views' schema is made: %v", err)
	}
	if s := r.strangers(t); len(s) > 0 {
		t.Errorf("a superuser's migration left %v another role's", s)
	}
	r.readsAsOf(t)
}

// Migrate as a role that doesn't own the package's tables and is no superuser is refused, saying to
// migrate as the role that does, before it applies anything or takes a lock, so it doesn't wait for
// another replica's migration first: as the application's role, and as a member of the
// administrator's, whose migration would make what it makes its own. Each waited for the other
// replica, and the member's then made its own what it migrated; and the refusal said to migrate as
// the schema.
func TestMigrateAsARoleNotOwningTheTablesIsRefused(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	made, version := madeViews(t)
	if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", made); err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, r.adminPool, made)
	r.harden(t)
	member := "rbac_member_" + strings.ToLower(rand.Text())
	if _, err := r.super.Exec(ctx, `CREATE ROLE `+member+`; GRANT `+r.admin+` TO `+member); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := r.super.Exec(context.WithoutCancel(ctx), `DROP ROLE `+member); err != nil {
			t.Errorf("DROP ROLE %s: %v", member, err)
		}
	})
	superuser := superuserOn(t, r.schema)
	replica, err := superuser.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replica.Rollback(context.WithoutCancel(ctx)) }()
	sql, args := rbac.MigrateLock(r.schema)
	if _, err := replica.Exec(ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = r.schema
	for _, role := range []string{r.app, member} {
		func() {
			conn, err := pgx.ConnectConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
			if _, err := conn.Exec(ctx, `SET ROLE `+role); err != nil {
				t.Fatal(err)
			}
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := rbac.Migrate(bounded, conn); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+r.admin+",") {
				t.Errorf("Migrate as %s, beside another replica's migration: %v", role, err)
			}
		}()
	}
	if err := replica.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if v := migratedTo(t, r.adminPool); v != version-1 {
		t.Errorf("migrated to %d", v)
	}
	if s := r.strangers(t); len(s) > 0 {
		t.Errorf("a refused migration left %v another role's", s)
	}
}

// Replicas of a superuser and of the role owning the package's tables, migrating at once, each
// decide who they migrate as once they hold the schema's lock, as the replica they waited for can
// have made the tables, or given them to another role, meanwhile: every migration is made as the
// role that made the first, or as the one they were given to, and a replica that is neither that
// role nor a superuser is refused, as ErrInvalid naming it, on transactions of their own or, for the
// superuser's, a host's, which runs as it did after; a superuser's replica that takes the lock first
// on the administrator's schema, holding none of the tables, is refused, naming that role, which
// then migrates. Deciding before the lock, a superuser's
// replica that read no tables made the next migration's its own once the other had made the first,
// and both failed at 0003_history with SQLSTATE 42501, as every Migrate after did, or, on a host's
// transaction, made every one after its own and failed at 0028_as_of_views; a replica of the
// administrator's role that read none failed with SQLSTATE 42501 reading rbac_migrations, the
// superuser's, rather than being refused; and once the tables were given to another role, the
// administrator's replica, which read them its own, and the superuser's, which read them that
// role's, both migrated as that role, which could no longer use the schema.
func TestReplicasDecideWhoMigratesOnceTheyHoldTheSchemasLock(t *testing.T) {
	names, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		// theirs: the package's schema is the superuser's, which lets the administrator's role create
		// in it, and so is the views' where the superuser's replica migrates first.
		theirs, superuserFirst, host bool
		// given: the administrator's role made the first tables, which are given to the application's
		// role while both replicas wait.
		given bool
	}{
		{name: "the administrator's schema, its replica first"},
		{name: "the administrator's schema, the superuser's replica first", superuserFirst: true},
		{name: "the superuser's schema, the administrator's replica first", theirs: true},
		{name: "the superuser's schema, the administrator's replica first, the superuser's on a host's transaction", theirs: true, host: true},
		{name: "the superuser's schema, its replica first", theirs: true, superuserFirst: true},
		{name: "the tables given to another role as both wait", given: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			superuser := superuserOn(t, r.schema)
			var me string
			if err := r.super.QueryRow(ctx, `SELECT current_user`).Scan(&me); err != nil {
				t.Fatal(err)
			}
			// The role every object is made as, and whether the administrator's replica is refused.
			owner, refused := r.admin, false
			switch {
			case c.given:
				owner, refused = r.app, true
			case c.theirs && c.superuserFirst:
				owner, refused = me, true
			}
			if c.theirs {
				sqls := []string{`ALTER SCHEMA ` + r.schema + ` OWNER TO CURRENT_USER`, `GRANT USAGE, CREATE ON SCHEMA ` + r.schema + ` TO ` + r.admin}
				if c.superuserFirst {
					sqls = append(sqls, `ALTER SCHEMA `+r.schema+`_as_of OWNER TO CURRENT_USER`)
				}
				for _, sql := range sqls {
					if _, err := r.super.Exec(ctx, sql); err != nil {
						t.Fatalf("%s: %v", sql, err)
					}
				}
			}
			if c.given {
				if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", names[1]); err != nil {
					t.Fatal(err)
				}
				recordMigrations(t, r.adminPool, names[1])
			}
			bounded, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			holder, err := superuser.Begin(bounded)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = holder.Rollback(context.WithoutCancel(ctx)) }()
			var pid uint32
			if err := holder.QueryRow(bounded, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			sql, args := rbac.MigrateLock(r.schema)
			if _, err := holder.Exec(bounded, sql, args...); err != nil {
				t.Fatal(err)
			}
			type replica struct {
				migrate func() error
				done    chan error
			}
			admin := replica{func() error { return rbac.Migrate(bounded, r.adminPool) }, make(chan error, 1)}
			super := replica{func() error {
				if !c.host {
					return rbac.Migrate(bounded, superuser)
				}
				return pgx.BeginFunc(bounded, superuser, func(tx pgx.Tx) error {
					if err := rbac.Migrate(bounded, tx); err != nil {
						return err
					}
					var current string
					if err := tx.QueryRow(bounded, `SELECT current_user`).Scan(&current); err != nil {
						return err
					}
					if current != me {
						return fmt.Errorf("the host's transaction runs as %s after Migrate, not as %s", current, me)
					}
					return nil
				})
			}, make(chan error, 1)}
			replicas := []replica{admin, super}
			if c.superuserFirst {
				slices.Reverse(replicas)
			}
			for i, p := range replicas {
				go func() { p.done <- p.migrate() }()
				waitingBehind(bounded, t, r.super, pid, i+1, p.done)
			}
			if c.given {
				if _, err := holder.Exec(bounded, `REASSIGN OWNED BY `+r.admin+` TO `+r.app); err != nil {
					t.Fatal(err)
				}
				err = holder.Commit(bounded)
			} else {
				err = holder.Rollback(bounded)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The superuser's replica that finds no tables in the administrator's schema makes none.
			if err := <-super.done; !c.theirs && !c.given && c.superuserFirst {
				if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+r.admin+",") {
					t.Errorf("the superuser's replica, first on the administrator's schema: %v", err)
				}
			} else if err != nil {
				t.Errorf("the superuser's replica: %v", err)
			}
			if err := <-admin.done; refused && (!errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+owner+",")) || !refused && err != nil {
				t.Errorf("the administrator's replica, where %s owns the tables: %v", owner, err)
			}
			if v := migratedTo(t, superuser); v != latestMigration(t) {
				t.Errorf("migrated to %d", v)
			}
			// The package's schema stays the superuser's where it lets the administrator's role create in it.
			var want []string
			if c.theirs && owner != me {
				want = []string{"schema " + r.schema}
			}
			if got := notOwned(t, r.super, r.schema, owner); !slices.Equal(got, want) {
				t.Errorf("migrating left %v another role's than %s", got, owner)
			}
		})
	}
}

// waitingBehind returns once n sessions wait for a lock the session pid holds, as db reads them,
// or fails t once ctx ends, or where done, the last session's call, ends first.
func waitingBehind(ctx context.Context, t *testing.T, db *pgx.Conn, pid uint32, n int, done <-chan error) {
	t.Helper()
	for {
		var waiting int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY (pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatalf("waiting for %d sessions to wait for session %d: %v", n, pid, err)
		}
		if waiting >= n {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("a call ended without waiting for session %d: %v", pid, err)
		case <-time.After(time.Millisecond):
		}
	}
}

// superuserByRole is a pool on r's schema of a login that is no superuser, which sets its role to a
// superuser role it is granted, as a deployment having its operators escalate explicitly does, and
// the two roles' names; both are made for t, and dropped when it ends, having given what they own to
// r's administrator's role.
func superuserByRole(t *testing.T, r *readmeRoles) (pool *pgxpool.Pool, login, super string) {
	t.Helper()
	ctx := t.Context()
	suffix := strings.TrimPrefix(r.schema, "rbac_")
	login, super = "rbac_login_"+suffix, "rbac_su_"+suffix
	if _, err := r.super.Exec(ctx, `CREATE ROLE `+login+` LOGIN; CREATE ROLE `+super+` SUPERUSER; GRANT `+super+` TO `+login); err != nil {
		t.Fatal(err)
	}
	// Before r's own, which drops the schemas and the administrator's role, as cleanups run last first.
	t.Cleanup(func() {
		if _, err := r.super.Exec(context.WithoutCancel(ctx), `REASSIGN OWNED BY `+login+`, `+super+` TO `+r.admin+`;
			DROP OWNED BY `+login+`, `+super+`; DROP ROLE `+login+`, `+super); err != nil {
			t.Errorf("dropping %s and %s: %v", login, super, err)
		}
	})
	cfg, err := pgxpool.ParseConfig(pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = login
	cfg.ConnConfig.RuntimeParams["search_path"] = r.schema
	cfg.ConnConfig.RuntimeParams["role"] = super
	if pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, login, super
}

// PostgreSQL lets a session SET ROLE only to a role its login may, whatever role it has set: a
// session whose login is no superuser, set to a superuser role it is granted, migrates as the role
// owning the tables where its login may set its role to that one, and is refused, as ErrInvalid
// naming the role and the login, where it may not, with nothing pending too. Where none are made,
// it makes them as itself, as any superuser does, and so is refused, making nothing, where another
// role owns the schema of AsOf's views, but migrates where its role owns that schema. Setting its
// role to the role owning them, its migration failed with SQLSTATE 42501, nothing pending as well.
func TestASuperuserByARoleMigratesAsTheOwnerWhereItsLoginMay(t *testing.T) {
	made, _ := madeViews(t)
	refused := func(t *testing.T, err error, owner, login string) {
		t.Helper()
		if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+owner+",") || !strings.Contains(err.Error(), "login, "+login+",") {
			t.Errorf("Migrate as a superuser by its role, its login %s may not SET ROLE to %s: %v", login, owner, err)
		}
	}
	t.Run("the tables made, nothing pending", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if err := rbac.Migrate(ctx, r.adminPool); err != nil {
			t.Fatal(err)
		}
		pool, login, _ := superuserByRole(t, r)
		refused(t, rbac.Migrate(ctx, pool), r.admin, login)
	})
	t.Run("migrations pending, the login may set its role to the tables' owner", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", made); err != nil {
			t.Fatal(err)
		}
		recordMigrations(t, r.adminPool, made)
		pool, login, _ := superuserByRole(t, r)
		if _, err := r.super.Exec(ctx, `GRANT `+r.admin+` TO `+login); err != nil {
			t.Fatal(err)
		}
		if err := rbac.Migrate(ctx, pool); err != nil {
			t.Fatalf("Migrate as a superuser by its role, its login %s a member of %s: %v", login, r.admin, err)
		}
		if v := migratedTo(t, pool); v != latestMigration(t) {
			t.Errorf("migrated to %d", v)
		}
		if s := r.strangers(t); len(s) > 0 {
			t.Errorf("a superuser's migration left %v another role's", s)
		}
	})
	t.Run("no tables, in the administrator's schema", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		pool, _, _ := superuserByRole(t, r)
		if err := rbac.Migrate(ctx, pool); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+r.admin+",") {
			t.Errorf("Migrate as a superuser by its role, where %s owns the views' schema: %v", r.admin, err)
		}
		var migrations bool
		if err := r.super.QueryRow(ctx, `SELECT to_regclass($1 || '.rbac_migrations') IS NOT NULL`, r.schema).Scan(&migrations); err != nil || migrations {
			t.Errorf("a refused migration made rbac_migrations: %t, %v", migrations, err)
		}
	})
	t.Run("no tables, in a superuser's schema", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		pool, _, super := superuserByRole(t, r)
		for _, sql := range []string{`ALTER SCHEMA ` + r.schema + ` OWNER TO CURRENT_USER`, `ALTER SCHEMA ` + r.schema + `_as_of OWNER TO ` + super} {
			if _, err := r.super.Exec(ctx, sql); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		if err := rbac.Migrate(ctx, pool); err != nil {
			t.Fatalf("Migrate as a superuser by its role, in a superuser's schema: %v", err)
		}
		if got, want := notOwned(t, r.super, r.schema, super), []string{"schema " + r.schema}; !slices.Equal(got, want) {
			t.Errorf("migrating left %v another role's than %s", got, super)
		}
	})
}

// Where none of the package's tables are made, a superuser makes them as itself, never as the
// schema's owner or the database's, which can be the application's role, as one owning the database
// owns public through pg_database_owner from PostgreSQL 15 on: owning the tables, that role could
// disable history's triggers. So a superuser's migration of the application's schema, or of public
// in a database that role owns, leaves every table the superuser's, and the database's owner is then
// refused. Where another role owns the schema of AsOf's views, as the README's administrator's role
// does, which 0028_as_of_views would fail on, it is refused, as ErrInvalid naming that role, before
// it makes anything, on transactions of its own or a host's, which runs as it did after, and that
// role then migrates. A view the application's role made named as rbac_grants doesn't make it the
// tables' owner, which the superuser would migrate as. Making them as the schema's owner, or the
// database's, it made them the application's role's.
func TestASuperuserMakesTheTablesAsItself(t *testing.T) {
	refused := func(t *testing.T, err error, owner string) {
		t.Helper()
		if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+owner+",") {
			t.Errorf("Migrate as a superuser where %s owns the schema of AsOf's views: %v", owner, err)
		}
	}
	unmade := func(t *testing.T, r *readmeRoles) {
		t.Helper()
		var made bool
		if err := r.super.QueryRow(t.Context(), `SELECT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname::text IN ($1::text, $1::text || '_as_of'))`, r.schema).Scan(&made); err != nil || made {
			t.Errorf("a refused migration made something: %t, %v", made, err)
		}
	}
	for _, host := range []bool{false, true} {
		t.Run(fmt.Sprintf("the administrator's schema, on a host's transaction %t", host), func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			superuser := superuserOn(t, r.schema)
			if host {
				var me string
				err := pgx.BeginFunc(ctx, superuser, func(tx pgx.Tx) error {
					if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&me); err != nil {
						return err
					}
					refused(t, rbac.Migrate(ctx, tx), r.admin)
					var current string
					if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&current); err != nil {
						return err
					}
					if current != me {
						return fmt.Errorf("the host's transaction runs as %s after Migrate, not as %s", current, me)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				refused(t, rbac.Migrate(ctx, superuser), r.admin)
			}
			unmade(t, r)
			if err := rbac.Migrate(ctx, r.adminPool); err != nil {
				t.Fatalf("Migrate as the administrator's role after a superuser's was refused: %v", err)
			}
			r.harden(t)
			if s := r.strangers(t); len(s) > 0 {
				t.Errorf("migrating left %v another role's", s)
			}
		})
	}
	t.Run("the application's schema and views' schema", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if _, err := r.super.Exec(ctx, `ALTER SCHEMA `+r.schema+` OWNER TO `+r.app+`; ALTER SCHEMA `+r.schema+`_as_of OWNER TO `+r.app); err != nil {
			t.Fatal(err)
		}
		refused(t, rbac.Migrate(ctx, superuserOn(t, r.schema)), r.app)
		unmade(t, r)
	})
	t.Run("the application's schema, no views' schema", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if _, err := r.super.Exec(ctx, `ALTER SCHEMA `+r.schema+` OWNER TO `+r.app+`; DROP SCHEMA `+r.schema+`_as_of`); err != nil {
			t.Fatal(err)
		}
		superuser := superuserOn(t, r.schema)
		if err := rbac.Migrate(ctx, superuser); err != nil {
			t.Fatalf("Migrate as a superuser: %v", err)
		}
		var me string
		if err := r.super.QueryRow(ctx, `SELECT current_user`).Scan(&me); err != nil {
			t.Fatal(err)
		}
		if got, want := notOwned(t, r.super, r.schema, me), []string{"schema " + r.schema}; !slices.Equal(got, want) {
			t.Errorf("a superuser's migration of the application's schema left %v another role's than %s", got, me)
		}
	})
	t.Run("the application's view named as a table", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if _, err := r.super.Exec(ctx, `GRANT USAGE, CREATE ON SCHEMA `+r.schema+` TO `+r.app); err != nil {
			t.Fatal(err)
		}
		if _, err := r.appPool.Exec(ctx, `CREATE VIEW rbac_grants AS SELECT 1 AS tenant`); err != nil {
			t.Fatal(err)
		}
		refused(t, rbac.Migrate(ctx, superuserOn(t, r.schema)), r.admin)
	})
	t.Run("public, in a database another role owns", func(t *testing.T) {
		ctx := t.Context()
		base := pgtest.URL(t)
		owner := "rbac_owner_" + strings.ToLower(rand.Text())
		super, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = super.Close(context.WithoutCancel(ctx)) })
		if _, err := super.Exec(ctx, `CREATE ROLE `+owner+` LOGIN`); err != nil {
			if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
				pgtest.Skip(t, "the test database's role can't create roles")
			}
			t.Fatal(err)
		}
		// Once the database it owns is dropped, as cleanups run last first.
		t.Cleanup(func() {
			if _, err := super.Exec(context.WithoutCancel(ctx), `DROP ROLE `+owner); err != nil {
				t.Errorf("DROP ROLE %s: %v", owner, err)
			}
		})
		_, database := pgtest.Database(t, "OWNER "+owner)
		on := func(user string) *pgxpool.Pool {
			t.Helper()
			cfg, err := pgxpool.ParseConfig(database)
			if err != nil {
				t.Fatal(err)
			}
			if user != "" {
				cfg.ConnConfig.User = user
			}
			cfg.ConnConfig.RuntimeParams["search_path"] = "public"
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			return pool
		}
		superuser := on("")
		if err := rbac.Migrate(ctx, superuser); err != nil {
			t.Fatalf("Migrate as a superuser: %v", err)
		}
		var me string
		if err := superuser.QueryRow(ctx, `SELECT current_user`).Scan(&me); err != nil {
			t.Fatal(err)
		}
		if got, want := notOwned(t, superuser, "public", me), []string{"schema public"}; !slices.Equal(got, want) {
			t.Errorf("a superuser's migration of public left %v another role's than %s", got, me)
		}
		if err := rbac.Migrate(ctx, on(owner)); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+me+",") {
			t.Errorf("Migrate as the database's owner after a superuser's: %v", err)
		}
	})
}

// A role that isn't a superuser is refused too, where none of the tables are made and another role
// owns the schema of AsOf's views: 0028_as_of_views would fail there, having made every table before
// it that role's. The application's role, where it may create in the administrator's schema, made
// rbac_history its own so, and the administrator's role was then refused; refused, it makes
// nothing, and the administrator's role migrates.
func TestARoleIsRefusedTheTablesWhereAnotherOwnsTheViewsSchema(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	if _, err := r.super.Exec(ctx, `GRANT USAGE, CREATE ON SCHEMA `+r.schema+` TO `+r.app); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(ctx, r.appPool); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "migrate as "+r.admin+",") {
		t.Errorf("Migrate as the application's role where the administrator's owns the views' schema: %v", err)
	}
	var made bool
	if err := r.super.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname::text IN ($1::text, $1::text || '_as_of'))`, r.schema).Scan(&made); err != nil || made {
		t.Errorf("a refused migration made something: %t, %v", made, err)
	}
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("Migrate as the administrator's role after the application's was refused: %v", err)
	}
	if got, want := notOwned(t, r.super, r.schema, r.admin), []string{}; !slices.Equal(got, want) {
		t.Errorf("migrating left %v another role's than %s", got, r.admin)
	}
}

// A schema named in more than 57 bytes can have no schema of AsOf's views beside it, which
// 0028_as_of_views refuses for every role: Migrate refuses every role on it before making anything,
// counting its bytes, not its characters, as otherwise the first role to migrate, the application's
// role given CREATE on it, or a superuser, made 0001 through 0027 its own, and the administrator's
// role, once it renamed the schema, couldn't migrate. At 57 bytes, it migrates.
func TestARoleIsRefusedTheTablesWhereTheSchemaIsNamedTooLongForTheViews(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	named := func(n int) string {
		s := "Rbac é " + strings.TrimPrefix(r.schema, "rbac_")
		return s + strings.Repeat("x", n-len(s))
	}
	long, short := named(58), named(57)
	t.Cleanup(func() {
		for _, s := range []string{long, short} {
			if _, err := r.super.Exec(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+pgtest.WithViews(s)+` CASCADE`); err != nil {
				t.Error(err)
			}
		}
	})
	for _, sql := range []string{
		`CREATE SCHEMA ` + pgx.Identifier{long}.Sanitize() + ` AUTHORIZATION ` + r.admin,
		`GRANT USAGE, CREATE ON SCHEMA ` + pgx.Identifier{long}.Sanitize() + ` TO ` + r.app,
	} {
		if _, err := r.super.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	on := func(user, schema string, encoding ...string) *pgxpool.Pool {
		cfg, err := pgxpool.ParseConfig(pgtest.URL(t))
		if err != nil {
			t.Fatal(err)
		}
		if user != "" {
			cfg.ConnConfig.User = user
		}
		cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize()
		// Set once connected, as the search_path is sent in UTF-8.
		if len(encoding) > 0 {
			cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
				_, err := c.Exec(ctx, `SELECT pg_catalog.set_config('client_encoding', $1, false)`, encoding[0])
				return err
			}
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	// A session whose client_encoding counts the name's é in a byte, as LATIN1 does, reads it in 57.
	for _, c := range []struct{ name, user, encoding string }{
		{"a superuser", "", "UTF8"}, {"the application's role", r.app, "UTF8"}, {"the administrator's role", r.admin, "UTF8"},
		{"a superuser whose session's client_encoding is LATIN1", "", "LATIN1"},
	} {
		if err := rbac.Migrate(ctx, on(c.user, long, c.encoding)); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "at most 57 bytes") {
			t.Errorf("Migrate as %s on a schema named in 58 bytes: %v", c.name, err)
		}
		var made bool
		if err := r.super.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname::text = $1)`, long).Scan(&made); err != nil || made {
			t.Fatalf("Migrate as %s, refused, made something: %t, %v", c.name, made, err)
		}
	}
	for _, sql := range []string{
		`ALTER SCHEMA ` + pgx.Identifier{long}.Sanitize() + ` RENAME TO ` + pgx.Identifier{short}.Sanitize(),
		`REVOKE CREATE ON SCHEMA ` + pgx.Identifier{short}.Sanitize() + ` FROM ` + r.app,
		`CREATE SCHEMA ` + pgx.Identifier{short + "_as_of"}.Sanitize() + ` AUTHORIZATION ` + r.admin,
	} {
		if _, err := r.super.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := rbac.Migrate(ctx, on(r.admin, short)); err != nil {
		t.Fatalf("Migrate as the administrator's role once the schema is named in 57 bytes: %v", err)
	}
	if got, want := notOwned(t, r.super, short, r.admin), []string{}; !slices.Equal(got, want) {
		t.Errorf("migrating left %v another role's than %s", got, r.admin)
	}
}

// Where a superuser's migration of the tables the administrator's role owns ran as itself, as
// before Migrate migrated as the role owning them, what the README says gives back what it made.
// From before 0028_as_of_views, it made AsOf's views, their schema and rbac_as_of_views its own,
// and AsOf, which reads only the views of the role owning the tables, refuses every read, saying
// what a superuser and that role run, and once they have, reads as of a time, as it does where the
// views' schema is gone; from 0028 on, it failed at 0033, and once given back migrates on. Either
// way it made rbac_expired and its functions its own, and from earlier still, what each migration
// it applied made, as rbac_changes_grants, which the README's statements give back, so every
// object of both schemas is the administrator's role's or history's, and DeleteExpired runs as the
// application's role. AsOf said to migrate to 0028_as_of_views, which was recorded, as that role,
// which couldn't run the function, a superuser's migration failed at 0033 again, and from earlier
// still, the README left rbac_changes_grants the superuser's.
func TestASuperusersMigrationAsItselfIsGivenBackAsTheReadmeSays(t *testing.T) {
	names, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	made, _ := madeViews(t)
	last := names[len(names)-1]
	sqls := migrationSQL(t)
	var grantsDenied string
	for _, name := range names {
		if strings.Contains(sqls[name], "CREATE FUNCTION rbac_changes_grants(") {
			grantsDenied = name
		}
	}
	quoted := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	// From before the views, whose schema wasn't made for the administrator's role, to the last, and
	// from earlier still; and from after them, as far as the last, which failed.
	for _, c := range []struct{ from, to string }{{made, ""}, {grantsDenied, ""}, {names[slices.Index(names, made)+1], last}} {
		before := c.to == ""
		t.Run(fmt.Sprintf("from %s", c.from), func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			views := r.schema + "_as_of"
			from, to := c.from, c.to
			if before {
				if _, err := r.super.Exec(ctx, `DROP SCHEMA `+views); err != nil {
					t.Fatal(err)
				}
			}
			if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", from); err != nil {
				t.Fatal(err)
			}
			recordMigrations(t, r.adminPool, from)
			r.harden(t)
			superuser := superuserOn(t, r.schema)
			if err := applyMigrations(ctx, superuser, pgx.ReadCommitted, from, to); err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				if name >= from && (to == "" || name < to) {
					if _, err := superuser.Exec(ctx, `INSERT INTO rbac_migrations (version) VALUES ($1::text::integer)`, name[:4]); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The README's statements, as a superuser with the package's schema first on its search_path,
			// and the same for each other table, function or statistics object there still its own, but
			// history's.
			var others []string
			if err := superuser.QueryRow(ctx, `SELECT ARRAY(
				SELECT 'ALTER TABLE ' || c.oid::regclass FROM pg_class c
				WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p') AND c.relowner = current_user::regrole
				  AND c.relname NOT IN ('rbac_expired', 'rbac_history')
				UNION ALL SELECT 'ALTER FUNCTION ' || p.oid::regprocedure FROM pg_proc p
				WHERE p.pronamespace = current_schema()::regnamespace AND p.proowner = current_user::regrole
				  AND p.proname NOT IN ('rbac_expired_until', 'rbac_expired_through', 'rbac_record', 'rbac_history_commit')
				UNION ALL SELECT 'ALTER STATISTICS ' || pg_catalog.quote_ident(x.stxname) FROM pg_statistic_ext x
				WHERE x.stxnamespace = current_schema()::regnamespace AND x.stxowner = current_user::regrole)`).Scan(&others); err != nil {
				t.Fatal(err)
			}
			for _, sql := range append([]string{
				`ALTER TABLE rbac_expired`, `ALTER FUNCTION rbac_expired_until()`, `ALTER FUNCTION rbac_expired_through(timestamptz)`,
			}, others...) {
				if _, err := superuser.Exec(ctx, sql+` OWNER TO `+r.admin); err != nil {
					t.Fatal(err)
				}
			}
			// says fails t unless AsOf fails saying to run each of super as a superuser, and then the
			// function as the administrator's role, and runs them.
			says := func(super ...string) {
				t.Helper()
				err := r.asOf(ctx, t)
				if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "as that role, with "+r.schema+" first on its search_path, SELECT rbac_as_of_views()") {
					t.Fatalf("AsOf where the views aren't the administrator's role's: %v", err)
				}
				for _, sql := range super {
					if !strings.Contains(err.Error(), sql) {
						t.Errorf("AsOf's error doesn't say to run %s: %v", sql, err)
					}
					if _, err := r.super.Exec(ctx, sql); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := r.adminPool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
					t.Fatal(err)
				}
			}
			if before {
				says(`DROP SCHEMA IF EXISTS `+quoted(views)+` CASCADE`, `CREATE SCHEMA `+quoted(views)+` AUTHORIZATION `+quoted(r.admin),
					`ALTER FUNCTION `+quoted(r.schema)+`.rbac_as_of_views() OWNER TO `+quoted(r.admin))
			} else if err := rbac.Migrate(ctx, superuser); err != nil {
				t.Fatalf("Migrate as a superuser where its migration as itself failed: %v", err)
			}
			if v := migratedTo(t, r.adminPool); v != latestMigration(t) {
				t.Errorf("migrated to %d", v)
			}
			if s := r.strangers(t); len(s) > 0 {
				t.Errorf("given back as the README says, %v are another role's", s)
			}
			r.readsAsOf(t)
			authz, err := rbac.New(r.appPool, rbac.Config{
				Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
				ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authz.DeleteExpired(ctx); err != nil {
				t.Errorf("DeleteExpired as the application's role: %v", err)
			}
			// Where the views' schema is gone, AsOf says to make it again.
			if _, err := r.super.Exec(ctx, `DROP SCHEMA `+views+` CASCADE`); err != nil {
				t.Fatal(err)
			}
			says(`CREATE SCHEMA ` + quoted(views) + ` AUTHORIZATION ` + quoted(r.admin))
			r.readsAsOf(t)
		})
	}
}

// Where views of history named as the package's tables stand in a schema of another role's other
// than AsOf's, and none of the role owning the tables stand anywhere, AsOf's error says to drop
// those views, and not that schema, which holds what else its owner keeps there: once a superuser
// has done what it says, and the administrator's role made the views, AsOf reads, and the other
// schema and what else it holds stand. It said to drop that schema, CASCADE, and make it again
// for the administrator's role, after which rbac_as_of_views, finding no views' schema, failed to
// make one.
func TestAsOfSaysToDropOnlyTheViewsOfHistoryStandingInAnotherSchema(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatal(err)
	}
	r.harden(t)
	quoted := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	views := r.schema + "_as_of"
	// Named to come before the views' schema, as AsOf's error names the first.
	other := "a_" + r.schema
	if _, err := r.super.Exec(ctx, `CREATE SCHEMA `+other+`; CREATE TABLE `+other+`.kept (id int);
		CREATE VIEW `+other+`.rbac_grants AS SELECT h.id FROM `+r.schema+`.rbac_history h`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := r.super.Exec(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+other+` CASCADE`); err != nil {
			t.Errorf("DROP SCHEMA %s: %v", other, err)
		}
	})
	if _, err := r.super.Exec(ctx, `DROP SCHEMA `+views+` CASCADE`); err != nil {
		t.Fatal(err)
	}
	err := r.asOf(ctx, t)
	want := `drop the views of history named as the package's tables in schema ` + quoted(other) + `, run DROP SCHEMA IF EXISTS ` +
		quoted(views) + ` CASCADE, CREATE SCHEMA ` + quoted(views) + ` AUTHORIZATION ` + quoted(r.admin)
	if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), `DROP SCHEMA IF EXISTS `+quoted(other)) {
		t.Fatalf("AsOf where views of history stand only in another schema: %v", err)
	}
	for _, sql := range []string{
		`DROP VIEW ` + other + `.rbac_grants`, `DROP SCHEMA IF EXISTS ` + views + ` CASCADE`,
		`CREATE SCHEMA ` + views + ` AUTHORIZATION ` + r.admin, `ALTER FUNCTION ` + r.schema + `.rbac_as_of_views() OWNER TO ` + r.admin,
	} {
		if _, err := r.super.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := r.adminPool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
		t.Fatal(err)
	}
	r.readsAsOf(t)
	var kept bool
	if err := r.super.QueryRow(ctx, `SELECT to_regclass($1 || '.kept') IS NOT NULL`, other).Scan(&kept); err != nil || !kept {
		t.Errorf("schema %s keeps its table: %t, %v", other, kept, err)
	}
}

// The README's database roles, set up as its steps say and given nothing more, run the package: as
// the administrator's role, Migrate, on a new schema or one history's role took history over in
// before the last migration, and on a host's transaction that changed the tables, and PruneHistory;
// and as the application's, changes to every table, checks, lists, DeleteExpired, a read as of a
// time, History and Export.
func TestThePackageRunsAsTheReadmesDatabaseRoles(t *testing.T) {
	names, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	last := names[len(names)-1]
	for _, upgrade := range []bool{false, true} {
		t.Run(fmt.Sprintf("upgrade=%t", upgrade), func(t *testing.T) {
			ctx := t.Context()
			r := newReadmeRoles(t)
			if upgrade {
				if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", last); err != nil {
					t.Fatal(err)
				}
				recordMigrations(t, r.adminPool, last)
				r.harden(t)
			}
			if err := rbac.Migrate(ctx, r.adminPool); err != nil {
				t.Fatalf("Migrate as the administrator's role: %v", err)
			}
			if !upgrade {
				r.harden(t)
			}
			cfg := rbac.Config{
				Catalog:        append(slices.Clone(catalog), guardRole, groupMembers, rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}),
				ContainerTypes: []string{"org", "workspace"},
				ValidateGrant:  func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
			}
			authz, err := rbac.New(r.appPool, cfg)
			if err != nil {
				t.Fatal(err)
			}
			h := &harness{ctx: ctx, pool: r.appPool, authz: authz, cfg: cfg}
			creator(t, r.appPool)
			owner, boss, u := h.as(t, "owner"), h.as(t, "boss"), h.as(t, "u")
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "cluster.admin", rbac.User, "boss"), grant(tenant, guardRole.ID, rbac.User, "boss"),
				grant(tenant, "tenant.roles", rbac.User, "boss"), grant(tenant, "tenant.groups", rbac.User, "boss"),
				grant(tenant, groupMembers.ID, rbac.User, "boss"))
			before := dbNow(t, h)
			check := func(what string, err error) {
				t.Helper()
				if err != nil {
					t.Errorf("%s as the application's role: %v", what, err)
				}
			}
			check("Apply", authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: u.Principal}}}))
			check("SetRole", authz.SetRole(ctx, boss, "t1", rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}))
			check("SetDeny", authz.SetDeny(ctx, boss, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("v")}, Permissions: []rbac.Permission{root}}))
			check("SetEligibility", authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}))
			check("SetMemberships", authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("v")}}))
			check("SetGroup", authz.SetGroup(ctx, boss, "t1", rbac.GroupDefinition{ID: "ops"}))
			check("ChangeMembers", authz.ChangeMembers(ctx, boss, "t1", []rbac.Member{{Group: "ops", Principal: u.Principal}}, nil))
			// A custom role to the group and the members, which the searches and Holders read them by.
			check("Import", authz.Import(ctx, host, "t1", []rbac.Grant{
				grant(cluster.Scope(), "custom.viewer", rbac.Group, "ops"),
				grant(cluster.Scope(), "custom.viewer", rbac.Members, "t1"),
			}))
			check("Authorize", authz.Authorize(ctx, u, login, cluster))
			_, err = authz.Holders(ctx, login, cluster)
			check("Holders", err)
			// Holders, Members and GroupsOf read the group's members and their memberships, and Filter
			// and Reachable whether u is a member and the custom roles granted to the members.
			reads := func(a *rbac.Authorizer) error {
				holders, err := a.Holders(ctx, view, cluster)
				if err == nil && !slices.ContainsFunc(holders, func(h rbac.Holder) bool { return h.Principal == u.Principal && slices.Equal(h.Groups, []string{"ops"}) }) {
					err = fmt.Errorf("Holders = %+v", holders)
				}
				if err != nil {
					return err
				}
				if members, err := a.Members(ctx, "t1", "ops"); err != nil || len(members) != 1 || members[0].Principal != u.Principal {
					return fmt.Errorf("Members = %+v, %w", members, err)
				}
				if groups, err := a.GroupsOf(ctx, "t1", u.Principal); err != nil || !slices.Equal(groups, []string{"ops"}) {
					return fmt.Errorf("GroupsOf = %v, %w", groups, err)
				}
				if _, err := a.Filter(ctx, u, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1); err != nil {
					return fmt.Errorf("Filter: %w", err)
				}
				_, err = a.Reachable(ctx, u, view, "t1", "cluster")
				return err
			}
			check("Holders, Members, GroupsOf, Filter and Reachable", reads(authz))
			check("SetGroup", authz.SetGroup(ctx, boss, "t1", rbac.GroupDefinition{ID: "spare"}))
			check("DeleteGroup", authz.DeleteGroup(ctx, boss, "t1", "spare"))
			// It records the time it deletes by, which every check above read, in the table the last
			// migration added, which an upgrade gives the role no privilege on by a step of its own.
			_, err = authz.DeleteExpired(ctx)
			check("DeleteExpired", err)
			check("AsOf", authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
				if err := a.Authorize(ctx, u, login, cluster); err != nil {
					return err
				}
				if _, err := a.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil {
					return err
				}
				return reads(a)
			}))
			// History's role records the commit again as it commits, deferring its trigger anew.
			check("A write around the package with constraints set immediate", pgx.BeginFunc(ctx, r.appPool, func(tx pgx.Tx) error {
				for _, q := range []string{`SET CONSTRAINTS ALL IMMEDIATE`, `UPDATE rbac_memberships SET note = 'immediate' WHERE tenant = 't1'`} {
					if _, err := tx.Exec(ctx, q); err != nil {
						return err
					}
				}
				return nil
			}))
			// Migrate on a host's transaction reads what it checks of one that changed the tables, its
			// locks, history's triggers, what was applied and history, as the administrator's role.
			if err := pgx.BeginFunc(ctx, r.adminPool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'migrating')`); err != nil {
					return err
				}
				return rbac.Migrate(ctx, tx)
			}); err != nil {
				t.Errorf("Migrate on a host's transaction that changed the tables, as the administrator's role: %v", err)
			}
			var n int
			if err := r.appPool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE entity <> 'commit'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			var cursor rbac.Cursor
			drain(t, h, &cursor, n)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = authz.Export(ctx, rbac.Checkpoint{}, rbac.MaxHistory, key)
			check("Export", err)
			if _, err := rbac.PruneHistory(ctx, r.adminPool, before, cursor); err != nil {
				t.Errorf("PruneHistory as the administrator's role: %v", err)
			}
			check("DeleteTenant", authz.DeleteTenant(ctx, host, "t1"))
		})
	}
}

// The commit-record checks refuse a change committed with a session's own enabled deferrable trigger
// on a temporary table, which only a session with the TEMPORARY privilege can make. The README's
// application role is denied TEMPORARY (revoked from PUBLIC on the database, granted to no one), so
// it can make no temporary object and can't plant such a trigger, and every call of the package's
// runs without it: AsOf too, which reads history through the views migrating made, in a read that
// takes no transaction id and writes nothing, whose every statement reads the past, a hook's and the
// host's, rbac_group_members's too, on its own transaction and under WithTx.
func TestTheApplicationRoleNeedsNoTemporary(t *testing.T) {
	ctx := t.Context()
	name, base := pgtest.Database(t, "")
	r := newReadmeRolesIn(t, base)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	r.harden(t)
	// No role has TEMPORARY on the database now, as a host that hardens it this way leaves it.
	if _, err := r.super.Exec(ctx, `REVOKE TEMPORARY ON DATABASE `+name+` FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	// What a constraint reads on the DB it is given: its transaction's id, and the grants of u.
	type seen struct {
		xid    *string
		grants int
	}
	var hooked []seen
	cfg := rbac.Config{
		Catalog:        append(slices.Clone(catalog), rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}),
		ContainerTypes: []string{"org", "workspace"},
		ValidateGrant:  func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
		Constraints: []rbac.Constraint{{Name: "reads", Deny: func(ctx context.Context, q rbac.DB, in rbac.ConstraintInput) (bool, error) {
			var s seen
			err := q.QueryRow(ctx, `SELECT pg_current_xact_id_if_assigned()::text, (SELECT count(*) FROM rbac_grants WHERE principal = 'user:u')`).Scan(&s.xid, &s.grants)
			hooked = append(hooked, s)
			return false, err
		}}},
	}
	authz, err := rbac.New(r.appPool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		creatorGrant,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'tenant', 't1', 'user', 'owner', 'tenant.groups')`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'owner'), ('t1', 'user', 'u')`,
	} {
		if _, err := r.appPool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	owner, u := rbac.Subject{Principal: identity("owner")}, rbac.Subject{Principal: identity("u")}
	// The application's role can make no temporary object, so it can plant no deferrable trigger to
	// run code at the commit after its change is dated.
	if _, err := r.appPool.Exec(ctx, `CREATE TEMP TABLE held (a int)`); true {
		if pg := (*pgconn.PgError)(nil); !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatalf("the application's role makes a temporary table without TEMPORARY: %v", err)
		}
	}
	check := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s without TEMPORARY: %v", what, err)
		}
	}
	check("SetGroup", authz.SetGroup(ctx, owner, "t1", rbac.GroupDefinition{ID: "ops"}))
	exec := func(sql string) {
		t.Helper()
		if _, err := r.appPool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'ops', 'user', 'u')`)
	check("Apply", authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "cluster.login", Principal: u.Principal}, {Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "ops"}},
	}}))
	var at time.Time
	if err := r.appPool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	// Since: u's grants were revoked, and u left ops.
	check("Apply", authz.Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{
		{Role: "cluster.login", Principal: u.Principal}, {Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "ops"}},
	}}))
	exec(`DELETE FROM rbac_members WHERE tenant = 't1' AND principal = 'user:u'`)
	check("Authorize", authz.Authorize(ctx, owner, login, cluster))
	// Every record, read once every transaction older than the last has ended, as other sessions
	// sharing the cluster can hold one for a while.
	var n int
	if err := r.appPool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE entity <> 'commit'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	var cursor rbac.Cursor
	drain(t, &harness{ctx: ctx, pool: r.appPool, authz: authz, cfg: cfg}, &cursor, n)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authz.Export(ctx, rbac.Checkpoint{}, rbac.MaxHistory, key); err != nil {
		t.Errorf("Export without TEMPORARY: %v", err)
	}
	if _, err := rbac.PruneHistory(ctx, r.adminPool, time.Unix(0, 0), cursor); err != nil {
		t.Errorf("PruneHistory without TEMPORARY: %v", err)
	}
	// As of then, every read finds u's grant and place in ops, as does the host's query on the read's
	// transaction, and rbac_group_members.
	reads := func(a *rbac.Authorizer, q pgx.Tx) error {
		if err := a.Authorize(ctx, u, login, cluster); err != nil {
			return err
		}
		holders, err := a.Holders(ctx, login, cluster)
		if err == nil && !slices.ContainsFunc(holders, func(h rbac.Holder) bool { return h.Principal == u.Principal && slices.Equal(h.Groups, []string{"ops"}) }) {
			err = fmt.Errorf("Holders = %+v", holders)
		}
		if err != nil {
			return err
		}
		if members, err := a.Members(ctx, "t1", "ops"); err != nil || len(members) != 1 {
			return fmt.Errorf("Members = %+v, %w", members, err)
		}
		if groups, err := a.GroupsOf(ctx, "t1", u.Principal); err != nil || !slices.Equal(groups, []string{"ops"}) {
			return fmt.Errorf("GroupsOf = %v, %w", groups, err)
		}
		if grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u.Principal}}); err != nil || len(grants) != 1 {
			return fmt.Errorf("Grants = %+v, %w", grants, err)
		}
		if _, err := a.Filter(ctx, u, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1); err != nil {
			return fmt.Errorf("Filter: %w", err)
		}
		if _, err := a.Reachable(ctx, u, view, "t1", "cluster"); err != nil {
			return fmt.Errorf("Reachable: %w", err)
		}
		if _, err := a.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil {
			return fmt.Errorf("Denies: %w", err)
		}
		if _, _, err := a.History(ctx, rbac.Cursor{}, 1); err != nil {
			return fmt.Errorf("History: %w", err)
		}
		if q == nil {
			return nil
		}
		var grants, members int
		var xid *string
		if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM rbac_grants WHERE principal IN ('user:u', 'group:ops')),
			(SELECT count(*) FROM rbac_group_members('t1', '{ops}', $1, NULL, true)), pg_current_xact_id_if_assigned()::text`, at).Scan(&grants, &members, &xid); err != nil {
			return err
		}
		if grants != 2 || members != 1 || xid != nil {
			return fmt.Errorf("the host's query on the read's transaction reads %d grants and %d members, in transaction %v", grants, members, xid)
		}
		// Nor can it write, though it names the table itself rather than its view: the read only reads.
		err = pgx.BeginFunc(ctx, q, func(s pgx.Tx) error {
			_, err := s.Exec(ctx, `INSERT INTO `+r.schema+`.rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'w')`)
			return err
		})
		if pg := (*pgconn.PgError)(nil); !errors.As(err, &pg) || pg.Code != "25006" {
			return fmt.Errorf("a write in the read: %w", err)
		}
		return nil
	}
	hooked = nil
	check("AsOf", authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return reads(a, nil) }))
	if len(hooked) == 0 || slices.ContainsFunc(hooked, func(s seen) bool { return s.xid != nil || s.grants != 1 }) {
		t.Errorf("as of then, a constraint read %+v", hooked)
	}
	tx, err := r.appPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	check("AsOf under WithTx", authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return reads(a, tx) }))
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'w')`); err != nil {
		t.Errorf("the host's transaction once AsOf returned: %v", err)
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

// Renamed, the package's schema keeps its history, as the README's roles run it: history's triggers
// find history beside the table each fires on, never a session's own table named as history's,
// which pg_temp on their search_path gave them once the schema no longer answered to the name it
// had when they were made. A change the application's role makes is recorded in history, and a
// delete the administrator's makes with a prune recorded in its own table is refused, while
// PruneHistory prunes; and an export reads on, as its generation names the schema by its OID.
func TestHistoryIsKeptWhateverItsSchemaIsNamed(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatal(err)
	}
	r.harden(t)
	cfg := rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	}
	exec := func(db rbac.DB, sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	const write = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	exec(r.appPool, write, "before")
	authz, err := rbac.New(r.appPool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var exported rbac.Cursor
	drain(t, &harness{ctx: ctx, pool: r.appPool, authz: authz, cfg: cfg}, &exported, 1)
	renamed := r.schema + "_renamed"
	exec(r.super, `ALTER SCHEMA `+r.schema+` RENAME TO `+renamed)
	// Before the roles' cleanup drops the schema by its name.
	t.Cleanup(func() {
		if _, err := r.super.Exec(context.WithoutCancel(ctx), `ALTER SCHEMA `+renamed+` RENAME TO `+r.schema); err != nil {
			t.Error(err)
		}
	})
	history := pgx.Identifier{renamed, "rbac_history"}.Sanitize()
	// A session of each role, on the schema by its new name, with a table of its own named as
	// history's, which any role may make and its session reads before any schema's.
	session := func(user string) *pgxpool.Pool {
		t.Helper()
		c, err := pgxpool.ParseConfig(pgtest.URL(t))
		if err != nil {
			t.Fatal(err)
		}
		c.MaxConns, c.ConnConfig.User = 1, user
		c.ConnConfig.RuntimeParams["search_path"] = renamed
		p, err := pgxpool.NewWithConfig(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		exec(p, `CREATE TEMP TABLE rbac_history (LIKE `+history+` INCLUDING DEFAULTS INCLUDING IDENTITY)`)
		exec(p, `GRANT ALL ON pg_temp.rbac_history TO PUBLIC`)
		return p
	}
	app, admin := session(r.app), session(r.admin)
	exec(app, write, "after")
	exec(app, `UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:after'`)
	var kept, taken int
	if err := app.QueryRow(ctx, `SELECT (SELECT count(*) FROM `+history+` WHERE principal = 'user:after'),
		(SELECT count(*) FROM pg_temp.rbac_history)`).Scan(&kept, &taken); err != nil || kept != 2 || taken != 0 {
		t.Fatalf("after the rename, history recorded %d of the 2 changes and the session's own table %d, %v", kept, taken, err)
	}
	renamedAuthz, err := rbac.New(app, cfg)
	if err != nil {
		t.Fatal(err)
	}
	through := exported
	read := drain(t, &harness{ctx: ctx, pool: app, authz: renamedAuthz, cfg: cfg}, &through, 2)
	if through.Generation != exported.Generation {
		t.Fatalf("History after the rename reads generation %q, not %q", through.Generation, exported.Generation)
	}
	// As history's owner, a delete with a prune recorded in the session's own table, which History
	// never reads.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec(tx, `SELECT set_config('rbac.prune', 'on', true)`)
	exec(tx, `INSERT INTO pg_temp.rbac_history (effective_at, tenant, entity, key, op, after, how) VALUES (now(), '', 'history', 'k', 'prune',
		jsonb_build_object('last', jsonb_build_object('txid', '18446744073709551615', 'id', 9223372036854775807)), '')`)
	exec(tx, `DELETE FROM `+history+` WHERE id = $1`, read[0].ID)
	err = tx.Commit(ctx)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a delete from history with a prune recorded in the session's own table: %v", err)
	}
	var now time.Time
	if err := admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	// A version and its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, admin, now, through); err != nil || n != 2 {
		t.Fatalf("PruneHistory after the rename deleted %d, %v", n, err)
	}
	if _, _, err := renamedAuthz.History(ctx, exported, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History from before what PruneHistory deleted after the rename: %v", err)
	}
}

// History's triggers refuse a row where the search_path each sets can't name the schema of the table
// it fires on, rather than find history in pg_temp: a search_path reads $user, however it is quoted,
// as a role's name, and leaves out a schema the role has no USAGE on. A session's own table named as
// history's would take the record of each change it wrote, and a prune recorded there would let a
// delete from history through. And rbac_record refuses before it reads such a table, which would run
// what the table runs, as its row security policy, as history's role before the row was refused:
// what no rollback undoes would stay, as setting history's id sequence back, which numbers later
// records below earlier ones. Each case runs with 0023's rbac_record too, which read history before
// it refused, so the run itself shows that its spy sees such a read.
func TestHistorysTriggersRefuseASchemaTheirSearchPathCantName(t *testing.T) {
	const write = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	historySchema, err := fs.ReadFile(rbac.Migrations(), "0023_history_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec := func(t *testing.T, db rbac.DB, sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(t.Context(), sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		if pg := (*pgconn.PgError)(nil); !errors.As(err, &pg) || pg.Code != "3F000" {
			t.Errorf("%s: %v", what, err)
		}
	}
	// spy makes db's session a table of its own named as history's, holding a record of a grant no
	// case writes, whose policy takes a value of a sequence of the session's, which no rollback gives
	// back, for each row a role but its owner reads there; ran reports whether one was read. The
	// policy costs less than any test of a column, as the planner orders a read's tests by cost, a
	// cheap leakproof one of the read's own before a policy that costs more: a read whose own tests
	// left the record out would otherwise run nothing.
	spy := func(t *testing.T, db rbac.DB) (ran func() bool) {
		t.Helper()
		for _, sql := range []string{
			`CREATE TEMP TABLE rbac_history (LIKE rbac_history INCLUDING DEFAULTS INCLUDING IDENTITY)`,
			`INSERT INTO pg_temp.rbac_history (effective_at, tenant, entity, key, op) VALUES (now(), 't1', 'grant', 'spied', 'create')`,
			`CREATE TEMP SEQUENCE spied`,
			`CREATE FUNCTION pg_temp.spied() RETURNS boolean LANGUAGE plpgsql COST 0.001
				AS $$ BEGIN RETURN pg_catalog.nextval('pg_temp.spied') > 0; END $$`,
			`ALTER TABLE pg_temp.rbac_history ENABLE ROW LEVEL SECURITY`,
			`CREATE POLICY spied ON pg_temp.rbac_history USING (pg_temp.spied())`,
			`GRANT ALL ON pg_temp.rbac_history TO PUBLIC`,
			`GRANT USAGE ON SEQUENCE pg_temp.spied TO PUBLIC`,
		} {
			exec(t, db, sql)
		}
		return func() bool {
			t.Helper()
			var called bool
			if err := db.QueryRow(t.Context(), `SELECT is_called FROM pg_temp.spied`).Scan(&called); err != nil {
				t.Fatal(err)
			}
			return called
		}
	}
	t.Run("named $user", func(t *testing.T) {
		pool := pgtest.Open(t, "")
		if err := rbac.Migrate(t.Context(), pool); err != nil {
			t.Fatal(err)
		}
		exec(t, pool, write, "before")
		// As migrated, and with 0023's rbac_record, each in a transaction it rolls back.
		for _, read := range []bool{false, true} {
			t.Run(fmt.Sprintf("0023=%t", read), func(t *testing.T) {
				ctx := t.Context()
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if read {
					exec(t, tx, string(historySchema))
				}
				// Owned by a role of history's own, as the README sets it up, which a policy binds, as
				// it binds no superuser.
				history, schema := role(t, tx)
				exec(t, tx, `ALTER FUNCTION rbac_record() OWNER TO `+history)
				ran := spy(t, tx)
				// Renamed in tx, which rolls it back, so no other test meets the name.
				exec(t, tx, `ALTER SCHEMA `+pgx.Identifier{schema}.Sanitize()+` RENAME TO "$user"`)
				exec(t, tx, `SET CONSTRAINTS ALL IMMEDIATE`)
				in := func(sqls ...string) error {
					sp, err := tx.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = sp.Rollback(ctx) }()
					for _, sql := range sqls {
						if _, err := sp.Exec(ctx, sql); err != nil {
							return err
						}
					}
					return nil
				}
				refused(t, "a change in a schema named $user", in(`INSERT INTO "$user".rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', 'c1', 'user', 'after', 'cluster.login')`))
				refused(t, "a delete from history in a schema named $user, with a prune recorded in the session's own table", in(
					`SELECT set_config('rbac.prune', 'on', true)`,
					`INSERT INTO pg_temp.rbac_history (effective_at, tenant, entity, key, op, after, how) VALUES (now(), '', 'history', 'k', 'prune',
						jsonb_build_object('last', jsonb_build_object('txid', '18446744073709551615', 'id', 9223372036854775807)), '')`,
					`DELETE FROM "$user".rbac_history WHERE principal = 'user:before'`))
				switch ran := ran(); {
				case ran && !read:
					t.Error("a change in a schema named $user read the session's own table as history's role before it was refused")
				case !ran && read:
					t.Error("the spy saw no read by 0023's rbac_record, which read the session's own table before it refused a schema named $user")
				}
			})
		}
	})
	t.Run("history's role without USAGE", func(t *testing.T) {
		ctx := t.Context()
		r := newReadmeRoles(t)
		if err := rbac.Migrate(ctx, r.adminPool); err != nil {
			t.Fatal(err)
		}
		r.harden(t)
		exec(t, r.super, `REVOKE USAGE ON SCHEMA `+r.schema+` FROM `+r.history)
		conn, err := r.appPool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		ran := spy(t, conn)
		_, err = conn.Exec(ctx, write, "u")
		refused(t, "a change recorded by a role without USAGE on the schema", err)
		if ran() {
			t.Error("a change recorded by a role without USAGE on the schema read the session's own table as that role before it was refused")
		}
		// As a superuser migrating replaces it, which keeps its owner.
		exec(t, superuserOn(t, r.schema), string(historySchema))
		_, err = conn.Exec(ctx, write, "u")
		refused(t, "a change recorded by 0023's rbac_record, as a role without USAGE on the schema", err)
		if !ran() {
			t.Error("the spy saw no read by 0023's rbac_record, which read the session's own table before it refused a schema its role has no USAGE on")
		}
	})
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
			pgtest.Skip(t, "the test database's role can't create roles")
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
	// The owner's grant's first version, which its second supersedes, and its transaction's commit
	// record.
	if n, err := rbac.PruneHistory(ctx, h.pool, before, through); err != nil || n != 2 {
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
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM rbac_history WHERE entity <> 'commit'`).Scan(&n); err != nil {
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
// its bound, holding what is no element of it, or in another shape than one dimension from 1, which
// history gives back. Unbounded, one row a hundred megabytes long, built on the server, was recorded
// as JSON no read of history could return, and every export stopped there; and as of a time, a deny
// naming its keys in two dimensions named none.
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
	// MaxExpression bytes, as the package counts a condition's or requirement's.
	expr := strings.Repeat("é", rbac.MaxExpression/2)
	for _, c := range [][2]string{{"rbac_grants", "condition"}, {"rbac_denies", "condition"}, {"rbac_eligibilities", "requires"}} {
		bounds = append(bounds, bound{c[0], c[1], []any{expr}, []any{expr + "x"}})
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
		bound{"rbac_denies", "permissions", []any{[]string{"cluster:login", "cluster:*"}}, []any{[]string{"cluster:deny"}, []string{"cluster:login,cluster:view"}}},
	)
	// A list the package can write, in more dimensions than one or from another subscript than 1,
	// which history, holding it as JSON, gives back in one from 1: every list the tables hold.
	shaped := map[string]bool{}
	for i, b := range bounds {
		if v, ok := b.ok[len(b.ok)-1].([]string); ok && len(v) > 0 {
			bounds[i].bad = append(bounds[i].bad, [][]string{v}, [][]string{v[:1], v[len(v)-1:]},
				pgtype.Array[string]{Elements: v, Dims: []pgtype.ArrayDimension{{Length: int32(len(v)), LowerBound: 0}}, Valid: true})
			shaped[b.table+"."+b.column] = true
		}
	}
	lists, err := h.pool.Query(ctx, `SELECT c.relname || '.' || a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind = 'r' AND a.atttypid = 'text[]'::regtype AND NOT a.attisdropped`)
	if err != nil {
		t.Fatal(err)
	}
	columns, err := pgx.CollectRows(lists, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range columns {
		if !shaped[c] {
			t.Errorf("list %s is shaped by no bound here", c)
		}
	}
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

// Migrating rewrites each list a row holds in more dimensions than one, or from another subscript
// than 1, as before 0016 the tables took, in one dimension from 1, its elements in the order every
// read took them, and history records it as Migrate's change; a row whose lists are so already is
// left as it is.
func TestMigratingWritesEveryListInOneDimension(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0016")
	for _, sql := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
		 VALUES ('t1', 'custom.r', '{{cluster:view,cluster:login},{cluster:root,cluster:grant}}', '[0:0]={cluster}', '{{cluster.login},{cluster.sudo}}'),
		   ('t1', 'custom.flat', '{cluster:view}', '{cluster}', '{}')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 VALUES ('t1', 'cluster', 'c1', 'd', '[0:1]={user:a,user:b}', '{{user:c}}', '{{cluster:login},{cluster:view}}'),
		   ('t1', 'cluster', 'c1', 'flat', '{user:a}', '{}', '{cluster:login}')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 60, '{{user:a,group:g}}'),
		   ('t1', 'cluster', 'c1', 'user', 'flat', 'cluster.sudo', 60, '{user:a}')`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	migrateFiles(t, pool, "0016", "")
	rows, err := pool.Query(ctx, `
		SELECT id || ' ' || permissions::text || ' ' || resource_types::text || ' ' || grantable_roles::text FROM rbac_roles
		UNION ALL SELECT id || ' ' || principals::text || ' ' || exempt::text || ' ' || permissions::text FROM rbac_denies
		UNION ALL SELECT principal_id || ' ' || approvers::text FROM rbac_eligibilities
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"custom.flat {cluster:view} {cluster} {}",
		"custom.r {cluster:view,cluster:login,cluster:root,cluster:grant} {cluster} {cluster.login,cluster.sudo}",
		"d {user:a,user:b} {user:c} {cluster:login,cluster:view}",
		"flat {user:a}",
		"flat {user:a} {} {cluster:login}",
		"u {user:a,group:g}",
	}
	if got, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(got, want) {
		t.Fatalf("lists once migrated: %q, %v", got, err)
	}
	recorded, err := pool.Query(ctx, `SELECT entity || ' ' || key FROM rbac_history WHERE op = 'update' AND how = 'Migrate' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(recorded, pgx.RowTo[string]); err != nil ||
		len(got) != 3 || got[0] != "deny cluster:c1 d" || !strings.HasPrefix(got[1], "eligibility ") || got[2] != "role custom.r" {
		t.Fatalf("changes migrating recorded: %q, %v", got, err)
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

// recordMigrations records in rbac_migrations, as Migrate does, every migration named before to,
// as migrateFiles applies them up to to, so Migrate applies those from to on.
func recordMigrations(t *testing.T, pool *pgxpool.Pool, to string) {
	t.Helper()
	ctx := t.Context()
	files, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE rbac_migrations (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if name >= to {
			break
		}
		prefix, _, _ := strings.Cut(name, "_")
		if _, err := pool.Exec(ctx, `INSERT INTO rbac_migrations (version) VALUES ($1::text::integer)`, prefix); err != nil {
			t.Fatal(err)
		}
	}
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE (txid, id) > ($1::xid8, $2) AND entity <> 'commit'`, cursor.TxID, cursor.ID).Scan(&n); err != nil {
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
			recordMigrations(t, pool, "0008")
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
	// And one dated past the times history holds, which pgx would send as another, or PostgreSQL
	// refuse as out of range: 2^64 microseconds on or back, it reaches the database as the record's
	// own time, and less than a microsecond before the earliest, pgx sends a microsecond before it.
	earliest := time.Date(-4713, time.November, 24, 0, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{
		wrapped(cursor.RecordedAt, 1), wrapped(cursor.RecordedAt, -1), time.Date(300000, time.January, 1, 0, 0, 0, 0, time.UTC),
		earliest.Add(-time.Nanosecond),
	} {
		far := cursor
		far.RecordedAt = at
		if _, _, err := h.authz.History(ctx, far, 1); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a cursor of a record dated in year %d: %v", at.Year(), err)
		}
	}
	if _, _, err := h.authz.History(ctx, rbac.Cursor{}, rbac.MaxHistory+1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("too many: %v", err)
	}
}

// wrapped is a time laps times 2^64 microseconds after t, past the times PostgreSQL holds, which pgx
// writes in microseconds from 2000 in 64 bits, so sends as t.
func wrapped(t time.Time, laps int64) time.Time {
	const seconds, micros = 18446744073709, 551616
	return time.Unix(t.Unix()+laps*seconds, int64(t.Nanosecond())+laps*micros*1000).UTC()
}

const grantLogin = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
	VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`

// A prune through the cursor of one export deletes records another export, further behind, hasn't
// read, and can keep that one's last record, which no later version supersedes: History refuses the
// cursor behind, as it would one whose record a prune deleted, rather than read on past them and
// chain what it read as all history held. A prune that deleted only what an export had read leaves
// its cursor be, as does one before it, and the export past the prune reads on.
func TestHistoryRefusesACursorAPruneWentPast(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, id := range []string{"a", "d", "e", "f", "x"} {
		h.as(t, id)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// x's first version, which its second supersedes, and then a's grant, which no later version
	// does: the last record the export behind read.
	exec(grantLogin, "x")
	exec(`UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:x'`)
	exec(grantLogin, "a")
	behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:a'`)
	exec(grantLogin, "e")
	ahead := exported(t, h)
	// Through the export ahead, a prune deletes x's first version alone, with its transaction's commit
	// record, which both have read.
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), ahead); err != nil || n != 2 {
		t.Fatalf("PruneHistory of what both exports read = %d, %v", n, err)
	}
	for _, c := range []rbac.Cursor{behind, ahead} {
		if _, _, err := h.authz.History(ctx, c, 1); err != nil {
			t.Fatalf("History after a prune of what it read: %v", err)
		}
	}
	// d is granted and revoked, and a prune through a later export deletes both: after both cursors,
	// whose records stay.
	exec(grantLogin, "d")
	exec(`DELETE FROM rbac_grants WHERE principal = 'user:d'`)
	exec(grantLogin, "f")
	further := exported(t, h)
	// Both, and their transactions' commit records.
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), further); err != nil || n != 4 {
		t.Fatalf("PruneHistory past both = %d, %v", n, err)
	}
	for _, c := range []rbac.Cursor{behind, ahead} {
		if got, _, err := h.authz.History(ctx, c, rbac.MaxHistory); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("History from a cursor a prune went past: %d records, %v", len(got), err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from, err := rbac.Checkpoint{Cursor: behind, Count: 7, Hash: sha256.Sum256([]byte("the chain so far"))}.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if got, next, err := h.authz.Export(ctx, from, rbac.MaxHistory, key); !errors.Is(err, rbac.ErrInvalid) || !reflect.DeepEqual(next, from) {
		t.Errorf("Export from a checkpoint a prune went past: %d records, %+v, %v", len(got), next, err)
	}
	if _, _, err := h.authz.History(ctx, further, 1); err != nil {
		t.Errorf("History past the prune: %v", err)
	}
}

// A prune recorded before migration 0020 holds the cursor it went through, not the last record it
// deleted: History refuses a cursor before that one, after which it may have deleted records.
func TestHistoryRefusesACursorBeforeWhereAnEarlierPruneWent(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'membership'`)
	h.as(t, "v")
	through := exported(t, h)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
		VALUES (now(), '', 'history', '2025-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '2025-01-01 00:00:00+00',
		  'through', jsonb_build_object('txid', $1::text, 'id', $2::bigint), 'deleted', 1, 'reached', $2::bigint), 'PruneHistory')`,
		fmt.Sprint(through.TxID), through.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.authz.History(ctx, behind, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History from before where a prune went: %v", err)
	}
	if _, _, err := h.authz.History(ctx, through, 1); err != nil {
		t.Errorf("History from where a prune went: %v", err)
	}
}

// History refuses a cursor a prune went past whether or not it would read anything after it, as
// while a transaction that took its id before what follows runs, rather than read nothing and
// refuse the cursor only once that has ended.
func TestHistoryRefusesACursorAPruneWentPastWhileItReadsNothing(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, id := range []string{"a", "d", "f"} {
		h.as(t, id)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(grantLogin, "a")
	behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:a'`)
	exec(grantLogin, "d")
	exec(`DELETE FROM rbac_grants WHERE principal = 'user:d'`)
	older, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = older.Rollback(ctx) }()
	if _, err := older.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	// What follows d's revoke, and the prune, are of transactions after the older one.
	exec(grantLogin, "f")
	// d's grant and revoke, and their transactions' commit records.
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), exported(t, h)); err != nil || n != 4 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if got, _, err := h.authz.History(ctx, behind, rbac.MaxHistory); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History from a cursor a prune went past, with nothing after it to read: %+v, %v", got, err)
	}
}

// History finds the prunes that reached past its cursor by history's index of them, so what it reads
// to check a cursor grows neither with the prunes recorded before it, which no prune removes, nor
// with the records after it, of however many tenants, as a cursor far behind has.
func TestHistoryChecksACursorAsFastWhateverHistoryHolds(t *testing.T) {
	h := setup(t)
	// The pages of history and its indexes a read of a record reads, from a cursor after prunes and
	// before records, each of a tenant of its own.
	read := func(t *testing.T, prunes, records int) int64 {
		t.Helper()
		ctx := t.Context()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
			SELECT now(), '', 'history', to_char(now() - interval '1 year' - i * interval '1 second', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'prune',
			  jsonb_build_object('through', jsonb_build_object('txid', '1', 'id', 1), 'last', jsonb_build_object('txid', '1', 'id', 1)), 'PruneHistory'
			FROM generate_series(1, $1) i`, prunes); err != nil {
			t.Fatal(err)
		}
		cursor := exported(t, h)
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, after)
			SELECT now(), 'tenant-' || $1::int || '-' || i, 'grant', 'k' || i, 'create', 'user:k' || i, '{}' FROM generate_series(1, $1) i`, records); err != nil {
			t.Fatal(err)
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
		if _, _, err := h.authz.WithTx(tx).History(ctx, cursor, 1); err != nil {
			t.Fatal(err)
		}
		return historyPages(ctx, t, tx) - start
	}
	if few, many := read(t, 1, 1), read(t, 1000, 20000); many > few+10 {
		t.Fatalf("History read %d pages of history from a cursor between a prune and a record, and %d between 1,000 prunes and 20,000 records", few, many)
	}
}

// History finds the prunes that reached past its cursor by the last record each deleted, so what it
// reads to check a cursor grows with none of the prunes since its export began that went no further
// than the cursor, as each through it does while its export is the one furthest behind: whether the
// export catches up from the start, its cursor behind its Horizon, or has fallen behind past it. Found
// by where each was recorded, every one of them was read from history's rows, twice in each read, as
// in each window of a prune through it. It holds whether a statement is planned for its cursor or for
// any.
func TestHistoryChecksACursorAsFastWhateverPrunesWentThroughIt(t *testing.T) {
	for _, plans := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(plans, func(t *testing.T) {
			// One connection, so each read but the first finds history's indexes described already.
			h := setupOn(t, pgtest.Open(t, "pool_max_conns=1&plan_cache_mode="+plans))
			ctx := t.Context()
			for _, id := range []string{"a", "b", "c"} {
				h.as(t, id)
			}
			a := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:a'`)
			c := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:c'`)
			// Exports that have read b's membership: one from the start that began once c's was
			// written, and one that began before b's and fell behind there.
			catching := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:b'`)
			behind := catching
			catching.Horizon, behind.Horizon = c.TxID+1, catching.TxID
			// n prunes through b's membership, each deleting up to a's, and then statistics as
			// autovacuum's analyses keep them.
			prune := func(n int) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
					SELECT now(), '', 'history', to_char(now() - i * interval '1 second', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'prune',
					  jsonb_build_object('through', jsonb_build_object('txid', $1::text, 'id', $2::bigint),
					    'last', jsonb_build_object('txid', $3::text, 'id', $4::bigint)), 'PruneHistory'
					FROM generate_series(1, $5) i`, fmt.Sprint(catching.TxID), catching.ID, fmt.Sprint(a.TxID), a.ID, n); err != nil {
					t.Fatal(err)
				}
				if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
					t.Fatal(err)
				}
			}
			// The pages of history and its indexes a read of a record from cursor reads, once the
			// read before it has planned it as the statistics now say and the connection has read
			// how history's indexes are laid out.
			read := func(cursor rbac.Cursor) int64 {
				t.Helper()
				var pages int64
				for range 2 {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					start := historyPages(ctx, t, tx)
					if _, _, err := h.authz.WithTx(tx).History(ctx, cursor, 1); err != nil {
						t.Fatalf("History from a cursor no prune went past: %v", err)
					}
					pages = historyPages(ctx, t, tx) - start
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
				}
				return pages
			}
			// From prunes enough that history's indexes are as deep as they will be.
			prune(500)
			fewCatching, fewBehind := read(catching), read(behind)
			prune(2500)
			if many := read(catching); many > fewCatching+10 {
				t.Errorf("History read %d pages of history from a cursor behind its Horizon after 500 prunes through it, and %d after 3,000", fewCatching, many)
			}
			if many := read(behind); many > fewBehind+10 {
				t.Errorf("History read %d pages of history from a cursor past its Horizon after 500 prunes through it, and %d after 3,000", fewBehind, many)
			}
		})
	}
}

// So it does where history's statistics hold no prune, as until an analysis samples one, which it
// can miss while prunes are few among history's records: there the planner counted the prunes as
// none, and History and each window of a prune through the cursor read every one since the cursor
// by their transactions, to sort them; a prune read every prune to find where the last of the same
// time and cursor stopped, and AsOf every prune, twice, to find the latest. Here each prune is of
// a transaction of its own beside a change, as a host's prunes go on while the application writes,
// and history was last analyzed before them, with autovacuum off for it, so none of its analyses
// counts them meanwhile. It holds whether a statement is planned for its arguments or for any.
func TestReadingPrunesCostsAsMuchWhateverHistorysStatisticsCount(t *testing.T) {
	for _, plans := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(plans, func(t *testing.T) {
			// One record a prune, so one through the cursor deletes a's membership as it was alone.
			rbac.SetMaxPrune(t, 1)
			h := setupOn(t, pgtest.Open(t, "pool_max_conns=1&plan_cache_mode="+plans))
			ctx := t.Context()
			if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_history SET (autovacuum_enabled = off)`); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"a", "b", "c"} {
				h.as(t, id)
			}
			a := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:a'`)
			behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:b'`)
			behind.Horizon = behind.TxID
			// The application's records after the cursor; and after history's last analysis, a change
			// to a's membership, which supersedes the version before the cursor.
			for _, sql := range []string{
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'cluster', 'x' || i, 'user', 'x' || i, 'cluster.login' FROM generate_series(1, 20000) i`,
				`ANALYZE rbac_history`,
				`UPDATE rbac_memberships SET note = 'changed' WHERE principal = 'user:a'`,
			} {
				if _, err := h.pool.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			before := dbNow(t, h)
			// n prunes through the cursor, each deleting up to a's membership, and each in a
			// transaction of its own beside a change.
			prune := func(n int) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN FOR i IN 1..%d LOOP
					INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					  VALUES ('t1', 'cluster', 'y' || i || '-' || pg_current_xact_id(), 'user', 'w', 'cluster.login');
					INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
					  SELECT now(), '', 'history', to_char(now() - i * interval '1 second', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'prune',
					  jsonb_build_object('through', jsonb_build_object('txid', '%d', 'id', %d),
					    'last', jsonb_build_object('txid', '%d', 'id', %d)), 'PruneHistory';
					COMMIT; END LOOP; END $$`, n, behind.TxID, behind.ID, a.TxID, a.ID)); err != nil {
					t.Fatal(err)
				}
			}
			// The pages of history and its indexes a read of a record from the cursor, and a prune
			// through it, read, once the one before has planned it and read how history's indexes are
			// laid out; each rolled back.
			read := func(f func(pgx.Tx) error) int64 {
				t.Helper()
				var pages int64
				for range 7 {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					start := historyPages(ctx, t, tx)
					if err := f(tx); err != nil {
						_ = tx.Rollback(ctx)
						t.Fatal(err)
					}
					pages = historyPages(ctx, t, tx) - start
					if err := tx.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
				}
				return pages
			}
			history := func(tx pgx.Tx) error {
				_, _, err := h.authz.WithTx(tx).History(ctx, behind, 1)
				return err
			}
			pruning := func(tx pgx.Tx) error {
				_, err := rbac.PruneHistory(ctx, tx, before, behind)
				return err
			}
			asOf := func(tx pgx.Tx) error {
				return h.authz.WithTx(tx).AsOf(ctx, "t1", before, func(*rbac.Authorizer) error { return nil })
			}
			prune(300)
			fewRead, fewPruned, fewAsOf := read(history), read(pruning), read(asOf)
			prune(2700)
			if many := read(history); many > fewRead+10 {
				t.Errorf("History read %d pages of history from a cursor after 300 prunes through it, and %d after 3,000", fewRead, many)
			}
			if many := read(pruning); many > fewPruned+10 {
				t.Errorf("A prune through a cursor read %d pages of history after 300 prunes through it, and %d after 3,000", fewPruned, many)
			}
			if many := read(asOf); many > fewAsOf+10 {
				t.Errorf("AsOf read %d pages of history after 300 prunes, and %d after 3,000", fewAsOf, many)
			}
		})
	}
}

// History reads the records after its cursor in a statement of its own, after the one that checks
// the cursor: a prune past the cursor that commits between them is refused all the same, rather than
// read past.
func TestHistoryRefusesACursorAPruneWentPastAsItRead(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, id := range []string{"a", "d", "f"} {
		h.as(t, id)
	}
	if _, err := h.pool.Exec(ctx, grantLogin, "a"); err != nil {
		t.Fatal(err)
	}
	behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:a'`)
	for _, q := range []struct {
		sql  string
		args []any
	}{{grantLogin, []any{"d"}}, {`DELETE FROM rbac_grants WHERE principal = 'user:d'`, nil}, {grantLogin, []any{"f"}}} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	further, then := exported(t, h), dbNow(t, h)
	// Once no transaction in the cluster holds the records back, so the read finds them.
	cursor := behind
	drain(t, h, &cursor, 3)
	pruned := false
	rbac.SetFollowed(t, func(pgx.Tx) {
		if pruned {
			return
		}
		pruned = true
		// d's grant and revoke, and their transactions' commit records.
		if n, err := rbac.PruneHistory(ctx, h.pool, then, further); err != nil || n != 4 {
			t.Errorf("PruneHistory = %d, %v", n, err)
		}
	})
	if got, _, err := h.authz.History(ctx, behind, rbac.MaxHistory); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History from a cursor a prune went past as it read: %+v, %v", got, err)
	}
}

// A delete from history, which only a role with the rights of history's owner makes, is refused as
// its transaction commits unless a prune it records reaches the record, so an export from before
// the record reads it, or is refused: by the last record it deleted, or as one recorded before
// migration 0020, the cursor it went through. And only a record of an earlier transaction, as a
// prune is recorded after what it deletes, so History finds it after any cursor it went past.
func TestHistoryRefusesADeleteNoPruneRecords(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	behind := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE entity = 'membership'`)
	for _, id := range []string{"v", "w"} {
		h.as(t, id)
	}
	record := func(principal string) int64 {
		t.Helper()
		var id int64
		if err := h.pool.QueryRow(ctx, `SELECT id FROM rbac_history WHERE entity = 'membership' AND principal = $1`, principal).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// del deletes record id as history's owner, first recording a prune reaching it by reach, last or
	// through, unless reach is empty, and returns what committing did.
	del := func(tx pgx.Tx, reach string, id int64) error {
		t.Helper()
		if _, err := tx.Exec(ctx, `SELECT set_config('rbac.prune', 'on', true)`); err != nil {
			t.Fatal(err)
		}
		if reach != "" {
			if _, err := tx.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
				SELECT now(), '', 'history', '0001-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '0001-01-01 00:00:00+00',
				  $1::text, jsonb_build_object('txid', txid::text, 'id', id), 'deleted', 1), ''
				FROM rbac_history WHERE id = $2`, reach, id); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM rbac_history WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		return tx.Commit(ctx)
	}
	refused := func(what string, err error) {
		t.Helper()
		if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: %v", what, err)
		}
	}
	begin := func() pgx.Tx {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
		return tx
	}
	refused("a delete no prune records", del(begin(), "", record("user:v")))
	if _, _, err := h.authz.History(ctx, behind, 1); err != nil {
		t.Fatalf("History after a delete refused: %v", err)
	}
	// A transaction that took its id before a record, recording a prune of it after.
	early := begin()
	if _, err := early.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	h.as(t, "late")
	refused("a delete of a record of a later transaction", del(early, "last", record("user:late")))
	if err := del(begin(), "last", record("user:v")); err != nil {
		t.Fatalf("a delete a prune records by the last record it deleted: %v", err)
	}
	if err := del(begin(), "through", record("user:w")); err != nil {
		t.Fatalf("a delete a prune records by the cursor it went through: %v", err)
	}
	if _, _, err := h.authz.History(ctx, behind, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("History from before a delete a prune records: %v", err)
	}
}

// rbac_history_pruned lets a delete through for any prune its transaction records, whatever the
// record's id, which history's owner can choose, and History counts the prunes of every transaction
// from its export's Horizon on, whatever theirs: so a prune numbered 0 or below, in the transaction
// that was the oldest running as an export began, and so before any record of its own in History's
// order, refuses the export's cursor before what it deleted, as one numbered after them does.
func TestHistoryCountsAPruneWhateverItsRecordIsNumbered(t *testing.T) {
	for _, id := range []int64{-1, 0, 1 << 60} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			for _, p := range []string{"a", "b"} {
				h.as(t, p)
			}
			var b int64
			if err := h.pool.QueryRow(ctx, `SELECT id FROM rbac_history WHERE principal = 'user:b'`).Scan(&b); err != nil {
				t.Fatal(err)
			}
			owner, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = owner.Rollback(context.WithoutCancel(ctx)) }()
			// An export that has read a's membership, before b's, and began as owner's transaction
			// was the oldest running.
			cursor := cursorAt(t, h, `SELECT txid, id, recorded_at FROM rbac_history WHERE principal = 'user:a'`)
			if err := owner.QueryRow(ctx, `SELECT pg_current_xact_id()`).Scan(&cursor.Horizon); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `SELECT set_config('rbac.prune', 'on', true)`); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `INSERT INTO rbac_history (id, effective_at, tenant, entity, key, op, after, how) OVERRIDING SYSTEM VALUE
				SELECT $1, now(), '', 'history', '0001-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '0001-01-01 00:00:00+00',
				  'last', jsonb_build_object('txid', txid::text, 'id', id), 'deleted', 1), ''
				FROM rbac_history WHERE id = $2`, id, b); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, `DELETE FROM rbac_history WHERE id = $1`, b); err != nil {
				t.Fatal(err)
			}
			if err := owner.Commit(ctx); err != nil {
				t.Fatalf("a delete a prune numbered %d records: %v", id, err)
			}
			if got, _, err := h.authz.History(ctx, cursor, rbac.MaxHistory); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("History from before a delete a prune numbered %d records: %d records, %v", id, len(got), err)
			}
		})
	}
}

// interleaved writes the rows of k1, d, k2, e and k3, of which d's and e's are granted and revoked,
// so a prune through the end deletes every version of them, between the rows it keeps, and the
// commit records of their four transactions, and returns the cursor after them all.
func interleaved(t *testing.T, h *harness) rbac.Cursor {
	t.Helper()
	ctx := t.Context()
	for _, id := range []string{"k1", "d", "k2", "e", "k3"} {
		h.as(t, id)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{grantLogin, []any{"k1"}},
		{grantLogin, []any{"d"}},
		{`DELETE FROM rbac_grants WHERE principal = 'user:d'`, nil},
		{grantLogin, []any{"k2"}},
		{grantLogin, []any{"e"}},
		{`DELETE FROM rbac_grants WHERE principal = 'user:e'`, nil},
		{grantLogin, []any{"k3"}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	return exported(t, h)
}

// An export from the start after a prune, as after History refuses a cursor or a failover starts a
// generation, reads history as the prune left it: it stands before the last record the prune
// deleted, as an export begun before the prune could, but began after it, so it reads to the end
// one record at a time, and its chain verifies.
func TestExportingFromTheStartAfterAPrune(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := interleaved(t, h)
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); err != nil || n != 8 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var from, start rbac.Checkpoint
	var all []rbac.Record
	for deadline := time.Now().Add(10 * time.Second); from.Count == 0 || from.Cursor.ID < through.ID; {
		got, next, err := h.authz.Export(ctx, from, 1, key)
		if err != nil {
			t.Fatalf("Export from the start after %d records: %v", len(all), err)
		}
		if from.Count == 0 {
			start = rbac.Genesis(next.Cursor.Generation)
		}
		if len(got) == 0 && time.Now().After(deadline) {
			t.Fatalf("read %d records", len(all))
		}
		all, from = append(all, got...), next
	}
	if err := rbac.VerifyChain(start, all, from, key.Public()); err != nil {
		t.Fatal(err)
	}
}

// An export that begins while a transaction older than a prune is still running reads nothing until
// that one ends: its Horizon, the oldest transaction it saw running, would count the prune as one
// since it began, and refuse its cursor once it had read a record before the last the prune deleted.
func TestExportingFromTheStartWaitsForATransactionOlderThanAPrune(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := interleaved(t, h)
	older, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = older.Rollback(ctx) }()
	if _, err := older.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); err != nil || n != 8 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	got, cursor, err := h.authz.History(ctx, rbac.Cursor{}, 1)
	if err != nil || len(got) != 0 {
		t.Fatalf("History from the start while a transaction older than a prune runs: %+v, %v", got, err)
	}
	if err := older.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// The memberships, the creator's grant, k1's, k2's and k3's, and the prune's record.
	drain(t, h, &cursor, 10)
}

// A prune in a transaction that took its id before an export's first read from the start, and
// commits after it, is of one the read saw running, no older than the export's Horizon: History
// refuses the export's cursor before the last record the prune deleted.
func TestHistoryRefusesAnExportBegunAsAPrunesTransactionRan(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := interleaved(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var txid uint64
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()`).Scan(&txid); err != nil {
		t.Fatal(err)
	}
	var cursor rbac.Cursor
	for deadline := time.Now().Add(10 * time.Second); cursor.ID == 0; {
		got, next, err := h.authz.History(ctx, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 && time.Now().After(deadline) {
			t.Fatal("read 0 records")
		}
		cursor = next
	}
	if cursor.Horizon == 0 || cursor.Horizon > txid {
		t.Fatalf("an export begun as transaction %d ran has Horizon %d", txid, cursor.Horizon)
	}
	if n, err := rbac.PruneHistory(ctx, tx, dbNow(t, h), through); err != nil || n != 8 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.authz.History(ctx, cursor, 10); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("History from before what a prune of a transaction running as its export began deleted: %v", err)
	}
}

// exporter is an export in TestHistoryRefusesExactlyTheExportsAPruneDeletedFrom: where it stands,
// whether it has begun, by a read from the start that found records, whether a prune has since
// deleted a record after its cursor, which it then never reads, and whether one deleted the
// cursor's own record, which History refuses too, as it can't tell that from a restore; and whether
// its cursor has no Horizon, as one kept from before Cursor had one.
type exporter struct {
	cursor                      rbac.Cursor
	begun, harmed, unmet, stale bool
}

// place is a record's place in History's order.
type place struct {
	txid uint64
	id   int64
}

func (p place) compare(q place) int {
	return cmp.Or(cmp.Compare(p.txid, q.txid), cmp.Compare(p.id, q.id))
}

func placeOf(c rbac.Cursor) place { return place{c.TxID, c.ID} }

// Exports at random cursors, among random writes, a transaction that took its id early, and prunes
// through a random export's cursor, of this release alone, two in a host's transaction, or one in a
// host's that took its id early, as an export reads, of a release before migration 0020, or by hand
// as a role with the rights of history's owner, whose record holds an id that role chose, 0, below
// it or past every other, alone or in a host's transaction that took its id early: each export
// reads every record history holds after its cursor, and is refused exactly where a prune since it
// began deleted a record after its cursor, or for one recorded before 0020, went through a cursor
// after it, or deleted its cursor's record. One that began after a prune, as an export from the
// start again, is never refused for it, unless its cursor lost its Horizon, as one kept from before
// Cursor had one: then it is refused where a prune since it began deleted a record after it, and
// may be where an earlier one did.
func TestHistoryRefusesExactlyTheExportsAPruneDeletedFrom(t *testing.T) {
	var refusals int
	for seed := range uint64(60) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) { refusals += randomExports(t, seed) })
	}
	if refusals == 0 {
		t.Error("no export was refused: transactions elsewhere in the cluster held every read back")
	}
}

// randomExports runs TestHistoryRefusesExactlyTheExportsAPruneDeletedFrom's exports of seed, and
// returns how many reads were refused.
func randomExports(t *testing.T, seed uint64) (refusals int) {
	t.Helper()
	h := setup(t)
	ctx := t.Context()
	admin := ownersRights(t, h)
	rng := mrand.New(mrand.NewPCG(seed, seed))
	users := []string{"p0", "p1", "p2", "p3", "p4", "p5"}
	for _, id := range users {
		h.as(t, id)
	}
	// heldOn is every record history holds, as q reads it, in History's order; with records alone,
	// those History reads, but for transactions' commit records, which it returns with each.
	heldOn := func(q rbac.DB, records bool) []place {
		t.Helper()
		rows, err := q.Query(ctx, `SELECT txid, id FROM rbac_history WHERE NOT $1 OR entity <> 'commit' ORDER BY txid, id`, records)
		if err != nil {
			t.Fatal(err)
		}
		ps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (place, error) {
			var p place
			return p, row.Scan(&p.txid, &p.id)
		})
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	held := func() []place { return heldOn(h.pool, false) }
	readable := func() []place { return heldOn(h.pool, true) }
	// begin begins a host's transaction, rolled back if the test stops before it ends, as the pool
	// it holds a connection of closes only once that is back.
	begin := func(level pgx.TxIsoLevel) pgx.Tx {
		t.Helper()
		tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: level})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.WithoutCancel(ctx)) })
		return tx
	}
	exports := []*exporter{{}, {}}
	// bygone is every record a prune deleted, and for one of a release before 0020, the cursor it
	// went through, whenever it ran.
	var bygone []place
	// pruned marks harmed each export begun before a prune that, from what history held, was, to
	// what it holds, now, deleted a record after its cursor, or for one of a release before 0020,
	// went through a cursor after it; and unmet one whose cursor's record it deleted.
	pruned := func(was, now []place, through *rbac.Cursor) {
		gone := slices.DeleteFunc(was, func(p place) bool {
			_, ok := slices.BinarySearchFunc(now, p, place.compare)
			return ok
		})
		bygone = append(bygone, gone...)
		if through != nil {
			bygone = append(bygone, placeOf(*through))
		}
		for _, e := range exports {
			if !e.begun {
				continue
			}
			c := placeOf(e.cursor)
			e.harmed = e.harmed || slices.ContainsFunc(gone, func(p place) bool { return p.compare(c) > 0 }) ||
				through != nil && placeOf(*through).compare(c) > 0
			e.unmet = e.unmet || slices.ContainsFunc(gone, func(p place) bool { return p.compare(c) == 0 })
		}
	}
	// mayRefuse reports whether History may refuse e: harmed or unmet, or without a Horizon, after a
	// cursor a prune went past at any time.
	mayRefuse := func(e *exporter) bool {
		c := placeOf(e.cursor)
		return e.harmed || e.unmet || e.stale && slices.ContainsFunc(bygone, func(p place) bool { return p.compare(c) > 0 })
	}
	// refusable reports whether History may refuse the export at c.
	refusable := func(c rbac.Cursor) bool {
		return slices.ContainsFunc(exports, func(e *exporter) bool { return e.cursor == c && mayRefuse(e) })
	}
	// through is the cursor of a random export that has begun, or nil.
	through := func() *rbac.Cursor {
		var begun []*exporter
		for _, e := range exports {
			if e.begun {
				begun = append(begun, e)
			}
		}
		if len(begun) == 0 {
			return nil
		}
		c := begun[rng.IntN(len(begun))].cursor
		return &c
	}
	// prune prunes history on db through c, as of now or of when a random record took effect, which
	// it refuses only where History may refuse the export at c.
	prune := func(db rbac.DB, c rbac.Cursor) {
		t.Helper()
		query := `SELECT clock_timestamp()`
		if rng.IntN(3) == 0 {
			query = `SELECT effective_at FROM rbac_history ORDER BY random() LIMIT 1`
		}
		var before time.Time
		if err := h.pool.QueryRow(ctx, query).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := rbac.PruneHistory(ctx, db, before, c); err != nil && (!refusable(c) || !errors.Is(err, rbac.ErrInvalid)) {
			t.Fatalf("PruneHistory through %+v: %v", c, err)
		}
	}
	// forged counts forge's prunes, whose records' ids it keeps apart; zero is whether one is 0.
	var forged int64
	var zero bool
	// forge deletes on tx by hand, as admin, up to two random records before c, and records a prune
	// of them as PruneHistory never would: its record's id is one admin chose, 0, below it or past
	// every other, and it reaches them by the last it deleted or, as one recorded before 0020, by c,
	// the cursor it went through, which it returns, and otherwise nil. It records the prune before
	// its delete, or after, as the trigger checks the delete as tx commits, unless tx checks
	// constraints at each statement.
	forge := func(tx pgx.Tx, c rbac.Cursor) (through *rbac.Cursor) {
		t.Helper()
		forged++
		ids := []int64{-forged, 1<<60 + forged}
		if !zero {
			ids = append(ids, 0)
		}
		id := ids[rng.IntN(len(ids))]
		zero = zero || id == 0
		immediate := rng.IntN(2) == 0
		settings := []string{`SELECT set_config('rbac.prune', 'on', true)`}
		if admin != "" {
			settings = append(settings, `SET LOCAL ROLE `+admin)
		}
		if immediate {
			settings = append(settings, `SET CONSTRAINTS ALL IMMEDIATE`)
		}
		for _, sql := range settings {
			if _, err := tx.Exec(ctx, sql); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		var victims []int64
		if err := tx.QueryRow(ctx, `SELECT ARRAY(SELECT id FROM rbac_history WHERE (txid, id) < ($1::xid8, $2) ORDER BY random() LIMIT 2)`,
			fmt.Sprint(c.TxID), c.ID).Scan(&victims); err != nil {
			t.Fatal(err)
		}
		if len(victims) == 0 {
			return nil
		}
		var reached place
		if err := tx.QueryRow(ctx, `SELECT txid, id FROM rbac_history WHERE id = ANY ($1) ORDER BY txid DESC, id DESC LIMIT 1`, victims).
			Scan(&reached.txid, &reached.id); err != nil {
			t.Fatal(err)
		}
		reach := "last"
		if rng.IntN(3) == 0 {
			reach, reached, through = "through", placeOf(c), &c
		}
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rbac_history (id, effective_at, tenant, entity, key, op, after, how) OVERRIDING SYSTEM VALUE
			  VALUES ($1, now(), '', 'history', '0001-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '0001-01-01 00:00:00+00',
			    $2::text, jsonb_build_object('txid', $3::text, 'id', $4::bigint), 'deleted', $5::int), '')`, []any{id, reach, fmt.Sprint(reached.txid), reached.id, len(victims)}},
			{`DELETE FROM rbac_history WHERE id = ANY ($1)`, []any{victims}},
		}
		if !immediate && rng.IntN(2) == 0 {
			slices.Reverse(statements)
		}
		for _, s := range statements {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				t.Fatalf("%s: %v", s.sql, err)
			}
		}
		return through
	}
	// read reads a random few records from e's cursor, on its own transaction or a host's, with arm
	// set to run between checking the cursor and reading, and checks that it read every record
	// history holds between its cursor and the next, or that it was refused, as only a harmed or
	// unmet export is, which then begins again: an unmet one reads on where the prune that deleted
	// its cursor's record committed as it read. While patient, it reads again for a while where
	// transactions elsewhere in the cluster hold back records it hasn't read. It returns how many it
	// read.
	read := func(e *exporter, patient bool, arm func(pgx.Tx)) int {
		t.Helper()
		for deadline := time.Now().Add(time.Second); ; {
			rbac.SetFollowed(t, arm)
			limit := 1 + rng.IntN(4)
			var got []rbac.Record
			var next rbac.Cursor
			var err error
			if level := rng.IntN(3); level == 0 {
				got, next, err = h.authz.History(ctx, e.cursor, limit)
			} else {
				// A host's snapshot taken before the prune would read what it deleted.
				if level == 2 {
					rbac.SetFollowed(t, func(pgx.Tx) {})
				}
				tx := begin([]pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead}[level-1])
				got, next, err = h.authz.WithTx(tx).History(ctx, e.cursor, limit)
				if rerr := tx.Rollback(ctx); rerr != nil {
					t.Fatal(rerr)
				}
			}
			rbac.SetFollowed(t, func(pgx.Tx) {})
			switch {
			case mayRefuse(e) && errors.Is(err, rbac.ErrInvalid):
				refusals++
				*e = exporter{}
				return 0
			case e.harmed && (err != nil || len(got) > 0):
				t.Fatalf("an export a prune harmed, from %+v: %d records, %v", e.cursor, len(got), err)
			case e.harmed:
				// A prune that committed as it read deleted all it would have read.
				return 0
			case err != nil:
				t.Fatalf("an export no prune harmed, from %+v: %v", e.cursor, err)
			}
			var want []place
			for _, p := range readable() {
				if p.compare(placeOf(e.cursor)) > 0 && (len(got) == 0 || p.compare(placeOf(next)) <= 0) {
					want = append(want, p)
				}
			}
			if len(got) == 0 {
				if patient && len(want) > 0 && time.Now().Before(deadline) {
					arm = func(pgx.Tx) {}
					time.Sleep(10 * time.Millisecond)
					continue
				}
				return 0
			}
			places := make([]place, len(got))
			for i, r := range got {
				places[i] = place{r.TxID, r.ID}
			}
			if !slices.Equal(places, want) {
				t.Fatalf("from %+v, read %v of %v", e.cursor, places, want)
			}
			e.cursor, e.begun, e.unmet = next, true, false
			return len(got)
		}
	}
	var early, pruner pgx.Tx
	for step := range 200 {
		if early != nil && rng.IntN(4) == 0 {
			if err := early.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			early = nil
		}
		switch op := rng.IntN(23); {
		case op < 6:
			// A grant, its change or its revoke; or in the transaction that took its id early, a
			// membership no other write touches, so none waits for it.
			u := users[rng.IntN(len(users))]
			var err error
			switch k := rng.IntN(4); {
			case early != nil && k == 0:
				_, err = early.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', $1)`,
					fmt.Sprint("early", step))
			case k <= 1:
				_, err = h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'cluster', 'c1', 'user', $1, 'cluster.login' WHERE NOT EXISTS (SELECT FROM rbac_grants WHERE principal = 'user:' || $1)`, u)
			case k == 2:
				_, err = h.pool.Exec(ctx, `UPDATE rbac_grants SET note = $2 WHERE principal = 'user:' || $1`, u, fmt.Sprint(step))
			default:
				_, err = h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:' || $1`, u)
			}
			if err != nil {
				t.Fatal(err)
			}
		case op < 7:
			// A transaction that takes its id now and commits later, which holds every export back
			// meanwhile, and its records come before those written since.
			if early == nil {
				tx := begin(pgx.ReadCommitted)
				if _, err := tx.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
					t.Fatal(err)
				}
				early = tx
			}
		case op < 8:
			// A host's transaction that takes its id now, and later prunes and commits: it deletes
			// records of earlier transactions, and its record comes before those written since, so an
			// export that began meanwhile, with a Horizon no later than it, counts it, as it does one
			// by hand whose record's id puts it before every other of that transaction.
			if pruner == nil {
				tx := begin(pgx.ReadCommitted)
				if _, err := tx.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
					t.Fatal(err)
				}
				pruner = tx
			} else if c := through(); c != nil {
				was := held()
				var went *rbac.Cursor
				if rng.IntN(2) == 0 {
					prune(pruner, *c)
				} else {
					went = forge(pruner, *c)
				}
				if err := pruner.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				pruner = nil
				pruned(was, held(), went)
			}
		case op < 10:
			exports = append(exports, &exporter{})
		case op < 16:
			// At times as a prune through another export's cursor commits between its checking the
			// cursor and reading.
			arm := func(pgx.Tx) {}
			if c := through(); c != nil && rng.IntN(4) == 0 {
				arm = func(pgx.Tx) {
					rbac.SetFollowed(t, func(pgx.Tx) {})
					was := held()
					prune(h.pool, *c)
					pruned(was, held(), nil)
				}
			}
			read(exports[rng.IntN(len(exports))], early == nil && pruner == nil, arm)
		case op < 19:
			c := through()
			if c == nil {
				continue
			}
			was := held()
			if rng.IntN(3) > 0 {
				prune(h.pool, *c)
			} else {
				// Two in a host's transaction, which may check constraints at each statement: the
				// second sees what the first deleted.
				tx := begin(pgx.ReadCommitted)
				if rng.IntN(2) == 0 {
					if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
						t.Fatal(err)
					}
				}
				prune(tx, *c)
				between := heldOn(tx, false)
				pruned(was, between, nil)
				prune(tx, *through())
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				was = between
			}
			pruned(was, held(), nil)
		case op < 20:
			// An export that goes on from its cursor kept without its Horizon, as one kept from before
			// Cursor had one.
			if e := exports[rng.IntN(len(exports))]; e.begun {
				e.cursor.Horizon, e.stale = 0, true
			}
		case op < 21:
			// A prune by hand, in a transaction of its own.
			if c := through(); c != nil {
				was := held()
				tx := begin(pgx.ReadCommitted)
				went := forge(tx, *c)
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				pruned(was, held(), went)
			}
		default:
			// A prune of a release before 0020: its record, written in a statement after its delete,
			// holds the cursor it went through, not the last record it deleted, and it refused a
			// cursor a prune since went past, as one whose export is harmed.
			c := through()
			if c == nil || refusable(*c) {
				continue
			}
			was := held()
			tx := begin(pgx.ReadCommitted)
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`SELECT set_config('rbac.prune', 'on', true)`, nil},
				{`DELETE FROM rbac_history WHERE id IN (SELECT id FROM rbac_history WHERE entity <> 'history'
				  AND (txid, id) < ($1::xid8, $2) ORDER BY random() LIMIT 2)`, []any{fmt.Sprint(c.TxID), c.ID}},
				{`INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
				  VALUES (now(), '', 'history', '0001-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '0001-01-01 00:00:00+00',
				    'through', jsonb_build_object('txid', $1::text, 'id', $2::bigint), 'deleted', 2), 'PruneHistory')`, []any{fmt.Sprint(c.TxID), c.ID}},
			} {
				if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			pruned(was, held(), c)
		}
	}
	for _, tx := range []pgx.Tx{early, pruner} {
		if tx != nil {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Each reads to the end of history, or is refused and then does.
	all := readable()
	last := all[len(all)-1]
	for i, e := range exports {
		for deadline := time.Now().Add(10 * time.Second); e.harmed || e.unmet || !e.begun || placeOf(e.cursor).compare(last) < 0; {
			if read(e, true, func(pgx.Tx) {}) == 0 && !e.harmed && time.Now().After(deadline) {
				t.Fatalf("export %d read up to %+v of %d records", i, e.cursor, len(all))
			}
		}
	}
	return refusals
}

// ownersRights gives history in h's schema to a role of its own, as the README's step 2 does, and
// returns, quoted, a role that is a member of it and no superuser, as the README's administrator's
// role is, both dropped when the test ends; or "" where the test database's role can't make roles,
// so that role, which owns history, acts for it.
func ownersRights(t *testing.T, h *harness) string {
	t.Helper()
	ctx := t.Context()
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	suffix := strings.ToLower(rand.Text())
	owner, admin := pgx.Identifier{"rbac_history_" + suffix}.Sanitize(), pgx.Identifier{"rbac_admin_" + suffix}.Sanitize()
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		for _, sql := range []string{
			`CREATE ROLE ` + owner, `CREATE ROLE ` + admin, `GRANT ` + owner + ` TO ` + admin,
			`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + admin,
			`ALTER TABLE rbac_history OWNER TO ` + owner,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return fmt.Errorf("%s: %w", sql, err)
			}
		}
		return nil
	}); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			return ""
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(ctx)
		for _, sql := range []string{
			`REASSIGN OWNED BY ` + owner + ` TO CURRENT_USER`, `DROP OWNED BY ` + owner + `, ` + admin, `DROP ROLE ` + admin + `, ` + owner,
		} {
			if _, err := h.pool.Exec(ctx, sql); err != nil {
				t.Errorf("%s: %v", sql, err)
			}
		}
	})
	return admin
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

// Records no trigger counted the bytes of, as history written before they were counted, are each
// measured by writing their rows out as JSON, so a read measures only so many of them, and stops at
// the next, however small: the next read goes on from there.
func TestHistoryMeasuresFewRecordsNoTriggerCounted(t *testing.T) {
	rbac.SetMaxUnsized(t, 2)
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, after)
		SELECT now(), 't1', 'grant', 'k' || i, 'create', 'user:u' || i, '{}' FROM generate_series(1, 5) i`); err != nil {
		t.Fatal(err)
	}
	var pages []int
	for deadline := time.Now().Add(10 * time.Second); len(pages) < 3 && time.Now().Before(deadline); {
		got, next, err := h.authz.History(ctx, cursor, rbac.MaxHistory)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > 0 {
			pages = append(pages, len(got))
		} else {
			time.Sleep(10 * time.Millisecond)
		}
		cursor = next
	}
	if !slices.Equal(pages, []int{2, 2, 1}) {
		t.Fatalf("read pages of %v records", pages)
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

// recordedSince reads the records after *last directly, in id order, but for commit records, which
// History returns with the others rather than as records, and moves *last past them:
// each change has committed, and History would wait on transactions other sessions hold open.
func recordedSince(t *testing.T, h *harness, last *int64) []recorded {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), `SELECT id, actor, on_behalf_of, how, request, reason, op FROM rbac_history
		WHERE id > $1 AND entity <> 'commit' ORDER BY id`, *last)
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
	// An expiry is no one's, and is recorded as one, after the time DeleteExpired deleted by, which
	// its function records in a statement of its own.
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); !slices.Equal(got, []recorded{{how: "DeleteExpired", op: "create"}, {how: "DeleteExpired", op: "expire"}}) {
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
	if got := recordedSince(t, h, &last); !slices.Equal(got, []recorded{{how: "DeleteExpired", op: "create"}, {how: "DeleteExpired", op: "expire"}}) {
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

// transactions is a tracer telling of each statement beginning or rolling back a transaction.
type transactions func(sql string)

func (f transactions) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "begin") || strings.HasPrefix(d.SQL, "rollback") {
		f(strings.Fields(d.SQL)[0])
	}
	return ctx
}

func (transactions) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// A change refused under its locks before it reads the clock there is dated by a reading it takes
// there, where it decided: not its reading from before them, nor one taken once its transaction
// ended.
func TestARefusalIsDatedTheTimeTheChangeDecidedAt(t *testing.T) {
	var mu sync.Mutex
	var log, told []string
	var refused []rbac.Refusal
	readings := 0
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	pool := pgtest.Open(t, "")
	cfg := pool.Config()
	cfg.ConnConfig.Tracer = transactions(func(sql string) {
		mu.Lock()
		defer mu.Unlock()
		log = append(log, sql)
	})
	traced, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(traced.Close)
	h := setupOn(t, traced, func(c *rbac.Config) {
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			at := base.Add(time.Duration(readings) * time.Minute)
			readings++
			log = append(log, at.Format(time.Kitchen))
			return at
		}
		c.OnRefused = func(_ context.Context, r rbac.Refusal) {
			mu.Lock()
			defer mu.Unlock()
			refused, told = append(refused, r), slices.Clone(log)
		}
	})
	owner := h.as(t, "owner")
	// The group is looked for under the locks, which need no time.
	nosuch := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "nosuch"}}}}
	if err := h.authz.Apply(t.Context(), owner, cluster, nosuch); !errors.Is(err, rbac.ErrInvalid) || len(refused) != 1 {
		t.Fatalf("Apply = %v, reported %+v", err, refused)
	}
	if n := len(told); n < 3 || told[n-3] != "begin" || told[n-2] != refused[0].At.Format(time.Kitchen) || told[n-1] != "rollback" {
		t.Errorf("the refusal is dated %s, by the clock read and transactions begun and rolled back %v", refused[0].At.Format(time.Kitchen), told)
	}
}

// A change refused under its locks by what committed while it waited for them is dated no earlier
// than that: its reading from before them can be.
func TestARefusalIsDatedAfterWhatTheChangeWaitedFor(t *testing.T) {
	var mu sync.Mutex
	var refused []rbac.Refusal
	readings := 0
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		readings++
		return base.Add(time.Duration(readings) * time.Minute)
	}
	h := setup(t, func(c *rbac.Config) {
		c.Now = now
		c.OnRefused = func(_ context.Context, r rbac.Refusal) {
			mu.Lock()
			defer mu.Unlock()
			refused = append(refused, r)
		}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	// The group is deleted in a transaction that holds it until it commits.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ops := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "ops"}}}}
	go func() { done <- h.authz.Apply(ctx, owner, cluster, ops) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("Apply waited for nothing the deletion holds: %v", err)
		default:
		}
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	deleted := now()
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("Apply to a group deleted while it waited = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(refused) != 1 || refused[0].At.Before(deleted) {
		t.Errorf("a change refused once the group was deleted at %v is dated %+v", deleted, refused)
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
	// u's first version, which its second superseded before then, and d, whose delete ended it, with
	// the commit records of the three transactions that wrote them.
	if n, err := rbac.PruneHistory(ctx, h.pool, then, through); err != nil || n != 6 {
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
		!strings.Contains(string(r.After), `"deleted": 6`) || r.Key != then.UTC().Format("2006-01-02T15:04:05.000000Z") {
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
	// Nor one past the times the package stores, yet to come: 2^64 microseconds on, pgx would send it
	// as a time that has passed, and past PostgreSQL's times, as one it refuses as out of range.
	h.as(t, "since")
	for _, before := range []time.Time{wrapped(dbNow(t, h), 1), time.Date(300000, time.January, 1, 0, 0, 0, 0, time.UTC)} {
		if n, err := rbac.PruneHistory(ctx, h.pool, before, exported(t, h)); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a prune of history up to year %d: %d, %v", before.Year(), n, err)
		}
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
	// as history's owner, with no commit record, as before history recorded commits.
	var row string
	if err := h.pool.QueryRow(ctx, `SELECT to_jsonb(g) || jsonb_build_object('id', gen_random_uuid(), 'principal_id', 'dated', 'principal', 'user:dated')
		FROM rbac_grants g WHERE principal = 'user:mark'`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		at time.Time
		op string
	}{{then.Add(time.Millisecond), "create"}, {then.Add(-time.Second), "delete"}} {
		if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_committed`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, before, after)
				SELECT $1, 't1', 'grant', r->>'id', $2, r->>'principal', r->>'role', r->>'scope',
				  CASE $2 WHEN 'delete' THEN r END, CASE $2 WHEN 'create' THEN r END
				FROM (SELECT $3::jsonb r) x`, r.at, r.op, row); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed`)
			return err
		}); err != nil {
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
// A prune is recorded in the statement that deletes, so one in a transaction that checks
// constraints at the end of each statement, rather than as it commits, is recorded by then. The
// host's transaction gets back the sorting and JIT the prune turned off.
func TestPruningHistoryOnAHostsTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET note = 'changed' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	through := exported(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE; SET LOCAL jit = on; SET LOCAL enable_sort = on`); err != nil {
		t.Fatal(err)
	}
	// The membership's first version and its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, tx, dbNow(t, h), through); err != nil || n != 2 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	var jit, sorting string
	if err := tx.QueryRow(ctx, `SELECT current_setting('jit'), current_setting('enable_sort')`).Scan(&jit, &sorting); err != nil ||
		jit != "on" || sorting != "on" {
		t.Errorf("after the prune, jit %q and enable_sort %q, %v", jit, sorting, err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM rbac_history WHERE id = (SELECT min(id) FROM rbac_history)`)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("a delete from history after the prune: %v", err)
	}
}

// History, a prune and AsOf read prunes with sorting and JIT off, and give a host's transaction its
// own settings back, whether they read or refuse; AsOf before its read, which plans as the host's
// statements do, but without JIT.
func TestReadingPrunesLeavesTheHostsSettings(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	then := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET note = 'changed' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	through := exported(t, h)
	// The membership's first version and its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); err != nil || n != 2 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL jit = on; SET LOCAL enable_sort = on`); err != nil {
		t.Fatal(err)
	}
	settings := func() string {
		t.Helper()
		var jit, sorting string
		if err := tx.QueryRow(ctx, `SELECT current_setting('jit'), current_setting('enable_sort')`).Scan(&jit, &sorting); err != nil {
			t.Fatal(err)
		}
		return "jit " + jit + ", enable_sort " + sorting
	}
	a := h.authz.WithTx(tx)
	var reading string
	read := func(*rbac.Authorizer) error {
		var jit, sorting string
		err := tx.QueryRow(ctx, `SELECT current_setting('jit'), current_setting('enable_sort')`).Scan(&jit, &sorting)
		reading = "jit " + jit + ", enable_sort " + sorting
		return err
	}
	now := dbNow(t, h)
	for _, c := range []struct {
		name    string
		call    func() error
		refused bool
	}{
		{"History", func() error { _, _, err := a.History(ctx, through, 1); return err }, false},
		{"History from another generation's cursor", func() error {
			_, _, err := a.History(ctx, rbac.Cursor{Generation: "another", TxID: through.TxID, ID: through.ID}, 1)
			return err
		}, true},
		{"PruneHistory", func() error { _, err := rbac.PruneHistory(ctx, tx, now, through); return err }, false},
		{"AsOf", func() error { return a.AsOf(ctx, "t1", now, read) }, false},
		{"AsOf of a time pruned", func() error { return a.AsOf(ctx, "t1", then, read) }, true},
	} {
		if err := c.call(); err != nil && !c.refused || c.refused && !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := settings(); got != "jit on, enable_sort on" {
			t.Errorf("after %s, %s", c.name, got)
		}
	}
	if reading != "jit off, enable_sort on" {
		t.Errorf("AsOf's read ran with %s", reading)
	}
}

// A prune is dated as any change is, when its statement began, not when its transaction did: on a
// host's transaction begun before the records it deletes were written, it was dated before them,
// and before its own before.
func TestAPruneIsDatedWhenItsStatementBegan(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// u's grant and its change, written after the host's transaction began, on other connections:
	// the prune deletes the grant's first version.
	for _, q := range []struct {
		sql  string
		args []any
	}{{grantLogin, []any{"u"}}, {`UPDATE rbac_grants SET note = 'changed' WHERE principal = 'user:u'`, nil}} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	var deleted time.Time
	if err := h.pool.QueryRow(ctx, `SELECT effective_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:u' AND op = 'create'`).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	through, before := exported(t, h), dbNow(t, h)
	// With its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, tx, before, through); err != nil || n != 2 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	var began, effective, recorded time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp(), effective_at, recorded_at FROM rbac_history WHERE entity = 'history' AND op = 'prune'`).
		Scan(&began, &effective, &recorded); err != nil {
		t.Fatal(err)
	}
	if effective.Before(deleted) || effective.Before(before) || effective.After(recorded) {
		t.Errorf("a prune on a transaction begun at %v, of %v, deleting a version dated %v, is dated %v and recorded at %v", began, before, deleted, effective, recorded)
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
	// And the commit records of the three transactions that wrote them.
	if total != 6 {
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
		// As of first, b's first version alone, which comes after a's, and its transaction's commit
		// record.
		if n := prune(t, h, first, through); n != 2 {
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
	// With its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, host, then, through); err != nil || n != 2 {
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
		// The other prune, of another time, records what it deletes, as a prune does.
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`SELECT set_config('rbac.prune', 'on', true)`, nil},
			{`INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
			  SELECT now(), '', 'history', '0001-01-01T00:00:00.000000Z', 'prune', jsonb_build_object('before', timestamptz '0001-01-01 00:00:00+00',
			    'deleted', 1, 'last', jsonb_build_object('txid', txid::text, 'id', id)), 'PruneHistory'
			  FROM rbac_history WHERE id = $1`, []any{ids[1]}},
			{`DELETE FROM rbac_history WHERE id = $1`, []any{ids[1]}},
		} {
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

// AsOf finds the latest prune by its record's key, its time in UTC, whatever the TimeZone of the
// session that pruned: from PostgreSQL 18 one of UTC+5 makes AT TIME ZONE 'UTC' five hours west, so
// a later prune made there was keyed before an earlier one, and AsOf read a time it had pruned. The
// key is as one written before in UTC, which a prune of the same time goes on from.
func TestAsOfRefusesATimeAPruneInAnotherTimeZonePruned(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'a', 'cluster.login')`)
	exec(`UPDATE rbac_grants SET note = 'first' WHERE principal = 'user:a'`)
	first := dbNow(t, h)
	exec(`UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:a'`)
	second := dbNow(t, h)
	exec(`UPDATE rbac_grants SET note = 'third' WHERE principal = 'user:a'`)
	through := exported(t, h)
	if n, err := rbac.PruneHistory(ctx, h.pool, first, through); err != nil || n == 0 {
		t.Fatalf("PruneHistory as of first = %d, %v", n, err)
	}
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET TimeZone = 'UTC+5'`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `RESET TimeZone`) }()
	if n, err := rbac.PruneHistory(ctx, conn.Conn(), second, through); err != nil || n == 0 {
		t.Fatalf("PruneHistory as of second under UTC+5 = %d, %v", n, err)
	}
	if got, err := notesAt(t, h, first); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("as of first, which the prune as of second pruned: %v, %v", got, err)
	}
	if got, err := notesAt(t, h, second); err != nil || got["a"] != "second" {
		t.Errorf("as of second: %v, %v", got, err)
	}
	var keyed bool
	if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_history WHERE entity = 'history' AND op = 'prune'
		AND key = to_char($1::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))`, second).Scan(&keyed); err != nil || !keyed {
		t.Errorf("the prune as of second is keyed as a UTC session keyed one before: %t, %v", keyed, err)
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

// commitDates is the name of the migration from which history records when each transaction that
// changes the package's tables commits: the first to make the trigger that records it.
func commitDates(t *testing.T) string {
	t.Helper()
	sqls := migrationSQL(t)
	for _, name := range slices.Sorted(maps.Keys(sqls)) {
		if strings.Contains(sqls[name], "CREATE CONSTRAINT TRIGGER rbac_history_committed") {
			return name
		}
	}
	t.Fatal("no migration records commits")
	return ""
}

// History returns with each record when its transaction committed, as history records it as the
// transaction commits, and returns no record of that itself: the same time for every record of a
// transaction, no earlier than any of them took effect, and no earlier than the transaction's end
// however long after its changes it ran.
func TestHistoryReturnsWhenEachRecordsTransactionCommitted(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	var cursor rbac.Cursor
	drain(t, h, &cursor, 2)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, q := range []string{grantLogin, `UPDATE rbac_grants SET note = 'later' WHERE principal = 'user:u'`} {
		args := []any{}
		if q == grantLogin {
			args = []any{"u"}
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	ran := dbNow(t, h)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 2)
	var cluster string
	if err := h.pool.QueryRow(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Entity == "commit" || r.CommittedAt.IsZero() || !r.CommittedAt.Equal(got[0].CommittedAt) || r.CommittedAt.Before(ran) || r.CommittedAt.Before(r.EffectiveAt) {
			t.Errorf("record %+v, of a transaction that ran to %v", r, ran)
		}
		if r.Cluster != cluster {
			t.Errorf("record %+v, written in cluster %s", r, cluster)
		}
	}
}

// A change committed before history recorded commits keeps its date: AsOf counts it from when its
// statement began, as it did, and History returns its records with no CommittedAt, chained as they
// were. One after counts from its commit.
func TestAChangeCommittedBeforeHistoryRecordedCommitsKeepsItsDate(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	to := commitDates(t)
	migrateFiles(t, pool, "", to)
	recordMigrations(t, pool, to)
	h := migrated(t, pool)
	h.as(t, "u")
	h.as(t, "v")
	for _, id := range []string{"u", "v"} {
		if _, err := pool.Exec(ctx, grantLogin, id); err != nil {
			t.Fatal(err)
		}
	}
	// Each revoke is made in a transaction held open past a moment, mid, that it commits after.
	revoke := func(id string) time.Time {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:' || $1::text`, id); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		var mid time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&mid); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return mid
	}
	before := revoke("u")
	if err := rbac.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	after := revoke("v")
	for _, c := range []struct {
		at   time.Time
		held map[string]bool
	}{{before, map[string]bool{"u": false, "v": true}}, {after, map[string]bool{"u": false, "v": true}}} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for id, held := range c.held {
				grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity(id)}})
				if err != nil {
					return err
				}
				if (len(grants) == 1) != held {
					t.Errorf("as of %v, %s holds %+v", c.at, id, grants)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	var cursor rbac.Cursor
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE entity <> 'commit'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	for _, r := range drain(t, h, &cursor, n) {
		if r.Entity == "grant" && r.Op == "delete" && (r.CommittedAt.IsZero() != (r.Principal.ID == "u") || (r.Cluster == "") != (r.Principal.ID == "u")) {
			t.Errorf("revoke %+v", r)
		}
	}
}

// A prune counts a version from when its transaction committed, as AsOf does, and deletes a
// transaction's commit record only with the last of its other records: a version made before a
// prune's time but committed after it is no later version by then, and one kept counts from its
// commit still.
func TestPruningCountsAVersionFromItsCommit(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	if _, err := h.pool.Exec(ctx, grantLogin, "u"); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE rbac_grants SET note = 'second' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	mid := dbNow(t, h)
	time.Sleep(20 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	commits := func() int {
		t.Helper()
		var n int
		if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history c WHERE c.entity = 'commit'
			AND c.txid IN (SELECT txid FROM rbac_history WHERE entity = 'grant' AND principal = 'user:u')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// As of mid, the update hadn't committed: the grant's first version is its last, and stays.
	if n, err := rbac.PruneHistory(ctx, h.pool, mid, exported(t, h)); err != nil || n != 0 {
		t.Fatalf("PruneHistory as of mid = %d, %v", n, err)
	}
	if got, err := notesAt(t, h, mid); err != nil || got["u"] != "" {
		t.Errorf("as of mid, after pruning: %v, %v", got, err)
	}
	if got := commits(); got != 2 {
		t.Errorf("history holds %d commit records of the grant's transactions", got)
	}
	// As of now, the first version is superseded, and goes with its transaction's commit record.
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), exported(t, h)); err != nil || n != 2 {
		t.Fatalf("PruneHistory as of now = %d, %v", n, err)
	}
	if got := commits(); got != 1 {
		t.Errorf("history holds %d commit records of the grant's transactions", got)
	}
	if got, err := notesAt(t, h, dbNow(t, h)); err != nil || got["u"] != "second" {
		t.Errorf("as of now, after pruning: %v, %v", got, err)
	}
}

// Versions of a row dated alike, as every write of a DO block is, cost a prune a few pages each, as
// versions dated apart do: each was tested for a later one in history's index of an entity's
// versions, which ordered those of one date by their places, oldest first, so each read every one
// before it.
func TestPruningVersionsDatedAlikeReadsAFewPagesForEach(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	const n = 2000
	if _, err := h.pool.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN FOR i IN 1..%d LOOP
		UPDATE rbac_memberships SET note = i::text WHERE tenant = 't1' AND principal = 'user:u'; END LOOP; END $$`, n)); err != nil {
		t.Fatal(err)
	}
	through := exported(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	start := historyPages(ctx, t, tx)
	deleted, err := rbac.PruneHistory(ctx, tx, dbNow(t, h), through)
	if err != nil || deleted < n {
		t.Fatalf("PruneHistory = %d, %v", deleted, err)
	}
	if pages := historyPages(ctx, t, tx) - start; pages > 20*deleted {
		t.Errorf("pruning %d versions dated alike read %d pages of history", deleted, pages)
	}
}
