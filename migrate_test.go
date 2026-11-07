package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"regexp"
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

// beforeMigration is a pool whose transactions run fire just before each sends sql, a migration.
type beforeMigration struct {
	*pgxpool.Pool
	sql  string
	fire func()
}

func (p *beforeMigration) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &beforeMigrationTx{Tx: tx, p: p}, nil
}

type beforeMigrationTx struct {
	pgx.Tx
	p *beforeMigration
}

func (tx *beforeMigrationTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if sql == tx.p.sql {
		tx.p.fire()
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

// migratedTo is the version rbac_migrations records last.
func migratedTo(t *testing.T, db rbac.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(t.Context(), `SELECT coalesce(max(version), 0) FROM rbac_migrations`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// latestMigration is the version of the last migration the package holds, which Migrate migrates
// to once nothing stops it.
func latestMigration(t *testing.T) int {
	t.Helper()
	files, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	var v int
	if _, err := fmt.Sscanf(files[len(files)-1], "%04d_", &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Migrating from 0015, a change that writes a grant just as 0019 starts, and then history, as each
// change to a table does, doesn't make 0019 give way, whether it imports a grant of a built-in role
// or deletes one, neither of which reads the tables 0016 locks first: each migration is applied in
// a transaction of its own, so none holds history from 0016 on while 0019 waits for rbac_grants,
// which it locks before history. Applied in one, every try of 0019 waited for the change, which
// waited for history.
func TestMigratingSeveralLocksEachAsItWouldAlone(t *testing.T) {
	seeks, err := fs.ReadFile(rbac.Migrations(), "0019_principal_seeks.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		write func(ctx context.Context, h *harness, scope rbac.Scope) error
	}{
		{"Import", func(ctx context.Context, h *harness, scope rbac.Scope) error {
			// Of another role there, as granting one held already changes nothing.
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(scope, "cluster.admin", rbac.User, "u")})
		}},
		{"DeleteGrants", func(ctx context.Context, h *harness, scope rbac.Scope) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(scope, "cluster.login", rbac.User, "u")})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			migrateFiles(t, pool, "", "0016")
			recordMigrations(t, pool, "0016")
			// Grants for each try's change to delete, and a member to hold them.
			for _, sql := range []string{
				`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'u')`,
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'cluster', 'k' || i, 'user', 'u', 'cluster.login' FROM generate_series(0, 9) i`,
			} {
				if _, err := pool.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			h := migrated(t, pool)
			rbac.SetMigrateAttempts(t, 3, time.Millisecond)
			db := &beforeMigration{Pool: pool, sql: string(seeks)}
			var fired int
			wrote := make(chan error, 10)
			db.fire = func() {
				done := make(chan error, 1)
				scope := rbac.Scope{Type: "cluster", ID: fmt.Sprintf("k%d", fired)}
				fired++
				go func() { done <- c.write(context.WithoutCancel(ctx), h, scope) }()
				// One result in wrote for each change, however the wait for it ends, as one is read for each.
				defer func() { go func() { wrote <- <-done }() }()
				// Until the change has written, or waits for a lock, as for history a migration holds.
				for deadline := time.Now().Add(10 * time.Second); len(done) == 0; time.Sleep(time.Millisecond) {
					var waiting bool
					if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
						WHERE NOT l.granted AND c.relnamespace = current_schema()::regnamespace)`).Scan(&waiting); err != nil {
						t.Error(err)
						return
					}
					if waiting {
						return
					}
					if time.Now().After(deadline) {
						t.Error("the change neither wrote nor waited")
						return
					}
				}
			}
			if err := rbac.Migrate(ctx, db); err != nil {
				t.Errorf("Migrate from 0015 beside a change as 0019 starts: %v", err)
			}
			if fired == 0 {
				t.Fatal("Migrate never applied 0019")
			}
			for range fired {
				if err := <-wrote; err != nil {
					t.Errorf("%s as 0019 starts: %v", c.name, err)
				}
			}
			if v := migratedTo(t, pool); v != latestMigration(t) {
				t.Errorf("migrated to %d", v)
			}
		})
	}
}

// A migration giving up leaves those Migrate applied before it applied and recorded: from 0015,
// with a read holding history, which only 0019 locks against reads, the tables are as 0018 left
// them, as rbac_migrations says, and migrating again once the read has ended goes on from there.
// On a host's transaction it applies all of them or none, as rolling back to its savepoint does.
func TestMigrateRecordsEachMigrationAsItCommits(t *testing.T) {
	// 0016 adds the check; 0019 builds the index.
	state := func(t *testing.T, db rbac.DB) (flat, seeks bool) {
		t.Helper()
		if err := db.QueryRow(t.Context(), `SELECT EXISTS (SELECT FROM pg_constraint
			WHERE conname = 'rbac_denies_principals_flat' AND connamespace = current_schema()::regnamespace),
			to_regclass('rbac_grants_custom_principal') IS NOT NULL`).Scan(&flat, &seeks); err != nil {
			t.Fatal(err)
		}
		return flat, seeks
	}
	for _, onHost := range []bool{false, true} {
		t.Run(fmt.Sprintf("host=%t", onHost), func(t *testing.T) {
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			migrateFiles(t, pool, "", "0016")
			recordMigrations(t, pool, "0016")
			rbac.SetMigrateAttempts(t, 2, time.Millisecond)
			reader, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Rollback(ctx) }()
			if _, err := reader.Exec(ctx, `SELECT FROM rbac_history LIMIT 1`); err != nil {
				t.Fatal(err)
			}
			var db rbac.DB = pool
			want, flat := 18, true
			if onHost {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
					t.Fatal(err)
				}
				db, want, flat = tx, 15, false
			}
			var pg *pgconn.PgError
			if err := rbac.Migrate(ctx, db); !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
				t.Fatalf("Migrate while a read holds history: %v", err)
			}
			if v := migratedTo(t, db); v != want {
				t.Errorf("after 0019 gave up, migrated to %d, want %d", v, want)
			}
			if f, s := state(t, db); f != flat || s {
				t.Errorf("after 0019 gave up, the tables hold 0016's check %t and 0019's index %t", f, s)
			}
			if onHost {
				return
			}
			if err := reader.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := rbac.Migrate(ctx, pool); err != nil {
				t.Fatalf("Migrate once the read has ended: %v", err)
			}
			if v := migratedTo(t, pool); v != latestMigration(t) {
				t.Errorf("migrated again to %d", v)
			}
			if _, s := state(t, pool); !s {
				t.Error("migrating again built no index")
			}
		})
	}
}

// No function of the package's keeps the name its schema had when it was made, which a rename would
// leave naming no schema, or another installation's, as rbac_record's and rbac_history_pruned's
// search_paths did: migrated from none, or with every migration from 0004 on pending, as for an
// installation a host's own tool first migrated, whose functions those migrations replace.
func TestNoFunctionKeepsItsSchemasName(t *testing.T) {
	for _, from := range []string{"", "0004"} {
		t.Run(fmt.Sprintf("from=%q", from), func(t *testing.T) {
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			if from != "" {
				migrateFiles(t, pool, "", from)
				recordMigrations(t, pool, from)
				if _, err := pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
					t.Fatal(err)
				}
			}
			if err := rbac.Migrate(ctx, pool); err != nil {
				t.Fatal(err)
			}
			rows, err := pool.Query(ctx, `SELECT p.proname || ' ' || array_to_string(p.proconfig, ', ') FROM pg_proc p
				WHERE p.pronamespace = current_schema()::regnamespace AND p.proconfig IS NOT NULL ORDER BY p.proname`)
			if err != nil {
				t.Fatal(err)
			}
			settings, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"rbac_group_members enable_seqscan=off",
				"rbac_history_append_only search_path=pg_catalog, pg_temp",
				"rbac_history_commit search_path=pg_catalog, pg_temp, plan_cache_mode=force_generic_plan, enable_seqscan=off",
				"rbac_history_pruned search_path=pg_catalog, pg_temp",
				"rbac_record search_path=pg_catalog, pg_temp, TimeZone=UTC, plan_cache_mode=force_generic_plan, enable_seqscan=off",
			}
			if !slices.Equal(settings, want) {
				t.Errorf("the package's functions are set as %q, want %q", settings, want)
			}
		})
	}
}

// Migrate on a host's transaction waits as long as that transaction's lock_timeout says, and leaves
// it so, through a host's wrapper around the transaction too, whose Begin gives a savepoint of it
// that can set the isolation it is at again: taken for a transaction of its own, the savepoint was
// bounded, and kept lock_timeout at 100 ms in the host's transaction once Migrate returned.
func TestMigrateOnAHostsTransactionLeavesItsLockTimeout(t *testing.T) {
	names, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	last := names[len(names)-1]
	for name, wrap := range map[string]func(pgx.Tx) rbac.DB{
		"the host's transaction":                  func(tx pgx.Tx) rbac.DB { return tx },
		"a wrapper around the host's transaction": func(tx pgx.Tx) rbac.DB { return hostTx{tx} },
	} {
		for _, timeout := range []string{"0", "5s"} {
			t.Run(fmt.Sprintf("%s/%s", name, timeout), func(t *testing.T) {
				ctx := t.Context()
				pool := pgtest.Open(t, "")
				migrateFiles(t, pool, "", last)
				recordMigrations(t, pool, last)
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, timeout); err != nil {
					t.Fatal(err)
				}
				if err := rbac.Migrate(ctx, wrap(tx)); err != nil {
					t.Fatalf("Migrate on %s: %v", name, err)
				}
				var after string
				if err := tx.QueryRow(ctx, `SELECT current_setting('lock_timeout')`).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if after != timeout {
					t.Errorf("Migrate on %s left its lock_timeout at %q, not %q", name, after, timeout)
				}
				if v := migratedTo(t, tx); v != latestMigration(t) {
					t.Errorf("migrated to %d", v)
				}
			})
		}
	}
}

// Migrate on a host's transaction comes before any change in it to the package's tables: from
// 0027_commit_dates on, each record of history a change writes holds an event deferred to the
// commit, as from 0020_recorded_prunes on each record a prune deletes does, and PostgreSQL alters no
// table whose events are pending, as migrations up to rbac.HistoryAltered alter history. Where one
// of those is pending, Migrate refuses a transaction holding such events, as ErrInvalid, before it
// applies any, or waits for another replica's migration, whose migration altering history can't
// commit while the transaction holds history, and the transaction goes on to commit its change with
// its commit record: one that changed the tables; pruned history, with the commit record's trigger
// on or off, or before 0027, as a release then pruned; or wrote a record of history as its owner,
// naming no cluster. It migrates one that took a transaction id writing no history, also where a
// commit record or a prune's record restored from another cluster holds that id; one that changed
// the tables before 0027, whose records hold no events, and whose change counts from its own date,
// with no commit record; and one that changed them once no migration pending alters history, which
// a later migration that does fails until HistoryAltered names it.
func TestMigrateOnAHostsTransactionComesBeforeItsChanges(t *testing.T) {
	const (
		change = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`
		took = `SELECT pg_current_xact_id()`
		// As a host's tool restoring history writes it.
		owned = `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
		VALUES (now(), 't1', 'grant', 'restored', 'create', '{}', 'restore')`
		// As PruneHistory of a release before 0027 pruned a grant's version.
		pruned = `SET LOCAL rbac.prune = 'on';
		WITH gone AS (DELETE FROM rbac_history WHERE entity = 'grant' RETURNING txid, id)
		INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, how)
		SELECT now(), '', 'history', 'pruned', 'prune', jsonb_build_object('last', jsonb_build_object('txid', txid::text, 'id', id)), 'PruneHistory'
		FROM gone`
	)
	altering, after := fmt.Sprintf("%04d", rbac.HistoryAltered), fmt.Sprintf("%04d", rbac.HistoryAltered+1)
	for _, c := range []struct {
		name, from, seed, write, restored string
		refused, replica, prune, off      bool
		commits                           int
	}{
		{name: "a change, with a migration altering history pending", from: altering, write: change, refused: true, commits: 1},
		{name: "a change, with a migration altering history pending, as another replica migrates", from: altering, write: change, refused: true, replica: true, commits: 1},
		{name: "a prune, with a migration altering history pending", from: altering, refused: true, prune: true},
		{name: "a prune, with the commit record's trigger off and a migration altering history pending", from: altering, refused: true, prune: true, off: true},
		{name: "a prune before history recorded commits", from: commitDates(t), seed: change, write: pruned, refused: true},
		{name: "a record history's owner writes naming no cluster, with a migration altering history pending", from: altering, write: owned, refused: true},
		{name: "a transaction id, with a migration altering history pending", from: altering, write: took},
		{name: "a transaction id a commit record restored from another cluster holds, with a migration altering history pending", from: altering, write: took, restored: "commit"},
		{name: "a transaction id a prune's record restored from another cluster holds, with a migration altering history pending", from: altering, write: took, restored: "prune"},
		{name: "a change before history recorded commits", from: commitDates(t), write: change},
		{name: "a change, with none pending altering history", from: after, write: change, commits: 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.from == after && latestMigration(t) <= rbac.HistoryAltered {
				t.Skip("no migration after the last that alters history")
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			pool := pgtest.Open(t, "")
			migrateFiles(t, pool, "", c.from)
			recordMigrations(t, pool, c.from)
			if c.seed != "" {
				if _, err := pool.Exec(ctx, c.seed); err != nil {
					t.Fatal(err)
				}
			}
			// A grant's first version, which its change supersedes, for a prune, once an export has read
			// both.
			var through rbac.Cursor
			var before time.Time
			if c.prune {
				for _, sql := range []string{change, `UPDATE rbac_grants SET note = 'changed'`} {
					if _, err := pool.Exec(ctx, sql); err != nil {
						t.Fatal(err)
					}
				}
				h := migrated(t, pool)
				drain(t, h, &through, 2)
				before = dbNow(t, h)
			}
			if c.off {
				if _, err := pool.Exec(ctx, `ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_committed`); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if c.write != "" {
				if _, err := tx.Exec(ctx, c.write); err != nil {
					t.Fatal(err)
				}
			}
			if c.prune {
				if n, err := rbac.PruneHistory(ctx, tx, before, through); err != nil || n == 0 {
					t.Fatalf("PruneHistory = %d, %v", n, err)
				}
			}
			if c.restored != "" {
				var txid, theirs string
				if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text,
					(SELECT CASE s.system_identifier WHEN 1 THEN 2 ELSE 1 END::text FROM pg_control_system() s)`).Scan(&txid, &theirs); err != nil {
					t.Fatal(err)
				}
				restore := fakeCommit("2000-01-01 00:00:00", theirs, txid)
				if c.restored == "prune" {
					// A prune's record names no cluster.
					restore = `INSERT INTO rbac_history (effective_at, txid, tenant, entity, key, op, after, how)
						VALUES (timestamptz '2000-01-01 00:00:00', '` + txid + `'::xid8, '', 'history', 'restored', 'prune', '{}', 'PruneHistory')`
				}
				for _, sql := range []string{
					`ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_committed`,
					restore,
					`ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed`,
				} {
					if _, err := pool.Exec(ctx, sql); err != nil {
						t.Fatalf("%s: %v", sql, err)
					}
				}
			}
			if c.replica {
				var schema string
				if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
					t.Fatal(err)
				}
				replica, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = replica.Rollback(ctx) }()
				sql, args := rbac.MigrateLock(schema)
				if _, err := replica.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
				// The replica's migration altering history waits for the transaction, which holds
				// history, so it can't commit before the transaction ends: what the transaction reads as
				// applied before it waits for the replica, it would read after.
				names, err := fs.Glob(rbac.Migrations(), altering+"_*.sql")
				if err != nil || len(names) != 1 {
					t.Fatalf("migration %s: %v, %v", altering, names, err)
				}
				migration, err := fs.ReadFile(rbac.Migrations(), names[0])
				if err != nil {
					t.Fatal(err)
				}
				if _, err := replica.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
					t.Fatal(err)
				}
				var pg *pgconn.PgError
				if _, err := replica.Exec(ctx, string(migration)); !errors.As(err, &pg) || pg.Code != "55P03" {
					t.Fatalf("%s beside a transaction that wrote history: %v", names[0], err)
				}
				// Past which a wait for the replica fails as a conflict, not a refusal.
				if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
					t.Fatal(err)
				}
			}
			err = rbac.Migrate(ctx, tx)
			if c.refused && !errors.Is(err, rbac.ErrInvalid) || !c.refused && err != nil {
				t.Fatalf("Migrate on a host's transaction after %s: %v", c.name, err)
			}
			want := latestMigration(t)
			if c.refused {
				if _, err := fmt.Sscanf(c.from, "%04d", &want); err != nil {
					t.Fatal(err)
				}
				want--
			}
			if v := migratedTo(t, tx); v != want {
				t.Errorf("migrated to %d, not %d", v, want)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var grants, commits int
			if err := pool.QueryRow(ctx, `SELECT count(DISTINCT g.id), count(c.id) FROM rbac_history g
				LEFT JOIN rbac_history c ON c.txid = g.txid AND c.entity = 'commit' WHERE g.entity = 'grant'`).Scan(&grants, &commits); err != nil {
				t.Fatal(err)
			}
			if c.write == change && (grants != 1 || commits != c.commits) {
				t.Errorf("the change committed %d grants with %d commit records, not %d", grants, commits, c.commits)
			}
		})
	}
}

// HistoryAltered names the last migration that may alter history's table, as PostgreSQL refuses in
// a transaction holding events of its deferred triggers (SQLSTATE 55006), as alteringHistory finds
// them. A migration that does so fails this until HistoryAltered names it, before Migrate on a host's
// transaction lets a change in it through to fail the migration; and HistoryAltered naming one that
// doesn't fails it too, before Migrate refuses a transaction no pending migration would.
func TestHistoryAlteredNamesTheLastMigrationAlteringHistory(t *testing.T) {
	sqls := migrationSQL(t)
	names := slices.Sorted(maps.Keys(sqls))
	texts := make([]string, len(names))
	for i, name := range names {
		texts[i] = sqls[name]
	}
	last := ""
	for i, alters := range alteringHistory(texts) {
		if alters {
			last = names[i]
		}
	}
	var version int
	if _, err := fmt.Sscanf(last, "%04d_", &version); err != nil || version != rbac.HistoryAltered {
		t.Errorf("the last migration altering history is %s, not the %d HistoryAltered names: %v", last, rbac.HistoryAltered, err)
	}
}

// alteringHistory finds history's table altered however a migration writes it: in any case, quoted
// or qualified, in dynamic SQL, in a DO block, or in a function a later migration calls; and not in
// a comment, a message, or history's column named cluster.
func TestAlteringHistoryIsFoundHoweverAMigrationWritesIt(t *testing.T) {
	const alters = `CREATE FUNCTION rbac_alter() RETURNS void LANGUAGE plpgsql AS $$
		BEGIN EXECUTE pg_catalog.format('ALTER TABLE %I.%I VALIDATE CONSTRAINT c', pg_catalog.current_schema(), 'rbac_history'); END $$;`
	for _, c := range []struct {
		sqls []string
		want []bool
	}{
		{[]string{`alter table RBAC_HISTORY add column x int;`}, []bool{true}},
		{[]string{`ALTER TABLE IF EXISTS ONLY "s"."rbac_history" SET (fillfactor = 90);`}, []bool{true}},
		{[]string{`/* ALTER TABLE rbac_grants */ CREATE UNIQUE INDEX i ON ONLY public.rbac_history (id);`}, []bool{true}},
		{[]string{`CREATE CONSTRAINT TRIGGER t AFTER INSERT ON rbac_history DEFERRABLE FOR EACH ROW EXECUTE FUNCTION f();`}, []bool{true}},
		{[]string{`DROP TRIGGER t ON rbac_history;`, `DROP TABLE rbac_grants, rbac_history;`}, []bool{true, true}},
		{[]string{`TRUNCATE rbac_grants, rbac_history;`, `TRUNCATE TABLE ONLY %s;`}, []bool{true, true}},
		{[]string{`CLUSTER VERBOSE rbac_history USING rbac_history_pkey;`, `REINDEX INDEX rbac_history_entity;`}, []bool{true, true}},
		{[]string{`DROP FUNCTION rbac_history_commit() CASCADE;`, `DROP SCHEMA s CASCADE;`}, []bool{true, true}},
		// Its name a placeholder, or built where it runs.
		{[]string{`DO $do$ DECLARE history text := format('%I.rbac_history', current_schema());
			BEGIN EXECUTE format('ALTER TABLE %s SET (fillfactor = 90)', history); END $do$;`}, []bool{true}},
		{[]string{`DO $$ BEGIN EXECUTE 'ALTER ' || 'TABLE ' || quote_ident('rbac_' || 'history') || ' SET (fillfactor = 90)'; END $$;`}, []bool{true}},
		{[]string{`DO $$ DECLARE s text; BEGIN SELECT q INTO s FROM queued; EXECUTE s; END $$;`}, []bool{true}},
		{[]string{`DO $$ BEGIN EXECUTE format(CASE WHEN true THEN 'ALTER TABLE x' END); END $$;`}, []bool{true}},
		// A -- in a string hides nothing after it.
		{[]string{`DO $$ BEGIN EXECUTE 'COMMENT ON TABLE rbac_grants IS ''--'''; ALTER TABLE rbac_history SET (fillfactor = 90); END $$;`}, []bool{true}},
		// By a function a migration made, and one that calls it.
		{[]string{alters, `SELECT 1;`, `SELECT rbac_alter();`}, []bool{true, false, true}},
		{[]string{alters, `CREATE PROCEDURE rbac_both() LANGUAGE sql AS 'SELECT rbac_alter()';`, `CALL rbac_both();`}, []bool{true, true, true}},
		{[]string{
			`-- ALTER TABLE rbac_history
			/* ALTER TABLE rbac_history /* nested */ TRUNCATE rbac_history */ SELECT 1;`,
			`SELECT h.cluster FROM rbac_history h WHERE h.cluster IS NOT NULL;`,
			`CREATE FUNCTION f() RETURNS bigint LANGUAGE sql AS $$ SELECT CASE WHEN true THEN cluster END FROM rbac_history $$;`,
			`DO $$ BEGIN RAISE EXCEPTION 'cannot alter history' USING HINT = 'Drop or disable the trigger.'; END $$;`,
			`ALTER TABLE rbac_grants ADD COLUMN x int; CREATE INDEX i ON rbac_grants (x); TRUNCATE rbac_grants; CLUSTER rbac_grants;`,
			`CREATE TRIGGER t BEFORE TRUNCATE ON rbac_grants FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();`,
			`INSERT INTO rbac_history (op) VALUES ('create'), ('truncate'); SELECT has_function_privilege('f()', 'EXECUTE');`,
			`DO $$ BEGIN EXECUTE format('GRANT SELECT ON %s TO %s', 'rbac_history', 'r'); EXECUTE 'SELECT 1' || 'FROM rbac_history'; END $$;`,
			`LOCK TABLE rbac_history IN SHARE MODE; ANALYZE rbac_history; DROP INDEX rbac_history_entity CASCADE;`,
		}, []bool{false, false, false, false, false, false, false, false, false}},
	} {
		if got := alteringHistory(c.sqls); !slices.Equal(got, c.want) {
			t.Errorf("%q: %v, not %v", c.sqls, got, c.want)
		}
	}
}

// alteringHistory reports, for each of sqls, migrations in order, whether it may alter history's
// table, as altersHistory reads a statement: by a statement of its own, of dynamic SQL in it, or of
// the body of a function or procedure a migration made, which it, or one it calls, calls by name.
func alteringHistory(sqls []string) []bool {
	type migration struct {
		statements []sqlStatement
		owners     []string
	}
	ms := make([]migration, len(sqls))
	for i, sql := range sqls {
		words := sqlWords(sql, 0)
		ms[i] = migration{sqlStatements(words), sqlBodies(words)}
	}
	functions := map[string]bool{}
	altering := make([]bool, len(sqls))
	for found := true; found; {
		found = false
		for i, m := range ms {
			for _, s := range m.statements {
				if !altersHistory(s) && !s.calls(functions) {
					continue
				}
				altering[i] = true
				if f := m.owners[s.at]; f != "" && !functions[f] {
					functions[f], found = true, true
				}
			}
		}
	}
	return altering
}

// sqlBoundary stands among sqlWords where the text of a string or a dollar-quoted body begins or
// ends.
const sqlBoundary = "\x00"

// sqlWord is a token of SQL, and how many strings and bodies deep it stands.
type sqlWord struct {
	text  string
	depth int
}

var (
	dollarQuote = regexp.MustCompile(`^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$`)
	placeholder = regexp.MustCompile(`^%(?:[0-9]+\$)?-?(?:[0-9]+|\*(?:[0-9]+\$)?)?[sIL]`)
)

// sqlWords splits sql into tokens, leaving out its comments: words, lowercased unless quoted;
// numbers; format()'s placeholders, as %I and %1$s; || and each other character of punctuation; and
// the text of each string and dollar-quoted body, split so in turn, as dynamic SQL runs it, between
// two sqlBoundary.
func sqlWords(sql string, depth int) []sqlWord {
	var out []sqlWord
	add := func(text string) { out = append(out, sqlWord{text, depth}) }
	quoted := func(text string) {
		add(sqlBoundary)
		out = append(out, sqlWords(text, depth+1)...)
		add(sqlBoundary)
	}
	// The text up to the quote that ends it, which two of it stand for in it, and how much of sql
	// that takes.
	until := func(i int, quote byte) (string, int) {
		var b strings.Builder
		j := i + 1
		for ; j < len(sql); j++ {
			if sql[j] == quote {
				if j+1 < len(sql) && sql[j+1] == quote {
					b.WriteByte(quote)
					j++
					continue
				}
				break
			}
			b.WriteByte(sql[j])
		}
		return b.String(), j + 1
	}
	for i := 0; i < len(sql); {
		rest, c := sql[i:], sql[i]
		switch {
		case strings.HasPrefix(rest, "--"):
			if n := strings.IndexByte(rest, '\n'); n >= 0 {
				i += n
			} else {
				i = len(sql)
			}
		case strings.HasPrefix(rest, "/*"):
			nested, j := 1, i+2
			for j < len(sql) && nested > 0 {
				switch {
				case strings.HasPrefix(sql[j:], "/*"):
					nested, j = nested+1, j+2
				case strings.HasPrefix(sql[j:], "*/"):
					nested, j = nested-1, j+2
				default:
					j++
				}
			}
			i = j
		case c == '\'':
			var text string
			text, i = until(i, '\'')
			quoted(text)
		case c == '"':
			var text string
			text, i = until(i, '"')
			add(text)
		case c == '$' && dollarQuote.MatchString(rest):
			tag := dollarQuote.FindString(rest)
			body := rest[len(tag):]
			if n := strings.Index(body, tag); n >= 0 {
				body, i = body[:n], i+2*len(tag)+n
			} else {
				i = len(sql)
			}
			quoted(body)
		case c == '%' && placeholder.MatchString(rest):
			p := placeholder.FindString(rest)
			add(p)
			i += len(p)
		case wordByte(c, true), c >= '0' && c <= '9':
			j := i + 1
			for j < len(sql) && wordByte(sql[j], false) {
				j++
			}
			add(strings.ToLower(sql[i:j]))
			i = j
		case strings.HasPrefix(rest, "||"):
			add("||")
			i += 2
		case c <= ' ':
			i++
		default:
			add(string(c))
			i++
		}
	}
	return out
}

// wordByte reports whether c, first or not, belongs to a word as PostgreSQL reads an identifier.
func wordByte(c byte, first bool) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80 ||
		!first && (c >= '0' && c <= '9' || c == '$')
}

// isWord reports whether a token is a word, a name or a keyword.
func isWord(token string) bool {
	return token != "" && wordByte(token[0], true)
}

// sqlStatement is a statement among sqlWords, its words from at on, and whether || joins it to what
// stands beside it, as a string of dynamic SQL built in parts.
type sqlStatement struct {
	words  []string
	at     int
	joined bool
}

// calls reports whether s calls one of functions by name.
func (s sqlStatement) calls(functions map[string]bool) bool {
	for i, word := range s.words {
		if functions[word] && i+1 < len(s.words) && s.words[i+1] == "(" {
			return true
		}
	}
	return false
}

// sqlStatements splits words at each semicolon and sqlBoundary, and after each keyword after which
// PL/pgSQL begins a statement, so that each starts with what it does.
func sqlStatements(words []sqlWord) []sqlStatement {
	var out []sqlStatement
	start := 0
	end := func(i int) {
		if i > start {
			s := sqlStatement{at: start}
			for _, w := range words[start:i] {
				s.words = append(s.words, w.text)
			}
			s.joined = start >= 2 && words[start-1].text == sqlBoundary && words[start-2].text == "||" ||
				i+1 < len(words) && words[i].text == sqlBoundary && words[i+1].text == "||"
			out = append(out, s)
		}
		start = i + 1
	}
	for i, w := range words {
		switch w.text {
		case ";", sqlBoundary, "begin", "then", "else", "loop", "declare":
			end(i)
		}
	}
	end(len(words))
	return out
}

// sqlBodies is, for each of words, the name of the function or procedure a CREATE statement makes
// whose body it stands in, or "".
func sqlBodies(words []sqlWord) []string {
	owners := make([]string, len(words))
	for i, w := range words {
		if w.text != "create" {
			continue
		}
		j := i + 1
		for j < len(words) && (words[j].text == "or" || words[j].text == "replace") {
			j++
		}
		if j >= len(words) || words[j].text != "function" && words[j].text != "procedure" {
			continue
		}
		// Named last before its arguments; its body the string or dollar-quoted body after AS.
		name := ""
		for j++; j < len(words) && words[j].text != "("; j++ {
			if isWord(words[j].text) {
				name = words[j].text
			}
		}
		for j < len(words) && (words[j].depth != w.depth || words[j].text != "as" && words[j].text != ";") {
			j++
		}
		if j+1 >= len(words) || words[j].text != "as" || words[j+1].text != sqlBoundary {
			continue
		}
		for j += 2; j < len(words) && words[j].depth > w.depth; j++ {
			owners[j] = name
		}
	}
	return owners
}

// altersHistory reports whether s may alter history's table, as PostgreSQL refuses while events of
// its deferred triggers are pending: ALTER TABLE, CREATE INDEX, CLUSTER, VACUUM, REINDEX, TRUNCATE or
// DROP TABLE of it, or a trigger, rule or policy made or dropped on it, by a statement that names it;
// DROP SCHEMA, DROP OWNED, or another DROP ... CASCADE, which can reach it or its triggers; or one
// that doesn't write out the table it alters, as a format() placeholder or a name built where it
// runs, or dynamic SQL run from a variable, as it can't be told not to.
func altersHistory(s sqlStatement) bool {
	w := s.words
	for i, word := range w {
		if word == "execute" && hidden(w[i+1:]) {
			return true
		}
	}
	verbs := []string{"alter", "create", "drop", "truncate", "cluster", "reindex", "vacuum"}
	if len(w) == 0 || !slices.Contains(verbs, w[0]) {
		return false
	}
	if len(w) == 1 {
		// Alone, a word in a string, as an op history records, unless the rest is built onto it.
		return s.joined
	}
	names := slices.Contains(w, "rbac_history")
	skip := func(i int, words ...string) int {
		for i < len(w) && slices.Contains(words, w[i]) {
			i++
		}
		return i
	}
	on := func(i int) int {
		if j := slices.Index(w[i:], "on"); j >= 0 {
			return skip(i+j+1, "only")
		}
		return len(w)
	}
	switch w[0] {
	case "alter":
		if w[1] == "table" {
			i := skip(2, "if", "exists", "only")
			return names || i < len(w) && w[i] == "all" || mayBeHistory(w, i)
		}
		return !isWord(w[1])
	case "create":
		i := skip(1, "or", "replace", "unique", "constraint", "temporary", "temp", "unlogged")
		if i >= len(w) || !isWord(w[i]) {
			return true
		}
		switch w[i] {
		case "index", "trigger", "rule", "policy":
			return names || mayBeHistory(w, on(i))
		case "table":
			return names
		}
		return false
	case "drop":
		switch w[1] {
		case "table":
			return names || anyMayBeHistory(w, skip(2, "if", "exists"))
		case "trigger", "rule", "policy":
			return names || mayBeHistory(w, on(2))
		case "schema", "owned":
			return true
		case "index", "view", "materialized":
			return false
		}
		return !isWord(w[1]) || slices.Contains(w, "cascade")
	case "truncate":
		return names || anyMayBeHistory(w, skip(1, "table", "only"))
	case "cluster":
		i := skip(1, "verbose")
		if j := slices.Index(w[i:], ")"); i < len(w) && w[i] == "(" && j >= 0 {
			i += j + 1
		}
		if i < len(w) && !isWord(w[i]) && !strings.HasPrefix(w[i], "%") {
			// History's column named cluster.
			return false
		}
		if j := i + 1; j < len(w) && w[j] == "on" {
			i = j + 1
		}
		return mayBeHistory(w, i)
	case "reindex":
		i := 1
		if w[1] == "(" {
			i += slices.Index(w[1:], ")") + 1
		}
		if i >= len(w) {
			return true
		}
		switch kind, j := w[i], skip(i+1, "concurrently"); kind {
		case "table":
			return names || mayBeHistory(w, j)
		case "index":
			name, _, ok := relation(w, j)
			return !ok || strings.HasPrefix(name, "rbac_history")
		}
		return true
	}
	// VACUUM, which no migration runs, as it can't run in a transaction.
	return true
}

// hidden reports whether EXECUTE, followed by rest, runs SQL whose text isn't written there: from a
// variable, or format() of a format that isn't a literal. Not EXECUTE FUNCTION or PROCEDURE, nor the
// privilege, nor the word alone in a string.
func hidden(rest []string) bool {
	if len(rest) >= 2 && rest[0] == "pg_catalog" && rest[1] == "." {
		rest = rest[2:]
	}
	if len(rest) == 0 {
		return false
	}
	switch rest[0] {
	case "function", "procedure", "on":
		return false
	case "format":
		return len(rest) != 2 || rest[1] != "("
	}
	return true
}

// relation is the name of the table named from w[i] on, qualified or not, and where its name ends,
// unless its name isn't written out, as a placeholder.
func relation(w []string, i int) (name string, end int, ok bool) {
	for i+1 < len(w) && w[i+1] == "." && (isWord(w[i]) || strings.HasPrefix(w[i], "%")) {
		i += 2
	}
	if i < len(w) && isWord(w[i]) {
		return w[i], i + 1, true
	}
	return "", i, false
}

// mayBeHistory reports whether the table named from w[i] on is history, or isn't written out.
func mayBeHistory(w []string, i int) bool {
	name, _, ok := relation(w, i)
	return !ok || name == "rbac_history"
}

// anyMayBeHistory is mayBeHistory of each table in the list from w[i] on, as TRUNCATE and DROP
// TABLE take one.
func anyMayBeHistory(w []string, i int) bool {
	for {
		name, end, ok := relation(w, i)
		if !ok || name == "rbac_history" {
			return true
		}
		if end < len(w) && w[end] == "*" {
			end++
		}
		if end >= len(w) || w[end] != "," {
			return false
		}
		i = end + 1
	}
}

// Migrate waits for another replica's migration as long as the session's lock_timeout lets it,
// and no longer: a try that wait ends isn't tried again, as each would wait as long again.
func TestMigrateWaitsForAReplicaAsLongAsTheSessionsLockTimeout(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "lock_timeout=300")
	if err := rbac.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	// Another replica migrating, on a host's transaction, which holds the migration's lock until it
	// ends.
	replica, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replica.Rollback(ctx) }()
	if err := rbac.Migrate(ctx, replica); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	err = rbac.Migrate(ctx, pool)
	waited := time.Since(began)
	var pg *pgconn.PgError
	if !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("Migrate while a replica migrates: %v", err)
	}
	if waited > 2*time.Second {
		t.Errorf("Migrate waited %v for a replica's migration, past the session's lock_timeout of 300ms", waited)
	}
}

// historyToVacuum migrates pool's schema up to 0019 and fills history with enough records that a
// vacuum slowed to a crawl takes minutes over it. Autovacuum is off for history and rbac_grants,
// whose rows the records are of, from before they fill: a worker that vacuumed history as it
// filled, before a test slowed it, would leave nothing for the test's worker to vacuum.
func historyToVacuum(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := applyMigrations(t.Context(), pool, pgx.ReadCommitted, "", "0019"); err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, pool, "0019")
	if _, err := pool.Exec(t.Context(), `ALTER TABLE rbac_grants SET (autovacuum_enabled = off);
		ALTER TABLE rbac_history SET (autovacuum_enabled = off)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 't1', 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.admin' FROM generate_series(1, 10000) i`); err != nil {
		t.Fatal(err)
	}
}

// vacuumSlowly has a session of pool vacuum table, slowed to a crawl, until t ends, and returns its
// pid once it has started.
func vacuumSlowly(t *testing.T, pool *pgxpool.Pool, table string) uint32 {
	t.Helper()
	ctx := t.Context()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := conn.Conn().PgConn().PID()
	if _, err := conn.Exec(ctx, `SET vacuum_cost_delay = 100; SET vacuum_cost_limit = 1`); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	vacuumed := make(chan error, 1)
	go func() {
		_, err := conn.Exec(context.WithoutCancel(ctx), `VACUUM `+table)
		vacuumed <- err
	}()
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), `SELECT pg_cancel_backend($1)`, pid); err != nil {
			t.Error(err)
		}
		<-vacuumed
		conn.Release()
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var running bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_progress_vacuum WHERE pid = $1 AND relid = $2::regclass)`, pid, table).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatal("the vacuum never started")
		}
	}
}

// superuserOn is a pool of the test database's role, which the README's roles are made by, on
// schema.
func superuserOn(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// outwaiting returns once a session of role has waited for a lock on table past what a migration's
// own locks wait, as Migrate does for what an autovacuum worker holds, or fails t if migrated ends
// first.
func outwaiting(t *testing.T, super *pgxpool.Pool, role, table string, migrated <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var waiting bool
		if err := super.QueryRow(t.Context(), `SELECT EXISTS (SELECT FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND a.usename = $1 AND l.relation = $2::regclass AND l.waitstart < now() - interval '300 ms')`,
			role, table).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-migrated:
			t.Fatalf("Migrate ended without waiting out the vacuum: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Migrate never waited out the vacuum")
		}
	}
}

// An autovacuum worker holding history, as one vacuuming a large history does for minutes, holds
// 0019 back only until PostgreSQL cancels it, which it does once a wait for its lock passes
// deadlock_timeout: Migrate waits that long for the worker's lock once the worker held the table as
// a try gave way, as the README's administrator's role, which can't read the worker's backend type.
// Waiting at most 100 ms each time, it gave way on every try while the worker ran on.
func TestMigrateWaitsForPostgreSQLToCancelAutovacuum(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	var on bool
	var naptime int64
	if err := r.super.QueryRow(ctx, `SELECT current_setting('autovacuum')::bool AND current_setting('track_counts')::bool,
		(SELECT setting::bigint FROM pg_settings WHERE name = 'autovacuum_naptime')`).Scan(&on, &naptime); err != nil {
		t.Fatal(err)
	}
	if !on {
		pgtest.Skip(t, "autovacuum is off")
	}
	historyToVacuum(t, r.adminPool)
	// Table-level settings alone: autovacuum vacuums history for the records inserted, slowly, and
	// doesn't analyze it.
	if _, err := r.adminPool.Exec(ctx, `ALTER TABLE rbac_history SET (autovacuum_enabled = on, autovacuum_vacuum_insert_threshold = 1,
		autovacuum_vacuum_insert_scale_factor = 0, autovacuum_vacuum_cost_delay = 100, autovacuum_vacuum_cost_limit = 1,
		autovacuum_analyze_threshold = 1000000000)`); err != nil {
		t.Fatal(err)
	}
	// The launcher starts a worker in the database once each naptime, which can be busy with other
	// tables first. In CI only the run's own tables keep it busy, and one has come within a minute, so
	// there the test fails rather than skip. A naptime of a second had autovacuum analyze a crowded
	// copy before TestACrowdedCopyIsWhatWritingItAfreshMakes read that nothing had.
	var pid int
	for deadline := time.Now().Add(2*time.Duration(naptime)*time.Second + 30*time.Second); ; time.Sleep(200 * time.Millisecond) {
		err := r.super.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'
			AND query LIKE '%' || $1 || '.rbac_history%'`, r.schema).Scan(&pid)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			pgtest.Skip(t, "no autovacuum worker reached history in time")
		}
	}
	rbac.SetMigrateAttempts(t, 3, time.Millisecond)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("Migrate while autovacuum vacuums history: %v", err)
	}
	if v := migratedTo(t, r.adminPool); v != latestMigration(t) {
		t.Errorf("migrated to %d", v)
	}
	var vacuuming bool
	if err := r.super.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE pid = $1 AND query LIKE '%' || $2 || '.rbac_history%')`,
		pid, r.schema).Scan(&vacuuming); err != nil {
		t.Fatal(err)
	}
	if vacuuming {
		t.Error("the autovacuum worker still vacuums history")
	}
}

// While Migrate waits for PostgreSQL to cancel what holds a table, as a client's vacuum of history
// that a role without pg_read_all_stats can't tell from autovacuum's, it holds none of the locks the
// migration takes: a write to rbac_grants goes on. Waiting so with 0019's lock on rbac_grants, taken
// before history's, held every write to grants back until the wait ended. Once the vacuum outlasts
// the wait, 0019's own locks wait 100 ms again, as they hold grants meanwhile.
func TestMigrateOutwaitingAVacuumHoldsNoWriteBack(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	historyToVacuum(t, r.adminPool)
	super := superuserOn(t, r.schema)
	vacuumSlowly(t, super, "rbac_history")
	seeks, err := fs.ReadFile(rbac.Migrations(), "0019_principal_seeks.sql")
	if err != nil {
		t.Fatal(err)
	}
	// When the last try applied 0019, which follows its wait for the vacuum.
	var applied time.Time
	db := &beforeMigration{Pool: r.adminPool, sql: string(seeks), fire: func() { applied = time.Now() }}
	rbac.SetMigrateAttempts(t, 2, time.Millisecond)
	migrated := make(chan error, 1)
	go func() { migrated <- rbac.Migrate(ctx, db) }()
	outwaiting(t, super, r.admin, "rbac_history", migrated)
	began := time.Now()
	if _, err := r.adminPool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'w', 'user', 'w', 'cluster.admin')`); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 500*time.Millisecond {
		t.Errorf("a grant written while Migrate waited out a vacuum took %v", took)
	}
	var pg *pgconn.PgError
	if err := <-migrated; !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("Migrate while a client vacuums history: %v", err)
	}
	if took := time.Since(applied); took > 500*time.Millisecond {
		t.Errorf("0019 waited %v for history once the wait for its vacuum ended", took)
	}
}

// Where a vacuum outlasts Migrate's wait for one table, as a client's of rbac_groups that a role
// without pg_read_all_stats can't tell from autovacuum's, Migrate still waits for each table after
// it: a vacuum of history, which this test cancels as PostgreSQL cancels an autovacuum worker once
// a wait for its lock passes deadlock_timeout, ends, and 0019, which doesn't lock rbac_groups,
// migrates. Locking them in one statement, the wait for rbac_groups ended it, so history's worker
// was never canceled, and 0019 gave way on every try.
func TestMigrateOutwaitsEachTableAVacuumHolds(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	historyToVacuum(t, r.adminPool)
	// So no autovacuum worker on the table filled holds it as well, from before it fills.
	for _, sql := range []string{
		`ALTER TABLE rbac_groups SET (autovacuum_enabled = off)`,
		`INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'g' || i FROM generate_series(1, 10000) i`,
	} {
		if _, err := r.adminPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	super := superuserOn(t, r.schema)
	// Waited for first, as rbac_groups sorts before rbac_history.
	vacuumSlowly(t, super, "rbac_groups")
	history := vacuumSlowly(t, super, "rbac_history")
	rbac.SetMigrateAttempts(t, 2, time.Millisecond)
	migrated := make(chan error, 1)
	go func() { migrated <- rbac.Migrate(ctx, r.adminPool) }()
	outwaiting(t, super, r.admin, "rbac_history", migrated)
	if _, err := super.Exec(ctx, `SELECT pg_cancel_backend($1)`, history); err != nil {
		t.Fatal(err)
	}
	if err := <-migrated; err != nil {
		t.Fatalf("Migrate beside a vacuum of rbac_groups it can't outwait and one of history that ends: %v", err)
	}
	if v := migratedTo(t, r.adminPool); v != latestMigration(t) {
		t.Errorf("migrated to %d", v)
	}
}

// Where what Migrate waits for as autovacuum's isn't, as a client's vacuum of rbac_memberships that
// a role without pg_read_all_stats can't tell from autovacuum's, outlasts the wait, the try goes on
// without it, and 0019, which doesn't lock that table, migrates once the read that held history
// back has ended.
func TestMigrateGoesOnWhereAVacuumOutlastsItsWait(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	if err := applyMigrations(ctx, r.adminPool, pgx.ReadCommitted, "", "0019"); err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, r.adminPool, "0019")
	// So no autovacuum worker on the tables filled holds them as well, from before they fill.
	for _, sql := range []string{
		`ALTER TABLE rbac_memberships SET (autovacuum_enabled = off); ALTER TABLE rbac_history SET (autovacuum_enabled = off)`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', 'u' || i FROM generate_series(1, 10000) i`,
	} {
		if _, err := r.adminPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	super := superuserOn(t, r.schema)
	vacuumSlowly(t, super, "rbac_memberships")
	// A read holds history, which 0019 locks, so its first try gives way.
	reader, err := r.adminPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback(ctx) }()
	if _, err := reader.Exec(ctx, `SELECT FROM rbac_history LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	rbac.SetMigrateAttempts(t, 2, time.Millisecond)
	migrated := make(chan error, 1)
	go func() { migrated <- rbac.Migrate(ctx, r.adminPool) }()
	outwaiting(t, super, r.admin, "rbac_memberships", migrated)
	if err := reader.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-migrated; err != nil {
		t.Fatalf("Migrate once the read has ended, beside a client's vacuum of another table: %v", err)
	}
	if v := migratedTo(t, r.adminPool); v != latestMigration(t) {
		t.Errorf("migrated to %d", v)
	}
}

// A vacuum a client runs, which PostgreSQL never cancels for a lock, doesn't have Migrate wait
// past deadlock_timeout for it, where its role can tell the vacuum from autovacuum's.
func TestMigrateDoesntWaitOutAClientsVacuum(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	// No autovacuum worker on the tables it fills has Migrate wait past deadlock_timeout.
	historyToVacuum(t, pool)
	vacuumSlowly(t, pool, "rbac_history")
	var ms int64
	if err := pool.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'deadlock_timeout'`).Scan(&ms); err != nil {
		t.Fatal(err)
	}
	rbac.SetMigrateAttempts(t, 2, time.Millisecond)
	began := time.Now()
	err := rbac.Migrate(ctx, pool)
	took := time.Since(began)
	var pg *pgconn.PgError
	if !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("Migrate while a client vacuums history: %v", err)
	}
	if limit := time.Duration(ms) * time.Millisecond; took >= limit {
		t.Errorf("Migrate took %v beside a client's vacuum, past deadlock_timeout's %v", took, limit)
	}
}

// viewsDiverged is each of the package's tables in the schema of pool's connections, but history,
// rbac_migrations and rbac_expired, whose view beside it for AsOf is missing or gives other columns than it holds: by
// name, type, its modifier and collation, in its order.
func viewsDiverged(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT t.relname::text FROM pg_class t
		CROSS JOIN LATERAL (SELECT to_regclass(quote_ident(current_schema() || '_as_of') || '.' || quote_ident(t.relname)) AS oid) v
		WHERE t.relnamespace = current_schema()::regnamespace AND t.relkind = 'r' AND starts_with(t.relname, 'rbac_')
		  AND t.relname NOT IN ('rbac_history', 'rbac_migrations', 'rbac_expired')
		  AND (v.oid IS NULL OR EXISTS (
		    (SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = t.oid AND attnum > 0 AND NOT attisdropped
		     EXCEPT SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = v.oid)
		    UNION ALL
		    (SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = v.oid
		     EXCEPT SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = t.oid AND attnum > 0 AND NOT attisdropped)))
		ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	diverged, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return diverged
}

// Every one of the package's tables but history and rbac_migrations has a view of its history
// beside it, which AsOf reads it by, of the columns it holds, migrated from none or from before the
// views were made, of a table holding rows: one that gave fewer would fail a host's query of a
// column it lacks, or, given in another order, the package's statements prepared before AsOf, which
// read the table. A migration that changes a table makes the views again (rbac_as_of_views), so a
// column it adds is one its view gives.
func TestEveryTableHasAViewOfItsColumns(t *testing.T) {
	for _, from := range []string{"", "0028"} {
		t.Run(fmt.Sprintf("from=%q", from), func(t *testing.T) {
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			if from != "" {
				migrateFiles(t, pool, "", from)
				recordMigrations(t, pool, from)
				if _, err := pool.Exec(ctx, creatorGrant); err != nil {
					t.Fatal(err)
				}
			}
			if err := rbac.Migrate(ctx, pool); err != nil {
				t.Fatal(err)
			}
			if diverged := viewsDiverged(t, pool); len(diverged) != 0 {
				t.Errorf("the views of %v give other columns than their tables hold", diverged)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE rbac_grants ADD COLUMN later text COLLATE "C"`); err != nil {
				t.Fatal(err)
			}
			if diverged := viewsDiverged(t, pool); !slices.Equal(diverged, []string{"rbac_grants"}) {
				t.Errorf("with a column added to rbac_grants alone, the views of %v give other columns than their tables hold", diverged)
			}
			if _, err := pool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
				t.Fatal(err)
			}
			if diverged := viewsDiverged(t, pool); len(diverged) != 0 {
				t.Errorf("made again, the views of %v give other columns than their tables hold", diverged)
			}
		})
	}
}

// Migrating makes the schema of AsOf's views, or, where the role migrating may make no schema, as
// the README's administrator's may not, takes one made for it, empty and that role's: AsOf names it
// first on its search_path, so one holding anything, another role's or one another may create in is
// refused, as a function made there would be called in place of the package's, as whoever reads.
// Made, the views read history with the rights of whoever reads them, and are given to each role
// that may read history and use the package's schema, not to the public, which may read history
// but not reach it, until it is given that schema and they are made again. Made again, as a later
// migration makes them, they are refused alike where another role may since create there or the
// schema holds more than them, though not for its default privileges.
func TestMigratingMakesAsOfsViewsInASchemaOfTheirOwn(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	views := r.schema + "_as_of"
	exec := func(sql string) {
		t.Helper()
		if _, err := r.super.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// Up to the views, with history readable by the application's role, and by the public, which has
	// no USAGE on the package's schema.
	migrateFiles(t, r.adminPool, "", "0028")
	recordMigrations(t, r.adminPool, "0028")
	exec(`GRANT USAGE ON SCHEMA ` + r.schema + ` TO ` + r.app)
	exec(`GRANT SELECT ON ` + r.schema + `.rbac_history TO ` + r.app + `, PUBLIC`)
	for _, c := range []struct {
		what, set, unset, code string
	}{
		{"another role's", `ALTER SCHEMA ` + views + ` OWNER TO ` + r.app, `ALTER SCHEMA ` + views + ` OWNER TO ` + r.admin, "42P15"},
		{"one another may create in", `GRANT CREATE ON SCHEMA ` + views + ` TO ` + r.app, `REVOKE CREATE ON SCHEMA ` + views + ` FROM ` + r.app, "42P15"},
		{"one holding a table", `CREATE TABLE ` + views + `.held (a int)`, `DROP TABLE ` + views + `.held`, "42P15"},
		{"none, which the role may not make", `DROP SCHEMA ` + views, `CREATE SCHEMA ` + views + ` AUTHORIZATION ` + r.admin, "42501"},
	} {
		exec(c.set)
		if err := rbac.Migrate(ctx, r.adminPool); sqlState(err) != c.code {
			t.Errorf("migrating with %s as the schema of AsOf's views: %v", c.what, err)
		}
		exec(c.unset)
	}
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("migrating with an empty schema of the role's made for AsOf's views: %v", err)
	}
	var n, invoker, given int
	if err := r.super.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE 'security_invoker=true' = ANY(reloptions)),
		count(*) FILTER (WHERE has_table_privilege($2, oid, 'SELECT') AND has_schema_privilege($2, relnamespace, 'USAGE'))
		FROM pg_class WHERE relnamespace = $1::regnamespace AND relkind = 'v' AND relowner = $3::regrole`, views, r.app, r.admin).Scan(&n, &invoker, &given); err != nil {
		t.Fatal(err)
	}
	if n != 7 || invoker != 7 || given != 7 {
		t.Errorf("the administrator's role made %d views, %d read with their reader's rights, %d given to the application's role", n, invoker, given)
	}
	var public int
	if err := r.super.QueryRow(ctx, `SELECT count(*) FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.oid = $1::regnamespace AND a.grantee = 0`, views).Scan(&public); err != nil || public != 0 {
		t.Errorf("the public, which may read history but not use the package's schema, was given the views' schema %d times: %v", public, err)
	}
	// Given the package's schema since, as a role can be after migrating, the public is given the
	// views once they are made again, as the README says.
	exec(`GRANT USAGE ON SCHEMA ` + r.schema + ` TO PUBLIC`)
	if _, err := r.adminPool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
		t.Fatal(err)
	}
	var reads bool
	if err := r.super.QueryRow(ctx, `SELECT has_schema_privilege('public', $1::regnamespace, 'USAGE') AND has_table_privilege('public', $1 || '.rbac_grants', 'SELECT')`,
		views).Scan(&reads); err != nil || !reads {
		t.Errorf("the public, given the package's schema since the views were made, was given them as they were made again %t: %v", reads, err)
	}
	for _, c := range []struct {
		what, set, unset string
		refused          bool
	}{
		{"another may create in it", `GRANT CREATE ON SCHEMA ` + views + ` TO ` + r.app, `REVOKE CREATE ON SCHEMA ` + views + ` FROM ` + r.app, true},
		{"it holds a table", `CREATE TABLE ` + views + `.held (a int)`, `DROP TABLE ` + views + `.held`, true},
		{
			"it has default privileges", `ALTER DEFAULT PRIVILEGES FOR ROLE ` + r.admin + ` IN SCHEMA ` + views + ` GRANT SELECT ON TABLES TO ` + r.app,
			`ALTER DEFAULT PRIVILEGES FOR ROLE ` + r.admin + ` IN SCHEMA ` + views + ` REVOKE SELECT ON TABLES FROM ` + r.app, false,
		},
	} {
		exec(c.set)
		_, err := r.adminPool.Exec(ctx, `SELECT rbac_as_of_views()`)
		if c.refused && sqlState(err) != "42P15" || !c.refused && err != nil {
			t.Errorf("making the views again where %s: %v", c.what, err)
		}
		exec(c.unset)
	}
}

// A schema the role migrating makes for AsOf's views takes that role's default privileges, as one a
// superuser makes for it does: where they let another role create in each schema the role makes,
// migrating refuses the one it made, as AsOf would call what that role made there.
func TestMigratingRefusesAViewsSchemaTheRolesDefaultPrivilegesOpen(t *testing.T) {
	ctx := t.Context()
	name, base := pgtest.Database(t, "")
	r := newReadmeRolesIn(t, base)
	views := r.schema + "_as_of"
	exec := func(sql string) {
		t.Helper()
		if _, err := r.super.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// The administrator's role makes the schema itself.
	exec(`DROP SCHEMA ` + views)
	exec(`GRANT CREATE ON DATABASE ` + name + ` TO ` + r.admin)
	exec(`ALTER DEFAULT PRIVILEGES FOR ROLE ` + r.admin + ` GRANT CREATE ON SCHEMAS TO ` + r.app)
	if err := rbac.Migrate(ctx, r.adminPool); sqlState(err) != "42P15" {
		t.Errorf("migrating where the role's default privileges let another create in the schema it makes: %v", err)
	}
	exec(`ALTER DEFAULT PRIVILEGES FOR ROLE ` + r.admin + ` REVOKE CREATE ON SCHEMAS FROM ` + r.app)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("migrating where the role's default privileges let no other create: %v", err)
	}
	var owned, creates bool
	if err := r.super.QueryRow(ctx, `SELECT nspowner = $2::regrole, has_schema_privilege($3, oid, 'CREATE') FROM pg_namespace WHERE oid = $1::regnamespace`,
		views, r.admin, r.app).Scan(&owned, &creates); err != nil || !owned || creates {
		t.Errorf("the schema of AsOf's views the administrator's role made is its own %t, and the application's may create in it %t: %v", owned, creates, err)
	}
}
