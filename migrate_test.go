package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
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
// commit, and PostgreSQL alters no table whose events are pending, as migrations up to
// rbac.HistoryAltered alter history. Where one of those is pending, Migrate refuses a transaction
// holding such events, as ErrInvalid, before it applies any, and the transaction goes on to commit
// its change with its commit record. It migrates one that took a transaction id writing no history;
// one that wrote history before 0027, whose records hold no events, and whose change counts from its
// own date, with no commit record; and one that wrote history once no migration pending alters it,
// which a later migration that does fails until HistoryAltered names it.
func TestMigrateOnAHostsTransactionComesBeforeItsChanges(t *testing.T) {
	const change = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`
	altering, after := fmt.Sprintf("%04d", rbac.HistoryAltered), fmt.Sprintf("%04d", rbac.HistoryAltered+1)
	for _, c := range []struct {
		name, from, write string
		refused           bool
		commits           int
	}{
		{"a change, with a migration altering history pending", altering, change, true, 1},
		{"a transaction id, with a migration altering history pending", altering, `SELECT pg_current_xact_id()`, false, 0},
		{"a change before history recorded commits", commitDates(t), change, false, 0},
		{"a change, with none pending altering history", after, change, false, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.from == after && latestMigration(t) <= rbac.HistoryAltered {
				t.Skip("no migration after the last that alters history")
			}
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			migrateFiles(t, pool, "", c.from)
			recordMigrations(t, pool, c.from)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := tx.Exec(ctx, c.write); err != nil {
				t.Fatal(err)
			}
			err = rbac.Migrate(ctx, tx)
			if c.refused && !errors.Is(err, rbac.ErrInvalid) || !c.refused && err != nil {
				t.Fatalf("Migrate on a host's transaction after %s: %v", c.name, err)
			}
			want := latestMigration(t)
			if c.refused {
				want = rbac.HistoryAltered - 1
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
