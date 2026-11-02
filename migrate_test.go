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
				"rbac_history_append_only search_path=pg_catalog, pg_temp",
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
