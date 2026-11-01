package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
				// Until the change has written, or waits for a lock, as for history a migration holds.
				for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
					select {
					case err := <-done:
						wrote <- err
						return
					default:
					}
					var waiting bool
					if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
						WHERE NOT l.granted AND c.relnamespace = current_schema()::regnamespace)`).Scan(&waiting); err != nil {
						t.Error(err)
						return
					}
					if waiting {
						go func() { wrote <- <-done }()
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
			if v := migratedTo(t, pool); v != 19 {
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
			if v := migratedTo(t, pool); v != 19 {
				t.Errorf("migrated again to %d", v)
			}
			if _, s := state(t, pool); !s {
				t.Error("migrating again built no index")
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

// deadlockTimeout is the session's deadlock_timeout.
func deadlockTimeout(t *testing.T, db rbac.DB) time.Duration {
	t.Helper()
	var ms int64
	if err := db.QueryRow(t.Context(), `SELECT setting::bigint FROM pg_settings WHERE name = 'deadlock_timeout'`).Scan(&ms); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ms) * time.Millisecond
}

// historyToVacuum migrates pool's schema up to 0019 and fills history with enough records that a
// vacuum slowed to a crawl takes minutes over it.
func historyToVacuum(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := applyMigrations(t.Context(), pool, pgx.ReadCommitted, "", "0019"); err != nil {
		t.Fatal(err)
	}
	recordMigrations(t, pool, "0019")
	if _, err := pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 't1', 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.admin' FROM generate_series(1, 10000) i`); err != nil {
		t.Fatal(err)
	}
}

// An autovacuum worker holding history, as one vacuuming a large history does for minutes, holds
// 0019 back only until PostgreSQL cancels it, which it does once a wait for its lock passes
// deadlock_timeout: Migrate waits that long once the worker held the table as a try gave way, as
// the README's administrator's role, which can't read the worker's backend type. Waiting at most
// 100 ms each time, it gave way on every try while the worker ran on.
func TestMigrateWaitsForPostgreSQLToCancelAutovacuum(t *testing.T) {
	ctx := t.Context()
	r := newReadmeRoles(t)
	historyToVacuum(t, r.adminPool)
	// Table-level settings alone: autovacuum vacuums history for the records inserted, slowly, and
	// doesn't analyze it.
	if _, err := r.adminPool.Exec(ctx, `ALTER TABLE rbac_history SET (autovacuum_vacuum_insert_threshold = 1,
		autovacuum_vacuum_insert_scale_factor = 0, autovacuum_vacuum_cost_delay = 100, autovacuum_vacuum_cost_limit = 1,
		autovacuum_analyze_threshold = 1000000000)`); err != nil {
		t.Fatal(err)
	}
	var pid int
	for deadline := time.Now().Add(5 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		err := r.super.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE backend_type = 'autovacuum worker'
			AND query LIKE '%' || $1 || '.rbac_history%'`, r.schema).Scan(&pid)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Skip("no autovacuum worker reached history in time")
		}
	}
	rbac.SetMigrateAttempts(t, 3, time.Millisecond)
	if err := rbac.Migrate(ctx, r.adminPool); err != nil {
		t.Fatalf("Migrate while autovacuum vacuums history: %v", err)
	}
	if v := migratedTo(t, r.adminPool); v != 19 {
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

// A vacuum a client runs, which PostgreSQL never cancels for a lock, doesn't have Migrate wait
// past deadlock_timeout for it, where its role can tell the vacuum from autovacuum's.
func TestMigrateDoesntWaitOutAClientsVacuum(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	historyToVacuum(t, pool)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	pid := conn.Conn().PgConn().PID()
	if _, err := conn.Exec(ctx, `SET vacuum_cost_delay = 100; SET vacuum_cost_limit = 1`); err != nil {
		t.Fatal(err)
	}
	vacuumed := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, `VACUUM rbac_history`)
		vacuumed <- err
	}()
	defer func() {
		if _, err := pool.Exec(context.WithoutCancel(ctx), `SELECT pg_cancel_backend($1)`, pid); err != nil {
			t.Error(err)
		}
		<-vacuumed
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var running bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_progress_vacuum WHERE pid = $1 AND relid = 'rbac_history'::regclass)`, pid).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the vacuum never started")
		}
	}
	rbac.SetMigrateAttempts(t, 2, time.Millisecond)
	began := time.Now()
	err = rbac.Migrate(ctx, pool)
	took := time.Since(began)
	var pg *pgconn.PgError
	if !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("Migrate while a client vacuums history: %v", err)
	}
	if limit := deadlockTimeout(t, pool); took >= limit {
		t.Errorf("Migrate took %v beside a client's vacuum, past deadlock_timeout's %v", took, limit)
	}
}
