package rbac

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrations are the SQL files that create and upgrade the package's tables, for a host that
// runs its migrations with a tool of its own: apply each once, in order of their names, in a
// transaction of its own or at READ COMMITTED, in a database whose encoding is UTF8: one that
// waits for the writes in flight to the tables reads them once they end, which a stricter
// transaction's snapshot, taken by an earlier statement, doesn't. They hold no backslash, so they
// mean the same whatever the session's standard_conforming_strings. Apply each with a short
// lock_timeout, and where it is refused as SQLSTATE 55P03 or 40P01, roll it back and apply it
// again, as Migrate does: a migration that waits for a lock holds those it took meanwhile, and so
// can deadlock with a change, or stall every other. A wait shorter than deadlock_timeout never ends
// an autovacuum worker holding the table, as PostgreSQL cancels one only once a wait for its lock
// passes that: where one holds a table of the package's as a migration gives way, apply it again
// with a lock_timeout past deadlock_timeout, as Migrate does. Migrate applies them itself.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

// Migrate creates or upgrades the package's tables, prefixed rbac_, in the current schema: the
// first in the search_path that exists, in a database whose encoding is UTF8. It records what it
// applied in rbac_migrations, is safe to call from several replicas at once, and never runs by
// itself. It applies each pending migration in a transaction of its own, which records it as it
// commits: so each takes its locks in the order it names them, not after those an earlier one
// took, and a failure leaves the database at the last migration recorded, from which migrating
// again goes on. On a host's transaction it applies them all in one savepoint of it, at that
// transaction's isolation, and refuses any but READ COMMITTED: a stricter one's snapshot, taken by
// an earlier statement, reads the versions from before it waited for another replica, and the rows
// it records as they were before the writes it waited for.
//
// A migration waits at most 100 ms for any lock it takes on the package's tables, as it holds those
// it took before meanwhile, which every statement reading them waits for: a change that reads them
// in another order than the migration locks them would deadlock with it, and a transaction holding
// one for long would stall every other. Migrate then rolls it back and tries it again, waiting
// longer each time, up to 10 times over about 20 seconds, and then fails as ErrConflict: migrate
// again once what held the table has ended. A wait that short ends before PostgreSQL's deadlock
// check, deadlock_timeout into it, which alone cancels an autovacuum worker holding the table the
// wait is for: where one holds any of the package's tables as a migration gives way, as one
// vacuuming a large history can for minutes, the next try waits a second past deadlock_timeout,
// so PostgreSQL cancels the worker, unless it vacuums to prevent wraparound, which PostgreSQL never
// cancels. A role that can't read other sessions' backend types, as one without pg_read_all_stats,
// can't tell autovacuum's vacuums and analyses from a client's, and counts them all. On a host's
// transaction it does none of this, as rolling back to its savepoint frees nothing the host's
// transaction took before, which what the migration waits for can be waiting for in turn: it waits
// as that transaction's lock_timeout says, for PostgreSQL to end such a wait as a deadlock, and
// fails as ErrConflict where it ends the migration's. On any connection it waits for another
// replica's migration as long as the session's lock_timeout lets it, and fails as ErrConflict where
// that ends the wait, without trying again.
func Migrate(ctx context.Context, db DB) error {
	wait, attempt, vacuumed := migrateBackoff, 1, false
	for {
		own, more, err := migrateOnce(ctx, db, vacuumed)
		switch {
		case err == nil && more:
			// The next migration, with tries of its own.
			wait, attempt, vacuumed = migrateBackoff, 1, false
			continue
		case err == nil, !own, attempt >= migrateAttempts, !errors.Is(err, ErrConflict), errors.Is(err, errReplica):
			return err
		}
		var verr error
		if vacuumed, verr = vacuumHolds(ctx, db, err); verr != nil {
			return errors.Join(err, verr)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		wait = min(2*wait, maxMigrateBackoff)
		attempt++
	}
}

// migrateAttempts is how many times Migrate tries a migration before it gives up on a lock;
// migrateLockWait is the longest a migration waits for any one lock, and migrateBackoff how long
// Migrate waits before it tries again, doubling with each try up to maxMigrateBackoff;
// migrateVacuumWait is how much longer than deadlock_timeout a try waits once an autovacuum worker
// held a table as the last gave way. A test lowers the first and third.
var (
	migrateAttempts   = 10
	migrateLockWait   = 100 * time.Millisecond
	migrateBackoff    = 100 * time.Millisecond
	maxMigrateBackoff = 5 * time.Second
	migrateVacuumWait = time.Second
)

// errReplica marks a wait for another replica's migration that the session's lock_timeout ended,
// which Migrate doesn't try again: each try would wait as long again, past what the host set.
var errReplica = errors.New("rbac: waiting for another migration of the schema")

// vacuumHolds reports whether err is a migration giving up on a lock while an autovacuum worker
// holds one of the package's tables in the current schema, as its vacuum or analysis does. Where
// the role can't read a vacuum's backend type, the vacuum counts as autovacuum's, as a client's
// can't be told from it; where it can, only autovacuum's, as PostgreSQL cancels no other. The
// worker can hold another table than the migration waited for, which costs the next try only its
// longer wait.
func vacuumHolds(ctx context.Context, db DB, err error) (bool, error) {
	if pg := (*pgconn.PgError)(nil); !errors.As(err, &pg) || pg.Code != "55P03" {
		return false, nil
	}
	var held bool
	err = db.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_locks l
		JOIN pg_class c ON c.oid = l.relation
		LEFT JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'relation' AND l.granted AND l.mode = 'ShareUpdateExclusiveLock'
		  AND l.database = (SELECT d.oid FROM pg_database d WHERE d.datname = current_database())
		  AND c.relnamespace = (SELECT n.oid FROM pg_namespace n WHERE n.nspname = current_schema())
		  AND starts_with(c.relname, 'rbac_')
		  AND l.pid IN (SELECT v.pid FROM pg_stat_progress_vacuum v UNION ALL SELECT z.pid FROM pg_stat_progress_analyze z)
		  AND coalesce(a.backend_type, 'autovacuum worker') = 'autovacuum worker')`).Scan(&held)
	return held, err
}

// migrateOnce applies the first pending migration in a transaction of its own, reporting whether
// more are pending after it, or every one in a savepoint of the host's, and reports whether it was
// one of its own. vacuumed has a migration wait for a lock past deadlock_timeout.
func migrateOnce(ctx context.Context, db DB, vacuumed bool) (own, more bool, err error) {
	// At READ COMMITTED, so a replica that waited for the lock reads the versions another applied
	// meanwhile: a stricter snapshot, taken before the lock, would apply them again.
	err = beginOwn(ctx, db, func(tx pgx.Tx, fresh bool) error {
		own = fresh
		var schema *string
		var level, conforming string
		if err := tx.QueryRow(ctx, `SELECT current_schema(), current_setting('transaction_isolation'),
			current_setting('standard_conforming_strings')`).Scan(&schema, &level, &conforming); err != nil {
			return err
		}
		if err := readCommitted("Migrate", level); err != nil {
			return err
		}
		if schema == nil {
			return errors.New("rbac: no schema in the search_path exists to migrate in")
		}
		// A session with it off reads a backslash in a literal as an escape, so a pattern would check
		// another thing than its migration says. This covers what migrating parses, not a function
		// body, which each session parses as it calls it, so no migration holds a backslash either.
		standard := conforming == "on"
		if !standard {
			if _, err := tx.Exec(ctx, `SET LOCAL standard_conforming_strings = on`); err != nil {
				return err
			}
		}
		// A database in another encoding can give back text that isn't UTF-8, as SQL_ASCII gives
		// back whatever was stored: history would record it, and no export could chain it, so every
		// export would stop there.
		var encoding string
		if err := tx.QueryRow(ctx, `SELECT current_setting('server_encoding')`).Scan(&encoding); err != nil {
			return err
		}
		if encoding != "UTF8" {
			return fmt.Errorf("rbac: the database's encoding is %s, not UTF8", encoding)
		}
		// One migration at a time in the schema, under a key named as the change locks' are: by the
		// schema it migrates, as the tables may not exist yet, which is the one they are in once
		// they do.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || '/rbac/' || $1, 0))`, "migrate"); err != nil {
			return fmt.Errorf("%w: %w", errReplica, err)
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS rbac_migrations (
			version    integer     PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
			return err
		}
		var applied int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM rbac_migrations`).Scan(&applied); err != nil {
			return err
		}
		// From here, a lock it waits for is one the tables' readers and writers can hold. Bounded only
		// in a transaction of its own, where giving way frees what it holds, and where the setting
		// ends with it.
		if own {
			wait := migrateLockWait.Milliseconds()
			if vacuumed {
				// Past the deadlock check, which alone cancels an autovacuum worker blocking the wait:
				// only a superuser can set deadlock_timeout lower.
				var deadlock int64
				if err := tx.QueryRow(ctx, `SELECT setting::bigint FROM pg_settings WHERE name = 'deadlock_timeout'`).Scan(&deadlock); err != nil {
					return err
				}
				wait = deadlock + migrateVacuumWait.Milliseconds()
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(wait, 10)+"ms"); err != nil {
				return err
			}
		}
		fsys := Migrations()
		names, err := fs.Glob(fsys, "*.sql")
		if err != nil {
			return err
		}
		done := false
		for _, name := range names {
			prefix, _, _ := strings.Cut(name, "_")
			version, err := strconv.Atoi(prefix)
			if err != nil {
				return fmt.Errorf("rbac: migration %s has no version", name)
			}
			if version <= applied {
				continue
			}
			// One in a transaction of its own, so it takes its locks with none of an earlier one's
			// held, and a try rolls back that one alone; every one in a host's savepoint, as rolling
			// it back frees nothing the host's transaction took before.
			if own && done {
				more = true
				break
			}
			sql, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return fmt.Errorf("rbac: migration %s: %w", name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rbac_migrations (version) VALUES ($1)`, version); err != nil {
				return err
			}
			done = true
		}
		if standard {
			return nil
		}
		// As it was, for what a host's transaction runs after.
		_, err = tx.Exec(ctx, `SELECT set_config('standard_conforming_strings', $1, true)`, conforming)
		return err
	})
	return own, more, err
}
