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

// Migrations are the SQL files that create and upgrade the package's tables, for a host that runs
// its migrations with a tool of its own: apply each once, in order of their names, as the role
// owning the package's tables, as Migrate does, in a transaction of its own or at READ COMMITTED,
// in a database whose encoding is UTF8: one that waits for the writes in flight to the tables reads
// them once they end, which a stricter transaction's snapshot, taken by an earlier statement,
// doesn't, and before any change to the package's tables in that transaction, as Migrate requires.
// They hold no backslash, so they mean the same whatever the session's standard_conforming_strings.
// Apply each with a short lock_timeout, and where it is refused as SQLSTATE 55P03 or 40P01, roll it
// back and apply it again, as Migrate does: a migration that waits for a lock holds those it took
// meanwhile, and so can deadlock with a change, or stall every other. A wait shorter than
// deadlock_timeout never ends an autovacuum worker holding the table, as PostgreSQL cancels one
// only once a wait for its lock passes that: where one holds a table of the package's as a
// migration gives way, apply it again having first locked that table IN SHARE UPDATE EXCLUSIVE MODE
// with a lock_timeout past deadlock_timeout, and then with the short one again, as Migrate does.
// Migrate applies them itself.
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
// again goes on. On a host's transaction, a pgx.Tx or a DB whose Begin gives a savepoint of one, it
// applies them all in one savepoint of it, at that transaction's isolation, and refuses any but
// READ COMMITTED: a stricter one's snapshot, taken by an earlier statement, reads the versions from
// before it waited for another replica, and the rows it records as they were before the writes it
// waited for. Call it there before any change to the package's tables: from 0027_commit_dates on,
// each record of history a change writes holds an event deferred to the commit, as from
// 0020_recorded_prunes on each record a prune deletes does, and PostgreSQL alters no table whose
// events are pending, as migrations up to 0032_expired_writes alter history.
// So where one of those is pending, it refuses, as ErrInvalid, a transaction holding such events,
// before it waits for another replica's migration or applies any.
//
// Only the role owning the package's tables migrates them: a migration makes what it makes its
// maker's, and from 0028_as_of_views on checks the schema of AsOf's views against it, which AsOf
// finds among that role's views. As another role, Migrate refuses, as ErrInvalid naming that one,
// before it applies anything or takes any lock, but as a superuser, which it runs each migration as
// that role for, by SET LOCAL ROLE, and as itself again after: so a superuser's migration makes
// and checks what that role's own would, and fails where that one's would, saying what to grant.
// A superuser whose login may not SET ROLE to that role is refused too. It decides so again once it
// holds the schema's lock, as the replica it waited for can have made the tables meanwhile. Where
// the tables aren't made yet, the role migrating makes them, and owns them, a superuser too; it is
// refused, as ErrInvalid, where the schema of AsOf's views is made and another role's.
//
// A migration waits at most 100 ms for any lock it takes on the package's tables, as it holds those
// it took before meanwhile, which every statement reading them waits for: a change that reads them
// in another order than the migration locks them would deadlock with it, and a transaction holding
// one for long would stall every other. Migrate then rolls it back and tries it again, waiting
// longer each time, up to 10 times over about 20 seconds, and then fails as ErrConflict: migrate
// again once what held the table has ended. A wait that short ends before PostgreSQL's deadlock
// check, deadlock_timeout into it, which alone cancels an autovacuum worker holding the table the
// wait is for, as one vacuuming a large history can for minutes. So where a try gave way, the next
// first takes the SHARE UPDATE EXCLUSIVE lock of each of the package's tables an autovacuum worker
// holds, waiting a second past deadlock_timeout, whatever the session's lock_timeout, for
// PostgreSQL to cancel the worker, and then the migration's own locks: no check, list or change
// takes a lock that one conflicts with, so none waits behind it, and none of the migration's is
// held yet. Where a table's wait ends, as for a vacuum to prevent wraparound, which PostgreSQL
// never cancels, the try goes on without that table's lock, and each try after it waits so again:
// with deadlock_timeout's default of 1 second, some 20 seconds more over the 10 tries for each such
// table. The worker can hold a table the migration doesn't lock, which it then cancels too. A role
// that can't read other sessions' backend types, as one without pg_read_all_stats, can't tell
// autovacuum's vacuums and analyses from a client's, and waits so for them all. On a host's
// transaction it does none of this, as rolling back to its savepoint frees nothing the host's
// transaction took before, which what the migration waits for can be waiting for in turn: it waits
// as that transaction's lock_timeout says, for PostgreSQL to end such a wait as a deadlock, and
// fails as ErrConflict where it ends the migration's. On any connection it waits for another
// replica's migration as long as the session's lock_timeout lets it, and fails as ErrConflict where
// that ends the wait, without trying again.
func Migrate(ctx context.Context, db DB) error {
	for {
		more, err := migrateNext(ctx, db)
		if err != nil || !more {
			return err
		}
	}
}

// migrateNext applies the first pending migration, or on a host's transaction every one, trying it
// again as it gives way, and reports whether more are pending after it.
func migrateNext(ctx context.Context, db DB) (bool, error) {
	wait, gaveWay := migrateBackoff, false
	for attempt := 1; ; attempt++ {
		own, more, err := migrateOnce(ctx, db, gaveWay)
		if err == nil || !own || attempt >= migrateAttempts || !errors.Is(err, ErrConflict) || errors.Is(err, errReplica) {
			return more, err
		}
		pg := (*pgconn.PgError)(nil)
		gaveWay = errors.As(err, &pg) && pg.Code == "55P03"
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		wait = min(2*wait, maxMigrateBackoff)
	}
}

// migrateAttempts is how many times Migrate tries a migration before it gives up on a lock;
// migrateLockWait is the longest a migration waits for any one lock, and migrateBackoff how long
// Migrate waits before it tries again, doubling with each try up to maxMigrateBackoff;
// migrateVacuumWait is how much longer than deadlock_timeout a try that follows one giving way
// waits for the tables an autovacuum worker holds. A test lowers the first and third.
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

// historyAltered is the version of the last migration that alters rbac_history's table, as ALTER
// TABLE or CREATE INDEX does, which PostgreSQL refuses in a transaction holding events of the
// table's deferred triggers (SQLSTATE 55006), as one that wrote history holds those of its commit
// record's until it commits, and one that pruned it those of its prunes'. A test migrates such a
// host's transaction from the migration after it, which a later one that alters history fails until
// this names it, and checks that this one can't commit while such a transaction holds history;
// another finds each migration altering history by its statements, failing until this names the
// last.
const historyAltered = 32

// historyUnwritten refuses, as ErrInvalid, a host's transaction tx that holds events of history's
// deferred triggers in schema, where a migration pending alters history (historyAltered), which
// PostgreSQL refuses while they are pending: rbac_history_committed's (from 0027_commit_dates on),
// one for each record tx wrote, and rbac_history_pruned's (from 0020_recorded_prunes on), one for
// each record a prune in tx deleted, which then writes the prune's record. Each counts while its
// trigger is enabled: with the commit record's disabled, a prune's deletes still hold the other's. tx's records are those of its txid while tx holds the lock that writing
// history takes, whatever cluster they name, as rbac_record stamps one with any cluster a session
// sets, and history's owner can write one naming none: a record a restore carried under a txid this
// cluster has since given tx, a prune's naming no cluster too, is another transaction's, and a
// transaction that only took that txid holds no such lock. Migrate calls it before it takes any
// lock, so a refusal doesn't wait for another replica's migration first: historyAltered's migration
// locks history against writes, so it doesn't commit while tx holds that lock, and tx reads as
// applied what it would after the wait. Firing the events early to let it through would write the
// commit record before the transaction commits, and AsOf would count its changes from before any
// other session saw them.
func historyUnwritten(ctx context.Context, tx pgx.Tx, schema string) error {
	var wrote, committed, pruned bool
	if err := tx.QueryRow(ctx, `WITH history AS (SELECT pg_catalog.to_regclass(pg_catalog.quote_ident($1) || '.rbac_history') AS oid)
		SELECT pg_catalog.pg_current_xact_id_if_assigned() IS NOT NULL
		    AND pg_catalog.to_regclass(pg_catalog.quote_ident($1) || '.rbac_migrations') IS NOT NULL
		    AND EXISTS (SELECT FROM pg_catalog.pg_locks l, history h WHERE l.pid = pg_catalog.pg_backend_pid()
		      AND l.locktype = 'relation' AND l.relation = h.oid AND l.mode = 'RowExclusiveLock'),
		  EXISTS (SELECT FROM pg_catalog.pg_trigger t, history h WHERE t.tgrelid = h.oid
		    AND t.tgname = 'rbac_history_committed' AND t.tgenabled <> 'D'),
		  EXISTS (SELECT FROM pg_catalog.pg_trigger t, history h WHERE t.tgrelid = h.oid
		    AND t.tgname = 'rbac_history_pruned' AND t.tgenabled <> 'D')`, schema).Scan(&wrote, &committed, &pruned); err != nil || !wrote || !committed && !pruned {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT (SELECT coalesce(max(m.version), 0) FROM `+pgx.Identifier{schema, "rbac_migrations"}.Sanitize()+` m) < $1
		AND EXISTS (SELECT FROM `+historyTable(schema)+` h WHERE h.txid = pg_catalog.pg_current_xact_id_if_assigned()
		  AND ($2::boolean OR $3::boolean AND h.entity = 'history' AND h.op = 'prune'))`, historyAltered, committed, pruned).Scan(&wrote); err != nil || !wrote {
		return err
	}
	return fmt.Errorf("%w: Migrate on a host's transaction comes before the transaction changes the package's tables: this one has written history, whose events, deferred to its commit, keep a pending migration from altering it", ErrInvalid)
}

// outwaitVacuum locks, in a savepoint of tx, each of the package's tables in schema an autovacuum
// worker holds, as its vacuum or analysis does, in the mode it holds them, waiting
// migrateVacuumWait past deadlock_timeout, so PostgreSQL's deadlock check cancels the worker, and
// then has the migration's own locks wait migrateLockWait again. Where the role can't read a
// vacuum's backend type, the vacuum counts as autovacuum's, as a client's can't be told from it;
// where it can, only autovacuum's, as PostgreSQL cancels no other. Each table is locked in a
// savepoint of its own, so where a wait ends, as for a vacuum PostgreSQL never cancels, the try
// goes on without that table's lock, and the waits for the tables after it, which cancel their
// workers, still come. Where the role can't read what holds the tables, it rolls back to the first
// savepoint, which frees what it locked and sets lock_timeout back, so the try goes on as it would
// without it.
func outwaitVacuum(ctx context.Context, tx pgx.Tx, schema string) {
	_ = savepoint(ctx, tx, func(tx pgx.Tx) error {
		var held []string
		var deadlock int64
		if err := tx.QueryRow(ctx, `SELECT ARRAY(SELECT DISTINCT c.relname FROM pg_locks l
			JOIN pg_class c ON c.oid = l.relation
			LEFT JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE l.locktype = 'relation' AND l.granted AND l.mode = 'ShareUpdateExclusiveLock'
			  AND l.database = (SELECT d.oid FROM pg_database d WHERE d.datname = current_database())
			  AND c.relnamespace = (SELECT n.oid FROM pg_namespace n WHERE n.nspname = $1)
			  AND starts_with(c.relname, 'rbac_')
			  AND l.pid IN (SELECT v.pid FROM pg_stat_progress_vacuum v UNION ALL SELECT z.pid FROM pg_stat_progress_analyze z)
			  AND coalesce(a.backend_type, 'autovacuum worker') = 'autovacuum worker'
			ORDER BY 1),
			(SELECT setting::bigint FROM pg_settings WHERE name = 'deadlock_timeout')`, schema).Scan(&held, &deadlock); err != nil || len(held) == 0 {
			return err
		}
		// Past the deadlock check: only a superuser can set deadlock_timeout lower.
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, milliseconds(time.Duration(deadlock)*time.Millisecond+migrateVacuumWait)); err != nil {
			return err
		}
		for _, name := range held {
			_ = savepoint(ctx, tx, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `LOCK TABLE `+pgx.Identifier{schema, name}.Sanitize()+` IN SHARE UPDATE EXCLUSIVE MODE`)
				return err
			})
		}
		_, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, milliseconds(migrateLockWait))
		return err
	})
}

// asOwner has tx, which migrates the package's tables in schema, run as the role owning them, and
// returns what puts its role back as it was, or nil where it runs as it is. A migration makes what
// it makes its maker's, and some check what they find against their maker, as 0028_as_of_views
// does the schema of AsOf's views, which AsOf finds among the views of the tables' owner: another
// role's migration would leave them another's, or fail partway, having made some that are. So it
// refuses another role, as ErrInvalid naming the owner, but a superuser, which it sets, by SET
// LOCAL ROLE, to the owner, whose privileges its statements are then checked against, so it makes
// and checks what the owner's own migration would: no bound on what runs, as code of the owner's a
// migration calls can RESET ROLE, as it ran as the superuser outright before. The role is the
// current one, which a migration makes what it makes as, not the session's login, which a host can
// have set another for; but PostgreSQL lets a session SET ROLE only to a role its login may, so it
// refuses a superuser whose login may not, as one that is a superuser only by SET ROLE to a
// superuser role, as ErrInvalid saying to migrate as the owner: setting the role would fail with
// SQLSTATE 42501 even with nothing pending, and as itself it would make what it makes its own.
// Where the tables aren't made, the role migrating makes them as itself, a superuser too: never as
// the schema's owner or the database's, which can be the application's role, as where it owns the
// database and so public, and that role, owning them, could disable history's triggers. But once it
// holds the lock, it refuses any role, a superuser too, where the schema of AsOf's views is made and
// another role's, as the README's administrator's role's is, naming that role: 0028_as_of_views
// would fail there, having made every table before it the role migrating's, which that role then
// couldn't migrate, and which, where the application's role may create in the schema, would be
// that role's. So it refuses any role too, before the lock and under it, where the schema is named
// in more than maxAsOfSchema bytes, which 0028_as_of_views refuses for every role, as the views'
// schema, named as it with _as_of after, would be cut short: the server counts them, as it cuts a
// name, in the database's encoding, not len in the session's client_encoding, which a host can set
// to one that counts fewer.
// Migrate calls it before it takes the schema's lock, locked false, where it only refuses, so a
// role is refused without waiting for another replica's migration, and again once it holds the
// lock, locked true, where it sets the role, or refuses a role on a schema holding none of the
// tables, as that replica can have made the tables, or given them to another role, since it read
// them: a superuser that read none would make the next migration's tables its own, which the
// owner's migrations after it then fail on. The current schema is the first on the search_path the
// role has USAGE on, which "$user" names by the role, so it refuses an owner it is another for.
func asOwner(ctx context.Context, tx pgx.Tx, schema string, locked bool) (restore func() error, err error) {
	var owner, views *string
	var mine, super, set bool
	var login, role string
	var bytes int
	// The tables by name, read at the statement's snapshot, not by to_regclass: the session caches
	// the table's absence as it looks it up before the lock, and reads the replica's tables only once
	// it takes a table's lock, so under the lock it would read none of those made meanwhile. A table
	// only: another relation so named is no owner's of the tables, but a role that may create in the
	// schema could make one to have a superuser migrate as that role. A table so named that such a
	// role makes still does: 0001 then fails as that role, the table being made, having made
	// nothing, and the owner's role is refused, told to migrate as that role.
	if err := tx.QueryRow(ctx, `SELECT o.rolname::pg_catalog.text, coalesce(o.oid = r.oid, false), r.rolsuper,
		  coalesce(pg_catalog.pg_has_role(SESSION_USER, o.oid, 'SET'), false), SESSION_USER::pg_catalog.text, pg_catalog.current_setting('role'),
		  (SELECT pg_catalog.pg_get_userbyid(v.nspowner)::pg_catalog.text FROM pg_catalog.pg_namespace v
		    WHERE v.nspname = $1 || '_as_of' AND v.nspowner <> r.oid),
		  pg_catalog.octet_length($1)
		FROM pg_catalog.pg_roles r
		LEFT JOIN pg_catalog.pg_namespace n ON n.nspname = $1
		LEFT JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = 'rbac_grants' AND c.relkind IN ('r', 'p')
		LEFT JOIN pg_catalog.pg_roles o ON o.oid = c.relowner
		WHERE r.rolname = CURRENT_USER`, schema).Scan(&owner, &mine, &super, &set, &login, &role, &views, &bytes); err != nil {
		return nil, err
	}
	planted, err := plantedFor(ctx, tx, schema)
	if err != nil {
		return nil, err
	}
	creator, err := creatorIn(ctx, tx, schema)
	if err != nil {
		return nil, err
	}
	switch {
	case planted != nil && owner == nil:
		return nil, fmt.Errorf("%w: schema %s holds none of the package's tables, but holds %s, which a migration would find in its place, run, or call as the role migrating: drop it, or migrate in another schema",
			ErrInvalid, schema, *planted)
	case planted != nil:
		return nil, fmt.Errorf("%w: schema %s holds %s, which a migration would find in place of its own, run, or call as the role migrating, and which neither %s, owning the package's tables, nor history's owner nor a superuser owns: drop it",
			ErrInvalid, schema, *planted, *owner)
	case owner == nil && bytes > maxAsOfSchema:
		return nil, fmt.Errorf("%w: schema %s holds none of the package's tables, which a migration makes its maker's, and is named in %d bytes, too many for the schema of AsOf's views, named as it with _as_of after, in at most 63, so 0028_as_of_views fails there for every role: rename it to a name of at most %d bytes",
			ErrInvalid, schema, bytes, maxAsOfSchema)
	case owner == nil && locked && views != nil:
		return nil, fmt.Errorf("%w: schema %s holds none of the package's tables, which a migration makes its maker's, and 0028_as_of_views makes AsOf's views only in a schema %s_as_of of its maker's, which is %s's: migrate as %[4]s, or give that schema to this role",
			ErrInvalid, schema, schema, *views)
	case creator != nil && (owner == nil && locked || mine || super && set):
		return nil, fmt.Errorf("%w: in schema %s, %s may create, which could make there, while the migration runs, what it would find in place of its own, run, or call as the role migrating: revoke CREATE on the schema from it, or give the schema to the role owning the package's tables",
			ErrInvalid, schema, *creator)
	case owner == nil || mine:
		return nil, nil
	case !super:
		return nil, fmt.Errorf("%w: the package's tables in schema %s are %s's, and a migration makes what it makes its maker's: migrate as %[3]s, or as a superuser, which migrates as that role",
			ErrInvalid, schema, *owner)
	case !set:
		return nil, fmt.Errorf("%w: the package's tables in schema %s are %s's, and a migration makes what it makes its maker's: a superuser's migration sets its role to that one, which this session's login, %s, may not SET ROLE to; migrate as %[3]s, connecting as it or setting the role to it from a login that may",
			ErrInvalid, schema, *owner, login)
	case !locked:
		return nil, nil
	}
	var current *string
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('role', $1, true)`, *owner); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_schema()`).Scan(&current); err != nil {
		return nil, err
	}
	if current == nil || *current != schema {
		return nil, fmt.Errorf("%w: as %s, which owns the package's tables, schema %s isn't the first on the search_path: that role has no USAGE on it, or the search_path names another for it first", ErrInvalid, *owner, schema)
	}
	return func() error {
		_, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('role', $1, true)`, role)
		return err
	}, nil
}

// plantedFor names, as "table s.rbac_migrations, role's", an object in schema or the schema of
// AsOf's views beside it that a role other than the one owning the package's tables made, where a
// migration would find it in place of its own, run it, or call it, as the role migrating, or nil
// where there is none. A role that may create in the schema, as the application's can where it is
// given CREATE there or owns the database and so public, could otherwise make rbac_migrations
// first, which CREATE TABLE IF NOT EXISTS keeps, with versions that skip migrations or a trigger
// that runs as the role migrating, a superuser too, on each version recorded. So a relation, type
// or function named rbac_, which a migration makes or would find so named, is one where neither the
// tables' owner, nor history's once they are made, nor a superuser owns it, and rbac_migrations is
// unless it is an ordinary table of the tables' owner's. So is a function or operator in the
// schema that none of those owns, which a statement whose arguments it matches better than
// pg_catalog's would call, as format(text, name) does format(..., current_schema()), and a trigger
// on any of the tables calling a function none of those owns: its maker needs only TRIGGER on the
// table, and it fires on the migration's writes. Its WHEN clause runs as the role migrating too,
// whatever function it executes, as pg_catalog's own, so a trigger is one where anything it
// depends on, a function, operator or type, as a domain whose check calls one, is another's, and
// one with a WHEN clause or arguments at all, whoever made it, none of the package's has either:
// pg_catalog's own functions run SQL text, as query_to_xml('SELECT f()', ...) does, which depends on
// nothing another role owns, set_config would undo the search_path the migrations run under, and a
// superuser's trigger function can run what its arguments name, as refint's check_primary_key reads
// the relation they do, which can be another role's view calling its function. So too is any other object in the schema that names
// can find, but tables, views and indexes not named rbac_, which a migration names only so: a type
// or domain, a composite type, collation, conversion, text search configuration or dictionary,
// statistics object, foreign table, or a sequence no column owns, which a name a migration gives
// could resolve to, or which a migration's CREATE would meet, now or once a later one names it. Rules
// and policies only a table's owner makes, and operator classes and families, text search parsers
// and templates only a superuser. The tables' owner is the role that will make them, the current
// one, where they aren't made.
func plantedFor(ctx context.Context, tx pgx.Tx, schema string) (*string, error) {
	var planted *string
	err := tx.QueryRow(ctx, `WITH s AS (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = $1),
		  ns AS (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname IN ($1, $1 || '_as_of')),
		  tables AS (SELECT c.relowner FROM pg_catalog.pg_class c JOIN s ON c.relnamespace = s.oid
		    WHERE c.relname = 'rbac_grants' AND c.relkind IN ('r', 'p')),
		  maker AS (SELECT coalesce((SELECT t.relowner FROM tables t),
		    (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER)) AS oid),
		  trusted AS (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolsuper OR r.oid = (SELECT m.oid FROM maker m)
		    OR r.oid IN (SELECT c.relowner FROM pg_catalog.pg_class c JOIN s ON c.relnamespace = s.oid
		      WHERE c.relname = 'rbac_history' AND c.relkind IN ('r', 'p') AND EXISTS (SELECT FROM tables))),
		  named AS (SELECT 'pg_catalog.pg_class'::pg_catalog.regclass AS class, c.oid, c.relowner AS owner,
		      c.relname = 'rbac_migrations' AND (c.relkind <> 'r' OR c.relowner <> (SELECT m.oid FROM maker m)) AS wrong,
		      CASE WHEN c.relname = 'rbac_migrations' THEN 0 WHEN c.relkind IN ('i', 'I') THEN 2 ELSE 1 END AS rank
		    FROM pg_catalog.pg_class c JOIN ns ON c.relnamespace = ns.oid WHERE pg_catalog.starts_with(c.relname::pg_catalog.text, 'rbac_')
		    UNION ALL SELECT 'pg_catalog.pg_type'::pg_catalog.regclass, y.oid, y.typowner, false, 1
		    FROM pg_catalog.pg_type y JOIN ns ON y.typnamespace = ns.oid
		    WHERE y.typrelid = 0 AND pg_catalog.starts_with(y.typname::pg_catalog.text, 'rbac_') AND NOT EXISTS (SELECT FROM pg_catalog.pg_type e WHERE e.typarray = y.oid)
		    UNION ALL SELECT 'pg_catalog.pg_proc'::pg_catalog.regclass, p.oid, p.proowner, false, 1
		    FROM pg_catalog.pg_proc p JOIN ns ON p.pronamespace = ns.oid WHERE pg_catalog.starts_with(p.proname::pg_catalog.text, 'rbac_')),
		  planted AS (SELECT n.class, n.oid, n.owner, n.rank FROM named n
		    WHERE n.wrong OR n.owner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_proc'::pg_catalog.regclass, p.oid, p.proowner, 1 FROM pg_catalog.pg_proc p JOIN s ON p.pronamespace = s.oid
		    WHERE p.proowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_operator'::pg_catalog.regclass, o.oid, o.oprowner, 1 FROM pg_catalog.pg_operator o JOIN s ON o.oprnamespace = s.oid
		    WHERE o.oprowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_trigger'::pg_catalog.regclass, g.oid, u.owner, 1 FROM pg_catalog.pg_trigger g
		    JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN ns ON c.relnamespace = ns.oid
		    JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_trigger'::pg_catalog.regclass AND d.objid = g.oid
		    JOIN (SELECT 'pg_catalog.pg_proc'::pg_catalog.regclass AS class, p.oid, p.proowner AS owner FROM pg_catalog.pg_proc p
		      UNION ALL SELECT 'pg_catalog.pg_operator'::pg_catalog.regclass, o.oid, o.oprowner FROM pg_catalog.pg_operator o
		      UNION ALL SELECT 'pg_catalog.pg_type'::pg_catalog.regclass, y.oid, y.typowner FROM pg_catalog.pg_type y) u
		      ON u.class = d.refclassid AND u.oid = d.refobjid
		    WHERE NOT g.tgisinternal AND pg_catalog.starts_with(c.relname::pg_catalog.text, 'rbac_') AND u.owner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_trigger'::pg_catalog.regclass, g.oid, 0::pg_catalog.oid, 1 FROM pg_catalog.pg_trigger g
		    JOIN pg_catalog.pg_class c ON c.oid = g.tgrelid JOIN ns ON c.relnamespace = ns.oid
		    WHERE NOT g.tgisinternal AND (g.tgqual IS NOT NULL OR g.tgnargs > 0) AND pg_catalog.starts_with(c.relname::pg_catalog.text, 'rbac_')
		    UNION ALL SELECT 'pg_catalog.pg_type'::pg_catalog.regclass, y.oid, y.typowner, 1 FROM pg_catalog.pg_type y JOIN s ON y.typnamespace = s.oid
		    WHERE y.typrelid = 0 AND y.typowner NOT IN (SELECT t.oid FROM trusted t) AND NOT EXISTS (SELECT FROM pg_catalog.pg_type e WHERE e.typarray = y.oid)
		    UNION ALL SELECT 'pg_catalog.pg_class'::pg_catalog.regclass, c.oid, c.relowner, 1 FROM pg_catalog.pg_class c JOIN s ON c.relnamespace = s.oid
		    WHERE c.relkind IN ('S', 'c', 'f') AND c.relowner NOT IN (SELECT t.oid FROM trusted t)
		      AND NOT EXISTS (SELECT FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
		        AND d.objid = c.oid AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refobjsubid <> 0 AND d.deptype IN ('a', 'i'))
		    UNION ALL SELECT 'pg_catalog.pg_collation'::pg_catalog.regclass, l.oid, l.collowner, 1 FROM pg_catalog.pg_collation l JOIN s ON l.collnamespace = s.oid
		    WHERE l.collowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_conversion'::pg_catalog.regclass, v.oid, v.conowner, 1 FROM pg_catalog.pg_conversion v JOIN s ON v.connamespace = s.oid
		    WHERE v.conowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_ts_config'::pg_catalog.regclass, f.oid, f.cfgowner, 1 FROM pg_catalog.pg_ts_config f JOIN s ON f.cfgnamespace = s.oid
		    WHERE f.cfgowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_ts_dict'::pg_catalog.regclass, d.oid, d.dictowner, 1 FROM pg_catalog.pg_ts_dict d JOIN s ON d.dictnamespace = s.oid
		    WHERE d.dictowner NOT IN (SELECT t.oid FROM trusted t)
		    UNION ALL SELECT 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass, x.oid, x.stxowner, 1 FROM pg_catalog.pg_statistic_ext x JOIN s ON x.stxnamespace = s.oid
		    WHERE x.stxowner NOT IN (SELECT t.oid FROM trusted t))
		SELECT pg_catalog.pg_describe_object(p.class, p.oid, 0) || CASE WHEN p.owner <> 0 THEN ', ' || pg_catalog.pg_get_userbyid(p.owner)::pg_catalog.text || '''s'
		  WHEN (SELECT g.tgqual IS NOT NULL FROM pg_catalog.pg_trigger g WHERE g.oid = p.oid) THEN ', whose WHEN clause runs as the role migrating'
		  ELSE ', whose arguments name what its function runs as the role migrating' END
		FROM planted p ORDER BY p.rank, 1 LIMIT 1`, schema).Scan(&planted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return planted, err
}

// creatorIn names a role, or PUBLIC, that may create in schema but neither owns the package's
// tables, the role that will make them where they aren't made, nor owns history once they are, nor
// is a superuser, or nil where there is none. plantedFor reads the schema as it is, but such a role
// could make what it refuses after it reads it and before a migration's statement finds it, as a
// session creating in a schema waits for no lock a migration holds: an overload a migration's
// statement calls, a relation named as one a later migration makes. The schema's owner may, as it
// can grant itself CREATE whatever its privileges say, as can a member of it that may use its
// rights, SET ROLE to it, or grant itself either, holding ADMIN on it, the database's owner too
// where pg_database_owner owns it, as public, and any member of a role that may; a member holding
// none of those may do nothing as it. A role holding the rights of the tables' owner, history's or
// a superuser, as a login that may SET ROLE to the tables' owner, could do as that one anyway, so
// isn't named, nor is one holding ADMIN on the first two, which can grant itself SET, as the role
// that made one does where a role with CREATEROLE, not a superuser, made it. asOwner refuses it on
// a schema holding none of the tables only under the lock, as the replica it waits for can make
// them meanwhile, whose owner may then create.
func creatorIn(ctx context.Context, tx pgx.Tx, schema string) (*string, error) {
	var creator *string
	err := tx.QueryRow(ctx, `WITH s AS (SELECT n.oid, n.nspowner, n.nspacl FROM pg_catalog.pg_namespace n WHERE n.nspname = $1),
		  tables AS (SELECT c.relowner FROM pg_catalog.pg_class c JOIN s ON c.relnamespace = s.oid
		    WHERE c.relname = 'rbac_grants' AND c.relkind IN ('r', 'p')),
		  maker AS (SELECT coalesce((SELECT t.relowner FROM tables t),
		    (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER)) AS oid),
		  trusted AS (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolsuper OR r.oid = (SELECT m.oid FROM maker m)
		    OR r.oid IN (SELECT c.relowner FROM pg_catalog.pg_class c JOIN s ON c.relnamespace = s.oid
		      WHERE c.relname = 'rbac_history' AND c.relkind IN ('r', 'p') AND EXISTS (SELECT FROM tables))),
		  trusting AS (SELECT r.oid FROM pg_catalog.pg_roles r WHERE EXISTS (SELECT FROM trusted t
		    WHERE pg_catalog.pg_has_role(r.oid, t.oid, 'USAGE') OR pg_catalog.pg_has_role(r.oid, t.oid, 'SET')
		      OR pg_catalog.pg_has_role(r.oid, t.oid, 'USAGE WITH ADMIN OPTION')
		        AND NOT (SELECT o.rolsuper FROM pg_catalog.pg_roles o WHERE o.oid = t.oid))),
		  creators AS (SELECT 0 AS rank, 'PUBLIC'::pg_catalog.text AS name FROM s, pg_catalog.aclexplode(s.nspacl) a
		    WHERE a.grantee = 0 AND a.privilege_type = 'CREATE'
		    UNION ALL SELECT 1, pg_catalog.quote_ident(r.rolname) FROM pg_catalog.pg_roles r, s
		    WHERE r.rolname <> 'pg_database_owner' AND r.oid NOT IN (SELECT t.oid FROM trusting t)
		      AND (pg_catalog.pg_has_role(r.oid, s.nspowner, 'USAGE') OR pg_catalog.pg_has_role(r.oid, s.nspowner, 'SET')
		        OR pg_catalog.pg_has_role(r.oid, s.nspowner, 'USAGE WITH ADMIN OPTION') OR pg_catalog.has_schema_privilege(r.oid, s.oid, 'CREATE')))
		SELECT c.name FROM creators c ORDER BY c.rank, c.name LIMIT 1`, schema).Scan(&creator)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return creator, err
}

// milliseconds is d as a setting such as lock_timeout reads it.
func milliseconds(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}

// migrateOnce applies the first pending migration in a transaction of its own, reporting whether
// more are pending after it, or every one in a savepoint of the host's, and reports whether it was
// one of its own. gaveWay, that the last try of it gave way, has it first outwait autovacuum.
func migrateOnce(ctx context.Context, db DB, gaveWay bool) (own, more bool, err error) {
	// At READ COMMITTED, so a replica that waited for the lock reads the versions another applied
	// meanwhile: a stricter snapshot, taken before the lock, would apply them again.
	err = beginOwn(ctx, db, func(tx pgx.Tx, fresh bool) error {
		own = fresh
		var schema *string
		var level, conforming, path string
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_schema(), pg_catalog.current_setting('transaction_isolation'),
			pg_catalog.current_setting('standard_conforming_strings'), pg_catalog.current_setting('search_path')`).Scan(&schema, &level, &conforming, &path); err != nil {
			return err
		}
		if err := readCommitted("Migrate", level); err != nil {
			return err
		}
		if schema == nil {
			return errors.New("rbac: no schema in the search_path exists to migrate in")
		}
		// The schema alone, after pg_catalog, which PostgreSQL searches first: a function or operator
		// in a schema after it on the host's search_path, another role's, as public's is where that
		// role owns the database, would otherwise be called by a migration's statement it matches
		// better than pg_catalog's, as format(text, name) does format(..., current_schema()), and run
		// as the role migrating. asOwner refuses another's in the schema itself. And pg_temp after it,
		// which PostgreSQL otherwise searches first for a relation or type: a table the session made
		// there, as rbac_migrations holding versions, would be read in place of the schema's.
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path', pg_catalog.quote_ident($1) || ', pg_temp', true)`, *schema); err != nil {
			return err
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
		if _, err := asOwner(ctx, tx, *schema, false); err != nil {
			return err
		}
		if !own {
			if err := historyUnwritten(ctx, tx, *schema); err != nil {
				return err
			}
		}
		// One migration at a time in the schema, under a lock named and keyed as the changes' are: by
		// the schema it migrates, as the tables may not exist yet, which is the one they are in once
		// they do.
		sql, args := advisory{kind: "migrate"}.taking(*schema)
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return fmt.Errorf("%w: %w", errReplica, err)
		}
		// The session reads the catalog changes the replica it waited for committed, as it reads any,
		// only once it takes a lock that isn't a relation's it already holds, which the advisory lock
		// isn't, and every catalog asOwner reads it locked before the wait: its cached schema would
		// still be the one from before, as where that replica gave the schema and the tables to another
		// role, which the cache then reads as having no USAGE on it, so a superuser's replica, setting
		// its role to that one, would find no current schema, and refuse it. Locking the schema as an
		// object, as CREATE in it does, reads them first, and keeps it from being dropped meanwhile.
		if _, err := tx.Exec(ctx, `SELECT FROM pg_catalog.pg_get_object_address('schema', ARRAY[$1::pg_catalog.text], '{}')`, *schema); err != nil {
			return err
		}
		restore, err := asOwner(ctx, tx, *schema, true)
		if err != nil {
			return err
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
			if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, milliseconds(migrateLockWait)); err != nil {
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
			if own && gaveWay {
				outwaitVacuum(ctx, tx, *schema)
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
		// As they were, for what a host's transaction runs after.
		if restore != nil {
			if err := restore(); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path', $1, true)`, path); err != nil {
			return err
		}
		if standard {
			return nil
		}
		_, err = tx.Exec(ctx, `SELECT set_config('standard_conforming_strings', $1, true)`, conforming)
		return err
	})
	return own, more, err
}
