package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AsOf runs read on an Authorizer that reads a tenant as it was at a time, from its history: who
// held what, who was in which group, what was denied, and what custom roles gave. Its checks,
// lists and searches answer as they would have then, with the catalog and the label dimensions as
// they are now, and find nothing in another tenant. A resource's label, as its path, is what the
// host passes: pass it as it was then. A change made on it is refused, as no actor's attempt, which
// Config.OnRefused isn't told of, and its reads see no change made since, but for History, which
// reads the whole record as it does outside. A change counts from when its transaction committed,
// as history records it (Record.CommittedAt), as no other session sees it before, or from its own
// date (Record.EffectiveAt) where that is later; one of a transaction that committed before history
// recorded commits, or that a logical dump carried from another cluster whose commit records are
// gone, counts from its date, and one of the transaction AsOf reads in, which hasn't committed,
// counts by no time. A commit record dates only versions of the cluster that wrote it, so a restore
// into another cluster keeps its own commit dates and takes none from a colliding id. So what a
// time reads can still change until every transaction whose commit record is dated by then is one
// other sessions see: one waiting for synchronous replication, or prepared for two-phase commit, is
// not yet.
// Hooks run as for any read, but in its transaction, which holds one of the pool's connections
// until read returns: a constraint that reads the package's tables through the DB it is given reads
// them as of the time too, and one that reads the host's reads them as they are now. A hook that
// queries the pool, rather than the DB it is given, waits for another of its connections, which on
// a busy pool, or one of a single connection, may never come: under AsOf, hooks query what they are
// given.
// A Filter condition reads as of the time only in a query on the transaction read runs in: under
// WithTx, the host's, before read returns. It refuses a time earlier than the before of any
// PruneHistory that deleted records, as they can be versions such a time would read, and fails
// once read returns if such a prune committed while it ran.
//
// WithTx on the Authorizer read is given returns it as it is, reading the past on its own
// transaction.
//
// The Authorizer read is given runs every call on that one transaction, as WithTx's does, so it is
// for one goroutine at a time: for an access review in parallel, run several AsOf calls on a pool's
// Authorizer, each on its own goroutine. Make read's calls on it, not on the Authorizer AsOf was
// called on: one bound to a transaction, as WithTx's, runs in AsOf's savepoint until AsOf returns,
// and so reads the past, and one on a pool reads the tables as they are now.
//
// It reads in one transaction, or a savepoint of the host's under WithTx, which it makes READ ONLY
// and rolls back, even once ctx is done, with the schema of history's views that migrating makes
// beside the package's, named as it with _as_of after, first on the search_path: each view is
// named as the table it stands in for and reads history as of the time, so every statement there,
// the host's too, reads a table by its name as it was, and the current schema is the views'. As
// PostgreSQL cuts a name to 63 bytes, migrating makes them beside no schema named in more than 57,
// which it refuses, and AsOf, finding none there, says to rename it. Every statement there is
// planned for its arguments, the host's under WithTx too, as plan_cache_mode force_custom_plan
// plans them, and without JIT, until the rollback restores the settings: planned so over history,
// a check or a host's query of a Filter condition costs past jit_above_cost for an ordinary
// subject, and compiling it took several times as long as running it. It makes no object
// and takes no transaction id, so the role reading needs no TEMPORARY, only USAGE on the views'
// schema and SELECT on them, which it is refused without, and its read holds no History or Export
// back; under WithTx, a host's transaction that has taken one holds them back as it would anyway,
// as does a statement of read that writes a session's temporary table, which READ ONLY lets
// through. So it reads on a hot standby too, as of what the standby has replayed, where History
// fails. It drops the session's cached plans (DISCARD PLANS), under WithTx the host's too, which
// their statements plan again at their next run. The search_path it reads by names the views'
// schema, then pg_temp, then the session's, as one that doesn't name pg_temp reads a session's own
// tables first: one that names pg_temp after the package's schema would have them read before the
// package's, and one that names it first reads them as history, so AsOf refuses both. A function,
// operator or type in the views' schema is found before the package's and run as whoever reads, so
// it refuses that schema where it holds more than its owner's views, another role may create in it,
// or it isn't the role's that owns the package's tables. A statement looks each name up by the
// catalog as it is then, whatever its transaction's snapshot, so it checks that schema again once
// read returns: on its own transaction, once that has rolled back, as a query of the catalog there,
// at REPEATABLE READ, reads its snapshot, and under WithTx in the savepoint. A statement of read
// that sets the search_path, the role, or the settings the views read the tenant, the time and the
// cluster by, or another session revoking the role's USAGE on the views' schema, dropping one of
// the views or making something there, has the statements after it read another tenant or time, or
// the tables as they are now, or call what was made, so AsOf fails once read returns where one
// stays so: read's answers stand only where it returns nil. One made and undone within read it
// can't tell, and the package's statements run between the two read by it: a call read makes
// meanwhile, and those of a call after a hook of it that made it. So set them, or the role, in read
// or a hook only within a savepoint rolled back before the package's next statement. Nor can it
// tell what was made in the views' schema and dropped again as read ran, which only a role that may
// create there can make: its owner, the role that migrated, a member of it, a superuser, or one
// either let. And under WithTx in a host's transaction at REPEATABLE READ or SERIALIZABLE, whose
// queries read the catalog as of its first statement, both checks of that schema read past what was
// made there, or let another create there, since: read where that matters on a pool's Authorizer,
// or under WithTx at READ COMMITTED. It orders a row's changes by their ids in rbac_history, which
// sessions take out of order once its id sequence caches more than one, so AsOf refuses that too.
// It refuses a time before 4714 BC, the earliest PostgreSQL holds, or after 9999-12-30, the last
// the package stores.
func (a *Authorizer) AsOf(ctx context.Context, tenant string, at time.Time, read func(*Authorizer) error) (err error) {
	defer conflicting(&err)
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if a.asOf {
		return fmt.Errorf("%w: a read as of a time is read as of one time", ErrInvalid)
	}
	if read == nil {
		return fmt.Errorf("%w: a read as of a time has a read to run", ErrInvalid)
	}
	// The time is every statement's clock, which pgx would send from year 294,000 or so on as
	// another, one the read would answer as of, or one PostgreSQL refuses. It sends it to the
	// microsecond, rounded down, as the package stores a time, so the bounds are those of that.
	if s := stored(at); s.Before(earliest) || s.After(latest) {
		return fmt.Errorf("%w: a read as of a time is of one from 4714 BC to 9999-12-30", ErrInvalid)
	}
	var tx pgx.Tx
	host := false
	switch conn := a.db.(type) {
	case ownTx:
		tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	case pgx.Tx:
		host = true
		tx, err = conn.Begin(ctx)
	default:
		tx, err = repeatableRead(ctx, conn)
	}
	if err != nil {
		return err
	}
	// Once ctx is done, a rollback on it isn't sent: a savepoint of the host's left standing keeps
	// its settings in its transaction, which then reads the past, and can't write.
	var stood standIns
	defer func() {
		if rerr := finish(ctx, tx.Rollback); rerr != nil {
			err = errors.Join(err, rerr)
		} else if err == nil && !host && stood.views != "" {
			err = finish(ctx, func(c context.Context) error { return a.stoodBy(c, stood) })
		}
	}()
	stood, err = a.readAsOf(ctx, tx, tenant, at, read, host)
	return err
}

// stoodBy refuses, once AsOf's read on a transaction of its own has rolled back, the views it read
// by, as stand does, on the DB AsOf was called on: as it is, a pool or a connection, or in what its
// Begin begins, as a host's wrapper's can be a savepoint of the host's transaction, which a failure
// would otherwise abort. A statement of the read looked each name up by the catalog as it was then,
// but AsOf's own transaction is REPEATABLE READ, whose queries, of the catalog too, read the
// snapshot it took at its first: stand there would read past a function made in the views' schema
// since, which a statement after it called. Under WithTx stand reads in AsOf's savepoint
// (readAsOf), as here it would read on the host's transaction.
func (a *Authorizer) stoodBy(ctx context.Context, stood standIns) error {
	if _, own := a.db.(ownTx); own {
		return stood.stand(ctx, a.db)
	}
	return savepoint(ctx, a.db, func(tx pgx.Tx) error { return stood.stand(ctx, tx) })
}

// historySchema returns the schema tx reads history in, as packageSchema does, refusing it where
// history's ids can't order a row's changes.
func historySchema(ctx context.Context, tx pgx.Tx) (string, error) {
	schema, err := packageSchema(ctx, tx)
	if err != nil {
		return "", err
	}
	// A cached sequence hands each session a block of ids of its own, so a change made after
	// another can take the lower id.
	var ordered bool
	if err := tx.QueryRow(ctx, `SELECT s.seqcache = 1 FROM pg_catalog.pg_sequence s
		WHERE s.seqrelid = pg_catalog.pg_get_serial_sequence(pg_catalog.quote_ident($1) || '.rbac_history', 'id')::pg_catalog.regclass`,
		schema).Scan(&ordered); err != nil {
		return "", err
	}
	if !ordered {
		return "", fmt.Errorf("%w: the sequence numbering %s.rbac_history caches ids, so they can't order a row's changes", ErrInvalid, schema)
	}
	return schema, nil
}

// standIns are the views of history in schema that 0028_as_of_views makes, which AsOf's read finds
// the package's tables by: their schema, views, of oid id, and the name and oid of each view, one
// for each table.
type standIns struct {
	schema, views string
	id            uint32
	names         []string
	oids          []uint32
}

// planted is SQL for whether the schema n, an alias of pg_namespace, as that of AsOf's views,
// isn't the role's that owns the package's tables in the schema of oid here, SQL for it, lets
// another role create in it, or holds anything but views of its owner's, but for default
// privileges, which hold no object: a function, operator or type made there, as by a grant of
// CREATE or an extension installed there, would be called in place of the package's, as whoever
// reads. Every object in a schema, of whatever catalog, depends on it (pg_depend), but for a type
// made with another object, as a relation's row type or a type's array type, which depends on that.
func planted(n, here string) string {
	return `(` + n + `.nspowner IS DISTINCT FROM (SELECT t.relowner FROM pg_catalog.pg_class t
		    WHERE t.relnamespace = ` + here + ` AND t.relname = 'rbac_grants' AND t.relkind IN ('r', 'p'))
		  OR EXISTS (SELECT FROM pg_catalog.aclexplode(` + n + `.nspacl) a WHERE a.privilege_type = 'CREATE' AND a.grantee <> ` + n + `.nspowner)
		  OR EXISTS (SELECT FROM pg_catalog.pg_depend d
		    WHERE d.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND d.refobjid = ` + n + `.oid
		      AND d.classid <> 'pg_catalog.pg_default_acl'::pg_catalog.regclass
		      AND NOT EXISTS (SELECT FROM pg_catalog.pg_class c WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
		        AND c.oid = d.objid AND c.relkind = 'v' AND c.relowner = ` + n + `.nspowner)))`
}

// errPlanted is the error of AsOf refusing the schema views of the views of history in schema, as
// planted is true of it.
func errPlanted(views, schema string) error {
	return fmt.Errorf("%w: schema %s, of AsOf's views, holds more than its owner's views, isn't the role's that owns %s's tables, or lets another role create in it: what is made there is called in place of the package's", ErrInvalid, views, schema)
}

// asOfViews returns the views of history in schema, which it finds by what they read, whatever
// either schema is named, among the views of the role owning schema's tables outside every
// session's temporary schema, and the search_path q reads by: refusing them where they are of no
// one schema, where theirs holds no view of one of the package's tables, those of schema prefixed
// rbac_ but rbac_expired, which no read as of a time reads, as it would be read as it is now, or, as
// migrating does, where planted is true of it. A view of history that another session made in its
// temporary schema, as any role with TEMPORARY that reads history can, or another role's, would
// otherwise stand beside them, and have every read as of a time refused while it stood.
func asOfViews(ctx context.Context, q DB, schema string) (standIns, string, error) {
	s := standIns{schema: schema}
	var views, bare []string
	var path string
	var refused bool
	if err := q.QueryRow(ctx, `WITH here AS (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = $2),
		  v AS (
		  SELECT DISTINCT c.relnamespace AS oid FROM pg_catalog.pg_depend d
		  JOIN pg_catalog.pg_rewrite w ON w.oid = d.objid
		  JOIN pg_catalog.pg_class c ON c.oid = w.ev_class
		  WHERE d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
		    AND d.refobjid = $1::pg_catalog.text::pg_catalog.regclass AND c.relkind = 'v' AND c.relname = 'rbac_grants'
		    AND c.relowner = (SELECT t.relowner FROM pg_catalog.pg_class t
		      WHERE t.relnamespace = (SELECT here.oid FROM here) AND t.relname = 'rbac_grants' AND t.relkind IN ('r', 'p'))
		    AND NOT pg_catalog.pg_is_other_temp_schema(c.relnamespace) AND c.relnamespace <> pg_catalog.pg_my_temp_schema()),
		  tables AS (SELECT t.relname, c.oid AS view FROM pg_catalog.pg_class t
		    LEFT JOIN (pg_catalog.pg_class c JOIN v ON c.relnamespace = v.oid) ON c.relname = t.relname AND c.relkind = 'v'
		    WHERE t.relnamespace = (SELECT here.oid FROM here)
		      AND t.relkind IN ('r', 'p') AND pg_catalog.starts_with(t.relname, 'rbac_') AND t.relname NOT IN ('rbac_history', 'rbac_migrations', 'rbac_expired'))
		SELECT ARRAY(SELECT n.nspname::pg_catalog.text FROM v JOIN pg_catalog.pg_namespace n ON n.oid = v.oid ORDER BY 1),
		  coalesce((SELECT pg_catalog.min(v.oid) FROM v), 0),
		  ARRAY(SELECT t.relname::pg_catalog.text FROM tables t WHERE t.view IS NULL ORDER BY t.relname),
		  ARRAY(SELECT t.relname::pg_catalog.text FROM tables t WHERE t.view IS NOT NULL ORDER BY t.relname),
		  ARRAY(SELECT t.view FROM tables t WHERE t.view IS NOT NULL ORDER BY t.relname),
		  pg_catalog.current_setting('search_path'),
		  EXISTS (SELECT FROM v JOIN pg_catalog.pg_namespace n ON n.oid = v.oid WHERE `+planted("n", "(SELECT here.oid FROM here)")+`)`,
		historyTable(schema), schema).Scan(&views, &s.id, &bare, &s.names, &s.oids, &path, &refused); err != nil {
		return standIns{}, "", err
	}
	switch {
	case len(views) == 0:
		return standIns{}, "", noViews(ctx, q, schema)
	case len(views) > 1:
		return standIns{}, "", fmt.Errorf("%w: views of %s.rbac_history stand in schemas %s", ErrInvalid, schema, strings.Join(views, ", "))
	case len(bare) > 0:
		return standIns{}, "", fmt.Errorf("%w: schema %s holds no view of %s, which would be read as it is now", ErrInvalid, views[0], strings.Join(bare, ", "))
	case refused:
		return standIns{}, "", errPlanted(views[0], schema)
	}
	s.views = views[0]
	return s, path, nil
}

// maxAsOfSchema is the longest, in bytes, the package's schema is named where migrating makes AsOf's
// views beside it, in a schema named as it with _as_of after, as PostgreSQL cuts a name to 63 bytes.
const maxAsOfSchema = 63 - len("_as_of")

// noViews is the error of AsOf finding no views of history of the role owning schema's tables
// (asOfViews), read on q, which says what makes them: migrating to 0028_as_of_views as that role,
// which makes rbac_as_of_views and runs it, or where that is applied, running rbac_as_of_views as
// that role. That takes the function being that role's, and the views' schema being that role's
// and holding nothing else, which a migration as a superuser, before Migrate migrated as the
// tables' owner, left another's: a superuser then gives that role the function, and makes the
// schema again for it, empty, as one makes the schema where it is gone. And it takes no other
// views of history named as the package's tables standing anywhere, which rbac_as_of_views would
// take for the views and refuse: in a schema other than the views', one that can hold anything
// else, only those views are dropped. And it takes schema being named in at most maxAsOfSchema
// bytes, which rbac_as_of_views refuses otherwise, so the error says to rename it first: the
// schema it would have a superuser make or drop, cut to 63 bytes, is another, or schema itself.
func noViews(ctx context.Context, q DB, schema string) error {
	if len(schema) > maxAsOfSchema {
		return fmt.Errorf("%w: no views of history stand beside schema %s, whose name, of %d bytes, is too long for theirs, named as it with _as_of after, in at most 63: rename it to a name of at most %d bytes",
			ErrInvalid, schema, len(schema), maxAsOfSchema)
	}
	var owner, made, in, by string
	var standing bool
	if err := q.QueryRow(ctx, `WITH here AS (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = $2),
		  owner AS (SELECT t.relowner FROM pg_catalog.pg_class t
		    WHERE t.relnamespace = (SELECT here.oid FROM here) AND t.relname = 'rbac_grants' AND t.relkind IN ('r', 'p')),
		  v AS (
		  SELECT DISTINCT n.nspname::pg_catalog.text AS nspname, r.rolname::pg_catalog.text AS rolname FROM pg_catalog.pg_depend d
		  JOIN pg_catalog.pg_rewrite w ON w.oid = d.objid
		  JOIN pg_catalog.pg_class c ON c.oid = w.ev_class
		  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
		  WHERE d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
		    AND d.refobjid = $1::pg_catalog.text::pg_catalog.regclass AND c.relkind = 'v' AND c.relname = 'rbac_grants'
		    AND NOT pg_catalog.pg_is_other_temp_schema(c.relnamespace) AND c.relnamespace <> pg_catalog.pg_my_temp_schema())
		SELECT coalesce((SELECT r.rolname::pg_catalog.text FROM pg_catalog.pg_roles r WHERE r.oid = (SELECT owner.relowner FROM owner)), ''),
		  coalesce((SELECT r.rolname::pg_catalog.text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
		    WHERE p.pronamespace = (SELECT here.oid FROM here) AND p.proname = 'rbac_as_of_views' AND p.pronargs = 0), ''),
		  coalesce((SELECT v.nspname FROM v ORDER BY v.nspname, v.rolname LIMIT 1), ''), coalesce((SELECT v.rolname FROM v ORDER BY v.nspname, v.rolname LIMIT 1), ''),
		  pg_catalog.to_regnamespace(pg_catalog.quote_ident($2 || '_as_of')) IS NOT NULL`,
		historyTable(schema), schema).Scan(&owner, &made, &in, &by, &standing); err != nil {
		return err
	}
	if made == "" {
		return fmt.Errorf("%w: no views of history stand beside schema %s: migrate it to 0028_as_of_views as %s, the role owning its tables", ErrInvalid, schema, owner)
	}
	mine := schema + "_as_of"
	why := fmt.Sprintf("no views of history of %s, the role owning its tables, stand beside schema %s", owner, schema)
	switch in {
	case "":
	case mine:
		why = fmt.Sprintf("AsOf's views of history beside schema %s are %s's, and it reads only those of %s, the role owning its tables", schema, by, owner)
	default:
		why = fmt.Sprintf("views of history beside schema %s stand in schema %s, and are %s's, and AsOf reads only those of %s, the role owning its tables", schema, in, by, owner)
	}
	views, role := pgx.Identifier{mine}.Sanitize(), pgx.Identifier{owner}.Sanitize()
	run := fmt.Sprintf("as that role, with %s first on its search_path, SELECT rbac_as_of_views()", schema)
	switch {
	case made != owner || in != "":
		run = fmt.Sprintf("run DROP SCHEMA IF EXISTS %s CASCADE, CREATE SCHEMA %[1]s AUTHORIZATION %s and ALTER FUNCTION %[3]s.rbac_as_of_views() OWNER TO %[2]s, and then, %[4]s",
			views, role, pgx.Identifier{schema}.Sanitize(), run)
		if in != "" && in != mine {
			run = fmt.Sprintf("drop the views of history named as the package's tables in schema %s, %s", pgx.Identifier{in}.Sanitize(), run)
		}
		run = "as a superuser, " + run
	case !standing:
		run = fmt.Sprintf("as a superuser, run CREATE SCHEMA %s AUTHORIZATION %s, and then, %s", views, role, run)
	}
	return fmt.Errorf("%w: %s: %s", ErrInvalid, why, run)
}

// stand refuses, on q, the schema of the views s found, where planted is true of it by the catalog
// as q reads it now, or it is gone: what was made there since, or granted, a statement of the read
// that looked a name up since could have found. It reads the catalog as of q's snapshot, which in a
// transaction at REPEATABLE READ is that of its first statement, whereas a name is looked up by the
// catalog as it is (stoodBy). A view dropped, or the schema left off the search_path, kept refuses.
func (s standIns) stand(ctx context.Context, q DB) error {
	var refused bool
	if err := q.QueryRow(ctx, `SELECT coalesce((SELECT `+planted("n", "(SELECT h.oid FROM pg_catalog.pg_namespace h WHERE h.nspname = $2)")+`
		FROM pg_catalog.pg_namespace n WHERE n.oid = $1), true)`, s.id, s.schema).Scan(&refused); err != nil {
		return err
	}
	if refused {
		return errPlanted(s.views, s.schema)
	}
	return nil
}

// namesTemp reports whether the search_path setting names pg_temp, as PostgreSQL reads its names:
// one quoted as it is but for each "" in it, and one unquoted with its ASCII letters in lower case.
func namesTemp(setting string) bool {
	const space = " \t\n\r\v\f"
	for s := setting; ; {
		if s = strings.TrimLeft(s, ","+space); s == "" {
			return false
		}
		var name strings.Builder
		if s[0] == '"' {
			for s = s[1:]; s != ""; s = s[1:] {
				if s[0] == '"' {
					if s = s[1:]; s == "" || s[0] != '"' {
						break
					}
				}
				name.WriteByte(s[0])
			}
		} else {
			end := strings.IndexAny(s, ","+space)
			if end < 0 {
				end = len(s)
			}
			for _, c := range []byte(s[:end]) {
				if 'A' <= c && c <= 'Z' {
					c += 'a' - 'A'
				}
				name.WriteByte(c)
			}
			s = s[end:]
		}
		if name.String() == "pg_temp" {
			return true
		}
	}
}

// asOfTime is the format AsOf writes its time in, and its views read it back by, in rbac.as_of: TZH
// writes a timestamp without a time zone, as UTC's here, as +00.
const asOfTime = `YYYY-MM-DD HH24:MI:SS.US TZH BC`

// asOfSet is what AsOf set its read's transaction to read by: the views' settings and the
// search_path, as set_config returned them, and the views that stand in for the tables by it, the
// current schema being theirs.
type asOfSet struct {
	tenant, at, cluster, path string
	standIns
}

// kept refuses, on tx, what a statement of AsOf's read left set otherwise, or another session left
// otherwise since. The search_path alone doesn't keep the views first: a role without USAGE on
// their schema, as a SET ROLE can make the session's, or once another session revokes it, reads by
// it the tables as they are now, as it does one whose view is dropped. So each table's name is
// looked up as a statement of the read looks it up, by the catalog as it is, whatever tx's
// snapshot, and must name the view it named as the read began.
func (s asOfSet) kept(ctx context.Context, tx pgx.Tx) error {
	var kept bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('rbac.as_of_tenant') = $1 AND pg_catalog.current_setting('rbac.as_of') = $2
		AND pg_catalog.current_setting('rbac.as_of_cluster') = $3 AND pg_catalog.current_setting('search_path') = $4
		AND pg_catalog.current_schema() IS NOT DISTINCT FROM $5::pg_catalog.text
		AND NOT EXISTS (SELECT FROM ROWS FROM (pg_catalog.unnest($6::pg_catalog.text[]), pg_catalog.unnest($7::pg_catalog.oid[])) AS v(name, oid)
		  WHERE pg_catalog.to_regclass(pg_catalog.quote_ident(v.name))::pg_catalog.oid IS DISTINCT FROM v.oid)`,
		s.tenant, s.at, s.cluster, s.path, s.views, s.names, s.oids).Scan(&kept); err != nil {
		return err
	}
	if !kept {
		return fmt.Errorf("%w: a statement of the read set the search_path, the role, or what the views read the tenant, the time or the cluster by, or the role lost USAGE on the views' schema, or one of the views was dropped, so those after it read another tenant or time, or the tables as they are now", ErrInvalid)
	}
	return nil
}

// readAsOf runs read on tx, with history's views standing in for the package's tables, and returns
// those views. Under WithTx, host, tx is a savepoint of the host's transaction, on which it checks
// them again as read returns, as stoodBy does once a transaction of AsOf's own has rolled back.
func (a *Authorizer) readAsOf(ctx context.Context, tx pgx.Tx, tenant string, at time.Time, read func(*Authorizer) error, host bool) (standIns, error) {
	schema, err := historySchema(ctx, tx)
	if err != nil {
		return standIns{}, err
	}
	views, path, err := asOfViews(ctx, tx, schema)
	if err != nil {
		return standIns{}, err
	}
	if namesTemp(path) {
		return standIns{}, fmt.Errorf("%w: the search_path names pg_temp after %s, whose tables AsOf would read the session's own before", ErrInvalid, schema)
	}
	if err := unpruned(ctx, tx, schema, at); err != nil {
		return standIns{}, err
	}
	// Each statement is planned for its arguments until AsOf rolls back. A connection prepares a
	// statement once, as of a time and now alike, and from its sixth run can plan it generically,
	// costing history's indexes by an average tenant's few rows: a check would then read every
	// version of the tenant's custom roles again for each it read, and a list of a principal's
	// memberships every member's. The time is written in UTC, to the microsecond and with its era,
	// and read back by the format it was written in (asOfTime), not as a time's text, which each
	// statement reads by its own DateStyle and TimeZone, as a host's read can change them: a time's
	// text in the session's DateStyle can name its zone by an abbreviation, which another TimeZone,
	// or before PostgreSQL 18 timezone_abbreviations, reads as another zone's, hours off, and one of
	// another field order reads its month as its day. From PostgreSQL 18 a TimeZone's own
	// abbreviations name zones too, before any other, as UTC+5 makes UTC one five hours west, in
	// AT TIME ZONE 'UTC' as in a time's text, and <AD>-2 makes its era one: so UTC is an offset here
	// (inUTC), and the format reads the era as its own field. JIT is off: planned for their
	// arguments over history's views, statements cost past jit_above_cost though they read little,
	// and a host's query of a Filter condition for a subject of a few hundred grants spent most of
	// its time compiling. Read only, so no statement of read writes, or takes the transaction id a
	// write would, but to a session's temporary table, and none can set the transaction to write
	// again; under WithTx the savepoint's rollback leaves the host's as writable as it was. A
	// statement the session prepared earlier is parsed again, as PostgreSQL does once the
	// search_path it was parsed by changes, so it reads the views. The current schema is then the
	// views', unless the role has no USAGE on them, which the search_path leaves out, and the tables
	// would be read as they are now.
	// And the plans the session's statements took in an earlier read are dropped (DISCARD PLANS),
	// as that read's search_path was this one's: a generic plan a host's read forced there, made for
	// its time and tenant and by the settings of the call that first ran it, would stand, so the
	// pages of history a search read turned on which reads its connection had run before.
	set := asOfSet{standIns: views}
	var current string
	if err := tx.QueryRow(ctx, `SELECT set_config('rbac.as_of_tenant', $1, true),
		set_config('rbac.as_of', pg_catalog.to_char($2::pg_catalog.timestamptz `+inUTC+`, '`+asOfTime+`'), true),
		set_config('rbac.as_of_cluster', (pg_catalog.pg_control_system()).system_identifier::pg_catalog.text, true),
		set_config('plan_cache_mode', 'force_custom_plan', true), set_config('jit', 'off', true),
		set_config('transaction_read_only', 'on', true),
		set_config('search_path', pg_catalog.quote_ident($3) || ', pg_temp, ' || pg_catalog.current_setting('search_path'), true),
		pg_catalog.current_schema()`,
		tenant, at, views.views).Scan(&set.tenant, &set.at, &set.cluster, nil, nil, nil, &set.path, &current); err != nil {
		return standIns{}, err
	}
	if current != views.views {
		return standIns{}, fmt.Errorf("%w: the role has no USAGE on schema %s, so its views can't stand in for the package's tables", ErrInvalid, views.views)
	}
	if _, err := tx.Exec(ctx, `DISCARD PLANS`); err != nil {
		return standIns{}, err
	}
	b := *a
	b.db, b.asOf, b.history, b.schema = tx, true, historyTable(schema), schema
	b.cfg.Now = func() time.Time { return at }
	// A change is refused before its transaction, so the host is never asked about one that can't
	// be made.
	b.cfg.ValidateGrant = func(context.Context, DB, GrantInput) error { return b.writable() }
	if err := read(&b); err != nil {
		return standIns{}, err
	}
	// At READ COMMITTED, as a host's transaction under WithTx is, each of read's queries reads what
	// has committed by then, so one after a prune that committed since the check read what it
	// removed, and one after a function was made in the views' schema called it, as each looks a
	// name up by the catalog as it is. Checked once ctx is done too, as read's answers stand only if
	// this passes: the views' schema under WithTx here, in the savepoint, as a query failing on the
	// host's transaction once it has rolled back would abort that, and on AsOf's own transaction
	// once it has rolled back (stoodBy).
	return views, finish(ctx, func(c context.Context) error {
		if err := set.kept(c, tx); err != nil {
			return err
		}
		if host {
			if err := views.stand(c, tx); err != nil {
				return err
			}
		}
		return unpruned(c, tx, schema, at)
	})
}

// byTime is SQL for what a read as of a time tests history's versions by: history, its table; at,
// the time; and cluster, the identifier of the cluster reading it (system_identifier).
type byTime struct{ history, at, cluster string }

// counts is SQL for whether v, the alias of a version in history, counts by the time: from its
// date, or where it is later, its transaction's commit (committedBy).
func (b byTime) counts(v string) string {
	return v + `.effective_at <= ` + b.at + ` AND ` + b.committedBy(v)
}

// committedBy is SQL for whether the transaction that wrote v, the alias of a version in history,
// had committed by the time: no other session sees a change before its transaction commits. It
// does as its latest commit record says, which it looks up by its transaction in history's index
// of them, a few pages, as History reads each record's CommittedAt, so what a time reads turns on
// nothing History doesn't return: a bound on the transactions every commit record held as running
// would count, unlooked up, any change of one older as committed, and an inserted commit record
// with a bound past them all, which no export holds, would count a revoke held open as in force.
// The commit record must be of v's own cluster, so a restored version counts from its own
// cluster's commit, not from a transaction the new cluster gave the same txid. One that committed
// before history recorded commits, or that a restore carried from a cluster whose commit records
// are gone, counts as committed, as its versions count from their dates; the transaction reading v
// hasn't committed (byAnother).
func (b byTime) committedBy(v string) string {
	return b.byAnother(v) + `
		AND coalesce((SELECT max(c.effective_at) FROM ` + b.history + ` c WHERE c.entity = 'commit' AND c.txid = ` + v + `.txid
		    AND c.cluster IS NOT DISTINCT FROM ` + v + `.cluster),
		  ` + v + `.effective_at) <= ` + b.at
}

// later is SQL selecting a version of h's row written after h, h the alias of a version in
// history of entity, SQL for its entity, that counts by the time, or that h's own transaction
// wrote dated by then: their commit is the same, so where it hasn't counted, h hasn't either, and
// h isn't its row's last by then in either case. Since history records commits, a row's versions
// are dated in the order they were written, as none is dated before the one before it, so it reads
// the row's latest version dated by then that follows h in history's index of an entity's
// versions, which orders those of one date by id, and selects it where it counts. Only where it
// doesn't, as its transaction committed after then, does it read on from h in that index until the
// first it selects: each version between two counted is read once, whatever their dates. Read on
// from h alone, against the index's order, h its row's last read the page before h's, of another
// row, wherever h was first on its page. Ordered by date alone, as that index was, versions dated
// alike, as every write of a DO block is, read in the order of their places, oldest first, so each
// read every one before it.
func (b byTime) later(h, entity string) string {
	return `(SELECT CASE WHEN l.id > ` + h + `.id AND (` + sameTransaction("l", h) + ` OR ` + b.committedBy("l") + `) THEN l.id
		  ELSE (SELECT n.id FROM ` + b.history + ` n WHERE ` + b.laterOf(h, entity) + `
		    AND (n.effective_at, n.id) > (` + h + `.effective_at, ` + h + `.id)
		  ORDER BY n.effective_at, n.id LIMIT 1) END
		FROM (SELECT n.id, n.txid, n.effective_at, n.cluster FROM ` + b.history + ` n
		  WHERE n.tenant = ` + h + `.tenant AND n.entity = ` + entity + ` AND n.key = ` + h + `.key AND n.effective_at <= ` + b.at + `
		    AND (n.effective_at, n.id) > (` + h + `.effective_at, ` + h + `.id)
		  ORDER BY n.effective_at DESC, n.id DESC LIMIT 1) l)`
}

// writtenLater is SQL for whether a version of h's row written after h counts by the time, or h's
// own transaction wrote one dated by then, as later selects, for a version h of a transaction that
// committed before history recorded commits: by a release before 0006, it can be dated before a
// version written earlier, so it reads the row's versions dated by then from the latest, which
// history's index of an entity's versions gives first, until one written after h.
func (b byTime) writtenLater(h, entity string) string {
	return `EXISTS (SELECT FROM ` + b.history + ` n WHERE ` + b.laterOf(h, entity) + `)`
}

// laterOf is SQL for whether n is a version of h's row written after h that counts by the time or
// that h's own transaction wrote dated by then, as later and writtenLater select.
func (b byTime) laterOf(h, entity string) string {
	return `n.tenant = ` + h + `.tenant AND n.entity = ` + entity + ` AND n.key = ` + h + `.key AND n.id > ` + h + `.id
		  AND n.effective_at <= ` + b.at + ` AND (` + sameTransaction("n", h) + ` OR ` + b.committedBy("n") + `)`
}

// byAnother is SQL for whether v, the alias of a version in history, was written by a transaction
// other than the one reading it, which hasn't committed: a version a restore carried from another
// cluster, of a txid this cluster has since given the reading transaction, is another's.
func (b byTime) byAnother(v string) string {
	return `(` + v + `.txid, ` + v + `.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), ` + b.cluster + `)`
}

// sameTransaction is SQL for whether versions v and w, aliases in history, were written by one
// transaction: of one txid in one cluster, as a txid a restore carried from another cluster can be
// one this cluster has since given a transaction of its own.
func sameTransaction(v, w string) string {
	return `(` + v + `.txid = ` + w + `.txid AND ` + v + `.cluster IS NOT DISTINCT FROM ` + w + `.cluster)`
}

// byCommit is SQL for, as h's transaction's latest commit record of h's own cluster is looked up
// once, in history, dated where it committed before history recorded commits, or where a restore
// carried h from a cluster whose commit records are gone, and committed, SQL in which c.at is when
// it committed, where it records commits.
func (b byTime) byCommit(h, dated, committed string) string {
	return `(SELECT CASE WHEN c.at IS NULL THEN ` + dated + ` ELSE ` + committed + ` END
		FROM (SELECT max(c.effective_at) AS at FROM ` + b.history + ` c WHERE c.entity = 'commit' AND c.txid = ` + h + `.txid
		  AND c.cluster IS NOT DISTINCT FROM ` + h + `.cluster) c)`
}

// unpruned refuses at, on tx, once a prune has run past it: of each row a prune keeps only its
// last version as of the prune's time, which an earlier time would read as the row's version
// then, or as no row. Of the prunes' times, the last is that of the last record by key, which
// holds its prune's time as text that sorts as time, so history's index finds it alone: no
// prune's record is removed, and every AsOf would otherwise read them all, twice. With sorting off,
// as no other index gives that order: where history's statistics hold no prune, the planner would
// read them all by history's index of prunes to sort them, as History would (prunedPast).
func unpruned(ctx context.Context, tx pgx.Tx, schema string, at time.Time) error {
	restore, err := planning(ctx, tx, unsorted)
	if err != nil {
		return err
	}
	var pruned bool
	if err := tx.QueryRow(ctx, `SELECT coalesce($1::pg_catalog.timestamptz < (SELECT (h.after->>'before')::pg_catalog.timestamptz
		FROM `+historyTable(schema)+` h WHERE h.tenant = '' AND h.entity = 'history' AND h.op = 'prune' ORDER BY h.key DESC LIMIT 1), false)`,
		at).Scan(&pruned); err != nil {
		return err
	}
	if err := restore(); err != nil {
		return err
	}
	if pruned {
		return fmt.Errorf("%w: history was pruned past the time, so it can't be read as of then", ErrInvalid)
	}
	return nil
}

// writable refuses a change on an Authorizer AsOf gave, which reads the past.
func (a *Authorizer) writable() error {
	if a.asOf {
		return fmt.Errorf("%w: a read as of a time changes nothing", ErrInvalid)
	}
	return nil
}
