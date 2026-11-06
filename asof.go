package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// asOfEntities are the tables history records, by the entity it records each as, and the columns
// history records beside each of a table's rows, by the table's column each copies. A role's id is
// its key, which history's index of an entity's versions seeks with its tenant: its role column is
// indexed beside every grant and eligibility of the role, and a plan that counts the tenant's
// roles as a few reads them all rather than seek that index. So are a membership's principal and a
// group's id: by its principal or group column, which history indexes beside the entity, a plan by
// statistics that count the tenant's memberships or groups as a few read every one of them by the
// entity to find one. A grant, an eligibility and a place in a group are read by columns other
// than their key, as their principal, and that index holds their versions only for a read that
// names their key, as history's index of scopes holds them only for one that names a scope: so by
// whichever of history's indexes leading to those columns a plan reads them, it seeks them.
var asOfEntities = []struct {
	table, entity string
	columns       map[string]string
}{
	{"rbac_grants", "grant", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
	{"rbac_roles", "role", map[string]string{"tenant": "tenant", "id": "key"}},
	{"rbac_denies", "deny", map[string]string{"tenant": "tenant", "scope": "scope"}},
	{"rbac_eligibilities", "eligibility", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
	{"rbac_memberships", "membership", map[string]string{"tenant": "tenant", "principal": "key"}},
	{"rbac_groups", "group", map[string]string{"tenant": "tenant", "id": "key"}},
	{"rbac_members", "member", map[string]string{"tenant": "tenant", "group_id": "group_id", "principal": "principal"}},
}

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
// It reads in one transaction, or a savepoint of the host's under WithTx, in which temporary
// views named as the package's tables stand in for them, and rolls it back, even once ctx is
// done. Every statement there is planned for its arguments, the host's under WithTx too, as
// plan_cache_mode force_custom_plan plans them, and without JIT, until the rollback restores both
// settings: planned so over history, a check or a host's query of a Filter condition costs past
// jit_above_cost for an ordinary subject, and compiling it took several times as long as running
// it. It needs a transaction that may write, on a primary, as a role that may create temporary
// tables. Making the views takes a transaction id, which AsOf's transaction holds until it rolls
// back, and under WithTx the host's until it ends: as any transaction holding one does, it holds
// History and Export back, in every database of the cluster, for as long as read runs. So keep
// read short, as an access review of many subjects reads them in several calls rather than one. A
// search_path that names pg_temp after the package's schema would read the tables as they are
// now, and one that names it first the session's own tables as history, so AsOf refuses both. It
// orders a row's changes by their ids in rbac_history, which sessions take out of order once its
// id sequence caches more than one, so AsOf refuses that too. It refuses a time before 4714 BC,
// the earliest PostgreSQL holds, or after 9999-12-30, the last the package stores.
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
	switch conn := a.db.(type) {
	case ownTx:
		tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	case pgx.Tx:
		tx, err = conn.Begin(ctx)
	default:
		tx, err = repeatableRead(ctx, conn)
	}
	if err != nil {
		return err
	}
	// Once ctx is done, a rollback on it isn't sent: a savepoint of the host's left standing keeps
	// the views in its transaction, which then reads the past, and in its session once it commits.
	defer func() {
		if rerr := finish(ctx, tx.Rollback); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}()
	return a.readAsOf(ctx, tx, tenant, at, read)
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

// asOfTime is the format AsOf writes its time in, and reads it back by, in rbac.as_of: TZH writes
// a timestamp without a time zone, as UTC's here, as +00.
const asOfTime = `YYYY-MM-DD HH24:MI:SS.US TZH BC`

// readAsOf runs read on tx, with history standing in for the package's tables.
func (a *Authorizer) readAsOf(ctx context.Context, tx pgx.Tx, tenant string, at time.Time, read func(*Authorizer) error) error {
	schema, err := historySchema(ctx, tx)
	if err != nil {
		return err
	}
	if err := unpruned(ctx, tx, schema, at); err != nil {
		return err
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
	// its time compiling.
	if _, err := tx.Exec(ctx, `SELECT set_config('rbac.as_of_tenant', $1, true),
		set_config('rbac.as_of', pg_catalog.to_char($2::pg_catalog.timestamptz `+inUTC+`, '`+asOfTime+`'), true),
		set_config('plan_cache_mode', 'force_custom_plan', true), set_config('jit', 'off', true)`,
		tenant, at); err != nil {
		return err
	}
	// Each table as the last version of each of its rows counted by the time left it: none where
	// that was a delete or an expiry. A version counts from its date, or its transaction's commit
	// record where that is later (counts), which is always but for a transaction that committed
	// before history kept them: no other session sees a change before it commits. A row's versions
	// are written one at a time, each after the last committed, so their ids order them, as their
	// dates do only since none is dated before the last: one dated by its transaction's start, as
	// before 0006, can have been written after a version dated later. The view reads its tenant and
	// time from settings of the transaction, so no value is spliced into its definition. Each row's
	// record is built once, where `(f(x)).*` builds it once a column. A version is its row's last
	// unless a later one counts by then, and gives the columns history copied beside it as its
	// row's, so a statement's condition on one, as a check's on its subject's principals, reads
	// history by its index for the rows it names, rather than every version of every row in the
	// tenant. Tested in a subquery the planner can't make a join of (later), each version reads
	// its row's later ones by their key in history's index of an entity's versions: a few pages for
	// each version, whatever their dates. As a join, planned by statistics from before most of
	// history was written, as autovacuum leaves them until a tenth of it is new, it read every version
	// of the entity in the tenant for each version it found, the key only a filter.
	names := make([]string, len(asOfEntities))
	for i, e := range asOfEntities {
		names[i] = e.table
	}
	rows, err := tx.Query(ctx, `SELECT c.relname::pg_catalog.text, array_agg(a.attname::pg_catalog.text ORDER BY a.attnum)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
		WHERE c.relnamespace = (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = $1)
		  AND c.relname = ANY($2::pg_catalog.text[]) AND a.attnum > 0 AND NOT a.attisdropped
		GROUP BY c.relname`, schema, names)
	if err != nil {
		return err
	}
	tables := map[string][]string{}
	var table string
	var columns []string
	if _, err := pgx.ForEachRow(rows, []any{&table, &columns}, func() error {
		tables[table] = slices.Clone(columns)
		return nil
	}); err != nil {
		return err
	}
	for _, e := range asOfEntities {
		selected := make([]string, len(tables[e.table]))
		for i, name := range tables[e.table] {
			selected[i] = "r." + pgx.Identifier{name}.Sanitize()
			if h, ok := e.columns[name]; ok {
				selected[i] = "h." + h + " AS " + pgx.Identifier{name}.Sanitize()
			}
			// The keys a deny names, by the expression history's index on them reads them by
			// (0015), so a list finds the denies naming its subject as it does now, by that index.
			if e.table == "rbac_denies" && name == "principals" {
				selected[i] = pgx.Identifier{schema}.Sanitize() + `.rbac_text_array(h.after -> 'principals') COLLATE "C" AS principals`
			}
			// A version recorded before the tables refused an infinite expiry reads as migrating
			// rewrote its row: a time.Time holds no infinity.
			if name == "expires_at" {
				selected[i] = `CASE r.expires_at WHEN 'infinity' THEN NULL WHEN '-infinity' THEN pg_catalog.timestamptz 'epoch' ELSE r.expires_at END AS expires_at`
			}
		}
		b := byTime{history: "%[1]s.rbac_history", at: "%[5]s"}
		view := `SELECT %[4]s FROM %[1]s.rbac_history h, LATERAL pg_catalog.jsonb_populate_record(NULL::%[1]s.%[2]s, h.after) r
			WHERE h.tenant = current_setting('rbac.as_of_tenant') AND h.entity = '%[3]s'
			  AND h.op NOT IN ('delete', 'expire') AND h.effective_at <= %[5]s
			  AND h.txid IS DISTINCT FROM pg_catalog.pg_current_xact_id_if_assigned()
			  AND CASE WHEN ` + b.later("h", "'%[3]s'") + ` IS NOT NULL THEN false
			    ELSE ` + b.byCommit("h", "NOT "+b.writtenLater("h", "'%[3]s'"), "c.at <= %[5]s") + ` END`
		// Roles are read by their ids, the key, or all at once, as Grantable reads them: their view
		// takes each one's newest version counted by then, which a condition on the key reaches
		// into, so each version is read once, where the test for a later one, joined to every
		// version of the tenant's roles, is planned generically by reading them all again for each.
		// One on another column, as a grant's principal, wouldn't reach in.
		if e.entity == "role" {
			view = `SELECT %[4]s FROM (SELECT DISTINCT ON (h.key) h.* FROM %[1]s.rbac_history h
			    WHERE h.tenant = current_setting('rbac.as_of_tenant') AND h.entity = '%[3]s' AND ` + b.counts("h") + `
			    ORDER BY h.key, h.id DESC) h, LATERAL pg_catalog.jsonb_populate_record(NULL::%[1]s.%[2]s, h.after) r
			WHERE h.op NOT IN ('delete', 'expire')`
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP VIEW %[2]s AS `+view,
			pgx.Identifier{schema}.Sanitize(), e.table, e.entity, strings.Join(selected, ", "),
			`pg_catalog.to_timestamp(current_setting('rbac.as_of'), '`+asOfTime+`')`)); err != nil {
			return err
		}
	}
	// A statement the session prepared earlier would still read the tables: PostgreSQL parses a
	// prepared statement again when the search_path or what it reads changes, and once the
	// session has its temporary schema, a view made there changes neither.
	if _, err := tx.Exec(ctx, `DISCARD PLANS`); err != nil {
		return err
	}
	// Unless the search_path names pg_temp after the package's schema, its tables' names are
	// the views'.
	var shadowed bool
	if err := tx.QueryRow(ctx, `SELECT 'rbac_grants'::pg_catalog.regclass = 'pg_temp.rbac_grants'::pg_catalog.regclass`).Scan(&shadowed); err != nil {
		return err
	}
	if !shadowed {
		return fmt.Errorf("%w: the search_path names pg_temp after %s, so history can't stand in for the package's tables", ErrInvalid, schema)
	}
	b := *a
	b.db, b.asOf, b.history = tx, true, historyTable(schema)
	b.cfg.Now = func() time.Time { return at }
	// A change is refused before its transaction, so the host is never asked about one that can't
	// be made.
	b.cfg.ValidateGrant = func(context.Context, DB, GrantInput) error { return b.writable() }
	if err := read(&b); err != nil {
		return err
	}
	// At READ COMMITTED, as a host's transaction under WithTx is, each of read's queries reads what
	// has committed by then, so one after a prune that committed since the check read what it
	// removed. Checked once ctx is done too, as read's answers stand only if this passes.
	return finish(ctx, func(c context.Context) error { return unpruned(c, tx, schema, at) })
}

// byTime is SQL for what a read as of a time tests history's versions by: history, its table, and
// at, the time.
type byTime struct{ history, at string }

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
// hasn't committed.
func (b byTime) committedBy(v string) string {
	return v + `.txid IS DISTINCT FROM pg_catalog.pg_current_xact_id_if_assigned()
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
	return `(SELECT CASE WHEN l.id > ` + h + `.id AND (l.txid = ` + h + `.txid OR ` + b.committedBy("l") + `) THEN l.id
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
		  AND n.effective_at <= ` + b.at + ` AND (n.txid = ` + h + `.txid OR ` + b.committedBy("n") + `)`
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
