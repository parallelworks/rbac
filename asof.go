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
// history records beside each of a table's rows, by the table's column each copies.
var asOfEntities = []struct {
	table, entity string
	columns       map[string]string
}{
	{"rbac_grants", "grant", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
	{"rbac_roles", "role", map[string]string{"tenant": "tenant", "id": "role"}},
	{"rbac_denies", "deny", map[string]string{"tenant": "tenant", "scope": "scope"}},
	{"rbac_eligibilities", "eligibility", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
	{"rbac_memberships", "membership", map[string]string{"tenant": "tenant", "principal": "principal"}},
	{"rbac_groups", "group", map[string]string{"tenant": "tenant", "id": "group_id"}},
	{"rbac_members", "member", map[string]string{"tenant": "tenant", "group_id": "group_id", "principal": "principal"}},
}

// AsOf runs read on an Authorizer that reads a tenant as it was at a time, from its history: who
// held what, who was in which group, what was denied, and what custom roles gave. Its checks,
// lists and searches answer as they would have then, with the catalog and the label dimensions as
// they are now, and find nothing in another tenant. A resource's label, as its path, is what the
// host passes: pass it as it was then. A change made on it is refused, as no actor's attempt, which
// Config.OnRefused isn't told of, and its reads see no change made since, but for History, which
// reads the whole record as it does outside. A change counts from when the statement that made it
// began, but never before its row's change before it, so what a time reads can still change until
// every transaction running then has ended.
// Hooks run as for any read, and a constraint that reads the package's tables through the DB it
// is given reads them as of the time too; one that reads the host's reads them as they are now.
// A Filter condition reads as of the time only in a query on the transaction read runs in: under
// WithTx, the host's, before read returns. It refuses a time earlier than any PruneHistory's
// before, since the prune removed versions such a time would read, and fails once read returns
// if such a prune committed while it ran.
//
// WithTx on the Authorizer read is given returns it as it is, reading the past on its own
// transaction.
//
// It reads in one transaction, or a savepoint of the host's under WithTx, in which temporary
// views named as the package's tables stand in for them, and rolls it back, even once ctx is
// done. It needs a transaction that may write, on a primary, as a role that may create temporary
// tables. A search_path that names pg_temp after the package's schema would read the tables as
// they are now, so AsOf refuses it. It orders a row's changes by their ids in rbac_history, which
// sessions take out of order once its id sequence caches more than one, so AsOf refuses that too.
func (a *Authorizer) AsOf(ctx context.Context, tenant string, at time.Time, read func(*Authorizer) error) (err error) {
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if a.asOf {
		return fmt.Errorf("%w: a read as of a time is read as of one time", ErrInvalid)
	}
	var tx pgx.Tx
	if conn, ok := a.db.(ownTx); ok {
		tx, err = conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	} else {
		tx, err = a.db.Begin(ctx)
	}
	if err != nil {
		return err
	}
	// Once ctx is done, a rollback on it isn't sent: a savepoint of the host's left standing keeps
	// the views in its transaction, which then reads the past, and in its session once it commits.
	defer func() {
		if rerr := tx.Rollback(context.WithoutCancel(ctx)); rerr != nil {
			err = errors.Join(err, rerr)
		}
	}()
	return a.readAsOf(ctx, tx, tenant, at, read)
}

// historySchema returns the schema tx reads history in, refusing it where history's ids can't
// order a row's changes.
func historySchema(ctx context.Context, tx pgx.Tx) (string, error) {
	var schema string
	if err := tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		return "", err
	}
	// A cached sequence hands each session a block of ids of its own, so a change made after
	// another can take the lower id.
	var ordered bool
	if err := tx.QueryRow(ctx, `SELECT s.seqcache = 1 FROM pg_catalog.pg_sequence s
		WHERE s.seqrelid = pg_catalog.pg_get_serial_sequence(pg_catalog.quote_ident($1) || '.rbac_history', 'id')::regclass`,
		schema).Scan(&ordered); err != nil {
		return "", err
	}
	if !ordered {
		return "", fmt.Errorf("%w: the sequence numbering %s.rbac_history caches ids, so they can't order a row's changes", ErrInvalid, schema)
	}
	return schema, nil
}

// readAsOf runs read on tx, with history standing in for the package's tables.
func (a *Authorizer) readAsOf(ctx context.Context, tx pgx.Tx, tenant string, at time.Time, read func(*Authorizer) error) error {
	schema, err := historySchema(ctx, tx)
	if err != nil {
		return err
	}
	if err := unpruned(ctx, tx, schema, at); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('rbac.as_of_tenant', $1, true), set_config('rbac.as_of', $2::timestamptz::text, true)`,
		tenant, at); err != nil {
		return err
	}
	// Each table as the last version of each of its rows dated at or before the time left it:
	// none where that was a delete or an expiry. A row's versions are written one at a time,
	// each after the last committed, so their ids order them, as their dates do only since none
	// is dated before the last: one dated by its transaction's start, as before, can have been
	// written after a version dated later. The view reads its tenant and time from settings of
	// the transaction, so no value is spliced into its definition. Each row's record is built
	// once, where `(f(x)).*` builds it once a column. A version is its row's last unless a later
	// one is dated by then, and gives the columns history copied beside it as its row's, so a
	// statement's condition on one, as a check's on its subject's principals, reads history by
	// its index for the rows it names, rather than every version of every row in the tenant.
	names := make([]string, len(asOfEntities))
	for i, e := range asOfEntities {
		names[i] = e.table
	}
	rows, err := tx.Query(ctx, `SELECT c.relname::text, array_agg(a.attname::text ORDER BY a.attnum)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
		WHERE c.relnamespace = (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = $1)
		  AND c.relname = ANY($2::text[]) AND a.attnum > 0 AND NOT a.attisdropped
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
			// A version recorded before the tables refused an infinite expiry reads as migrating
			// rewrote its row: a time.Time holds no infinity.
			if name == "expires_at" {
				selected[i] = `CASE r.expires_at WHEN 'infinity' THEN NULL WHEN '-infinity' THEN timestamptz 'epoch' ELSE r.expires_at END AS expires_at`
			}
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP VIEW %[2]s AS
			SELECT %[4]s FROM %[1]s.rbac_history h, LATERAL pg_catalog.jsonb_populate_record(NULL::%[1]s.%[2]s, h.after) r
			WHERE h.tenant = current_setting('rbac.as_of_tenant') AND h.entity = '%[3]s'
			  AND h.effective_at <= current_setting('rbac.as_of')::timestamptz AND h.op NOT IN ('delete', 'expire')
			  AND NOT EXISTS (SELECT FROM %[1]s.rbac_history n
			    WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key
			      AND n.effective_at <= current_setting('rbac.as_of')::timestamptz AND n.id > h.id)`,
			pgx.Identifier{schema}.Sanitize(), e.table, e.entity, strings.Join(selected, ", "))); err != nil {
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
	if err := tx.QueryRow(ctx, `SELECT 'rbac_grants'::regclass = 'pg_temp.rbac_grants'::regclass`).Scan(&shadowed); err != nil {
		return err
	}
	if !shadowed {
		return fmt.Errorf("%w: the search_path names pg_temp after %s, so history can't stand in for the package's tables", ErrInvalid, schema)
	}
	b := *a
	b.db, b.asOf = tx, true
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
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), savepointEnd)
	defer cancel()
	return unpruned(c, tx, schema, at)
}

// unpruned refuses at, on tx, once a prune has run past it: of each row a prune keeps only its
// last version as of the prune's time, which an earlier time would read as the row's version
// then, or as no row.
func unpruned(ctx context.Context, tx pgx.Tx, schema string, at time.Time) error {
	var pruned bool
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT coalesce($1::timestamptz < max((h.after->>'before')::timestamptz), false)
		FROM %s.rbac_history h WHERE h.tenant = '' AND h.entity = 'history' AND h.op = 'prune'`, pgx.Identifier{schema}.Sanitize()),
		at).Scan(&pruned); err != nil {
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
