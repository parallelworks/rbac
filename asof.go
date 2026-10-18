package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// asOfEntities are the tables history records, by the entity it records each as.
var asOfEntities = []struct{ table, entity string }{
	{"rbac_grants", "grant"},
	{"rbac_roles", "role"},
	{"rbac_denies", "deny"},
	{"rbac_eligibilities", "eligibility"},
	{"rbac_memberships", "membership"},
	{"rbac_groups", "group"},
	{"rbac_members", "member"},
}

// errAsOf is returned by a read that AsOf rolls back, which is how it ends.
var errAsOf = errors.New("rbac: as of")

// AsOf runs read on an Authorizer that reads a tenant as it was at a time, from its history: who
// held what, who was in which group, what was denied, and what custom roles gave. Its checks,
// lists and searches answer as they would have then, with the catalog as it is now, and find
// nothing in another tenant. A change made on it is refused, and its reads see no change made
// since, but for History, which reads the whole record as it does outside. A change counts from
// when its transaction began, so what a time reads can still change until every transaction that
// began before it has ended. Hooks run as for any read, and a constraint that reads the package's
// tables through the DB it is given reads them as of the time too; one that reads the host's
// reads them as they are now. A Filter condition reads as of the time only in a query on the
// transaction read runs in: under WithTx, the host's, before read returns.
//
// WithTx on the Authorizer read is given returns it as it is, reading the past on its own
// transaction.
//
// It reads in one transaction, or a savepoint of the host's under WithTx, in which temporary
// views named as the package's tables stand in for them, and rolls it back: it needs a
// transaction that may write, on a primary, as a role that may create temporary tables. A
// search_path that names pg_temp after the package's schema would read the tables as they are
// now, so AsOf refuses it.
func (a *Authorizer) AsOf(ctx context.Context, tenant string, at time.Time, read func(*Authorizer) error) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if a.asOf {
		return fmt.Errorf("%w: a read as of a time is read as of one time", ErrInvalid)
	}
	begin := func(fn func(pgx.Tx) error) error { return pgx.BeginFunc(ctx, a.db, fn) }
	if conn, ok := a.db.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	}); ok {
		begin = func(fn func(pgx.Tx) error) error {
			return pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, fn)
		}
	}
	err := begin(func(tx pgx.Tx) error {
		var schema string
		if err := tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('rbac.as_of_tenant', $1, true), set_config('rbac.as_of', $2::timestamptz::text, true)`,
			tenant, at); err != nil {
			return err
		}
		// Each table as the last version of each of its rows dated at or before the time left it:
		// none where that was a delete or an expiry. A row's versions are written one at a time,
		// each after the last committed, so their ids order them as their dates can't: a version
		// is dated by its transaction's start, and one that began first can write last. The view
		// reads its tenant and time from settings of the transaction, so no value is spliced into
		// its definition. Each row's record is built once, where `(f(x)).*` builds it once a column.
		for _, e := range asOfEntities {
			if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TEMP VIEW %[2]s AS
				SELECT r.* FROM (SELECT DISTINCT ON (h.key) h.op, h.after FROM %[1]s.rbac_history h
				      WHERE h.tenant = current_setting('rbac.as_of_tenant') AND h.entity = '%[3]s'
				        AND h.effective_at <= current_setting('rbac.as_of')::timestamptz
				      ORDER BY h.key, h.id DESC) v,
				  LATERAL pg_catalog.jsonb_populate_record(NULL::%[1]s.%[2]s, v.after) r
				WHERE v.op NOT IN ('delete', 'expire')`, pgx.Identifier{schema}.Sanitize(), e.table, e.entity)); err != nil {
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
		if err := read(&b); err != nil {
			return err
		}
		return errAsOf
	})
	if errors.Is(err, errAsOf) {
		return nil
	}
	return err
}

// writable refuses a change on an Authorizer AsOf gave, which reads the past.
func (a *Authorizer) writable() error {
	if a.asOf {
		return fmt.Errorf("%w: a read as of a time changes nothing", ErrInvalid)
	}
	return nil
}
