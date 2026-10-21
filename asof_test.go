package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// dbNow is the database's clock, which history dates changes by.
func dbNow(t *testing.T, h *harness) time.Time {
	t.Helper()
	var now time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

func TestAsOfReadsATenantAsItWas(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	u, v := h.as(t, "u", "sre"), h.as(t, "v")
	h.groups(t, "sre")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"))
	// x's login expires between the two times. Then is when its grant's statement began, which
	// history dates the grant by, and its expiry is set from that same instant, so however slow the
	// machine, then is before it.
	x := h.as(t, "x")
	var then, expires time.Time
	if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', statement_timestamp() + interval '200 milliseconds')
		RETURNING statement_timestamp(), expires_at`).Scan(&then, &expires); err != nil {
		t.Fatal(err)
	}
	// Since: u left sre, a deny took login from u, and v was granted login.
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_members WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "v"))
	// Until x's login expires by the database's clock, which dates it, not this machine's.
	if _, err := h.pool.Exec(ctx, `SELECT pg_sleep(extract(epoch FROM $1 - clock_timestamp()))`, expires); err != nil {
		t.Fatal(err)
	}
	now := dbNow(t, h)
	for _, c := range []struct {
		name        string
		at          time.Time
		uRoot       bool
		uLogin      bool
		vLogin      bool
		xLogin      bool
		loginHeldBy []rbac.Principal
	}{
		{"then", then, true, true, false, true, []rbac.Principal{u.Principal, x.Principal}},
		{"now", now, false, false, true, false, []rbac.Principal{v.Principal}},
	} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for _, check := range []struct {
				s    rbac.Subject
				p    rbac.Permission
				want bool
			}{{u, root, c.uRoot}, {u, login, c.uLogin}, {v, login, c.vLogin}, {x, login, c.xLogin}} {
				err := a.Authorize(ctx, check.s, check.p, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != check.want {
					t.Errorf("%s: Authorize(%s, %s) = %v", c.name, check.s.Principal.ID, check.p, err)
				}
			}
			d, err := a.Explain(ctx, u, login, cluster)
			if err != nil || d.Allowed != c.uLogin || (d.DeniedBy != "") == c.uLogin {
				t.Errorf("%s: Explain = %+v, %v", c.name, d, err)
			}
			holders, err := a.Holders(ctx, login, cluster)
			if err != nil || !slices.Equal(holderPrincipals(holders), c.loginHeldBy) {
				t.Errorf("%s: Holders = %+v, %v", c.name, holders, err)
			}
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
}

func TestAsOfChangesNothing(t *testing.T) {
	asked := 0
	h := setup(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked++
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "later"))
	asked = 0
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if err := a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply as of a time: %v", err)
		}
		if asked != 0 {
			t.Errorf("the host was asked about a change as of a time %d times", asked)
		}
		if _, err := a.DeleteExpired(ctx); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteExpired as of a time: %v", err)
		}
		// On another transaction it still reads the past, not the grant made since.
		other, err := h.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = other.Rollback(ctx) }()
		if got, err := a.WithTx(other).Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "later"}}}); err != nil || len(got) != 0 {
			t.Errorf("Grants on another transaction = %+v, %v", got, err)
		}
		if err := a.AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf as of a time: %v", err)
		}
		// History is a read, which changes nothing.
		if _, _, err := a.History(ctx, rbac.Cursor{}, 1); err != nil {
			t.Errorf("History as of a time: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
	if err := h.authz.AsOf(ctx, "", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("AsOf with no tenant: %v", err)
	}
}

// AsOf on a host's DB that has no BeginTx reads the past at REPEATABLE READ, as on a pool, so a
// read of several statements reads one snapshot; on a wrapper around the host's transaction, at
// that transaction's isolation, as under WithTx.
func TestAsOfOnAWrapperReadsOneSnapshot(t *testing.T) {
	var level string
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "level", Deny: func(ctx context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			return false, q.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level)
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, c := range []struct {
		name string
		db   rbac.DB
		want string
	}{{"a pool", h.pool, "repeatable read"}, {"the host's transaction", tx, "read committed"}} {
		a, err := rbac.New(struct{ rbac.DB }{c.db}, h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		level = ""
		if err := a.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, owner, login, cluster) }); err != nil {
			t.Fatalf("on a wrapper around %s: %v", c.name, err)
		}
		if level != c.want {
			t.Errorf("on a wrapper around %s, AsOf read at %q, not %q", c.name, level, c.want)
		}
	}
}

func TestAsOfLeavesTheHostsTransactionAsItWas(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL plan_cache_mode = force_generic_plan`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		_, err := a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The views are gone with its savepoint, and the host plans as it did: the host's transaction
	// reads the tables again.
	var name, plans string
	if err := tx.QueryRow(ctx, `SELECT 'rbac_grants'::regclass::text, current_setting('plan_cache_mode')`).Scan(&name, &plans); err != nil ||
		name != "rbac_grants" || plans != "force_generic_plan" {
		t.Fatalf("rbac_grants is %q, plan_cache_mode %q, %v", name, plans, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
}

func TestAsOfRefusesASearchPathThatReadsTheTablesFirst(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('search_path', current_schema() || ', pg_temp', true)`); err != nil {
			return err
		}
		err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil })
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf with pg_temp after the package's schema: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// AsOf and a prune, which keeps each row's last version by its id, refuse ids a cache can take out
// of order.
func TestAsOfRefusesCachedHistoryIds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := exported(t, h)
	if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_history ALTER COLUMN id SET CACHE 2`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf with history's ids cached: %v", err)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("PruneHistory with history's ids cached: %v", err)
	}
}

func TestAsOfRollsBackOnceItsContextIsDone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The read ends as its context does, before AsOf rolls back its savepoint.
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := h.authz.WithTx(tx).AsOf(readCtx, "t1", at, func(*rbac.Authorizer) error {
		cancel()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.WithTx(tx).Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != 0 {
		t.Errorf("after AsOf, the host's transaction reads u's grants as %+v, %v", got, err)
	}
}

// stalled is a pool whose transactions' rollbacks wait until their context is done, or the
// test's, as on a connection that has stopped answering.
type stalled struct {
	*pgxpool.Pool
	test context.Context
}

func (s stalled) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := s.Pool.BeginTx(ctx, opts)
	return stalledTx{tx, s.test}, err
}

type stalledTx struct {
	pgx.Tx
	test context.Context
}

func (s stalledTx) Rollback(ctx context.Context) error {
	select {
	case <-ctx.Done():
	case <-s.test.Done():
	}
	_ = s.Tx.Rollback(context.WithoutCancel(ctx))
	return ctx.Err()
}

// AsOf's rollback is bounded, as a savepoint's end is, so a connection that stops answering fails
// it rather than holding it for good.
func TestAsOfEndsOnAConnectionThatStopsAnswering(t *testing.T) {
	rbac.SetSavepointEnd(t, 100*time.Millisecond)
	h := setup(t)
	authz, err := rbac.New(stalled{h.pool, t.Context()}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := dbNow(t, h)
	done := make(chan error, 1)
	go func() { done <- authz.AsOf(t.Context(), "t1", at, func(*rbac.Authorizer) error { return nil }) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("AsOf on a connection that stops answering: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AsOf waited for good on a rollback its connection never answers")
	}
}

func TestAsOfRebuildsEveryTableAsItIs(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.as(t, "u", "sre")
	h.as(t, "v", "devs")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(workspace.Scope(), "cluster.login", rbac.Group, "devs"))
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at, condition, note)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.login', now() + interval '1 day', 'request.time > timestamp("2020-01-01T00:00:00Z")', 'n')`,
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', 'custom.x', '{cluster:view}', '{cluster}', '{cluster.login}')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.sudo', 3600, '{user:u}')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, expires_at) VALUES ('t1', 'devs', 'group', 'sre', 'sync', now() + interval '1 hour')`,
		`UPDATE rbac_memberships SET suspended = true, note = 'x' WHERE principal = 'user:v'`,
		`DELETE FROM rbac_grants WHERE principal = 'user:u'`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t2', 'user', 'u')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t2', 'cluster', 'c1', 'user', 'u', 'cluster.login')`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.User, ID: "v"}}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	rebuilt(t, h, dbNow(t, h))
}

// rebuilt checks that AsOf as of at reads each of the package's tables as t1's rows of it are now.
func rebuilt(t *testing.T, h *harness, at time.Time) {
	t.Helper()
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT quote_ident(current_schema()), relname::text FROM pg_class
		WHERE relnamespace = current_schema()::regnamespace AND relkind = 'r' AND relname NOT IN ('rbac_history', 'rbac_migrations') ORDER BY 2`)
	if err != nil {
		t.Fatal(err)
	}
	type table struct{ Schema, Name string }
	tables, err := pgx.CollectRows(rows, pgx.RowToStructByPos[table])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error {
		for _, tb := range tables {
			// The tenant's rows, each whole, generated columns included, in columns of the table's
			// names, types and collations, in its order.
			var missing, extra, columns int
			if err := tx.QueryRow(ctx, `SELECT
				  (SELECT count(*) FROM (SELECT * FROM `+tb.Schema+`.`+tb.Name+` WHERE tenant = 't1' EXCEPT ALL SELECT * FROM `+tb.Name+`) x),
				  (SELECT count(*) FROM (SELECT * FROM `+tb.Name+` EXCEPT ALL SELECT * FROM `+tb.Schema+`.`+tb.Name+` WHERE tenant = 't1') x),
				  (SELECT count(*) FROM (
				    SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
				    EXCEPT SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = to_regclass('pg_temp.' || $2)) x)`,
				tb.Schema+"."+tb.Name, tb.Name).Scan(&missing, &extra, &columns); err != nil {
				return err
			}
			if missing != 0 || extra != 0 || columns != 0 {
				t.Errorf("%s as of %v: %d rows missing, %d extra, %d columns differ", tb.Name, at, missing, extra, columns)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAsOfOrdersARowsChangesAsTheyWereMade(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "m")
	// Each transaction begins before another's change, which it then undoes: one revokes a grant
	// made after it began, and one makes again a membership ended after it began.
	var txs []pgx.Tx
	for range 2 {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		txs = append(txs, tx)
	}
	revoke, rejoin := txs[0], txs[1]
	var id string
	if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'w', 'cluster.login') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := revoke.Exec(ctx, `DELETE FROM rbac_grants WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_memberships WHERE principal = 'user:m'`); err != nil {
		t.Fatal(err)
	}
	if _, err := rejoin.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'm')`); err != nil {
		t.Fatal(err)
	}
	for _, tx := range txs {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "w"}}})
		if err != nil || len(grants) != 0 {
			t.Errorf("as of now, w holds %+v, %v", grants, err)
		}
		ms, err := a.Memberships(ctx, "t1", []rbac.Principal{{Kind: rbac.User, ID: "m"}})
		if err != nil || len(ms) != 1 {
			t.Errorf("as of now, m's memberships are %+v, %v", ms, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A change counts from its statement, not its transaction's start: a revoke made in a host's
// transaction that began before the grant counts from after it, so the grant was held between.
func TestAsOfReadsARevokeInAnOlderTransactionAfterItsGrant(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), rbac.Principal{Kind: rbac.User, ID: "u"}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	h.seed(t, grant(cluster.Scope(), "cluster.login", u.Kind, u.ID))
	time.Sleep(20 * time.Millisecond)
	between := dbNow(t, h)
	time.Sleep(20 * time.Millisecond)
	if err := h.authz.WithTx(tx).Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u}}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]int{between: 1, dbNow(t, h): 0} {
		if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u}})
			if err == nil && len(grants) != want {
				t.Errorf("as of %v, u holds %+v, want %d", at, grants, want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// RecordedAt is when each was written: the revoke's after the grant's.
	rows, err := h.pool.Query(ctx, `SELECT recorded_at FROM rbac_history WHERE principal = 'user:u' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	written, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil || len(written) != 2 || !written[0].Before(written[1]) {
		t.Fatalf("written at %v, %v", written, err)
	}
}

// A statement reads a row by the columns history copies beside its versions, but only its last
// version counts: a grant moved to another principal and scope, in place, as by hand, is the new
// one's from then on, not the old one's too.
func TestAsOfReadsARowChangedInPlaceAsItsLastVersion(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, v := h.as(t, "u"), h.as(t, "v")
	h.seed(t, grant(workspace.Scope(), "cluster.login", rbac.User, "u"))
	before := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET principal_id = 'v', scope_type = 'cluster', scope_id = 'c1'
		WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	after := dbNow(t, h)
	for _, c := range []struct {
		at               time.Time
		holder, other    rbac.Subject
		scope, elsewhere rbac.Scope
	}{{before, u, v, workspace.Scope(), cluster.Scope()}, {after, v, u, cluster.Scope(), workspace.Scope()}} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for _, f := range []struct {
				filter rbac.GrantFilter
				held   bool
			}{
				{rbac.GrantFilter{Principals: []rbac.Principal{c.holder.Principal}}, true},
				{rbac.GrantFilter{Principals: []rbac.Principal{c.other.Principal}}, false},
				{rbac.GrantFilter{Scopes: []rbac.Scope{c.scope}}, true},
				{rbac.GrantFilter{Scopes: []rbac.Scope{c.elsewhere}}, false},
			} {
				grants, err := a.Grants(ctx, "t1", f.filter)
				if err != nil {
					return err
				}
				if held := slices.ContainsFunc(grants, func(g rbac.Grant) bool { return g.Role == "cluster.login" }); held != f.held {
					t.Errorf("as of %v, Grants(%+v) = %+v", c.at, f.filter, grants)
				}
			}
			for _, s := range []rbac.Subject{c.holder, c.other} {
				err := a.Authorize(ctx, s, login, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != (s.Principal == c.holder.Principal) {
					t.Errorf("as of %v, Authorize(%s) = %v", c.at, s.Principal.ID, err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// A check as of a time reads the history of its subject's grants, memberships and groups, not
// every row's, and of a conditional grant it holds, for its condition: other principals' history
// costs it nothing.
func TestAsOfReadsOnlyTheRowsAStatementNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, w := h.as(t, "u", "sre"), h.as(t, "w")
	conditional := grant(cluster.Scope(), "cluster.login", rbac.User, "w")
	conditional.Condition = rbac.Condition{Title: "t", Expression: `action == "cluster:login"`}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"), conditional)
	// Other principals' grants on the cluster, each changed once since.
	others := func(n int) {
		t.Helper()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', 'c1', 'user', 'other-' || gen_random_uuid(), 'cluster.login' FROM generate_series(1, $1)`, []any{n}},
			{`UPDATE rbac_grants SET note = 'changed' WHERE principal LIKE 'user:other-%' AND note = ''`, nil},
			{`ANALYZE rbac_history`, nil},
		} {
			if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The pages of history and its indexes a check reads, as of at.
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			if err := a.Authorize(ctx, u, root, cluster); err != nil {
				return err
			}
			err := a.Authorize(ctx, w, login, cluster)
			read = historyPages(ctx, t, tx) - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	// Each time as deep in history's indexes, so a check reads as many pages unless it reads
	// other principals' history.
	others(500)
	few := read(dbNow(t, h))
	others(2000)
	if many := read(dbNow(t, h)); many > few {
		t.Fatalf("a check as of a time read %d pages of history, and %d once 2000 more principals had grants", few, many)
	}
}

// As of a time, a group's members and the denies on a resource's path are read by the rows they
// name too: other groups' members and denies on other scopes cost about nothing.
func TestAsOfReadsAGroupsMembersAndAScopesDeniesAlone(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	u := h.as(t, "u", "sre")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"))
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	h.groups(t, "other")
	// Members of another group and denies on other clusters, each changed once since.
	others := func(n int) {
		t.Helper()
		for _, q := range []string{
			`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'other', 'user', gen_random_uuid()::text FROM generate_series(1, $1)`,
			`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'd', '{user:u}', '{cluster:sudo}' FROM generate_series(1, $1)`,
			`UPDATE rbac_members SET note = 'changed' WHERE group_id = 'other' AND note = ''`,
			`UPDATE rbac_denies SET name = 'changed' WHERE scope_id <> 'c1' AND name = ''`,
			`ANALYZE rbac_history`,
		} {
			var args []any
			if strings.Contains(q, "$1") {
				args = []any{n}
			}
			if _, err := h.pool.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			members, err := a.Members(ctx, "t1", "sre")
			if err != nil || len(members) != 1 {
				return fmt.Errorf("members of sre: %v, %w", members, err)
			}
			if err := a.Authorize(ctx, u, root, cluster); !errors.Is(err, rbac.ErrDenied) {
				return fmt.Errorf("the deny: %w", err)
			}
			read = historyPages(ctx, t, tx) - start
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	// Their longer keys deepen history's indexes, which each lookup reads a page more of.
	others(500)
	few := read(dbNow(t, h))
	others(2000)
	if many := read(dbNow(t, h)); many > few*3/2 {
		t.Fatalf("a group's members and a cluster's denies as of a time read %d pages of history, and %d once 2000 more of each were changed", few, many)
	}
}

func TestAsOfReadsPastAStatementTheSessionPrepared(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	// A temporary table gives the session its temporary schema for good.
	if _, err := h.pool.Exec(ctx, `CREATE TEMP TABLE scratch (x int)`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	held := func(a *rbac.Authorizer) int {
		got, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}})
		if err != nil {
			t.Error(err)
		}
		return len(got)
	}
	if n := held(h.authz); n != 1 {
		t.Fatalf("u holds %d grants", n)
	}
	at := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if n := held(a); n != 1 {
			t.Errorf("as of before the revoke, u holds %d grants", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := held(h.authz); n != 0 {
		t.Errorf("after AsOf, u holds %d grants", n)
	}
}

// A connection's statement is the same one as of a time as now, and from its sixth run can take a
// generic plan, which costs history's indexes by an average tenant's few rows. As of a time, each
// run of a check reads as much history as the first, in a tenant whose custom roles have each been
// defined three times, one of which the check's subject holds.
func TestAsOfReadsAsMuchOnEveryRunOfACheck(t *testing.T) {
	h := crowded(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	u := h.as(t, "u")
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.r' || i, '{cluster:login}', '{cluster}' FROM generate_series(1, 300) i`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'custom.r1')`,
		`UPDATE rbac_roles SET name = 'again' WHERE tenant = 't1'`,
		`UPDATE rbac_roles SET name = 'and again' WHERE tenant = 't1'`,
		`ANALYZE rbac_history, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		var first int64
		for run := range 8 {
			start := historyPages(ctx, t, tx)
			if err := a.Authorize(ctx, u, login, cluster); err != nil {
				return err
			}
			read := historyPages(ctx, t, tx) - start
			if run == 0 {
				first = read
			} else if read > first*3/2+deeper {
				t.Errorf("as of a time, a check read %d pages of history on its first run, and %d on run %d", first, read, run+1)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// As of a time, a session that plans each statement generically lists a principal's memberships
// from its own versions: planned by the averages, the read leads to the tenant and reads every
// member's.
func TestAsOfListsAPrincipalsMembershipsAloneWhateverTheSessionsPlans(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	u := h.as(t, "u")
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			ms, err := a.Memberships(ctx, "t1", []rbac.Principal{u.Principal})
			if err == nil && len(ms) != 1 {
				err = fmt.Errorf("u's memberships: %+v", ms)
			}
			read = historyPages(ctx, t, tx) - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	manyMembers(t, h, 500, `SELECT FROM others`, "rbac_history")
	few := read(dbNow(t, h))
	manyMembers(t, h, 4500, `SELECT FROM others`, "rbac_history")
	if many := read(dbNow(t, h)); many > few*3/2+deeper {
		t.Errorf("as of a time, a principal's memberships read %d pages of history beside 500 other members, and %d beside 5000", few, many)
	}
}

// customRolesAsOf is how many pages of history a check by s reads as of now, beside many tenants'
// history, before the tenant has other custom roles and once it has 200, each defined twice. With
// plans, the read sets its transaction's plan_cache_mode to it first.
func customRolesAsOf(t *testing.T, h *harness, s rbac.Subject, plans string) (few, many int64) {
	t.Helper()
	ctx := t.Context()
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if plans != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
					return err
				}
			}
			start := historyPages(ctx, t, tx)
			err := a.Authorize(ctx, s, login, cluster)
			read = historyPages(ctx, t, tx) - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history, rbac_roles`); err != nil {
		t.Fatal(err)
	}
	few = read(dbNow(t, h))
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.other' || i, '{cluster:view}', '{cluster}' FROM generate_series(1, 200) i`,
		`UPDATE rbac_roles SET name = 'again' WHERE tenant = 't1' AND id LIKE 'custom.other%'`,
		`ANALYZE rbac_history, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return few, read(dbNow(t, h))
}

// heldCustomRoleAsOf is customRolesAsOf for a subject whose grant names a custom role.
func heldCustomRoleAsOf(t *testing.T, h *harness) (few, many int64) {
	t.Helper()
	u := h.as(t, "u")
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.login', '{cluster:login}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.login", rbac.User, "u"))
	return customRolesAsOf(t, h, u, "")
}

// skewed is crowded where history's statistics leave out the tenant's custom roles: they hold
// only the commonest tenant and entity, another tenant's grants.
func skewed(t *testing.T) *harness {
	t.Helper()
	h := crowded(t, pgtest.Open(t, "default_statistics_target=1"))
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 'large', 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.login' FROM generate_series(1, 5000) i`); err != nil {
		t.Fatal(err)
	}
	return h
}

// As of a time, a check reads the custom role its grant names by its id, however few of history's
// records, among many tenants', are the tenant's custom roles: counted as a row, they would all be
// read for each version of the one it holds.
func TestAsOfReadsACheckersCustomRoleAloneAmongManyTenants(t *testing.T) {
	if few, many := heldCustomRoleAsOf(t, crowded(t, pgtest.Open(t, ""))); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no other custom role, and %d beside 200", few, many)
	}
}

// As of a time, a check seeks the custom role its grant names by its key where history's
// statistics leave out the tenant's: by its role column, which every grant of the role shares too,
// a plan counting the tenant's roles as a few reads every version of each.
func TestAsOfReadsAHeldCustomRoleByItsKey(t *testing.T) {
	if few, many := heldCustomRoleAsOf(t, skewed(t)); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no other custom role, and %d beside 200", few, many)
	}
}

// As of a time, a check reads no custom role its grants don't name, however its statements are
// planned: a read may plan its transaction's generically, which, matching the roles to the grants,
// reads every version of the tenant's custom roles again for each.
func TestAsOfReadsNoCustomRoleACheckDoesntName(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	if few, many := customRolesAsOf(t, h, u, "force_generic_plan"); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no custom role, and %d beside 200", few, many)
	}
}

// Migrating counts the history recorded before it by tenant and entity together, rather than once
// autovacuum next analyzes it, which on a large history is long after.
func TestMigratingCountsHistoryByTenantAndEntity(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0015")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		SELECT 't1', 'custom.r' || i, '{cluster:login}', '{cluster}' FROM generate_series(1, 100) i`); err != nil {
		t.Fatal(err)
	}
	migrateFiles(t, pool, "0015", "")
	var counted bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_catalog.pg_stats_ext WHERE statistics_schemaname = current_schema()
		AND statistics_name = 'rbac_history_tenant_entity' AND most_common_vals IS NOT NULL)`).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if !counted {
		t.Error("once migrated, history's statistics of tenant and entity together are empty")
	}
}

// History's index of the keys denies name reads each deny record's principals, which a record
// written as history's owner can hold as any JSON: one that isn't an array is indexed as naming
// none, an array's arrays as their values and its other values as their text, and history takes
// each, as it takes any record.
func TestHistoryTakesADenyRecordWhosePrincipalsArentStrings(t *testing.T) {
	h := setup(t)
	for _, principals := range []string{`"user:u"`, `1`, `null`, `{"user": "u"}`, `[1, null, {"a": "b"}, ["user:u"]]`} {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after)
			VALUES (now(), 't1', 'deny', 'cluster:c1 d', 'create', jsonb_build_object('principals', $1::jsonb))`, principals); err != nil {
			t.Errorf("history refuses a deny record whose principals are %s: %v", principals, err)
		}
	}
}

// History's index of the keys denies name calls rbac_tenant_keys and rbac_text_array as history's
// owner, as migrating builds it and each time a deny is recorded. Where history's role holds no
// EXECUTE on them, as a host that revoked it from PUBLIC and granted it to the application's role
// alone has it, migrating gives it that, so neither migrating nor a change to a deny fails.
func TestMigratingLetsHistorysRoleCallWhatItsIndexCalls(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0015")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{user:u}', '{cluster:login}')`); err != nil {
		t.Fatal(err)
	}
	migration, err := fs.ReadFile(rbac.Migrations(), "0015_history_seeks.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	history, schema := role(t, tx)
	app, _ := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + history + `, ` + app,
		`ALTER TABLE rbac_history OWNER TO ` + history,
		`ALTER FUNCTION rbac_record() OWNER TO ` + history,
		`REVOKE EXECUTE ON FUNCTION rbac_tenant_keys(text, text[]) FROM PUBLIC`,
		`GRANT EXECUTE ON FUNCTION rbac_tenant_keys(text, text[]) TO ` + app,
		`GRANT INSERT ON rbac_denies TO ` + app,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("migrating where history's role may not call rbac_tenant_keys: %v", err)
	}
	for _, sql := range []string{
		`SET LOCAL ROLE ` + app,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		  VALUES ('t1', 'cluster', 'c2', 'd', '{user:u}', '{cluster:login}')`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("once migrated, %s: %v", sql, err)
		}
	}
}

// As of a time, a list of the grants or the eligibilities on a scope reads their history, not every
// grant's and eligibility's in the tenant.
func TestAsOfListsAScopesGrantsAndEligibilitiesAlone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 3600)`); err != nil {
		t.Fatal(err)
	}
	// Grants and eligibilities on other clusters.
	others := func(n int) {
		t.Helper()
		for _, q := range []string{
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'user', gen_random_uuid()::text, 'cluster.login' FROM generate_series(1, $1)`,
			`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'user', gen_random_uuid()::text, 'cluster.sudo', 3600 FROM generate_series(1, $1)`,
		} {
			if _, err := h.pool.Exec(ctx, q, n); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
	}
	scopes := rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}
	lists := []struct {
		what string
		list func(a *rbac.Authorizer) (int, error)
	}{
		{"the grants on a cluster", func(a *rbac.Authorizer) (int, error) {
			gs, err := a.Grants(ctx, "t1", scopes)
			return len(gs), err
		}},
		{"the eligibilities on a cluster", func(a *rbac.Authorizer) (int, error) {
			es, err := a.Eligibilities(ctx, "t1", scopes)
			return len(es), err
		}},
	}
	read := func(at time.Time) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			for _, l := range lists {
				start := historyPages(ctx, t, tx)
				n, err := l.list(a)
				if err == nil && n == 0 {
					err = errors.New("none listed")
				}
				if err != nil {
					return fmt.Errorf("%s: %w", l.what, err)
				}
				pages[l.what] = historyPages(ctx, t, tx) - start
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	others(1000)
	few := read(dbNow(t, h))
	others(9000)
	for what, many := range read(dbNow(t, h)) {
		if many > few[what]*3/2+deeper {
			t.Errorf("as of a time, %s read %d pages of history beside 1000 others in the tenant, and %d beside 10,000", what, few[what], many)
		}
	}
}

// As of a time, Filter and Reachable find the denies binding their subject by the keys those name,
// as they do now: thousands of denies naming others on other clusters cost them nothing, and the
// one naming the subject's group still leaves its cluster out.
func TestAsOfListsFindTheDeniesNamingTheirSubjectByItsKeys(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	ann := h.as(t, "ann", "oncall")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "ann"))
	if err := h.authz.SetDeny(ctx, guardian, resources[1], rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.Group, ID: "oncall"}}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	denies := 0
	others := func(n int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			SELECT 't1', 'cluster', 'other' || i, 'd', ARRAY['user:other' || i], '{cluster:login}' FROM generate_series($1::int + 1, $2::int) i`, denies, n); err != nil {
			t.Fatal(err)
		}
		denies = n
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
	}
	lists := []struct {
		what string
		list func(tx pgx.Tx, a *rbac.Authorizer) error
	}{
		{"Reachable", func(_ pgx.Tx, a *rbac.Authorizer) error {
			reach, err := a.Reachable(ctx, ann, login, "t1", "cluster")
			if err == nil && (!reach.All || !slices.Equal(reach.Except, []rbac.Scope{resources[1].Scope()})) {
				err = fmt.Errorf("reach %+v", reach)
			}
			return err
		}},
		{"Filter", func(tx pgx.Tx, a *rbac.Authorizer) error {
			pred, err := a.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
			if err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err == nil && !slices.Equal(ids, []string{"c0", "c2", "c3"}) {
				err = fmt.Errorf("kept %v", ids)
			}
			return err
		}},
	}
	read := func(at time.Time) map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for _, l := range lists {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
					start := historyPages(ctx, t, tx)
					err := l.list(tx, a)
					pages[l.what] = historyPages(ctx, t, tx) - start
					return err
				}); err != nil {
					t.Fatalf("%s: %v", l.what, err)
				}
			}()
		}
		return pages
	}
	others(500)
	few := read(dbNow(t, h))
	others(5000)
	for what, many := range read(dbNow(t, h)) {
		if many > few[what]*3/2+deeper {
			t.Errorf("as of a time, %s read %d pages of history beside 500 denies naming others, and %d beside 5000", what, few[what], many)
		}
	}
}

// Before 0016 the tables took a list in more than one dimension, as a write around the package with
// the application's rights could store, and every check and list took its elements in order: a
// deny naming '{{user:u}}' bound u. As of a time, history's reads took the inner array as one key,
// its JSON, so the deny bound no one. Migrating writes its row in one dimension, and as of a time
// before, every check and list reads the deny as they did then, as they read it now: by history's
// index of the keys denies name too, past enough denies naming others that lists find theirs by it.
func TestAsOfReadsAListOfMoreDimensionsAsChecksDid(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0016")
	h := migrated(t, pool)
	hostTable(t, h)
	u := h.as(t, "u")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "u"))
	for _, sql := range []string{
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 VALUES ('t1', 'workspace', 'w1', 'd', '{{user:u}}', '{{user:x}}', '{{cluster:login}}')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		 SELECT 't1', 'cluster', 'other' || i, 'd', ARRAY['user:other' || i], '{cluster:login}' FROM generate_series(1, 2000) i`,
		`ANALYZE rbac_history`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	before := dbNow(t, h)
	migrateFiles(t, pool, "0016", "")
	answers := func(a *rbac.Authorizer, q pgx.Tx) []string {
		t.Helper()
		err := a.Authorize(ctx, u, login, cluster)
		out := []string{fmt.Sprintf("Authorize: %v", err)}
		reach, err := a.Reachable(ctx, u, login, "t1", "cluster")
		out = append(out, fmt.Sprintf("Reachable: all %t except %v, %v", reach.All, reach.Except, err))
		pred, err := a.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		var kept []string
		if err == nil {
			var rows pgx.Rows
			if rows, err = q.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...); err == nil {
				kept, err = pgx.CollectRows(rows, pgx.RowTo[string])
			}
		}
		out = append(out, fmt.Sprintf("Filter: %v, %v", kept, err))
		holders, err := a.Holders(ctx, login, cluster)
		var who []string
		for _, x := range holders {
			who = append(who, x.Principal.ID)
		}
		out = append(out, fmt.Sprintf("Holders: %v, %v", who, err))
		denies, err := a.Denies(ctx, "t1", []rbac.Scope{{Type: "workspace", ID: "w1"}})
		for _, d := range denies {
			out = append(out, fmt.Sprintf("Denies: %+v %+v %v", d.Principals, d.Exempt, d.Permissions))
		}
		return append(out, fmt.Sprintf("Denies: %v", err))
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := answers(h.authz.WithTx(tx), tx)
	want := []string{
		"Authorize: rbac: cluster:login denied",
		"Reachable: all true except [{workspace w1}], <nil>",
		"Filter: [c1 c2 c3], <nil>",
		"Holders: [], <nil>",
		"Denies: [{Kind:user ID:u}] [{Kind:user ID:x}] [cluster:login]",
		"Denies: <nil>",
	}
	if !slices.Equal(now, want) {
		t.Fatalf("now:\n%s", strings.Join(now, "\n"))
	}
	var then []string
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", before, func(a *rbac.Authorizer) error {
		then = answers(a, tx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(then, now) {
		t.Errorf("as of a time before migrating:\n%s\nnow:\n%s", strings.Join(then, "\n"), strings.Join(now, "\n"))
	}
}

// AsOf reads history as of its time to the microsecond, whatever the session's DateStyle and
// TimeZone and whatever its read sets them to: a time's text in a DateStyle but ISO names its
// zone by an abbreviation, which another TimeZone reads as its own zone's, and one of another
// field order reads its month as its day. From PostgreSQL 18 a TimeZone's own abbreviations name
// zones too, as UTC+5's UTC, five hours west, does in AT TIME ZONE 'UTC', and in a time's text
// as Z or AD would.
func TestAsOfReadsItsTimeWhateverTheSessionsDateStyle(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	var granted time.Time
	if err := h.pool.QueryRow(ctx, `SELECT effective_at FROM rbac_history WHERE entity = 'grant' AND principal = 'user:u'`).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ dateStyle, timeZone, inRead string }{
		{"ISO, MDY", "UTC", ""},
		{"Postgres, DMY", "America/Los_Angeles", ""},
		{"SQL, MDY", "Europe/Dublin", ""},
		{"German", "Asia/Kolkata", ""},
		{"Postgres, YMD", "Pacific/Chatham", ""},
		{"Postgres, MDY", "XYZ-3", `SET LOCAL TimeZone = 'XYZ+5'`},
		{"SQL, MDY", "Australia/Lord_Howe", `SET LOCAL DateStyle = 'SQL, DMY'`},
		{"ISO, MDY", "UTC+5", ""},
		{"ISO, MDY", "UTC", `SET LOCAL TimeZone = '<Z>+5'`},
		{"SQL, DMY", "<AD>-2", ""},
	} {
		for _, at := range []time.Time{granted, granted.Add(-time.Microsecond), time.Date(-100, time.March, 15, 12, 0, 0, 0, time.UTC)} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err := tx.Exec(ctx, `SELECT set_config('DateStyle', $1, true), set_config('TimeZone', $2, true)`, c.dateStyle, c.timeZone); err != nil {
					t.Fatal(err)
				}
				var held error
				if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
					if c.inRead != "" {
						if _, err := tx.Exec(ctx, c.inRead); err != nil {
							return err
						}
					}
					held = a.Authorize(ctx, u, login, cluster)
					return nil
				}); err != nil {
					t.Errorf("%s, %s, %s: as of %v: %v", c.dateStyle, c.timeZone, c.inRead, at, err)
				} else if (held == nil) != at.Equal(granted) {
					t.Errorf("%s, %s, %s: as of %v, granted at %v: %v", c.dateStyle, c.timeZone, c.inRead, at, granted, held)
				}
			}()
		}
	}
}
