package rbac_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
	h.privileged(t, "sre")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"))
	// x's login expires between the two times.
	x := h.as(t, "x")
	expires := dbNow(t, h).Add(200 * time.Millisecond)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', $1)`, expires); err != nil {
		t.Fatal(err)
	}
	then := dbNow(t, h)
	// Since: u left sre, a deny took login from u, and v was granted login.
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_members WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "v"))
	time.Sleep(time.Until(expires) + 50*time.Millisecond)
	now := dbNow(t, h)
	for _, c := range []struct {
		name        string
		at          time.Time
		uRoot       bool
		uLogin      bool
		vLogin      bool
		loginHeldBy []rbac.Principal
	}{
		{"then", then, true, true, false, []rbac.Principal{u.Principal, x.Principal}},
		{"now", now, false, false, true, []rbac.Principal{v.Principal}},
	} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for _, check := range []struct {
				s    rbac.Subject
				p    rbac.Permission
				want bool
			}{{u, root, c.uRoot}, {u, login, c.uLogin}, {v, login, c.vLogin}, {x, login, c.at.Before(expires)}} {
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

func TestAsOfLeavesTheHostsTransactionAsItWas(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		_, err := a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The views are gone with its savepoint: the host's transaction reads the tables again.
	var name string
	if err := tx.QueryRow(ctx, `SELECT 'rbac_grants'::regclass::text`).Scan(&name); err != nil || name != "rbac_grants" {
		t.Fatalf("rbac_grants is %q, %v", name, err)
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

func TestAsOfRefusesCachedHistoryIds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_history ALTER COLUMN id SET CACHE 2`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf with history's ids cached: %v", err)
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
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error {
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
				t.Errorf("%s as of now: %d rows missing, %d extra, %d columns differ", tb.Name, missing, extra, columns)
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
