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
	h.groups(t, "sre")
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
