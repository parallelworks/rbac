package rbac_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
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
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if err := a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply as of a time: %v", err)
		}
		if _, err := a.DeleteExpired(ctx); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteExpired as of a time: %v", err)
		}
		if err := a.AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf as of a time: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
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
