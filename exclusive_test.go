package rbac_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/parallelworks/rbac"
)

// bank is a dimension whose values are parties with a conflict of interest.
var bank = rbac.LabelDimension{Name: "bank", Rule: rbac.AnyOf, Values: []string{"a", "b", "c"}, Exclusive: true}

// banks adds bank to labeled's dimensions, with a public role for the tenant giving each of its
// values.
func banks(c *rbac.Config) {
	c.Labels = append(slices.Clone(c.Labels), bank)
	for _, v := range bank.Values {
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{
			ID: rbac.Role("bank." + v), Permissions: []rbac.Permission{rbac.Permission("bank:" + v)}, ResourceTypes: []string{rbac.TenantScope}, Public: true,
		})
	}
}

// excluded fails t unless err refuses a change for letting someone hold two of bank's values.
func excluded(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "two values of bank") {
		t.Fatalf("not refused as exclusive: %v", err)
	}
}

var tenantT1 = rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}

func TestAChangeLettingAnIdentityHoldTwoExclusiveValuesIsRefused(t *testing.T) {
	root := rbac.TenantRoot("t1")
	for name, c := range map[string]func(t *testing.T, h *harness) error{
		"a grant": func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "ann")})
		},
		"a grant under a condition": func(t *testing.T, h *harness) error {
			t.Helper()
			g := grant(root, "bank.b", rbac.User, "ann")
			g.Condition = rbac.Condition{Expression: `request.attributes.mission == true`}
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{g})
		},
		"a grant to the tenant's members": func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.Members, "t1")})
		},
		"a grant to the public": func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.Public, "")})
		},
		"a grant to a group it is in": func(t *testing.T, h *harness) error {
			t.Helper()
			h.as(t, "ann", "staff")
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.Group, "staff")})
		},
		"a place in a group": func(t *testing.T, h *harness) error {
			t.Helper()
			h.seed(t, grant(root, "bank.b", rbac.Group, "b-team"))
			return h.authz.ImportMembers(t.Context(), host, "t1", []rbac.Member{{Group: "b-team", Principal: identity("ann")}})
		},
		"a group it is in placed in another": func(t *testing.T, h *harness) error {
			t.Helper()
			h.as(t, "ann", "staff")
			h.seed(t, grant(root, "bank.b", rbac.Group, "b-team"))
			return h.authz.ImportMembers(t.Context(), host, "t1", []rbac.Member{{Group: "b-team", Principal: groupOf("staff")}})
		},
		"a membership no longer a guest's": func(t *testing.T, h *harness) error {
			t.Helper()
			h.seed(t, grant(root, "bank.a", rbac.Members, "t1"))
			h.guest(t, "dee")
			h.hold(t, "dee", "bank:b")
			return h.authz.SetMemberships(t.Context(), host, "t1", []rbac.Membership{{Principal: identity("dee")}})
		},
		"an eligibility": func(t *testing.T, h *harness) error {
			t.Helper()
			admin := h.as(t, "admin")
			h.seed(t, grant(root, "tenant.admin", rbac.User, "admin"))
			h.hold(t, "admin", "bank:c")
			return h.authz.SetEligibility(t.Context(), admin, tenantT1, rbac.Eligibility{Role: "bank.c", Principal: identity("ann"), MaxDuration: time.Hour})
		},
		"a custom role redefined": func(t *testing.T, h *harness) error {
			t.Helper()
			admin := roleAdmin(t, h)
			h.hold(t, "admin", "comp:alpha", "bank:b")
			ctx := t.Context()
			r := rbac.RoleDefinition{ID: "custom.liaison", Permissions: []rbac.Permission{"comp:alpha"}, ResourceTypes: []string{rbac.TenantScope}}
			if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(root, r.ID, rbac.User, "ann"))
			r.Permissions = append(r.Permissions, "bank:b")
			return h.authz.SetRole(ctx, admin, "t1", r)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := labeled(t, banks)
			h.as(t, "ann")
			h.hold(t, "ann", "bank:a")
			excluded(t, c(t, h))
		})
	}
}

func TestExclusiveValuesAreHeldOneAtATime(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.as(t, "ann")
	h.as(t, "bob")
	h.hold(t, "ann", "bank:a")
	// Another identity, another value of the dimension, and a value of one that isn't exclusive.
	h.seed(t, grant(root, "bank.b", rbac.Group, "b-team"))
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "b-team", Principal: identity("bob")}}); err != nil {
		t.Fatal(err)
	}
	h.hold(t, "ann", "bank:a", "comp:alpha", "comp:bravo")
	// The same value again, through a group.
	h.seed(t, grant(root, "bank.a", rbac.Group, "a-team"))
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a-team", Principal: identity("ann")}}); err != nil {
		t.Fatal(err)
	}
	// Another value to every member.
	excluded(t, h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.c", rbac.Members, "t1")}))
	// Two to the public, which the anonymous hold.
	err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.Public, ""), grant(root, "bank.c", rbac.Public, "")})
	excluded(t, err)
	if !strings.Contains(err.Error(), "the public") {
		t.Fatalf("refused for: %v", err)
	}
}

func TestOnlyAValueHeldNowCountsAgainstAnother(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	admin := h.as(t, "admin")
	h.seed(t, grant(root, "tenant.admin", rbac.User, "admin"))
	h.hold(t, "admin", "bank:c")
	h.as(t, "ann")
	h.hold(t, "ann", "bank:a")
	if err := h.authz.SetEligibility(ctx, admin, tenantT1, rbac.Eligibility{Role: "bank.c", Principal: identity("ann"), MaxDuration: time.Hour}); err == nil {
		t.Fatal("an eligibility for another value")
	}
	// A grant and an eligibility that have ended, which DeleteExpired hasn't removed yet, and a
	// value's grant on a scope below the tenant, as a catalog change can leave, give nothing.
	ended := h.now.Add(-time.Minute)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rbac_grants SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:ann' AND role = 'bank.a'`, []any{ended}},
		{`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
			VALUES ('t1', 'tenant', 't1', 'user', 'ann', 'bank.c', 3600, $1)`, []any{ended}},
		{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'workspace', 'w1', 'user', 'ann', 'bank.c')`, nil},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "ann")}); err != nil {
		t.Fatal(err)
	}
}

func TestASubjectWhoseGrantsCouldGiveTwoExclusiveValuesHoldsNone(t *testing.T) {
	// Granted before the dimension was exclusive, as a host's catalog changes.
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
	})
	ctx := t.Context()
	// The owner may view the cluster, but for its label.
	owner := h.as(t, "owner")
	h.hold(t, "owner", "bank:a", "rel:gbr")
	g := grant(rbac.TenantRoot("t1"), "bank.b", rbac.User, "owner")
	g.Condition = rbac.Condition{Expression: `request.attributes.mission == true`}
	h.seed(t, g)
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := cluster, cluster
	a.Labels, b.Labels = rbac.Label{"bank": {"a"}}, rbac.Label{"bank": {"b"}}
	for _, ctx := range []context.Context{ctx, rbac.WithRequest(ctx, map[string]any{"mission": true})} {
		holding, err := authz.Holding(ctx, "t1", owner)
		if err != nil {
			t.Fatal(err)
		}
		if got := holding.Values(); !slices.Equal(got, []rbac.Permission{"rel:gbr"}) {
			t.Fatalf("Values = %v", got)
		}
		for _, r := range []rbac.Resource{a, b} {
			if err := authz.Authorize(ctx, owner, view, r); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("Authorize %v: %v", r.Labels, err)
			}
			holders, err := authz.Holders(ctx, view, r)
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == owner.Principal }) {
				t.Fatalf("Holders of %v = %+v", r.Labels, holders)
			}
		}
	}
	// Ending the other grant gives it back the value it holds alone.
	if err := authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{g}); err != nil {
		t.Fatal(err)
	}
	if err := authz.Authorize(ctx, owner, view, a); err != nil {
		t.Fatalf("once it could hold one: %v", err)
	}
}

func TestChangesToExclusiveValuesRunInTurn(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	// Changes that lock nothing in common: one to a group's grants, one to another group's members.
	h.as(t, "ann", "a-team")
	h.seed(t, grant(root, "bank.b", rbac.Group, "b-team"))
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.a", rbac.Group, "a-team")}); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() {
		second <- h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "b-team", Principal: identity("ann")}})
	}()
	select {
	case err := <-second:
		t.Fatalf("the second change ran before the first committed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	excluded(t, <-second)
}

func TestAnOrderedDimensionIsntExclusive(t *testing.T) {
	h := labeled(t)
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[0].Exclusive = true
	if _, err := rbac.New(h.pool, cfg); err == nil {
		t.Fatal("New accepted an exclusive Ordered dimension")
	}
}
