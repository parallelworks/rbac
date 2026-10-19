package rbac_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
)

// bank is a dimension whose values are parties with a conflict of interest.
var bank = rbac.LabelDimension{Name: "bank", Rule: rbac.AnyOf, Values: []string{"a", "b", "c"}, Exclusive: true}

// banks adds bank to labeled's dimensions, with a public role for the tenant giving each of its
// values, and a privileged one its power to release.
func banks(c *rbac.Config) {
	c.Labels = append(slices.Clone(c.Labels), bank)
	for _, v := range bank.Values {
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{
			ID: rbac.Role("bank." + v), Permissions: []rbac.Permission{rbac.Permission("bank:" + v)}, ResourceTypes: []string{rbac.TenantScope}, Public: true,
		})
	}
	c.Catalog = append(c.Catalog, rbac.RoleDefinition{
		ID: "bank.release", Permissions: []rbac.Permission{rbac.ReleasePermission("bank")}, ResourceTypes: []string{rbac.TenantScope}, Privileged: true,
	})
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
		"a grant to an identity yet to join": func(t *testing.T, h *harness) error {
			t.Helper()
			h.hold(t, "zed", "bank:a")
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "zed")})
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
		"a grant to the public beside the own grants of an identity yet to join": func(t *testing.T, h *harness) error {
			t.Helper()
			h.hold(t, "zed", "bank:b")
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, "bank.a", rbac.Public, "")})
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
		"a custom role's grant": func(t *testing.T, h *harness) error {
			t.Helper()
			admin := roleAdmin(t, h)
			h.hold(t, "admin", "bank:b")
			r := rbac.RoleDefinition{ID: "custom.liaison", Permissions: []rbac.Permission{"bank:b"}, ResourceTypes: []string{rbac.TenantScope}}
			if err := h.authz.SetRole(t.Context(), admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			return h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(root, r.ID, rbac.User, "ann")})
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
	ann := h.as(t, "ann")
	h.as(t, "bob")
	h.hold(t, "ann", "bank:a")
	// Another identity, another value of the dimension, and a value of one that isn't exclusive.
	h.seed(t, grant(root, "bank.b", rbac.Group, "b-team"))
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "b-team", Principal: identity("bob")}}); err != nil {
		t.Fatal(err)
	}
	// The power to release is no value.
	h.hold(t, "ann", "bank:a", "comp:alpha", "comp:bravo", "bank:release")
	if holding, err := h.authz.Holding(ctx, "t1", ann); err != nil || !slices.Contains(holding.Values(), "bank:a") {
		t.Fatalf("Holding = %+v, %v", holding, err)
	}
	// The same value again, through a group.
	h.seed(t, grant(root, "bank.a", rbac.Group, "a-team"))
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a-team", Principal: identity("ann")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Authorize(ctx, ann, "bank:a", tenantT1); err != nil {
		t.Fatalf("bank:a through two grants: %v", err)
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
	excluded(t, h.authz.SetEligibility(ctx, admin, tenantT1, rbac.Eligibility{Role: "bank.c", Principal: identity("ann"), MaxDuration: time.Hour}))
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
	h.hold(t, "owner", "bank:a", "rel:gbr", "bank:release")
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
		// Nor does a check of a value itself allow it.
		if err := authz.Authorize(ctx, owner, "bank:a", tenantT1); !errors.Is(err, rbac.ErrDenied) {
			t.Fatalf("Authorize bank:a: %v", err)
		}
		if perms, err := authz.Permissions(ctx, owner, tenantT1); err != nil || slices.Contains(perms, "bank:a") || slices.Contains(perms, "bank:b") {
			t.Fatalf("Permissions = %v, %v", perms, err)
		}
		holders, err := authz.Holders(ctx, "bank:a", tenantT1)
		if err != nil || slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == owner.Principal }) {
			t.Fatalf("Holders of bank:a = %+v, %v", holders, err)
		}
		// Nor does a search of one.
		if reach, err := authz.Reachable(ctx, owner, "bank:a", "t1", rbac.TenantScope); err != nil || reach.All {
			t.Fatalf("Reachable bank:a = %+v, %v", reach, err)
		}
		pred, err := authz.Filter(ctx, owner, "bank:a", "t1", rbac.TenantScope, rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var kept bool
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM (SELECT 't1'::text AS tenant, '{tenant:t1}'::text[] AS path, '{}'::text[] AS labels) r
			WHERE `+pred.SQL+`)`, pred.Args...).Scan(&kept); err != nil || kept {
			t.Fatalf("Filter of bank:a kept the tenant: %v", err)
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
	conflicts, err := authz.Conflicts(ctx, "t1")
	if want := []rbac.Conflict{{Principal: owner.Principal, Dimension: "bank", Values: []rbac.Permission{"bank:a", "bank:b"}}}; err != nil || !reflect.DeepEqual(conflicts, want) {
		t.Fatalf("Conflicts = %+v, %v", conflicts, err)
	}
	// Its power to release is no value, which it keeps.
	if reach, err := authz.Reachable(ctx, owner, rbac.ReleasePermission("bank"), "t1", rbac.TenantScope); err != nil || !reach.All {
		t.Fatalf("Reachable bank:release = %+v, %v", reach, err)
	}
	// A change reaching it is refused until a removal leaves it one value.
	h.groups(t, "staff")
	err = authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "staff", Principal: owner.Principal}})
	excluded(t, err)
	if !strings.Contains(err.Error(), "leaves user:owner able to hold") {
		t.Fatalf("refused for: %v", err)
	}
	if err := authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{g}); err != nil {
		t.Fatal(err)
	}
	if err := authz.Authorize(ctx, owner, view, a); err != nil {
		t.Fatalf("once it could hold one: %v", err)
	}
	if err := authz.Authorize(ctx, owner, "bank:a", tenantT1); err != nil {
		t.Fatalf("bank:a once it could hold one: %v", err)
	}
	if reach, err := authz.Reachable(ctx, owner, "bank:a", "t1", rbac.TenantScope); err != nil || !reach.All {
		t.Fatalf("Reachable bank:a once it could hold one = %+v, %v", reach, err)
	}
	if conflicts, err := authz.Conflicts(ctx, "t1"); err != nil || len(conflicts) != 0 {
		t.Fatalf("Conflicts once resolved = %+v, %v", conflicts, err)
	}
	// Where no dimension is exclusive, there are none to list.
	if conflicts, err := h.authz.Conflicts(ctx, "t1"); err != nil || conflicts != nil {
		t.Fatalf("Conflicts with no exclusive dimension = %+v, %v", conflicts, err)
	}
}

func TestConflictsListsThePublic(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
	})
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.as(t, "ann")
	h.seed(t, grant(root, "bank.b", rbac.Public, ""), grant(root, "bank.c", rbac.Public, ""))
	// An identity that is no member yet, whose own grants it would hold once it joined.
	h.hold(t, "zed", "bank:a", "bank:b")
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	conflicts, err := authz.Conflicts(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	anyone := rbac.Conflict{Principal: rbac.Principal{Kind: rbac.Public}, Dimension: "bank", Values: []rbac.Permission{"bank:b", "bank:c"}}
	zed := rbac.Conflict{Principal: identity("zed"), Dimension: "bank", Values: []rbac.Permission{"bank:a", "bank:b", "bank:c"}}
	for _, want := range []rbac.Conflict{anyone, zed} {
		if !slices.ContainsFunc(conflicts, func(c rbac.Conflict) bool { return reflect.DeepEqual(c, want) }) {
			t.Fatalf("Conflicts = %+v, without %+v", conflicts, want)
		}
	}
	// The public's own grants give two, so no one holds either through it.
	public := func(x rbac.Holder) bool { return x.Principal.Kind == rbac.Public }
	holders, err := authz.Holders(ctx, "bank:b", tenantT1)
	if err != nil || slices.ContainsFunc(holders, public) {
		t.Fatalf("Holders of bank:b = %+v, %v", holders, err)
	}
	// With one, the other ended though DeleteExpired hasn't removed it yet, it holds a value each
	// of its people may hold none of.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET expires_at = $1 WHERE tenant = 't1' AND principal = 'public:' AND role = 'bank.c'`,
		h.now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	holders, err = authz.Holders(ctx, "bank:b", tenantT1)
	if err != nil || !slices.ContainsFunc(holders, func(x rbac.Holder) bool { return public(x) && x.MaybeDenied }) {
		t.Fatalf("Holders of bank:b with one = %+v, %v", holders, err)
	}
	// Suspending a member, which then holds only the public's values, is never refused.
	if err := authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("ann"), Suspended: true}}); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	if _, err := authz.Conflicts(ctx, ""); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("Conflicts of no tenant: %v", err)
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

func TestAValueAConstraintRemovesStillCountsAgainstAnother(t *testing.T) {
	// The constraint removes bank:a from a subject not cleared for it, as Holders asks it of a
	// holder without its attributes.
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
		c.Catalog = append(c.Catalog, tenantGuard)
		c.Constraints = []rbac.Constraint{{Name: "cleared", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == "bank:a" && (in.Subject == nil || in.Subject.Attributes["cleared"] != true), nil
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.hold(t, "owner", "bank:a", "bank:b")
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b := cluster
	b.Labels = rbac.Label{"bank": {"b"}}
	cleared := rbac.Subject{Principal: owner.Principal, Attributes: map[string]any{"cleared": true}}
	if err := authz.Authorize(ctx, cleared, view, b); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Authorize cleared: %v", err)
	}
	holding, err := authz.Holding(ctx, "t1", owner)
	if err != nil {
		t.Fatal(err)
	}
	if got := holding.Values(); len(got) != 0 {
		t.Fatalf("Values = %v", got)
	}
	holders, err := authz.Holders(ctx, view, b)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == owner.Principal }) {
		t.Fatalf("Holders = %+v", holders)
	}
	// A deny taking the value too leaves it counted, so it still holds none, cleared or not.
	guardian := h.as(t, "guardian")
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	if err := authz.SetDeny(ctx, guardian, tenantT1, rbac.Deny{ID: "no-a", Principals: []rbac.Principal{owner.Principal}, Permissions: []rbac.Permission{"bank:a"}}); err != nil {
		t.Fatal(err)
	}
	if err := authz.Authorize(ctx, cleared, view, b); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Authorize cleared under a deny: %v", err)
	}
}

func TestARoleGivingTwoExclusiveValuesIsRefused(t *testing.T) {
	h := labeled(t, banks)
	both := rbac.RoleDefinition{ID: "bank.both", Permissions: []rbac.Permission{"bank:a", "bank:b"}, ResourceTypes: []string{rbac.TenantScope}}
	cfg := h.cfg
	cfg.Catalog = append(slices.Clone(cfg.Catalog), both)
	if _, err := rbac.New(h.pool, cfg); err == nil || !strings.Contains(err.Error(), "exclusive") {
		t.Fatalf("New: %v", err)
	}
	admin := roleAdmin(t, h)
	both.ID = "custom.both"
	if err := h.authz.SetRole(t.Context(), admin, "t1", both); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "exclusive") {
		t.Fatalf("SetRole: %v", err)
	}
}

func TestAnActorHoldingNoneOfTwoExclusiveValuesHandsNeitherOn(t *testing.T) {
	// Constraints run before a change's transaction, so one that queries the pool can't wait on it.
	inTx := false
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
		c.Constraints = []rbac.Constraint{{Name: "watch", Deny: func(_ context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			_, tx := q.(pgx.Tx)
			inTx = inTx || tx
			return false, nil
		}}}
	})
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	admin := h.as(t, "admin")
	h.as(t, "bob")
	h.seed(t, grant(root, "tenant.admin", rbac.User, "admin"))
	h.hold(t, "admin", "bank:a", "bank:b")
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	toBob := rbac.Change{Grant: []rbac.Binding{{Role: "bank.a", Principal: identity("bob")}}}
	if err := authz.Apply(ctx, admin, tenantT1, toBob); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a value it holds none of handed on: %v", err)
	}
	if err := authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "admin")}); err != nil {
		t.Fatal(err)
	}
	if err := authz.Apply(ctx, admin, tenantT1, toBob); err != nil {
		t.Fatalf("once it holds one: %v", err)
	}
	if inTx {
		t.Fatal("a constraint was asked in the change's transaction")
	}
}

func TestEveryGrantCountsTowardTwoExclusiveValues(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{ID: "bank.c-staff", Permissions: []rbac.Permission{"bank:c"}, ResourceTypes: []string{rbac.TenantScope}})
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.hold(t, "owner", "bank:a")
	// A grant to the public of a role that isn't public, as a catalog change can leave, gives no
	// check anything, but counts as Conflicts counts it, so the owner holds neither.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'tenant', 't1', 'public', '', 'bank.c-staff')`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Authorize(ctx, owner, "bank:a", tenantT1); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Authorize bank:a: %v", err)
	}
	conflicts, err := h.authz.Conflicts(ctx, "t1")
	if err != nil || !slices.ContainsFunc(conflicts, func(c rbac.Conflict) bool { return c.Principal == owner.Principal }) {
		t.Fatalf("Conflicts = %+v, %v", conflicts, err)
	}
}

func TestHoldersLeaveOutTheMembersWhoseGrantsGiveTwoExclusiveValues(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
	})
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.as(t, "ann")
	h.seed(t, grant(root, "bank.a", rbac.Members, "t1"), grant(root, "bank.b", rbac.Members, "t1"))
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	holders, err := authz.Holders(ctx, "bank:a", tenantT1)
	if err != nil || slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal.Kind == rbac.Members }) {
		t.Fatalf("Holders of bank:a = %+v, %v", holders, err)
	}
}

// A change reads the values the identities it reaches hold, however many others in the tenant
// hold one.
func TestAChangeReadsOnlyTheValuesOfWhomItReaches(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	others := func(n int) {
		t.Helper()
		for _, q := range []string{
			`CREATE TEMP TABLE others AS SELECT gen_random_uuid()::text AS id FROM generate_series(1, $1)`,
			`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', id FROM others`,
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) SELECT 't1', 'tenant', 't1', 'user', id, 'bank.b' FROM others`,
			`DROP TABLE others`,
			`ANALYZE`,
		} {
			args := []any{n}
			if !strings.Contains(q, "$1") {
				args = nil
			}
			if _, err := h.pool.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	h.as(t, "ann")
	// The pages of the grants and their indexes giving ann a value reads.
	read := func() int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_grants")
		if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "bank.a", rbac.User, "ann")}); err != nil {
			t.Fatal(err)
		}
		return pagesRead(ctx, t, tx, "rbac_grants") - start
	}
	// Ten times as many others deepen the indexes, which a change reads a few pages more of, but
	// reading their values would take ten times the pages.
	others(500)
	few := read()
	others(4500)
	if many := read(); many > few*3/2 {
		t.Fatalf("a grant of a value read %d pages of grants, and %d once 4500 more held one", few, many)
	}
}

// The check of a change's exclusive values runs without JIT, but leaves the host's transaction
// its own setting.
func TestAChangeLeavesTheHostItsJITSetting(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	h.as(t, "ann")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SET LOCAL jit = on`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "bank.a", rbac.User, "ann")}); err != nil {
		t.Fatal(err)
	}
	var jit string
	if err := tx.QueryRow(ctx, `SELECT current_setting('jit')`).Scan(&jit); err != nil || jit != "on" {
		t.Fatalf("jit = %q, %v", jit, err)
	}
}

// pagesRead is how many pages of table and its indexes tx has read.
func pagesRead(ctx context.Context, t *testing.T, tx pgx.Tx, table string) int64 {
	t.Helper()
	var n int64
	if err := tx.QueryRow(ctx, `SELECT sum(pg_stat_get_xact_blocks_fetched(oid)) FROM pg_class
		WHERE oid = $1::regclass OR oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = $1::regclass)`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The public's grants on the tenant are read with the custom roles they name, as of one moment, as
// a check reads them, for whether their exclusive values leave it none.
func TestThePublicsValuesAreReadWithTheirCustomRolesAsOfOneMoment(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, public)
		VALUES ('t1', 'custom.x', '{bank:a}', '{tenant}', true), ('t1', 'custom.y', '{comp:alpha}', '{tenant}', true)`); err != nil {
		t.Fatal(err)
	}
	root := rbac.TenantRoot("t1")
	h.seed(t, grant(root, "custom.x", rbac.Public, ""), grant(root, "custom.y", rbac.Public, ""))
	// Once they are read, x's grant is revoked, and then y gives another value of bank: at no
	// moment does the public hold two.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		for _, q := range []string{
			`DELETE FROM rbac_grants WHERE role = 'custom.x'`,
			`UPDATE rbac_roles SET permissions = '{bank:b}' WHERE id = 'custom.y'`,
		} {
			if _, err := h.pool.Exec(ctx, q); err != nil {
				t.Error(err)
			}
		}
	})
	holders, err := h.authz.Holders(ctx, "bank:a", tenantT1)
	if err != nil {
		t.Fatal(err)
	}
	if !once {
		t.Fatal("Holders read the public's values without reaching the hook")
	}
	if !slices.Equal(holderPrincipals(holders), []rbac.Principal{{Kind: rbac.Public}}) {
		t.Fatalf("Holders = %+v: the public's values were read from two moments", holders)
	}
}
