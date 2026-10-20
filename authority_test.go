package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// granter changes grants on clusters, holding nothing it hands on; lister grants cluster.sudo
// without holding it.
var (
	granter = rbac.RoleDefinition{ID: "cluster.granter", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, Privileged: true}
	lister  = rbac.RoleDefinition{
		ID: "cluster.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, Privileged: true,
		GrantableRoles: []rbac.Role{"cluster.sudo"},
	}
)

func TestAConditionReadingTheSubjectIsNoAuthorityToHandItOn(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter, lister) })
	ctx := t.Context()
	carolOnly := rbac.Condition{Expression: `subject.id == "carol"`}
	mfa := rbac.Condition{Expression: `request.attributes.mfa == true`}
	held := func(role rbac.Role, id string, c rbac.Condition) rbac.Grant {
		g := grant(cluster.Scope(), role, rbac.User, id)
		g.Condition = c
		return g
	}
	// bob holds sudo only where the subject is carol, which he never is; lee may grant sudo there
	// only on the same terms.
	h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, "bob"), held("cluster.sudo", "bob", carolOnly),
		held("cluster.lister", "lee", carolOnly), grant(cluster.Scope(), "cluster.granter", rbac.User, "max"), held("cluster.sudo", "max", mfa))
	h.join(t, "carol")
	toCarol := func(c rbac.Condition) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("carol"), Condition: c}}}
	}
	mfaCtx := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	for name, actor := range map[string]rbac.Subject{"held": h.as(t, "bob"), "listed": h.as(t, "lee")} {
		if err := h.authz.Apply(mfaCtx, actor, cluster, toCarol(carolOnly)); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s under a condition on the subject, handed on under it: %v", name, err)
		}
	}
	// Named from the root, it reads the subject all the same.
	rooted := rbac.Condition{Expression: `.subject.id == "carol"`}
	h.seed(t, held("cluster.sudo", "ray", rooted), grant(cluster.Scope(), "cluster.granter", rbac.User, "ray"))
	if err := h.authz.Apply(mfaCtx, h.as(t, "ray"), cluster, toCarol(rooted)); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("held under a condition on the subject named from the root, handed on under it: %v", err)
	}
	// A condition on the request is the same for whoever is granted it.
	if err := h.authz.Apply(mfaCtx, h.as(t, "max"), cluster, toCarol(mfa)); err != nil {
		t.Fatalf("held under a condition on the request, handed on under it: %v", err)
	}
}

func TestAnActivationLastsNoLongerThanThePlaceThatMakesItsSubjectEligible(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 300 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	u := h.as(t, "u", "oncall")
	act := func(d time.Duration) error {
		_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: d, Justification: "INC-1"})
		return err
	}
	if err := act(30 * 24 * time.Hour); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an activation outlasting the place in the group: %v", err)
	}
	if err := act(30 * time.Minute); err != nil {
		t.Fatalf("one ending before it: %v", err)
	}
}

func TestAnActivationIsHandedOnNoLongerThanItLasts(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	// u changes grants on the cluster for good, and holds sudo for an hour, as boss approved.
	h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, "u"))
	u, boss, v := h.as(t, "u"), h.as(t, "boss"), h.as(t, "v")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{
		Role: "cluster.sudo", Principal: u.Principal,
		MaxDuration: time.Hour, Approvers: []rbac.Principal{boss.Principal},
	}); err != nil {
		t.Fatal(err)
	}
	activated, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "INC-1", Approver: boss})
	if err != nil {
		t.Fatal(err)
	}
	sudo := func(p rbac.Principal, until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: p, ExpiresAt: until}}}
	}
	for name, until := range map[string]time.Time{"for good": {}, "past its end": activated.ExpiresAt.Add(time.Microsecond)} {
		for _, to := range []rbac.Subject{u, v} {
			if err := h.authz.Apply(ctx, u, cluster, sudo(to.Principal, until)); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("an activation handed on to %s %s: %v", to.Principal.ID, name, err)
			}
		}
	}
	// An eligibility is activated on terms its setter chooses, such as no approver, so even one
	// ending with the activation would outlast what boss approved.
	for _, until := range []time.Time{{}, activated.ExpiresAt} {
		e := rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour, ExpiresAt: until}
		if err := h.authz.SetEligibility(ctx, u, cluster, e); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("an activation handed on as an eligibility until %v: %v", until, err)
		}
	}
	if roles, err := h.authz.Grantable(ctx, u, cluster); err != nil || slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.sudo" }) {
		t.Errorf("Grantable offers what u may grant only until its activation ends: %v, %v", roles, err)
	}
	if err := h.authz.Apply(ctx, u, cluster, sudo(v.Principal, activated.ExpiresAt)); err != nil {
		t.Fatalf("an activation handed on until it ends: %v", err)
	}
	h.now = activated.ExpiresAt
	if allowed(t, h, u, root, cluster) || allowed(t, h, v, root, cluster) {
		t.Fatal("what was handed on outlived the activation")
	}
}

func TestAnActivatedPowerToChangeGrantsIsHandedOnNoLongerThanItLasts(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	// u holds sudo for good, and activates the power to change grants on the cluster for an hour.
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"))
	u := h.as(t, "u")
	h.as(t, "v")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.granter", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	activated, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.granter", Duration: time.Hour, Justification: "INC-1"})
	if err != nil {
		t.Fatal(err)
	}
	to := func(role rbac.Role, until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: identity("v"), ExpiresAt: until}}}
	}
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.admin", time.Time{})); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("the power activated for an hour handed on for good: %v", err)
	}
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.admin", activated.ExpiresAt)); err != nil {
		t.Errorf("handed on until it ends: %v", err)
	}
	// What u holds for good, it grants for good through it.
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.sudo", time.Time{})); err != nil {
		t.Errorf("what its holder holds for good granted for good through it: %v", err)
	}
}

func TestWhatEndsIsHandedOnNoLongerThanItsLatestHolding(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	hour, later := h.now.Add(time.Hour), h.now.Add(3*time.Hour)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}, {ID: "night"}, {ID: "inner"}, {ID: "outer"}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "g", "m", "n", "p", "v", "x")
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("m"), ExpiresAt: hour}}); err != nil {
		t.Fatal(err)
	}
	expiring := grant(cluster.Scope(), "cluster.sudo", rbac.User, "g")
	expiring.ExpiresAt = hour
	// g holds sudo until a time; m holds it for good, but is a member until then; n is in a group
	// holding it until then; p is in a group in one holding it until then; and v is in two groups
	// holding it, its place in one ending later.
	h.seed(t, expiring, grant(cluster.Scope(), "cluster.sudo", rbac.User, "m"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "ops"),
		grant(cluster.Scope(), "cluster.sudo", rbac.Group, "night"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "outer"))
	for _, id := range []string{"g", "m", "n", "p", "v"} {
		h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, id))
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "ops", Principal: identity("n"), ExpiresAt: hour},
		{Group: "inner", Principal: identity("p")},
		{Group: "outer", Principal: groupOf("inner"), ExpiresAt: hour},
		{Group: "ops", Principal: identity("v"), ExpiresAt: hour},
		{Group: "night", Principal: identity("v"), ExpiresAt: later},
	}); err != nil {
		t.Fatal(err)
	}
	sudo := func(until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("x"), ExpiresAt: until}}}
	}
	for id, ends := range map[string]time.Time{"g": hour, "m": hour, "n": hour, "p": hour, "v": later} {
		actor := rbac.Subject{Principal: identity(id)}
		for name, until := range map[string]time.Time{"for good": {}, "past its end": ends.Add(time.Second)} {
			if err := h.authz.Apply(ctx, actor, cluster, sudo(until)); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("%s handing sudo on %s: %v", id, name, err)
			}
		}
		if err := h.authz.Apply(ctx, actor, cluster, sudo(ends)); err != nil {
			t.Errorf("%s handing sudo on until its holding ends: %v", id, err)
		}
	}
}

func TestDefiningARoleNeedsWhatItGivesHeldForGood(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	expiring := grant(tenant, "cluster.sudo", rbac.User, "definer")
	expiring.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "definer"), expiring)
	definer := h.as(t, "definer")
	r := rbac.RoleDefinition{ID: "custom.root", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, definer, "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role from what the definer holds for an hour: %v", err)
	}
	h.seed(t, grant(tenant, "cluster.sudo", rbac.User, "definer"))
	if err := h.authz.SetRole(ctx, definer, "t1", r); err != nil {
		t.Fatalf("from what it holds for good: %v", err)
	}
}

func TestChangingMembersHandsOnNoLongerThanTheActorHolds(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}, {ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	// lead changes ops' and oncall's members, and grants on the cluster, for good, but holds sudo,
	// which ops holds and oncall may activate, only for an hour.
	hour := h.now.Add(time.Hour)
	expiring := grant(cluster.Scope(), "cluster.sudo", rbac.User, "lead")
	expiring.ExpiresAt = hour
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "cluster.granter", rbac.User, "lead"), expiring,
		grant(cluster.Scope(), "cluster.sudo", rbac.Group, "ops"))
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: time.Minute}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	lead := h.as(t, "lead")
	in := func(group string, until time.Time) []rbac.Member {
		return []rbac.Member{{Group: group, Principal: identity("u"), ExpiresAt: until}}
	}
	for name, add := range map[string][]rbac.Member{
		"for good":                     in("ops", time.Time{}),
		"past the holding's end":       in("ops", hour.Add(time.Second)),
		"eligible, ending before then": in("oncall", hour.Add(-time.Minute)),
	} {
		if err := h.authz.ChangeMembers(ctx, lead, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("a place in a group handing sudo on %s: %v", name, err)
		}
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("ops", hour), nil); err != nil {
		t.Fatalf("a place ending with the holding: %v", err)
	}
}

// meanwhileAsked is a harness whose host runs meanwhile, once, the first time it is asked about a
// grant made as via, as another change committing between a change's checks and its transaction.
func meanwhileAsked(t *testing.T, via rbac.Via, meanwhile *func(context.Context) error) *harness {
	t.Helper()
	return grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if do := *meanwhile; do != nil && in.Via == via {
				*meanwhile = nil
				if err := do(ctx); err != nil {
					return err
				}
			}
			return validate(ctx, q, in)
		}
	})
}

func TestAGrantToAGroupAMemberJoinedWhileTheHostWasAskedIsTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "g1")
	meanwhile = func(ctx context.Context) error {
		return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("g1")}})
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: groupOf("ops")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to a group that gained a member while the host was asked: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

func TestAGrantToAnIdentityThatLeftWhileTheHostWasAskedIsTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	h.join(t, "u")
	meanwhile = func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("u")) }
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("u")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to an identity that left while the host was asked: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("u")}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestDeleteExpiredRunsAtReadCommitted(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); err == nil {
		t.Fatal("DeleteExpired at REPEATABLE READ")
	}
}

func TestTheHostTakingAGroupOverRemovesTheMembersATenantPutInIt(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", rbac.GroupDefinition{ID: "dir-admins"}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	// It holds nothing yet, so a tenant's manager may add itself.
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "dir-admins", Principal: manager.Principal}}, nil); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "dir-admins", Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Left) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if got, err := h.authz.Members(ctx, "t1", "dir-admins"); err != nil || len(got) != 0 {
		t.Fatalf("Members = %+v, %v", got, err)
	}
}

func TestChangingMembersOfALabeledGroupNeedsItsLabel(t *testing.T) {
	crew := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "crew", Labels: rbac.Label{"level": {"high"}}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == crew.Scope() {
				return crew, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.groups(t, "crew")
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.join(t, "u")
	admin := h.as(t, "admin")
	add := []rbac.Member{{Group: "crew", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing a labeled group's members without its label: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", add, nil); err != nil {
		t.Fatalf("with its label: %v", err)
	}
}

func TestARemovalIsNeverRefusedForAnExclusiveConflict(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
	})
	ctx := t.Context()
	h.as(t, "ann")
	h.hold(t, "ann", "bank:a", "bank:b")
	h.groups(t, "approvers")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		VALUES ('t1', 'tenant', 't1', 'user', 'ann', 'bank.c', 3600, '{group:approvers,user:boss}')`); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Taking the group out of the approvers rewrites the eligibility, as no change that gives.
	if err := authz.DeleteGroups(ctx, host, "t1", []string{"approvers"}); err != nil {
		t.Fatalf("deleting a group a conflicted identity's eligibility names: %v", err)
	}
}

func TestSuspendingAMemberLiftsNoDeny(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, guardRole) })
	ctx := t.Context()
	resources := hostTable(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.viewer", rbac.Public, ""), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	for _, d := range []rbac.Deny{
		{ID: "contractors", Principals: []rbac.Principal{groupOf("contractors")}, Permissions: []rbac.Permission{view}},
		{ID: "members", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{groupOf("staff")}, Permissions: []rbac.Permission{view}},
	} {
		h.groups(t, slices.Collect(func(yield func(string) bool) {
			for _, p := range slices.Concat(d.Principals, d.Exempt) {
				if p.Kind == rbac.Group && !yield(p.ID) {
					return
				}
			}
		})...)
		if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	for name, s := range map[string]rbac.Subject{"a contractor": h.as(t, "contractor", "contractors"), "a member": h.as(t, "member")} {
		if allowed(t, h, s, view, cluster) {
			t.Fatalf("%s before its suspension", name)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = $1`, string(s.Principal.Kind)+":"+s.Principal.ID); err != nil {
			t.Fatal(err)
		}
		if allowed(t, h, s, view, cluster) {
			t.Errorf("%s once suspended, by the public's grant", name)
		}
		if d, err := h.authz.Explain(ctx, s, view, cluster); err != nil || d.Allowed {
			t.Errorf("Explain for %s once suspended = %+v, %v", name, d, err)
		}
		listingsAgree(t, h, resources, s, view)
	}
	// An exemption through a group a suspended identity is in lifts nothing either.
	staff := h.as(t, "staffer", "staff")
	if !allowed(t, h, staff, view, cluster) {
		t.Fatal("a member exempt through its group")
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:staffer'`); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, staff, view, cluster) {
		t.Error("a suspended identity exempt through its group")
	}
	listingsAgree(t, h, resources, staff, view)
}

func TestRedefiningARoleGrantedOnALabeledScopeNeedsItsLabel(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "pilot"))
	widened := r
	widened.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("widening a role granted on a labeled scope without its label: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("deleting a role granted on a labeled scope without its label: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("with its label: %v", err)
	}
}

func TestASuspendedMembersGroupsCountTowardTwoExclusiveValues(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.as(t, "ann", "a-team")
	h.seed(t, grant(root, "bank.a", rbac.Group, "a-team"))
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:ann'`); err != nil {
		t.Fatal(err)
	}
	excluded(t, h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "ann")}))
}

// Every change that asks the host about grants is tried again when the memberships its answers
// rest on change between the asking and the change.
func TestAChangeWhoseHostsAnswerRestsOnAChangedMembershipIsTriedAgain(t *testing.T) {
	asGuest := func(h *harness, id string) func(context.Context) error {
		return func(ctx context.Context) error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity(id), Guest: true}})
		}
	}
	for _, c := range []struct {
		name  string
		via   rbac.Via
		setup func(*testing.T, *harness) (meanwhile func(context.Context) error, change func(context.Context) error)
	}{
		{"Import", rbac.ViaImport, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			return func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("u")) },
				func(ctx context.Context) error {
					return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.sudo", rbac.User, "u")})
				}
		}},
		{"ImportMembers", rbac.ViaMembership, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
			return asGuest(h, "u"), func(ctx context.Context) error {
				return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}})
			}
		}},
		{"ChangeMembers", rbac.ViaMembership, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
			return asGuest(h, "u"), func(ctx context.Context) error {
				return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}, nil)
			}
		}},
		{"SetRole", rbac.ViaRedefinition, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			admin := roleAdmin(t, h)
			r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(t.Context(), admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(cluster.Scope(), r.ID, rbac.Group, "ops"))
			h.join(t, "g1")
			r.Permissions = []rbac.Permission{view, login}
			return func(ctx context.Context) error {
					return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("g1")}})
				}, func(ctx context.Context) error {
					return h.authz.SetRole(ctx, admin, "t1", r)
				}
		}},
		{"Activate", rbac.ViaActivation, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			u := h.as(t, "u")
			if err := h.authz.SetEligibility(t.Context(), h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
			return asGuest(h, "u"), func(ctx context.Context) error {
				_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"})
				return err
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h := meanwhileAsked(t, c.via, &meanwhile)
			do, change := c.setup(t, h)
			meanwhile = do
			if err := change(t.Context()); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("a membership the host's answer rests on changed meanwhile: %v", err)
			}
		})
	}
}

func TestAMembershipTheHostWasNotAskedAboutChangingIsNoConflict(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaMembership, &meanwhile)
	ctx := t.Context()
	h.join(t, "u", "v")
	h.groups(t, "everyone")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	// v joins a group that holds nothing, so the host is asked nothing about it.
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("v"), Guest: true}})
	}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}, {Group: "everyone", Principal: identity("v")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", add); err != nil {
		t.Fatalf("a member of a group holding nothing became a guest while the host was asked about another: %v", err)
	}
}

func TestARedefinitionWhoseGrantWasRevokedWhileTheHostWasAskedIsNoConflict(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaRedefinition, &meanwhile)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	g := grant(cluster.Scope(), r.ID, rbac.User, "u")
	h.seed(t, g)
	meanwhile = func(ctx context.Context) error { return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{g}) }
	r.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatalf("widening a role whose grant was revoked while the host was asked: %v", err)
	}
}

func TestAnEndedGrantOnALabeledScopeAsksNothingOfDeletingItsRole(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	g := grant(cluster.Scope(), r.ID, rbac.User, "pilot")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	h.now = h.now.Add(2 * time.Hour)
	if err := h.authz.DeleteRole(ctx, admin, "t1", r.ID); err != nil {
		t.Fatalf("deleting a role whose only grant on a labeled scope has ended: %v", err)
	}
}

func TestAMembershipReadsTheSameInAnotherTimeZone(t *testing.T) {
	// One connection, so the host's answer and the change's transaction read on the same one,
	// whose time zone the host changes in between.
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"), func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if _, err := q.Exec(ctx, `SET TIME ZONE 'Asia/Tokyo'`); err != nil {
				return err
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("u")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); err != nil {
		t.Fatalf("a grant the host was asked about in one time zone, made in another: %v", err)
	}
}

func TestARoleGrantedOnALabeledScopeWhileItsLabelsWereCheckedIsTriedAgain(t *testing.T) {
	for _, op := range []string{"SetRole", "DeleteRole"} {
		t.Run(op, func(t *testing.T) {
			secret := cluster
			secret.Labels = rbac.Label{"level": {"high"}}
			open := rbac.Scope{Type: "cluster", ID: "c2"}
			var meanwhile func(context.Context) error
			h := labeled(t, func(c *rbac.Config) {
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s == secret.Scope() {
						return secret, nil
					}
					// Asked about the scope it is granted on, the host grants it on the labeled one.
					if do := meanwhile; s == open && do != nil {
						meanwhile = nil
						if err := do(ctx); err != nil {
							return rbac.Resource{}, err
						}
					}
					return resourceOf(ctx, tenant, s)
				}
			})
			ctx := t.Context()
			admin := roleAdmin(t, h)
			r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(open, r.ID, rbac.User, "pilot"))
			meanwhile = func(ctx context.Context) error {
				return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(secret.Scope(), r.ID, rbac.User, "pilot")})
			}
			change := func() error {
				if op == "DeleteRole" {
					return h.authz.DeleteRole(ctx, admin, "t1", r.ID)
				}
				widened := r
				widened.Permissions = []rbac.Permission{view, login}
				return h.authz.SetRole(ctx, admin, "t1", widened)
			}
			if err := change(); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("granted on a labeled scope while its labels were checked: %v", err)
			}
			if err := change(); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("tried again: %v", err)
			}
		})
	}
}

func TestAMemberWhoseIDSpellsTwoMembersIsAChangedMembership(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	// An id the host can give, which reads as the two members' memberships one after the other.
	both := "a=false false \nuser:b"
	h.join(t, "a", "b", both)
	two := []rbac.Member{{Group: "ops", Principal: identity("a")}, {Group: "ops", Principal: identity("b")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", two); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		if err := h.authz.DeleteMembers(ctx, host, "t1", two); err != nil {
			return err
		}
		return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity(both)}})
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: groupOf("ops")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to a group whose members were replaced by one spelling them: %v", err)
	}
}

// A change's authority is read with the custom roles its actor's grants name, as of one moment, as
// a check reads them: a grant made and a role narrowed meanwhile can't refuse what no moment did.
func TestAChangesAuthorityIsReadWithItsCustomRolesAsOfOneMoment(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// Each lets its holder grant cluster.login.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.a', $1, '{cluster}'), ('t1', 'custom.b', $1, '{cluster}')`,
		[]string{string(view), string(login), string(grantC)}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.a", rbac.User, "lead"))
	lead := h.as(t, "lead")
	h.as(t, "u")
	// Once they are read, the lead is granted b, and then a no longer lets it grant: at every
	// moment, one of them does.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "custom.b", rbac.User, "lead")}); err != nil {
			t.Error(err)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_roles SET permissions = $1 WHERE id = 'custom.a'`, []string{string(view)}); err != nil {
			t.Error(err)
		}
	})
	if err := h.authz.Apply(ctx, lead, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("u")}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !once {
		t.Fatal("the change read its authority without reaching the hook")
	}
}

// What a change rests on is read by the memberships it names, however many others the tenant has
// in its groups.
func TestAChangeReadsTheStandingOfOnlyWhomItNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g1", "g2")
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'g' || (1 + (random() < 0.5)::int), 'user', id FROM others`, "rbac_members")
	}
	h.as(t, "ann")
	// The pages of memberships and their indexes granting ann a role reads.
	read := func() int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_memberships")
		if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "ann")}); err != nil {
			t.Fatal(err)
		}
		return pagesRead(ctx, t, tx, "rbac_memberships") - start
	}
	// Ten times as many others deepen the indexes, which a change reads a few pages more of, but
	// reading every membership would take ten times the pages.
	others(500)
	few := read()
	others(4500)
	if many := read(); many > few*3/2 {
		t.Fatalf("granting ann a role read %d pages of memberships, and %d once 4500 more were members of groups", few, many)
	}
}

// What a change rests on is costed by what it reads, however large the tenant's groups: costed as
// if it read every member, its statement would be compiled each time, which takes longer than
// reading what it names.
func TestAChangeReadsTheStandingOfWhomItNamesWithoutJIT(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone")
	everyone := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members")
	}
	// Each kind a change doesn't name is sent as NULL, as stand sends it.
	cost := func(identities, groups []string) float64 {
		t.Helper()
		var plan []struct {
			Plan struct {
				Cost float64 `json:"Total Cost"`
			}
		}
		if err := h.pool.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+rbac.StandSQL, "t1", identities, groups, h.now).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		return plan[0].Plan.Cost
	}
	one := []string{"user:u1"}
	everyone(1500)
	few := cost(one, nil)
	everyone(13500)
	for _, named := range []struct{ identities, groups []string }{{one, nil}, {nil, []string{"everyone"}}} {
		// PostgreSQL's default jit_above_cost.
		if c := cost(named.identities, named.groups); c >= 100000 {
			t.Fatalf("reading the standing of %+v is costed at %.0f, past JIT's threshold", named, c)
		}
	}
	// One identity's is costed alike in a tenant ten times as large: costed by its groups, it would
	// pass JIT's threshold once they are large enough.
	if many := cost(one, nil); many > few*3/2 {
		t.Fatalf("reading the standing of one identity is costed at %.0f, and %.0f once 13500 more were members of a group", few, many)
	}
}

// What a change rests on is read in rows as many as whom it names, whichever plan PostgreSQL
// picks: it costs the memberships a change reaches as ten, so where sorting is dear, as at a
// small work_mem or in a large tenant, and under the generic plan a cached statement moves to, a
// join would compare each member with every membership found, which takes seconds for a group of
// 20,000, under the change's locks.
func TestAChangeReadsTheStandingOfALargeGroupInRowsAsMany(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g1", "g2")
	const n = 2000
	manyMembers(t, h, 2*n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'g' || (1 + row_number() OVER () % 2), 'user', id FROM others`, "rbac_members")
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET work_mem = '64kB'; PREPARE stand AS `+rbac.StandSQL); err != nil {
		t.Fatal(err)
	}
	// Each loop's rows, with those its filters removed, as a nested loop can compare each member
	// with every membership in a filter and pass on one.
	type node struct {
		Rows       float64 `json:"Actual Rows"`
		Filtered   float64 `json:"Rows Removed by Filter"`
		JoinFilter float64 `json:"Rows Removed by Join Filter"`
		Loops      float64 `json:"Actual Loops"`
		Plans      []node
	}
	var rows func(node) float64
	rows = func(p node) float64 {
		sum := (p.Rows + p.Filtered + p.JoinFilter) * p.Loops
		for _, c := range p.Plans {
			sum += rows(c)
		}
		return sum
	}
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		var plan []struct{ Plan node }
		if _, err := conn.Exec(ctx, `SET plan_cache_mode = `+mode); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(ctx, `EXPLAIN (ANALYZE, FORMAT JSON) EXECUTE stand('t1', NULL, '{g1}', now())`).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if r := rows(plan[0].Plan); r > 50*n {
			t.Fatalf("reading the standing of a group of %d under %s passed %.0f rows through its plan", n, mode, r)
		}
	}
}

// A small group's members are read alone, however large the tenant's other groups, by a change
// naming it, by Holders and by Holders as of a time: each statement reads the members of the groups
// it reaches planned for those groups' own size.
func TestASmallGroupsMembersAreReadAlone(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	h.groups(t, "everyone", "admins")
	for _, id := range []string{"a1", "a2", "a3"} {
		h.as(t, id, "admins")
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	// The pages of the members, and of history, that each reads, in a transaction it rolls back.
	read := func(at time.Time) (change, holders, asOf int64) {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_members")
		if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "bank.a", rbac.Group, "admins")}); err != nil {
			t.Fatal(err)
		}
		mid := pagesRead(ctx, t, tx, "rbac_members")
		if hs, err := h.authz.WithTx(tx).Holders(ctx, login, cluster); err != nil || len(hs) < 3 {
			t.Fatalf("Holders = %+v, %v", hs, err)
		}
		change, holders = mid-start, pagesRead(ctx, t, tx, "rbac_members")-mid
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := pagesRead(ctx, t, tx, "rbac_history")
			hs, err := a.Holders(ctx, login, cluster)
			if err == nil && len(hs) < 3 {
				err = fmt.Errorf("Holders as of now = %+v", hs)
			}
			asOf = pagesRead(ctx, t, tx, "rbac_history") - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return change, holders, asOf
	}
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	}
	// Ten times as many others deepen the indexes, which each reads a few pages more of, but reading
	// every member would take ten times the pages.
	others(500)
	change, holders, asOf := read(dbNow(t, h))
	others(4500)
	moreChange, moreHolders, moreAsOf := read(dbNow(t, h))
	for _, c := range []struct {
		what      string
		few, many int64
	}{{"a change naming it", change, moreChange}, {"Holders", holders, moreHolders}, {"Holders as of a time", asOf, moreAsOf}} {
		if c.many > c.few*3/2 {
			t.Errorf("%s read %d pages, and %d once 4500 more were in another group", c.what, c.few, c.many)
		}
	}
}

// Holders reads, of the members of a large group a deny on the resource names, only the holders,
// now and as of a time: what reads them counts a function's rows as a thousand, and finding the
// holders among every member reads each one.
func TestHoldersReadsOnlyTheHoldersInTheGroupsADenyNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone", "admins")
	h.as(t, "a1", "admins", "everyone")
	h.as(t, "a2", "admins")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{group:everyone}', '{cluster:login}')`); err != nil {
		t.Fatal(err)
	}
	// The pages of the members, and of history, that Holders reads, in a transaction it rolls back.
	read := func(at time.Time) (now, asOf int64) {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		held := func(a *rbac.Authorizer) error {
			hs, err := a.Holders(ctx, login, cluster)
			if ps := holderPrincipals(hs); err == nil && (slices.Contains(ps, rbac.Principal{Kind: rbac.User, ID: "a1"}) ||
				!slices.Contains(ps, rbac.Principal{Kind: rbac.User, ID: "a2"})) {
				err = fmt.Errorf("Holders = %+v", hs)
			}
			return err
		}
		start := pagesRead(ctx, t, tx, "rbac_members")
		if err := held(h.authz.WithTx(tx)); err != nil {
			t.Fatal(err)
		}
		now = pagesRead(ctx, t, tx, "rbac_members") - start
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := pagesRead(ctx, t, tx, "rbac_history")
			err := held(a)
			asOf = pagesRead(ctx, t, tx, "rbac_history") - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return now, asOf
	}
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	}
	others(500)
	now, asOf := read(dbNow(t, h))
	others(4500)
	moreNow, moreAsOf := read(dbNow(t, h))
	for _, c := range []struct {
		what      string
		few, many int64
	}{{"Holders", now, moreNow}, {"Holders as of a time", asOf, moreAsOf}} {
		if c.many > c.few*3/2 {
			t.Errorf("%s read %d pages, and %d once 4500 more were in the group a deny names", c.what, c.few, c.many)
		}
	}
}

// Holders reads the memberships of a large group it lists in no more pages than they fill, now
// and as of a time: what reads them counts a function's rows as a thousand, and would look each
// member's up on its own, which as of a time reads its every version.
func TestHoldersReadsTheMembershipsOfALargeGroupInAsManyPages(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "everyone"))
	// Only in a tenant this large does the planner, counting a function's rows as a thousand, look
	// each member's membership up on its own: at 5,000 it hashes them.
	const n = 20000
	manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	// The pages table and its indexes fill.
	filled := func(table string) int64 {
		t.Helper()
		var pages int64
		if err := h.pool.QueryRow(ctx, `SELECT sum(pg_relation_size(oid) / current_setting('block_size')::bigint) FROM pg_class
			WHERE oid = $1::regclass OR oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = $1::regclass)`, table).Scan(&pages); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	at, history := dbNow(t, h), filled("rbac_history")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	held := func(a *rbac.Authorizer) error {
		hs, err := a.Holders(ctx, login, cluster)
		if err == nil && len(hs) < n {
			err = fmt.Errorf("Holders listed %d of the group's %d", len(hs), n)
		}
		return err
	}
	start := pagesRead(ctx, t, tx, "rbac_memberships")
	if err := held(h.authz.WithTx(tx)); err != nil {
		t.Fatal(err)
	}
	if read, fill := pagesRead(ctx, t, tx, "rbac_memberships")-start, filled("rbac_memberships"); read > 2*fill {
		t.Errorf("Holders read %d pages of memberships that fill %d", read, fill)
	}
	// History as of the time reads each version and whether a later one replaced it.
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		start := pagesRead(ctx, t, tx, "rbac_history")
		err := held(a)
		if read := pagesRead(ctx, t, tx, "rbac_history") - start; err == nil && read > 4*history {
			err = fmt.Errorf("Holders as of a time read %d pages of history that fill %d", read, history)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// deeper is how many more pages a change or a read of a few rows reads once ten times as many rows
// are beside them, each of its statements descending indexes a level deeper; reading those rows
// would take ten times the pages.
const deeper = 20

// generic is setup on a pool whose sessions plan every statement as PostgreSQL plans one a
// connection has run five times, generically, costing each index by the tables' averages, in a
// database of many small tenants beside t1, where a principal and a scope hold a grant or two and a
// group has a member or two.
func generic(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	h := setupOn(t, pgtest.Open(t, "plan_cache_mode=force_generic_plan"), mutate...)
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		 SELECT 's' || j, 'cluster', 'c' || i, 'user', 'u' || j || '-' || i, 'cluster.admin' FROM generate_series(1, 2000) j, generate_series(1, 10) i`,
		`INSERT INTO rbac_groups (tenant, id) SELECT 's' || j, 'g' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id)
		 SELECT 's' || j, 'user', 'u' || j || '-' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		 SELECT 's' || j, 'g' || i, 'user', 'u' || j || '-' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
	} {
		if _, err := h.pool.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// A check, a list of what a subject may do and a change's authority read, of the grants, only the
// subject's principals' on the path under a generic plan, and of the groups, only its own: there an
// index leading to a scope or a principal alone looks as cheap as the key index, and would read
// every grant on a busy tenant, or of a group granted on every cluster; and the groups a group is
// in, joined to the tenant's members, would read every one.
func TestChecksUnderAGenericPlanReadOnlyTheirSubjectsGrants(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	h.groups(t, "builders", "everyone")
	ann := h.as(t, "ann", "inner")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'builders', 'group', 'inner')`); err != nil {
		t.Fatal(err)
	}
	owner := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "owner"}}
	h.as(t, owner.Principal.ID)
	sudo := grant(cluster.Scope(), "cluster.sudo", rbac.Group, "builders")
	sudo.Condition = rbac.Condition{Expression: `subject.id == "ann"`}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "ann"), sudo)
	// The pages of the grants and the members, and their indexes, each reads, in a transaction it
	// rolls back.
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		a := h.authz.WithTx(tx)
		pages := map[string]int64{}
		for what, f := range map[string]func() error{
			"Authorize":                   func() error { return a.Authorize(ctx, ann, login, cluster) },
			"Authorize under a condition": func() error { return a.Authorize(ctx, ann, root, cluster) },
			"Permissions":                 func() error { return second(a.Permissions(ctx, ann, cluster)) },
			"Permissions on the tenant":   func() error { return second(a.Permissions(ctx, ann, tenantT1)) },
			"Grantable":                   func() error { return second(a.Grantable(ctx, owner, cluster)) },
			"Apply": func() error {
				return a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
			},
		} {
			for _, table := range []string{"rbac_grants", "rbac_members"} {
				pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
			}
			if err := f(); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
			for _, table := range []string{"rbac_grants", "rbac_members"} {
				pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
			}
		}
		return pages
	}
	// Others hold a role on the tenant and are in another group, and builders hold one on each of
	// as many clusters.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others
			UNION ALL SELECT 't1', 'cluster', id, 'group', 'builders', 'cluster.login' FROM others`, "rbac_grants", "rbac_members")
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages, and %d once 4500 more were on the tenant, in another group and builders'", what, few[what], many)
		}
	}
}

// A check reads its subject's grants from an index alone, under a generic plan too: a plan picks
// the narrower indexes leading to a scope or to a principal over the key, so they hold what a check
// reads, as the key does, or it would read each grant's row, which grants made at different times
// have on pages of their own.
func TestChecksReadTheirGrantsFromAnIndexAlone(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = setup(t)
			}
			ctx := t.Context()
			ann := h.as(t, "ann", "builders")
			held := 0
			for _, s := range []rbac.Scope{cluster.Scope(), {Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}, rbac.TenantRoot("t1")} {
				for _, r := range []rbac.Role{"cluster.login", "cluster.sudo", "cluster.admin"} {
					h.seed(t, grant(s, r, rbac.User, "ann"), grant(s, r, rbac.Group, "builders"))
					held += 2
					manyMembers(t, h, 300, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
						SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others`, "rbac_grants")
				}
			}
			// So the visibility map lets a scan of an index skip the rows.
			if _, err := h.pool.Exec(ctx, `VACUUM rbac_grants`); err != nil {
				t.Fatal(err)
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// The pages of the table itself, not its indexes: its rows and its visibility map.
			rows := func() int64 {
				t.Helper()
				var n int64
				if err := tx.QueryRow(ctx, `SELECT pg_stat_get_xact_blocks_fetched('rbac_grants'::regclass)`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			start := rows()
			if err := h.authz.WithTx(tx).Authorize(ctx, ann, login, cluster); err != nil {
				t.Fatal(err)
			}
			if read := rows() - start; read > int64(held/4) {
				t.Errorf("a check of a subject holding %d grants read %d pages of the table's rows", held, read)
			}
		})
	}
}

// Filter, its condition in the host's query, and Reachable read, of the grants, only the subject's
// principals' on scopes of the types a resource's path holds, a type at a time, under a generic plan
// too: of a range of each type's scopes, a plan can seek only one, and reading every grant of the
// principals instead reads a group's on thousands of resources of another type; and a range of
// every tenant's grants on clusters, by the scope alone, looks as cheap as the subject's.
func TestListingsUnderAGenericPlanReadOnlyTheirSubjectsGrants(t *testing.T) {
	volumes := rbac.RoleDefinition{ID: "volume.admin", Permissions: []rbac.Permission{"volume:view"}, ResourceTypes: []string{"volume"}}
	h := generic(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), volumes) })
	ctx := t.Context()
	hostTable(t, h)
	ann := h.as(t, "ann", "builders")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "ann"))
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		a := h.authz.WithTx(tx)
		var pred rbac.Predicate
		pages := map[string]int64{}
		for _, c := range []struct {
			what string
			f    func() error
		}{
			{"Filter", func() (err error) {
				pred, err = a.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				return err
			}},
			{"Filter's condition", func() error {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 1 {
					return fmt.Errorf("listed %d, %w", n, err)
				}
				return nil
			}},
			{"Reachable", func() error { return second(a.Reachable(ctx, ann, login, "t1", "cluster")) }},
		} {
			start := pagesRead(ctx, t, tx, "rbac_grants")
			if err := c.f(); err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			pages[c.what] = pagesRead(ctx, t, tx, "rbac_grants") - start
		}
		return pages
	}
	// Others hold a role on a cluster each, and builders one on each of as many volumes.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others
			UNION ALL SELECT 't1', 'volume', id, 'group', 'builders', 'volume.admin' FROM others`, "rbac_grants")
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages of grants, and %d once 4500 more were on clusters and builders' on volumes", what, few[what], many)
		}
	}
}

// Revoking a grant on a scope many hold grants on reads only the revoked principal's, under its
// lock, by Apply and by DeleteGrants, under a generic plan too: matched to the scope's grants, a
// revoke reads each of them.
func TestRevokingAGrantOnABusyScopeReadsOnlyItsPrincipals(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = setup(t)
			}
			ctx := t.Context()
			admin := h.as(t, "admin")
			ann := h.as(t, "ann")
			h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "ann"))
			revoke := rbac.Binding{Role: "cluster.login", Principal: ann.Principal}
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"Apply": func(a *rbac.Authorizer) error {
						return a.Apply(ctx, admin, tenantT1, rbac.Change{Revoke: []rbac.Binding{revoke}})
					},
					"DeleteGrants": func(a *rbac.Authorizer) error {
						return a.DeleteGrants(ctx, host, "t1", []rbac.Grant{{Scope: rbac.TenantRoot("t1"), Binding: revoke}})
					},
				} {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					start := pagesRead(ctx, t, tx, "rbac_grants")
					if err := f(h.authz.WithTx(tx)); err != nil {
						t.Fatalf("%s: %v", what, err)
					}
					var left bool
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE principal = 'user:ann')`).Scan(&left); err != nil || left {
						t.Fatalf("%s left ann's grant: %v", what, err)
					}
					pages[what] = pagesRead(ctx, t, tx, "rbac_grants") - start
					_ = tx.Rollback(ctx)
				}
				return pages
			}
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others`, "rbac_grants")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages of grants, and %d once 4500 more held a role on the tenant", what, few[what], many)
				}
			}
		})
	}
}
