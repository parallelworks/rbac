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
