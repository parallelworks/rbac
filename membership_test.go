package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
)

// grouped sets up a host whose catalog lets "groups" manage the tenant's groups.
func grouped(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	privileged := rbac.RoleDefinition{
		ID: "tenant.privileged-groups", Permissions: []rbac.Permission{rbac.ManageGroups, rbac.ManagePrivilegedGroups},
		ResourceTypes: []string{rbac.TenantScope}, Privileged: true,
	}
	h := setup(t, append([]func(*rbac.Config){func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groups, privileged)
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
	}}, mutate...)...)
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "groups"),
		grant(rbac.TenantRoot("t1"), "tenant.privileged-groups", rbac.User, "privileged"))
	return h
}

// groupOwner manages a group, on its scope.
var groupOwner = rbac.RoleDefinition{ID: "group.owner", Permissions: []rbac.Permission{"group:manage"}, ResourceTypes: []string{rbac.GroupScope}}

// groupAdmin manages groups and who manages them, granted on the tenant.
var groupAdmin = rbac.RoleDefinition{
	ID: "group.admin", Permissions: []rbac.Permission{"group:manage", rbac.GrantPermission(rbac.GroupScope), rbac.DenyPermission(rbac.GroupScope)},
	ResourceTypes: []string{rbac.GroupScope},
}

func identity(id string) rbac.Principal { return rbac.Principal{Kind: rbac.User, ID: id} }

func groupOf(id string) rbac.Principal { return rbac.Principal{Kind: rbac.Group, ID: id} }

// join makes identities members of t1.
func (h *harness) join(t *testing.T, ids ...string) {
	t.Helper()
	var ms []rbac.Membership
	for _, id := range ids {
		ms = append(ms, rbac.Membership{Principal: identity(id)})
	}
	if err := h.authz.SetMemberships(t.Context(), host, "t1", ms); err != nil {
		t.Fatal(err)
	}
}

func TestSettingMemberships(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	bot := rbac.Principal{Kind: "service_account", ID: "ci"}
	h.events = nil
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{
		{Principal: identity("u")},
		{Principal: identity("guest"), Guest: true, ExpiresAt: h.now.Add(time.Hour), Note: "audit"},
		{Principal: bot, Source: "directory"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Memberships) != 3 || h.events[0].Actor != host {
		t.Fatalf("events = %+v", h.events)
	}
	// The same again changes nothing, so reports nothing; a change reports the one it changed.
	h.events = nil
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u")}, {Principal: bot, Source: "directory", Suspended: true}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Memberships) != 1 || !h.events[0].Memberships[0].Suspended {
		t.Fatalf("events = %+v", h.events)
	}
	got, err := h.authz.Memberships(ctx, "t1", nil)
	if err != nil || len(got) != 3 || got[0].Principal != bot || got[1].Principal != identity("guest") || !got[1].Guest || got[1].Note != "audit" ||
		got[0].CreatedBy != host || got[0].Tenant != "t1" {
		t.Fatalf("Memberships = %+v, %v", got, err)
	}
	if got, err := h.authz.Memberships(ctx, "t1", []rbac.Principal{identity("u")}); err != nil || len(got) != 1 {
		t.Fatalf("Memberships of u = %+v, %v", got, err)
	}
	if err := h.authz.SetMemberships(ctx, host, "t2", []rbac.Membership{{Principal: identity("u"), Guest: true}}); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.MembershipsOf(ctx, identity("u")); err != nil || len(of) != 2 || of[0].Tenant != "t1" || of[1].Tenant != "t2" || !of[1].Guest {
		t.Fatalf("MembershipsOf = %+v, %v", of, err)
	}
	// An expired membership is gone, as DeleteExpired finds it.
	h.now = h.now.Add(2 * time.Hour)
	if got, err := h.authz.Memberships(ctx, "t1", []rbac.Principal{identity("guest")}); err != nil || len(got) != 0 {
		t.Fatalf("an expired membership = %+v, %v", got, err)
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	for name, m := range map[string]rbac.Membership{
		"a group":            {Principal: groupOf("g")},
		"the members":        {Principal: rbac.TenantMembers("t1")},
		"the public":         {Principal: rbac.Principal{Kind: rbac.Public}},
		"an undeclared kind": {Principal: rbac.Principal{Kind: "robot", ID: "r"}},
		"no id":              {Principal: rbac.Principal{Kind: rbac.User}},
		"already expired":    {Principal: identity("v"), ExpiresAt: h.now.Add(-time.Minute)},
		"a malformed source": {Principal: identity("v"), Source: "Directory"},
		"a reserved source":  {Principal: identity("v"), Source: "rbac.sync"},
	} {
		if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{m}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := h.authz.SetMemberships(ctx, rbac.Principal{Kind: rbac.Group, ID: "g"}, "t1", []rbac.Membership{{Principal: identity("v")}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a group as actor: %v", err)
	}
}

func TestManagingGroups(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	ops := rbac.GroupDefinition{ID: "ops", Name: "Operations"}
	for name, s := range map[string]rbac.Subject{"without the permission": h.as(t, "owner"), "anonymous": {}} {
		if err := h.authz.SetGroup(ctx, s, "t1", ops); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	h.events = nil
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	ops.Description = "On call"
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || h.events[1].Groups[0].Description != "On call" {
		t.Fatalf("events = %+v", h.events)
	}
	// The host's own groups only the host changes.
	synced := rbac.GroupDefinition{ID: "engineering", Source: "directory"}
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", synced); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an admin making a group from the host's source: %v", err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{synced}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "groups")
	for name, change := range map[string]func() error{
		"renaming it": func() error { return h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "engineering"}) },
		"deleting it": func() error { return h.authz.DeleteGroup(ctx, admin, "t1", "engineering") },
	} {
		if err := change(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("an admin %s from the host's source: %v", name, err)
		}
	}
	groups, err := h.authz.Groups(ctx, "t1")
	if err != nil || len(groups) != 2 || groups[0].ID != "engineering" || groups[1].Name != "Operations" || groups[1].CreatedBy != h.as(t, "groups").Principal {
		t.Fatalf("Groups = %+v, %v", groups, err)
	}
	for name, g := range map[string]rbac.GroupDefinition{
		"no id":             {},
		"a NUL":             {ID: "a\x00b"},
		"a long name":       {ID: "g", Name: strings.Repeat("n", rbac.MaxName+1)},
		"a reserved source": {ID: "g", Source: "rbac.sync"},
	} {
		if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", g); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A group that holds a grant is deleted once it is revoked, as revoking it is a change of its own.
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "ops"))
	if err := h.authz.DeleteGroup(ctx, h.as(t, "groups"), "t1", "ops"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a group that holds a grant: %v", err)
	}
	if err := h.authz.DeletePrincipal(ctx, host, "t1", groupOf("ops")); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteGroup(ctx, h.as(t, "groups"), "t1", "ops"); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].DeletedGroups) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if err := h.authz.DeleteGroup(ctx, h.as(t, "groups"), "t1", "ops"); err != nil {
		t.Fatalf("deleting a group that doesn't exist: %v", err)
	}
}

func TestGroupMembers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.join(t, "u", "v")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}, {ID: "b"}, {ID: "c"}}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	// u is in a, and a is in b, through which u is in b too; v is in c until an hour from now.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "a", Principal: identity("u"), Source: "directory"},
		{Group: "b", Principal: groupOf("a")},
		{Group: "c", Principal: identity("v"), ExpiresAt: h.now.Add(time.Hour), Note: "on call"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Joined) != 3 {
		t.Fatalf("events = %+v", h.events)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || !slices.Equal(of, []string{"a", "b"}) {
		t.Fatalf("GroupsOf(u) = %v, %v", of, err)
	}
	if members, err := h.authz.Members(ctx, "t1", "b"); err != nil || len(members) != 1 || members[0].Principal != groupOf("a") {
		t.Fatalf("Members(b) = %+v, %v", members, err)
	}
	if members, err := h.authz.Members(ctx, "t1", "c"); err != nil || len(members) != 1 || members[0].Note != "on call" {
		t.Fatalf("Members(c) = %+v, %v", members, err)
	}
	// Another tenant's group and member are no group or member of this one.
	if err := h.authz.ImportGroups(ctx, host, "t2", []rbac.GroupDefinition{{ID: "t2-group"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetMemberships(ctx, host, "t2", []rbac.Membership{{Principal: identity("stranger")}}); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]rbac.Member{
		"to a group that doesn't exist":      {Group: "nope", Principal: identity("u")},
		"of a group that doesn't exist":      {Group: "a", Principal: groupOf("nope")},
		"an identity not in the tenant":      {Group: "a", Principal: identity("stranger")},
		"a group in itself":                  {Group: "a", Principal: groupOf("a")},
		"a group in one it contains":         {Group: "a", Principal: groupOf("b")},
		"the tenant's members":               {Group: "a", Principal: rbac.TenantMembers("t1")},
		"the public":                         {Group: "a", Principal: rbac.Principal{Kind: rbac.Public}},
		"an undeclared kind":                 {Group: "a", Principal: rbac.Principal{Kind: "robot", ID: "r"}},
		"already expired":                    {Group: "a", Principal: identity("v"), ExpiresAt: h.now.Add(-time.Minute)},
		"from a reserved source":             {Group: "a", Principal: identity("v"), Source: "rbac.sync"},
		"a group of another tenant's own id": {Group: "a", Principal: groupOf("t2-group")},
	} {
		if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{m}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Once its membership ends, v is in no group.
	h.now = h.now.Add(2 * time.Hour)
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("v")); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf(v) after it expired = %v, %v", of, err)
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	h.events = nil
	if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u"), Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 || len(h.events) != 1 || len(h.events[0].Left) != 1 {
		t.Fatalf("GroupsOf(u) after it left = %v, %v, events %+v", of, err, h.events)
	}
}

func TestGroupsNestAtMostMaxGroupDepthDeep(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	var groups []rbac.GroupDefinition
	for i := range rbac.MaxGroupDepth + 1 {
		groups = append(groups, rbac.GroupDefinition{ID: fmt.Sprint("g", i)})
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", groups); err != nil {
		t.Fatal(err)
	}
	// g0 in g1 in … g7: a chain of MaxGroupDepth groups.
	for i := 1; i < rbac.MaxGroupDepth; i++ {
		if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: groups[i].ID, Principal: groupOf(groups[i-1].ID)}}); err != nil {
			t.Fatalf("nesting %d deep: %v", i+1, err)
		}
	}
	last := groups[rbac.MaxGroupDepth]
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: last.ID, Principal: groupOf(groups[rbac.MaxGroupDepth-1].ID)}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a chain one group too long, above: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: groups[0].ID, Principal: groupOf(last.ID)}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a chain one group too long, below: %v", err)
	}
	// Two that each would be fine make a cycle together, in one change or two.
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "x"}, {ID: "y"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "x", Principal: groupOf("y")}, {Group: "y", Principal: groupOf("x")}}); !errors.Is(err, rbac.ErrInvalid) ||
		!strings.Contains(err.Error(), "contain itself") {
		t.Fatalf("a cycle in one change: %v", err)
	}
	if members, err := h.authz.Members(ctx, "t1", "x"); err != nil || len(members) != 0 {
		t.Fatalf("a refused change stored %+v, %v", members, err)
	}
}

func TestLeavingATenantRemovesWhatItHeldThere(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.join(t, "u")
	if err := h.authz.SetMemberships(ctx, host, "t2", []rbac.Membership{{Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	h.events = nil
	if err := h.authz.DeletePrincipal(ctx, host, "t1", identity("u")); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].EndedMemberships) != 1 || len(h.events[0].Left) != 1 || len(h.events[0].Revoked) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if of, err := h.authz.MembershipsOf(ctx, identity("u")); err != nil || len(of) != 1 || of[0].Tenant != "t2" {
		t.Fatalf("MembershipsOf = %+v, %v", of, err)
	}
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, identity("u")); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.MembershipsOf(ctx, identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("MembershipsOf after deleting it everywhere = %+v, %v", of, err)
	}
	// Deleting the tenant deletes its groups and memberships too.
	h.join(t, "v")
	if err := h.authz.DeleteTenant(ctx, host, "t1"); err != nil {
		t.Fatal(err)
	}
	if groups, err := h.authz.Groups(ctx, "t1"); err != nil || len(groups) != 0 {
		t.Fatalf("Groups after deleting the tenant = %+v, %v", groups, err)
	}
	if ms, err := h.authz.Memberships(ctx, "t1", nil); err != nil || len(ms) != 0 {
		t.Fatalf("Memberships after deleting the tenant = %+v, %v", ms, err)
	}
}

func TestDeletingGroupsRemovesTheirGrants(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.join(t, "u")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a", Privileged: true}, {ID: "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}, {Group: "b", Principal: groupOf("a")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "a"))
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("a"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteGroups(ctx, host, "t1", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if e := h.events[0]; len(e.DeletedGroups) != 1 || len(e.Revoked) != 1 || len(e.Ineligible) != 1 || len(e.Left) != 2 {
		t.Fatalf("event = %+v", e)
	}
	if members, err := h.authz.Members(ctx, "t1", "b"); err != nil || len(members) != 0 {
		t.Fatalf("a deleted group is still in another: %+v, %v", members, err)
	}
}

func TestDeleteGroupLeavesAccessAndTheHostsMembersAsTheyAre(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole, groupOwner)
		c.Sources = []string{"directory"}
	})
	ctx := t.Context()
	groupManager, owner := h.as(t, "groups"), h.as(t, "owner")
	h.join(t, "u")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	for _, id := range []string{"denied", "exempt", "synced", "nested", "managed", "expired"} {
		if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "engineering", Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "synced", Principal: identity("u"), Source: "directory"},
		{Group: "engineering", Principal: groupOf("nested"), Source: "directory"},
	}); err != nil {
		t.Fatal(err)
	}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("denied")}, Exempt: []rbac.Principal{groupOf("exempt")}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, owner, cluster, d); err != nil {
		t.Fatal(err)
	}
	// Who manages a group, as the host grants it, is the host's to change.
	managed := grant(rbac.Scope{Type: rbac.GroupScope, ID: "managed"}, "group.owner", rbac.User, "lead")
	managed.Source = "directory"
	h.seed(t, managed)
	for _, id := range []string{"denied", "exempt", "synced", "nested", "managed"} {
		if err := h.authz.DeleteGroup(ctx, groupManager, "t1", id); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("deleting %s: %v", id, err)
		}
	}
	// Deleting a group that doesn't exist leaves the grants on its scope, as one stored before the
	// package kept groups.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'group', 'missing', 'user', 'lead', 'group.owner')`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "missing"); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{{Type: rbac.GroupScope, ID: "missing"}}}); err != nil || len(got) != 1 {
		t.Fatalf("grants on a group that doesn't exist after deleting it = %+v, %v", got, err)
	}
	// A grant that has expired gives nothing, and goes with its group.
	expiring := grant(cluster.Scope(), "cluster.login", rbac.Group, "expired")
	expiring.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, expiring)
	h.now = h.now.Add(2 * time.Hour)
	h.events = nil
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "expired"); err != nil {
		t.Fatalf("deleting a group whose grant expired: %v", err)
	}
	if len(h.events) != 1 || len(h.events[0].DeletedGroups) != 1 || len(h.events[0].Revoked) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
}

func TestAConstraintStopsManagingGroups(t *testing.T) {
	h := grouped(t, constrain("frozen", rbac.ManageGroups))
	ctx := t.Context()
	groupManager := h.as(t, "groups")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: "ops", Name: "Operations"}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("SetGroup: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "ops"); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("DeleteGroup: %v", err)
	}
}

func TestNewRefusesAContainerNamedGroup(t *testing.T) {
	ok := func(context.Context, rbac.DB, rbac.GrantInput) error { return nil }
	if _, err := rbac.New(&pgxpool.Pool{}, rbac.Config{Catalog: catalog, ContainerTypes: []string{rbac.GroupScope}, ValidateGrant: ok}); err == nil {
		t.Fatal("New accepted a container type named as groups are")
	}
}

func TestPrivilegedGroups(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	groupManager, privilegedManager := h.as(t, "groups"), h.as(t, "privileged")
	admins := rbac.GroupDefinition{ID: "admins", Privileged: true}
	// Making one needs ManagePrivilegedGroups, not ManageGroups alone.
	if err := h.authz.SetGroup(ctx, groupManager, "t1", admins); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a privileged group by an admin of ordinary groups: %v", err)
	}
	if err := h.authz.SetGroup(ctx, privilegedManager, "t1", admins); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: "devs"}); err != nil {
		t.Fatal(err)
	}
	// Whether a group is privileged is set when it is made, and never after.
	for name, change := range map[string]func() error{
		"unmarking one": func() error {
			return h.authz.SetGroup(ctx, privilegedManager, "t1", rbac.GroupDefinition{ID: "admins"})
		},
		"marking one": func() error {
			return h.authz.SetGroup(ctx, privilegedManager, "t1", rbac.GroupDefinition{ID: "devs", Privileged: true})
		},
		"importing it again": func() error { return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}) },
	} {
		if err := change(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if groups, err := h.authz.Groups(ctx, "t1"); err != nil || len(groups) != 2 || !groups[0].Privileged || groups[1].Privileged {
		t.Fatalf("Groups = %+v, %v", groups, err)
	}
	// Its members are identities: no group passes privileged access in.
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: groupOf("devs")}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a group in a privileged one: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}, {Group: "devs", Principal: groupOf("admins")}}); err != nil {
		t.Fatalf("an identity in a privileged group, and that group in an ordinary one: %v", err)
	}
	// Deleting one needs what making one does.
	if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}, {Group: "devs", Principal: groupOf("admins")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "admins"); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("deleting a privileged group as an admin of ordinary groups: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, privilegedManager, "t1", "admins"); err != nil {
		t.Fatal(err)
	}
}

func TestManagingGroupsChangesAccess(t *testing.T) {
	h := grouped(t)
	// Whoever is in a group holds what it is granted, so managing groups is never everyone's.
	if err := h.authz.Import(t.Context(), host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.Members, "t1")}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("managing groups for the tenant's members: %v", err)
	}
}

func TestAMembershipThatEndsLeavesTheTenantsGroups(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	// It is in no group once the membership ends, before DeleteExpired removes what it was in.
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf once the membership ended = %v, %v", of, err)
	}
	if members, err := h.authz.Members(ctx, "t1", "a"); err != nil || len(members) != 0 {
		t.Fatalf("Members once the membership ended = %+v, %v", members, err)
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	// Joining again gives back none of the groups it was in.
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf after the membership ended = %v, %v", of, err)
	}
}

func TestDeleteExpiredPassesOverAMembershipAChangeJoinsGroupsWith(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authz.WithTx(tx).ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// The membership ends while the change joining u to a is still open, so DeleteExpired can't
	// see what it joins: it waits for the next run, rather than leave u in a.
	h.now = h.now.Add(2 * time.Hour)
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 0 {
		t.Fatalf("DeleteExpired during the change = %d, %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("DeleteExpired after it = %d, %v", n, err)
	}
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_members`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d members left, %v", left, err)
	}
}

func TestDeleteExpiredRefusedForARaceConflicts(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	// Another transaction holds u's place in a, which DeleteExpired waits for once it ends u's
	// membership: PostgreSQL refuses the wait past lock_timeout, as it refuses one side of a
	// deadlock.
	held, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := held.Exec(ctx, `SELECT FROM rbac_members FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("DeleteExpired refused a lock: %v", err)
	}
}

func TestDeletingGroupsTakesThemOutOfDenies(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}, {ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []rbac.Deny{
		{ID: "all-but-ops", Principals: []rbac.Principal{rbac.TenantMembers("t1"), groupOf("oncall")}, Exempt: []rbac.Principal{groupOf("ops")}, Permissions: []rbac.Permission{login}},
		{ID: "oncall", Principals: []rbac.Principal{groupOf("oncall")}, Permissions: []rbac.Permission{login}},
	} {
		if err := h.authz.SetDeny(ctx, owner, cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	h.events = nil
	if err := h.authz.DeleteGroups(ctx, host, "t1", []string{"ops", "oncall"}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Denies) != 1 || len(h.events[0].DeletedDenies) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	// A group made again with ops's id is exempt from nothing, and one with oncall's denied nothing.
	ds, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
	if err != nil || len(ds) != 1 || len(ds[0].Exempt) != 0 || !slices.Equal(ds[0].Principals, []rbac.Principal{rbac.TenantMembers("t1")}) {
		t.Fatalf("Denies = %+v, %v", ds, err)
	}
}

func TestAChangeNamesOnlyGroupsThatExist(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole, groupOwner, groupAdmin) })
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"), grant(rbac.TenantRoot("t1"), "group.admin", rbac.User, "owner"))
	none := groupOf("none")
	// A change on a group's own scope, as to who manages it, names it too.
	onNone := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "none"}
	for name, change := range map[string]func() error{
		"apply": func() error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: none}}})
		},
		"import": func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.Group, "none")})
		},
		"eligibility": func() error {
			return h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: none, MaxDuration: time.Hour})
		},
		"approver": func() error {
			return h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{
				Role: "cluster.sudo", Principal: identity("u"), MaxDuration: time.Hour, Approvers: []rbac.Principal{none},
			})
		},
		"deny": func() error {
			return h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{none}, Permissions: []rbac.Permission{login}})
		},
		"exempt": func() error {
			return h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{
				ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{none}, Permissions: []rbac.Permission{login},
			})
		},
		"apply on it": func() error {
			return h.authz.Apply(ctx, owner, onNone, rbac.Change{Grant: []rbac.Binding{{Role: "group.owner", Principal: identity("u")}}})
		},
		"import on it": func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(onNone.Scope(), "group.owner", rbac.User, "u")})
		},
		"eligibility on it": func() error {
			return h.authz.SetEligibility(ctx, owner, onNone, rbac.Eligibility{Role: "group.owner", Principal: identity("u"), MaxDuration: time.Hour})
		},
		"deny on it": func() error {
			return h.authz.SetDeny(ctx, owner, onNone, rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("u")}, Permissions: []rbac.Permission{"group:manage"}})
		},
	} {
		if err := change(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s naming a group that doesn't exist: %v", name, err)
		}
	}
	// What a group made later with its id would inherit, there is none of.
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{none}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{onNone.Scope()}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants on it = %+v, %v", got, err)
	}
	// Revoking needs no group.
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: none}}}); err != nil {
		t.Fatal(err)
	}
}

func TestDeletingGroupsTakesThemOutOfApprovers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	groupManager, owner := h.as(t, "groups"), h.as(t, "owner")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "leads"}, {ID: "sre"}}); err != nil {
		t.Fatal(err)
	}
	shared := rbac.Eligibility{Role: "cluster.sudo", Principal: identity("a"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("leads"), identity("boss")}}
	only := rbac.Eligibility{Role: "cluster.sudo", Principal: identity("b"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("leads"), groupOf("sre")}}
	// One no one approves names neither, and stays.
	unapproved := rbac.Eligibility{Role: "cluster.sudo", Principal: identity("c"), MaxDuration: time.Hour}
	for _, e := range []rbac.Eligibility{shared, only, unapproved} {
		if err := h.authz.SetEligibility(ctx, owner, cluster, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "leads"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a group that approves activations: %v", err)
	}
	h.events = nil
	if err := h.authz.DeleteGroups(ctx, host, "t1", []string{"leads", "sre"}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Eligible) != 1 || len(h.events[0].Ineligible) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	// One only the groups approved would activate without approval: it goes rather than do so.
	got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
	if err != nil || len(got) != 2 || got[0].Principal != identity("a") || !slices.Equal(got[0].Approvers, []rbac.Principal{identity("boss")}) ||
		got[1].Principal != identity("c") || len(got[1].Approvers) != 0 {
		t.Fatalf("Eligibilities = %+v, %v", got, err)
	}
}

func TestDeletingGroupsAtOnceLeavesNoEligibilityWithoutItsApprovers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "leads"}, {ID: "sre"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{
		Role: "cluster.sudo", Principal: identity("b"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("leads"), groupOf("sre")},
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"leads"}); err != nil {
		t.Fatal(err)
	}
	// Deleting sre meanwhile, it takes sre out of the approvers leads's deletion left, which are
	// then none: it waits for that deletion, and so deletes the eligibility rather than keep it.
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteGroups(ctx, host, "t1", []string{"sre"}) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			done <- err
			waiting = true
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE wait_event_type = 'Lock'
				AND (query LIKE '%/rbac/%' OR query LIKE 'UPDATE rbac_eligibilities%'))`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || len(got) != 0 {
		t.Fatalf("Eligibilities = %+v, %v", got, err)
	}
}

func TestAChangeNamingAGroupWaitsForItsDeletion(t *testing.T) {
	for name, change := range map[string]func(ctx context.Context, a *rbac.Authorizer, owner rbac.Subject) error{
		"deny": func(ctx context.Context, a *rbac.Authorizer, owner rbac.Subject) error {
			return a.SetDeny(ctx, owner, cluster, rbac.Deny{
				ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{groupOf("ops")}, Permissions: []rbac.Permission{login},
			})
		},
		"approver": func(ctx context.Context, a *rbac.Authorizer, owner rbac.Subject) error {
			return a.SetEligibility(ctx, owner, cluster, rbac.Eligibility{
				Role: "cluster.sudo", Principal: identity("u"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("ops")},
			})
		},
		"grant on it": func(ctx context.Context, a *rbac.Authorizer, owner rbac.Subject) error {
			return a.Apply(ctx, owner, rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "ops"},
				rbac.Change{Grant: []rbac.Binding{{Role: "group.owner", Principal: identity("u")}}})
		},
		"import": func(ctx context.Context, a *rbac.Authorizer, owner rbac.Subject) error {
			return a.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.Group, "ops")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole, groupOwner, groupAdmin) })
			ctx := t.Context()
			h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"), grant(rbac.TenantRoot("t1"), "group.admin", rbac.User, "owner"))
			if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
				t.Fatal(err)
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"ops"}); err != nil {
				t.Fatal(err)
			}
			owner := h.as(t, "owner")
			done := make(chan error, 1)
			go func() { done <- change(ctx, h.authz, owner) }()
			for waiting := false; !waiting; {
				select {
				case err := <-done:
					done <- err
					waiting = true
				default:
					if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
						WHERE wait_event_type = 'Lock' AND wait_event = 'advisory' AND query LIKE '%/rbac/%')`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, rbac.ErrInvalid) {
				t.Fatalf("naming a group deleted meanwhile: %v", err)
			}
		})
	}
}

func TestDeletingAGroupDeletesGrantsOnIt(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	// A grant on the group, as to who manages it, which a group made later with its id mustn't inherit.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'group', 'ops', 'user', 'lead', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroups(ctx, host, "t1", []string{"ops"}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{{Type: rbac.GroupScope, ID: "ops"}}}); err != nil || len(got) != 0 {
		t.Fatalf("grants on a deleted group = %+v, %v", got, err)
	}
}

func TestDeleteGroupLeavesWhatTheGroupsItIsInGiveAsTheyAre(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	groupManager, owner := h.as(t, "groups"), h.as(t, "owner")
	h.join(t, "u")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	for _, id := range []string{"granted", "leads", "denied", "staff", "deep", "contractors", "exempt", "trusted", "approving", "reviewers", "idle", "empty"} {
		if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	// Each is in a group that holds a grant, that a deny names or exempts, or that approves
	// activations, deep two groups down; idle is in one that does none of these.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "leads", Principal: groupOf("granted")},
		{Group: "staff", Principal: groupOf("denied")},
		{Group: "contractors", Principal: groupOf("deep")},
		{Group: "staff", Principal: groupOf("contractors")},
		{Group: "trusted", Principal: groupOf("exempt")},
		{Group: "reviewers", Principal: groupOf("approving")},
		{Group: "empty", Principal: groupOf("idle")},
	}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "leads"))
	if err := h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{
		ID: "d", Principals: []rbac.Principal{groupOf("staff")}, Exempt: []rbac.Principal{groupOf("trusted")}, Permissions: []rbac.Permission{login},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{
		Role: "cluster.sudo", Principal: identity("u"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("reviewers")},
	}); err != nil {
		t.Fatal(err)
	}
	// Deleting one would take its members out of the groups above it, and what those give or bind.
	for _, id := range []string{"granted", "denied", "deep", "exempt", "approving"} {
		if err := h.authz.DeleteGroup(ctx, groupManager, "t1", id); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("deleting %s: %v", id, err)
		}
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "idle"); err != nil {
		t.Fatal(err)
	}
	if members, err := h.authz.Members(ctx, "t1", "empty"); err != nil || len(members) != 0 {
		t.Fatalf("Members of the group a deleted one was in = %+v, %v", members, err)
	}
}

func TestJoiningAgainBeforeDeleteExpiredGivesBackNoGroups(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	h.events = nil
	admin := identity("admin")
	if err := h.authz.SetMemberships(ctx, admin, "t1", []rbac.Membership{{Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf after joining again = %v, %v", of, err)
	}
	// It is a membership made now, by whoever made it again.
	if len(h.events) != 1 || len(h.events[0].Memberships) != 1 || len(h.events[0].Left) != 1 || h.events[0].Memberships[0].CreatedBy != admin {
		t.Fatalf("events = %+v", h.events)
	}
}

func TestEndingMembershipsNeverDeadlocksWithDeleteExpired(t *testing.T) {
	for name, end := range map[string]func(ctx context.Context, a *rbac.Authorizer) error{
		"DeletePrincipal": func(ctx context.Context, a *rbac.Authorizer) error {
			return a.DeletePrincipal(ctx, host, "t1", identity("u"))
		},
		"DeletePrincipalEverywhere": func(ctx context.Context, a *rbac.Authorizer) error {
			return a.DeletePrincipalEverywhere(ctx, host, identity("u"))
		},
		"DeleteTenant": func(ctx context.Context, a *rbac.Authorizer) error { return a.DeleteTenant(ctx, host, "t1") },
		"SetMemberships": func(ctx context.Context, a *rbac.Authorizer) error {
			return a.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u")}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			ctx := t.Context()
			if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}, {ID: "b"}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}, {Group: "b", Principal: identity("u")}}); err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(2 * time.Hour)
			// Another transaction holds one of u's places in a group, so the change ending u's
			// membership, or joining u again once it ended, waits partway through removing them,
			// while DeleteExpired ends it too.
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := tx.Exec(ctx, `SELECT FROM rbac_members WHERE group_id = 'b' FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			waiting := func(query string) bool {
				var w bool
				if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE $1)`,
					query).Scan(&w); err != nil {
					t.Fatal(err)
				}
				return w
			}
			ended := make(chan error, 1)
			go func() { ended <- end(ctx, h.authz) }()
			for !waiting("DELETE FROM rbac_members%") {
			}
			expired := make(chan error, 1)
			go func() {
				_, err := h.authz.DeleteExpired(ctx)
				expired <- err
			}()
			for done := false; !done; {
				select {
				case err := <-expired:
					expired <- err
					done = true
				default:
					done = waiting("%WITH ended%")
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-ended; err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if err := <-expired; err != nil {
				t.Errorf("DeleteExpired: %v", err)
			}
		})
	}
}

func TestOnlyMembersAndGuestsHoldAnything(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	u := identity("u")
	// u's own grant gives view, and the members' login too.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.view', '{cluster:view}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t,
		grant(cluster.Scope(), "custom.view", rbac.User, "u"),
		grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"),
	)
	s := rbac.Subject{Principal: u}
	check := func(what string, wantView, wantLogin bool) {
		t.Helper()
		if got := allowed(t, h, s, view, cluster); got != wantView {
			t.Errorf("%s: view %v, want %v", what, got, wantView)
		}
		if got := allowed(t, h, s, login, cluster); got != wantLogin {
			t.Errorf("%s: login %v, want %v", what, got, wantLogin)
		}
		listingsAgree(t, h, resources, s, view)
		listingsAgree(t, h, resources, s, login)
	}
	// A grant to an identity outside the tenant is stored, and gives nothing until it joins.
	check("not a member", false, false)
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u, Guest: true}}); err != nil {
		t.Fatal(err)
	}
	check("a guest", true, false)
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u, ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	check("a member", true, true)
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u, Suspended: true}}); err != nil {
		t.Fatal(err)
	}
	check("suspended", false, false)
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u, ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	check("a membership expired", false, false)
	// Nor does anything it holds let it change access.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}); err != nil {
		t.Fatalf("the owner, a member: %v", err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "outside"))
	if err := h.authz.Apply(ctx, rbac.Subject{Principal: identity("outside")}, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an admin outside the tenant: %v", err)
	}
}

func TestGroupsGiveTheirGrantsToTheirMembers(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	h.join(t, "u", "v")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "oncall"}, {ID: "sre"}, {ID: "contractors"}}); err != nil {
		t.Fatal(err)
	}
	// u is on call, and on-call is in sre until three hours from now; v is a contractor until an
	// hour from now.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "oncall", Principal: identity("u")},
		{Group: "sre", Principal: groupOf("oncall"), ExpiresAt: h.now.Add(3 * time.Hour)},
		{Group: "contractors", Principal: identity("v"), ExpiresAt: h.now.Add(time.Hour)},
		{Group: "sre", Principal: identity("v")},
	}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(workspace.Scope(), "cluster.sudo", rbac.Group, "sre"))
	u, v := rbac.Subject{Principal: identity("u")}, rbac.Subject{Principal: identity("v")}
	if !allowed(t, h, u, root, cluster) || !allowed(t, h, v, root, cluster) {
		t.Fatal("a grant to a group should reach its members, through the groups in it")
	}
	// A deny on a group binds its members, as the package knows them.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "no-contractor-root", Principals: []rbac.Principal{groupOf("contractors")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, u, root, cluster) || allowed(t, h, v, root, cluster) {
		t.Fatal("a deny on a group should bind its members and no one else")
	}
	for _, s := range []rbac.Subject{u, v} {
		listingsAgree(t, h, resources, s, root)
	}
	// Once v's place in the group ends, the deny no longer binds it.
	h.now = h.now.Add(2 * time.Hour)
	if !allowed(t, h, v, root, cluster) {
		t.Fatal("a membership that ended should bind nothing")
	}
	// The package's own groups are what count.
	if d, err := h.authz.Explain(ctx, u, root, cluster); err != nil || !d.Allowed || d.Grants[0].Principal != groupOf("sre") {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	// A suspended member's groups give it nothing.
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), Suspended: true}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, u, root, cluster) {
		t.Fatal("a suspended member's groups should give it nothing")
	}
	listingsAgree(t, h, resources, u, root)
	h.join(t, "u")
	// Once on-call's place in sre ends, sre's grant no longer reaches on-call's members.
	h.now = h.now.Add(2 * time.Hour)
	if allowed(t, h, u, root, cluster) {
		t.Fatal("a group whose place in another ended should give its members nothing through it")
	}
	listingsAgree(t, h, resources, u, root)
}

func TestAGroupIsOnlyItsTenants(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	// Two tenants each with a group named admins; mallory is in t2's.
	if err := h.authz.SetMemberships(ctx, host, "t2", []rbac.Membership{{Principal: identity("mallory")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t2", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t2", []rbac.Member{{Group: "admins", Principal: identity("mallory")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
	if allowed(t, h, rbac.Subject{Principal: identity("mallory")}, root, cluster) {
		t.Fatal("a member of another tenant's group named alike holds what this tenant's group does")
	}
	// Even as a guest here.
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("mallory"), Guest: true}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, rbac.Subject{Principal: identity("mallory")}, root, cluster) {
		t.Fatal("a guest in another tenant's group named alike holds what this tenant's group does")
	}
	// Nor is a group in another tenant's group: t2's on-call is in its admins, and t1's isn't.
	if err := h.authz.ImportGroups(ctx, host, "t2", []rbac.GroupDefinition{{ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t2", []rbac.Member{{Group: "admins", Principal: groupOf("oncall")}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, rbac.Subject{Principal: identity("u")}, root, cluster) {
		t.Fatal("a group in another tenant's group named alike holds what this tenant's group does")
	}
}

func TestHoldersReadGroupsAsChecksDo(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	// The owner holds root on the cluster; u holds root itself and is a contractor; v is on call,
	// and on-call is in sre, which holds root; w, also on call, is exempt as a lead; x is a guest;
	// y is suspended.
	h.as(t, "owner")
	h.as(t, "u", "contractors")
	h.as(t, "v", "oncall")
	h.as(t, "w", "oncall", "leads")
	h.guest(t, "x")
	h.as(t, "y", "sre")
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE principal = 'user:y'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "sre", Principal: groupOf("oncall")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t,
		grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"),
		grant(workspace.Scope(), "cluster.sudo", rbac.Group, "sre"),
		grant(cluster.Scope(), "cluster.sudo", rbac.User, "x"),
		grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"),
	)
	byID := func(holders []rbac.Holder) map[string]rbac.Holder {
		m := map[string]rbac.Holder{}
		for _, h := range holders {
			m[h.Principal.ID] = h
		}
		return m
	}
	holders, err := h.authz.Holders(ctx, root, cluster)
	if err != nil {
		t.Fatal(err)
	}
	got := byID(holders)
	if len(got) != 5 || !slices.Equal(got["v"].Groups, []string{"sre"}) || got["u"].Groups != nil || got["y"].Principal.ID != "" {
		t.Fatalf("Holders(root) = %+v", holders)
	}
	// A deny on a group binds its members, as checks read them, and spares those it exempts.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
		ID: "no-root", Principals: []rbac.Principal{groupOf("contractors"), groupOf("oncall")},
		Exempt: []rbac.Principal{groupOf("leads")}, Permissions: []rbac.Permission{root},
	}); err != nil {
		t.Fatal(err)
	}
	holders, err = h.authz.Holders(ctx, root, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(holderPrincipals(holders), []rbac.Principal{identity("owner"), identity("w"), identity("x")}) {
		t.Fatalf("Holders(root) with a deny on groups = %+v", holders)
	}
	for _, holder := range holders {
		if !allowed(t, h, rbac.Subject{Principal: holder.Principal}, root, cluster) {
			t.Errorf("Holders lists %s, whom Authorize refuses", holder.Principal.ID)
		}
	}
	for _, id := range []string{"u", "v", "y"} {
		if allowed(t, h, rbac.Subject{Principal: identity(id)}, root, cluster) {
			t.Errorf("Authorize allows %s, whom Holders leaves out", id)
		}
	}
	// A deny whose condition reads the request may bind; one naming some of the members binds some.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
		ID: "mfa", Principals: []rbac.Principal{identity("w"), identity("owner")},
		Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: "request.attributes.mfa != true"},
	}); err != nil {
		t.Fatal(err)
	}
	holders, err = h.authz.Holders(ctx, login, cluster)
	if err != nil {
		t.Fatal(err)
	}
	got = byID(holders)
	if !got["owner"].MaybeDenied || !got["w"].MaybeDenied || got["x"].MaybeDenied || !got["t1"].MaybeDenied || got["t1"].Principal != rbac.TenantMembers("t1") {
		t.Fatalf("Holders(login) = %+v", holders)
	}
	// The members are one holder, which a deny on them all removes; a guest isn't among them.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "no-login", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	holders, err = h.authz.Holders(ctx, login, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(holderPrincipals(holders), []rbac.Principal{identity("x")}) {
		t.Fatalf("Holders(login) with a deny on the members = %+v", holders)
	}
}

func TestHoldersReadNestedAndEndedMemberships(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	// sre holds root, and on-call and former are in it; contractors are in banned, which a deny
	// names. v is on call; z is on call and a contractor; q is on call and was banned; e was in sre;
	// f is in former, which was in sre; and m, granted root, was a member of the tenant.
	h.as(t, "v", "oncall")
	h.as(t, "z", "oncall", "contractors")
	h.as(t, "q", "oncall", "banned")
	h.as(t, "e", "sre")
	h.as(t, "f", "former")
	h.as(t, "m")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "sre", Principal: groupOf("oncall")},
		{Group: "sre", Principal: groupOf("former")},
		{Group: "banned", Principal: groupOf("contractors")},
	}); err != nil {
		t.Fatal(err)
	}
	ended := h.now.Add(-time.Hour)
	for _, q := range []string{
		`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND (group_id, principal) IN (('banned', 'user:q'), ('sre', 'user:e'), ('sre', 'group:former'))`,
		`UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:m'`,
	} {
		if _, err := h.pool.Exec(ctx, q, ended); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(workspace.Scope(), "cluster.sudo", rbac.Group, "sre"), grant(cluster.Scope(), "cluster.sudo", rbac.User, "m"))
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "banned", Principals: []rbac.Principal{groupOf("banned")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	holders, err := h.authz.Holders(ctx, root, cluster)
	if err != nil {
		t.Fatal(err)
	}
	listed := holderPrincipals(holders)
	if !slices.Equal(listed, []rbac.Principal{identity("q"), identity("v")}) {
		t.Fatalf("Holders(root) = %+v", holders)
	}
	for _, id := range []string{"e", "f", "m", "q", "v", "z"} {
		if allowed(t, h, rbac.Subject{Principal: identity(id)}, root, cluster) != slices.Contains(listed, identity(id)) {
			t.Errorf("Holders(root) = %+v, which Authorize doesn't agree with for %s", holders, id)
		}
	}
}

func TestHoldersReadDeniesOnTheMembersAndThePublic(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	guard := rbac.RoleDefinition{ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, guard) })
	ctx := t.Context()
	h.seed(t,
		grant(cluster.Scope(), "guard", rbac.User, "guardian"),
		grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"),
		grant(cluster.Scope(), "cluster.viewer", rbac.Public, ""),
	)
	guardian, member, guest := h.as(t, "guardian"), h.as(t, "m"), h.guest(t, "g")
	members, public := rbac.TenantMembers("t1"), rbac.Principal{Kind: rbac.Public}
	for _, c := range []struct {
		name                     string
		named, exempt            []rbac.Principal
		listed, marked           []rbac.Principal
		member, guest, anonymous bool
	}{
		// Everyone, the members among them.
		{name: "public", named: []rbac.Principal{public}},
		// Those who aren't members: the public perhaps, and the members not at all.
		{
			name: "public but the members", named: []rbac.Principal{public}, exempt: []rbac.Principal{members},
			listed: []rbac.Principal{members, public}, marked: []rbac.Principal{public}, member: true,
		},
		// The members, who are some of the public.
		{
			name: "members", named: []rbac.Principal{members},
			listed: []rbac.Principal{public}, marked: []rbac.Principal{public}, guest: true, anonymous: true,
		},
	} {
		if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: c.named, Exempt: c.exempt, Permissions: []rbac.Permission{view}}); err != nil {
			t.Fatal(err)
		}
		holders, err := h.authz.Holders(ctx, view, cluster)
		if err != nil {
			t.Fatal(err)
		}
		var listed, marked []rbac.Principal
		for _, holder := range holders {
			if holder.Principal.Kind == rbac.Members || holder.Principal.Kind == rbac.Public {
				listed = append(listed, holder.Principal)
				if holder.MaybeDenied {
					marked = append(marked, holder.Principal)
				}
			}
		}
		if !slices.Equal(listed, c.listed) || !slices.Equal(marked, c.marked) {
			t.Errorf("a deny on %s: Holders(view) = %+v", c.name, holders)
		}
		for i, s := range []rbac.Subject{member, guest, {}} {
			if want := []bool{c.member, c.guest, c.anonymous}[i]; allowed(t, h, s, view, cluster) != want {
				t.Errorf("a deny on %s: Authorize(%v) isn't %t", c.name, s.Principal, want)
			}
		}
	}
}

func TestPrivilegedRolesAreHeldOnlyByIdentitiesAndPrivilegedGroups(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins", Privileged: true}}); err != nil {
		t.Fatal(err)
	}
	owner := h.as(t, "owner")
	sudo := func(p rbac.Principal) rbac.Binding { return rbac.Binding{Role: "cluster.sudo", Principal: p} }
	for name, change := range map[string]func(rbac.Principal) error{
		"apply": func(p rbac.Principal) error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{sudo(p)}})
		},
		"import": func(p rbac.Principal) error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: sudo(p)}})
		},
		"eligibility": func(p rbac.Principal) error {
			return h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: p, MaxDuration: time.Hour})
		},
	} {
		for _, p := range []rbac.Principal{groupOf("devs"), rbac.TenantMembers("t1")} {
			if err := change(p); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("%s of a privileged role to %v: %v", name, p, err)
			}
		}
		for _, p := range []rbac.Principal{groupOf("admins"), identity("u")} {
			if err := change(p); err != nil {
				t.Errorf("%s of a privileged role to %v: %v", name, p, err)
			}
		}
	}
	// What isn't privileged any group holds.
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: groupOf("devs")}}}); err != nil {
		t.Fatal(err)
	}
}

func TestAPrivilegedRoleGivesNothingThroughTheMembersOrAnOrdinaryGroup(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins", Privileged: true}}); err != nil {
		t.Fatal(err)
	}
	// As a catalog change that makes a role privileged leaves them: refused now, but stored.
	for _, p := range []rbac.Principal{groupOf("devs"), rbac.TenantMembers("t1")} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'workspace', 'w1', $1, $2, 'cluster.admin')`, p.Kind, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		VALUES ('t1', 'cluster', 'c1', 'group', 'devs', 'cluster.sudo', 3600)`); err != nil {
		t.Fatal(err)
	}
	dev := h.as(t, "dev", "devs")
	for _, p := range []rbac.Permission{view, root, grantC} {
		if allowed(t, h, dev, p, cluster) {
			t.Errorf("%s through an ordinary group and the members", p)
		}
		listingsAgree(t, h, resources, dev, p)
		if d, err := h.authz.Explain(ctx, dev, p, cluster); err != nil || d.Allowed {
			t.Errorf("Explain %s = %+v, %v", p, d, err)
		}
	}
	if perms, err := h.authz.Permissions(ctx, dev, cluster); err != nil || len(perms) != 0 {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, root, cluster); err != nil || slices.Contains(holderPrincipals(holders), identity("dev")) ||
		slices.Contains(holderPrincipals(holders), rbac.TenantMembers("t1")) {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
	if err := h.authz.Apply(ctx, dev, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("granting through an ordinary group's privileged role: %v", err)
	}
	if _, err := h.authz.Activate(ctx, dev, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("activating through an ordinary group's eligibility for a privileged role: %v", err)
	}
	// Through a privileged group, the same grant gives what it gives.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET principal_id = 'admins' WHERE principal_kind = 'group'`); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "dev", "admins")
	if !allowed(t, h, admin, root, cluster) {
		t.Error("root through a privileged group")
	}
	listingsAgree(t, h, resources, admin, root)
}

func TestARoleBecomesPrivilegedOnlyWhereIdentitiesAndPrivilegedGroupsHoldIt(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins", Privileged: true}}); err != nil {
		t.Fatal(err)
	}
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	widened := op
	widened.Permissions = []rbac.Permission{view, login, root}
	for _, holder := range []struct {
		name string
		hold func() error
	}{
		{"an ordinary group's grant", func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: groupOf("devs")}}})
		}},
		{"the members' grant", func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: rbac.TenantMembers("t1")}}})
		}},
		{"an ordinary group's eligibility", func() error {
			return h.authz.SetEligibility(ctx, admin, cluster, rbac.Eligibility{Role: op.ID, Principal: groupOf("devs"), MaxDuration: time.Hour})
		}},
	} {
		if err := holder.hold(); err != nil {
			t.Fatal(err)
		}
		// Giving root makes it privileged, which they would hold nothing of.
		if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("making a role privileged that %s holds: %v", holder.name, err)
		}
		if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE role = 'custom.op'; DELETE FROM rbac_eligibilities WHERE role = 'custom.op'`); err != nil {
			t.Fatal(err)
		}
	}
	// An identity and a privileged group may hold it.
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{
		{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: identity("u")}},
		{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: groupOf("admins")}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("making a role privileged that only an identity and a privileged group hold: %v", err)
	}
}
