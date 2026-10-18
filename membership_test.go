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
	for name, s := range map[string]rbac.Subject{"without the permission": user("owner"), "anonymous": {}} {
		if err := h.authz.SetGroup(ctx, s, "t1", ops); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	h.events = nil
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	ops.Description = "On call"
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", ops); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || h.events[1].Groups[0].Description != "On call" {
		t.Fatalf("events = %+v", h.events)
	}
	// The host's own groups only the host changes.
	synced := rbac.GroupDefinition{ID: "engineering", Source: "directory"}
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", synced); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an admin making a group from the host's source: %v", err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{synced}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func() error{
		"renaming it": func() error {
			return h.authz.SetGroup(ctx, user("groups"), "t1", rbac.GroupDefinition{ID: "engineering"})
		},
		"deleting it": func() error { return h.authz.DeleteGroup(ctx, user("groups"), "t1", "engineering") },
	} {
		if err := change(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("an admin %s from the host's source: %v", name, err)
		}
	}
	groups, err := h.authz.Groups(ctx, "t1")
	if err != nil || len(groups) != 2 || groups[0].ID != "engineering" || groups[1].Name != "Operations" || groups[1].CreatedBy != user("groups").Principal {
		t.Fatalf("Groups = %+v, %v", groups, err)
	}
	for name, g := range map[string]rbac.GroupDefinition{
		"no id":             {},
		"a NUL":             {ID: "a\x00b"},
		"a long name":       {ID: "g", Name: strings.Repeat("n", rbac.MaxName+1)},
		"a reserved source": {ID: "g", Source: "rbac.sync"},
	} {
		if err := h.authz.SetGroup(ctx, user("groups"), "t1", g); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A group that holds a grant is deleted once it is revoked, as revoking it is a change of its own.
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "ops"))
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "ops"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a group that holds a grant: %v", err)
	}
	if err := h.authz.DeletePrincipal(ctx, host, "t1", groupOf("ops")); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "ops"); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].DeletedGroups) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "ops"); err != nil {
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
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}, {ID: "b"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}, {Group: "b", Principal: groupOf("a")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "a"))
	if err := h.authz.SetEligibility(ctx, user("owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("a"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteGroups(ctx, host, "t1", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	e := h.events[0]
	if len(h.events) != 1 || len(e.DeletedGroups) != 1 || len(e.Revoked) != 1 || len(e.Ineligible) != 1 || len(e.Left) != 2 {
		t.Fatalf("events = %+v", h.events)
	}
	if members, err := h.authz.Members(ctx, "t1", "b"); err != nil || len(members) != 0 {
		t.Fatalf("a deleted group is still in another: %+v, %v", members, err)
	}
}

func TestDeleteGroupLeavesAccessAndTheHostsMembersAsTheyAre(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.Sources = []string{"directory"}
	})
	ctx := t.Context()
	h.join(t, "u")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	for _, id := range []string{"denied", "exempt", "synced", "nested", "expired"} {
		if err := h.authz.SetGroup(ctx, user("groups"), "t1", rbac.GroupDefinition{ID: id}); err != nil {
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
	if err := h.authz.SetDeny(ctx, user("owner"), cluster, d); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"denied", "exempt", "synced", "nested"} {
		if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", id); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("deleting %s: %v", id, err)
		}
	}
	// A grant that has expired gives nothing, and goes with its group.
	expiring := grant(cluster.Scope(), "cluster.login", rbac.Group, "expired")
	expiring.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, expiring)
	h.now = h.now.Add(2 * time.Hour)
	h.events = nil
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "expired"); err != nil {
		t.Fatalf("deleting a group whose grant expired: %v", err)
	}
	if len(h.events) != 1 || len(h.events[0].DeletedGroups) != 1 || len(h.events[0].Revoked) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
}

func TestAConstraintStopsManagingGroups(t *testing.T) {
	h := grouped(t, constrain("frozen", rbac.ManageGroups))
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", rbac.GroupDefinition{ID: "ops", Name: "Operations"}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("SetGroup: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "ops"); !errors.Is(err, rbac.ErrDenied) {
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
	admins := rbac.GroupDefinition{ID: "admins", Privileged: true}
	// Making one needs ManagePrivilegedGroups, not ManageGroups alone.
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", admins); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a privileged group by an admin of ordinary groups: %v", err)
	}
	if err := h.authz.SetGroup(ctx, user("privileged"), "t1", admins); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetGroup(ctx, user("groups"), "t1", rbac.GroupDefinition{ID: "devs"}); err != nil {
		t.Fatal(err)
	}
	// Whether a group is privileged is set when it is made, and never after.
	for name, change := range map[string]func() error{
		"unmarking one": func() error {
			return h.authz.SetGroup(ctx, user("privileged"), "t1", rbac.GroupDefinition{ID: "admins"})
		},
		"marking one": func() error {
			return h.authz.SetGroup(ctx, user("privileged"), "t1", rbac.GroupDefinition{ID: "devs", Privileged: true})
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
	if err := h.authz.DeleteGroup(ctx, user("groups"), "t1", "admins"); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("deleting a privileged group as an admin of ordinary groups: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, user("privileged"), "t1", "admins"); err != nil {
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
