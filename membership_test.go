package rbac_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	mathrand "math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// grouped sets up a host whose catalog lets "groups" manage the tenant's groups, and "manager" the
// members of any, who administers the cluster too, so it can grant what the cluster's groups hold.
func grouped(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return groupedOn(t, pgtest.Open(t, ""), mutate...)
}

// groupedOn is grouped on a pool of the test's own.
func groupedOn(t *testing.T, pool *pgxpool.Pool, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	h := setupOn(t, pool, append([]func(*rbac.Config){func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groups, groupMembers)
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
	}}, mutate...)...)
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "groups"),
		grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "manager"), grant(cluster.Scope(), "cluster.admin", rbac.User, "manager"))
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
		"a group":                {Principal: groupOf("g")},
		"the members":            {Principal: rbac.TenantMembers("t1")},
		"the public":             {Principal: rbac.Principal{Kind: rbac.Public}},
		"an undeclared kind":     {Principal: rbac.Principal{Kind: "robot", ID: "r"}},
		"no id":                  {Principal: rbac.Principal{Kind: rbac.User}},
		"already expired":        {Principal: identity("v"), ExpiresAt: h.now.Add(-time.Minute)},
		"expiring past 9999":     {Principal: identity("v"), ExpiresAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
		"expiring on 9999-12-31": {Principal: identity("v"), ExpiresAt: time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)},
		"a malformed source":     {Principal: identity("v"), Source: "Directory"},
		"a reserved source":      {Principal: identity("v"), Source: "rbac.sync"},
	} {
		if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{m}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := h.authz.SetMemberships(ctx, rbac.Principal{Kind: rbac.Group, ID: "g"}, "t1", []rbac.Membership{{Principal: identity("v")}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a group as actor: %v", err)
	}
}

// Memberships of named principals, and SetMemberships, read only their memberships under a generic
// plan: one plan for a tenant's every membership and for a few principals' reads every one to find
// theirs, and the keys a change sets, joined to the tenant's memberships to find those it makes or
// widens, read every one.
func TestMembershipsOfNamedPrincipalsUnderAGenericPlanReadOnlyTheirs(t *testing.T) {
	h := generic(t, banks)
	ctx := t.Context()
	ann := h.as(t, "ann")
	// The pages of memberships each reads, in a transaction it rolls back.
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range map[string]func(a *rbac.Authorizer) error{
			"Memberships": func(a *rbac.Authorizer) error {
				ms, err := a.Memberships(ctx, "t1", []rbac.Principal{ann.Principal, identity("new")})
				if err == nil && len(ms) != 1 {
					err = fmt.Errorf("Memberships = %+v", ms)
				}
				return err
			},
			// A suspended member's, which widens what it holds once lifted where none was, and one made.
			"SetMemberships": func(a *rbac.Authorizer) error {
				return a.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: ann.Principal, Suspended: true}, {Principal: identity("new")}})
			},
		} {
			// Rolled back on a failure too: a transaction left open keeps its connection, which the
			// pool's cleanup would wait on.
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				start := pagesRead(ctx, t, tx, "rbac_memberships")
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				pages[what] = pagesRead(ctx, t, tx, "rbac_memberships") - start
			}()
		}
		return pages
	}
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `SELECT 1`)
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages of memberships, and %d once 4500 more were members", what, few[what], many)
		}
	}
}

// Memberships of a principal reads only its own once its connection has listed the tenant's: as
// one statement, the plan PostgreSQL caches for the listing, generic once it has run five times,
// would read a principal's too, reading every membership.
func TestMembershipsOfAPrincipalReadOnlyItsOwnOnceItsConnectionListedEvery(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	ann := h.as(t, "ann")
	manyMembers(t, h, 5000, `SELECT 1`)
	// The pages of memberships reading ann's reads, in a transaction it rolls back.
	read := func() int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_memberships")
		if ms, err := h.authz.WithTx(tx).Memberships(ctx, "t1", []rbac.Principal{ann.Principal}); err != nil || len(ms) != 1 {
			t.Fatalf("Memberships = %+v, %v", ms, err)
		}
		return pagesRead(ctx, t, tx, "rbac_memberships") - start
	}
	before := read()
	for range 5 {
		if _, err := h.authz.Memberships(ctx, "t1", nil); err != nil {
			t.Fatal(err)
		}
	}
	if after := read(); after > 2*before {
		t.Errorf("reading ann's membership read %d pages, and %d once the tenant's were listed five times", before, after)
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
		"expiring past 9999":                 {Group: "a", Principal: identity("v"), ExpiresAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
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

func TestAPrincipalIsInAGroupABoundedNumberOfTimes(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	h.groups(t, "devs")
	h.join(t, "u")
	manager := h.as(t, "manager")
	until := func(from, n int) []rbac.Member {
		ms := make([]rbac.Member, n)
		for i := range ms {
			ms[i] = rbac.Member{Group: "devs", Principal: identity("u"), Source: fmt.Sprint("s", from+i), ExpiresAt: h.now.Add(time.Duration(from+i+1) * time.Hour)}
		}
		return ms
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", until(0, rbac.MaxPlacesInGroup), nil); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", until(rbac.MaxPlacesInGroup, 1), nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a place past the limit: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", until(rbac.MaxPlacesInGroup, 1)); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an import past the limit: %v", err)
	}
	// The host's own count apart, so the tenant's admins can't keep them from being made.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "devs", Principal: identity("u"), Source: "directory"}}); err != nil {
		t.Fatalf("a place from the host's source at the limit: %v", err)
	}
	// Adding one it has again stays possible at the limit.
	again := until(0, 1)
	again[0].Note = "renewed"
	if err := h.authz.ChangeMembers(ctx, manager, "t1", again, nil); err != nil {
		t.Fatalf("a new note at the limit: %v", err)
	}
	// Past it, as written around the package, a place made to end sooner, or whose note alone
	// changes, adds none.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source) VALUES ('t1', 'devs', 'user', 'u', 'past')`); err != nil {
		t.Fatal(err)
	}
	again[0].Note = "past the limit"
	if err := h.authz.ChangeMembers(ctx, manager, "t1", again, nil); err != nil {
		t.Fatalf("a new note past the limit: %v", err)
	}
	again[0].ExpiresAt = again[0].ExpiresAt.Add(-time.Minute)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", again, nil); err != nil {
		t.Fatalf("a place made to end sooner past the limit: %v", err)
	}
	again[0].ExpiresAt = again[0].ExpiresAt.Add(time.Hour)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", again, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a place made to last longer past the limit: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_members WHERE tenant = 't1' AND source = 'past'`); err != nil {
		t.Fatal(err)
	}
	// Places that have ended don't count.
	h.now = h.now.Add(time.Duration(rbac.MaxPlacesInGroup) * time.Hour)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", until(rbac.MaxPlacesInGroup, 1), nil); err != nil {
		t.Fatalf("a place once the others ended: %v", err)
	}
}

func TestAPrincipalIsInABoundedNumberOfGroups(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	h.groups(t, "inner", "more")
	h.join(t, "u")
	// u and inner are each in as many groups as they may be, for an hour, written around the hooks.
	if _, err := h.pool.Exec(ctx, `WITH g AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'g' || i FROM generate_series(1, $1::int) i RETURNING id)
		INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		SELECT 't1', id, k, p, $2 FROM g, (VALUES ('user', 'u'), ('group', 'inner')) AS m(k, p)`, rbac.MaxGroupsOfPrincipal, h.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	in := func(group string, p rbac.Principal, source string) []rbac.Member {
		return []rbac.Member{{Group: group, Principal: p, Source: source}}
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", in("more", identity("u"), ""), nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("joining a group past the limit: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", in("more", identity("u"), "")); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("an import past the limit: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", in("more", groupOf("inner"), "")); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("nesting a group past the limit: %v", err)
	}
	// The host's own count apart, so the tenant's admins can't keep them from being made.
	if err := h.authz.ImportMembers(ctx, host, "t1", in("more", identity("u"), "directory")); err != nil {
		t.Errorf("a place from the host's source at the limit: %v", err)
	}
	// Another place in a group it is in is in no more groups.
	if err := h.authz.ChangeMembers(ctx, manager, "t1", in("g1", identity("u"), "other"), nil); err != nil {
		t.Errorf("another place in a group at the limit: %v", err)
	}
	// Past it, as written around the package, a place made to end sooner, or whose note alone
	// changes, is in no more groups either.
	h.groups(t, "past")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'past', 'user', 'u')`); err != nil {
		t.Fatal(err)
	}
	place := []rbac.Member{{Group: "g2", Principal: identity("u"), ExpiresAt: h.now.Add(30 * time.Minute)}}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", place, nil); err != nil {
		t.Errorf("a place made to end sooner past the limit: %v", err)
	}
	place[0].Note = "past the limit"
	if err := h.authz.ChangeMembers(ctx, manager, "t1", place, nil); err != nil {
		t.Errorf("a new note past the limit: %v", err)
	}
	place[0].ExpiresAt = h.now.Add(45 * time.Minute)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", place, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a place made to last longer past the limit: %v", err)
	}
	if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "past", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// Places that have ended don't count.
	h.now = h.now.Add(time.Hour)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", in("more", identity("u"), ""), nil); err != nil {
		t.Errorf("a group once the others' places ended: %v", err)
	}
}

// A change adding a place counts the groups its principal is in from the index on the principal
// alone, its source included, so it reads none of the rows of the places the principal has.
func TestCountingAPrincipalsGroupsReadsTheIndexAlone(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "extra")
	h.join(t, "u")
	manager := h.as(t, "manager")
	// u is in all the groups it may be in but one, each of a hundred members, so its place in each
	// is on a page of the others'.
	in := rbac.MaxGroupsOfPrincipal - 1
	for _, q := range []string{
		`INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'g' || i FROM generate_series(1, $1::int) i`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		 SELECT 't1', 'g' || i, 'user', CASE WHEN j = 0 THEN 'u' ELSE 'o' || j END FROM generate_series(1, $1::int) i, generate_series(0, 99) j
		 ORDER BY i, j`,
	} {
		if _, err := h.pool.Exec(ctx, q, in); err != nil {
			t.Fatal(err)
		}
	}
	// So the visibility map lets a scan of an index skip the rows.
	visibleToAll(t, h, "rbac_members", `VACUUM (ANALYZE) rbac_members`)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The pages of the table itself, not its indexes: its rows and its visibility map.
	rows := func() int64 {
		t.Helper()
		var n int64
		if err := tx.QueryRow(ctx, `SELECT pg_stat_get_xact_blocks_fetched('rbac_members'::regclass)`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	start := rows()
	if err := h.authz.WithTx(tx).ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "extra", Principal: identity("u")}}, nil); err != nil {
		t.Fatal(err)
	}
	if read := rows() - start; read > int64(in/10) {
		t.Errorf("adding a place for a principal in %d groups read %d pages of the table's rows", in, read)
	}
}

// Migrating the index on the principal waits for a change in flight that has read the places and
// then writes one, as a change to members does under its locks, rather than deadlock with it.
func TestMigratingTheMembersIndexWaitsForAChangeInFlight(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0014")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'crew')`); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(ctx) }()
	var pid int
	if err := writer.QueryRow(ctx, `SELECT pg_backend_pid() FROM rbac_members WHERE tenant = 't1' AND principal = 'user:u' UNION ALL SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- applyMigrations(ctx, pool, pgx.ReadCommitted, "0014", "") }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("migrating never waited for the change")
		}
	}
	if _, err := writer.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'crew', 'user', 'u')`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("migrating while a change that read the places writes one: %v", err)
	}
}

// rolesAfterDenies is a pool whose transactions run fire, once, just before the first statement
// naming rbac_roles that follows one naming rbac_denies or rbac_eligibilities.
type rolesAfterDenies struct {
	*pgxpool.Pool
	fire func()
}

func (p *rolesAfterDenies) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := p.Pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &rolesAfterDeniesTx{Tx: tx, p: p}, nil
}

type rolesAfterDeniesTx struct {
	pgx.Tx
	p      *rolesAfterDenies
	denies bool
}

func (tx *rolesAfterDeniesTx) see(sql string) {
	if roles := strings.Contains(sql, "rbac_roles"); roles && tx.denies && tx.p.fire != nil {
		fire := tx.p.fire
		tx.p.fire = nil
		fire()
	} else if !roles && (strings.Contains(sql, "rbac_denies") || strings.Contains(sql, "rbac_eligibilities")) {
		tx.denies = true
	}
}

func (tx *rolesAfterDeniesTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.see(sql)
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx *rolesAfterDeniesTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.see(sql)
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx *rolesAfterDeniesTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.see(sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

// A migration locking a custom role's tables, rbac_roles first, as 0016 does, while ChangeMembers
// has read the denies and eligibilities and is to read the custom roles, waits a moment for the
// denies and gives way, so the change goes on, and Migrate tries again once it has: neither
// deadlocks, which PostgreSQL would end one of the two for.
func TestMigrateGivesWayToAChangeReadingItsTablesInAnotherOrder(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	migrateFiles(t, pool, "", "0016")
	recordMigrations(t, pool, "0016")
	// This release's ChangeMembers reads the denies through rbac_changes_grants, which 0021 makes:
	// the schema has it, as 0021 makes it, until the migration starts, which makes it again.
	grants, err := fs.ReadFile(rbac.Migrations(), "0021_grant_denies.sql")
	if err != nil {
		t.Fatal(err)
	}
	function, _, _ := strings.Cut(string(grants), "\n\nCREATE INDEX")
	if _, err := pool.Exec(ctx, function); err != nil {
		t.Fatal(err)
	}
	db := &rolesAfterDenies{Pool: pool}
	cfg := rbac.Config{
		Catalog:        append(slices.Clone(catalog), groupMembers),
		ContainerTypes: []string{"org", "workspace"},
		ValidateGrant:  func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	}
	authz, err := rbac.New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{ctx: ctx, pool: pool, authz: authz, cfg: cfg}
	h.groups(t, "g")
	h.as(t, "u")
	manager := h.as(t, "manager")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'tenant', 't1', 'user', 'manager', 'group.members')`); err != nil {
		t.Fatal(err)
	}
	migrated := make(chan error, 1)
	db.fire = func() {
		if _, err := pool.Exec(ctx, `DROP FUNCTION rbac_changes_grants(text[])`); err != nil {
			migrated <- err
			return
		}
		go func() { migrated <- rbac.Migrate(context.WithoutCancel(ctx), pool) }()
		// Until the migration, holding rbac_roles, waits for a table this transaction read.
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
			var waiting bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
				WHERE NOT l.granted AND c.relname IN ('rbac_denies', 'rbac_eligibilities') AND c.relnamespace = current_schema()::regnamespace)`).Scan(&waiting); err != nil {
				t.Error(err)
				return
			}
			if waiting {
				return
			}
			if time.Now().After(deadline) {
				t.Error("the migration never waited for the change")
				return
			}
		}
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "g", Principal: identity("u")}}, nil); err != nil {
		t.Errorf("ChangeMembers while migrating: %v", err)
	}
	if db.fire != nil {
		t.Fatal("ChangeMembers never read the custom roles after the denies in its transaction")
	}
	if err := <-migrated; err != nil {
		t.Errorf("Migrate while a change reads the tables: %v", err)
	}
}

// Migrate gives up on a lock it can't take, after as many tries as it makes, rather than wait as
// long as what holds it runs, while every statement reading the tables it locked meanwhile waits.
func TestMigrateGivesUpOnALockHeldTooLong(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	migrateFiles(t, pool, "", "0016")
	recordMigrations(t, pool, "0016")
	rbac.SetMigrateAttempts(t, 3, time.Millisecond)
	// A read holds rbac_denies, which 0016 locks, until it ends, holding no transaction id.
	reader, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback(ctx) }()
	if _, err := reader.Exec(ctx, `SELECT FROM rbac_denies LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	waited, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var pg *pgconn.PgError
	if err := rbac.Migrate(waited, pool); !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
		t.Fatalf("Migrate while a read holds a table it locks: %v", err)
	}
	if err := reader.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate once the read has ended: %v", err)
	}
}

// On a host's transaction, a table the migration waits for can be held by a transaction waiting
// for what the host's transaction holds, which rolling back to Migrate's savepoint doesn't free:
// Migrate waits there, so PostgreSQL ends the other as a deadlock, rather than give way until it
// gives up while the other waits on. So it does through a host's wrapper around its transaction,
// whose Begin gives a savepoint of it, which can set the isolation the transaction is at again.
func TestMigrateOnAHostsTransactionLetsPostgreSQLEndADeadlockWithIt(t *testing.T) {
	for name, wrap := range map[string]func(pgx.Tx) rbac.DB{
		"the host's transaction":                  func(tx pgx.Tx) rbac.DB { return tx },
		"a wrapper around the host's transaction": func(tx pgx.Tx) rbac.DB { return hostTx{tx} },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			pool := pgtest.Open(t, "")
			migrateFiles(t, pool, "", "0016")
			recordMigrations(t, pool, "0016")
			// So a Migrate that gave way would give up at once.
			rbac.SetMigrateAttempts(t, 2, time.Millisecond)
			if _, err := pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'u')`); err != nil {
				t.Fatal(err)
			}
			host, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = host.Rollback(ctx) }()
			if _, err := host.Exec(ctx, `UPDATE rbac_memberships SET note = 'host' WHERE principal = 'user:u'`); err != nil {
				t.Fatal(err)
			}
			// Another has read rbac_denies, which 0016 locks, and waits for the row the host's changed.
			other, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = other.Rollback(ctx) }()
			if _, err := other.Exec(ctx, `SELECT FROM rbac_denies LIMIT 1`); err != nil {
				t.Fatal(err)
			}
			pid := other.Conn().PgConn().PID()
			done := make(chan struct{})
			var waited error
			go func() {
				defer close(done)
				_, waited = other.Exec(ctx, `UPDATE rbac_memberships SET note = 'other' WHERE principal = 'user:u'`)
			}()
			// Before other's rollback, its wait ends with the host's.
			defer func() { _ = host.Rollback(ctx); <-done }()
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
				var waiting bool
				if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the other transaction never waited for the host's")
				}
			}
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			migrated := rbac.Migrate(bounded, wrap(host))
			if err := host.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			<-done
			if migrated != nil {
				t.Errorf("Migrate on %s: %v", name, migrated)
			}
			if pg := (*pgconn.PgError)(nil); !errors.As(waited, &pg) || pg.Code != "40P01" {
				t.Errorf("the transaction waiting for the host's: %v", waited)
			}
		})
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

// An identity that leaves a tenant leaves the denies that exempt it and the approvers of what it
// approves: exempt by its own key from a deny on the public, it would otherwise read, as an
// outsider, what the deny takes from every other, and joining again it would approve again. A deny
// naming it still does.
func TestLeavingATenantEndsItsExemptionsAndApprovals(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	for name, leave := range map[string]func(ctx context.Context, h *harness) error{
		"DeletePrincipal": func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipal(ctx, host, "t1", identity("x"))
		},
		"DeletePrincipalEverywhere": func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, identity("x"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, guardRole) })
			ctx := t.Context()
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.viewer", rbac.Public, ""), grant(cluster.Scope(), "guard", rbac.User, "owner"))
			owner, x, u, w := h.as(t, "owner"), h.as(t, "x"), h.as(t, "u"), h.as(t, "w")
			for _, d := range []rbac.Deny{
				{ID: "no-public", Principals: []rbac.Principal{{Kind: rbac.Public}}, Exempt: []rbac.Principal{rbac.TenantMembers("t1"), x.Principal}, Permissions: []rbac.Permission{view}},
				{ID: "watched", Principals: []rbac.Principal{x.Principal, u.Principal}, Permissions: []rbac.Permission{root}},
			} {
				if err := h.authz.SetDeny(ctx, owner, cluster, d); err != nil {
					t.Fatal(err)
				}
			}
			for _, e := range []rbac.Eligibility{
				{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{x.Principal}},
				{Role: "cluster.sudo", Principal: w.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{identity("lead"), x.Principal}},
			} {
				if err := h.authz.SetEligibility(ctx, owner, cluster, e); err != nil {
					t.Fatal(err)
				}
			}
			// In another tenant, x is in nothing but a deny's exemptions and an eligibility's approvers.
			for _, q := range []string{
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
				 VALUES ('t2', 'cluster', 'c1', 'd', '{public:}', '{user:x}', '{cluster:view}')`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
				 VALUES ('t2', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 3600, '{user:lead,user:x}')`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			h.events = nil
			if err := leave(ctx, h); err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, x, view, cluster) {
				t.Error("x left and reads, as an outsider, what the deny takes from every other")
			}
			ds, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
			if err != nil || len(ds) != 2 || !slices.Equal(ds[0].Exempt, []rbac.Principal{rbac.TenantMembers("t1")}) ||
				!slices.Equal(ds[1].Principals, []rbac.Principal{u.Principal, x.Principal}) {
				t.Fatalf("Denies = %+v, %v", ds, err)
			}
			es, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
			if err != nil || len(es) != 1 || es[0].Principal != w.Principal || !slices.Equal(es[0].Approvers, []rbac.Principal{identity("lead")}) {
				t.Fatalf("Eligibilities = %+v, %v", es, err)
			}
			var e rbac.ChangeEvent
			for _, ev := range h.events {
				if ev.Tenant == "t1" {
					e = ev
				}
			}
			if len(e.Denies) != 1 || len(e.Eligible) != 1 || len(e.Ineligible) != 1 || e.Ineligible[0].Principal != u.Principal {
				t.Fatalf("event = %+v", e)
			}
			h.as(t, "x")
			if _, err := h.authz.Activate(ctx, w, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "x", Approver: x}); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("x left and joined again, and approves as before: %v", err)
			}
			if name != "DeletePrincipalEverywhere" {
				return
			}
			if ds, err := h.authz.Denies(ctx, "t2", []rbac.Scope{cluster.Scope()}); err != nil || len(ds) != 1 || len(ds[0].Exempt) != 0 {
				t.Errorf("Denies in a tenant x was only exempt in = %+v, %v", ds, err)
			}
			if es, err := h.authz.Eligibilities(ctx, "t2", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || len(es) != 1 ||
				!slices.Equal(es[0].Approvers, []rbac.Principal{identity("lead")}) {
				t.Errorf("Eligibilities in a tenant x only approved in = %+v, %v", es, err)
			}
		})
	}
}

// Leaving a tenant reads, of its denies, only those that exempt whom leaves, and of its grants and
// places in groups, only its own and the activations its places allowed, under a generic plan too:
// no btree finds a key in exempt, and beside tenant = $1 a plan, costing the tenant's rows by
// averages, would read every deny. Not the eligibilities: under a generic plan, deleting the
// leaver's own in order (inOrder) reads every one in the tenant.
func TestLeavingUnderAGenericPlanReadsOnlyWhatNamesTheLeaver(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	h.groups(t, "oncall", "everyone")
	x := h.as(t, "x", "oncall")
	// oncall is in everyone, which is eligible on the cluster, where x activated through it; x and
	// oncall approve an eligibility there and are exempt from a deny.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'everyone', 'group', 'oncall')`, nil},
		{`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		  VALUES ('t1', 'cluster', 'c1', 'group', 'everyone', 'cluster.sudo', 7200, '{}'),
		         ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.sudo', 3600, '{user:x,group:oncall,user:lead}')`, nil},
		{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.sudo', 'activation', $1, 'group:everyone')`, []any{h.now.Add(time.Hour)}},
		{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		  VALUES ('t1', 'cluster', 'c1', 'd', '{public:}', '{user:x,group:oncall}', '{cluster:root}')`, nil},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members"}
	// The pages of each, and their indexes, each reads, in a transaction it rolls back.
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range map[string]func(a *rbac.Authorizer) error{
			"DeletePrincipal": func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", x.Principal) },
			// Which ends x's activation, through oncall's place in everyone.
			"DeletePrincipal of a group": func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", groupOf("oncall")) },
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range tables {
					pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
				}
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range tables {
					pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
				}
				var left int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM rbac_grants WHERE tenant = 't1' AND source = 'activation'`).Scan(&left); err != nil || left != 0 {
					t.Fatalf("%s left %d activations, %v", what, left, err)
				}
			}()
		}
		return pages
	}
	// Others are in everyone, and each holds a grant on a cluster of its own, approves an eligibility
	// there and is exempt from a deny there.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others),
			granted AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others),
			eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, ARRAY['user:' || id] FROM others)
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			SELECT 't1', 'cluster', id, 'd', '{public:}', ARRAY['user:' || id], '{cluster:root}' FROM others`, tables...)
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages, and %d once 4500 more were granted, approving, exempt and in a group", what, few[what], many)
		}
	}
}

// A change adding identities to a group reads only their memberships, under a generic plan too,
// each looked up on its own: a generic plan costing a tenant's memberships as an average tenant's few
// would read every one of them into a hash, to look each identity up there.
func TestJoiningUnderAGenericPlanReadsOnlyTheJoinersMemberships(t *testing.T) {
	h := generic(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers) })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "manager"))
	manager := h.as(t, "manager")
	h.groups(t, "crew")
	h.as(t, "x")
	h.as(t, "y")
	joining := []rbac.Member{{Group: "crew", Principal: identity("x")}, {Group: "crew", Principal: identity("y")}}
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range map[string]func(a *rbac.Authorizer) error{
			"ChangeMembers": func(a *rbac.Authorizer) error { return a.ChangeMembers(ctx, manager, "t1", joining, nil) },
			"ImportMembers": func(a *rbac.Authorizer) error { return a.ImportMembers(ctx, host, "t1", joining) },
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				pages[what] -= pagesRead(ctx, t, tx, "rbac_memberships")
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				pages[what] += pagesRead(ctx, t, tx, "rbac_memberships")
			}()
		}
		return pages
	}
	manyMembers(t, h, 500, `SELECT`)
	few := read()
	manyMembers(t, h, 4500, `SELECT`)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages of memberships, and %d once 4500 more were members", what, few[what], many)
		}
	}
}

// Activate through a nested group, and the changes ending a place in a group or a membership an
// activation rests on, read of the grants, places, memberships and eligibilities only those of the
// identities whose activations they make or check, and the paths up from them, under a generic plan
// too: joined to the arguments, or beside the tenant, a generic plan costing them by averages would
// read every activation, place or membership in the tenant.
func TestActivationsUnderAGenericPlanReadOnlyTheirHoldersPaths(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	h.groups(t, "oncall", "everyone")
	ann := h.as(t, "ann", "inner")
	bob := h.as(t, "bob", "inner")
	// inner is in oncall, which is eligible on the cluster, where bob activated through it.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'oncall', 'group', 'inner')`, nil},
		{`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		  VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.sudo', 7200)`, nil},
		{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'bob', 'cluster.sudo', 'activation', $1, 'group:oncall')`, []any{h.now.Add(time.Hour)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	soon := h.now.Add(30 * time.Minute)
	tables := []string{"rbac_grants", "rbac_members", "rbac_memberships", "rbac_eligibilities"}
	// The pages of each, and their indexes, each reads, in a transaction it rolls back.
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, c := range map[string]struct {
			f func(a *rbac.Authorizer) error
			// ends is when bob's activation ends once it has run, zero for ended.
			ends time.Time
		}{
			"Activate": {f: func(a *rbac.Authorizer) error {
				return second(a.Activate(ctx, ann, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}))
			}, ends: h.now.Add(time.Hour)},
			"DeleteMembers": {f: func(a *rbac.Authorizer) error {
				return a.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "inner", Principal: bob.Principal}})
			}},
			"ImportMembers ending a group's place sooner": {f: func(a *rbac.Authorizer) error {
				return a.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner"), ExpiresAt: soon}})
			}, ends: soon},
			"SetMemberships ending a membership sooner": {f: func(a *rbac.Authorizer) error {
				return a.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: bob.Principal, ExpiresAt: soon}})
			}, ends: soon},
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range tables {
					pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
				}
				if err := c.f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range tables {
					pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
				}
				var ends *time.Time
				if err := tx.QueryRow(ctx, `SELECT max(expires_at) FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:bob'`).Scan(&ends); err != nil ||
					(ends == nil) != c.ends.IsZero() || ends != nil && !ends.Equal(c.ends) {
					t.Fatalf("%s left bob's activation ending at %v, %v", what, ends, err)
				}
			}()
		}
		return pages
	}
	// Others are in a group of their own, in everyone, and each activated, through everyone, on a
	// cluster of its own, where everyone is eligible.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, groups AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'g' || id FROM others),
			members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'g' || id, 'user', id FROM others UNION ALL SELECT 't1', 'everyone', 'group', 'g' || id FROM others),
			eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
			  SELECT 't1', 'cluster', id, 'group', 'everyone', 'cluster.sudo', 3600 FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
			SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 'activation', '2026-01-01 13:00:00+00', 'group:everyone' FROM others`,
			"rbac_groups", "rbac_grants", "rbac_members", "rbac_eligibilities")
	}
	// Measured at three sizes, as a plan that reads the tenant's activations by the index on them
	// alone, costing it as an average tenant's few, is picked only while they are few.
	others(50)
	few := read()
	for _, n := range []int{450, 4500} {
		others(n)
		for what, many := range read() {
			if many > few[what]*3/2+deeper {
				t.Errorf("%s read %d pages, and %d once %d more were in groups and activated", what, few[what], many, n)
			}
		}
	}
}

// Where labels are declared, a change to members reads, of the activations whose scopes' labels it
// checks, only those of the identities leaving and of those in the groups leaving, under a generic
// plan too: found by the group they were made through, or beside the tenant, a plan costing them by
// averages would read every activation in the tenant.
func TestLeavingUnderAGenericPlanReadsOnlyTheLeaversActivations(t *testing.T) {
	h := generic(t, withLabels, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers) })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.groups(t, "oncall")
	admin := h.as(t, "admin")
	bob := h.as(t, "bob", "inner")
	h.as(t, "ann", "inner")
	// inner is in oncall, through which bob activated on the cluster.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'oncall', 'group', 'inner')`, nil},
		{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'bob', 'cluster.sudo', 'activation', $1, 'group:oncall')`, []any{h.now.Add(time.Hour)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"rbac_grants", "rbac_members"}
	// The pages of each, and their indexes, each reads, in a transaction it rolls back.
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range map[string]func(a *rbac.Authorizer) error{
			"removing bob": func(a *rbac.Authorizer) error {
				return a.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "inner", Principal: bob.Principal}})
			},
			"ending bob's place sooner": func(a *rbac.Authorizer) error {
				return a.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "inner", Principal: bob.Principal, ExpiresAt: h.now.Add(time.Minute)}}, nil)
			},
			"removing bob's group": func(a *rbac.Authorizer) error {
				return a.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}})
			},
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range tables {
					pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
				}
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range tables {
					pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
				}
			}()
		}
		return pages
	}
	// Others are in oncall, and each activated through it on a cluster of its own.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'oncall', 'user', id FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
			SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 'activation', '2026-01-01 13:00:00+00', 'group:oncall' FROM others`, tables...)
	}
	// Measured at three sizes, as a plan that reads the tenant's activations by the index on them
	// alone, costing it as an average tenant's few, is picked only while they are few.
	others(50)
	few := read()
	for _, n := range []int{450, 4500} {
		others(n)
		for what, many := range read() {
			if many > few[what]*3/2+deeper {
				t.Errorf("%s read %d pages, and %d once %d more were in oncall and activated through it", what, few[what], many, n)
			}
		}
	}
}

// A group removed from a tenant's grants and groups leaves the denies that exempt it too, but the
// tenant's members, whose grants are removed, stay exempt: they leave nothing.
func TestDeletingAPrincipalTakesOnlyAGroupOrIdentityOutOfExemptions(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	h.groups(t, "staff")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	if err := h.authz.SetDeny(ctx, h.as(t, "owner"), cluster, rbac.Deny{
		ID: "no-public", Principals: []rbac.Principal{{Kind: rbac.Public}}, Exempt: []rbac.Principal{rbac.TenantMembers("t1"), groupOf("staff")},
		Permissions: []rbac.Permission{view},
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []rbac.Principal{groupOf("staff"), rbac.TenantMembers("t1")} {
		if err := h.authz.DeletePrincipal(ctx, host, "t1", p); err != nil {
			t.Fatal(err)
		}
	}
	if ds, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil || len(ds) != 1 ||
		!slices.Equal(ds[0].Exempt, []rbac.Principal{rbac.TenantMembers("t1")}) {
		t.Fatalf("Denies = %+v, %v", ds, err)
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

// DeleteGroups reads, of the tenant's grants and places in groups, only the groups' own, under a
// generic plan too: a group's grants and those on it, and its members and its places in other
// groups, are found by conditions ORed that no index seeks, and deleted matched to them in a join,
// which a plan, costing the tenant's rows by averages, runs by reading every one.
func TestDeletingAGroupUnderAGenericPlanReadsOnlyItsGrantsAndPlaces(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	h.groups(t, "small", "everyone")
	h.as(t, "ann", "small")
	// small is in everyone, holds a grant and is granted on.
	for _, q := range []string{
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'everyone', 'group', 'small')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  VALUES ('t1', 'cluster', 'c1', 'group', 'small', 'cluster.login'), ('t1', 'group', 'small', 'user', 'ann', 'group.owner')`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"rbac_grants", "rbac_members"}
	// The pages of each that deleting small reads, in a transaction it rolls back.
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		for _, table := range tables {
			pages[table] -= pagesRead(ctx, t, tx, table)
		}
		if err := h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"small"}); err != nil {
			t.Fatal(err)
		}
		for _, table := range tables {
			pages[table] += pagesRead(ctx, t, tx, table)
		}
		var left int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM rbac_grants WHERE 'group:small' IN (principal, scope))
			+ (SELECT count(*) FROM rbac_members WHERE 'small' = group_id OR 'group:small' = principal)`).Scan(&left); err != nil || left != 0 {
			t.Fatalf("%d grants and places name small once it was deleted, %v", left, err)
		}
		return pages
	}
	// Others are in everyone, and hold a grant on the tenant and one on a cluster each.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others
			UNION ALL SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others`, tables...)
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("deleting small read %d pages of %s, and %d once 4500 more were in another group and granted", few[what], what, many)
		}
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
	for _, id := range []string{"denied", "exempt", "synced", "nested", "placed", "managed", "expired"} {
		if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "engineering", Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	// A place in the host's group is the host's to change, from whatever source.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "synced", Principal: identity("u"), Source: "directory"},
		{Group: "engineering", Principal: groupOf("nested"), Source: "directory"},
		{Group: "engineering", Principal: groupOf("placed")},
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
	for _, id := range []string{"denied", "exempt", "synced", "nested", "placed", "managed"} {
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

// An activation outlasts the eligibility it was made through, resting on its holder's place in
// that one's group, or in one in it: deleting either group would end it, so DeleteGroup refuses
// both while it lasts, as it refuses a group holding a grant, but not a group whose members hold
// none.
func TestDeleteGroupRefusesAGroupAnActivationRestsOn(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "crew", "outer", "spare")
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "crew", Principal: identity("u")},
		{Group: "outer", Principal: groupOf("crew")},
		{Group: "spare", Principal: identity("v")},
		{Group: "outer", Principal: groupOf("spare")},
	}); err != nil {
		t.Fatal(err)
	}
	owner := h.as(t, "owner")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("outer"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	u := rbac.Subject{Principal: identity("u")}
	if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "INC-1"}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteEligibility(ctx, owner, cluster, "cluster.sudo", groupOf("outer")); err != nil {
		t.Fatal(err)
	}
	groupManager := h.as(t, "groups")
	for _, id := range []string{"crew", "outer"} {
		if err := h.authz.DeleteGroup(ctx, groupManager, "t1", id); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("deleting %s while an activation made through outer rests on it: %v", id, err)
		}
	}
	if !allowed(t, h, u, root, cluster) {
		t.Fatal("u's activation should still give it root on the cluster")
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "spare"); err != nil {
		t.Errorf("deleting a group in outer whose members hold no activation: %v", err)
	}
	if err := h.authz.Deactivate(ctx, u, cluster, "cluster.sudo"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"crew", "outer"} {
		if err := h.authz.DeleteGroup(ctx, groupManager, "t1", id); err != nil {
			t.Errorf("deleting %s once the activation ended: %v", id, err)
		}
	}
}

// DeleteGroup holds the places in the group and of it before it reads the activations resting on
// them, which Activate holds until it commits: one that commits while the deletion waits for them,
// made through an eligibility of a group it is in that the host deleted meanwhile, refuses the
// deletion, as one made before it does, rather than be ended by it.
func TestDeleteGroupRefusesAnActivationThatCommitsWhileItWaitsForItsPlaces(t *testing.T) {
	var armed atomic.Bool
	paused := make(chan heldActivation, 1)
	h := grouped(t, pausingActivation(&armed, paused))
	ctx := t.Context()
	h.groups(t, "crew", "oncall")
	u := h.as(t, "u", "crew")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("crew")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	a, activated := activateAsTheHostDeletes(t, h, &armed, paused, u, cluster, "cluster.sudo", groupOf("oncall"))
	deleted := make(chan error, 1)
	go func() { deleted <- h.authz.DeleteGroup(ctx, h.as(t, "groups"), "t1", "crew") }()
	waitedOn(t, h, a.pid, deleted)
	close(a.release)
	if err := <-activated; err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := <-deleted; !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting crew while an activation made through oncall, which it is in, committed: %v", err)
	}
	if !allowed(t, h, u, root, cluster) {
		t.Fatal("u's activation should still give it root on the cluster")
	}
}

// A place from a source only the host changes, or in a group of the host's, gives nothing once it
// has ended, as an expired grant doesn't, so DeleteGroup deletes the group with it rather than
// refuse it until DeleteExpired runs.
func TestDeleteGroupDeletesAGroupWhoseHostsPlacesHaveEnded(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	h.groups(t, "team", "other")
	h.join(t, "u")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "hosts", Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	// u in team and team in other from the directory, and team in the host's group, each for an hour.
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "team", Principal: identity("u"), Source: "directory", ExpiresAt: h.now.Add(time.Hour)},
		{Group: "other", Principal: groupOf("team"), Source: "directory", ExpiresAt: h.now.Add(time.Hour)},
		{Group: "hosts", Principal: groupOf("team"), ExpiresAt: h.now.Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	groupManager := h.as(t, "groups")
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "team"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a group the host keeps places of: %v", err)
	}
	h.now = h.now.Add(2 * time.Hour)
	h.events = nil
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "team"); err != nil {
		t.Fatalf("deleting a group whose places from the host have all ended: %v", err)
	}
	if len(h.events) != 1 || len(h.events[0].DeletedGroups) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_members WHERE tenant = 't1' AND (group_id = 'team' OR principal = 'group:team')`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d places of team are left once it was deleted, %v", left, err)
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

func TestManagingGroupsReadsTheTenantFromTheHost(t *testing.T) {
	groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	given := func(tenant rbac.Resource) func(*rbac.Config) {
		return func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), groups)
			resourceOf := c.ResourceOf
			c.ResourceOf = func(ctx context.Context, t string, s rbac.Scope) (rbac.Resource, error) {
				if s == tenant.Scope() {
					return tenant, nil
				}
				return resourceOf(ctx, t, s)
			}
		}
	}
	manage := func(t *testing.T, h *harness, want error) {
		t.Helper()
		ctx := t.Context()
		if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
			t.Fatal(err)
		}
		actor := h.as(t, "groups")
		if err := h.authz.SetGroup(ctx, actor, "t1", rbac.GroupDefinition{ID: "ops", Name: "Operations"}); !errors.Is(err, want) {
			t.Errorf("SetGroup: %v", err)
		}
		if err := h.authz.DeleteGroup(ctx, actor, "t1", "ops"); !errors.Is(err, want) {
			t.Errorf("DeleteGroup: %v", err)
		}
	}
	t.Run("a constraint", func(t *testing.T) {
		locked := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"locked": true}}
		h := setup(t, given(locked), func(c *rbac.Config) {
			c.Constraints = []rbac.Constraint{{Name: "locked", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				return in.Permission == rbac.ManageGroups && in.Resource != nil && in.Resource.Attributes["locked"] == true, nil
			}}}
		})
		h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "groups"))
		manage(t, h, rbac.ErrDenied)
	})
	t.Run("a label", func(t *testing.T) {
		h := labeled(t, given(rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Labels: rbac.Label{"level": {"high"}}}))
		h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "groups"))
		manage(t, h, rbac.ErrDenied)
		h.hold(t, "groups", "level:high")
		manage(t, h, nil)
	})
}

func TestNewRefusesAContainerNamedGroup(t *testing.T) {
	ok := func(context.Context, rbac.DB, rbac.GrantInput) error { return nil }
	if _, err := rbac.New(&pgxpool.Pool{}, rbac.Config{Catalog: catalog, ContainerTypes: []string{rbac.GroupScope}, ValidateGrant: ok}); err == nil {
		t.Fatal("New accepted a container type named as groups are")
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

// DeleteExpired removes what has expired a batch at a time, each in a transaction of its own,
// until none is left.
// A join holds the membership it joins with, so DeleteExpired passes over it until the join
// commits; one committing while DeleteExpired is taking the memberships, before it reaches that
// one, made a place the statement taking them can't see, which it removes with the membership.
func TestDeleteExpiredRemovesAPlaceAJoinMadeWhileItRan(t *testing.T) {
	rbac.SetExpiryBatch(t, 1_000_000)
	// Named, to watch its own statements among those of other tests on the server.
	app := "rbac_" + strings.ToLower(rand.Text())
	h := setupOn(t, pgtest.Open(t, "application_name="+app))
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	// Many memberships that end before u's, ahead of it in the table and its expiry index, which
	// the statement taking them reads first.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		SELECT 't1', 'user', 'other' || i, $1 FROM generate_series(1, 20000) i`, h.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
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
	h.now = h.now.Add(2 * time.Hour)
	expired := make(chan error, 1)
	go func() {
		_, err := h.authz.DeleteExpired(ctx)
		expired <- err
	}()
	for taking := false; !taking; {
		select {
		case err := <-expired:
			expired <- err
			taking = true
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name = $1 AND state = 'active'
				AND query LIKE '%FROM rbac_memberships%expires_at <= least%' AND pid <> pg_backend_pid())`, app).Scan(&taking); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-expired; err != nil {
		t.Fatal(err)
	}
	var memberships, places int
	if err := h.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM rbac_memberships WHERE principal = 'user:u'),
		(SELECT count(*) FROM rbac_members WHERE principal = 'user:u')`).Scan(&memberships, &places); err != nil {
		t.Fatal(err)
	}
	if memberships == 0 && places > 0 {
		t.Errorf("u's membership ended, but %d places of it stay", places)
	}
}

// A change holding a place in a group, as one removing it, may roll back: DeleteExpired, holding
// the memberships it picked, doesn't wait on it, but passes over that place's membership for the
// next run, rather than end it and leave the place.
func TestDeleteExpiredPassesOverAMembershipAChangeHoldsAPlaceOf(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	ending := h.now.Add(time.Hour)
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: ending}, {Principal: identity("v"), ExpiresAt: ending}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}, {ID: "b"}}); err != nil {
		t.Fatal(err)
	}
	places := []rbac.Member{{Group: "a", Principal: identity("u")}, {Group: "b", Principal: identity("u")}, {Group: "a", Principal: identity("v")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", places); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	held, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authz.WithTx(held).DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// A wait on held fails past lock_timeout.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
		t.Fatal(err)
	}
	if n, err := h.authz.WithTx(tx).DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("DeleteExpired while a change holds a place of u's = %d, %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 3 {
		t.Fatalf("DeleteExpired once the change rolled back = %d, %v", n, err)
	}
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_members`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d members left, %v", left, err)
	}
}

func TestDeleteExpiredRemovesABatchAtATime(t *testing.T) {
	rbac.SetExpiryBatch(t, 2)
	h := setup(t)
	ctx := t.Context()
	// Three expired grants, eligibilities, members and memberships, whose identities are members
	// too.
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		  SELECT 't1', 'cluster', 'c1', 'user', 'g' || i, 'cluster.login', $1 FROM generate_series(1, 3) i`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
		  SELECT 't1', 'cluster', 'c1', 'user', 'e' || i, 'cluster.login', 60, $1 FROM generate_series(1, 3) i`,
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'a')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		  SELECT 't1', 'a', 'user', 'm' || i, $1 FROM generate_series(1, 3) i`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		  SELECT 't1', 'user', 'left' || i, $1 FROM generate_series(1, 3) i`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		  SELECT 't1', 'a', 'user', 'left' || i FROM generate_series(1, 3) i`,
	} {
		var args []any
		if strings.Contains(q, "$1") {
			args = []any{h.now.Add(-time.Hour)}
		}
		if _, err := h.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 15 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
	rows, err := h.pool.Query(ctx, `SELECT entity || ' ' || count(DISTINCT txid) FROM rbac_history
		WHERE op = 'expire' GROUP BY entity ORDER BY entity`)
	if err != nil {
		t.Fatal(err)
	}
	batches, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"eligibility 2", "grant 2", "member 2", "membership 2"}; !slices.Equal(batches, want) {
		t.Errorf("expiries by transaction = %v, want %v", batches, want)
	}
}

// A batch whose transaction fails, though its statement ran, removed nothing, so DeleteExpired
// counts only the batches before it.
func TestDeleteExpiredCountsOnlyTheBatchesItRemoved(t *testing.T) {
	rbac.SetExpiryBatch(t, 2)
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		  SELECT 't1', 'cluster', 'c1', 'user', 'g' || i, 'cluster.login', '2025-01-01' FROM generate_series(1, 3) i`,
		// Refused as its transaction commits, once the statement deleting it has counted it.
		`CREATE FUNCTION refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$`,
		`CREATE CONSTRAINT TRIGGER refuse AFTER DELETE ON rbac_grants DEFERRABLE INITIALLY DEFERRED
		  FOR EACH ROW WHEN (old.principal_id = 'g3') EXECUTE FUNCTION refuse()`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	n, err := h.authz.DeleteExpired(ctx)
	if err == nil {
		t.Fatal("DeleteExpired removed a grant its transaction refused")
	}
	var left int64
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_grants WHERE principal_id LIKE 'g_'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if n != 3-left {
		t.Errorf("DeleteExpired = %d, with %d of 3 grants left", n, left)
	}
}

func TestDeleteExpiredRefusedForARaceConflicts(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// Another transaction holds the grants table, as a migration of the host's can, which
	// DeleteExpired waits for: PostgreSQL refuses the wait past lock_timeout, as it refuses one side
	// of a deadlock.
	held, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := held.Exec(ctx, `LOCK TABLE rbac_grants IN SHARE MODE`); err != nil {
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

// DeleteExpired reads, of each table, only the rows expired, under a generic plan too, which costs
// a batch as a third of the table: matched to the batch it holds in a join, a plan reads every
// grant, eligibility and place in groups of every tenant, in each batch; and a batch taken in no
// order looks as cheap to find by reading the whole table as by the index of expiries. It reads
// across tenants, so one tenant's rows show what every tenant's would.
func TestDeleteExpiredUnderAGenericPlanReadsOnlyWhatExpired(t *testing.T) {
	tables := []string{"rbac_grants", "rbac_eligibilities", "rbac_members", "rbac_memberships"}
	// Tables of n others, who hold a grant and an eligibility each and are in a group for good: each
	// size in a schema and on a pool of its own, as a plan is made for what the tables held when it
	// was first run.
	beside := func(n int) *harness {
		t.Helper()
		h := setupOn(t, pgtest.Open(t, "plan_cache_mode=force_generic_plan"))
		h.groups(t, "everyone")
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others),
			eligibilities AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.login', 60 FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others`, "rbac_grants", "rbac_eligibilities", "rbac_members")
		return h
	}
	ctx := t.Context()
	// The pages of each table DeleteExpired reads there once ten of each expired, and ten
	// memberships with their places, in a transaction it rolls back.
	read := func(h *harness) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `WITH x AS (SELECT 'x' || i AS id FROM generate_series(1, 10) i),
			grants AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
			  SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login', '2025-01-01' FROM x),
			eligibilities AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
			  SELECT 't1', 'cluster', 'c1', 'user', id, 'cluster.login', 60, '2025-01-01' FROM x),
			memberships AS (INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
			  SELECT 't1', 'user', 'left-' || id, '2025-01-01' FROM x)
			INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, expires_at)
			SELECT 't1', 'everyone', 'user', id, 'directory', '2025-01-01'::timestamptz FROM x
			UNION ALL SELECT 't1', 'everyone', 'user', 'left-' || id, '', NULL FROM x`); err != nil {
			t.Fatal(err)
		}
		pages := map[string]int64{}
		for _, table := range tables {
			pages[table] -= pagesRead(ctx, t, tx, table)
		}
		if n, err := h.authz.WithTx(tx).DeleteExpired(ctx); err != nil || n != 50 {
			t.Fatalf("DeleteExpired = %d, %v", n, err)
		}
		for _, table := range tables {
			pages[table] += pagesRead(ctx, t, tx, table)
		}
		return pages
	}
	few := read(beside(500))
	for what, many := range read(beside(5000)) {
		if many > few[what]*3/2+deeper {
			t.Errorf("DeleteExpired read %d pages of %s, and %d beside ten times as many that never expire", few[what], what, many)
		}
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
	commitOnceWaitedOn(t, h, tx, done)
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
			commitOnceWaitedOn(t, h, tx, done)
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

// A deny set on a group above the one deleted, while the deletion checks what that one is in,
// waits for it: committed between its check and its deletes, it would be lifted from the deleted
// group's members.
func TestDeleteGroupWaitsForADenyOnAGroupAbove(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	groupManager, owner, u := h.as(t, "groups"), h.as(t, "owner"), h.as(t, "u")
	for _, id := range []string{"inner", "outer"} {
		if err := h.authz.SetGroup(ctx, groupManager, "t1", rbac.GroupDefinition{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner")}, {Group: "inner", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"), grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	// An eligibility on inner's scope, which the deletion removes once it has checked inner:
	// holding it stops the deletion there.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		VALUES ('t1', 'group', 'inner', 'user', 'x', 'group.members', 3600)`); err != nil {
		t.Fatal(err)
	}
	hold, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	var pid int
	if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, `SELECT FROM rbac_eligibilities WHERE tenant = 't1' AND scope = 'group:inner' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	// How many wait on the hold, directly or through one another.
	blocked := func() int {
		var n int
		if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
			SELECT count(*) FROM waiting`, pid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	deleted := make(chan error, 1)
	go func() { deleted <- h.authz.DeleteGroup(ctx, groupManager, "t1", "inner") }()
	for blocked() < 1 {
		select {
		case err := <-deleted:
			t.Fatalf("DeleteGroup ran before it was stopped: %v", err)
		default:
		}
	}
	// A guard binds outer's members, which u is through inner.
	denied := make(chan error, 1)
	go func() {
		denied <- h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("outer")}, Permissions: []rbac.Permission{login}})
	}()
	first := false
	for !first && blocked() < 2 {
		select {
		case err := <-denied:
			denied <- err
			first = true
		default:
		}
	}
	if err := hold.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	errDelete, errDeny := <-deleted, <-denied
	if errDeny != nil {
		t.Fatal(errDeny)
	}
	switch {
	case first && errDelete == nil:
		t.Errorf("a deny on a group above set while DeleteGroup checked it; deleting inner lifted it from u: allowed %v",
			allowed(t, h, u, login, cluster))
	case first && !errors.Is(errDelete, rbac.ErrInvalid), !first && errDelete != nil:
		t.Fatalf("DeleteGroup: %v", errDelete)
	}
}

// A group nested in another while its deletion waits for the locks of the groups it was in is in
// one whose lock the deletion doesn't hold, so it is tried again.
func TestDeletingAGroupNestedMeanwhileIsTriedAgain(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	groupManager := h.as(t, "groups")
	h.groups(t, "inner", "outer")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner")}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteGroup(ctx, groupManager, "t1", "inner") }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("deleting a group nested meanwhile: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, groupManager, "t1", "inner"); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

// Deleting a group reads, of the groups it is in, only those under a generic plan, and of the
// grants, eligibilities and denies, only those of the groups it reaches, and of the activations,
// only its members': joined to the tenant's members, the groups a group is in would read every
// one, and beside tenant = $1 a plan, costing the tenant's rows by averages, would read every grant
// and eligibility of them, every activation, and every deny and approver, which no btree finds by
// a key in an array. Of its places, its members' and the grants on it, it reads those from a
// source the host owns only where it owns one, each by the index leading to it, rather than every
// place or grant in the tenant.
func TestDeleteGroupUnderAGenericPlanReadsOnlyTheGroupsItIsIn(t *testing.T) {
	for name, sources := range map[string][]string{"owning no source": nil, "owning a source": {"directory"}} {
		t.Run(name, func(t *testing.T) { deletingReadsOnlyTheGroupsItIsIn(t, sources) })
	}
}

func deletingReadsOnlyTheGroupsItIsIn(t *testing.T, sources []string) {
	t.Helper()
	groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	h := generic(t, func(c *rbac.Config) { c.Catalog, c.Sources = append(slices.Clone(c.Catalog), groups), sources })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "groups"), grant(cluster.Scope(), "cluster.login", rbac.Group, "outer"))
	manager := h.as(t, "groups")
	h.groups(t, "inner", "everyone")
	h.as(t, "ann", "inner")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'outer', 'group', 'inner')`); err != nil {
		t.Fatal(err)
	}
	tables := []string{"rbac_members", "rbac_grants", "rbac_eligibilities", "rbac_denies"}
	// The pages of each, and their indexes, deciding inner can't be deleted reads, for the grant to
	// outer, which it is in.
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		for _, table := range tables {
			pages[table] -= pagesRead(ctx, t, tx, table)
		}
		if err := h.authz.WithTx(tx).DeleteGroup(ctx, manager, "t1", "inner"); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("deleting a group in one holding a grant: %v", err)
		}
		for _, table := range tables {
			pages[table] += pagesRead(ctx, t, tx, table)
		}
		return pages
	}
	// Others are in another group, hold a grant and an activation made through outer, approve an
	// eligibility and are exempt from a deny.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others),
			granted AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others),
			activated AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 'activation', '2026-01-01 13:00:00+00', 'group:outer' FROM others),
			eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, ARRAY['user:' || id] FROM others)
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			SELECT 't1', 'cluster', id, 'd', '{public:}', ARRAY['user:' || id], '{cluster:root}' FROM others`, tables...)
	}
	// Vacuumed and analyzed, as autovacuum may leave the tables at any moment: a plan then costs an
	// index-only scan, of an index holding every column a test reads, at its least.
	settle := func() {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `VACUUM (ANALYZE) `+strings.Join(tables, ", ")); err != nil {
			t.Fatal(err)
		}
	}
	others(500)
	settle()
	few := read()
	others(9500)
	settle()
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("deleting a group read %d pages of %s, and %d once 9500 more were in another group, granted, activated, approving and exempt", few[what], what, many)
		}
	}
}

// A place in a group made again once it has ended, while it is still stored, is made by whoever
// made it again, then, as a membership or an eligibility set again once it has ended is, and
// history records it so; one renewed before it ends keeps who made it.
func TestAPlaceMadeAgainOnceEndedIsMadeByWhoeverMadeItAgain(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"))
	h.groups(t, "crew", "team", "kept")
	h.join(t, "u")
	manager, lead, sync := h.as(t, "manager"), h.as(t, "lead"), identity("sync")
	u := identity("u")
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{
		{Group: "crew", Principal: u, ExpiresAt: h.now.Add(time.Minute)},
		{Group: "team", Principal: u, ExpiresAt: h.now.Add(time.Minute)},
		{Group: "kept", Principal: u, ExpiresAt: h.now.Add(2 * time.Hour)},
	}, nil); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	if err := h.authz.ImportMembers(ctx, sync, "t1", []rbac.Member{{Group: "crew", Principal: u}, {Group: "kept", Principal: u}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", []rbac.Member{{Group: "team", Principal: u}}, nil); err != nil {
		t.Fatal(err)
	}
	for group, want := range map[string]rbac.Principal{"crew": sync, "team": lead.Principal, "kept": manager.Principal} {
		ms, err := h.authz.Members(ctx, "t1", group)
		if err != nil || len(ms) != 1 {
			t.Fatalf("Members of %s = %+v, %v", group, ms, err)
		}
		if m := ms[0]; m.CreatedBy != want || m.CreatedAt.Equal(m.UpdatedAt) != (want != manager.Principal) {
			t.Errorf("u's place in %s made by %v at %v, updated at %v, want made by %v", group, m.CreatedBy, m.CreatedAt, m.UpdatedAt, want)
		}
		var recorded string
		if err := h.pool.QueryRow(ctx, `SELECT after->>'created_by' FROM rbac_history WHERE entity = 'member' AND group_id = $1 ORDER BY id DESC LIMIT 1`,
			group).Scan(&recorded); err != nil || recorded != string(want.Kind)+":"+want.ID {
			t.Errorf("history records u's place in %s as made by %q, %v", group, recorded, err)
		}
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

func TestJoiningRemovesPlacesLeftWithoutAMembership(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "a"))
	// A place of an identity with no membership, as a write around the package can leave.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'a', 'user', 'u')`); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf once it joined = %v, %v", of, err)
	}
	if allowed(t, h, rbac.Subject{Principal: identity("u")}, login, cluster) {
		t.Error("joining gave u what group a holds")
	}
	if len(h.events) != 1 || len(h.events[0].Left) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
}

// SetMemberships tells whether a membership it renews had ended as of one time, so one ending
// while it runs is renewed either as it was, in its groups, or anew, in none.
func TestRenewingAMembershipAsItEndsReadsTheClockOnce(t *testing.T) {
	var stepping bool
	h := grouped(t)
	cfg := h.cfg
	// A minute later each time it is read.
	cfg.Now = func() time.Time {
		now := h.now
		if stepping {
			h.now = h.now.Add(time.Minute)
		}
		return now
	}
	a, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	ends := h.now.Add(time.Hour)
	if err := a.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: ends}}); err != nil {
		t.Fatal(err)
	}
	if err := a.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a"}}); err != nil {
		t.Fatal(err)
	}
	if err := a.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// It ends between the clock's second read and its third.
	h.now = ends.Add(-90 * time.Second)
	stepping = true
	renewer := identity("admin")
	if err := a.SetMemberships(ctx, renewer, "t1", []rbac.Membership{{Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	stepping = false
	ms, err := a.Memberships(ctx, "t1", []rbac.Principal{identity("u")})
	if err != nil || len(ms) != 1 {
		t.Fatalf("Memberships = %+v, %v", ms, err)
	}
	of, err := a.GroupsOf(ctx, "t1", identity("u"))
	if err != nil {
		t.Fatal(err)
	}
	if anew := ms[0].CreatedBy == renewer; anew != (len(of) == 0) {
		t.Errorf("renewed as made by %v, in groups %v", ms[0].CreatedBy, of)
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
			// membership, or joining u again once it ended, waits partway through holding or
			// removing them, while DeleteExpired ends it too.
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := tx.Exec(ctx, `SELECT FROM rbac_members WHERE group_id = 'b' FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			var pid int
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			// Whether a session running query waits on tx, directly or through one another.
			waiting := func(query string) bool {
				var w bool
				if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
					SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
					UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
					SELECT EXISTS (SELECT FROM pg_stat_activity JOIN waiting USING (pid) WHERE query LIKE $2)`, pid, query).Scan(&w); err != nil {
					t.Fatal(err)
				}
				return w
			}
			ended := make(chan error, 1)
			go func() { ended <- end(ctx, h.authz) }()
			for blocked := false; !blocked; {
				select {
				case err := <-ended:
					t.Fatalf("%s didn't wait for the held place: %v", name, err)
				default:
					blocked = waiting("%FROM rbac_members WHERE%")
				}
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

// Every removal of places in groups takes them in one order, so two at once never deadlock: one
// stopped partway, holding the places before the one it waits for, holds none the other takes
// before those.
func TestRemovingPlacesInGroupsNeverDeadlocks(t *testing.T) {
	for name, c := range map[string]struct {
		// places are written in order, so a read of them by principal finds the first first; held is
		// one only the first removal takes, after another it takes too.
		places       [][3]string
		held         [3]string
		first, other func(ctx context.Context, a *rbac.Authorizer) error
	}{
		"SetMemberships joining again, with DeleteGroups": {
			places: [][3]string{{"b", "user:u", ""}, {"a", "user:u", ""}, {"a", "user:v", ""}},
			held:   [3]string{"a", "user:v", ""},
			first: func(ctx context.Context, a *rbac.Authorizer) error {
				return a.DeleteGroups(ctx, host, "t1", []string{"a", "b"})
			},
			other: func(ctx context.Context, a *rbac.Authorizer) error {
				return a.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u")}})
			},
		},
		"ImportGroups taking groups over, with DeletePrincipal": {
			places: [][3]string{{"b", "user:u", ""}, {"a", "user:u", ""}, {"a", "user:u", "directory"}},
			held:   [3]string{"a", "user:u", "directory"},
			first: func(ctx context.Context, a *rbac.Authorizer) error {
				return a.DeletePrincipal(ctx, host, "t1", identity("u"))
			},
			other: func(ctx context.Context, a *rbac.Authorizer) error {
				return a.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "a", Source: "directory"}, {ID: "b", Source: "directory"}})
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
			ctx := t.Context()
			h.groups(t, "a", "b")
			// u's membership has ended, so joining again removes its places.
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
				VALUES ('t1', 'user', 'u', '2025-01-01')`); err != nil {
				t.Fatal(err)
			}
			for _, p := range c.places {
				kind, id, _ := strings.Cut(p[1], ":")
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source) VALUES ('t1', $1, $2, $3, $4)`,
					p[0], kind, id, p[2]); err != nil {
					t.Fatal(err)
				}
			}
			hold, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hold.Rollback(ctx) }()
			var pid int
			if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(ctx, `SELECT FROM rbac_members WHERE tenant = 't1' AND group_id = $1 AND principal = $2 AND source = $3 FOR UPDATE`,
				c.held[0], c.held[1], c.held[2]); err != nil {
				t.Fatal(err)
			}
			errs := make(chan error, 2)
			done := 0
			// Until n wait on the hold, directly or through one another, or one is done.
			waiting := func(n int) {
				for blocked := 0; blocked < n; {
					select {
					case err := <-errs:
						if err != nil {
							t.Errorf("a removal run while the other waited: %v", err)
						}
						done++
						return
					default:
					}
					if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
						SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
						UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
						SELECT count(*) FROM waiting`, pid).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
				}
			}
			go func() { errs <- c.first(ctx, h.authz) }()
			waiting(1)
			go func() { errs <- c.other(ctx, h.authz) }()
			waiting(2)
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			for ; done < 2; done++ {
				if err := <-errs; err != nil {
					t.Errorf("removing places at once: %v", err)
				}
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

// Holders, Members and GroupsOf read a tenant's own groups and memberships, in every plan and as of
// a time, where another tenant names its groups alike and holds the same identities otherwise: one
// suspended there is a member here, and ones members there are here a guest, suspended, ended, gone
// though still in the group, or in the other tenant's group of the same id alone.
func TestHoldersAndMembersReadEachTenantsOwnGroupsAndMemberships(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	ending := h.now.Add(time.Hour)
	for tenant, ms := range map[string][]rbac.Membership{
		"t1": {
			{Principal: identity("a")},
			{Principal: identity("b"), Guest: true},
			{Principal: identity("c"), Suspended: true},
			{Principal: identity("d"), ExpiresAt: ending},
			{Principal: identity("f")},
			{Principal: identity("i")},
			{Principal: identity("j")},
		},
		"t2": {
			{Principal: identity("a"), Suspended: true},
			{Principal: identity("c")},
			{Principal: identity("d")},
			{Principal: identity("e")},
			{Principal: identity("f")},
			{Principal: identity("j")},
		},
	} {
		if err := h.authz.SetMemberships(ctx, host, tenant, ms); err != nil {
			t.Fatal(err)
		}
		if err := h.authz.ImportGroups(ctx, host, tenant, []rbac.GroupDefinition{{ID: "g"}, {ID: "inner"}}); err != nil {
			t.Fatal(err)
		}
	}
	for tenant, ms := range map[string][]rbac.Member{
		"t1": {
			{Group: "g", Principal: identity("a")},
			{Group: "g", Principal: identity("b")},
			{Group: "g", Principal: identity("c")},
			{Group: "g", Principal: identity("d")},
			{Group: "g", Principal: identity("f")},
			{Group: "g", Principal: groupOf("inner")},
			{Group: "inner", Principal: identity("i")},
		},
		"t2": {
			{Group: "g", Principal: identity("a")},
			{Group: "g", Principal: identity("c")},
			{Group: "g", Principal: identity("d")},
			{Group: "g", Principal: identity("e")},
			{Group: "g", Principal: groupOf("inner")},
			{Group: "inner", Principal: identity("j")},
		},
	} {
		if err := h.authz.ImportMembers(ctx, host, tenant, ms); err != nil {
			t.Fatal(err)
		}
	}
	// f's membership of t1 is gone, as a write around the package leaves its place in g; d's ends.
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_memberships WHERE tenant = 't1' AND principal = 'user:f'`); err != nil {
		t.Fatal(err)
	}
	h.now = ending.Add(time.Hour)
	on := map[string]rbac.Resource{"t1": cluster, "t2": {Tenant: "t2", Type: "cluster", ID: cluster.ID}}
	for tenant, r := range on {
		if err := h.authz.Import(ctx, host, tenant, []rbac.Grant{grant(r.Scope(), "cluster.login", rbac.Group, "g")}); err != nil {
			t.Fatal(err)
		}
	}
	type want struct {
		holders  []string
		members  map[string][]rbac.Principal
		groupsOf map[string][]string
	}
	wants := map[string]want{
		"t1": {
			holders:  []string{"a", "b", "i"},
			members:  map[string][]rbac.Principal{"g": {groupOf("inner"), identity("a"), identity("b"), identity("c")}, "inner": {identity("i")}},
			groupsOf: map[string][]string{"a": {"g"}, "b": {"g"}, "c": {"g"}, "d": nil, "e": nil, "f": nil, "i": {"g", "inner"}, "j": nil},
		},
		"t2": {
			holders:  []string{"c", "d", "e", "j"},
			members:  map[string][]rbac.Principal{"g": {groupOf("inner"), identity("a"), identity("c"), identity("d"), identity("e")}, "inner": {identity("j")}},
			groupsOf: map[string][]string{"a": {"g"}, "c": {"g"}, "d": {"g"}, "e": {"g"}, "f": nil, "i": nil, "j": {"g", "inner"}},
		},
	}
	check := func(t *testing.T, a *rbac.Authorizer, tenant string) {
		t.Helper()
		w := wants[tenant]
		holders, err := a.Holders(ctx, login, on[tenant])
		if err != nil {
			t.Fatal(err)
		}
		var listed []string
		for _, holder := range holders {
			listed = append(listed, holder.Principal.ID)
			if !slices.Equal(holder.Groups, []string{"g"}) {
				t.Errorf("Holders in %s lists %s through %v", tenant, holder.Principal.ID, holder.Groups)
			}
		}
		if !slices.Equal(listed, w.holders) {
			t.Errorf("Holders in %s = %v, want %v", tenant, listed, w.holders)
		}
		for group, want := range w.members {
			members, err := a.Members(ctx, tenant, group)
			if err != nil {
				t.Fatal(err)
			}
			var got []rbac.Principal
			for _, m := range members {
				got = append(got, m.Principal)
			}
			if !slices.Equal(got, want) {
				t.Errorf("Members(%s, %s) = %v, want %v", tenant, group, got, want)
			}
		}
		for id, want := range w.groupsOf {
			if got, err := a.GroupsOf(ctx, tenant, identity(id)); err != nil || !slices.Equal(got, want) {
				t.Errorf("GroupsOf(%s, %s) = %v, %v, want %v", tenant, id, got, err, want)
			}
		}
	}
	for tenant, w := range wants {
		for id := range w.groupsOf {
			if allowed(t, h, rbac.Subject{Principal: identity(id)}, login, on[tenant]) != slices.Contains(w.holders, id) {
				t.Errorf("Authorize in %s doesn't agree with Holders %v for %s", tenant, w.holders, id)
			}
		}
	}
	at := dbNow(t, h)
	for _, mode := range []string{"", "force_custom_plan", "force_generic_plan"} {
		t.Run("plan_cache_mode="+mode, func(t *testing.T) {
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if mode != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, mode); err != nil {
					t.Fatal(err)
				}
			}
			// From the sixth run a connection's statement can take a generic plan.
			for range 6 {
				for tenant := range wants {
					check(t, h.authz.WithTx(tx), tenant)
				}
			}
		})
	}
	t.Run("as of a time", func(t *testing.T) {
		for tenant := range wants {
			if err := h.authz.AsOf(ctx, tenant, at, func(a *rbac.Authorizer) error {
				check(t, a, tenant)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// rbac_group_members, which Holders of this release and the one before call, reads a group's members
// and then their memberships in two statements, both in the calling statement's snapshot, as it is
// stable: a change that commits between them, holding the memberships while the first reads, is read
// by neither. Volatile, the second read it, and the group of one, whose member the change suspended
// as it added another, had no member standing: neither what it was nor what it became.
func TestAGroupsMembersAndTheirMembershipsAreReadInOneSnapshot(t *testing.T) {
	h := setup(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h.as(t, "a", "g")
	h.join(t, "b")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for _, q := range []string{
		`LOCK TABLE rbac_memberships IN ACCESS EXCLUSIVE MODE`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g', 'user', 'b')`,
		`UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:a'`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	type read struct {
		standing []string
		err      error
	}
	done := make(chan read, 1)
	go func() {
		var r read
		r.err = h.pool.QueryRow(ctx, `SELECT coalesce(array_agg(principal ORDER BY principal), '{}')
			FROM rbac_group_members('t1', '{g}', $1, NULL, true)`, h.now).Scan(&r.standing)
		done <- r
	}()
	// Until the second statement waits for the change, which the first didn't.
	for waiting := false; !waiting; {
		select {
		case r := <-done:
			t.Fatalf("the members were read before the change committed: %v, %v", r.standing, r.err)
		default:
		}
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.err != nil || !slices.Equal(r.standing, []string{"user:a"}) {
		t.Fatalf("standing in g: %v, %v", r.standing, r.err)
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

func TestAPrivilegedRoleIsNeverTheMembers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}}); err != nil {
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
	} {
		if err := change(rbac.TenantMembers("t1")); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s of a privileged role to the members: %v", name, err)
		}
		for _, p := range []rbac.Principal{groupOf("devs"), identity("u")} {
			if err := change(p); err != nil {
				t.Errorf("%s of a privileged role to %v: %v", name, p, err)
			}
		}
	}
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("devs"), MaxDuration: time.Hour}); err != nil {
		t.Fatalf("a group eligible for a privileged role: %v", err)
	}
}

func TestAPrivilegedRoleGivesNothingThroughTheMembers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}}); err != nil {
		t.Fatal(err)
	}
	// As a catalog change that makes a role privileged leaves it: refused now, but stored.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'workspace', 'w1', 'members', 't1', 'cluster.admin')`); err != nil {
		t.Fatal(err)
	}
	member := h.as(t, "member")
	for _, p := range []rbac.Permission{view, root, grantC} {
		if allowed(t, h, member, p, cluster) {
			t.Errorf("%s through the members", p)
		}
		listingsAgree(t, h, resources, member, p)
		if d, err := h.authz.Explain(ctx, member, p, cluster); err != nil || d.Allowed {
			t.Errorf("Explain %s = %+v, %v", p, d, err)
		}
	}
	if perms, err := h.authz.Permissions(ctx, member, cluster); err != nil || len(perms) != 0 {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, root, cluster); err != nil || slices.Contains(holderPrincipals(holders), rbac.TenantMembers("t1")) {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
	if err := h.authz.Apply(ctx, member, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("granting through the members' privileged role: %v", err)
	}
	// Through a group, the same grant, and an eligibility, give what they give.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET principal_kind = 'group', principal_id = 'devs' WHERE principal_kind = 'members';
		INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		VALUES ('t1', 'cluster', 'c1', 'group', 'devs', 'cluster.sudo', 3600)`); err != nil {
		t.Fatal(err)
	}
	dev := h.as(t, "dev", "devs")
	if !allowed(t, h, dev, root, cluster) {
		t.Error("root through a group")
	}
	listingsAgree(t, h, resources, dev, root)
	if _, err := h.authz.Activate(ctx, dev, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}); err != nil {
		t.Errorf("activating through a group's eligibility for a privileged role: %v", err)
	}
}

func TestARoleBecomesPrivilegedOnlyWhereTheMembersDontHoldIt(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}}); err != nil {
		t.Fatal(err)
	}
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	widened := op
	widened.Permissions = []rbac.Permission{view, login, root}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: rbac.TenantMembers("t1")}}}); err != nil {
		t.Fatal(err)
	}
	// Giving root makes it privileged, which the members would hold nothing of.
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("making a role privileged that the members hold: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE role = 'custom.op'`); err != nil {
		t.Fatal(err)
	}
	// An identity, a group and a group's eligibility may hold it.
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{
		{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: identity("u")}},
		{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: groupOf("devs")}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, admin, cluster, rbac.Eligibility{Role: op.ID, Principal: groupOf("devs"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("making a role privileged that the members don't hold: %v", err)
	}
}

// groupMembers changes a group's members, on its scope.
var groupMembers = rbac.RoleDefinition{ID: "group.members", Permissions: []rbac.Permission{rbac.GroupMembers}, ResourceTypes: []string{rbac.GroupScope}}

func TestChangingMembers(t *testing.T) {
	var asked []rbac.GrantInput
	h := grouped(t, func(c *rbac.Config) {
		c.Sources = []string{"directory"}
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			if in.Binding.Principal.Kind == "service_account" && in.Role.Privileged {
				return fmt.Errorf("%w: service accounts hold no privileged role", rbac.ErrInvalid)
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "ops"}, {ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	// lead changes the members of devs and admins, and grants nothing on the cluster, where admins
	// holds roles.
	h.seed(t, grant(rbac.Scope{Type: rbac.GroupScope, ID: "devs"}, "group.members", rbac.User, "lead"),
		grant(rbac.Scope{Type: rbac.GroupScope, ID: "admins"}, "group.members", rbac.User, "lead"),
		grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"), grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.admin", Principal: groupOf("admins"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	bot := h.member(t, rbac.Principal{Kind: "service_account", ID: "ci"})
	lead, manager := h.as(t, "lead"), h.as(t, "manager")
	in := func(group string, p rbac.Principal) []rbac.Member { return []rbac.Member{{Group: group, Principal: p}} }

	asked = nil
	// The members of a group that holds nothing change with GroupMembers on it.
	h.events = nil
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("devs", identity("u")), nil); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Joined) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	for name, change := range map[string]func() error{
		"another group": func() error { return h.authz.ChangeMembers(ctx, lead, "t1", in("ops", identity("u")), nil) },
		// Adding to a group that holds roles grants them, which lead can't.
		"a group holding roles":    func() error { return h.authz.ChangeMembers(ctx, lead, "t1", in("admins", identity("u")), nil) },
		"a group into one of them": func() error { return h.authz.ChangeMembers(ctx, lead, "t1", in("admins", groupOf("devs")), nil) },
		"anonymously":              func() error { return h.authz.ChangeMembers(ctx, rbac.Subject{}, "t1", in("devs", identity("u")), nil) },
	} {
		if err := change(); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The host's own members only it changes.
	owned := []rbac.Member{{Group: "devs", Principal: identity("u"), Source: "directory"}}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", owned, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a member from the host's source: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("devs", identity("u")), slices.Repeat(in("devs", identity("v")), rbac.MaxBindings)); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("too many members: %v", err)
	}
	if asked != nil {
		t.Fatalf("asked = %+v", asked)
	}

	// manager, who may grant what admins holds, adds to it, and the host is asked about each grant
	// and eligibility it holds, as the new member's.
	h.events = nil
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "admins", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}, nil); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 3 || slices.ContainsFunc(asked, func(in rbac.GrantInput) bool {
		return in.Via != rbac.ViaMembership || in.Binding.Principal != identity("u") || in.Binding.ExpiresAt.IsZero() ||
			in.Actor.Principal != manager.Principal
	}) {
		t.Fatalf("asked = %+v", asked)
	}
	if !allowed(t, h, h.as(t, "u", "devs", "admins"), root, cluster) {
		t.Fatal("a member of a group holds what it holds")
	}
	// One the host refuses joins nothing.
	if err := h.authz.ChangeMembers(ctx, manager, "t1", in("admins", bot.Principal), nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a service account in a group holding a privileged role: %v", err)
	}
	if got, err := h.authz.GroupsOf(ctx, "t1", bot.Principal); err != nil || len(got) != 0 {
		t.Fatalf("GroupsOf = %v, %v", got, err)
	}
	// Removing a member gives nothing, so it takes GroupMembers alone.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", nil, slices.Concat(in("admins", identity("u")), in("devs", identity("u")))); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(got) != 0 {
		t.Fatalf("GroupsOf = %v, %v", got, err)
	}
}

func TestAMemberGainsWhatTheGroupsItsGroupIsInHold(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: rbac.GroupScope, ID: "devs"}, "group.members", rbac.User, "lead"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: groupOf("devs")}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	add := []rbac.Member{{Group: "devs", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "lead"), "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("adding to a group in one holding a role the actor can't grant: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); err != nil {
		t.Fatal(err)
	}
}

// A member added below a group the same change nests in another gains what that one holds: the
// host is asked about it as the member's, as it is when two changes make them, in either order.
func TestAChangeNestingAGroupAsksAboutWhatTheMembersItAddsReach(t *testing.T) {
	bot := rbac.Principal{Kind: "service_account", ID: "ci"}
	in := func(group string, p rbac.Principal) rbac.Member { return rbac.Member{Group: group, Principal: p} }
	for _, how := range []string{"ChangeMembers", "ImportMembers"} {
		for name, c := range map[string]struct {
			stored []rbac.Member
			add    func(rbac.Principal) []rbac.Member
		}{
			"in the group": {add: func(p rbac.Principal) []rbac.Member {
				return []rbac.Member{in("devs", p), in("admins", groupOf("devs"))}
			}},
			"below the group": {stored: []rbac.Member{in("admins", groupOf("ops"))}, add: func(p rbac.Principal) []rbac.Member {
				return []rbac.Member{in("devs", p), in("ops", groupOf("devs"))}
			}},
			"through a chain": {add: func(p rbac.Principal) []rbac.Member {
				return []rbac.Member{in("devs", p), in("ops", groupOf("devs")), in("admins", groupOf("ops"))}
			}},
		} {
			t.Run(how+"/"+name, func(t *testing.T) {
				h := grouped(t, func(c *rbac.Config) {
					validate := c.ValidateGrant
					c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
						if in.Binding.Principal.Kind == bot.Kind && in.Role.Privileged {
							return fmt.Errorf("%w: service accounts hold no privileged role", rbac.ErrInvalid)
						}
						return validate(ctx, q, in)
					}
				})
				ctx := t.Context()
				h.groups(t, "devs", "ops")
				h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
				if err := h.authz.ImportMembers(ctx, host, "t1", c.stored); err != nil {
					t.Fatal(err)
				}
				h.member(t, bot)
				u := h.as(t, "u")
				change := func(add []rbac.Member) error {
					if how == "ImportMembers" {
						return h.authz.ImportMembers(ctx, host, "t1", add)
					}
					return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil)
				}
				if err := change(c.add(bot)); !errors.Is(err, rbac.ErrInvalid) {
					t.Fatalf("the bot below admins in one change: %v", err)
				}
				if err := change(c.add(u.Principal)); err != nil {
					t.Fatalf("u below admins in one change: %v", err)
				}
				if !allowed(t, h, u, root, cluster) {
					t.Error("u gained nothing from admins")
				}
			})
		}
	}
}

func TestChangingMembersIsCheckedAsTheDeniesAndApprovalsItChanges(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "contractors"}, {ID: "oncall"}, {ID: "approvers"}}); err != nil {
		t.Fatal(err)
	}
	root := rbac.TenantRoot("t1")
	h.seed(t, grant(root, "group.members", rbac.User, "lead"), grant(root, "group.members", rbac.User, "guardian"),
		grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "contractors", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	guardian, lead := h.as(t, "guardian"), h.as(t, "lead")
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("contractors")}, Exempt: []rbac.Principal{groupOf("oncall")}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{
		Role: "cluster.sudo", Principal: identity("v"), MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("approvers")},
	}); err != nil {
		t.Fatal(err)
	}
	in := func(group string) []rbac.Member { return []rbac.Member{{Group: group, Principal: identity("u")}} }
	// Exempting someone from a deny, or lifting one that names them, takes the power to set it; and
	// approving an eligibility's activations, the power to set it.
	for name, change := range map[string]func(rbac.Subject) error{
		"joining an exempt group": func(s rbac.Subject) error { return h.authz.ChangeMembers(ctx, s, "t1", in("oncall"), nil) },
		"leaving a denied group":  func(s rbac.Subject) error { return h.authz.ChangeMembers(ctx, s, "t1", nil, in("contractors")) },
	} {
		if err := change(lead); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s by a member manager: %v", name, err)
		}
		if err := change(guardian); err != nil {
			t.Errorf("%s by one who sets the deny: %v", name, err)
		}
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("approvers"), nil); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("joining an approving group by a member manager: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", in("approvers"), nil); err != nil {
		t.Errorf("joining an approving group by one who sets the eligibility: %v", err)
	}
	// Joining a denied group only takes access away, as leaving an approving one does.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("contractors"), in("approvers")); err != nil {
		t.Errorf("joining a denied group and leaving an approving one: %v", err)
	}
}

// A member leaving a group the same change nests in another leaves only the groups it was in, so a
// deny naming the other binds it neither before nor after: nothing is lifted. One joining it is
// exempt as the group it will be in is.
func TestLeavingAGroupAChangeNestsLiftsNoDenyOnWhereItIsNested(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "contractors"}, {ID: "admins"}, {ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u")
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("admins")}, Exempt: []rbac.Principal{groupOf("oncall")}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	lead := h.as(t, "lead")
	u := rbac.Member{Group: "contractors", Principal: identity("u")}
	in := func(group string) rbac.Member { return rbac.Member{Group: group, Principal: groupOf("contractors")} }
	sooner := u
	sooner.ExpiresAt = h.now.Add(time.Hour)
	for name, c := range map[string]struct{ add, remove []rbac.Member }{
		"removed":       {add: []rbac.Member{in("admins")}, remove: []rbac.Member{u}},
		"ending sooner": {add: []rbac.Member{in("admins"), sooner}},
	} {
		if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{u}); err != nil {
			t.Fatal(err)
		}
		if err := h.authz.ChangeMembers(ctx, lead, "t1", c.add, c.remove); err != nil {
			t.Errorf("%s while nesting its group in a denied one: %v", name, err)
		}
		if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{u, in("admins")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", []rbac.Member{u, in("oncall")}, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("joining while nesting its group in an exempt one: %v", err)
	}
}

func TestChangingMembersReadsTheScopesItReachesFromTheHost(t *testing.T) {
	workspaceGuard := rbac.RoleDefinition{ID: "workspace.guard", Permissions: []rbac.Permission{rbac.DenyPermission("workspace")}, ResourceTypes: []string{"workspace"}}
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), workspaceGuard) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"), grant(workspace.Scope(), "workspace.guard", rbac.User, "guardian"))
	h.join(t, "u")
	manager := h.as(t, "manager")
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}}
	// A deny on the workspace the cluster is in takes the power to grant there, which only the
	// cluster's path shows.
	frozen := rbac.Deny{ID: "frozen", Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{grantC}}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), workspace, frozen); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("adding under a deny on the cluster's workspace: %v", err)
	}
	// Without Config.ResourceOf, a host with containers can't say where the cluster is, though its
	// resources have no attributes.
	cfg := h.cfg
	cfg.ResourceOf, cfg.Attributes = nil, rbac.Attributes{Resource: map[string]rbac.AttributeType{}}
	blind, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := blind.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "ResourceOf") {
		t.Fatalf("adding without ResourceOf: %v", err)
	}
	if err := blind.ChangeMembers(ctx, manager, "t1", nil, add); err != nil {
		t.Fatalf("removing without ResourceOf: %v", err)
	}
}

func TestEndingAMembershipSoonerIsCheckedAsLeaving(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "contractors"}}); err != nil {
		t.Fatal(err)
	}
	root := rbac.TenantRoot("t1")
	h.seed(t, grant(root, "group.members", rbac.User, "lead"), grant(root, "group.members", rbac.User, "guardian"),
		grant(cluster.Scope(), "guard", rbac.User, "guardian"), grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	guardian, lead := h.as(t, "guardian"), h.as(t, "lead")
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "contractors", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("contractors")}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
		t.Fatal(err)
	}
	until := func(id string) []rbac.Member {
		return []rbac.Member{{Group: "contractors", Principal: identity(id), ExpiresAt: h.now.Add(time.Minute)}}
	}
	// Once it ends, u is no longer in the group the deny names, as if removed now.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", until("u"), nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("ending u's membership of a denied group sooner by a member manager: %v", err)
	}
	// Joining for a while lifts nothing that bound v before.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", until("v"), nil); err != nil {
		t.Fatalf("v joining a denied group for a while: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, guardian, "t1", until("u"), nil); err != nil {
		t.Fatalf("ending u's membership sooner by one who sets the deny: %v", err)
	}
	// Ending one that ends already, sooner still, is the same.
	sooner := until("u")
	sooner[0].ExpiresAt = h.now.Add(time.Second)
	if err := h.authz.ChangeMembers(ctx, lead, "t1", sooner, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("ending u's membership sooner still by a member manager: %v", err)
	}
}

func TestEndingAPlaceSoonerGrantsNothing(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// In crew around the hooks, as the host refuses an outsider any grant.
	h.as(t, "outsider", "crew")
	sooner := func(id string) []rbac.Member {
		return []rbac.Member{{Group: "crew", Principal: identity(id), ExpiresAt: h.now.Add(time.Minute)}}
	}
	lead := h.as(t, "lead")
	// Removing u needs no power to grant what crew holds, and neither does ending its place sooner.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", sooner("u"), nil); err != nil {
		t.Fatalf("ending u's place sooner without the power to grant what crew holds: %v", err)
	}
	// Nor is the host asked about what a place ending sooner holds: it holds it already.
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", sooner("outsider"), nil); err != nil {
		t.Fatalf("ending the place of one the host refuses any grant sooner: %v", err)
	}
	// Nor is changing only the note of a place: here u's, ending as it does now.
	noted := sooner("u")
	noted[0].Note = "on call"
	if err := h.authz.ChangeMembers(ctx, lead, "t1", noted, nil); err != nil {
		t.Fatalf("changing the note of u's place without the power to grant what crew holds: %v", err)
	}
	noted = sooner("outsider")
	noted[0].Note = "on call"
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", noted, nil); err != nil {
		t.Fatalf("changing the note of the place of one the host refuses any grant: %v", err)
	}
	// Joining for a while gains what crew holds.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", sooner("v"), nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("v joining crew for a while by one who can't grant what it holds: %v", err)
	}
	// And so does making a place last longer.
	if err := h.authz.ChangeMembers(ctx, lead, "t1", []rbac.Member{{Group: "crew", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("making u's place last longer by one who can't grant what crew holds: %v", err)
	}
}

// A change joining someone to a group is refused when, while the host was asked about what it
// gains, they joined it already for longer: the change ends that sooner, lifting a deny.
func TestAJoinThatBecomesEndingSoonerMeanwhileIsTriedAgain(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "contractors"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "contractors"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u")
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("contractors")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "contractors", Principal: identity("u")}})
	}
	add := []rbac.Member{{Group: "contractors", Principal: identity("u"), ExpiresAt: h.now.Add(time.Minute)}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a join that ends a membership made meanwhile sooner: %v", err)
	}
}

// A place ended sooner, checked as leaving its group, is refused when the place is removed while
// the change is checked: it is a join then, gaining what the group holds.
func TestAPlaceEndingSoonerRemovedMeanwhileIsTriedAgain(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == rbac.DenyPermission("cluster") {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "guard", rbac.User, "lead"),
		grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	lead := h.as(t, "lead")
	// Leaving crew lifts this, which lead may.
	if err := h.authz.SetDeny(ctx, lead, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("crew")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}})
	}
	sooner := []rbac.Member{{Group: "crew", Principal: identity("u"), ExpiresAt: h.now.Add(time.Minute)}}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", sooner, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("ending sooner a place removed meanwhile, by one who can't grant what crew holds: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("u's place should have been removed meanwhile")
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("u is in %v, %v", of, err)
	}
}

// A place a change keeps, here one whose note alone changes, that is removed while the host is asked
// about another member joining the same group, is a join then, which neither the host nor the
// actor's authority was asked about: the change is tried again, though the other member gains the
// same there.
func TestAKeptPlaceRemovedMeanwhileBesideAJoinIsTriedAgain(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, db rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return err
				}
			}
			return validate(ctx, db, in)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "v", "w")
	manager := h.as(t, "manager")
	for _, change := range []struct {
		name   string
		member string
		apply  func([]rbac.Member) error
	}{
		{"ChangeMembers", "v", func(add []rbac.Member) error { return h.authz.ChangeMembers(ctx, manager, "t1", add, nil) }},
		{"ImportMembers", "w", func(add []rbac.Member) error { return h.authz.ImportMembers(ctx, host, "t1", add) }},
	} {
		// In crew around the hooks, as the host refuses an outsider any grant.
		h.as(t, "outsider", "crew")
		noted := []rbac.Member{{Group: "crew", Principal: identity("outsider"), Note: change.name}}
		if err := change.apply(noted); err != nil {
			t.Fatalf("%s changing only the note of the outsider's place: %v", change.name, err)
		}
		meanwhile = func(ctx context.Context) error {
			return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("outsider")}})
		}
		noted[0].Note += " again"
		add := append([]rbac.Member{{Group: "crew", Principal: identity(change.member)}}, noted...)
		if err := change.apply(add); !errors.Is(err, rbac.ErrConflict) {
			t.Errorf("%s with %s joining crew, the outsider's place removed meanwhile: %v", change.name, change.member, err)
		}
		if meanwhile != nil {
			t.Fatal("the outsider's place should have been removed meanwhile")
		}
		if of, err := h.authz.GroupsOf(ctx, "t1", identity("outsider")); err != nil || len(of) != 0 {
			t.Errorf("%s: the outsider is in %v, %v", change.name, of, err)
		}
		// Joining now, as it would have, the host refuses it.
		if err := change.apply(add); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s with the outsider joining crew: %v", change.name, err)
		}
	}
}

// Without declared labels or constraints, or a deny binding the actor, nothing can refuse it what a
// member leaving loses, so a grant to its group made while a removal is checked changes nothing the
// removal checked.
func TestARemovalWithoutLabelsIsNotTriedAgainForAGrantMadeMeanwhile(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if do := meanwhile; do != nil && s == cluster.Scope() {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return rbac.Resource{}, err
				}
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "manager"), grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	// Leaving crew lifts this, which asks the host for the cluster.
	if err := h.authz.SetDeny(ctx, manager, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("crew")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "workspace.admin", rbac.Group, "crew")})
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatalf("a removal from a group granted elsewhere meanwhile, with no labels declared: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("crew should have been granted on the workspace meanwhile")
	}
}

// Without declared labels, SetGroup and DeleteGroup don't ask Config.ResourceOf about the group,
// which has no label to check, so a host that knows no group it hasn't made yet can still make one.
func TestManagingGroupsWithoutLabelsAsksTheHostNothingOfThem(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == rbac.GroupScope {
				return rbac.Resource{}, fmt.Errorf("the host has no group %q", s.ID)
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	groups := h.as(t, "groups")
	if err := h.authz.SetGroup(ctx, groups, "t1", rbac.GroupDefinition{ID: "fresh"}); err != nil {
		t.Fatalf("making a group: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "fresh"); err != nil {
		t.Fatalf("deleting a group: %v", err)
	}
}

func TestAGroupApprovingWhatCantBeGrantedNowTakesNoMembers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "approvers"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		VALUES ('t1', 'node', 'n1', 'user', 'v', 'cluster.login', 3600, '{group:approvers}')`); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "approvers", Principal: identity("u")}}, nil)
	if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "can't be granted there now") {
		t.Fatalf("adding to a group approving what can't be granted now: %v", err)
	}
}

func TestWithoutResourceOfAScopesAttributesAreDeclaredNone(t *testing.T) {
	flat := func(attrs rbac.Attributes) func(*rbac.Config) {
		return func(c *rbac.Config) {
			c.ContainerTypes, c.ResourceOf, c.Attributes = nil, nil, attrs
			c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		}
	}
	c1 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c1", Attributes: map[string]any{"frozen": true}}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}}
	// Undeclared, a condition reads any attribute: one the scope is taken to lack would lift a
	// deny on the cluster.
	h := grouped(t, flat(rbac.Attributes{}))
	ctx := t.Context()
	h.seed(t, grant(c1.Scope(), "cluster.login", rbac.Group, "admins"), grant(c1.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u")
	manager := h.as(t, "manager")
	frozen := rbac.Deny{
		ID: "frozen", Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{grantC},
		Condition: rbac.Condition{Expression: "has(resource.attributes.frozen) && resource.attributes.frozen"},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), c1, frozen); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "ResourceOf") {
		t.Fatalf("adding with undeclared attributes and no ResourceOf: %v", err)
	}
	// Declared none, the scope is exactly as taken.
	h = grouped(t, flat(rbac.Attributes{Resource: map[string]rbac.AttributeType{}}))
	h.seed(t, grant(c1.Scope(), "cluster.login", rbac.Group, "admins"))
	h.join(t, "u")
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); err != nil {
		t.Fatalf("adding with no attributes declared: %v", err)
	}
}

func TestAConstraintStopsChangingMembers(t *testing.T) {
	h := grouped(t, constrain("managed elsewhere", rbac.GroupMembers))
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: rbac.GroupScope, ID: "devs"}, "group.members", rbac.User, "lead"))
	h.join(t, "u")
	if err := h.authz.ChangeMembers(ctx, h.as(t, "lead"), "t1", []rbac.Member{{Group: "devs", Principal: identity("u")}}, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a constraint on GroupMembers: %v", err)
	}
}

// freezingUnder is a constraint that, while frozen, stops changes to grants on a container and the
// scopes under it, as a host freezes changes under one; asked of no resource, it removes the power
// to change grants on any scope, as one of them may be under the container.
func freezingUnder(container rbac.Scope, frozen *bool) func(*rbac.Config) {
	return func(c *rbac.Config) {
		c.Constraints = append(slices.Clone(c.Constraints), rbac.Constraint{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if !*frozen || !strings.HasSuffix(string(in.Permission), ":grant") {
				return false, nil
			}
			r := in.Resource
			return r == nil || r.Scope() == container || slices.Contains(r.Ancestors, container), nil
		}})
	}
}

// A freeze under a container stops a change to members taking access away under it, as it stops
// Apply revoking there: removing a member of a group holding access there, ending its place sooner,
// adding a member to a group a deny there names, and removing a member whose activation there rests
// on its place. Each scope is asked about as the host gives it, so taking access away outside the
// container isn't stopped.
func TestAFreezeStopsTakingAccessAwayThroughMembers(t *testing.T) {
	frozen := false
	h := grouped(t, freezingUnder(workspace.Scope(), &frozen), func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	h.groups(t, "crew", "oncall", "denied", "outside")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(elsewhere.Scope(), "cluster.login", rbac.Group, "outside"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "cluster.login", rbac.User, "w"),
		grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u", "v", "w")
	in := func(group string) rbac.Member { return rbac.Member{Group: group, Principal: identity("u")} }
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{in("crew"), in("oncall"), in("outside")}); err != nil {
		t.Fatal(err)
	}
	// u activates through oncall, whose eligibility is then deleted: the activation alone rests on oncall.
	owner := h.as(t, "owner")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	u, w := rbac.Subject{Principal: identity("u")}, rbac.Subject{Principal: identity("w")}
	if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "INC-1"}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteEligibility(ctx, owner, cluster, "cluster.sudo", groupOf("oncall")); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{groupOf("denied")}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	frozen = true
	if err := h.authz.Apply(ctx, manager, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: identity("v")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Apply revoking under the freeze: %v", err)
	}
	sooner := in("crew")
	sooner.ExpiresAt = h.now.Add(time.Minute)
	for what, c := range map[string]struct{ add, remove []rbac.Member }{
		"removing a member of a group holding access there":           {remove: []rbac.Member{in("crew")}},
		"ending its place sooner":                                     {add: []rbac.Member{sooner}},
		"adding a member to a group a deny there names":               {add: []rbac.Member{{Group: "denied", Principal: identity("w")}}},
		"removing a member whose activation there rests on its place": {remove: []rbac.Member{in("oncall")}},
	} {
		if err := h.authz.ChangeMembers(ctx, manager, "t1", c.add, c.remove); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s under the freeze: %v", what, err)
		}
	}
	if !allowed(t, h, u, login, cluster) || !allowed(t, h, u, root, cluster) || !allowed(t, h, w, login, cluster) {
		t.Fatal("u and w should keep their access on the frozen cluster")
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{in("outside")}); err != nil {
		t.Errorf("removing a member of a group holding access only outside the frozen workspace: %v", err)
	}
	frozen = false
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{in("crew"), in("oncall")}); err != nil {
		t.Errorf("removing the members once the freeze is lifted: %v", err)
	}
}

// A freeze judges a change to members by what it ends there: a member leaving a group ends what the
// group gives it there, though another group gives it the same, as Apply revoking a grant held twice
// is stopped; but a place that ends, or ends sooner, while another, from another source, keeps the
// member in its group as long ends nothing.
func TestAFreezeStopsALeavingByWhatItsGroupGives(t *testing.T) {
	frozen := false
	h := grouped(t, freezingUnder(workspace.Scope(), &frozen))
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(cluster.Scope(), "cluster.login", rbac.Group, "oncall"))
	h.join(t, "u")
	crew, synced := rbac.Member{Group: "crew", Principal: identity("u")}, rbac.Member{Group: "crew", Principal: identity("u"), Source: "ops"}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{crew, synced, {Group: "oncall", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	frozen = true
	sooner := synced
	sooner.ExpiresAt = h.now.Add(time.Minute)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{sooner}, nil); err != nil {
		t.Errorf("ending sooner a place in crew, another of which keeps u in it, under the freeze: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{synced}); err != nil {
		t.Errorf("removing a place in crew, another of which keeps u in it, under the freeze: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{crew}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("removing u from crew, though oncall gives it the same, under the freeze: %v", err)
	}
}

// A scope the host no longer has is read as stored, as a revoke there reads it, so a freeze on every
// scope of its type stops a member losing access there.
func TestAFreezeStopsTakingAccessAwayOnAScopeTheHostNoLongerHas(t *testing.T) {
	gone := rbac.Scope{Type: "cluster", ID: "gone"}
	h := grouped(t, constrain("freeze", grantC), func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == gone {
				return rbac.Resource{}, fmt.Errorf("cluster %s: %w", s.ID, rbac.ErrNotFound)
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.groups(t, "crew")
	h.seed(t, grant(gone, "cluster.login", rbac.Group, "crew"))
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("removing a member of a group holding access on a frozen scope the host no longer has: %v", err)
	}
}

// workspaceGuard sets denies on workspaces.
var workspaceGuard = rbac.RoleDefinition{ID: "workspace.guard", Permissions: []rbac.Permission{rbac.DenyPermission("workspace")}, ResourceTypes: []string{"workspace"}}

// A deny on a scope's path that removes the actor's power to change grants there stops a change to
// members taking access away there, as it stops Apply revoking there; one removing another
// permission doesn't, nor does one off the path of the scopes the access is on.
func TestADenyOnChangingGrantsStopsTakingAccessAwayThroughMembers(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), workspaceGuard) })
	ctx := t.Context()
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	h.groups(t, "crew", "outside")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(elsewhere.Scope(), "cluster.login", rbac.Group, "outside"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(workspace.Scope(), "workspace.guard", rbac.User, "guardian"))
	h.join(t, "u", "v")
	crew, outside := rbac.Member{Group: "crew", Principal: identity("u")}, rbac.Member{Group: "outside", Principal: identity("u")}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{crew, outside}); err != nil {
		t.Fatal(err)
	}
	manager, guardian := h.as(t, "manager"), h.as(t, "guardian")
	deny := func(id string, p rbac.Permission) {
		t.Helper()
		if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: id, Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{p}}); err != nil {
			t.Fatal(err)
		}
	}
	deny("noroot", root)
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{crew}); err != nil {
		t.Fatalf("removing under a deny of another permission: %v", err)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{crew}); err != nil {
		t.Fatal(err)
	}
	deny("frozen", "cluster:*")
	if err := h.authz.Apply(ctx, manager, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: identity("v")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Apply revoking under the deny: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{crew}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("removing a member of a group holding access where a deny removes the power to change grants: %v", err)
	}
	if !allowed(t, h, rbac.Subject{Principal: identity("u")}, login, cluster) {
		t.Error("u should keep its login on the cluster")
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{outside}); err != nil {
		t.Errorf("removing a member of a group holding access only off the deny's path: %v", err)
	}
}

// A change to members that read no deny binding the actor before its transaction reads the denies
// on none of the paths of the scopes it takes access away on, so it is tried again where one that
// removes the actor's power to change grants was set while it was checked.
func TestADenyOnChangingGrantsSetWhileMembersAreCheckedIsTriedAgain(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), workspaceGuard)
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Resource == nil && in.Permission == grantC {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	h.groups(t, "crew")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(workspace.Scope(), "workspace.guard", rbac.User, "guardian"))
	h.join(t, "u")
	crew := rbac.Member{Group: "crew", Principal: identity("u")}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{crew}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetDeny(ctx, h.as(t, "guardian"), workspace, rbac.Deny{ID: "frozen", Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{grantC}})
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{crew}); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("removing while a deny on changing grants there was set: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the deny should have been set meanwhile")
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{crew}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
}

// A deny removing the actor's power to change grants on the path of a scope a member loses access
// on, set while the host is asked about what another member gains, stops the change under its
// locks: where a deny binding the actor listed that power on the scope's type before, the denies on
// its path are read again there and refuse it; where none did, as with nothing else that could
// refuse taking access away, the change read none of them, and is tried again.
func TestADenyOnChangingGrantsSetWhileTheHostIsAskedStopsARemoval(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprintf("bound before %t", before), func(t *testing.T) {
			var meanwhile func(ctx context.Context) error
			h := grouped(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), guardRole, workspaceGuard)
				validate := c.ValidateGrant
				c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
					if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
						meanwhile = nil
						if err := do(ctx); err != nil {
							return err
						}
					}
					return validate(ctx, q, in)
				}
			})
			ctx := t.Context()
			elsewhere, far := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}, rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c3"}
			h.groups(t, "crew", "other")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(elsewhere.Scope(), "cluster.login", rbac.Group, "other"),
				grant(elsewhere.Scope(), "cluster.admin", rbac.User, "manager"), grant(far.Scope(), "guard", rbac.User, "guardian"),
				grant(workspace.Scope(), "workspace.guard", rbac.User, "guardian"))
			h.join(t, "u", "v")
			crew := rbac.Member{Group: "crew", Principal: identity("u")}
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{crew}); err != nil {
				t.Fatal(err)
			}
			manager, guardian := h.as(t, "manager"), h.as(t, "guardian")
			deny := func(ctx context.Context, on rbac.Resource, id string) error {
				return h.authz.SetDeny(ctx, guardian, on, rbac.Deny{ID: id, Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{grantC}})
			}
			// Off the path of the cluster u loses access on.
			if before {
				if err := deny(ctx, far, "far"); err != nil {
					t.Fatal(err)
				}
			}
			meanwhile = func(ctx context.Context) error { return deny(ctx, workspace, "frozen") }
			change := func() error {
				return h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "other", Principal: identity("v")}}, []rbac.Member{crew})
			}
			want := rbac.ErrConflict
			if before {
				want = rbac.ErrDenied
			}
			if err := change(); !errors.Is(err, want) {
				t.Fatalf("removing u from crew while a deny on its cluster's path was set: %v", err)
			}
			if meanwhile != nil {
				t.Fatal("the deny should have been set meanwhile")
			}
			if err := change(); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("tried again: %v", err)
			}
			if !allowed(t, h, rbac.Subject{Principal: identity("u")}, login, cluster) {
				t.Fatal("u should keep its login on the cluster")
			}
		})
	}
}

// Deleting a group that doesn't exist does nothing, and asks Config.ResourceOf nothing of it, nor
// the constraints, under a freeze on groups as where a label would be asked for, with labels
// declared or not: a constraint that fails on a group the host doesn't know fails no deletion of
// it. One that exists is asked about.
func TestDeletingAGroupThatDoesntExistUnderAFreezeAsksTheHostNothing(t *testing.T) {
	for _, labels := range []bool{false, true} {
		t.Run(fmt.Sprintf("labels %t", labels), func(t *testing.T) {
			var asked []string
			mutate := []func(*rbac.Config){func(c *rbac.Config) {
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s.Type == rbac.GroupScope {
						asked = append(asked, "ResourceOf "+s.ID)
						if s.ID == "ghost" {
							return rbac.Resource{}, errors.New("no such group")
						}
					}
					return resourceOf(ctx, tenant, s)
				}
				c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if in.Permission != rbac.GrantPermission(rbac.GroupScope) {
						return false, nil
					}
					if r := in.Resource; r != nil && r.Type == rbac.GroupScope {
						asked = append(asked, "freeze "+r.ID)
						if r.ID == "ghost" {
							return false, errors.New("no such group")
						}
					}
					return true, nil
				}}}
			}}
			if labels {
				mutate = append(mutate, withLabels)
			}
			h := grouped(t, mutate...)
			if err := h.authz.DeleteGroup(t.Context(), h.as(t, "groups"), "t1", "ghost"); err != nil || len(asked) > 0 {
				t.Fatalf("deleting a group that doesn't exist under a freeze: %v, asked %q", err, asked)
			}
			h.groups(t, "real")
			if err := h.authz.DeleteGroup(t.Context(), h.as(t, "groups"), "t1", "real"); err != nil || !slices.Contains(asked, "freeze real") {
				t.Fatalf("deleting a group that exists under a freeze: %v, asked %q", err, asked)
			}
		})
	}
}

// Deleting a group revokes what is granted on its scope, so while anything is, a freeze there
// stops it, as it stops Apply revoking there: a constraint, or a deny on its path, that removes the
// actor's power to change grants on it.
func TestAFreezeOnAGroupsScopeStopsDeletingIt(t *testing.T) {
	tenantGuard := rbac.RoleDefinition{ID: "tenant.guard", Permissions: []rbac.Permission{rbac.DenyPermission(rbac.TenantScope)}, ResourceTypes: []string{rbac.TenantScope}}
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupAdmin, tenantGuard)
		c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == rbac.GrantPermission(rbac.GroupScope) && (in.Resource == nil || in.Resource.ID == "ops"), nil
		}}}
	})
	ctx := t.Context()
	h.groups(t, "ops", "spare", "dev")
	lead := func(group string) rbac.Grant {
		return grant(rbac.Scope{Type: rbac.GroupScope, ID: group}, "group.members", rbac.User, "lead")
	}
	h.seed(t, lead("ops"), lead("spare"), lead("dev"), grant(rbac.TenantRoot("t1"), "group.admin", rbac.User, "admin"),
		grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	groups := h.as(t, "groups")
	ops := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "ops"}
	if err := h.authz.Apply(ctx, h.as(t, "admin"), ops, rbac.Change{Revoke: []rbac.Binding{{Role: "group.members", Principal: identity("lead")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Apply revoking on the frozen group's scope: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("deleting a group a grant on whose frozen scope it would revoke: %v", err)
	}
	if !allowed(t, h, h.as(t, "lead"), rbac.GroupMembers, ops) {
		t.Fatal("the lead should still manage ops's members")
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "spare"); err != nil {
		t.Errorf("deleting a group whose scope isn't frozen: %v", err)
	}
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{lead("ops")}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); err != nil {
		t.Errorf("deleting a frozen group nothing is granted on: %v", err)
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), tenant, rbac.Deny{
		ID: "nogroups", Principals: []rbac.Principal{groups.Principal}, Permissions: []rbac.Permission{rbac.GrantPermission(rbac.GroupScope)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "dev"); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("deleting a group a grant on whose scope it would revoke, where a deny removes the power to change grants: %v", err)
	}
}

// Deleting a group revokes what is granted on its scope, so a deny there removing the actor's power
// to change grants stops it as it stops Apply revoking there and ChangeMembers taking access away
// there: on the group as Config.ResourceOf gives it, whether the host declares its attributes or
// not. A deny of the groups the host says are frozen stops all three on one; a deny failing to read
// whether one is, which on the group as stored, without attributes, would deny, stops none of them on
// a group the host says isn't.
func TestADenyOnAGroupsScopeReadsTheGroupAsTheHostGivesIt(t *testing.T) {
	for _, frozen := range []bool{true, false} {
		for _, declared := range []bool{false, true} {
			t.Run(fmt.Sprintf("frozen %t, declared %t", frozen, declared), func(t *testing.T) { deniedAsGiven(t, frozen, declared) })
		}
	}
}

func deniedAsGiven(t *testing.T, frozen, declared bool) {
	t.Helper()
	ops := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "ops", Attributes: map[string]any{"frozen": frozen}}
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupAdmin, tenantGuard)
		if declared {
			c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"frozen": rbac.AttrBool}}
		}
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == ops.Scope() {
				return ops, nil
			}
			r, err := resourceOf(ctx, tenant, s)
			if declared && r.Attributes == nil {
				r.Attributes = map[string]any{"frozen": false}
			}
			return r, err
		}
	})
	ctx := t.Context()
	h.groups(t, "ops", "crew")
	h.seed(t, grant(ops.Scope(), "group.members", rbac.User, "lead"), grant(ops.Scope(), "group.members", rbac.Group, "crew"),
		grant(rbac.TenantRoot("t1"), "group.admin", rbac.User, "groups"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "groups"),
		grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	groups := h.as(t, "groups")
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	condition := "resource.attributes.frozen == true"
	if frozen {
		condition = "has(resource.attributes.frozen) && " + condition
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"frozen": false}}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), tenant, rbac.Deny{
		ID: "frozen", Principals: []rbac.Principal{groups.Principal}, Permissions: []rbac.Permission{rbac.GrantPermission(rbac.GroupScope)},
		Condition: rbac.Condition{Expression: condition},
	}); err != nil {
		t.Fatal(err)
	}
	var want error
	if frozen {
		want = rbac.ErrDenied
	}
	// crew's grant on ops is left to revoke, whatever Apply revokes.
	for what, change := range map[string]func() error{
		"Apply revoking on its scope": func() error {
			return h.authz.Apply(ctx, groups, ops, rbac.Change{Revoke: []rbac.Binding{{Role: "group.members", Principal: identity("lead")}}})
		},
		"ChangeMembers removing a member of a group holding access there": func() error {
			return h.authz.ChangeMembers(ctx, groups, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}})
		},
	} {
		if err := change(); !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", what, err, want)
		}
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); !errors.Is(err, want) {
		t.Errorf("DeleteGroup: %v, want %v", err, want)
	}
	if held := allowed(t, h, h.as(t, "lead"), rbac.GroupMembers, ops); held != frozen {
		t.Errorf("the lead manages ops's members %t, want %t", held, frozen)
	}
}

// Without Config.ResourceOf, which a host declaring labels must give (New), a group is as stored,
// which is all of it only where the host declares resource attributes as none. Where a deny binding
// the actor, or a constraint, may stop it changing grants on groups, ChangeMembers refuses taking
// access away on a group's scope rather than read the group so, and DeleteGroup revoking what is
// granted there is refused too; a group nothing is granted on it deletes, revoking nothing.
func TestWithoutResourceOfDeletingAGroupWithGrantsOnItIsRefusedWhereItCouldBeStopped(t *testing.T) {
	for name, mutate := range map[string]func(*rbac.Config){
		"a deny": func(*rbac.Config) {},
		"a constraint": func(c *rbac.Config) {
			c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				return in.Permission == rbac.GrantPermission(rbac.GroupScope) && (in.Resource == nil || in.Resource.Attributes["frozen"] == true), nil
			}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), groupAdmin, tenantGuard)
				c.ResourceOf = nil
			}, mutate)
			ctx := t.Context()
			ops := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "ops"}
			h.groups(t, "ops", "spare", "crew")
			h.seed(t, grant(ops.Scope(), "group.members", rbac.User, "lead"), grant(ops.Scope(), "group.members", rbac.Group, "crew"),
				grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
			groups, manager := h.as(t, "groups"), h.as(t, "manager")
			h.join(t, "u")
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
				t.Fatal(err)
			}
			if name == "a deny" {
				if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, rbac.Deny{
					ID: "frozen", Principals: []rbac.Principal{groups.Principal, manager.Principal}, Permissions: []rbac.Permission{rbac.GrantPermission(rbac.GroupScope)},
					Condition: rbac.Condition{Expression: "has(resource.attributes.frozen) && resource.attributes.frozen"},
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); !errors.Is(err, rbac.ErrInvalid) {
				t.Fatalf("ChangeMembers removing a member of a group holding access on a group as stored: %v", err)
			}
			if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("DeleteGroup revoking on a group as stored: %v", err)
			}
			if !allowed(t, h, h.as(t, "lead"), rbac.GroupMembers, ops) {
				t.Error("the lead should still manage ops's members")
			}
			if err := h.authz.DeleteGroup(ctx, groups, "t1", "spare"); err != nil {
				t.Errorf("DeleteGroup of a group nothing is granted on: %v", err)
			}
		})
	}
}

// A deny removing the actor's power to change grants on groups, set while DeleteGroup asks the
// constraints whether a freeze may stop it, stops the deletion under its locks: no deny binding the
// actor listed that power before, so it read neither the group from the host nor the denies on its
// path, and is tried again, as a change to members is.
func TestADenyOnChangingGrantsOnGroupsSetWhileDeleteGroupWaitsHasItTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupAdmin, tenantGuard)
		c.Constraints = []rbac.Constraint{{Name: "none", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == rbac.GrantPermission(rbac.GroupScope) && in.Resource == nil {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	ops := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "ops"}
	h.groups(t, "ops")
	h.seed(t, grant(ops.Scope(), "group.members", rbac.User, "lead"), grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	groups, guardian := h.as(t, "groups"), h.as(t, "guardian")
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetDeny(ctx, guardian, rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, rbac.Deny{
			ID: "frozen", Principals: []rbac.Principal{groups.Principal}, Permissions: []rbac.Permission{rbac.GrantPermission(rbac.GroupScope)},
		})
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("deleting a group while a deny on changing grants on groups was set: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the deny should have been set meanwhile")
	}
	if err := h.authz.DeleteGroup(ctx, groups, "t1", "ops"); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
	if !allowed(t, h, h.as(t, "lead"), rbac.GroupMembers, ops) {
		t.Fatal("the lead should still manage ops's members")
	}
}

// A change to members, and DeleteGroup, read which types of scope a deny binding the actor removes
// its power to change grants on, wherever in the tenant it is, before their transaction and again
// under its locks (grantsDenied): of the denies naming a key the actor is bound by, only those that
// remove such a power, under a generic plan and planned for their arguments alike. Through the index
// of every deny's principals, they read each denying the tenant's members root on a cluster of its
// own.
func TestChangingMembersReadsOfTheDeniesNamingTheActorOnlyThoseOnChangingGrants(t *testing.T) {
	for _, plan := range []string{"generic", "custom"} {
		t.Run(plan, func(t *testing.T) {
			groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
			h := crowded(t, pgtest.Open(t, "plan_cache_mode=force_"+plan+"_plan"), func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), groupMembers, groups)
			})
			ctx := t.Context()
			spare := rbac.Scope{Type: rbac.GroupScope, ID: "spare"}
			h.groups(t, "oncall", "spare")
			h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "boss"), grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "boss"),
				grant(cluster.Scope(), "cluster.admin", rbac.User, "boss"), grant(cluster.Scope(), "cluster.login", rbac.Group, "oncall"),
				grant(spare, "group.members", rbac.User, "lead"))
			boss := h.as(t, "boss")
			h.as(t, "bob")
			h.as(t, "ann", "oncall")
			n := 0
			denies := func(more int) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					SELECT 't1', 'cluster', 'z' || i, 'd', '{members:t1}', '{cluster:root}' FROM generate_series($1::int + 1, $1::int + $2::int) i`, n, more); err != nil {
					t.Fatal(err)
				}
				n += more
				if _, err := h.pool.Exec(ctx, `ANALYZE rbac_denies`); err != nil {
					t.Fatal(err)
				}
			}
			changes := map[string]func(a *rbac.Authorizer) error{
				"adding": func(a *rbac.Authorizer) error {
					return a.ChangeMembers(ctx, boss, "t1", []rbac.Member{{Group: "oncall", Principal: identity("bob")}}, nil)
				},
				"removing": func(a *rbac.Authorizer) error {
					return a.ChangeMembers(ctx, boss, "t1", nil, []rbac.Member{{Group: "oncall", Principal: identity("ann")}})
				},
				"deleting": func(a *rbac.Authorizer) error { return a.DeleteGroup(ctx, boss, "t1", "spare") },
			}
			denies(500)
			few := map[string]int64{}
			for what, change := range changes {
				few[what] = pagesChanging(ctx, t, h, change, "rbac_denies")["rbac_denies"]
			}
			denies(9500)
			for what, change := range changes {
				if many := pagesChanging(ctx, t, h, change, "rbac_denies")["rbac_denies"]; many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages of denies beside 500 denying the members root on other clusters, and %d beside 10000", what, few[what], many)
				}
			}
		})
	}
}

// The host's own writes make none of the checks a change an actor makes does, so a freeze stops
// none of them, as it stops no DeleteGrants: the host keeps its own state as it decides. Taking a
// tenant's group over with ImportGroups removes the members the tenant put there, and what the group
// gives them on the frozen scope.
func TestAFreezeStopsNoneOfTheHostsWrites(t *testing.T) {
	h := grouped(t, constrain("freeze", grantC), func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	h.groups(t, "crew", "other", "taken")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"), grant(cluster.Scope(), "cluster.login", rbac.Group, "other"),
		grant(cluster.Scope(), "cluster.login", rbac.Group, "taken"))
	h.join(t, "u", "v", "w", "x", "y")
	in := func(group, id string) rbac.Member { return rbac.Member{Group: group, Principal: identity(id)} }
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{in("crew", "u"), in("crew", "v"), in("crew", "w"), in("other", "x"), in("taken", "y")}); err != nil {
		t.Fatal(err)
	}
	y := rbac.Subject{Principal: identity("y")}
	if !allowed(t, h, y, login, cluster) {
		t.Fatal("y should log in through taken")
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", nil, []rbac.Member{in("crew", "u")}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an actor removing under the freeze: %v", err)
	}
	sooner := in("crew", "v")
	sooner.ExpiresAt = h.now.Add(time.Minute)
	for what, write := range map[string]func() error{
		"DeleteMembers": func() error { return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{in("crew", "u")}) },
		"ImportMembers": func() error { return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{sooner}) },
		"SetMemberships": func() error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("w"), ExpiresAt: h.now.Add(time.Minute)}})
		},
		"DeleteGroups": func() error { return h.authz.DeleteGroups(ctx, host, "t1", []string{"other"}) },
		"DeleteGrants": func() error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.Group, "crew")})
		},
		"ImportGroups": func() error {
			return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "taken", Source: "directory"}})
		},
	} {
		if err := write(); err != nil {
			t.Errorf("%s under the freeze: %v", what, err)
		}
	}
	if allowed(t, h, y, login, cluster) {
		t.Error("y, whom the tenant put in the group ImportGroups took over, still logs in on the frozen cluster through it")
	}
}

func TestAGrantToAGroupMadeWhileMembersAreAskedAboutIsTriedAgain(t *testing.T) {
	var h *harness
	var meanwhile func(ctx context.Context) error
	h = grouped(t, func(c *rbac.Config) {
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
	h.join(t, "u")
	manager := h.as(t, "manager")
	meanwhile = func(ctx context.Context) error {
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.admin", rbac.Group, "admins")})
	}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to the group made while the host was asked: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

// A change adding members to two groups is tried again when, while the host is asked about what
// one's member gains through the group it is in, the other is nested in that group too: the change
// holds its lock already, and what it holds was asked about for the first member alone, so the
// other's would gain it unasked.
func TestAGroupNestedMeanwhileInOneAnotherJoinedGroupIsInIsTriedAgain(t *testing.T) {
	for _, how := range []string{"ChangeMembers", "ImportMembers"} {
		t.Run(how, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h := meanwhileAsked(t, rbac.ViaMembership, &meanwhile)
			ctx := t.Context()
			h.groups(t, "devs", "ops")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "staff"))
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "staff", Principal: groupOf("ops")}}); err != nil {
				t.Fatal(err)
			}
			h.join(t, "u", "v")
			add := []rbac.Member{{Group: "devs", Principal: identity("u")}, {Group: "ops", Principal: identity("v")}}
			change := func() error {
				if how == "ImportMembers" {
					return h.authz.ImportMembers(ctx, host, "t1", add)
				}
				return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil)
			}
			meanwhile = func(ctx context.Context) error {
				return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "staff", Principal: groupOf("devs")}})
			}
			if err := change(); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("a change adding to a group nested meanwhile in one another it adds to is in: %v", err)
			}
			if meanwhile != nil {
				t.Fatal("devs should have been nested in staff meanwhile")
			}
			if err := change(); err != nil {
				t.Fatalf("tried again: %v", err)
			}
		})
	}
}

// A group nested above one a change reaches while the host is asked about the change is one whose
// lock the change doesn't hold, so it is tried again, rather than let a grant to that group commit
// before it, unasked about the members it adds.
func TestAGroupNestedAboveWhileMembersAreAskedAboutIsTriedAgain(t *testing.T) {
	for _, how := range []string{"ChangeMembers", "ImportMembers"} {
		t.Run(how, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h := meanwhileAsked(t, rbac.ViaMembership, &meanwhile)
			ctx := t.Context()
			h.groups(t, "admins")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "devs"))
			h.join(t, "u")
			add := []rbac.Member{{Group: "devs", Principal: identity("u")}}
			change := func() error {
				if how == "ImportMembers" {
					return h.authz.ImportMembers(ctx, host, "t1", add)
				}
				return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil)
			}
			meanwhile = func(ctx context.Context) error {
				return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: groupOf("devs")}})
			}
			if err := change(); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("a change reaching a group nested above while the host was asked: %v", err)
			}
			if err := change(); err != nil {
				t.Fatalf("tried again: %v", err)
			}
		})
	}
}

func TestAnEligibilityChangedWhileMembersAreAskedAboutIsTriedAgain(t *testing.T) {
	var h *harness
	var meanwhile func(ctx context.Context) error
	h = grouped(t, func(c *rbac.Config) {
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	owner := h.as(t, "owner")
	e := rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("admins"), MaxDuration: time.Hour, ExpiresAt: h.now.Add(time.Hour)}
	if err := h.authz.SetEligibility(ctx, owner, cluster, e); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	// Made to never end while the host was asked about it ending in an hour.
	meanwhile = func(ctx context.Context) error {
		forever := e
		forever.ExpiresAt = time.Time{}
		return h.authz.SetEligibility(ctx, owner, cluster, forever)
	}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("an eligibility extended while the host was asked: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

// A join is tried again when, while the host is asked about what the member gains, its group, or
// another group the change adds a member to, comes to approve an eligibility's activations, or to
// be exempt from a deny, on a scope the change didn't check: those are checked on their scopes, for
// whichever of the groups reaches them, so they are compared for all of them.
func TestAnApprovalOrExemptionMadeWhileMembersAreAskedAboutIsTriedAgain(t *testing.T) {
	for name, meanwhile := range map[string]string{
		"an approval": `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			VALUES ('t1', 'cluster', 'c2', 'user', 'x', 'cluster.login', 3600, ARRAY['group:' || $1])`,
		"an exemption": `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', 'cluster', 'c2', 'd', '{user:z}', ARRAY['group:' || $1], '{cluster:login}')`,
	} {
		// crew is the group whose member the host is asked about, and deck the other the change
		// joins, which holds nothing, and comes after it.
		for _, given := range []string{"crew", "deck"} {
			t.Run(name+" to "+given, func(t *testing.T) {
				var do func(context.Context) error
				h := grouped(t, func(c *rbac.Config) {
					c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
						if f := do; f != nil && in.Via == rbac.ViaMembership {
							do = nil
							return f(ctx)
						}
						return nil
					}
				})
				ctx := t.Context()
				// crew holds a role on the cluster, so the join asks the host about it.
				h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
				h.groups(t, "deck")
				h.join(t, "u", "v")
				do = func(ctx context.Context) error {
					_, err := h.pool.Exec(ctx, meanwhile, given)
					return err
				}
				add := []rbac.Member{{Group: "crew", Principal: identity("u")}, {Group: "deck", Principal: identity("v")}}
				if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, rbac.ErrConflict) {
					t.Fatalf("a join to groups, %s given %s meanwhile: %v", given, name, err)
				}
				if do != nil {
					t.Fatalf("the host should have been asked, and %s made meanwhile", name)
				}
			})
		}
	}
}

// What a change of members checks on a scope for whichever group reaches it is found once for all
// the groups the change reaches, so it is checked for each: an actor that can't set the eligibility
// one of them approves, or set the deny one is exempt from or named in, is refused a change of
// their members, whichever comes first, and whether the others gain or leave.
func TestChangingMembersOfManyGroupsChecksWhatEachReaches(t *testing.T) {
	for _, c := range []struct {
		name, reach string
		joins       bool
	}{
		{"members joining groups, one approving", `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			VALUES ('t1', 'cluster', 'k2', 'user', 'x', 'cluster.login', 3600, '{group:b}')`, true},
		{"members joining groups, one exempt", `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', 'cluster', 'k2', 'd', '{user:z}', '{group:b}', '{cluster:login}')`, true},
		{"members leaving groups, one named in a deny", `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', 'cluster', 'k2', 'd', '{group:b}', '{}', '{cluster:login}')`, false},
	} {
		for _, mixed := range []bool{false, true} {
			name := c.name
			if mixed {
				name += ", while another group's members change the other way"
			}
			t.Run(name, func(t *testing.T) {
				h := grouped(t)
				ctx := t.Context()
				h.groups(t, "a", "b")
				h.join(t, "u", "v")
				if _, err := h.pool.Exec(ctx, c.reach); err != nil {
					t.Fatal(err)
				}
				// b reaches k2, where the manager may change nothing; a reaches nothing.
				u, v := rbac.Member{Group: "a", Principal: identity("u")}, rbac.Member{Group: "b", Principal: identity("v")}
				// Whether each joins its group, rather than leaves it.
				joins := map[string]bool{"a": c.joins != mixed, "b": c.joins}
				var add, remove []rbac.Member
				for _, m := range []rbac.Member{u, v} {
					if joins[m.Group] {
						add = append(add, m)
						continue
					}
					if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', $1, 'user', $2)`,
						m.Group, m.Principal.ID); err != nil {
						t.Fatal(err)
					}
					remove = append(remove, m)
				}
				manager := h.as(t, "manager")
				if err := h.authz.ChangeMembers(ctx, manager, "t1", add, remove); !errors.Is(err, rbac.ErrDenied) {
					t.Fatalf("a change of the members of a and b, which reaches k2: %v", err)
				}
				// a's member alone changes, as a reaches nothing.
				add, remove = slices.DeleteFunc(add, func(m rbac.Member) bool { return m.Group == "b" }), slices.DeleteFunc(remove, func(m rbac.Member) bool { return m.Group == "b" })
				if err := h.authz.ChangeMembers(ctx, manager, "t1", add, remove); err != nil {
					t.Fatalf("a change of the members of a alone: %v", err)
				}
			})
		}
	}
}

func TestSearchesReadCustomRolesPrivilegedWhereEveryBuiltInRoleIs(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = slices.Clone(c.Catalog)
		for i := range c.Catalog {
			c.Catalog[i].Privileged = true
		}
	})
	ctx := t.Context()
	resources := hostTable(t, h)
	// As a catalog change that makes every role privileged leaves it.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.view', '{cluster:view}', '{cluster}');
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'tenant', 't1', 'members', 't1', 'custom.view')`); err != nil {
		t.Fatal(err)
	}
	member := h.as(t, "member")
	listingsAgree(t, h, resources, member, view)
	if holders, err := h.authz.Holders(ctx, view, resources[0]); err != nil || slices.Contains(holderPrincipals(holders), rbac.TenantMembers("t1")) {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
}

func TestWideningAPrivilegedRoleAsksNothingOfGrantsThatGiveNothing(t *testing.T) {
	var asked []rbac.GrantInput
	h := grouped(t, func(c *rbac.Config) {
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			if in.Binding.Principal.Kind == rbac.Members {
				return fmt.Errorf("%w: not through the members", rbac.ErrInvalid)
			}
			return nil
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}}); err != nil {
		t.Fatal(err)
	}
	// Privileged, as it gives root, and held by the members, as a catalog change would leave it:
	// through them it gives nothing. A group's grant gives it, so the host is asked about it.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.op', '{cluster:view,cluster:root}', '{cluster}');
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES
		  ('t1', 'cluster', 'c1', 'members', 't1', 'custom.op'), ('t1', 'cluster', 'c1', 'group', 'devs', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	asked = nil
	widened := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login, root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil || len(asked) != 1 || asked[0].Binding.Principal != groupOf("devs") {
		t.Fatalf("widening a role the members and a group hold: %v, asked %+v", err, asked)
	}
}

// A role the catalog makes privileged gives the tenant's members nothing through a grant to them,
// so widening it asks the host nothing about that grant. Narrowing it so that it is no longer
// privileged gives them what it gives then, what was added while it gave them nothing too, so the
// host is asked about that grant, as the role will be, and refusing it refuses the narrowing.
func TestNarrowingARoleSoItIsNoLongerPrivilegedAsksAboutTheMembersGrant(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer) })
	ctx := t.Context()
	admin := roleAdmin(t, h)
	x := rbac.RoleDefinition{ID: "custom.x", Permissions: []rbac.Permission{login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", x); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), x.ID, rbac.Members, "t1"))
	member := h.as(t, "m")
	// The catalog makes logging in privileged, so x is, and the members' grant gives nothing.
	cfg := h.cfg
	cfg.Catalog = slices.Clone(cfg.Catalog)
	for i, r := range cfg.Catalog {
		if r.ID == "cluster.login" {
			cfg.Catalog[i].Privileged = true
		}
	}
	var asked []rbac.GrantInput
	refuseMembers := true
	cfg.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
		asked = append(asked, in)
		if refuseMembers && in.Binding.Principal.Kind == rbac.Members {
			return fmt.Errorf("%w: not through the members", rbac.ErrInvalid)
		}
		return nil
	}
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.Authorize(ctx, member, login, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a privileged role through the members: %v", err)
	}
	x.Permissions = []rbac.Permission{login, view}
	if err := authz.SetRole(ctx, admin, "t1", x); err != nil || len(asked) != 0 {
		t.Fatalf("widening a privileged role the members hold: %v, asked %+v", err, asked)
	}
	// Narrowed to what a role that isn't privileged gives, the members' grant would give every
	// member view on every cluster.
	x.Permissions = []rbac.Permission{view}
	err = authz.SetRole(ctx, admin, "t1", x)
	var ie *rbac.InvalidError
	if !errors.As(err, &ie) || ie.Binding.Principal != rbac.TenantMembers("t1") {
		t.Fatalf("narrowing a role the members hold so that it is no longer privileged: %v", err)
	}
	if len(asked) != 1 || asked[0].Via != rbac.ViaRedefinition || asked[0].Scope != rbac.TenantRoot("t1") ||
		asked[0].Role.Privileged || !slices.Equal(asked[0].Role.Permissions, x.Permissions) || asked[0].Actor.Principal != admin.Principal {
		t.Fatalf("asked = %+v", asked)
	}
	if err := authz.Authorize(ctx, member, view, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a refused narrowing gave the members view: %v", err)
	}
	// Once the host lets the members hold it, it gives them what it gives.
	refuseMembers, asked = false, nil
	if err := authz.SetRole(ctx, admin, "t1", x); err != nil || len(asked) != 1 {
		t.Fatalf("narrowing it once the host lets the members hold it: %v, asked %+v", err, asked)
	}
	if err := authz.Authorize(ctx, member, view, cluster); err != nil {
		t.Fatalf("the members' grant of a role no longer privileged: %v", err)
	}
}

func TestAPrivilegedRoleForTheMembersIsRefusedBeforeTheHostIsAsked(t *testing.T) {
	var asked []rbac.GrantInput
	h := setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			return nil
		}
	})
	ctx := t.Context()
	sudo := rbac.Binding{Role: "cluster.sudo", Principal: rbac.TenantMembers("t1")}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{sudo}}); !errors.Is(err, rbac.ErrInvalid) || len(asked) != 0 {
		t.Fatalf("Apply: %v, asked %+v", err, asked)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: sudo}}); !errors.Is(err, rbac.ErrInvalid) || len(asked) != 0 {
		t.Fatalf("Import: %v, asked %+v", err, asked)
	}
}

func TestImportingMembersAsksAboutWhatAGroupHolds(t *testing.T) {
	var asked []rbac.GrantInput
	h := grouped(t, func(c *rbac.Config) {
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Via != rbac.ViaMembership {
				return nil
			}
			asked = append(asked, in)
			if in.Binding.Principal.Kind == "service_account" {
				return fmt.Errorf("%w: service accounts hold no privileged role", rbac.ErrInvalid)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
	bot := h.member(t, rbac.Principal{Kind: "service_account", ID: "ci"})
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: bot.Principal}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing a service account into a group holding a privileged role: %v", err)
	}
	if got, err := h.authz.Members(ctx, "t1", "admins"); err != nil || len(got) != 0 {
		t.Fatalf("Members = %+v, %v", got, err)
	}
	asked = nil
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0].Binding.Principal != identity("u") || asked[0].Actor.Principal != host || asked[0].Binding.Role != "cluster.sudo" {
		t.Fatalf("asked = %+v", asked)
	}
	// A place made to end sooner gains nothing, so the host is asked about none of it, as by
	// ChangeMembers, and refuses none of it: here, the service account's, in admins around the hooks.
	h.member(t, bot.Principal, "admins")
	asked = nil
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: bot.Principal, ExpiresAt: h.now.Add(time.Hour)}}); err != nil || len(asked) != 0 {
		t.Fatalf("importing the service account's place to end sooner: %v, asked %+v", err, asked)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: bot.Principal, ExpiresAt: h.now.Add(2 * time.Hour)}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing it to end later, gaining what admins holds meanwhile: %v", err)
	}
}

func TestImportingMembersWaitsOnlyForWhatTheHostIsAsked(t *testing.T) {
	var h *harness
	var meanwhile func(ctx context.Context) error
	h = grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	h.join(t, "u")
	// The host's write isn't checked against denies, so one exempting the group meanwhile changes
	// nothing it was asked about.
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
			ID: "d", Principals: []rbac.Principal{{Kind: rbac.Public}},
			Exempt: []rbac.Principal{groupOf("admins")}, Permissions: []rbac.Permission{root},
		})
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}); err != nil {
		t.Fatalf("importing while a deny exempting the group is set: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the host wasn't asked about what u gains")
	}
}

func TestTheHostsGroupsMembersOnlyItChanges(t *testing.T) {
	var asked []rbac.GrantInput
	h := grouped(t, func(c *rbac.Config) {
		c.Sources = []string{"directory"}
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaMembership {
				asked = append(asked, in)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{
		{ID: "synced", Source: "directory"}, {ID: "synced-admins", Source: "directory"},
	}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "synced-admins"))
	h.join(t, "u")
	if err := h.authz.ChangeMembers(ctx, h.as(t, "lead"), "t1", []rbac.Member{{Group: "synced", Principal: identity("u")}}, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("adding a member to the host's group: %v", err)
	}
	// Refused before the host is asked about what the member would gain.
	add := []rbac.Member{{Group: "synced-admins", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, rbac.ErrInvalid) || len(asked) != 0 {
		t.Fatalf("adding a member to the host's group holding a role: %v, asked %+v", err, asked)
	}
}

// A change to members waits for a transaction changing a group it adds an identity to, and is
// refused for what that commits: a grant to it the change wasn't checked as making, the group
// made again holding a role, or the group taken by the host, whose members ImportMembers changes.
func TestChangingMembersWaitsForTheGroupsItChanges(t *testing.T) {
	for _, c := range []struct {
		name      string
		meanwhile func(context.Context, *rbac.Authorizer) error
		want      error
	}{
		{"a grant to it", func(ctx context.Context, a *rbac.Authorizer) error {
			return a.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.admin", rbac.Group, "g")})
		}, rbac.ErrConflict},
		{"made again holding a role", func(ctx context.Context, a *rbac.Authorizer) error {
			if err := a.DeleteGroups(ctx, host, "t1", []string{"g"}); err != nil {
				return err
			}
			if err := a.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "g"}}); err != nil {
				return err
			}
			return a.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.sudo", rbac.Group, "g")})
		}, rbac.ErrConflict},
		{"taken by the host", func(ctx context.Context, a *rbac.Authorizer) error {
			return a.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "g", Source: "directory"}})
		}, rbac.ErrInvalid},
	} {
		for name, add := range map[string]func(context.Context, *rbac.Authorizer, rbac.Subject, []rbac.Member) error{
			"ChangeMembers": func(ctx context.Context, a *rbac.Authorizer, actor rbac.Subject, ms []rbac.Member) error {
				return a.ChangeMembers(ctx, actor, "t1", ms, nil)
			},
			"ImportMembers": func(ctx context.Context, a *rbac.Authorizer, _ rbac.Subject, ms []rbac.Member) error {
				return a.ImportMembers(ctx, host, "t1", ms)
			},
		} {
			// The host changes its own groups' members.
			if name == "ImportMembers" && errors.Is(c.want, rbac.ErrInvalid) {
				continue
			}
			t.Run(c.name+"/"+name, func(t *testing.T) {
				h := grouped(t, func(cfg *rbac.Config) {
					cfg.Sources = []string{"directory"}
				})
				ctx := t.Context()
				if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "g"}}); err != nil {
					t.Fatal(err)
				}
				h.join(t, "u")
				actor := h.as(t, "manager")
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if err := c.meanwhile(ctx, h.authz.WithTx(tx)); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- add(ctx, h.authz, actor, []rbac.Member{{Group: "g", Principal: identity("u")}}) }()
				commitOnceWaitedOn(t, h, tx, done)
				if err := <-done; !errors.Is(err, c.want) {
					t.Fatalf("adding a member while %s: %v", c.name, err)
				}
				if got, err := h.authz.Members(ctx, "t1", "g"); err != nil || len(got) != 0 {
					t.Fatalf("Members = %+v, %v", got, err)
				}
			})
		}
	}
}

// commitOnceWaitedOn commits tx once the change reporting to done waits on it, or has finished.
func commitOnceWaitedOn(t *testing.T, h *harness, tx pgx.Tx, done chan error) {
	t.Helper()
	ctx := t.Context()
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	waitedOn(t, h, pid, done)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// waitedOn returns once a session waits on the session pid, as the change reporting to done does
// for a lock it holds, or that change has finished, leaving its result in done.
func waitedOn(t *testing.T, h *harness, pid int32, done chan error) {
	t.Helper()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			done <- err
			waiting = true
		default:
			// By the transaction it waits on, as other sessions on the server may wait on locks of their own.
			if err := h.pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// heldActivation is an activation paused in its transaction once it has written its grant, holding
// the places in groups it rests on: its session's pid, and release, which lets it commit.
type heldActivation struct {
	pid     int32
	release chan struct{}
}

// pausingActivation has the next activation made once armed is set pause in its transaction, as
// OnChange runs there, sending what it holds to paused, until it is released.
func pausingActivation(armed *atomic.Bool, paused chan<- heldActivation) func(*rbac.Config) {
	return func(c *rbac.Config) {
		onChange := c.OnChange
		c.OnChange = func(ctx context.Context, tx pgx.Tx, e rbac.ChangeEvent) error {
			if len(e.Granted) == 1 && e.Granted[0].Source == rbac.SourceActivation && armed.CompareAndSwap(true, false) {
				var pid int32
				if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				release := make(chan struct{})
				paused <- heldActivation{pid, release}
				<-release
			}
			return onChange(ctx, tx, e)
		}
	}
}

// activateAsTheHostDeletes has s activate role on r through an eligibility of eligible's while the
// host deletes eligible's grants and eligibilities: the activation reads the eligibility before the
// host's deletion commits, and pauses before committing itself, holding the places it rests on,
// once the deletion has (pausingActivation, armed with paused). So it outlasts the eligibility, as
// one made just before its deletion does, and commits once released. It returns it, and what
// Activate returns then.
func activateAsTheHostDeletes(t *testing.T, h *harness, armed *atomic.Bool, paused <-chan heldActivation, s rbac.Subject, r rbac.Resource,
	role rbac.Role, eligible rbac.Principal,
) (heldActivation, chan error) {
	t.Helper()
	ctx := t.Context()
	hostTx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hostTx.Rollback(ctx) }()
	if err := h.authz.WithTx(hostTx).DeletePrincipal(ctx, host, r.Tenant, eligible); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	activated := make(chan error, 1)
	go func() {
		_, err := h.authz.Activate(ctx, s, r, rbac.Activation{Role: role, Duration: 30 * time.Minute, Justification: "INC-1"})
		activated <- err
	}()
	var a heldActivation
	select {
	case a = <-paused:
	case err := <-activated:
		t.Fatalf("Activate: %v", err)
	}
	// A test that fails before releasing it would leave its transaction holding the places, and the
	// test's cleanup waiting on it.
	t.Cleanup(func() {
		select {
		case <-a.release:
		default:
			close(a.release)
		}
	})
	if err := hostTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return a, activated
}

func TestWhatEndedGivesAChangeToMembersNothingToCheck(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: rbac.GroupScope, ID: "devs"}, "group.members", rbac.User, "lead"))
	h.join(t, "u")
	// A grant and an eligibility devs held, and its place in admins, which holds a role, all ended,
	// though DeleteExpired hasn't removed them yet.
	ended := h.now.Add(-time.Minute)
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at) VALUES ('t1', 'cluster', 'c1', 'group', 'devs', 'cluster.sudo', $1)`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at) VALUES ('t1', 'cluster', 'c1', 'group', 'devs', 'cluster.admin', 3600, $1)`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'group', 'admins', 'cluster.sudo')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at) VALUES ('t1', 'admins', 'group', 'devs', $1)`,
	} {
		args := []any{ended}
		if !strings.Contains(q, "$1") {
			args = nil
		}
		if _, err := h.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "lead"), "t1", []rbac.Member{{Group: "devs", Principal: identity("u")}}, nil); err != nil {
		t.Fatalf("adding to a group whose access has ended: %v", err)
	}
}

func TestChangingMembersOfSeveralGroupsAsksAboutWhatEachGives(t *testing.T) {
	var asked []rbac.GrantInput
	h := grouped(t, func(c *rbac.Config) {
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaMembership {
				asked = append(asked, in)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "devs"}, {ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
	h.join(t, "u", "v")
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{
		{Group: "devs", Principal: identity("u")}, {Group: "admins", Principal: identity("v")},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0].Binding.Principal != identity("v") {
		t.Fatalf("asked = %+v", asked)
	}
}

// A change to members reads the actor's authority on every scope it reaches at once, before its
// transaction and again in it, however many there are, and asks Config.ResourceOf about each once.
func TestChangingMembersReadsTheActorsAuthorityOnceForAllItReaches(t *testing.T) {
	asked := 0
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			asked++
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "manager"), grant(rbac.TenantRoot("t1"), "guard", rbac.User, "manager"))
	h.join(t, "u", "v")
	reads := 0
	rbac.SetReadingRoles(t, func() { reads++ })
	// Joining a group granted a role on n clusters, each with a deny it is exempt from.
	join := func(group string, n int, member string) (int, int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_groups (tenant, id) VALUES ('t1', $1)`, group); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			 SELECT 't1', 'cluster', $1 || i, 'group', $1, 'cluster.login' FROM generate_series(1, $2) i`,
			`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			 SELECT 't1', 'cluster', $1 || i, 'd', '{members:t1}', ARRAY['group:' || $1], '{cluster:root}' FROM generate_series(1, $2) i`,
		} {
			if _, err := h.pool.Exec(ctx, q, group, n); err != nil {
				t.Fatal(err)
			}
		}
		reads, asked = 0, 0
		if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: group, Principal: identity(member)}}, nil); err != nil {
			t.Fatal(err)
		}
		return reads, asked
	}
	fewReads, fewAsked := join("few", 2, "u")
	manyReads, manyAsked := join("many", 40, "v")
	if manyReads != fewReads {
		t.Errorf("joining a group on 2 clusters read the actor's grants %d times, and on 40, %d", fewReads, manyReads)
	}
	if fewAsked != 2+1 || manyAsked != 40+1 {
		t.Errorf("joining a group on 2 clusters asked Config.ResourceOf %d times, and on 40, %d", fewAsked, manyAsked)
	}
	// So does one changing the members of many groups, on each of which it is checked.
	joinEach := func(n int) int {
		t.Helper()
		var add []rbac.Member
		var ids []string
		for i := range n {
			ids = append(ids, fmt.Sprintf("g%d-%d", n, i))
			add = append(add, rbac.Member{Group: ids[i], Principal: identity("u")})
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_groups (tenant, id) SELECT 't1', unnest($1::text[])`, ids); err != nil {
			t.Fatal(err)
		}
		reads = 0
		if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); err != nil {
			t.Fatal(err)
		}
		return reads
	}
	if few, many := joinEach(2), joinEach(40); many != few {
		t.Errorf("joining 2 groups read the actor's grants %d times, and 40, %d", few, many)
	}
}

// A change converts its actor's and its request's attributes once, however many scopes it checks a
// condition on, before its transaction and again in it, and each scope's resource's for that scope:
// converted again for each, adding a member to 400 groups, with a map of 40,000 entries in the
// request, took 6 seconds. Each scope's check still counts them in what it may convert, and reads
// its own resource's, converted apart, so a value it shares with them is counted again.
func TestAChangeConvertsItsActorsAndRequestsAttributesOnce(t *testing.T) {
	// Half of what a check may convert, which each scope's check counts, rather than the change.
	requested := make([]int, rbac.MaxConverted/2)
	crowded := map[string]any{"open": true, "l": make([]int, rbac.MaxConverted/2)}
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			r, err := resourceOf(ctx, tenant, s)
			switch {
			case s.Type != rbac.GroupScope:
			case s.ID == "crowded":
				r.Attributes = crowded
			case s.ID == "sharing":
				// The request's list, which a check converts again, as alone.
				r.Attributes = map[string]any{"open": true, "l": requested}
			default:
				r.Attributes = map[string]any{"open": s.ID != "closed"}
			}
			return r, err
		}
	})
	g := grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead")
	g.Condition = rbac.Condition{Expression: `request.attributes.mfa == true && subject.attributes.team == "ops" && resource.attributes.open == true`}
	h.seed(t, g)
	lead := h.as(t, "lead")
	lead.Attributes = map[string]any{"team": "ops"}
	h.join(t, "u", "v")
	ids := []string{"closed", "crowded", "sharing"}
	var add []rbac.Member
	for i := range 20 {
		ids = append(ids, fmt.Sprint("g", i))
		add = append(add, rbac.Member{Group: fmt.Sprint("g", i), Principal: identity("u")})
	}
	h.groups(t, ids...)
	ctx := rbac.WithRequest(t.Context(), map[string]any{"mfa": true, "l": requested})
	n := rbac.CountKindsConverted(t)
	if err := h.authz.ChangeMembers(ctx, lead, "t1", add, nil); err != nil {
		t.Fatal(err)
	}
	// The actor's and the request's, and each group's before the transaction and in it.
	if want := 2 + 2*len(add); *n != want {
		t.Errorf("adding a member to %d groups converted %d kinds' attributes, want %d", len(add), *n, want)
	}
	for _, id := range []string{"closed", "crowded", "sharing"} {
		if err := h.authz.ChangeMembers(ctx, lead, "t1", []rbac.Member{{Group: id, Principal: identity("u")}}, nil); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("adding a member to %s: %v", id, err)
		}
	}
	// The crowded and the sharing group's attributes alone fit.
	for _, id := range []string{"crowded", "sharing"} {
		if err := h.authz.ChangeMembers(rbac.WithRequest(t.Context(), map[string]any{"mfa": true}), lead, "t1",
			[]rbac.Member{{Group: id, Principal: identity("u")}}, nil); err != nil {
			t.Errorf("adding a member to %s with a small request: %v", id, err)
		}
	}
}

// A change decides each scope it reaches as a change of that scope alone does, however many it
// reaches, whatever attributes its actor, its request and each scope's resource pass, sharing values
// or not, about what a check converts or past it, and whatever a hook of the host's drops of the
// actor's once its first check converted them: each check counts the actor's and the request's,
// converted once for the change, as its own, and reads each resource's as its own.
func TestAChangeDecidesEachScopeAsAChangeOfItAloneDoes(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := mathrand.New(mathrand.NewPCG(seed, 43))
	var resources map[string]func() map[string]any
	var n *int
	var dropping func()
	// converted is how many kinds' attributes were converted before the change under way.
	var converted int
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			r, err := resourceOf(ctx, tenant, s)
			if made, ok := resources[s.ID]; ok && s.Type == rbac.GroupScope {
				r.Attributes = made()
			}
			return r, err
		}
		c.Constraints = []rbac.Constraint{{Name: "dropping", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
			if dropping != nil && *n > converted {
				dropping()
				dropping = nil
			}
			return false, nil
		}}}
	})
	g := grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead")
	g.Condition = rbac.Condition{Expression: `size(request.attributes) >= 0 && size(subject.attributes) >= 0 && size(resource.attributes) >= 0 &&
		resource.attributes.many.all(m, m.by == "resource")`}
	h.seed(t, g)
	lead := h.as(t, "lead")
	var members []string
	for i := range 200 {
		members = append(members, fmt.Sprint("m", i))
	}
	h.join(t, members...)
	// Maps a check makes as it converts a resource's attributes, after a hook dropped the actor's.
	var many strings.Builder
	for i := range 100 {
		fmt.Fprintf(&many, `,{"by": "resource", "i": %d}`, i)
	}
	parsed := json.RawMessage("[" + many.String()[1:] + "]")
	n = rbac.CountKindsConverted(t)
	for trial := range 8 {
		shared := drawnShared(rng, true)
		actorSeed, ctx := rng.Uint64(), rbac.WithRequest(t.Context(), drawnAttributes(rng, shared, false))
		// The actor as the host passes it to each change, and with drop what a hook of the host's
		// drops of it.
		actor := func() (rbac.Subject, func()) {
			s := lead
			s.Attributes = drawnAttributes(mathrand.New(mathrand.NewPCG(actorSeed, 0)), shared, true)
			byName, listed := map[string]map[string]any{}, make([]*[4]int, 20)
			for i := range 50 {
				byName[fmt.Sprint(i)] = map[string]any{"by": "actor", "i": i}
			}
			for i := range listed {
				listed[i] = &[4]int{i}
			}
			s.Attributes["byName"], s.Attributes["listed"] = byName, listed
			return s, func() {
				clear(byName)
				clear(listed)
				s.Attributes["a0"] = struct{}{}
				runtime.GC()
			}
		}
		var ids []string
		resources = map[string]func() map[string]any{}
		for i := range 5 {
			id, resourceSeed := fmt.Sprintf("t%dg%d", trial, i), rng.Uint64()
			ids = append(ids, id)
			resources[id] = func() map[string]any {
				attributes := drawnAttributes(mathrand.New(mathrand.NewPCG(resourceSeed, 0)), shared, true)
				attributes["many"] = parsed
				return attributes
			}
		}
		h.groups(t, ids...)
		change := func(groups []string, drop bool) error {
			s, drops := actor()
			if drop {
				dropping, converted = drops, *n
			}
			defer func() { dropping = nil }()
			var add []rbac.Member
			for _, id := range groups {
				add = append(add, rbac.Member{Group: id, Principal: identity(members[0])})
				members = members[1:]
			}
			err := h.authz.ChangeMembers(ctx, s, "t1", add, nil)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				t.Fatal(err)
			}
			return err
		}
		var allowed, denied []string
		for _, id := range ids {
			if change([]string{id}, false) == nil {
				allowed = append(allowed, id)
			} else {
				denied = append(denied, id)
			}
		}
		if len(allowed) > 0 {
			if err := change(allowed, true); err != nil {
				t.Errorf("trial %d: adding members to %v, each allowed alone: %v", trial, allowed, err)
			}
		}
		for _, id := range denied {
			if err := change(append(slices.Clone(allowed), id), true); err == nil {
				t.Errorf("trial %d: adding members to %v, %s denied alone, was allowed", trial, allowed, id)
			}
		}
	}
}

// The member a grant it gains names decides nothing of the actor's power to make it, so members
// gaining the same grant are decided as one: an actor that changes access on the scope but may not
// make it is refused it once, however many gain it, having allocated no more for them.
func TestMembersGainingAGrantAreDecidedAsOne(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "crew")
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"))
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.granter', '{cluster:view,cluster:grant}', '{cluster}')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		 SELECT 't1', 'cluster', 'k' || i, p, id, r FROM generate_series(1, 25) i,
		   (VALUES ('group', 'crew', 'cluster.login'), ('user', 'lead', 'custom.granter')) AS g(p, id, r)`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	lead := h.as(t, "lead")
	var allocated uint64
	rbac.SetDecidingGrants(t, func() func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		before := m.TotalAlloc
		return func() {
			runtime.ReadMemStats(&m)
			allocated += m.TotalAlloc - before
		}
	})
	n := 0
	// How many refusals adding count members to the group holds, and what deciding them allocated.
	refuse := func(count int) (int, uint64) {
		t.Helper()
		var add []rbac.Member
		var ms []rbac.Membership
		for range count {
			n++
			p := identity(fmt.Sprintf("m%d", n))
			add, ms = append(add, rbac.Member{Group: "crew", Principal: p}), append(ms, rbac.Membership{Principal: p})
		}
		if err := h.authz.SetMemberships(ctx, host, "t1", ms); err != nil {
			t.Fatal(err)
		}
		allocated = 0
		err := h.authz.ChangeMembers(ctx, lead, "t1", add, nil)
		if !errors.Is(err, rbac.ErrDenied) {
			t.Fatalf("adding %d members, by one who may not grant what they gain: %v", count, err)
		}
		return denials(err), allocated
	}
	oneRefused, oneAllocated := refuse(1)
	manyRefused, manyAllocated := refuse(40)
	if manyRefused != oneRefused {
		t.Errorf("adding one member was refused %d times, and forty %d", oneRefused, manyRefused)
	}
	if manyAllocated > 2*oneAllocated {
		t.Errorf("deciding what one member gains allocated %d bytes, and forty %d", oneAllocated, manyAllocated)
	}
}

// denials is how many refusals err holds.
func denials(err error) int {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		n := 0
		for _, e := range joined.Unwrap() {
			n += denials(e)
		}
		return n
	}
	var denied *rbac.DeniedError
	if errors.As(err, &denied) {
		return 1
	}
	return 0
}

// What a member gains, loses or approves is its group's, so a change finds it once for each group,
// however many members it changes: the members leaving a group granted on many scopes, with labels
// declared, and those joining one that approves eligibilities on many, cost each scope as much
// whether one changes or many.
func TestChangingManyMembersReadsWhatTheirGroupReachesOnce(t *testing.T) {
	const few, many, small, large = 1, 100, 10, 500
	h := grouped(t, withLabels)
	ctx := t.Context()
	h.groups(t, "held-small", "held-large", "approving-small", "approving-large")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', 'm' || i FROM generate_series(1, $1::int) i`,
		4*(few+many))
	for group, n := range map[string]int{"small": small, "large": large} {
		exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', $1 || i, 'group', $1, 'cluster.login' FROM generate_series(1, $2::int) i`, "held-"+group, n)
		exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			SELECT 't1', 'cluster', $1 || i, 'user', 'x', 'cluster.login', 3600, ARRAY['group:' || $1] FROM generate_series(1, $2::int) i`,
			"approving-"+group, n)
	}
	// The manager may set the eligibilities joining a group that approves them hands on.
	exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT tenant, scope_type, scope_id, 'user', 'manager', 'cluster.admin' FROM rbac_eligibilities WHERE tenant = 't1'`)
	// Those leaving are members of the groups granted access, each of its own.
	exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', CASE WHEN i <= $1 THEN 'held-small' ELSE 'held-large' END, 'user', 'm' || i FROM generate_series(1, 2 * $1::int) i`,
		few+many)
	manager := h.as(t, "manager")
	next := map[string]int{"held-small": 0, "held-large": few + many, "approving-small": 2 * (few + many), "approving-large": 3 * (few + many)}
	// The bytes a change of count members of group, joining or leaving it, allocates.
	change := func(group string, count int, leaving bool) uint64 {
		t.Helper()
		var ms []rbac.Member
		for range count {
			next[group]++
			ms = append(ms, rbac.Member{Group: group, Principal: identity(fmt.Sprintf("m%d", next[group]))})
		}
		add, remove := ms, []rbac.Member(nil)
		if leaving {
			add, remove = nil, ms
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if err := h.authz.ChangeMembers(ctx, manager, "t1", add, remove); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	for _, c := range []struct {
		name    string
		of      string
		leaving bool
	}{
		{"leaving a group granted on many scopes", "held", true},
		{"joining a group approving eligibilities on many scopes", "approving", false},
	} {
		// What the larger group's scopes add to a change of count members.
		grows := func(count int) uint64 {
			t.Helper()
			s := change(c.of+"-small", count, c.leaving)
			return change(c.of+"-large", count, c.leaving) - s
		}
		one, all := grows(few), grows(many)
		if all > one+one/2 {
			t.Errorf("%s: %d more scopes cost a change of %d members %d bytes, and of %d, %d", c.name, large-small, few, one, many, all)
		}
	}
}

// What the members of many groups reach through a group those are all in is that group's, so a
// change finds it once, however many of the groups change: members leaving many groups in one
// granted on many scopes, with labels declared, those joining many in one that approves
// eligibilities on many, and those joining many in one granted on more than MaxBindings, which are
// refused, cost each scope as much whether few groups change or many.
func TestChangingMembersOfManyGroupsReadsWhatAGroupTheyAreInReachesOnce(t *testing.T) {
	const few, many = 2, 100
	h := grouped(t, withLabels)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, of         string
		small, large     int
		leaving, refused bool
	}{
		{"leaving groups in one granted on many scopes", "held", 10, 500, true, false},
		{"joining groups in one approving eligibilities on many scopes", "approving", 10, 500, false, false},
		{"joining groups in one granted on more scopes than a change gains", "over", rbac.MaxBindings + 1, 2 * rbac.MaxBindings, false, true},
	}
	// Each of few+many groups in an outer one has a member, which a change adds or removes.
	identities := 0
	member := map[string]rbac.Principal{}
	for _, c := range cases {
		for size, n := range map[string]int{"small": c.small, "large": c.large} {
			outer := c.of + "-" + size
			exec(`INSERT INTO rbac_groups (tenant, id) SELECT 't1', $1 UNION ALL SELECT 't1', $1 || '-' || i FROM generate_series(1, $2::int) i`,
				outer, few+many)
			exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
				SELECT 't1', $1, 'group', $1 || '-' || i FROM generate_series(1, $2::int) i`, outer, few+many)
			if c.of == "approving" {
				exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					SELECT 't1', 'cluster', $1 || '-k' || i, 'user', 'x', 'cluster.login', 3600, ARRAY['group:' || $1]
					FROM generate_series(1, $2::int) i`, outer, n)
			} else {
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'cluster', $1 || '-k' || i, 'group', $1, 'cluster.login' FROM generate_series(1, $2::int) i`, outer, n)
			}
			for i := range few + many {
				identities++
				group := fmt.Sprintf("%s-%d", outer, i+1)
				member[group] = identity(fmt.Sprintf("m%d", identities))
				if c.leaving {
					exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', $1, 'user', $2)`,
						group, member[group].ID)
				}
			}
		}
	}
	exec(`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', 'm' || i FROM generate_series(1, $1::int) i`,
		identities)
	// The manager may set the eligibilities joining a group that approves them hands on.
	exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT tenant, scope_type, scope_id, 'user', 'manager', 'cluster.admin' FROM rbac_eligibilities WHERE tenant = 't1'`)
	manager := h.as(t, "manager")
	next := map[string]int{}
	for _, c := range cases {
		// The bytes a change of the members of count groups in outer allocates.
		change := func(outer string, count int) uint64 {
			t.Helper()
			var ms []rbac.Member
			for range count {
				next[outer]++
				g := fmt.Sprintf("%s-%d", outer, next[outer])
				ms = append(ms, rbac.Member{Group: g, Principal: member[g]})
			}
			add, remove := ms, []rbac.Member(nil)
			if c.leaving {
				add, remove = nil, ms
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			err := h.authz.ChangeMembers(ctx, manager, "t1", add, remove)
			runtime.ReadMemStats(&after)
			if c.refused && !errors.Is(err, rbac.ErrInvalid) || !c.refused && err != nil {
				t.Fatalf("%s: the members of %d groups in %s: %v", c.name, count, outer, err)
			}
			return after.TotalAlloc - before.TotalAlloc
		}
		// What the larger outer group's scopes add to a change of the members of count groups in it.
		grows := func(count int) uint64 {
			t.Helper()
			s := change(c.of+"-small", count)
			return change(c.of+"-large", count) - s
		}
		one, all := grows(few), grows(many)
		if all > one+one/2 {
			t.Errorf("%s: %d more scopes cost a change of %d groups %d bytes, and of %d, %d", c.name, c.large-c.small, few, one, many, all)
		}
	}
}

// The host is asked about each grant and eligibility a member gains as the member's, so the members
// one ChangeMembers adds gain at most MaxBindings of them, each member's counted apart, as one Apply
// makes at most as many grants: past it, it is refused before the host is asked about any, or the
// actor's power to make them decided. A member whose place lasts as long already gains nothing, so
// counts for nothing, and one alone gains whatever its group holds, or a group holding more could
// never gain one. The host's own ImportMembers, which no actor's access decides, takes the same
// change, asking about each grant each member gains.
func TestMembersGainAtMostMaxBindingsGrantsInAChange(t *testing.T) {
	const grants = 100
	members := rbac.MaxBindings / grants
	var validated, resourceOf, decided int
	h := grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaMembership {
				validated++
			}
			return validate(ctx, q, in)
		}
		of := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == "cluster" {
				resourceOf++
			}
			return of(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.groups(t, "crew", "synced", "all", "empty")
	// Each group holds a role on each of n clusters, which the manager may grant there.
	for group, n := range map[string]int{"crew": grants, "synced": grants, "all": rbac.MaxBindings + 1} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', $1 || i, p, id, r FROM generate_series(1, $2::int) i,
			  (VALUES ('group', $1, 'cluster.login'), ('user', 'manager', 'cluster.admin')) AS g(p, id, r)`, group, n); err != nil {
			t.Fatal(err)
		}
	}
	rbac.SetDecidingGrants(t, func() func() {
		decided++
		return func() {}
	})
	var ids []string
	var add []rbac.Member
	for i := range members + 1 {
		ids = append(ids, fmt.Sprintf("m%d", i))
		add = append(add, rbac.Member{Group: "crew", Principal: identity(ids[i])})
	}
	h.join(t, ids...)
	manager := h.as(t, "manager")
	synced := slices.Clone(add)
	for i := range synced {
		synced[i].Group = "synced"
	}
	validated, resourceOf, decided = 0, 0, 0
	if err := h.authz.ChangeMembers(ctx, manager, "t1", synced, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("ChangeMembers: %d members gaining %d grants each: %v", len(synced), grants, err)
	}
	if validated+resourceOf+decided > 0 {
		t.Fatalf("ChangeMembers: refused having asked Config.ValidateGrant %d times and Config.ResourceOf %d, and decided grants on %d scopes",
			validated, resourceOf, decided)
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", synced); err != nil || validated != len(synced)*grants {
		t.Fatalf("ImportMembers: %d members gaining %d grants each: %v, Config.ValidateGrant asked %d times", len(synced), grants, err, validated)
	}
	validated = 0
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add[:members], nil); err != nil || validated != rbac.MaxBindings {
		t.Fatalf("%d members gaining %d grants each: %v, Config.ValidateGrant asked %d times", members, grants, err, validated)
	}
	for i := range members {
		add[i].Note = "kept"
	}
	validated = 0
	if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); err != nil || validated != grants {
		t.Fatalf("one member gaining %d grants, and %d whose notes alone change: %v, Config.ValidateGrant asked %d times", grants, members, err, validated)
	}
	h.join(t, "x", "y")
	two := []rbac.Member{{Group: "all", Principal: identity("x")}, {Group: "all", Principal: identity("y")}}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", two, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("two members each gaining %d grants: %v", rbac.MaxBindings+1, err)
	}
	validated = 0
	// Joining a group holding nothing gains nothing, so it leaves the other member alone in gaining.
	alone := []rbac.Member{two[0], {Group: "empty", Principal: identity("y")}}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", alone, nil); err != nil || validated != rbac.MaxBindings+1 {
		t.Fatalf("one member alone gaining %d grants, and one gaining none: %v, Config.ValidateGrant asked %d times", rbac.MaxBindings+1, err, validated)
	}
}

// A member is its principal: added to a group from several sources, and to a group that one is in,
// it gains what they reach, and the host is asked about each grant it gains once, so it gains no
// more than one of those places alone, whatever its group holds. Past MaxBindings, a change gains no
// more than one place alone does: one member joining two groups that hold more in all, or two
// members, are refused before the host is asked about any of it.
func TestAMemberAddedToSeveralGroupsIsOneMember(t *testing.T) {
	var validated int
	h := grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaMembership {
				validated++
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	h.groups(t, "g1", "g2", "top")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "top", Principal: groupOf("g1")}, {Group: "top", Principal: groupOf("g2")}}); err != nil {
		t.Fatal(err)
	}
	// Each group holds a role on each of n clusters, which the manager may grant there.
	held := map[string]int{"g1": 800, "g2": 400, "top": 300}
	for group, n := range held {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', $1 || i, p, id, r FROM generate_series(1, $2::int) i,
			  (VALUES ('group', $1, 'cluster.login'), ('user', 'manager', 'cluster.admin')) AS g(p, id, r)`, group, n); err != nil {
			t.Fatal(err)
		}
	}
	h.join(t, "ann", "bob", "carol", "dan")
	manager := h.as(t, "manager")
	ann := []rbac.Member{{Group: "g1", Principal: identity("ann")}, {Group: "g1", Principal: identity("ann"), Source: "ops"}, {Group: "top", Principal: identity("ann")}}
	gains := held["g1"] + held["top"]
	if err := h.authz.ChangeMembers(ctx, manager, "t1", ann, nil); err != nil || validated != gains {
		t.Fatalf("one member added to a group from two sources, and to the group it is in, gaining %d grants: %v, Config.ValidateGrant asked %d times",
			gains, err, validated)
	}
	for what, add := range map[string][]rbac.Member{
		"one member added to two groups":    {{Group: "g1", Principal: identity("dan")}, {Group: "g2", Principal: identity("dan")}},
		"two members added to a group each": {{Group: "g1", Principal: identity("bob")}, {Group: "g2", Principal: identity("carol")}},
	} {
		validated = 0
		if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrInvalid) || validated != 0 {
			t.Errorf("%s, gaining more than MaxBindings in all and than either place alone: %v, Config.ValidateGrant asked %d times", what, err, validated)
		}
	}
}

// A principal joining many groups that are all in one gains what that one holds once, so a change
// gaining more than MaxBindings through it is no more than one place in it alone: what it builds,
// and asks the host about, is that, not that for each group it joins, so it allocates about as
// much as one member joining that group does.
func TestAMemberJoiningManyGroupsInOneBuildsWhatOnePlaceGains(t *testing.T) {
	var validated int
	h := grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaMembership {
				validated++
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	var groups []string
	for i := range rbac.MaxBindings {
		groups = append(groups, fmt.Sprintf("g%d", i))
	}
	h.groups(t, append(groups, "top")...)
	// Each group is in top, which holds a role on more clusters than MaxBindings, which the manager
	// may grant there.
	grants := rbac.MaxBindings + 1
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'top', 'group', unnest($1::text[])`, groups); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 't1', 'cluster', 'top' || i, p, id, r FROM generate_series(1, $1::int) i,
		  (VALUES ('group', 'top', 'cluster.login'), ('user', 'manager', 'cluster.admin')) AS g(p, id, r)`, grants); err != nil {
		t.Fatal(err)
	}
	h.join(t, "ann", "bob")
	manager := h.as(t, "manager")
	// What a change adding add allocates, and how often it asks the host.
	change := func(add []rbac.Member) (uint64, int) {
		t.Helper()
		validated = 0
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		before := m.TotalAlloc
		if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); err != nil {
			t.Fatalf("adding %d members: %v", len(add), err)
		}
		runtime.ReadMemStats(&m)
		return m.TotalAlloc - before, validated
	}
	one, asked := change([]rbac.Member{{Group: "top", Principal: identity("bob")}})
	if asked != grants {
		t.Fatalf("one member added to top, gaining %d grants: Config.ValidateGrant asked %d times", grants, asked)
	}
	var add []rbac.Member
	for _, g := range groups {
		add = append(add, rbac.Member{Group: g, Principal: identity("ann")})
	}
	many, asked := change(add)
	if asked != grants || many > 8*one {
		t.Fatalf("one member added to %d groups in top, gaining %d grants: Config.ValidateGrant asked %d times, and allocated %d MiB, one place in top %d MiB",
			len(add), grants, asked, many>>20, one>>20)
	}
}

// A principal leaving many groups that are all in one, through which it activated on many scopes,
// loses access on each of those scopes once, so what the change builds for its activations is
// found once for the principal, not once for each group it leaves: they cost it about what they
// cost leaving one of the groups.
func TestAMemberLeavingManyGroupsInOneReadsItsActivationsOnce(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		// Declared, so a removal reads what its members lose, as a freeze could stop it taking that
		// away; it stops nothing.
		c.Constraints = []rbac.Constraint{{Name: "thawed", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) { return false, nil }}}
	})
	ctx := t.Context()
	var groups []string
	for i := range rbac.MaxBindings {
		groups = append(groups, fmt.Sprintf("g%d", i))
	}
	h.groups(t, append(groups, "top")...)
	h.join(t, "u")
	// Each group is in top, and u in each, and in top itself, so it keeps what top gives, and its
	// activations through top, however many of the others it leaves.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'top', 'group', unnest($1::text[]) UNION ALL SELECT 't1', 'top', 'user', 'u'`, groups); err != nil {
		t.Fatal(err)
	}
	activated := func(n int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND source = 'activation'`); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
			SELECT 't1', 'cluster', 'top' || i, 'user', 'u', 'cluster.login', 'activation', $2, 'group:top' FROM generate_series(1, $1::int) i`,
			n, h.now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	manager := h.as(t, "manager")
	// What a change removing remove allocates, its places made again after it.
	change := func(remove []rbac.Member) uint64 {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', unnest($1::text[]), 'user', 'u' ON CONFLICT DO NOTHING`, groups); err != nil {
			t.Fatal(err)
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		before := m.TotalAlloc
		if err := h.authz.ChangeMembers(ctx, manager, "t1", nil, remove); err != nil {
			t.Fatalf("removing %d members: %v", len(remove), err)
		}
		runtime.ReadMemStats(&m)
		return m.TotalAlloc - before
	}
	var all []rbac.Member
	for _, g := range groups {
		all = append(all, rbac.Member{Group: g, Principal: identity("u")})
	}
	activated(1)
	bare := change(all)
	activated(rbac.MaxBindings)
	one, many := change(all[:1]), change(all)
	if many > bare+8*one {
		t.Fatalf("a member with %d activations through top leaving %d groups in it allocated %d MiB, with one activation %d MiB, and leaving one of them %d MiB",
			rbac.MaxBindings, len(all), many>>20, bare>>20, one>>20)
	}
}

// A change to members is checked again in its transaction: an actor that lost the power to make
// what it makes while the host was asked about it is refused.
func TestChangingMembersIsCheckedAgainUnderItsLocks(t *testing.T) {
	var meanwhile func(ctx context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}, {ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"), grant(cluster.Scope(), "guard", rbac.User, "manager"),
		grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	h.join(t, "u")
	manager, guardian := h.as(t, "manager"), h.as(t, "guardian")
	if err := h.authz.SetDeny(ctx, manager, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{groupOf("oncall")}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}, {Group: "oncall", Principal: identity("u")}}
	for name, lose := range map[string]func(context.Context) error{
		"the power to grant": func(ctx context.Context) error {
			return h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "no-grant", Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{grantC}})
		},
		// It may still grant, but not hand on what the group holds.
		"the power to hand it on": func(ctx context.Context) error {
			return h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "no-grant", Principals: []rbac.Principal{manager.Principal}, Permissions: []rbac.Permission{login}})
		},
		"the power to deny": func(ctx context.Context) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "guard", rbac.User, "manager")})
		},
	} {
		meanwhile = lose
		if err := h.authz.ChangeMembers(ctx, manager, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("losing %s meanwhile: %v", name, err)
		}
		if err := h.authz.DeleteDeny(ctx, guardian, cluster, "no-grant"); err != nil {
			t.Fatal(err)
		}
		h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "manager"))
	}
}

func TestARoleWidenedWhileMembersAreAskedAboutIsTriedAgain(t *testing.T) {
	for name, add := range map[string]func(context.Context, *harness, []rbac.Member) error{
		"ChangeMembers": func(ctx context.Context, h *harness, ms []rbac.Member) error {
			return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", ms, nil)
		},
		"ImportMembers": func(ctx context.Context, h *harness, ms []rbac.Member) error {
			return h.authz.ImportMembers(ctx, host, "t1", ms)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var meanwhile func(ctx context.Context) error
			h := grouped(t, func(c *rbac.Config) {
				c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
					if do := meanwhile; do != nil && in.Via == rbac.ViaMembership {
						meanwhile = nil
						return do(ctx)
					}
					return nil
				}
			})
			ctx := t.Context()
			admin := roleAdmin(t, h)
			op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(cluster.Scope(), op.ID, rbac.Group, "ops"))
			h.join(t, "u")
			meanwhile = func(ctx context.Context) error {
				widened := op
				widened.Permissions = []rbac.Permission{view, login}
				return h.authz.SetRole(ctx, admin, "t1", widened)
			}
			ms := []rbac.Member{{Group: "ops", Principal: identity("u")}}
			if err := add(ctx, h, ms); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("a role the group holds widened while the host was asked: %v", err)
			}
			if err := add(ctx, h, ms); err != nil {
				t.Fatalf("tried again: %v", err)
			}
		})
	}
}

func TestConfigResourceOfIsTheScopeItIsAskedFor(t *testing.T) {
	// Every cluster given as the one the manager administers.
	h := grouped(t, func(c *rbac.Config) {
		c.ResourceOf = func(_ context.Context, _ string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == "cluster" {
				return cluster, nil
			}
			return rbac.Resource{Tenant: "t1", Type: s.Type, ID: s.ID}, nil
		}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c2"}, "cluster.login", rbac.Group, "admins"))
	h.join(t, "u")
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}, nil); err == nil {
		t.Fatal("a change checked on a resource other than the scope it reaches")
	}
}

func TestChangingMembersReadsTheTenantFromTheHostToo(t *testing.T) {
	locked := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"locked": true}}
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == locked.Scope() {
				return locked, nil
			}
			return resourceOf(ctx, tenant, s)
		}
		c.Constraints = []rbac.Constraint{{Name: "locked", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == rbac.GrantPermission(rbac.TenantScope) && in.Resource != nil && in.Resource.Attributes["locked"] == true, nil
		}}}
	})
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "leads"}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(root, "tenant.admin", rbac.Group, "leads"), grant(root, "tenant.admin", rbac.User, "manager"))
	h.join(t, "u")
	add := []rbac.Member{{Group: "leads", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting on a locked tenant through a group: %v", err)
	}
}

func TestChangingMembersReadsTheGroupFromTheHost(t *testing.T) {
	locked := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "leads", Attributes: map[string]any{"locked": true}}
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == locked.Scope() {
				return locked, nil
			}
			return resourceOf(ctx, tenant, s)
		}
		c.Constraints = []rbac.Constraint{{Name: "locked", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == rbac.GroupMembers && in.Resource != nil && in.Resource.Attributes["locked"] == true, nil
		}}}
	})
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "leads"}, {ID: "devs"}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	manager := h.as(t, "manager")
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "leads", Principal: identity("u")}}, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("adding to a locked group: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "devs", Principal: identity("u")}}, nil); err != nil {
		t.Fatalf("adding to a group that isn't locked: %v", err)
	}
}

func TestAGroupHoldingWhatCantBeGrantedNowTakesNoMembers(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "admins"}}); err != nil {
		t.Fatal(err)
	}
	// As a catalog change leaves it: a role on a scope it is no longer for.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'node', 'n1', 'group', 'admins', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}, nil)
	if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), "can't be granted there now") {
		t.Fatalf("adding to a group holding what can't be granted now: %v", err)
	}
}

func TestWithoutResourceOfTheTenantIsAsStoredOnlyWhereResourcesHaveNoAttributes(t *testing.T) {
	// Containers sit under the tenant, never above it, so they don't count here.
	blind := func(attrs rbac.Attributes) func(*rbac.Config) {
		return func(c *rbac.Config) { c.ResourceOf, c.Attributes = nil, attrs }
	}
	root := rbac.TenantRoot("t1")
	add := []rbac.Member{{Group: "leads", Principal: identity("u")}}
	for name, c := range map[string]struct {
		attrs rbac.Attributes
		want  error
	}{
		"undeclared":    {rbac.Attributes{}, rbac.ErrInvalid},
		"declared none": {rbac.Attributes{Resource: map[string]rbac.AttributeType{}}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t, blind(c.attrs))
			ctx := t.Context()
			h.seed(t, grant(root, "tenant.admin", rbac.Group, "leads"), grant(root, "tenant.admin", rbac.User, "manager"))
			h.join(t, "u")
			if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", add, nil); !errors.Is(err, c.want) {
				t.Fatalf("adding to a group holding a role on the tenant: %v", err)
			}
		})
	}
}

// A change checks the end of a membership or a place in a group again under its locks, at the time
// it reads there, as it checks a grant's: here each reading of the clock is an hour after the last,
// so an end half an hour after the change's first reading passes while it waits, and the change is
// refused rather than store and report what has already ended.
func TestAnEndPassingWhileAMembershipChangeWaitsIsRefused(t *testing.T) {
	for name, change := range map[string]func(h *harness, x rbac.Subject, ends time.Time) error{
		"SetMemberships": func(h *harness, _ rbac.Subject, ends time.Time) error {
			return h.authz.SetMemberships(h.ctx, host, "t1", []rbac.Membership{{Principal: identity("v"), ExpiresAt: ends}})
		},
		"ImportMembers": func(h *harness, _ rbac.Subject, ends time.Time) error {
			return h.authz.ImportMembers(h.ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("v"), ExpiresAt: ends}})
		},
		"ChangeMembers": func(h *harness, x rbac.Subject, ends time.Time) error {
			return h.authz.ChangeMembers(h.ctx, x, "t1", []rbac.Member{{Group: "crew", Principal: identity("v"), ExpiresAt: ends}}, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			stepping := false
			var h *harness
			h = setup(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
				c.Now = func() time.Time {
					at := h.now
					if stepping {
						h.now = h.now.Add(time.Hour)
					}
					return at
				}
			})
			h.seed(t, grant(rbac.TenantRoot("t1"), groupMembers.ID, rbac.User, "x"))
			h.groups(t, "crew")
			h.as(t, "v")
			x := h.as(t, "x")
			start := h.now
			h.events = nil
			stepping = true
			err := change(h, x, start.Add(30*time.Minute))
			stepping = false
			if read := h.now.Sub(start) / time.Hour; read != 2 {
				t.Fatalf("the change read the clock %d times, not once before its transaction and once in it: %v", read, err)
			}
			if !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("the change stored what ended while it waited: %v, events %+v", err, h.events)
			}
		})
	}
}

// waitedPast runs change at 12:01 behind a host's transaction that hold has made a change in and
// left open, moves the clock to 13:00 once change waits for it, and returns what change returns
// once the transaction commits. It holds the transaction a little longer once change waits, so a
// wait once change has read its time lasts long enough for the tests' watch of row waits to see it.
func waitedPast(t *testing.T, h *harness, clock *atomic.Int64, hold func(*rbac.Authorizer) error, change func() error) error {
	t.Helper()
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := hold(h.authz.WithTx(tx)); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	clock.Store(h.now.Add(time.Minute).UnixNano())
	done := make(chan error, 1)
	go func() { done <- change() }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("the change waited for nothing the host's transaction holds: %v", err)
		default:
		}
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	clock.Store(h.now.Add(time.Hour).UnixNano())
	time.Sleep(20 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return <-done
}

// steppedHarness is grouped at 12:00 on a clock a test moves, which a change may read from another
// goroutine, with guardRole and Config.Sources the directory.
func steppedHarness(t *testing.T) (*harness, *atomic.Int64) {
	t.Helper()
	clock := &atomic.Int64{}
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
		c.Sources = []string{"directory"}
	})
	clock.Store(h.now.UnixNano())
	return h, clock
}

// A change decides at a time it reads once it holds every lock it waits for, as one made once the
// wait was over would: here each waits from 12:01 to 13:00 behind a host's transaction holding
// rows it locks, an activation's places in groups, a change to a place, a group's deletion or an
// activation's end, and what passed at 12:10 while it waited refuses it: an actor's power to make
// it, the eligibility it activates through, or the end it sets. Decided at the time it read before
// the wait, it committed what an actor no longer had the power to, and stored what had ended.
func TestATimeAChangeWaitedPastIsTheTimeItDecidesAt(t *testing.T) {
	type fixture struct {
		h                    *harness
		v, w, manager, owner rbac.Subject
		// temp is an actor whose roles end at 12:10, and a, v's activation through outer until 12:30.
		temp rbac.Subject
		a    rbac.Grant
	}
	// approvedByCrew has crew approve x's eligibility, and name x in a deny, which crew's deletion
	// changes holding neither's scope.
	approvedByCrew := func(f *fixture) {
		f.h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "keeper"))
		x, y := f.h.as(t, "x"), f.h.as(t, "y")
		if err := f.h.authz.SetDeny(f.h.ctx, f.h.as(t, "keeper"), cluster, rbac.Deny{ID: "d1", Principals: []rbac.Principal{groupOf("crew"), x.Principal}, Permissions: []rbac.Permission{root}}); err != nil {
			t.Fatal(err)
		}
		if err := f.h.authz.SetEligibility(f.h.ctx, f.owner, cluster, rbac.Eligibility{Role: "cluster.login", Principal: x.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("crew"), y.Principal}}); err != nil {
			t.Fatal(err)
		}
	}
	deleteCrew := func(f *fixture) func(*rbac.Authorizer) error {
		approvedByCrew(f)
		return func(a *rbac.Authorizer) error { return a.DeleteGroups(f.h.ctx, host, "t1", []string{"crew"}) }
	}
	activate := func(s rbac.Subject) func(*rbac.Authorizer) error {
		return func(a *rbac.Authorizer) error {
			_, err := a.Activate(t.Context(), s, cluster, rbac.Activation{Role: "cluster.login", Duration: 5 * time.Minute, Justification: "x"})
			return err
		}
	}
	for name, c := range map[string]struct {
		hold   func(f *fixture) func(*rbac.Authorizer) error
		change func(f *fixture) error
		want   error
	}{
		"ChangeMembers by an actor whose power ended": {
			hold: func(f *fixture) func(*rbac.Authorizer) error { return activate(f.v) },
			change: func(f *fixture) error {
				return f.h.authz.ChangeMembers(f.h.ctx, f.temp, "t1", nil, []rbac.Member{{Group: "outer", Principal: groupOf("inner")}})
			},
			want: rbac.ErrDenied,
		},
		"ChangeMembers by an actor whose power ended, ending nothing": {
			hold: func(f *fixture) func(*rbac.Authorizer) error { return activate(f.v) },
			change: func(f *fixture) error {
				return f.h.authz.ChangeMembers(f.h.ctx, f.temp, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner"), Note: "kept"}}, nil)
			},
			want: rbac.ErrDenied,
		},
		"ChangeMembers setting an end that passed": {
			hold: func(f *fixture) func(*rbac.Authorizer) error { return activate(f.v) },
			change: func(f *fixture) error {
				return f.h.authz.ChangeMembers(f.h.ctx, f.manager, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner"), ExpiresAt: f.h.now.Add(10 * time.Minute)}}, nil)
			},
			want: rbac.ErrInvalid,
		},
		"ImportMembers setting an end that passed": {
			hold: func(f *fixture) func(*rbac.Authorizer) error { return activate(f.v) },
			change: func(f *fixture) error {
				return f.h.authz.ImportMembers(f.h.ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner"), ExpiresAt: f.h.now.Add(10 * time.Minute)}})
			},
			want: rbac.ErrInvalid,
		},
		"SetMemberships setting an end that passed": {
			// w's membership ended at 11:00, but its place in crew is still stored, which the deletion holds.
			hold: func(f *fixture) func(*rbac.Authorizer) error {
				if _, err := f.h.pool.Exec(f.h.ctx, `UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:w'`, f.h.now.Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
				return func(a *rbac.Authorizer) error { return a.DeleteGroups(f.h.ctx, host, "t1", []string{"crew"}) }
			},
			change: func(f *fixture) error {
				return f.h.authz.SetMemberships(f.h.ctx, host, "t1", []rbac.Membership{{Principal: f.w.Principal, ExpiresAt: f.h.now.Add(10 * time.Minute)}})
			},
			want: rbac.ErrInvalid,
		},
		"Activate through an eligibility that ended": {
			hold: func(f *fixture) func(*rbac.Authorizer) error {
				return func(a *rbac.Authorizer) error {
					return a.ImportMembers(f.h.ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner"), ExpiresAt: f.h.now.Add(3 * time.Hour)}})
				}
			},
			change: func(f *fixture) error {
				_, err := f.h.authz.Activate(f.h.ctx, f.w, cluster, rbac.Activation{Role: "cluster.login", Duration: 5 * time.Minute, Justification: "x"})
				return err
			},
			want: rbac.ErrDenied,
		},
		"Activate again through an eligibility that ended, behind a removal holding the activation": {
			// The removal of crew's ended place in outer holds the activations of crew's members,
			// w's among them, but no place w rests one on: w waits for its activation alone.
			hold: func(f *fixture) func(*rbac.Authorizer) error {
				if _, err := f.h.authz.Activate(f.h.ctx, f.w, cluster, rbac.Activation{Role: "cluster.login", Duration: 3 * time.Minute, Justification: "x"}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.h.pool.Exec(f.h.ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
					VALUES ('t1', 'outer', 'group', 'crew', $1)`, f.h.now.Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
				return func(a *rbac.Authorizer) error {
					return a.DeleteMembers(f.h.ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("crew")}})
				}
			},
			change: func(f *fixture) error {
				_, err := f.h.authz.Activate(f.h.ctx, f.w, cluster, rbac.Activation{Role: "cluster.login", Duration: 5 * time.Minute, Justification: "x"})
				return err
			},
			want: rbac.ErrDenied,
		},
		"DeleteGroup by an actor whose power ended": {
			hold:   func(f *fixture) func(*rbac.Authorizer) error { return activate(f.w) },
			change: func(f *fixture) error { return f.h.authz.DeleteGroup(f.h.ctx, f.temp, "t1", "crew") },
			want:   rbac.ErrDenied,
		},
		"SetDeny by an actor whose power ended": {
			hold: deleteCrew,
			change: func(f *fixture) error {
				return f.h.authz.SetDeny(f.h.ctx, f.temp, cluster, rbac.Deny{ID: "d1", Principals: []rbac.Principal{identity("x")}, Permissions: []rbac.Permission{root}})
			},
			want: rbac.ErrDenied,
		},
		"DeleteDeny by an actor whose power ended": {
			hold:   deleteCrew,
			change: func(f *fixture) error { return f.h.authz.DeleteDeny(f.h.ctx, f.temp, cluster, "d1") },
			want:   rbac.ErrDenied,
		},
		"SetEligibility setting an end that passed": {
			hold: deleteCrew,
			change: func(f *fixture) error {
				e := rbac.Eligibility{Role: "cluster.login", Principal: identity("x"), MaxDuration: time.Hour, ExpiresAt: f.h.now.Add(10 * time.Minute), Approvers: []rbac.Principal{identity("y")}}
				return f.h.authz.SetEligibility(f.h.ctx, f.owner, cluster, e)
			},
			want: rbac.ErrInvalid,
		},
		"DeleteEligibility by an actor whose power ended": {
			hold: deleteCrew,
			change: func(f *fixture) error {
				return f.h.authz.DeleteEligibility(f.h.ctx, f.temp, cluster, "cluster.login", identity("x"))
			},
			want: rbac.ErrDenied,
		},
		"Apply by an actor whose power ended": {
			// The removal ends v's activation through outer, holding it.
			hold: func(f *fixture) func(*rbac.Authorizer) error {
				return func(a *rbac.Authorizer) error {
					return a.DeleteMembers(f.h.ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner")}})
				}
			},
			change: func(f *fixture) error {
				return f.h.authz.Apply(f.h.ctx, f.temp, cluster, rbac.Change{Revoke: []rbac.Binding{{ID: f.a.ID, Role: f.a.Role, Principal: f.a.Principal}}})
			},
			want: rbac.ErrDenied,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, clock := steppedHarness(t)
			ctx := t.Context()
			ends := h.now.Add(10 * time.Minute)
			// v is in outer through inner; w is in inner and crew, and eligible itself until 12:10.
			h.groups(t, "outer", "inner", "crew")
			f := &fixture{h: h, v: h.as(t, "v", "inner"), w: h.as(t, "w", "inner", "crew"), manager: h.as(t, "manager"), owner: h.as(t, "owner"), temp: h.as(t, "temp")}
			var temp []rbac.Grant
			for _, g := range []rbac.Grant{
				grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "temp"),
				grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "temp"),
				grant(cluster.Scope(), "cluster.admin", rbac.User, "temp"),
				grant(cluster.Scope(), "guard", rbac.User, "temp"),
			} {
				g.ExpiresAt = ends
				temp = append(temp, g)
			}
			h.seed(t, temp...)
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "outer", Principal: groupOf("inner")}}); err != nil {
				t.Fatal(err)
			}
			for _, e := range []rbac.Eligibility{
				{Role: "cluster.login", Principal: f.v.Principal, MaxDuration: time.Hour},
				{Role: "cluster.login", Principal: f.w.Principal, MaxDuration: time.Hour, ExpiresAt: ends},
				{Role: "cluster.sudo", Principal: groupOf("outer"), MaxDuration: time.Hour},
			} {
				if err := h.authz.SetEligibility(ctx, f.owner, cluster, e); err != nil {
					t.Fatal(err)
				}
			}
			a, err := h.authz.Activate(ctx, f.v, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 30 * time.Minute, Justification: "x"})
			if err != nil {
				t.Fatal(err)
			}
			f.a = a
			hold := c.hold(f)
			if err := waitedPast(t, h, clock, hold, func() error { return c.change(f) }); !errors.Is(err, c.want) {
				t.Errorf("at 13:00, after it waited from 12:01, the change = %v, not %v", err, c.want)
			}
		})
	}
}

// A removal that waits behind an activation it would end, or cut short, ends only what is in force
// at the time it reads once it holds it: here the activation, v's through inner's place in crew,
// ends at 12:05, while the removal waits from 12:01 to 13:00, so it ends nothing. Read before the
// wait, it deleted what had ended, and reported revoking it.
func TestARemovalEndsNoActivationThatEndedWhileItWaited(t *testing.T) {
	for name, c := range map[string]struct {
		// hold makes the host's change the removal waits for; with none, v activating then.
		hold   func(h *harness, a *rbac.Authorizer) error
		remove func(h *harness) error
	}{
		"DeleteMembers": {remove: func(h *harness) error {
			return h.authz.DeleteMembers(h.ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: groupOf("inner")}})
		}},
		"DeleteGroups": {remove: func(h *harness) error { return h.authz.DeleteGroups(h.ctx, host, "t1", []string{"crew"}) }},
		"ImportGroups": {remove: func(h *harness) error {
			return h.authz.ImportGroups(h.ctx, host, "t1", []rbac.GroupDefinition{{ID: "crew", Source: "directory"}})
		}},
		// Through outer, which crew leaves: it held the places it ends before it read the time, but
		// the grants it deletes after, crew's on the workspace, which the scope's deletion holds.
		"DeletePrincipal": {
			hold: func(h *harness, a *rbac.Authorizer) error {
				return a.DeleteScopes(h.ctx, host, "t1", []rbac.Scope{workspace.Scope()})
			},
			remove: func(h *harness) error { return h.authz.DeletePrincipal(h.ctx, host, "t1", groupOf("crew")) },
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, clock := steppedHarness(t)
			ctx := t.Context()
			h.groups(t, "outer", "crew", "inner")
			v := h.as(t, "v", "inner")
			h.seed(t, grant(workspace.Scope(), "workspace.admin", rbac.Group, "crew"))
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
				{Group: "crew", Principal: groupOf("inner")}, {Group: "outer", Principal: groupOf("crew")},
			}); err != nil {
				t.Fatal(err)
			}
			eligible := groupOf("crew")
			if c.hold != nil {
				eligible = groupOf("outer")
			}
			if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.login", Principal: eligible, MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
			activate := func(a *rbac.Authorizer) error {
				_, err := a.Activate(ctx, v, cluster, rbac.Activation{Role: "cluster.login", Duration: 5 * time.Minute, Justification: "x"})
				return err
			}
			hold := activate
			if c.hold != nil {
				if err := activate(h.authz); err != nil {
					t.Fatal(err)
				}
				hold = func(a *rbac.Authorizer) error { return c.hold(h, a) }
			}
			if err := waitedPast(t, h, clock, hold, func() error {
				h.events = nil
				return c.remove(h)
			}); err != nil {
				t.Fatal(err)
			}
			for _, e := range h.events {
				for _, g := range slices.Concat(e.Revoked, e.Shortened) {
					if g.Source == rbac.SourceActivation {
						t.Errorf("at 13:00 the removal ended an activation that ended at 12:05: %+v", g)
					}
				}
			}
		})
	}
}

// SetMemberships holds, before it reads the time it decides at, the places it removes of the
// memberships that had ended at its reading before its transaction, not those of every membership
// with an end: here a host's transaction deleting crew holds v's place there, which neither setting
// v's membership again while it is in force waits for, nor ending it once it ended in between, which
// is tried again instead. Waiting for it, having read its time, a change decides at a time the wait
// left behind.
func TestSettingMembershipsHoldsOnlyThePlacesItRemoves(t *testing.T) {
	for name, c := range map[string]struct {
		// ends is when v's membership ends: the change reads 12:00 before its transaction and 13:00 in
		// it.
		ends time.Duration
		want error
	}{
		"in force":          {ends: 2 * time.Hour},
		"ending in between": {ends: 30 * time.Minute, want: rbac.ErrConflict},
	} {
		t.Run(name, func(t *testing.T) {
			var clock atomic.Int64
			var stepping atomic.Bool
			h := grouped(t, func(cfg *rbac.Config) {
				cfg.Now = func() time.Time {
					at := time.Unix(0, clock.Load()).UTC()
					if stepping.Load() {
						clock.Add(int64(time.Hour))
					}
					return at
				}
			})
			clock.Store(h.now.UnixNano())
			ctx := t.Context()
			v := h.as(t, "v", "crew")
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:v'`, h.now.Add(c.ends)); err != nil {
				t.Fatal(err)
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if err := h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"crew"}); err != nil {
				t.Fatal(err)
			}
			var pid int32
			if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			stepping.Store(true)
			done := make(chan error, 1)
			go func() {
				done <- h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: v.Principal, ExpiresAt: h.now.Add(3 * time.Hour)}})
			}()
			for deadline := time.Now().Add(10 * time.Second); ; {
				select {
				case err := <-done:
					if !errors.Is(err, c.want) {
						t.Errorf("SetMemberships = %v, not %v", err, c.want)
					}
					return
				default:
				}
				var waiting bool
				if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting || time.Now().After(deadline) {
					_ = tx.Rollback(ctx)
					t.Fatalf("SetMemberships waited for v's place in crew: %v", <-done)
				}
			}
		})
	}
}

// A change decides at a time no earlier than the one it picks what it holds of what is in force by:
// where the host's clock goes back between the two, as from 12:10 to 12:00 here, it would leave in
// force at 12:00 an activation resting on the place it removes, which it didn't hold, as it had
// ended by 12:10. It is tried again, and then ends it. Each removal here reads the clock twice,
// both in its transaction: first for what it holds, then for what it decides, which DeletePrincipal
// of a group reads whether or not it found an activation to hold.
func TestAChangeWhoseClockWentBackIsTriedAgain(t *testing.T) {
	for name, c := range map[string]struct {
		// eligible is the group v's activation is made through, whose path from v remove ends.
		eligible string
		remove   func(h *harness) error
	}{
		"DeleteMembers": {"crew", func(h *harness) error {
			return h.authz.DeleteMembers(h.ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: groupOf("inner")}})
		}},
		"DeleteGroups": {"crew", func(h *harness) error { return h.authz.DeleteGroups(h.ctx, host, "t1", []string{"crew"}) }},
		"ImportGroups": {"crew", func(h *harness) error {
			return h.authz.ImportGroups(h.ctx, host, "t1", []rbac.GroupDefinition{{ID: "crew", Source: "directory"}})
		}},
		"DeletePrincipal of a group": {"outer", func(h *harness) error { return h.authz.DeletePrincipal(h.ctx, host, "t1", groupOf("crew")) }},
	} {
		t.Run(name, func(t *testing.T) {
			base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
			var back atomic.Bool
			var reads atomic.Int64
			h := grouped(t, func(c *rbac.Config) {
				c.Now = func() time.Time {
					if back.Load() && reads.Add(1) == 1 {
						return base.Add(10 * time.Minute)
					}
					return base
				}
				c.Sources = []string{"directory"}
			})
			ctx := t.Context()
			h.groups(t, "outer", "crew", "inner")
			v := h.as(t, "v", "inner")
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: groupOf("inner")}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "outer", Principal: groupOf("crew")}}, nil); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.login", Principal: groupOf(c.eligible), MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.authz.Activate(ctx, v, cluster, rbac.Activation{Role: "cluster.login", Duration: 5 * time.Minute, Justification: "x"}); err != nil {
				t.Fatal(err)
			}
			back.Store(true)
			if err := c.remove(h); !errors.Is(err, rbac.ErrConflict) {
				t.Errorf("%s, its clock going back = %v, not tried again", name, err)
			}
			if err := c.remove(h); err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, v, login, cluster) {
				t.Errorf("at 12:00 v logs in through its activation, which rested on a path through %s, which is gone", c.eligible)
			}
		})
	}
}

// DeleteExpired takes no lock a change waits for, and holds what it deletes until its transaction
// ends, a host's under WithTx, so a change holds first what it writes that DeleteExpired may be
// deleting: here DeleteExpired, run at 12:06 in a host's transaction left open, holds what ended at
// 12:05, which each change, from 12:01, sets again or deletes, while it waits. Decided at 13:00,
// once the transaction commits, what passed at 12:10 refuses it: the end it sets, or its actor's
// power. Writing it after it read its time, it waited there, and stored an end that had passed, or
// deleted as an actor whose power had ended.
func TestAChangeHoldsWhatDeleteExpiredDeletesBeforeItReadsItsTime(t *testing.T) {
	ends := 5 * time.Minute
	for name, c := range map[string]struct {
		// ending makes what ends at 12:05, and change makes the change.
		ending func(h *harness)
		change func(h *harness) error
		want   error
	}{
		"SetMemberships setting a membership again": {
			ending: func(h *harness) {
				h.as(t, "r")
				if err := h.authz.SetMemberships(h.ctx, host, "t1", []rbac.Membership{{Principal: identity("r"), ExpiresAt: h.now.Add(ends)}}); err != nil {
					t.Fatal(err)
				}
			},
			change: func(h *harness) error {
				return h.authz.SetMemberships(h.ctx, host, "t1", []rbac.Membership{{Principal: identity("r"), ExpiresAt: h.now.Add(30 * time.Minute)}})
			},
			want: rbac.ErrInvalid,
		},
		"Apply granting a grant again": {
			ending: func(h *harness) {
				h.as(t, "r")
				g := grant(cluster.Scope(), "cluster.login", rbac.User, "r")
				g.ExpiresAt = h.now.Add(ends)
				h.seed(t, g)
			},
			change: func(h *harness) error {
				return h.authz.Apply(h.ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("r"), ExpiresAt: h.now.Add(ends)}}})
			},
			want: rbac.ErrInvalid,
		},
		"Import granting a grant again": {
			ending: func(h *harness) {
				h.as(t, "r")
				g := grant(cluster.Scope(), "cluster.login", rbac.User, "r")
				g.ExpiresAt = h.now.Add(ends)
				h.seed(t, g)
			},
			change: func(h *harness) error {
				g := grant(cluster.Scope(), "cluster.login", rbac.User, "r")
				g.ExpiresAt = h.now.Add(ends)
				return h.authz.Import(h.ctx, host, "t1", []rbac.Grant{g})
			},
			want: rbac.ErrInvalid,
		},
		"DeleteRole by an actor whose power ended": {
			ending: func(h *harness) {
				h.as(t, "r")
				temp := grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "temp")
				temp.ExpiresAt = h.now.Add(10 * time.Minute)
				h.seed(t, temp)
				if _, err := h.pool.Exec(h.ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
					VALUES ('t1', 'custom.r', ARRAY['cluster:view'], ARRAY['cluster'])`); err != nil {
					t.Fatal(err)
				}
				g := grant(cluster.Scope(), "custom.r", rbac.User, "r")
				g.ExpiresAt = h.now.Add(ends)
				h.seed(t, g)
			},
			change: func(h *harness) error { return h.authz.DeleteRole(h.ctx, h.as(t, "temp"), "t1", "custom.r") },
			want:   rbac.ErrDenied,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, clock := steppedHarness(t)
			c.ending(h)
			deleting := func(a *rbac.Authorizer) error {
				clock.Store(h.now.Add(6 * time.Minute).UnixNano())
				_, err := a.DeleteExpired(h.ctx)
				return err
			}
			if err := waitedPast(t, h, clock, deleting, func() error { return c.change(h) }); !errors.Is(err, c.want) {
				t.Errorf("at 13:00, after it waited from 12:01, the change = %v, not %v", err, c.want)
			}
		})
	}
}

// The tests see a change wait for a row once it has read the time it decides at, which no clause of
// its statement shows, as an upsert's on the row it conflicts with: here SetGroup's of the group,
// which a write around the package holds, without the group's lock.
func TestTheTestsSeeAChangeWaitForARowOnceItHasReadItsTime(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "crew")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM rbac_groups WHERE tenant = 't1' AND id = 'crew' FOR UPDATE`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", rbac.GroupDefinition{ID: "crew", Name: "Crew"})
	}()
	for deadline := time.Now().Add(10 * time.Second); ; {
		var waiting bool
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SetGroup never waited for the group's row")
		}
	}
	// Long enough for the watch to see the wait.
	time.Sleep(20 * time.Millisecond)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := (<-panicked).(string); !strings.Contains(p, "waits for a row lock") || !strings.Contains(p, "INSERT INTO rbac_groups") {
		t.Errorf("SetGroup waiting for the group's row, having read its time, panicked with %q", p)
	}
}
