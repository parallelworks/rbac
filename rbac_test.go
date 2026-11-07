package rbac_test

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	mathrand "math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"cel.dev/cel-go/common/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

var errLookup = errors.New("membership lookup failed")

// guardRole sets denies on clusters.
var guardRole = rbac.RoleDefinition{ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, ResourceTypes: []string{"cluster"}}

const (
	view   rbac.Permission = "cluster:view"
	login  rbac.Permission = "cluster:login"
	root   rbac.Permission = "cluster:root"
	grantC rbac.Permission = "cluster:grant"
)

var catalog = []rbac.RoleDefinition{
	{ID: "cluster.admin", Permissions: []rbac.Permission{view, login, root, grantC}, ResourceTypes: []string{"cluster"}, Privileged: true},
	{ID: "cluster.sudo", Permissions: []rbac.Permission{view, login, root}, ResourceTypes: []string{"cluster"}, Privileged: true},
	{ID: "cluster.login", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}},
	{ID: "workspace.admin", Permissions: []rbac.Permission{"workspace:view", "workspace:grant"}, ResourceTypes: []string{"workspace"}},
	{ID: "tenant.admin", Permissions: []rbac.Permission{"tenant:view", "tenant:grant"}, ResourceTypes: []string{"tenant"}},
	{ID: "tenant.roles", Permissions: []rbac.Permission{rbac.DefineRoles}, ResourceTypes: []string{"tenant"}},
}

// declaring is what a host declares it checks (Config.Permissions): more, and everything roles
// give.
func declaring(roles []rbac.RoleDefinition, more ...rbac.Permission) []rbac.Permission {
	ps := slices.Clone(more)
	for _, r := range roles {
		ps = append(ps, r.Permissions...)
	}
	return ps
}

// A cluster in workspace w1 of org o1. setup grants "owner" its admin role, as a host does
// for whoever creates one.
var cluster = rbac.Resource{
	Tenant: "t1", Type: "cluster", ID: "c1",
	Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}},
}

var workspace = rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w1", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}

type harness struct {
	// ctx is the test's, which the helpers that write around the hooks use.
	ctx   context.Context
	pool  *pgxpool.Pool
	authz *rbac.Authorizer
	// cfg is what authz was made with, to make another on a database of a test's own.
	cfg    rbac.Config
	now    time.Time
	events []rbac.ChangeEvent
}

func TestMain(m *testing.M) {
	code := m.Run()
	//nolint:forbidigo // TestMain is the tests' main: once they have run, no test's context is left.
	if err := pgtest.DropTemplates(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = max(code, 1)
	}
	os.Exit(code)
}

func setup(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return setupOn(t, pgtest.Open(t, ""), mutate...)
}

// setupOn is setup on a pool of the test's own.
func setupOn(t *testing.T, pool *pgxpool.Pool, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	h := harnessOn(t, pool, mutate...)
	creator(t, pool)
	return h
}

// harnessOn is setupOn without the creator's grant.
func harnessOn(t *testing.T, pool *pgxpool.Pool, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	if err := rbac.Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	h := &harness{ctx: t.Context(), pool: pool, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	cfg := rbac.Config{
		Catalog:        catalog,
		ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			p := in.Binding.Principal
			switch {
			case strings.HasPrefix(p.ID, "outsider"):
				return fmt.Errorf("%w: not a member", rbac.ErrInvalid)
			case p.ID == "unreachable":
				return errLookup
			}
			return nil
		},
		OnChange: func(_ context.Context, _ pgx.Tx, e rbac.ChangeEvent) error {
			h.events = append(h.events, e)
			return nil
		},
		Now: func() time.Time { return h.now },
		// The resources tests name, as stored, and any other directly under the tenant.
		ResourceOf: func(_ context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			for _, r := range []rbac.Resource{cluster, workspace, {Tenant: "t1", Type: "org", ID: "o1"}} {
				if r.Tenant == tenant && r.Scope() == s {
					return r, nil
				}
			}
			return rbac.Resource{Tenant: tenant, Type: s.Type, ID: s.ID}, nil
		},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	authz, err := rbac.New(pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.authz, h.cfg = authz, cfg
	return h
}

// creatorGrant grants "owner" the cluster's admin role.
const creatorGrant = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
	VALUES ('t1', 'cluster', 'c1', 'user', 'owner', 'cluster.admin')`

// creator writes creatorGrant, around the hooks a test configures.
func creator(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), creatorGrant); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) path(t *testing.T, r rbac.Resource) []string {
	t.Helper()
	p, err := h.authz.Path(r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// constrain configures a constraint that removes p everywhere.
func constrain(name string, p rbac.Permission) func(*rbac.Config) {
	return func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: name, Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			q := in.Permission
			return q == p, nil
		}}}
	}
}

// seed grants in t1, making the groups granted to first.
func (h *harness) seed(t *testing.T, grants ...rbac.Grant) {
	t.Helper()
	var groups []string
	for _, g := range grants {
		if g.Principal.Kind == rbac.Group {
			groups = append(groups, g.Principal.ID)
		}
	}
	h.groups(t, groups...)
	if err := h.authz.Import(t.Context(), host, "t1", grants); err != nil {
		t.Fatal(err)
	}
}

// groups makes groups in t1 that don't exist yet.
func (h *harness) groups(t *testing.T, ids ...string) {
	t.Helper()
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_groups (tenant, id) SELECT 't1', unnest($1::text[]) ON CONFLICT DO NOTHING`, ids); err != nil {
		t.Fatal(err)
	}
}

func grant(scope rbac.Scope, role rbac.Role, kind rbac.PrincipalKind, id string) rbac.Grant {
	return rbac.Grant{Scope: scope, Binding: rbac.Binding{Role: role, Principal: rbac.Principal{Kind: kind, ID: id}}}
}

// host is who the host's own writes, Import and the deletes, are made as.
var host = rbac.Principal{Kind: rbac.User, ID: "host"}

// as is user id as a member of t1 in exactly the groups named, which exist: a test's subject,
// written directly, around the hooks, as creator writes the creator's grant.
func (h *harness) as(t *testing.T, id string, groups ...string) rbac.Subject {
	t.Helper()
	return h.member(t, rbac.Principal{Kind: rbac.User, ID: id}, groups...)
}

// guest is user id as a guest of t1 in exactly the groups named.
func (h *harness) guest(t *testing.T, id string, groups ...string) rbac.Subject {
	t.Helper()
	s := h.as(t, id, groups...)
	if _, err := h.pool.Exec(h.ctx, `UPDATE rbac_memberships SET guest = true WHERE tenant = 't1' AND principal = $1`, "user:"+id); err != nil {
		t.Fatal(err)
	}
	return s
}

// manyMembers makes n users of random ids members of t1, and in the same statement writes then,
// which reads their ids from others(id), as a pool's statements can each run on a connection of
// their own; then it analyzes the tables they were written to, those named and the memberships.
func manyMembers(t *testing.T, h *harness, n int, then string, tables ...string) {
	t.Helper()
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `WITH others AS (SELECT gen_random_uuid()::text AS id FROM generate_series(1, $1)),
		memberships AS (INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', id FROM others)
		`+then, n); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `ANALYZE `+strings.Join(append([]string{"rbac_memberships"}, tables...), ", ")); err != nil {
		t.Fatal(err)
	}
}

// member is p as a member of t1 in exactly the groups named, as as is for a user.
func (h *harness) member(t *testing.T, p rbac.Principal, groups ...string) rbac.Subject {
	t.Helper()
	if groups == nil {
		groups = []string{}
	}
	kind := string(p.Kind)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', $1, $2) ON CONFLICT DO NOTHING`, []any{kind, p.ID}},
		{`DELETE FROM rbac_members WHERE tenant = 't1' AND principal_kind = $1 AND principal_id = $2 AND source = '' AND group_id <> ALL($3::text[])`, []any{kind, p.ID, groups}},
		{`INSERT INTO rbac_groups (tenant, id) SELECT 't1', g FROM unnest($1::text[]) g ON CONFLICT DO NOTHING`, []any{groups}},
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) SELECT 't1', g, $2, $3 FROM unnest($1::text[]) g
			ON CONFLICT DO NOTHING`, []any{groups, kind, p.ID}},
	} {
		if _, err := h.pool.Exec(h.ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s:%s as a member: %v", kind, p.ID, err)
		}
	}
	return rbac.Subject{Principal: p}
}

func allowed(t *testing.T, h *harness, s rbac.Subject, p rbac.Permission, r rbac.Resource) bool {
	t.Helper()
	err := h.authz.Authorize(t.Context(), s, p, r)
	if err != nil && !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Authorize: %v", err)
	}
	return err == nil
}

func TestNewRejectsBadConfiguration(t *testing.T) {
	ok := func(context.Context, rbac.DB, rbac.GrantInput) error { return nil }
	for name, cfg := range map[string]rbac.Config{
		"no principal check": {Catalog: catalog},
		"duplicate role":     {Catalog: append(slices.Clone(catalog), catalog[0]), ValidateGrant: ok},
		"bad permission":     {Catalog: []rbac.RoleDefinition{{ID: "r", Permissions: []rbac.Permission{"login"}, ResourceTypes: []string{"cluster"}}}, ValidateGrant: ok},
		"no permissions":     {Catalog: []rbac.RoleDefinition{{ID: "r", ResourceTypes: []string{"cluster"}}}, ValidateGrant: ok},
		"bad container":      {Catalog: catalog, ContainerTypes: []string{"tenant"}, ValidateGrant: ok},
		"a container named as a dimension": {
			Catalog: catalog, ContainerTypes: []string{"rel"}, ValidateGrant: ok,
			Labels: []rbac.LabelDimension{{Name: "rel", Rule: rbac.AnyOf, Values: []string{"gbr"}}},
			ResourceOf: func(_ context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
				return rbac.Resource{Tenant: tenant, Type: s.Type, ID: s.ID}, nil
			},
		},
		"a kind every host has": {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{rbac.Group}, ValidateGrant: ok},
		"a malformed kind":      {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{"Service Account"}, ValidateGrant: ok},
		"a reserved kind":       {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{"authenticated"}, ValidateGrant: ok},
		"the package's prefix":  {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{"rbac_robot"}, ValidateGrant: ok},
		"a public admin role": {Catalog: []rbac.RoleDefinition{{
			ID: "r", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, Public: true,
		}}, ValidateGrant: ok},
		"a grantable role not in the catalog": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "r", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"nope"},
		}), ValidateGrant: ok},
		"grantable roles without a grant permission": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"},
		}), ValidateGrant: ok},
		"a built-in role named like a custom one": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "custom.r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"},
		}), ValidateGrant: ok},
		"a public privileged role": {Catalog: []rbac.RoleDefinition{{
			ID: "r", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}, Privileged: true, Public: true,
		}}, ValidateGrant: ok},
		"the activation source": {Catalog: catalog, ValidateGrant: ok, Sources: []string{rbac.SourceActivation}},
		"a reserved source":     {Catalog: catalog, ValidateGrant: ok, Sources: []string{"rbac.sync"}},
		"a malformed source":    {Catalog: catalog, ValidateGrant: ok, Sources: []string{"Directory"}},
		"no source":             {Catalog: catalog, ValidateGrant: ok, Sources: []string{""}},
		"unnamed constraint": {Catalog: catalog, ValidateGrant: ok, Constraints: []rbac.Constraint{{
			Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) { return true, nil },
		}}},
		// A built-in role naming a permission the host never checks is a typo in the catalog.
		"a built-in role giving a permission not declared": {Catalog: catalog, Permissions: []rbac.Permission{view, login, root}, ValidateGrant: ok},
		"a malformed declared permission":                  {Catalog: catalog, Permissions: declaring(catalog, "login"), ValidateGrant: ok},
	} {
		if _, err := rbac.New(&pgxpool.Pool{}, cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func TestAuthorizeThroughEveryScope(t *testing.T) {
	h := setup(t)
	h.seed(t,
		grant(cluster.Scope(), "cluster.login", rbac.User, "direct"),
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.sudo", rbac.Group, "ws-sudo"),
		grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.User, "org-user"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "tenant-user"),
		grant(rbac.Scope{Type: "workspace", ID: "w2"}, "cluster.admin", rbac.User, "elsewhere"),
		// Workspace admin gives nothing on clusters.
		grant(rbac.Scope{Type: "org", ID: "o1"}, "workspace.admin", rbac.User, "ws-admin"),
	)
	// The same scopes, in another tenant.
	if err := h.authz.Import(t.Context(), host, "t2", []rbac.Grant{
		grant(cluster.Scope(), "cluster.login", rbac.User, "elsewhere-tenant"),
		grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "elsewhere-tenant"),
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		s    rbac.Subject
		p    rbac.Permission
		want bool
	}{
		{"on the resource", h.as(t, "direct"), login, true},
		{"not more than the role", h.as(t, "direct"), root, false},
		{"through a group on the workspace", h.as(t, "someone", "ws-sudo"), root, true},
		{"on the org", h.as(t, "org-user"), login, true},
		{"on the tenant", h.as(t, "tenant-user"), login, true},
		{"on another workspace", h.as(t, "elsewhere"), login, false},
		{"a role for another type", h.as(t, "ws-admin"), view, false},
		{"no grant", h.as(t, "nobody"), view, false},
		{"a grant in another tenant", h.as(t, "elsewhere-tenant"), login, false},
		{"the creator's role", h.as(t, "owner"), root, true},
	}
	for _, c := range cases {
		if got := allowed(t, h, c.s, c.p, cluster); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if !allowed(t, h, h.as(t, "ws-admin"), "workspace:grant", workspace) {
		t.Error("workspace admin on the org should hold workspace:grant on its workspaces")
	}
}

func TestTenantMembersAndExpiry(t *testing.T) {
	h := setup(t)
	g := grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	if !allowed(t, h, h.as(t, "anyone"), login, cluster) {
		t.Fatal("a grant to the tenant's members should reach any member")
	}
	h.now = h.now.Add(2 * time.Hour)
	if allowed(t, h, h.as(t, "anyone"), login, cluster) {
		t.Fatal("an expired grant should give nothing")
	}
	n, err := h.authz.DeleteExpired(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
}

func TestConstraintsBindEveryGrantAndExplain(t *testing.T) {
	h := setup(t, constrain("no root", root))
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"))
	if allowed(t, h, h.as(t, "owner"), root, cluster) || allowed(t, h, h.as(t, "u"), root, cluster) {
		t.Fatal("a constraint should remove root from every grant")
	}
	d, err := h.authz.Explain(t.Context(), h.as(t, "u"), root, cluster)
	if err != nil || d.Allowed || d.DeniedBy != "no root" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	d, err = h.authz.Explain(t.Context(), h.as(t, "u"), login, cluster)
	if err != nil || !d.Allowed || len(d.Grants) != 1 || d.Grants[0].Role != "cluster.sudo" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	perms, err := h.authz.Permissions(t.Context(), h.as(t, "u"), cluster)
	if err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	perms, err = h.authz.Permissions(t.Context(), h.as(t, "owner"), cluster)
	if err != nil || !slices.Equal(perms, []rbac.Permission{grantC, login, view}) {
		t.Fatalf("admin's Permissions = %v, %v", perms, err)
	}
}

func TestMalformedInputIsAnErrorNotAnAllow(t *testing.T) {
	h := setup(t)
	bad := cluster
	bad.ID = ""
	if err := h.authz.Authorize(t.Context(), h.as(t, "owner"), login, bad); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a resource with no id: %v", err)
	}
	if err := h.authz.Authorize(t.Context(), h.as(t, "owner"), "login", cluster); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a malformed permission: %v", err)
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}}}
	if err := h.authz.Authorize(t.Context(), h.as(t, "u"), "tenant:grant", tenant); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("the tenant under a workspace: %v", err)
	}
}

// The host's resources, for Filter: each with its Path.
func hostTable(t *testing.T, h *harness) []rbac.Resource {
	t.Helper()
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE clusters (
		tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `CREATE INDEX ON clusters USING gin (path)`); err != nil {
		t.Fatal(err)
	}
	var resources []rbac.Resource
	for i, chain := range [][]rbac.Scope{
		{{Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}},
		{{Type: "workspace", ID: "w2"}, {Type: "org", ID: "o1"}},
		{{Type: "workspace", ID: "w3"}, {Type: "org", ID: "o2"}},
		{{Type: "org", ID: "o2"}},
	} {
		r := rbac.Resource{Tenant: "t1", Type: "cluster", ID: fmt.Sprintf("c%d", i), Ancestors: chain}
		if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	// Another tenant's cluster, under a workspace with the same id.
	if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ('t2', 'x', '{cluster:x,workspace:w1,tenant:t2}')`); err != nil {
		t.Fatal(err)
	}
	return resources
}

func TestFilterAndReachableAgreeWithAuthorize(t *testing.T) {
	h := setup(t)
	resources := hostTable(t, h)
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.login", rbac.Group, "g1"),
		grant(rbac.Scope{Type: "org", ID: "o2"}, "cluster.sudo", rbac.User, "u2"),
		grant(rbac.Scope{Type: "cluster", ID: "c1"}, "cluster.login", rbac.User, "u1"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "all"),
		grant(rbac.Scope{Type: "cluster", ID: "c3"}, "cluster.admin", rbac.User, "owner3"),
	)
	for _, s := range []rbac.Subject{h.as(t, "u1", "g1"), h.as(t, "u2"), h.as(t, "all"), h.as(t, "owner3"), h.as(t, "nobody")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

func TestListingsKeepToDeniesOnTheResourceItself(t *testing.T) {
	guard := rbac.RoleDefinition{ID: "cluster.guard", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guard) })
	resources := hostTable(t, h)
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.User, "u"),
		grant(resources[0].Scope(), "cluster.guard", rbac.User, "guard"))
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(t.Context(), h.as(t, "guard"), resources[0], d); err != nil {
		t.Fatal(err)
	}
	listingsAgree(t, h, resources, h.as(t, "u"), login)
	if allowed(t, h, h.as(t, "u"), login, resources[0]) || !allowed(t, h, h.as(t, "u"), login, resources[1]) {
		t.Fatal("the deny should remove access to its own cluster only")
	}
}

// Filter reads a row's own key as its path's first element whatever subscript the array starts
// from: a path stored from 0 holds the same keys in the same order, and read at 1, its second key,
// the workspace's, would stand for the cluster's, so Filter would keep a cluster a deny on it
// leaves out and, for a subject of many grants on clusters, leave out one a grant on it reaches.
func TestFilterReadsARowsOwnKeyWhereverItsPathStarts(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE clusters (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	var resources []rbac.Resource
	for i := range 10 {
		r := rbac.Resource{Tenant: "t1", Type: "cluster", ID: fmt.Sprintf("c%d", i), Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}}}
		if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, ('[0:' || cardinality($3::text[]) - 1 || ']=' || $3::text[]::text)::text[])`,
			r.Tenant, r.ID, h.path(t, r)); err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	// One holds the role on the workspace, the other on each cluster, past the grants Filter
	// overlaps with each row's path; a deny on the last cluster names both.
	broad, many := h.as(t, "broad"), h.as(t, "many")
	grants := []rbac.Grant{grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.login", rbac.User, "broad")}
	for _, r := range resources {
		grants = append(grants, grant(r.Scope(), "cluster.login", rbac.User, "many"))
	}
	h.seed(t, grants...)
	if err := h.authz.SetDeny(ctx, guardian, resources[9], rbac.Deny{ID: "d", Principals: []rbac.Principal{broad.Principal, many.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []rbac.Subject{broad, many} {
		pred, err := h.authz.Filter(ctx, s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := h.pool.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		kept, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(kept)
		if want := allowedOf(t, h, resources, s, login); !slices.Equal(kept, want) {
			t.Errorf("%s: Filter keeps %v of clusters whose paths start from 0, Authorize allows %v", s.Principal.ID, kept, want)
		}
	}
}

// One table can hold resources of several types, as one store of every resource does, and a grant
// on a container reaches every row under it, of any type: Filter keeps of them only those whose own
// key is of the type it lists, not of one whose name starts with its name, as Authorize refuses p
// on the rest, in each form its condition takes, overlapping the path with the subject's grants,
// looking its own key up in a hash of those on resources of the type, and looking each of its keys
// up in one object of them all. Its condition is false for the rest, not unknown, for a host that
// selects it as a column.
func TestFilterKeepsOnlyTheRowsOfTheListedType(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE resources (tenant text NOT NULL, type text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	o1 := rbac.Scope{Type: "org", ID: "o1"}
	w1 := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w1", Ancestors: []rbac.Scope{o1}}
	w2 := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w2", Ancestors: []rbac.Scope{w1.Scope(), o1}}
	resources := []rbac.Resource{
		{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"},
		w1,
		w2,
		{Tenant: "t1", Type: "cluster", ID: "c1", Ancestors: []rbac.Scope{w1.Scope(), o1}},
		{Tenant: "t1", Type: "cluster", ID: "c2", Ancestors: []rbac.Scope{w2.Scope(), w1.Scope(), o1}},
		{Tenant: "t1", Type: "cluster", ID: "c3", Ancestors: []rbac.Scope{o1}},
		{Tenant: "t1", Type: "clusterx", ID: "c1", Ancestors: []rbac.Scope{w1.Scope(), o1}},
	}
	for _, r := range resources {
		if _, err := h.pool.Exec(ctx, `INSERT INTO resources VALUES ($1, $2, $3, $4)`, r.Tenant, r.Type, r.ID, h.path(t, r)); err != nil {
			t.Fatal(err)
		}
	}
	// org may view the clusters of o1 but those a deny on w2 covers, lead administers w1 and the
	// workspace in it, many holds the role on w1 and on more clusters than Filter overlaps, and admin
	// holds every role on the tenant.
	grants := []rbac.Grant{
		grant(o1, "cluster.login", rbac.User, "org"),
		grant(w1.Scope(), "workspace.admin", rbac.User, "lead"),
		grant(w1.Scope(), "cluster.login", rbac.User, "many"),
	}
	for i := range 12 {
		grants = append(grants, grant(rbac.Scope{Type: "cluster", ID: fmt.Sprint("c", i+1)}, "cluster.login", rbac.User, "many"))
	}
	for _, role := range []rbac.Role{"cluster.login", "workspace.admin", "tenant.admin"} {
		grants = append(grants, grant(rbac.TenantRoot("t1"), role, rbac.User, "admin"))
	}
	h.seed(t, grants...)
	org, many := h.as(t, "org"), h.as(t, "many")
	if err := h.authz.SetDeny(ctx, guardian, w2, rbac.Deny{ID: "d", Principals: []rbac.Principal{org.Principal}, Permissions: []rbac.Permission{view}}); err != nil {
		t.Fatal(err)
	}
	subjects := []rbac.Subject{org, h.as(t, "lead"), many, h.as(t, "admin")}
	// The keys of the rows Filter keeps listing resourceType for s, and those of the resources of
	// the type Authorize allows.
	kept := func(t *testing.T, s rbac.Subject, p rbac.Permission, resourceType string) (got, want []string) {
		t.Helper()
		pred, err := h.authz.Filter(ctx, s, p, "t1", resourceType, rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := h.pool.Query(ctx, `SELECT type || ':' || id COLLATE "C" FROM resources WHERE `+pred.SQL+` ORDER BY 1`, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		if got, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			t.Fatal(err)
		}
		var unknown []string
		if err := h.pool.QueryRow(ctx, `SELECT coalesce(array_agg(type || ':' || id COLLATE "C"), '{}') FROM resources WHERE `+pred.SQL+` IS NULL`,
			pred.Args...).Scan(&unknown); err != nil {
			t.Fatal(err)
		}
		if len(unknown) > 0 {
			t.Errorf("%s listing %ss: Filter's condition is unknown for %v", s.Principal.ID, resourceType, unknown)
		}
		for _, r := range resources {
			if r.Type != resourceType {
				continue
			}
			switch err := h.authz.Authorize(ctx, s, p, r); {
			case err == nil:
				want = append(want, r.Scope().Key())
			case !errors.Is(err, rbac.ErrDenied):
				t.Fatalf("Authorize: %v", err)
			}
		}
		slices.Sort(want)
		return got, want
	}
	listings := []struct {
		resourceType string
		p            rbac.Permission
	}{{"cluster", view}, {"workspace", "workspace:view"}, {rbac.TenantScope, "tenant:view"}}
	agree := func(t *testing.T) {
		t.Helper()
		for _, l := range listings {
			for _, s := range subjects {
				if got, want := kept(t, s, l.p, l.resourceType); !slices.Equal(got, want) {
					t.Errorf("%s listing %ss: Filter keeps %v, Authorize allows %v", s.Principal.ID, l.resourceType, got, want)
				}
			}
		}
	}
	agree(t)
	pred, err := h.authz.Filter(ctx, many, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashing(ctx, t, h, "rbac_grants", `SELECT count(*) FROM resources WHERE `+pred.SQL, pred.Args...)) == 0 {
		t.Fatal("Filter doesn't look many's grants on clusters up in a hash")
	}
	t.Run("looking up grants on containers", func(t *testing.T) {
		rbac.SetMaxContainerOverlap(t, 0)
		pred, err := h.authz.Filter(ctx, org, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if over := overlapping(ctx, t, h, "rbac_grants", `SELECT count(*) FROM resources WHERE `+pred.SQL, pred.Args...); len(over) > 0 {
			t.Fatalf("with SetMaxContainerOverlap(0), Filter overlaps each row with org's grant: %q", over)
		}
		agree(t)
	})
}

// A table holding several types is listed through its path's index as one of a type is: each row's
// type is tested among the rows the index finds, so a list of the clusters in one workspace reads
// those and the workspace's own row, not the tenant's.
func TestFilterReadsATableOfSeveralTypesThroughThePathIndex(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`CREATE TABLE resources (tenant text NOT NULL, type text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO resources SELECT 't1', 'workspace', 'w' || i, ARRAY['workspace:w' || i, 'org:o' || (i % 50), 'tenant:t1']
			FROM generate_series(1, 2000) i`,
		`INSERT INTO resources SELECT 't1', 'cluster', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 2000 + 1), 'org:o' || ((i % 2000 + 1) % 50), 'tenant:t1']
			FROM generate_series(1, 20000) i`,
		`CREATE INDEX resources_path ON resources USING gin (path)`,
		`ANALYZE resources`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(rbac.Scope{Type: "workspace", ID: "w7"}, "cluster.login", rbac.User, "u"))
	pred, err := h.authz.Filter(ctx, h.as(t, "u"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	query := `SELECT count(*) FROM resources WHERE ` + pred.SQL
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var n, pages int64
	if err := tx.QueryRow(ctx, `SELECT relpages FROM pg_class WHERE oid = 'resources'::regclass`).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	start := pagesRead(ctx, t, tx, "resources")
	if err := tx.QueryRow(ctx, query, pred.Args...).Scan(&n); err != nil || n != 10 {
		t.Fatalf("Filter kept %d of w7's 10 clusters, %v", n, err)
	}
	if read := pagesRead(ctx, t, tx, "resources") - start; read*10 > pages {
		t.Errorf("a list of w7's 10 clusters read %d pages of a table of %d", read, pages)
	}
	rows, err := tx.Query(ctx, "EXPLAIN "+query, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if text := strings.Join(plan, "\n"); !strings.Contains(text, "Bitmap Index Scan on resources_path") {
		t.Errorf("Filter's plan on a table of several types:\n%s", text)
	}
}

// Testing a row's type leaves the planner's count of the rows Filter's condition keeps as it was,
// so a sorted, limited page of a table of one type whose condition no index serves, as for a subject
// holding grants on hundreds of workspaces, is still read in the order of the host's index until
// it is full, under a generic plan too. The planner has no statistics of a path's first key, and
// counts a test of it alone as keeping one row in 200, so a plain test would read and sort every
// row of the tenant.
func TestFilterTestsARowsTypeWithoutMovingAPageOffTheHostsIndex(t *testing.T) {
	for _, plan := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(plan, func(t *testing.T) {
			h := setupOn(t, pgtest.Open(t, "plan_cache_mode="+plan))
			ctx := t.Context()
			for _, q := range []string{
				`CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
				`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 500), 'org:o' || (i % 50), 'tenant:t1']
					FROM generate_series(1, 20000) i`,
				`CREATE INDEX ON fleet USING gin (path)`,
				`CREATE INDEX ON fleet (tenant, id)`,
				`ANALYZE fleet`,
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'workspace', 'w' || i, 'user', 'u', 'cluster.login' FROM generate_series(1, 200) i`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			pred, err := h.authz.Filter(ctx, h.as(t, "u"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			var pages int64
			if err := tx.QueryRow(ctx, `SELECT relpages FROM pg_class WHERE oid = 'fleet'::regclass`).Scan(&pages); err != nil {
				t.Fatal(err)
			}
			start := pagesRead(ctx, t, tx, "fleet")
			rows, err := tx.Query(ctx, `SELECT id FROM fleet WHERE `+pred.SQL+` ORDER BY id LIMIT 50`, pred.Args...)
			if err != nil {
				t.Fatal(err)
			}
			if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) != 50 {
				t.Fatalf("a page of %d clusters, %v", len(ids), err)
			}
			if read := pagesRead(ctx, t, tx, "fleet") - start; read*3 > pages {
				t.Errorf("a page of 50 clusters read %d pages of a table of %d", read, pages)
			}
		})
	}
}

// overlapping returns the conditions in the plan of query, on h's pool, that overlap an array with
// what a subquery reading table selects (`&&`): each compares a row with every value the subquery
// selects, rather than look the row's keys up in a hash or an object of them.
func overlapping(ctx context.Context, t *testing.T, h *harness, table, query string, args ...any) []string {
	t.Helper()
	return planConditions(ctx, t, h, overlap, table, query, args...)
}

// hashing returns the conditions in the plan of query, on h's pool, that look a row's key up in a
// hash of what a subquery reading table selects.
func hashing(ctx context.Context, t *testing.T, h *harness, table, query string, args ...any) []string {
	t.Helper()
	return planConditions(ctx, t, h, hashed, table, query, args...)
}

// planConditions returns the conditions in the plan of query, on h's pool, where use, which
// captures a subquery's name, finds one reading table.
func planConditions(ctx context.Context, t *testing.T, h *harness, use *regexp.Regexp, table, query string, args ...any) []string {
	t.Helper()
	var plans []struct{ Plan map[string]any }
	if err := h.pool.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+query, args...).Scan(&plans); err != nil || len(plans) != 1 {
		t.Fatalf("EXPLAIN %d plans, %v", len(plans), err)
	}
	// Each subquery's name, as conditions read it, and whether it reads table; every condition.
	reads := map[string]bool{}
	var conditions []string
	var walk func(node map[string]any) bool
	walk = func(node map[string]any) bool {
		found := node["Relation Name"] == table
		for _, k := range []string{"Filter", "Index Cond", "Recheck Cond", "Join Filter", "Hash Cond", "One-Time Filter"} {
			if c, ok := node[k].(string); ok {
				conditions = append(conditions, c)
			}
		}
		children, _ := node["Plans"].([]any)
		for _, c := range children {
			child, _ := c.(map[string]any)
			below := walk(child)
			if name, ok := child["Subplan Name"].(string); ok {
				reads[name] = below
			}
			found = found || below
		}
		return found
	}
	walk(plans[0].Plan)
	var found []string
	for _, c := range conditions {
		for _, m := range use.FindAllStringSubmatch(c, -1) {
			if reads[m[1]] {
				found = append(found, c)
				break
			}
		}
	}
	return found
}

// overlap finds an array overlapped with a subquery's in a plan's condition, and hashed a key
// looked up in a hashed subquery.
var (
	overlap = regexp.MustCompile(`&& \(*(InitPlan \d+)\)`)
	hashed  = regexp.MustCompile(`hashed (SubPlan \d+)`)
)

// Filter's condition leaves out the resources denies on thousands of them, or of the workspaces
// they are in, cover by looking each row's keys up: its own in a hash of the denies on resources of
// its type, and each of its keys in one object of those on containers and the tenant. Overlapping
// each row with every deny would cost it thousands of comparisons, and a tenant's admins can set
// them.
func TestFilterLooksUpDeniesByEachRowsKeys(t *testing.T) {
	for _, on := range []string{"cluster", "workspace"} {
		t.Run(on, func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			const rows = 20000
			if _, err := h.pool.Exec(ctx, `CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || i, 'org:o' || (i % 50), 'tenant:t1']
				FROM generate_series(1, $1) i`, rows); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "u"))
			u := h.as(t, "u")
			denied := 0
			// Filter's condition, with what it keeps and how its plan reads the denies, once n of the
			// rows are denied.
			listed := func(n int) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					SELECT 't1', $3, left($3, 1) || (i * 5), 'd', '{public:}', '{cluster:login}' FROM generate_series($1 + 1, $2) i`, denied, n, on); err != nil {
					t.Fatal(err)
				}
				denied = n
				pred, err := h.authz.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				if err != nil {
					t.Fatal(err)
				}
				query := `SELECT count(*) FROM fleet WHERE ` + pred.SQL
				var kept int
				if err := h.pool.QueryRow(ctx, query, pred.Args...).Scan(&kept); err != nil || kept != rows-n {
					t.Fatalf("Filter kept %d of %d rows with %d denied, %v", kept, rows, n, err)
				}
				if over := overlapping(ctx, t, h, "rbac_denies", query, pred.Args...); len(over) > 0 {
					t.Errorf("with %d %ss denied, Filter's condition overlaps each row with the denies: %q", n, on, over)
				}
				// u's one grant is overlapped with each row's path, so finding none above is the plan's.
				if len(overlapping(ctx, t, h, "rbac_grants", query, pred.Args...)) == 0 {
					t.Fatal("overlapping finds no overlap of the path with u's one grant")
				}
			}
			listed(40)
			listed(4000)
		})
	}
}

// A subject holding a grant on each of thousands of workspaces, as one on each it created, lists a
// page of them, or of the clusters in them, by looking each of a row's keys up in one object of
// them, past 128 grants. Overlapping each row with every grant would cost it thousands of
// comparisons, and the index, which merges the rows each finds, as many for each row it finds.
func TestFilterLooksUpGrantsOnContainersByEachRowsKeys(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`CREATE TABLE spaces (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO spaces SELECT 't1', 'w' || i, ARRAY['workspace:w' || i, 'org:o' || (i % 50), 'tenant:t1'] FROM generate_series(1, 20000) i`,
		`CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || i, 'org:o' || (i % 50), 'tenant:t1'] FROM generate_series(1, 20000) i`,
		`CREATE INDEX ON spaces USING gin (path)`,
		`CREATE INDEX ON spaces (tenant, id)`,
		`CREATE INDEX ON fleet USING gin (path)`,
		`CREATE INDEX ON fleet (tenant, id)`,
		`ANALYZE spaces, fleet`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'workspace', 'w' || i, 'user', 'u', r FROM generate_series(1, 4000) i, unnest('{workspace.admin,cluster.login}'::text[]) r`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u := h.as(t, "u")
	for _, l := range []struct {
		resourceType, table string
		p                   rbac.Permission
	}{{"workspace", "spaces", "workspace:view"}, {"cluster", "fleet", login}} {
		pred, err := h.authz.Filter(ctx, u, l.p, "t1", l.resourceType, rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var kept int
		if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM `+l.table+` WHERE `+pred.SQL, pred.Args...).Scan(&kept); err != nil || kept != 4000 {
			t.Fatalf("Filter kept %d %ss of 4000, %v", kept, l.resourceType, err)
		}
		page := `SELECT id FROM ` + l.table + ` WHERE ` + pred.SQL + ` ORDER BY id LIMIT 50`
		rows, err := h.pool.Query(ctx, page, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) != 50 {
			t.Fatalf("a page of %d %ss, %v", len(ids), l.resourceType, err)
		}
		if over := overlapping(ctx, t, h, "rbac_grants", page, pred.Args...); len(over) > 0 {
			t.Errorf("a page of %ss overlaps each row with the 4000 workspaces granted: %q", l.resourceType, over)
		}
	}
}

// A subject holding grants on many clusters and on dozens of workspaces, as one on each it created,
// is listed by looking every grant up by each of a row's keys: with those on clusters in a hash, no
// index serves the condition, so overlapping each row with every grant on the workspaces would cost
// every row of the tenant a comparison for each.
func TestFilterLooksUpGrantsOnContainersAlongsideManyOnResources(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 10000), 'org:o' || (i % 50), 'tenant:t1']
			FROM generate_series(1, 100000) i`,
		`ANALYZE fleet`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'workspace', 'w' || i, 'user', 'u', 'cluster.login' FROM generate_series(1, 100) i
			UNION ALL SELECT 't1', 'cluster', 'c' || (i * 7), 'user', 'u', 'cluster.login' FROM generate_series(1, 100) i`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u := h.as(t, "u")
	pred, err := h.authz.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The ten clusters in each of w1 to w100, and those of c7 to c700 in none of them.
	query := `SELECT count(*) FROM fleet WHERE ` + pred.SQL
	var kept int
	if err := h.pool.QueryRow(ctx, query, pred.Args...).Scan(&kept); err != nil || kept != 1086 {
		t.Fatalf("Filter kept %d clusters, %v", kept, err)
	}
	if over := overlapping(ctx, t, h, "rbac_grants", query, pred.Args...); len(over) > 0 {
		t.Errorf("Filter's condition overlaps each row with the grants on workspaces: %q", over)
	}
}

// A subject administering hundreds of workspaces still finds the clusters it may log in to in one
// of them through the path's index: only grants of roles giving the permission, custom ones among
// them, pick how Filter matches them, as only those are in its condition.
func TestFilterCountsOnlyTheGrantsGivingThePermission(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, roleAdmin(t, h), "t1", op); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 1000), 'org:o1', 'tenant:t1']
			FROM generate_series(1, 20000) i`,
		`CREATE INDEX fleet_path ON fleet USING gin (path)`,
		`ANALYZE fleet`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'workspace', 'w' || i, 'user', 'u', 'workspace.admin' FROM generate_series(1, 200) i
			UNION ALL SELECT 't1', 'workspace', 'w1', 'user', 'u', 'cluster.login'
			UNION ALL SELECT 't1', 'workspace', 'w' || i, 'user', 'op', 'custom.op' FROM generate_series(1, 200) i`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	// Whether Filter's condition for id, keeping the clusters of n workspaces, is served by the
	// path's index.
	indexed := func(id string, n int) bool {
		t.Helper()
		pred, err := h.authz.Filter(ctx, h.as(t, id), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var kept int
		if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...).Scan(&kept); err != nil || kept != 20*n {
			t.Fatalf("Filter kept %d clusters for %s, %v", kept, id, err)
		}
		rows, err := h.pool.Query(ctx, "EXPLAIN SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(strings.Join(plan, "\n"), "Bitmap Index Scan on fleet_path")
	}
	if !indexed("u", 1) {
		t.Error("Filter reads every cluster for a subject with one grant giving the permission")
	}
	if indexed("op", 200) {
		t.Error("Filter overlaps each cluster with 200 grants of a custom role")
	}
}

// A list keeps to the path's index whatever grants giving nothing are stored, as a privileged
// role's to the tenant's members, or the public's of a role that isn't public, as one a tenant's
// admin made no longer public leaves: its condition counts none of them, so they don't pick its
// form, where counted they would move every subject's list to a read of every row.
func TestFilterIsFormedByTheGrantsItCounts(t *testing.T) {
	public := rbac.RoleDefinition{ID: "cluster.public", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}, Public: true}
	// A harness with a table of clusters whose path is indexed, and ann granted on one, where the
	// public's grants count for logging in.
	fleet := func(t *testing.T) (*harness, rbac.Subject) {
		t.Helper()
		h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), public) })
		for _, q := range []string{
			`CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
			`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 500), 'org:o1', 'tenant:t1']
				FROM generate_series(1, 20000) i`,
			`CREATE INDEX fleet_path ON fleet USING gin (path)`,
			`ANALYZE fleet`,
		} {
			if _, err := h.pool.Exec(t.Context(), q); err != nil {
				t.Fatal(err)
			}
		}
		h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c7"}, "cluster.login", rbac.User, "ann"))
		return h, h.as(t, "ann")
	}
	// Whether s's list of clusters, keeping n, is served by the path's index.
	indexed := func(t *testing.T, h *harness, s rbac.Subject, n int) bool {
		t.Helper()
		ctx := t.Context()
		pred, err := h.authz.Filter(ctx, s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var kept int
		if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...).Scan(&kept); err != nil || kept != n {
			t.Fatalf("Filter kept %d clusters, %v", kept, err)
		}
		rows, err := h.pool.Query(ctx, "EXPLAIN SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return strings.Contains(strings.Join(plan, "\n"), "Bitmap Index Scan on fleet_path")
	}
	for name, inert := range map[string]string{
		"a privileged role's on 200 workspaces to the members": `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'workspace', 'w' || i, 'members', 't1', 'cluster.sudo' FROM generate_series(1, 200) i`,
		"a privileged role's on 9 clusters to the members": `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', 'x' || i, 'members', 't1', 'cluster.sudo' FROM generate_series(1, 9) i`,
		"the public's on 9 clusters of a role that isn't public": `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', 'x' || i, 'public', '', 'cluster.login' FROM generate_series(1, 9) i`,
	} {
		t.Run(name, func(t *testing.T) {
			h, ann := fleet(t)
			// Stored around the package, as a catalog change leaves them.
			if _, err := h.pool.Exec(t.Context(), inert); err != nil {
				t.Fatal(err)
			}
			if !indexed(t, h, ann, 1) {
				t.Error("grants giving nothing move a list off the path's index")
			}
		})
	}
	t.Run("a custom role made no longer public, the public's on 9 clusters", func(t *testing.T) {
		h, ann := fleet(t)
		ctx := t.Context()
		h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "admin"))
		admin := h.as(t, "admin")
		shared := rbac.RoleDefinition{ID: "custom.shared", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}, Public: true}
		if err := h.authz.SetRole(ctx, admin, "t1", shared); err != nil {
			t.Fatal(err)
		}
		var grants []rbac.Grant
		for i := range 9 {
			grants = append(grants, grant(rbac.Scope{Type: "cluster", ID: fmt.Sprint("c", 100+i)}, "custom.shared", rbac.Public, ""))
		}
		h.seed(t, grants...)
		shared.Public = false
		if err := h.authz.SetRole(ctx, admin, "t1", shared); err != nil {
			t.Fatalf("SetRole making it not public: %v", err)
		}
		if allowed(t, h, rbac.Subject{}, login, rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c100"}) {
			t.Fatal("the public's grant of a role no longer public gives")
		}
		for name, c := range map[string]struct {
			s rbac.Subject
			n int
		}{"ann": {ann, 1}, "the anonymous": {rbac.Subject{}, 0}} {
			if !indexed(t, h, c.s, c.n) {
				t.Errorf("%s: grants giving nothing move a list off the path's index", name)
			}
		}
	})
}

// Lowering how many grants on containers Filter overlaps, as a test does to compare the forms it
// takes past that, leaves a subject with many grants on resources of the type and none on
// containers looking those up in a hash: counted only as far as the lowered bound, they never
// passed the few the hash takes.
func TestLoweringTheContainerBoundKeepsTheHashOfGrantsOnResources(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	var grants []rbac.Grant
	for i := range 9 {
		grants = append(grants, grant(rbac.Scope{Type: "cluster", ID: fmt.Sprint("x", i)}, "cluster.login", rbac.User, "ann"))
	}
	h.seed(t, grants...)
	ann := h.as(t, "ann")
	rbac.SetMaxContainerOverlap(t, 0)
	pred, err := h.authz.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashing(ctx, t, h, "rbac_grants", "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...)) == 0 {
		t.Error("with SetMaxContainerOverlap(0), Filter doesn't look 9 grants on clusters up in a hash")
	}
}

func TestListingContainersUnderOthersOfTheirType(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE spaces (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	outer := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w1", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
	inner := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w9", Ancestors: []rbac.Scope{outer.Scope(), {Type: "org", ID: "o1"}}}
	other := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w5", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
	for _, r := range []rbac.Resource{outer, inner, other} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO spaces VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(outer.Scope(), "workspace.admin", rbac.User, "lead"))
	pred, err := h.authz.Filter(ctx, h.as(t, "lead"), "workspace:view", "t1", "workspace", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, "SELECT id FROM spaces WHERE "+pred.SQL+" ORDER BY id", pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || !slices.Equal(ids, []string{"w1", "w9"}) {
		t.Fatalf("a grant on a workspace should list it and the workspace under it: %v, %v", ids, err)
	}
	if !allowed(t, h, h.as(t, "lead"), "workspace:view", inner) {
		t.Fatal("Authorize should agree")
	}
}

func TestListingsApplyConstraints(t *testing.T) {
	h := setup(t, constrain("no root", root))
	resources := hostTable(t, h)
	h.seed(t,
		grant(rbac.Scope{Type: "org", ID: "o2"}, "cluster.sudo", rbac.User, "u2"),
		grant(rbac.Scope{Type: "cluster", ID: "c3"}, "cluster.admin", rbac.User, "owner3"),
	)
	for _, s := range []rbac.Subject{h.as(t, "owner3"), h.as(t, "u2")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

// listingsAgree checks Filter and Reachable against Authorize, resource by resource.
func listingsAgree(t *testing.T, h *harness, resources []rbac.Resource, s rbac.Subject, p rbac.Permission) {
	t.Helper()
	want := allowedOf(t, h, resources, s, p)
	if got := listed(t, h, s, p); !slices.Equal(got, want) {
		t.Errorf("%v %s: Filter %v, Authorize %v", s.Principal, p, got, want)
	}
	if reached, _ := reachedBy(t, h, resources, s, p); !slices.Equal(reached, want) {
		t.Errorf("%v %s: Reachable %v, Authorize %v", s.Principal, p, reached, want)
	}
}

// allowedOf is the ids of the resources Authorize lets s do p to, in order.
func allowedOf(t *testing.T, h *harness, resources []rbac.Resource, s rbac.Subject, p rbac.Permission) []string {
	t.Helper()
	var ids []string
	for _, r := range resources {
		if allowed(t, h, s, p, r) {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// listed is the ids of the rows of the clusters table that Filter keeps for s and p, in order.
func listed(t *testing.T, h *harness, s rbac.Subject, p rbac.Permission) []string {
	t.Helper()
	pred, err := h.authz.Filter(t.Context(), s, p, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	// A host's query builder can read a `?` as a placeholder of its own.
	if strings.Contains(pred.SQL, "?") {
		t.Errorf("Filter's condition has a ?: %s", pred.SQL)
	}
	// Another tenant's rows are named with their tenant, so one Filter keeps shows even where t1
	// has a cluster of the same id.
	rows, err := h.pool.Query(t.Context(), `SELECT CASE tenant WHEN 't1' THEN id ELSE tenant || '/' || id END
		FROM clusters WHERE `+pred.SQL+` ORDER BY 1`, pred.Args...)
	if err != nil {
		t.Fatalf("%s: %v", pred.SQL, err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// reachedBy is the ids of the resources a host listing by Reachable shows, reading Reach as it
// says a host does, and of those it shows without checking them with Authorize.
func reachedBy(t *testing.T, h *harness, resources []rbac.Resource, s rbac.Subject, p rbac.Permission) (reached, unchecked []string) {
	t.Helper()
	reach, err := h.authz.Reachable(t.Context(), s, p, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range resources {
		path := h.path(t, r)
		holds := func(scopes []rbac.Scope) bool {
			return slices.ContainsFunc(scopes, func(sc rbac.Scope) bool { return slices.Contains(path, sc.Key()) })
		}
		in := !holds(reach.Except) && (reach.All || holds(reach.Scopes) || holds(reach.Conditional))
		if in && (holds(reach.Conditional) || holds(reach.ConditionalExcept)) {
			in = allowed(t, h, s, p, r)
		} else if in {
			unchecked = append(unchecked, r.ID)
		}
		if in {
			reached = append(reached, r.ID)
		}
	}
	return reached, unchecked
}

func TestFilterOnATenantColumnThatIsNotText(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	r := rbac.Resource{Tenant: "6f1c1d0e-8f43-4b8e-9a35-1d2a3f4b5c6d", Type: "cluster", ID: "c"}
	if _, err := h.pool.Exec(ctx, `CREATE TABLE things (tenant uuid NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO things VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Import(ctx, host, r.Tenant, []rbac.Grant{grant(r.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetMemberships(ctx, host, r.Tenant, []rbac.Membership{{Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}); err != nil {
		t.Fatal(err)
	}
	pred, err := h.authz.Filter(ctx, rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}, login, r.Tenant, "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, "SELECT id FROM things WHERE "+pred.SQL, pred.Args...)
	if err != nil {
		t.Fatalf("%s: %v", pred.SQL, err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || !slices.Equal(got, []string{"c"}) {
		t.Fatalf("Filter on a uuid tenant column = %v, %v", got, err)
	}
}

// A host's columns in a collation that isn't deterministic compare keys and tenants the package
// tells apart as equal: Filter compares them as Authorize does, byte for byte.
func TestFilterTellsKeysAndTenantsApartInAnyCollation(t *testing.T) {
	// Few grants on clusters are compared with the path, and many by its first key; few on
	// containers are compared with the path, and many by each of its keys, as all denies on them
	// are.
	for _, n := range []int{1, 9} {
		for _, keyed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d cluster grants, workspace grants looked up %t", n, keyed), func(t *testing.T) {
				h, guardian := guarded(t)
				if keyed {
					rbac.SetMaxContainerOverlap(t, 0)
				}
				ctx := t.Context()
				for _, q := range []string{
					`CREATE COLLATION loose (provider = icu, locale = 'und-u-ks-level2', deterministic = false)`,
					`CREATE TABLE clusters (tenant text COLLATE loose NOT NULL, id text NOT NULL, path text[] COLLATE loose NOT NULL)`,
				} {
					if _, err := h.pool.Exec(ctx, q); err != nil {
						t.Fatal(err)
					}
				}
				o1 := rbac.Scope{Type: "org", ID: "o1"}
				w1 := []rbac.Scope{{Type: "workspace", ID: "w1"}, o1}
				w2 := []rbac.Scope{{Type: "workspace", ID: "w2"}, o1}
				grants := []rbac.Grant{grant(w1[0], "cluster.login", rbac.User, "u")}
				for i := range n {
					grants = append(grants, grant(rbac.Scope{Type: "cluster", ID: fmt.Sprintf("c%d", i+1)}, "cluster.login", rbac.User, "u"))
				}
				h.seed(t, grants...)
				u := h.as(t, "u")
				// u is granted c1 and w1 and denied d1 and W2, which C1, D1, W1 and w2 aren't.
				resources := []rbac.Resource{
					{Tenant: "t1", Type: "cluster", ID: "C1", Ancestors: w2},
					{Tenant: "t1", Type: "cluster", ID: "D1", Ancestors: w1},
					{Tenant: "t1", Type: "cluster", ID: "c1", Ancestors: w2},
					{Tenant: "t1", Type: "cluster", ID: "d1", Ancestors: w1},
					{Tenant: "t1", Type: "cluster", ID: "e1", Ancestors: []rbac.Scope{{Type: "workspace", ID: "W1"}, o1}},
				}
				deny := rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{login}}
				for _, r := range []rbac.Resource{resources[3], {Tenant: "t1", Type: "workspace", ID: "W2", Ancestors: []rbac.Scope{o1}}} {
					if err := h.authz.SetDeny(ctx, guardian, r, deny); err != nil {
						t.Fatal(err)
					}
				}
				// And a tenant that differs from t1 only in case.
				for _, r := range append(slices.Clone(resources), rbac.Resource{Tenant: "T1", Type: "cluster", ID: "x", Ancestors: w1}) {
					if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
						t.Fatal(err)
					}
				}
				if got := allowedOf(t, h, resources, u, login); !slices.Equal(got, []string{"D1", "c1"}) {
					t.Fatalf("Authorize allowed %v", got)
				}
				pred, err := h.authz.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				if err != nil {
					t.Fatal(err)
				}
				rows, err := h.pool.Query(ctx, `SELECT tenant || '/' || id COLLATE "C" FROM clusters WHERE `+pred.SQL+` ORDER BY 1`, pred.Args...)
				if err != nil {
					t.Fatalf("%s: %v", pred.SQL, err)
				}
				got, err := pgx.CollectRows(rows, pgx.RowTo[string])
				if err != nil {
					t.Fatal(err)
				}
				if want := []string{"t1/D1", "t1/c1"}; !slices.Equal(got, want) {
					t.Errorf("Filter kept %v, want %v", got, want)
				}
			})
		}
	}
}

// A path column's GIN index is in its collation, which Filter compares keys in too, as byte for
// byte, so the index serves whatever it is.
func TestFilterReadsThePathIndexInItsCollation(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`CREATE TABLE fleet (tenant text COLLATE "C" NOT NULL, id text NOT NULL, path text[] COLLATE "C" NOT NULL)`,
		`INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 50), 'org:o1', 'tenant:t1']
			FROM generate_series(1, 20000) i`,
		`CREATE INDEX ON fleet USING gin (path)`,
		`ANALYZE fleet`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c7"}, "cluster.login", rbac.User, "few"))
	pred, err := h.authz.Filter(ctx, h.as(t, "few"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 1 {
		t.Fatalf("Filter found %d, %v", n, err)
	}
	rows, err := h.pool.Query(ctx, "EXPLAIN SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if text := strings.Join(plan, "\n"); !strings.Contains(text, "Bitmap Index Scan") {
		t.Fatalf("Filter's plan on a path column in the C collation:\n%s", text)
	}
}

func TestHolders(t *testing.T) {
	h := setup(t)
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.sudo", rbac.Group, "admins"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "u"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"),
		grant(cluster.Scope(), "cluster.sudo", rbac.User, "stranger"),
	)
	// a is in admins, and owner and u are members; stranger, granted root, isn't in the tenant.
	h.as(t, "a", "admins")
	h.as(t, "owner")
	h.as(t, "u")
	got, err := h.authz.Holders(t.Context(), root, cluster)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbac.Principal{{Kind: rbac.User, ID: "a"}, {Kind: rbac.User, ID: "owner"}}
	if !slices.Equal(holderPrincipals(got), want) || !slices.Equal(got[0].Groups, []string{"admins"}) || len(got[0].Grants) != 1 || got[1].Groups != nil {
		t.Errorf("Holders(root) = %+v, want %v", got, want)
	}
	got, err = h.authz.Holders(t.Context(), login, cluster)
	want = []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.User, ID: "a"}, {Kind: rbac.User, ID: "owner"}, {Kind: rbac.User, ID: "u"}}
	if err != nil || !slices.Equal(holderPrincipals(got), want) {
		t.Errorf("Holders(login) = %+v, %v", got, err)
	}
}

// holderPrincipals is who Holders lists.
func holderPrincipals(holders []rbac.Holder) []rbac.Principal {
	ps := make([]rbac.Principal, len(holders))
	for i, h := range holders {
		ps[i] = h.Principal
	}
	return ps
}

// Holders evaluates no condition, so an access review lists too many rather than too few: a holder
// whose every grant has a condition is listed and marked Conditional, and one a conditional deny
// binds is listed and marked MaybeDenied, though each condition here reads the resource alone, so
// a check decides it whatever the request. Only a deny with no condition leaves out whom it binds.
func TestHoldersMarksConditionalGrantsAndDeniesWithoutEvaluatingThem(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	prod := cluster
	prod.Attributes = map[string]any{"env": "prod"}
	onDev := grant(prod.Scope(), "cluster.login", rbac.User, "dev")
	onDev.Condition = rbac.Condition{Expression: `resource.attributes.env == "dev"`}
	h.seed(t, onDev, grant(prod.Scope(), "cluster.login", rbac.User, "always"), grant(prod.Scope(), "cluster.login", rbac.User, "never"),
		grant(prod.Scope(), "cluster.login", rbac.User, "unconditional"))
	subjects := map[string]rbac.Subject{}
	for _, id := range []string{"dev", "always", "never", "unconditional"} {
		subjects[id] = h.as(t, id)
	}
	for _, d := range []rbac.Deny{
		{ID: "always", Principals: []rbac.Principal{identity("always")}, Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: `resource.attributes.env == "prod"`}},
		{ID: "never", Principals: []rbac.Principal{identity("never")}, Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: `resource.attributes.env == "dev"`}},
		{ID: "unconditional", Principals: []rbac.Principal{identity("unconditional")}, Permissions: []rbac.Permission{login}},
	} {
		if err := h.authz.SetDeny(ctx, guardian, prod, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []context.Context{ctx, rbac.WithRequest(ctx, map[string]any{"mfa": true})} {
		for id, allowed := range map[string]bool{"dev": false, "always": false, "never": true, "unconditional": false} {
			if err := h.authz.Authorize(c, subjects[id], login, prod); (err == nil) != allowed {
				t.Errorf("Authorize(%s) = %v, whatever the request", id, err)
			}
		}
	}
	holders, err := h.authz.Holders(ctx, login, prod)
	if err != nil {
		t.Fatal(err)
	}
	type marks struct{ conditional, maybeDenied bool }
	got := map[string]marks{}
	for _, hd := range holders {
		if _, ok := subjects[hd.Principal.ID]; ok && hd.Principal.Kind == rbac.User {
			got[hd.Principal.ID] = marks{hd.Conditional, hd.MaybeDenied}
		}
	}
	if want := map[string]marks{"dev": {conditional: true}, "always": {maybeDenied: true}, "never": {maybeDenied: true}}; !maps.Equal(got, want) {
		t.Errorf("Holders marks %+v, not %+v", got, want)
	}
}

func TestAMisspelledPermissionOrTypeIsInvalid(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	misspelled := cluster
	misspelled.Type = "clutser"
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	owner := h.as(t, "owner")
	cols := rbac.Columns{Tenant: "tenant", Path: "path"}
	for name, ask := range map[string]func() error{
		"a permission":         func() error { return h.authz.Authorize(ctx, owner, "cluster:lgoin", cluster) },
		"a type":               func() error { return h.authz.Authorize(ctx, owner, login, misspelled) },
		"a permission Explain": func() error { _, err := h.authz.Explain(ctx, owner, "cluster:lgoin", cluster); return err },
		"a type Explain":       func() error { _, err := h.authz.Explain(ctx, owner, login, misspelled); return err },
		"a permission Holders": func() error { _, err := h.authz.Holders(ctx, "cluster:lgoin", cluster); return err },
		"a type Holders":       func() error { _, err := h.authz.Holders(ctx, login, misspelled); return err },
		"a permission Reachable": func() error {
			_, err := h.authz.Reachable(ctx, owner, "cluster:lgoin", "t1", "cluster")
			return err
		},
		"a type Reachable": func() error {
			_, err := h.authz.Reachable(ctx, owner, login, "t1", "clutser")
			return err
		},
		"a permission Filter": func() error {
			_, err := h.authz.Filter(ctx, owner, "cluster:lgoin", "t1", "cluster", cols, 1)
			return err
		},
		"a type Filter": func() error {
			_, err := h.authz.Filter(ctx, owner, login, "t1", "clutser", cols, 1)
			return err
		},
		"a type Permissions": func() error { _, err := h.authz.Permissions(ctx, owner, misspelled); return err },
		"a type Grantable":   func() error { _, err := h.authz.Grantable(ctx, owner, misspelled); return err },
		"the anonymous":      func() error { return h.authz.Authorize(ctx, rbac.Subject{}, "cluster:lgoin", cluster) },
		"a type Apply": func() error {
			return h.authz.Apply(ctx, owner, misspelled, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u}}})
		},
		"a type SetDeny": func() error {
			return h.authz.SetDeny(ctx, owner, misspelled, rbac.Deny{ID: "d", Principals: []rbac.Principal{u}, Permissions: []rbac.Permission{login}})
		},
		"a type DeleteDeny": func() error { return h.authz.DeleteDeny(ctx, owner, misspelled, "d") },
		"a type SetEligibility": func() error {
			return h.authz.SetEligibility(ctx, owner, misspelled, rbac.Eligibility{Role: "cluster.login", Principal: u})
		},
		"a type DeleteEligibility": func() error {
			return h.authz.DeleteEligibility(ctx, owner, misspelled, "cluster.login", u)
		},
		"a type Activate": func() error {
			_, err := h.authz.Activate(ctx, h.as(t, "u"), misspelled, rbac.Activation{Role: "cluster.login", Duration: time.Hour, Justification: "on call"})
			return err
		},
		// A removal too, which would otherwise succeed having removed nothing, leaving the grants
		// of the type it meant.
		"a type Deactivate":  func() error { return h.authz.Deactivate(ctx, h.as(t, "u"), misspelled, "cluster.login") },
		"a type DeleteScope": func() error { return h.authz.DeleteScope(ctx, host, "t1", misspelled.Scope()) },
		"a type DeleteScopes": func() error {
			return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope(), misspelled.Scope()})
		},
		"a type DeleteGrants": func() error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(misspelled.Scope(), "cluster.admin", rbac.User, "owner")})
		},
	} {
		if err := ask(); !errors.Is(err, rbac.ErrInvalid) || errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s misspelled: %v", name, err)
		}
	}
	// A permission no built-in role gives on a type can still be asked about there: a custom role
	// may give it, as it gives any permission the catalog has, on any type it has.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.ws-login', '{cluster:login}', '{workspace}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(workspace.Scope(), "custom.ws-login", rbac.User, "u"))
	if !allowed(t, h, h.as(t, "u"), login, workspace) {
		t.Fatal("a permission a custom role gives on a type no built-in role gives it on")
	}
	// What a container is can be asked even where no role is for its type.
	if perms, err := h.authz.Permissions(ctx, h.as(t, "owner"), rbac.Resource{Tenant: "t1", Type: "org", ID: "o1"}); err != nil || len(perms) != 0 {
		t.Fatalf("Permissions on a container no role is for = %v, %v", perms, err)
	}
}

func TestARetiredTypesScopesAreDeletedWhileTheHostChecksIt(t *testing.T) {
	queue := rbac.RoleDefinition{ID: "queue.reader", Permissions: []rbac.Permission{"queue:read"}, ResourceTypes: []string{"queue"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), queue) })
	ctx := t.Context()
	q1, q2 := rbac.Scope{Type: "queue", ID: "q1"}, rbac.Scope{Type: "queue", ID: "q2"}
	h.seed(t, grant(q1, queue.ID, rbac.User, "u"), grant(q2, queue.ID, rbac.User, "u"), grant(q2, queue.ID, rbac.User, "v"))
	// The catalog drops queues; while the host still lists one of their permissions, it has the type.
	retiring := func(c *rbac.Config) {
		c.Catalog = catalog
		c.Permissions = declaring(catalog, "queue:read")
	}
	for name, mutate := range map[string]func(*rbac.Config){"retired": func(c *rbac.Config) { c.Catalog = catalog }, "retiring": retiring} {
		authz, err := rbac.New(h.pool, func() rbac.Config { c := h.cfg; mutate(&c); return c }())
		if err != nil {
			t.Fatal(err)
		}
		err = authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{q1})
		if name == "retired" && !errors.Is(err, rbac.ErrInvalid) || name == "retiring" && err != nil {
			t.Errorf("deleting a %s type's scopes: %v", name, err)
		}
	}
	if gs, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{q1, q2}}); err != nil || len(gs) != 2 {
		t.Fatalf("Grants = %+v, %v", gs, err)
	}
	// Whatever the type, a principal's grants go with it.
	retired, err := rbac.New(h.pool, func() rbac.Config { c := h.cfg; c.Catalog = catalog; return c }())
	if err != nil {
		t.Fatal(err)
	}
	if err := retired.DeletePrincipal(ctx, host, "t1", identity("u")); err != nil {
		t.Fatal(err)
	}
	if gs, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{q2}}); err != nil || len(gs) != 1 || gs[0].Principal != identity("v") {
		t.Fatalf("Grants = %+v, %v", gs, err)
	}
}

func TestTheHostDeclaresThePermissionsItChecks(t *testing.T) {
	// The host checks storage:mount, which its catalog, configured by an operator, leaves out.
	h := setup(t, func(c *rbac.Config) { c.Permissions = declaring(c.Catalog, "storage:mount") })
	ctx := t.Context()
	storage := rbac.Resource{Tenant: "t1", Type: "storage", ID: "s1", Ancestors: cluster.Ancestors}
	if err := h.authz.Authorize(ctx, h.as(t, "owner"), "storage:mount", storage); !errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a permission the host checks that no role gives: %v", err)
	}
	pred, err := h.authz.Filter(ctx, h.as(t, "owner"), "storage:mount", "t1", "storage", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil || pred.SQL != "FALSE" {
		t.Fatalf("Filter = %+v, %v", pred, err)
	}
	if holders, err := h.authz.Holders(ctx, "storage:mount", storage); err != nil || len(holders) != 0 {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	if err := h.authz.Authorize(ctx, h.as(t, "owner"), "storage:mnt", storage); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a permission the host doesn't check: %v", err)
	}
}

func TestApplyPreventsEscalation(t *testing.T) {
	h := setup(t)
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "workspace.admin", rbac.User, "ws-admin"),
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "workspace.admin", rbac.User, "manager"),
		grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.sudo", rbac.User, "manager"),
	)
	ctx := t.Context()
	b := func(role rbac.Role, id string) rbac.Binding {
		return rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: id}}
	}

	// May change access on the workspace, but holds no cluster permission to hand on.
	err := h.authz.Apply(ctx, h.as(t, "ws-admin"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}})
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting what the actor doesn't hold: %v", err)
	}
	// Holds sudo on clusters here and may change access: can hand on login and sudo, not admin.
	if err := h.authz.Apply(ctx, h.as(t, "manager"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x"), b("cluster.sudo", "y")}}); err != nil {
		t.Fatalf("granting what the actor holds: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "manager"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.admin", "z")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting more than the actor holds: %v", err)
	}
	// No grant permission on the cluster itself.
	if err := h.authz.Apply(ctx, h.as(t, "manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access without cluster:grant: %v", err)
	}
	// The creator's admin role holds every permission, so it may grant any role.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.admin", "z")}}); err != nil {
		t.Fatalf("the creator: %v", err)
	}
	if !allowed(t, h, h.as(t, "y"), root, cluster) || !allowed(t, h, h.as(t, "z"), root, cluster) {
		t.Fatal("the grants should give what they say")
	}
	// Revoking needs only the grant permission.
	if err := h.authz.Apply(ctx, h.as(t, "ws-admin"), workspace, rbac.Change{Revoke: []rbac.Binding{b("cluster.sudo", "y")}}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if allowed(t, h, h.as(t, "y"), root, cluster) {
		t.Fatal("revoked access should be gone")
	}
}

func TestConstraintsBindWhatAnActorHandsOn(t *testing.T) {
	robot := rbac.PrincipalKind("service_account")
	var asked []rbac.ConstraintInput
	var redefine bool
	h := setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{robot}
		c.Constraints = []rbac.Constraint{{Name: "no root for service accounts", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Subject != nil && in.Subject.Principal.Kind == robot {
				asked = append(asked, in)
			}
			return in.Permission == root && (in.Subject == nil || in.Subject.Principal.Kind == robot), nil
		}}}
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			// As another change would, between the checks before the change's transaction and in it.
			if redefine {
				if _, err := q.Exec(ctx, `UPDATE rbac_roles SET permissions = '{cluster:view,cluster:login,cluster:root}' WHERE id = 'custom.op'`); err != nil {
					return err
				}
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	bot := h.member(t, rbac.Principal{Kind: robot, ID: "ci"})
	h.seed(t,
		grant(rbac.TenantRoot("t1"), "cluster.admin", robot, "ci"),
		grant(rbac.TenantRoot("t1"), "tenant.roles", robot, "ci"),
		grant(rbac.TenantRoot("t1"), "workspace.admin", robot, "ci"),
		grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "admin"),
		grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"),
	)
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	if allowed(t, h, bot, root, cluster) {
		t.Fatal("the constraint should keep root from the service account")
	}
	// What it may not use it may not hand on, on the cluster or through the workspace above it.
	for _, on := range []rbac.Resource{cluster, workspace} {
		asked = nil
		err := h.authz.Apply(ctx, bot, on, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: u}}})
		var denied *rbac.DeniedError
		if !errors.As(err, &denied) || denied.Permission != root || !strings.Contains(denied.Reason, "no root for service accounts") {
			t.Fatalf("handing on root on a %s: %v", on.Type, err)
		}
		i := slices.IndexFunc(asked, func(in rbac.ConstraintInput) bool { return in.Permission == root })
		if i < 0 || asked[i].ResourceType != "cluster" || asked[i].Resource == nil || asked[i].Resource.Scope() != on.Scope() {
			t.Fatalf("on a %s the constraint was asked %+v", on.Type, asked)
		}
	}
	if err := h.authz.SetEligibility(ctx, bot, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u, MaxDuration: time.Hour}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("making another eligible for root: %v", err)
	}
	if allowed(t, h, h.as(t, "u"), root, cluster) {
		t.Fatal("a refused grant gave root")
	}
	if err := h.authz.Apply(ctx, bot, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: u}}}); err != nil {
		t.Fatalf("handing on what the constraint leaves: %v", err)
	}
	roles, err := h.authz.Grantable(ctx, bot, cluster)
	if err != nil || slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return slices.Contains(r.Permissions, root) }) ||
		!slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.login" }) {
		t.Fatalf("Grantable = %v, %v", roles, err)
	}
	// Defining a role hands on what it gives, to every holder of it.
	withRoot := rbac.RoleDefinition{ID: "custom.root", Permissions: []rbac.Permission{view, root}, ResourceTypes: []string{"cluster"}}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, bot, "t1", withRoot); !errors.As(err, &denied) || !strings.Contains(denied.Reason, "no root for service accounts") {
		t.Fatalf("defining a role giving root: %v", err)
	}
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, bot, "t1", op); err != nil {
		t.Fatalf("defining a role giving what the constraint leaves: %v", err)
	}
	// A role redefined to give root once the constraints were asked is refused in the transaction,
	// to be tried again, rather than granted unasked; tried again, the constraint refuses it.
	redefine = true
	grantOp := rbac.Change{Grant: []rbac.Binding{{Role: op.ID, Principal: u}}}
	if err := h.authz.Apply(ctx, bot, cluster, grantOp); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a role redefined while the change waited: %v", err)
	}
	redefine = false
	if err := h.authz.Apply(ctx, bot, cluster, grantOp); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
	if allowed(t, h, h.as(t, "u"), root, cluster) {
		t.Fatal("a refused grant gave root")
	}
	// Those the constraint doesn't bind hand on as before.
	if err := h.authz.Apply(ctx, h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: u}}}); err != nil {
		t.Fatalf("an admin the constraint doesn't bind: %v", err)
	}
}

func TestConstraintsBindThePowerAnActorHandsOn(t *testing.T) {
	robot := rbac.PrincipalKind("service_account")
	gatekeeper := rbac.RoleDefinition{ID: "cluster.gatekeeper", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{robot}
		c.Catalog = append(slices.Clone(c.Catalog), gatekeeper)
		c.Constraints = []rbac.Constraint{{Name: "people manage clusters' access", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == grantC && (in.Subject == nil || in.Subject.Principal.Kind == robot), nil
		}}}
	})
	ctx := t.Context()
	bot := h.member(t, rbac.Principal{Kind: robot, ID: "ci"})
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", robot, "ci"), grant(rbac.TenantRoot("t1"), "workspace.admin", robot, "ci"))
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	// A change on the workspace changes no cluster's grants, but the power it hands on would.
	if err := h.authz.Apply(ctx, bot, workspace, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: u}}}); err != nil {
		t.Fatalf("granting what the constraint leaves: %v", err)
	}
	var denied *rbac.DeniedError
	if err := h.authz.Apply(ctx, bot, workspace, rbac.Change{Grant: []rbac.Binding{{Role: gatekeeper.ID, Principal: u}}}); !errors.As(err, &denied) || denied.Permission != grantC {
		t.Fatalf("handing on the power to change clusters' grants: %v", err)
	}
}

func TestAConstraintOnOneContainerLeavesHandingOnElsewhere(t *testing.T) {
	frozen := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "frozen", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
	// Changes to grants are frozen under one workspace, for everyone.
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if !in.Permission.Valid() || !strings.HasSuffix(string(in.Permission), ":grant") {
				return false, nil
			}
			return in.Resource == nil || in.Resource.Scope() == frozen.Scope() || slices.Contains(in.Resource.Ancestors, frozen.Scope()), nil
		}}}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.admin", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "admin"))
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	for _, role := range []rbac.Role{"workspace.admin", "cluster.admin"} {
		if err := h.authz.Apply(ctx, h.as(t, "admin"), workspace, rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: u}}}); err != nil {
			t.Errorf("handing on %s on a workspace the freeze doesn't cover: %v", role, err)
		}
		if err := h.authz.Apply(ctx, h.as(t, "admin"), frozen, rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: u}}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("handing on %s on the frozen workspace: %v", role, err)
		}
	}
}

func TestAConstraintThatErrsFailsHandingOn(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "lookup", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Permission == root {
				return false, errLookup
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}
	if err := h.authz.Apply(ctx, admin, cluster, sudo); !errors.Is(err, errLookup) {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := h.authz.Grantable(ctx, admin, cluster); !errors.Is(err, errLookup) {
		t.Fatalf("Grantable: %v", err)
	}
	withRoot := rbac.RoleDefinition{ID: "custom.root", Permissions: []rbac.Permission{view, root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", withRoot); !errors.Is(err, errLookup) {
		t.Fatalf("SetRole: %v", err)
	}
}

func TestDefiningARoleListingOneRedefinedMeanwhileConflicts(t *testing.T) {
	var redefine bool
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "watch", Deny: func(ctx context.Context, q rbac.DB, in rbac.ConstraintInput) (bool, error) {
			// Asked last before SetRole's transaction, as another change would land between them.
			if redefine && in.Permission == rbac.GrantPermission(rbac.TenantScope) && in.Resource == nil {
				redefine = false
				_, err := q.Exec(ctx, `UPDATE rbac_roles SET permissions = '{cluster:view,cluster:login,cluster:root}' WHERE id = 'custom.op'`)
				return false, err
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	lead := rbac.RoleDefinition{ID: "custom.lead", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{op.ID}}
	for _, r := range []rbac.RoleDefinition{op, lead} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	lead.Permissions = []rbac.Permission{view, login, grantC}
	redefine = true
	if err := h.authz.SetRole(ctx, admin, "t1", lead); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a listed role redefined while the change waited: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", lead); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

// A grant outlives the actor's power to change grants, but what it hands on the actor holds until
// the grant ends; a role a role it holds lists, it grants without holding, so for good.
func TestAGrantOutlivesTheActorsAccess(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "workspace.lister", Permissions: []rbac.Permission{"workspace:grant"},
			ResourceTypes: []string{"workspace"}, GrantableRoles: []rbac.Role{"cluster.login"},
		})
	})
	ctx := t.Context()
	hour := h.now.Add(time.Hour)
	expiring := func(g rbac.Grant) rbac.Grant { g.ExpiresAt = hour; return g }
	org := rbac.Scope{Type: "org", ID: "o1"}
	// temp changes grants on the workspace for an hour, and logs in to its clusters for good; brief
	// changes them for good, and logs in for an hour; lister, for an hour, may grant login there.
	h.seed(t, expiring(grant(workspace.Scope(), "workspace.admin", rbac.User, "temp")), grant(org, "cluster.login", rbac.User, "temp"),
		grant(workspace.Scope(), "workspace.admin", rbac.User, "brief"), expiring(grant(org, "cluster.login", rbac.User, "brief")),
		expiring(grant(workspace.Scope(), "workspace.lister", rbac.User, "lister")))
	h.groups(t, "friends", "others", "listed")
	logins := func(group string, until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: groupOf(group), ExpiresAt: until}}}
	}
	if err := h.authz.Apply(ctx, h.as(t, "temp"), workspace, logins("friends", time.Time{})); err != nil {
		t.Fatalf("a power for an hour granting for good what its holder holds for good: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "brief"), workspace, logins("others", time.Time{})); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("access for an hour granted for good: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "brief"), workspace, logins("others", hour)); err != nil {
		t.Fatalf("access for an hour granted for the hour: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "lister"), workspace, logins("listed", time.Time{})); err != nil {
		t.Fatalf("a listed role granted for good by a power for an hour: %v", err)
	}
	h.now = h.now.Add(2 * time.Hour)
	if !allowed(t, h, h.as(t, "f", "friends"), login, cluster) || !allowed(t, h, h.as(t, "l", "listed"), login, cluster) {
		t.Fatal("a grant should outlive the power to change grants of whoever made it")
	}
	if allowed(t, h, h.as(t, "o", "others"), login, cluster) {
		t.Fatal("a grant should end with the access it handed on")
	}
}

func TestApplyValidatesEveryBinding(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "nope", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}},
		{Role: "workspace.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}},
		{Role: "cluster.admin", Principal: rbac.TenantMembers("t1")},
		{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "outsider1"}},
		{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, ExpiresAt: h.now.Add(-time.Minute)},
		{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, ExpiresAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)},
	}})
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("want every invalid binding reported, got %v", err)
	}
	var invalid []*rbac.InvalidError
	for _, e := range joined.Unwrap() {
		var ie *rbac.InvalidError
		if errors.As(e, &ie) {
			invalid = append(invalid, ie)
		}
	}
	if len(invalid) != 6 || !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("got %d invalid bindings: %v", len(invalid), err)
	}
	if len(h.events) != 0 {
		t.Fatal("an invalid change must store nothing")
	}
}

// refusal is a host's own error type for a grant it refuses, as a host maps to a response.
type refusal struct{ code string }

func (r *refusal) Error() string { return "refused: " + r.code }

func TestAHostsRefusalKeepsItsError(t *testing.T) {
	errNotMember := errors.New("not a member of the tenant")
	h := setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			switch in.Binding.Principal.ID {
			case "outsider":
				return fmt.Errorf("%w: %w", rbac.ErrInvalid, errNotMember)
			case "guest":
				return fmt.Errorf("%w: %w", rbac.ErrInvalid, &refusal{code: "guest_role"})
			case "plain":
				return rbac.ErrInvalid
			case "after":
				return fmt.Errorf("not a member of the tenant: %w", rbac.ErrInvalid)
			case "joined":
				return errors.Join(rbac.ErrInvalid, errNotMember)
			case "own":
				return &rbac.InvalidError{Binding: in.Binding, Reason: "not a member of the tenant"}
			}
			return nil
		}
	})
	apply := func(id string) error {
		return h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{
			{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: id}},
		}})
	}
	err := apply("outsider")
	var ie *rbac.InvalidError
	if !errors.Is(err, errNotMember) || !errors.Is(err, rbac.ErrInvalid) || !errors.As(err, &ie) || ie.Binding.Principal.ID != "outsider" {
		t.Fatalf("a refusal wrapping the host's error: %v", err)
	}
	if want := "rbac: cluster.login for user:outsider: not a member of the tenant"; err.Error() != want {
		t.Errorf("message %q, want %q", err, want)
	}
	var r *refusal
	if err := apply("guest"); !errors.As(err, &r) || r.code != "guest_role" {
		t.Fatalf("a refusal of the host's own type: %v", err)
	}
	if err := apply("plain"); !errors.Is(err, rbac.ErrInvalid) || err.Error() != "rbac: cluster.login for user:plain: refused by the host" {
		t.Fatalf("a refusal that is ErrInvalid alone: %v", err)
	}
	for _, id := range []string{"after", "joined", "own"} {
		if err, want := apply(id), "rbac: cluster.login for user:"+id+": not a member of the tenant"; !errors.Is(err, rbac.ErrInvalid) || err.Error() != want {
			t.Errorf("a refusal %s: %q, want %q", id, err, want)
		}
	}
}

func TestOnlyTheHostChangesTheSourcesItOwns(t *testing.T) {
	var asked []rbac.GrantInput
	h := setup(t, func(c *rbac.Config) {
		c.Sources = []string{"directory"}
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	synced := rbac.Binding{Role: "cluster.login", Principal: u, Source: "directory"}
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: synced})
	stored, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u}})
	if err != nil || len(stored) != 1 {
		t.Fatalf("Grants = %+v, %v", stored, err)
	}
	asked = nil
	// The tenant's owner may change access on the cluster, but not the host's own grants.
	forged := rbac.Binding{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "v"}, Source: "directory"}
	for name, c := range map[string]rbac.Change{
		"granting from it":      {Grant: []rbac.Binding{forged}},
		"revoking from it":      {Revoke: []rbac.Binding{synced}},
		"revoking none from it": {Revoke: []rbac.Binding{{Role: synced.Role, Principal: forged.Principal, Source: "directory"}}},
		"revoking one by ID":    {Revoke: []rbac.Binding{{ID: stored[0].ID, Role: synced.Role, Principal: u}}},
		"a reserved source":     {Grant: []rbac.Binding{{Role: "cluster.login", Principal: u, Source: "rbac.sync"}}},
	} {
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, c); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// One who may not change access is refused as such, learning nothing of the host's sources.
	if err := h.authz.Apply(ctx, h.as(t, "nobody"), cluster, rbac.Change{Grant: []rbac.Binding{forged}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("granting from it without the power to: %v", err)
	}
	// A revoke by ID that names another principal matches no grant, so it isn't refused.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Revoke: []rbac.Binding{{ID: stored[0].ID, Role: synced.Role, Principal: forged.Principal}}}); err != nil {
		t.Errorf("revoking by ID with another principal: %v", err)
	}
	if !allowed(t, h, h.as(t, "u"), login, cluster) || allowed(t, h, h.as(t, "v"), view, cluster) || len(asked) != 0 {
		t.Fatalf("the host's grant should stand and no other be made, asked %+v", asked)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{Role: "cluster.login", Principal: u, Source: "rbac.sync"}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing from a reserved source: %v", err)
	}
	// Grants from other sources change as before.
	mine := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "w"}, Source: "tickets"}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{mine}}); err != nil {
		t.Fatal(err)
	}
	theirs, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{mine.Principal}})
	if err != nil || len(theirs) != 1 {
		t.Fatalf("Grants = %+v, %v", theirs, err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Revoke: []rbac.Binding{{ID: theirs[0].ID, Role: mine.Role, Principal: mine.Principal}}}); err != nil {
		t.Fatalf("revoking by ID a grant from another source: %v", err)
	}
	if allowed(t, h, h.as(t, "w"), login, cluster) {
		t.Fatal("the revoke by ID should have removed the grant")
	}
	// The host removes its own, by source and by ID.
	h.events = nil
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: synced}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "u"), login, cluster) || len(h.events) != 1 || len(h.events[0].Revoked) != 1 || h.events[0].Actor != host {
		t.Fatalf("DeleteGrants left the grant or reported %+v", h.events)
	}
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: synced})
	again, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u}})
	if err != nil || len(again) != 1 {
		t.Fatalf("Grants = %+v, %v", again, err)
	}
	byID := rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{ID: again[0].ID, Role: synced.Role, Principal: u}}
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{byID}); err != nil || allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatalf("DeleteGrants by ID: %v", err)
	}
	for name, g := range map[string]rbac.Grant{
		"another tenant's scope": {Scope: rbac.TenantRoot("t2"), Binding: synced},
		"no role":                {Scope: cluster.Scope(), Binding: rbac.Binding{Principal: u, Source: "directory"}},
		"a malformed principal":  {Scope: cluster.Scope(), Binding: rbac.Binding{Role: synced.Role, Principal: rbac.Principal{Kind: rbac.User}, Source: "directory"}},
	} {
		if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{g}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteGrants %s: %v", name, err)
		}
	}
	one := []rbac.Grant{{Scope: cluster.Scope(), Binding: synced}}
	for name, err := range map[string]error{
		"no tenant":       h.authz.DeleteGrants(ctx, host, "", one),
		"a group actor":   h.authz.DeleteGrants(ctx, rbac.Principal{Kind: rbac.Group, ID: "g"}, "t1", one),
		"too many grants": h.authz.DeleteGrants(ctx, host, "t1", slices.Repeat(one, rbac.MaxBindings+1)),
	} {
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteGrants with %s: %v", name, err)
		}
	}
}

func TestAnAdminCantFillTheBoundBeforeTheHostsGrants(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	u := rbac.Principal{Kind: rbac.User, ID: "u"}
	var fill []rbac.Binding
	for i := range rbac.MaxGrantsPerRole {
		fill = append(fill, rbac.Binding{Role: "cluster.login", Principal: u, ExpiresAt: h.now.Add(time.Duration(i+1) * time.Hour)})
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: fill}); err != nil {
		t.Fatal(err)
	}
	more := rbac.Binding{Role: "cluster.login", Principal: u, ExpiresAt: h.now.Add(48 * time.Hour)}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{more}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("the admin's grant past the bound: %v", err)
	}
	synced := rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{Role: "cluster.login", Principal: u, Source: "directory"}}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{synced}); err != nil {
		t.Fatalf("the host's grant beside an admin's filled bound: %v", err)
	}
}

func TestDeletingARoleTheHostGrantsIsRefused(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	synced := rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{Role: op.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, Source: "directory"}}
	h.seed(t, synced)
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a role the host grants: %v", err)
	}
	if !allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("a refused deletion revoked the host's grant")
	}
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{synced}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); err != nil {
		t.Fatalf("deleting it once the host removed its grants: %v", err)
	}
	// One the host granted only until a time that has passed gives nothing, and Grants lists none
	// for the host to remove.
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	synced.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, synced)
	h.now = h.now.Add(2 * time.Hour)
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); err != nil {
		t.Fatalf("deleting a role the host granted only until a time that has passed: %v", err)
	}
}

func TestDeleteGrantsAcrossScopes(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	scopes := []rbac.Scope{cluster.Scope(), {Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}}
	var grants []rbac.Grant
	for _, s := range scopes {
		grants = append(grants, rbac.Grant{Scope: s, Binding: rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, Source: "directory"}})
	}
	h.seed(t, grants...)
	h.events = nil
	if err := h.authz.DeleteGrants(ctx, host, "t1", grants); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Revoked) != len(scopes) {
		t.Fatalf("events = %+v", h.events)
	}
	left, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}})
	if err != nil || len(left) != 0 {
		t.Fatalf("Grants = %+v, %v", left, err)
	}
}

func TestApplyReportsARoleTheScopeCantTakeAsInvalid(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "admin"))
	b := rbac.Binding{Role: "workspace.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	err := h.authz.Apply(t.Context(), h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, rbac.ErrInvalid) || errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a role a cluster can't take: %v", err)
	}
}

func TestApplyChecksTheActorBeforePrincipals(t *testing.T) {
	asked := 0
	h := setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(context.Context, rbac.DB, rbac.GrantInput) error {
			asked++
			return errors.New("not a member")
		}
	})
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "someone"}}
	err := h.authz.Apply(t.Context(), h.as(t, "nobody"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) || asked != 0 {
		t.Fatalf("a refused actor got %v after %d principal lookups", err, asked)
	}
}

func TestTheHostIsAskedAboutEachGrant(t *testing.T) {
	var asked []rbac.GrantInput
	robot := rbac.PrincipalKind("service_account")
	h := setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{robot}
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			// A host's policy: service accounts hold no privileged role.
			if in.Binding.Principal.Kind == robot && in.Role.Privileged {
				return fmt.Errorf("%w: service accounts hold no privileged role", rbac.ErrInvalid)
			}
			return nil
		}
	})
	ctx := t.Context()
	bot := rbac.Principal{Kind: robot, ID: "ci"}
	login := rbac.Binding{Role: "cluster.login", Principal: bot}
	sudo := rbac.Binding{Role: "cluster.sudo", Principal: bot}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{login, sudo}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a privileged role for a service account: %v", err)
	}
	if len(asked) != 2 || asked[1].Role.ID != "cluster.sudo" || !asked[1].Role.Privileged || asked[1].Actor.Principal != h.as(t, "owner").Principal ||
		asked[1].Via != rbac.ViaApply || asked[1].Scope != cluster.Scope() || asked[1].Tenant != "t1" {
		t.Fatalf("asked = %+v", asked)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{login}}); err != nil {
		t.Fatal(err)
	}
	for via, try := range map[rbac.Via]func() error{
		rbac.ViaImport: func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: sudo}})
		},
		rbac.ViaEligibility: func() error {
			return h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: sudo.Role, Principal: bot, MaxDuration: time.Hour})
		},
	} {
		asked = nil
		if err := try(); !errors.Is(err, rbac.ErrInvalid) || len(asked) != 1 || asked[0].Via != via {
			t.Errorf("%s: %v, asked %+v", via, err, asked)
		} else if via == rbac.ViaImport && asked[0].Actor.Principal != host {
			t.Errorf("Import's actor: %+v", asked[0])
		}
	}
	// Activating is asked about too, as the grant it makes.
	e := rbac.Eligibility{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	asked = nil
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: e.Role, Duration: time.Minute, Justification: "x"}); err != nil ||
		len(asked) != 1 || asked[0].Via != rbac.ViaActivation || asked[0].Binding.Source != rbac.SourceActivation {
		t.Fatalf("activating: %v, asked %+v", err, asked)
	}
}

func TestConstraintsSeeWhoAndWhere(t *testing.T) {
	prod := rbac.Scope{Type: "workspace", ID: "prod"}
	// No root under prod but for the SRE group; a search, which can't see the resource, finds none.
	var h *harness
	h = setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "prod root", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Permission != root {
				return false, nil
			}
			if in.Resource == nil || in.Subject == nil {
				return true, nil
			}
			groups, err := h.authz.GroupsOf(ctx, in.Tenant, in.Subject.Principal)
			return slices.Contains(in.Resource.Ancestors, prod) && !slices.Contains(groups, "sre"), err
		}}}
	})
	ctx := t.Context()
	inProd := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "p1", Ancestors: []rbac.Scope{prod, {Type: "org", ID: "o1"}}}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.sudo", rbac.User, "dev"), grant(rbac.TenantRoot("t1"), "cluster.sudo", rbac.User, "sre"))
	if err := h.authz.Authorize(ctx, h.as(t, "dev"), root, cluster); err != nil {
		t.Fatalf("root outside prod: %v", err)
	}
	if err := h.authz.Authorize(ctx, h.as(t, "dev"), root, inProd); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("root in prod outside the SRE group: %v", err)
	}
	if err := h.authz.Authorize(ctx, h.as(t, "sre", "sre"), root, inProd); err != nil {
		t.Fatalf("root in prod for the SRE group: %v", err)
	}
	if d, err := h.authz.Explain(ctx, h.as(t, "dev"), root, inProd); err != nil || d.DeniedBy != "prod root" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	if reach, err := h.authz.Reachable(ctx, h.as(t, "sre", "sre"), root, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Fatalf("a search can't see the resource, so a constraint on some removes it from all: %+v, %v", reach, err)
	}
	// Holders asks it again about each holder, and marks the one it may remove root from.
	holders, err := h.authz.Holders(ctx, root, inProd)
	if err != nil || !slices.Equal(holderPrincipals(holders), []rbac.Principal{identity("dev"), identity("sre")}) || !holders[0].MaybeDenied || holders[1].MaybeDenied {
		t.Fatalf("Holders asks a constraint on some about each holder: %+v, %v", holders, err)
	}
}

func TestAConstraintWritingToWhatItIsAskedChangesNothing(t *testing.T) {
	w9 := rbac.Scope{Type: "workspace", ID: "w9"}
	var seen []string
	h := labeled(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{
			// A hook that fills in what it reads, as one loading the stored resource might.
			{Name: "careless", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if r := in.Resource; r != nil {
					if len(r.Ancestors) > 0 {
						r.Ancestors[0] = w9
					}
					if r.Attributes != nil {
						r.Attributes["env"] = "prod"
					}
					if vs := r.Labels["level"]; len(vs) > 0 {
						vs[0] = "low"
					}
				}
				if s := in.Subject; s != nil && s.Attributes != nil {
					s.Attributes["team"] = "sre"
				}
				return false, nil
			}},
			{Name: "after", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if r := in.Resource; r != nil && (slices.Contains(r.Ancestors, w9) || r.Attributes["env"] == "prod" || slices.Contains(r.Labels["level"], "low")) ||
					in.Subject != nil && in.Subject.Attributes["team"] == "sre" {
					seen = append(seen, string(in.Permission))
				}
				return false, nil
			}},
		}
	})
	ctx := t.Context()
	c2 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2", Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}}}
	prodOnly := grant(rbac.Scope{Type: "cluster", ID: "c3"}, "cluster.sudo", rbac.User, "u")
	prodOnly.Condition = rbac.Condition{Expression: `resource.attributes.env == "prod"`}
	sreOnly := grant(rbac.Scope{Type: "cluster", ID: "c4"}, "cluster.sudo", rbac.User, "u")
	sreOnly.Condition = rbac.Condition{Expression: `subject.attributes.team == "sre"`}
	// u logs in to clusters under w9 and to the secret one, and is root on c3 in prod and on c4 for
	// the SRE team; owner changes grants under w9.
	h.seed(t, grant(w9, "cluster.login", rbac.User, "u"), grant(rbac.Scope{Type: "cluster", ID: "c5"}, "cluster.login", rbac.User, "u"),
		prodOnly, sreOnly, grant(w9, "cluster.admin", rbac.User, "admin"))
	h.hold(t, "u", "level:low")
	u := rbac.Subject{Principal: h.as(t, "u").Principal, Attributes: map[string]any{"team": "dev"}}
	h.as(t, "x")
	c3 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c3", Attributes: map[string]any{"env": "dev"}}
	c4 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c4"}
	c5 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c5", Labels: rbac.Label{"level": {"high"}}}
	for name, ask := range map[string]func() bool{
		"its ancestors":  func() bool { return allowed(t, h, u, login, c2) },
		"its attributes": func() bool { return allowed(t, h, u, root, c3) },
		"the subject's":  func() bool { return allowed(t, h, u, root, c4) },
		"its label":      func() bool { return allowed(t, h, u, view, c5) },
		"its ancestors, handing": func() bool {
			return h.authz.Apply(ctx, h.as(t, "admin"), c2, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}) == nil
		},
	} {
		if ask() {
			t.Errorf("a constraint writing to %s changed what was decided", name)
		}
	}
	if c2.Ancestors[0] != (rbac.Scope{Type: "workspace", ID: "w1"}) || c3.Attributes["env"] != "dev" || c5.Labels["level"][0] != "high" || u.Attributes["team"] != "dev" {
		t.Errorf("a constraint wrote to what the host passed: %v %v %v %v", c2.Ancestors, c3.Attributes, c5.Labels, u.Attributes)
	}
	if seen != nil {
		t.Errorf("a constraint was asked about what another wrote, for %v", seen)
	}
}

func TestAConstraintWritingToAStructItIsGivenChangesNothing(t *testing.T) {
	type owner struct{ Tags map[string]string }
	var seen bool
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{
			{Name: "careless", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if o, ok := in.Resource.Attributes["owner"].(owner); ok {
					o.Tags["team"] = "sre"
				}
				return false, nil
			}},
			{Name: "after", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if o, ok := in.Resource.Attributes["owner"].(owner); ok && o.Tags["team"] == "sre" {
					seen = true
				}
				return false, nil
			}},
		}
	})
	r := cluster
	r.Attributes = map[string]any{"owner": owner{Tags: map[string]string{"team": "dev"}}}
	if !allowed(t, h, h.as(t, "owner"), login, r) {
		t.Fatal("the owner should log in")
	}
	if o, _ := r.Attributes["owner"].(owner); seen || o.Tags["team"] != "dev" {
		t.Fatalf("a constraint's write to a struct's map reached another or the host: %v, %v", seen, r.Attributes)
	}
}

type claims struct{ Roles []string }

// account embeds claims unexported, so its Roles is a field of account's to whoever holds one.
type account struct {
	claims
	Name string
}

func TestAConstraintWritingAFieldAnEmbeddedStructPromotesChangesNothing(t *testing.T) {
	var seen bool
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{
			{Name: "careless", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if a, ok := in.Subject.Attributes["account"].(account); ok {
					a.Roles[0] = "admin"
				}
				return false, nil
			}},
			{Name: "after", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if a, ok := in.Subject.Attributes["account"].(account); ok && a.Roles[0] == "admin" {
					seen = true
				}
				return false, nil
			}},
		}
	})
	owner := h.as(t, "owner")
	owner.Attributes = map[string]any{"account": account{claims: claims{Roles: []string{"viewer"}}, Name: "o"}}
	if !allowed(t, h, owner, login, cluster) {
		t.Fatal("the owner should log in")
	}
	if a, _ := owner.Attributes["account"].(account); seen || a.Roles[0] != "viewer" {
		t.Fatalf("a constraint's write to a promoted field reached another or the host: %v, %v", seen, owner.Attributes)
	}
}

// A hook's copy of a list decoded from JSON costs an allocation for the list, not one for each of
// its strings: every constraint is given one in every call. A few more are the copy's own, as the
// maps it keeps what it copied in.
func TestCopyingAListOfStringsForAHookAllocatesOnce(t *testing.T) {
	groups := make([]any, 1000)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%04d", i)
	}
	attributes := map[string]any{"groups": groups}
	if n := testing.AllocsPerRun(20, func() { rbac.DeepCopy(attributes) }); n > 16 {
		t.Errorf("copying a list of %d strings took %.0f allocations", len(groups), n)
	}
	if c, ok := rbac.DeepCopy(attributes)["groups"].([]any); !ok || &c[0] == &groups[0] {
		t.Error("the copy shares the list")
	}
}

// A hook is given a copy of what an interface holds, but nothing writes through an interface to a
// value holding no map, slice or pointer, as an array, so the copy shares it: copied element by
// element for each interface holding it, a hundred holding one array of 100 KB took 170 ms and
// allocated 10 MB. One held by value is copied whole, as setting it does. Each costs the copy what
// converting it does, a tenth of its bytes, so a copy holds ten.
func TestCopyingAnArrayInterfacesHoldSharesIt(t *testing.T) {
	var a [100_000]byte
	a[0] = 1
	held := make([]any, 10)
	for i := range held {
		held[i] = a
	}
	attributes := map[string]any{"held": held, "byValue": map[string][100_000]byte{"a": a}}
	if allocated := rbac.CopyAllocates(attributes); allocated > 3*uint64(len(a)) {
		t.Errorf("copying an array ten interfaces hold allocated %d bytes", allocated)
	}
	copied := rbac.DeepCopy(attributes)
	if h, ok := copied["held"].([]any); !ok || len(h) != len(held) || h[len(h)-1] != any(a) {
		t.Error("the copy doesn't hold the array")
	}
	if m, ok := copied["byValue"].(map[string][100_000]byte); !ok || m["a"][0] != 1 {
		t.Error("the copy doesn't hold the array a map holds")
	}
}

// A slice reached at many lengths, as each prefix of one, is copied once from where it starts, and
// each length is a slice of that copy: copied for each length, the 3,000 prefixes of one slice of
// 3,000 maps took half a second and allocated 70 MB. A copy is the hook's own, and appending to one
// writes to none of the others.
func TestCopyingPrefixesOfOneSliceCopiesItOnce(t *testing.T) {
	base := make([]any, 3000)
	for i := range base {
		base[i] = map[string]any{"i": i}
	}
	prefixes := make([]any, len(base))
	for i := range prefixes {
		prefixes[i] = base[:i+1]
	}
	attributes := map[string]any{"prefixes": prefixes}
	if allocated := rbac.CopyAllocates(attributes); allocated > 4<<20 {
		t.Errorf("copying the prefixes of one slice allocated %d bytes", allocated)
	}
	copied, ok := rbac.DeepCopy(attributes)["prefixes"].([]any)
	if !ok || len(copied) != len(prefixes) {
		t.Fatalf("the prefixes were copied as %T", rbac.DeepCopy(attributes)["prefixes"])
	}
	first, _ := copied[0].([]any)
	last, _ := copied[len(copied)-1].([]any)
	if len(first) != 1 || len(last) != len(base) || reflect.ValueOf(first[0]).Pointer() != reflect.ValueOf(last[0]).Pointer() {
		t.Fatal("the prefixes were copied apart")
	}
	if reflect.ValueOf(last[0]).Pointer() == reflect.ValueOf(base[0]).Pointer() {
		t.Fatal("the copy shares the host's maps")
	}
	_ = append(first, "appended")
	if _, ok := last[1].(map[string]any); !ok {
		t.Error("appending to one prefix's copy wrote to another's")
	}
}

// A slice reached again while its elements are copied, shorter and then longer, as by an element
// holding both, is copied whole wherever it is reached: the shorter copy, given out before the
// longer replaced it, kept the host's elements, so a hook writing to one wrote to the host's map.
func TestCopyingASliceThatGrowsWhileItIsCopiedSharesNothingWithTheHost(t *testing.T) {
	held := map[string]any{"v": "host"}
	base, both := make([]any, 5), make([]any, 2)
	base[0], base[1], base[2], base[3], base[4] = both, held, "c", "d", "e"
	both[0], both[1] = base[:3], base[:5]
	attributes := map[string]any{"a": base[:3]}
	copied := rbac.DeepCopy(attributes)
	if !reflect.DeepEqual(copied, attributes) {
		t.Fatal("the copy doesn't hold what the host passed")
	}
	hosts, copies := map[[2]uintptr]bool{}, map[[2]uintptr]bool{}
	reachedFrom(reflect.ValueOf(attributes), hosts)
	reachedFrom(reflect.ValueOf(copied), copies)
	for at := range copies {
		if hosts[at] {
			t.Fatalf("the copy holds a map or slice of the host's, at %#x", at[0])
		}
	}
}

// reachedFrom adds where each map and slice v reaches points, a slice with its length.
func reachedFrom(v reflect.Value, seen map[[2]uintptr]bool) {
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			reachedFrom(v.Elem(), seen)
		}
	case reflect.Map:
		at := [2]uintptr{v.Pointer()}
		if v.IsNil() || seen[at] {
			return
		}
		seen[at] = true
		for it := v.MapRange(); it.Next(); {
			reachedFrom(it.Value(), seen)
		}
	case reflect.Slice:
		at := [2]uintptr{v.Pointer(), uintptr(v.Len())}
		if v.IsNil() || seen[at] {
			return
		}
		seen[at] = true
		for i := range v.Len() {
			reachedFrom(v.Index(i), seen)
		}
	default:
	}
}

// Each constraint is given a copy of the subject's and the resource's attributes once for a call,
// the first time the call asks it, and the same copy whenever it asks it about the same: copied for
// each ask, Permissions of 300 permissions on a resource tagged 20,000 times took a second with one
// constraint, against 4 ms without, and a check of a resource labeled with 60 values by a subject
// passing 20,000 attributes 160 ms. ValidateGrant is given the actor's once for a call too. A hook
// writing to its copy sees its write when it is asked again in the call, and nothing else does.
func TestAHookIsGivenOneCopyForACall(t *testing.T) {
	var perms []rbac.Permission
	for i := range 300 {
		perms = append(perms, rbac.Permission(fmt.Sprintf("cluster:p%03d", i)))
	}
	var asked, seen int
	h := setup(t, compartments, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{ID: "cluster.many", Permissions: perms, ResourceTypes: []string{"cluster"}})
		c.Permissions = declaring(c.Catalog)
		c.Constraints = []rbac.Constraint{
			{Name: "counting", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if r := in.Resource; r != nil && r.Attributes != nil {
					n, _ := r.Attributes["asked"].(int)
					r.Attributes["asked"], asked = n+1, max(asked, n+1)
				}
				return false, nil
			}},
			{Name: "after", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
				if r := in.Resource; r != nil && r.Attributes["asked"] != nil {
					seen++
				}
				return false, nil
			}},
		}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.many", rbac.User, "u"), grant(rbac.TenantRoot("t1"), "compartments", rbac.User, "u"),
		grant(cluster.Scope(), "cluster.admin", rbac.User, "u"))
	u := h.as(t, "u")
	u.Attributes = map[string]any{"team": "sre"}
	r := cluster
	r.Attributes = map[string]any{"tags": map[string]any{"env": "prod"}}
	copies := rbac.CountCopies(t)
	for range 2 {
		*copies, asked = 0, 0
		got, err := h.authz.Permissions(t.Context(), u, r)
		if err != nil || len(got) < len(perms) {
			t.Fatalf("Permissions listed %d: %v", len(got), err)
		}
		// Each hook's copies of the subject's attributes, the resource's and its ancestors.
		if *copies != 2*3 || asked < len(perms) {
			t.Errorf("Permissions of %d permissions made %d copies, and the hook saw its own write %d times", len(perms), *copies, asked)
		}
	}
	if seen != 0 || r.Attributes["asked"] != nil {
		t.Errorf("a hook's write reached another %d times, or the host: %v", seen, r.Attributes)
	}
	labeled := r
	labeled.Attributes = nil
	labeled.Labels = rbac.Label{"comp": nil}
	for i := range 60 {
		labeled.Labels["comp"] = append(labeled.Labels["comp"], fmt.Sprintf("c%02d", i))
	}
	*copies = 0
	if !allowed(t, h, u, view, labeled) || *copies > 2*3 {
		t.Errorf("a check of a resource labeled with 60 values made %d copies", *copies)
	}
	*copies = 0
	var bindings []rbac.Binding
	for i := range 20 {
		bindings = append(bindings, rbac.Binding{Role: "cluster.login", Principal: identity(fmt.Sprintf("x%02d", i))})
		h.as(t, fmt.Sprintf("x%02d", i))
	}
	if err := h.authz.Apply(t.Context(), u, cluster, rbac.Change{Grant: bindings}); err != nil {
		t.Fatal(err)
	}
	// ValidateGrant's copy of the actor's attributes, and each constraint's of them and the cluster's
	// ancestors.
	if *copies > 1+2*2 {
		t.Errorf("granting %d bindings made %d copies", len(bindings), *copies)
	}
}

// A call knows the copy it gave a hook by where what the host passed points, so it keeps what the
// host passed until it returns: dropped and collected, as a resource Config.ResourceOf made for one
// scope may be, its place can be another's, made after, which would be given the first one's copy,
// as all but 2 of 2,000 values were where the call kept none.
func TestACallGivesAHookTheCopyOfNoValueFreedSince(t *testing.T) {
	copies := rbac.CopiedInOneCall(200, func(i int) map[string]any { return map[string]any{"i": i} })
	for i, c := range copies {
		if c["i"] != i {
			t.Fatalf("value %d was given the copy of %v", i, c["i"])
		}
	}
}

// A copy counts each value as converting does, so a hook can be given a copy of whatever a check
// converts, and of no more: counting a list's elements once for the list and again as values, a
// string in a []string by the 16 bytes moving it moves, a protobuf Value's field apart from the
// Value, or a message a pointer reaches once for the pointer and again for the message, attributes
// a check converts couldn't be copied, so a constrained check of them was refused, whoever asked,
// as of a resource holding nearly 40,000 timestamps, which a check converts. Converting counts what JSON
// text and a packed message decode to as well, which a copy holds as bytes. And an array of
// interfaces costs what it holds, as a slice does: uncounted, a copy of one holding more values
// than a check converts cost one.
func TestACopyForAHookCountsWhatItHoldsAsConvertingDoes(t *testing.T) {
	type level int
	type named string
	const long = "abcdefghijklmnopqrstuvwxyz"
	stamp := func(i int) *timestamppb.Timestamp { return timestamppb.New(time.Unix(int64(i), 0)) }
	unknown := func(m proto.Message) proto.Message {
		m.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, 40)))
		return m
	}
	messages := map[string]func(i int) proto.Message{
		"a Struct": func(i int) proto.Message {
			return &structpb.Struct{Fields: map[string]*structpb.Value{long: structpb.NewNumberValue(float64(i)), "b": nil}}
		},
		"an empty Struct": func(int) proto.Message { return &structpb.Struct{} },
		"a ListValue": func(i int) proto.Message {
			return &structpb.ListValue{Values: []*structpb.Value{structpb.NewNumberValue(float64(i)), nil}}
		},
		"an empty ListValue":           func(int) proto.Message { return &structpb.ListValue{} },
		"a null Value":                 func(int) proto.Message { return structpb.NewNullValue() },
		"a number Value":               func(i int) proto.Message { return structpb.NewNumberValue(float64(i)) },
		"a string Value":               func(int) proto.Message { return structpb.NewStringValue(long) },
		"a bool Value":                 func(int) proto.Message { return structpb.NewBoolValue(true) },
		"a Struct's Value":             func(int) proto.Message { return structpb.NewStructValue(&structpb.Struct{}) },
		"a ListValue's Value":          func(int) proto.Message { return structpb.NewListValue(&structpb.ListValue{}) },
		"a Value holding a nil Struct": func(int) proto.Message { return &structpb.Value{Kind: &structpb.Value_StructValue{}} },
		"a Value of a nil kind":        func(int) proto.Message { return &structpb.Value{Kind: (*structpb.Value_ListValue)(nil)} },
		"a BoolValue":                  func(int) proto.Message { return wrapperspb.Bool(true) },
		"a BytesValue":                 func(int) proto.Message { return wrapperspb.Bytes([]byte(long)) },
		"a DoubleValue":                func(i int) proto.Message { return wrapperspb.Double(float64(i)) },
		"a FloatValue":                 func(i int) proto.Message { return wrapperspb.Float(float32(i)) },
		"an Int32Value":                func(i int) proto.Message { return wrapperspb.Int32(int32(i)) },
		"an Int64Value":                func(i int) proto.Message { return wrapperspb.Int64(int64(i)) },
		"a StringValue":                func(int) proto.Message { return wrapperspb.String(long) },
		"a UInt32Value":                func(i int) proto.Message { return wrapperspb.UInt32(uint32(i)) },
		"a UInt64Value":                func(i int) proto.Message { return wrapperspb.UInt64(uint64(i)) },
		"a Timestamp":                  func(i int) proto.Message { return stamp(i) },
		"a Duration":                   func(i int) proto.Message { return durationpb.New(time.Duration(i)) },
		"a Timestamp with fields it doesn't know": func(i int) proto.Message { return unknown(stamp(i)) },
		"a Struct with fields it doesn't know":    func(int) proto.Message { return unknown(&structpb.Struct{}) },
	}
	values := map[string]func(i int) any{
		"a bool":                         func(int) any { return true },
		"an int of the host's type":      func(i int) any { return level(i) },
		"a uint":                         func(i int) any { return uint8(i) },
		"a float":                        func(i int) any { return float32(i) },
		"a string":                       func(int) any { return strings.Repeat("s", 33) },
		"a string of the host's type":    func(int) any { return named(long) },
		"a time":                         func(i int) any { return time.Unix(int64(i), 0) },
		"a duration":                     func(i int) any { return time.Duration(i) },
		"bytes":                          func(int) any { return make([]byte, 33) },
		"an array of bytes":              func(int) any { return [33]byte{} },
		"a JSON number":                  func(int) any { return json.Number("12.5e3") },
		"nil":                            func(int) any { return nil },
		"a nil pointer":                  func(int) any { return (*int)(nil) },
		"a nil map":                      func(int) any { return map[string]any(nil) },
		"a nil list":                     func(int) any { return []any(nil) },
		"CEL's string":                   func(int) any { return types.String(long) },
		"CEL's timestamp":                func(i int) any { return types.Timestamp{Time: time.Unix(int64(i), 0)} },
		"a NullValue":                    func(int) any { return structpb.NullValue_NULL_VALUE },
		"a list":                         func(i int) any { return []any{i, long} },
		"an empty list":                  func(int) any { return make([]any, 0, 1) },
		"a list of strings":              func(int) any { return []string{long, "b"} },
		"an array":                       func(i int) any { return [2]any{i, long} },
		"an array of strings":            func(int) any { return [2]string{long, "b"} },
		"a map":                          func(i int) any { return map[string]any{long: i} },
		"an empty map":                   func(int) any { return map[string]any{} },
		"a map keyed by an interface":    func(i int) any { return map[any]any{long: i, 1: true} },
		"a map keyed by the host's type": func(i int) any { return map[named]level{long: level(i)} },
		"a map of Values":                func(i int) any { return map[string]*structpb.Value{long: structpb.NewNumberValue(float64(i))} },
		"a list of Values":               func(i int) any { return []*structpb.Value{structpb.NewNumberValue(float64(i))} },
		"a pointer":                      func(i int) any { return &i },
		"a pointer to a pointer":         func(i int) any { p := &i; return &p },
		"a pointer to a map":             func(i int) any { m := map[string]any{long: i}; return &m },
	}
	for name, made := range messages {
		values[name] = func(i int) any { return made(i) }
		// A pointer to the message, which a pointer to a pointer to it reaches.
		values["a pointer to "+name] = func(i int) any {
			m := reflect.ValueOf(made(i))
			p := reflect.New(m.Type())
			p.Elem().Set(m)
			return p.Interface()
		}
	}
	// What these decode to, converting counts and a copy doesn't.
	decoded := map[string]func(i int) any{
		"JSON text": func(int) any { return json.RawMessage(`{"a": [1, "b"]}`) },
	}
	for name, made := range messages {
		packed := func(i int) *anypb.Any {
			packed, err := anypb.New(made(i))
			if err != nil {
				t.Fatal(err)
			}
			return packed
		}
		decoded[name+" packed in an Any"] = func(i int) any { return packed(i) }
		decoded["a pointer to "+name+" packed in an Any"] = func(i int) any { p := packed(i); return &p }
	}
	listed := func(made func(i int) any, n int) map[string]any {
		l := make([]any, n)
		for i := range l {
			l[i] = made(i)
		}
		return map[string]any{"tags": l}
	}
	for name, made := range values {
		one := rbac.ConvertingWork(listed(made, 1))
		if copied := rbac.CopyingWork(listed(made, 1)); !one.Done || copied.Charged != one.Charged {
			t.Errorf("%s: converting it costs %d, read %t, and copying it %d", name, one.Charged, one.Done, copied.Charged)
		}
		// As many as a check converts.
		each := rbac.ConvertingWork(listed(made, 2)).Charged - one.Charged
		most := listed(made, int((rbac.MaxConverted-one.Charged)/each)+1)
		converted, copied := rbac.ConvertingWork(most), rbac.CopyingWork(most)
		if !converted.Done || !copied.Done || copied.Charged != converted.Charged || converted.Charged+each <= rbac.MaxConverted {
			t.Errorf("%s: as many as a check converts cost converting %d, read %t, and copying %d, copied %t", name, converted.Charged,
				converted.Done, copied.Charged, copied.Done)
		}
	}
	for name, made := range decoded {
		converted, copied := rbac.ConvertingWork(listed(made, 1)), rbac.CopyingWork(listed(made, 1))
		if !converted.Done || !copied.Done || copied.Charged >= converted.Charged {
			t.Errorf("%s: converting it costs %d, read %t, and copying it %d", name, converted.Charged, converted.Done, copied.Charged)
		}
	}
	var half [rbac.MaxConverted/2 + 1]any
	if rbac.Copies(map[string]any{"a": half, "b": half}) {
		t.Error("arrays holding more values than a check converts were copied")
	}
	// A constrained check of a resource holding as many timestamps as a check converts, as conditions
	// read them, is decided, as an unconstrained one is.
	n := int(rbac.MaxConverted-rbac.MapCost-1-rbac.ListCost) / rbac.MessageCost
	r := cluster
	r.Attributes = listed(func(i int) any { return stamp(i) }, n)
	for _, constrained := range []bool{false, true} {
		h := setup(t, func(c *rbac.Config) {
			if constrained {
				c.Constraints = []rbac.Constraint{{Name: "never", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
					return false, nil
				}}}
			}
		})
		g := grant(cluster.Scope(), "cluster.login", rbac.User, "reader")
		g.Condition = rbac.Condition{Expression: fmt.Sprintf(`size(resource.attributes.tags) == %d`, n)}
		h.seed(t, g)
		for _, id := range []string{"owner", "reader"} {
			if !allowed(t, h, h.as(t, id), login, r) {
				t.Errorf("constrained %t: %s can't log in to a cluster holding %d timestamps", constrained, id, n)
			}
		}
	}
}

// Converting and copying for a hook count alike, so a hook can be given a copy of whatever a check
// converts: values of random shapes, nesting every type both handle in one another, cost a copy
// what converting them costs, and no more where they hold JSON text or packed messages, which
// converting decodes and a copy holds as bytes, or a value reached twice, which a copy copies once
// where converting may count it again.
func TestACopyOfAnyShapeCostsWhatConvertingItDoes(t *testing.T) {
	for _, mode := range []struct {
		name             string
		decoded, sharing bool
	}{{"each value once", false, false}, {"decoded", true, false}, {"shared", false, true}, {"both", true, true}} {
		for seed := range uint64(1500) {
			d := &copyDraw{rng: mathrand.New(mathrand.NewPCG(seed, 116)), decoded: mode.decoded, sharing: mode.sharing}
			attributes := map[string]any{}
			for i := range d.rng.IntN(4) + 1 {
				attributes[fmt.Sprint("a", i)] = d.value(3)
			}
			converted, read := rbac.ConvertingCharge(attributes)
			copied, ok := rbac.CopyingCharge(attributes)
			switch {
			case !read || !ok:
				t.Errorf("%s, seed %d: read %t, copied %t", mode.name, seed, read, ok)
			case copied > converted || copied < converted && !mode.decoded && !mode.sharing:
				t.Errorf("%s, seed %d: converting costs %d and copying %d: %#v", mode.name, seed, converted, copied, attributes)
			}
		}
	}
}

// copyDraw draws values a check converts and a hook is given a copy of: every scalar, time, bytes
// and number Attributes names, CEL's own scalars, lists, arrays, maps keyed by each kind they may
// be, some of values holding more in place than one unit covers, pointers, nil ones of each, and
// every well-known message, through a pointer too, some holding fields they don't know. With
// decoded, JSON text and packed messages, and with sharing, values it drew before.
type copyDraw struct {
	rng              *mathrand.Rand
	decoded, sharing bool
	drawn            []any
}

func (d *copyDraw) text() string { return strings.Repeat("s", d.rng.IntN(45)) }

func (d *copyDraw) unknown(m proto.Message) proto.Message {
	if d.rng.IntN(4) == 0 {
		m.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, d.rng.IntN(60))))
	}
	return m
}

func (d *copyDraw) double() float64 {
	return []float64{0.5, d.rng.Float64(), math.NaN(), math.Inf(-1)}[d.rng.IntN(4)]
}

func (d *copyDraw) protoValue(depth int) *structpb.Value {
	switch k := d.rng.IntN(8); {
	case k == 0:
		return structpb.NewNullValue()
	case k == 1:
		return structpb.NewNumberValue(d.double())
	case k == 2:
		return structpb.NewStringValue(d.text())
	case k == 3:
		return structpb.NewBoolValue(true)
	case k == 4 && depth > 0:
		return structpb.NewStructValue(d.protoStruct(depth - 1))
	case k == 5 && depth > 0:
		return structpb.NewListValue(d.protoList(depth - 1))
	case k == 6:
		return []*structpb.Value{{Kind: &structpb.Value_StructValue{}}, {Kind: &structpb.Value_ListValue{}}}[d.rng.IntN(2)]
	default:
		return &structpb.Value{}
	}
}

func (d *copyDraw) protoStruct(depth int) *structpb.Struct {
	s := &structpb.Struct{Fields: map[string]*structpb.Value{}}
	for i := range d.rng.IntN(4) {
		s.Fields[fmt.Sprint(d.text(), i)] = d.protoValue(depth)
	}
	d.unknown(s)
	return s
}

func (d *copyDraw) protoList(depth int) *structpb.ListValue {
	l := &structpb.ListValue{}
	for range d.rng.IntN(4) {
		l.Values = append(l.Values, d.protoValue(depth))
	}
	d.unknown(l)
	return l
}

func (d *copyDraw) message(depth int) proto.Message {
	return []func() proto.Message{
		func() proto.Message { return d.protoStruct(depth) },
		func() proto.Message { return d.protoList(depth) },
		func() proto.Message { return d.unknown(d.protoValue(depth)) },
		func() proto.Message { return d.unknown(wrapperspb.Bool(true)) },
		func() proto.Message { return d.unknown(wrapperspb.Bytes(make([]byte, d.rng.IntN(45)))) },
		func() proto.Message { return d.unknown(wrapperspb.Double(d.double())) },
		func() proto.Message { return d.unknown(wrapperspb.Float(float32(d.double()))) },
		func() proto.Message { return d.unknown(wrapperspb.Int32(int32(d.rng.IntN(3)))) },
		func() proto.Message { return d.unknown(wrapperspb.Int64(int64(d.rng.IntN(3)))) },
		func() proto.Message { return d.unknown(wrapperspb.String(d.text())) },
		func() proto.Message { return d.unknown(wrapperspb.UInt32(uint32(d.rng.IntN(3)))) },
		func() proto.Message { return d.unknown(wrapperspb.UInt64(uint64(d.rng.IntN(3)))) },
		func() proto.Message { return d.unknown(timestamppb.New(time.Unix(int64(d.rng.IntN(1000)), 0))) },
		func() proto.Message { return d.unknown(durationpb.New(time.Duration(d.rng.IntN(1000)))) },
	}[d.rng.IntN(14)]()
}

// pointer is a pointer to v, or a nil one where v is nil.
func pointer(v any) any {
	if v == nil {
		return (*int)(nil)
	}
	p := reflect.New(reflect.TypeOf(v))
	p.Elem().Set(reflect.ValueOf(v))
	return p.Interface()
}

func (d *copyDraw) value(depth int) any {
	if d.sharing && len(d.drawn) > 0 && d.rng.IntN(6) == 0 {
		return d.drawn[d.rng.IntN(len(d.drawn))]
	}
	n := 20
	switch {
	case d.decoded:
		n = 32
	case depth > 0:
		n = 30
	}
	var v any
	switch d.rng.IntN(n) {
	case 0:
		v = []any{nil, true, d.text(), time.Unix(int64(d.rng.IntN(1000)), 0), time.Duration(d.rng.IntN(1000))}[d.rng.IntN(5)]
	case 1:
		v = []any{int8(1), int16(2), int32(3), int64(4), 5, uint8(1), uint16(2), uint32(3), uint64(4), uint(5)}[d.rng.IntN(10)]
	case 2:
		v = []any{float32(d.double()), d.double()}[d.rng.IntN(2)]
	case 3:
		type level int
		type named string
		v = []any{level(1), named(d.text())}[d.rng.IntN(2)]
	case 4:
		v = []any{json.Number("12.5e3"), json.Number("7"), structpb.NullValue_NULL_VALUE}[d.rng.IntN(3)]
	case 5:
		cels := []any{
			types.String(d.text()), types.Int(1), types.Uint(2), types.Double(d.double()), types.Bool(true),
			types.Bytes(make([]byte, d.rng.IntN(45))), types.NullValue,
			types.Timestamp{Time: time.Unix(1, 0)},
			types.Duration{Duration: time.Second},
		}
		v = cels[d.rng.IntN(len(cels))]
	case 6:
		v = []any{make([]byte, d.rng.IntN(45)), []byte(nil), [33]byte{}}[d.rng.IntN(3)]
	case 7:
		v = []any{(*int)(nil), map[string]any(nil), []any(nil), (*structpb.Struct)(nil), (*timestamppb.Timestamp)(nil)}[d.rng.IntN(5)]
	case 8, 9:
		v = d.message(1)
	case 10:
		v = pointer(d.message(1))
	case 11:
		v = []any{[3]int{1, 2, 3}, [2]string{d.text(), d.text()}, [2][2]int{}}[d.rng.IntN(3)]
	case 12:
		v = []any{[]string{d.text(), d.text()}, []int64{1, 2, 3}, make([]any, 0, 2)}[d.rng.IntN(3)]
	case 13:
		v = map[int]string{1: d.text(), 2: d.text()}
	case 14:
		v = map[bool]uint{true: 1}
	case 15:
		type key string
		v = map[key]int{key(d.text()): 1}
	case 16:
		v = map[string]*structpb.Value{d.text(): d.protoValue(1)}
	case 17:
		v = []*timestamppb.Timestamp{timestamppb.New(time.Unix(1, 0)), nil}
	case 18:
		v = []any{map[string]time.Time{d.text(): time.Unix(1, 0)}, map[string][64]int64{d.text(): {}}, map[string][64]int64{}}[d.rng.IntN(3)]
	case 19:
		v = [][]byte{make([]byte, d.rng.IntN(45))}
	case 20, 21:
		l := make([]any, d.rng.IntN(4))
		for i := range l {
			l[i] = d.value(depth - 1)
		}
		v = l
	case 22:
		v = [2]any{d.value(depth - 1), d.value(depth - 1)}
	case 23, 24:
		m := map[string]any{}
		for i := range d.rng.IntN(4) {
			m[fmt.Sprint(d.text(), i)] = d.value(depth - 1)
		}
		v = m
	case 25:
		v = map[any]any{d.text() + "k": d.value(depth - 1), 7: d.value(depth - 1), true: 1, uint(9): "x"}
	case 26, 27:
		v = pointer(d.value(depth - 1))
	case 28:
		v = []*structpb.Value{d.protoValue(depth - 1)}
	case 29:
		v = map[string][]any{d.text(): {d.value(depth - 1)}}
	case 30:
		v = json.RawMessage([]string{`{"a": [1, "b"]}`, `[]`, `{}`, `"x"`, `[[{}], {"k": []}]`}[d.rng.IntN(5)])
	default:
		packed, err := anypb.New(d.message(1))
		if err != nil {
			panic(err)
		}
		v = []any{packed, pointer(packed)}[d.rng.IntN(2)]
	}
	if k := reflect.ValueOf(v).Kind(); d.sharing && (k == reflect.Map || k == reflect.Slice || k == reflect.Pointer) {
		d.drawn = append(d.drawn, v)
	}
	return v
}

// A hook is given a copy of no more than a check converts, as copying recurses as far as what the
// host passes reaches: a check of a resource tagged a million times took 400 ms with one constraint
// that returns false, against 3 ms without, copying the tags whole. A hook that can't be given its
// copy can't be asked, so the call is refused, as one it would refuse: a check, and a change whose
// actor passes as much, which ValidateGrant can't be asked about either.
func TestAHookIsGivenACopyOfNoMoreThanACheckConverts(t *testing.T) {
	tags := map[string]any{}
	for i := range rbac.MaxConverted {
		tags[fmt.Sprint("t", i)] = "v"
	}
	if rbac.Copies(map[string]any{"tags": tags}) || !rbac.Copies(map[string]any{"tags": map[string]any{"env": "prod"}}) {
		t.Error("a copy is bounded by what a check converts")
	}
	for _, constrained := range []bool{false, true} {
		h := setup(t, func(c *rbac.Config) {
			if constrained {
				c.Constraints = []rbac.Constraint{{Name: "never", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
					return false, nil
				}}}
			}
		})
		h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "u"))
		u := h.as(t, "u")
		r := cluster
		r.Attributes = map[string]any{"tags": tags}
		if err := h.authz.Authorize(t.Context(), u, login, r); (err != nil) != constrained || constrained && !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("constrained %t: a check of a resource tagged past what a check converts: %v", constrained, err)
		}
		h.as(t, "x")
		u.Attributes = map[string]any{"tags": tags}
		change := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}
		if err := h.authz.Apply(t.Context(), u, cluster, change); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("constrained %t: a change by an actor passing past what a check converts: %v", constrained, err)
		}
	}
}

// A call refused because a hook can't be given a copy is refused as any other: a DeniedError, of
// the permission on the resource asked about, or the tenant, whose message names only the
// permission and whose Reason names the hook. Wrapping ErrDenied, its message named the constraint,
// and a user who can write a resource's tags could have any check of it show that name.
func TestARefusalForWhatAHookCantBeGivenNamesOnlyThePermission(t *testing.T) {
	tags := map[string]any{}
	for i := range rbac.MaxConverted {
		tags[fmt.Sprint("t", i)] = "v"
	}
	const name = "freeze-project-x"
	for _, constrained := range []bool{true, false} {
		h := setup(t, func(c *rbac.Config) {
			if constrained {
				c.Constraints = []rbac.Constraint{{Name: name, Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
					return false, nil
				}}}
			}
		})
		ctx := t.Context()
		h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "u"))
		h.as(t, "x")
		u := h.as(t, "u")
		tagged := cluster
		tagged.Attributes = map[string]any{"tags": tags}
		heavy := u
		heavy.Attributes = map[string]any{"tags": tags}
		hook := "ValidateGrant"
		if constrained {
			hook = fmt.Sprintf("constraint %q", name)
		}
		refused := func(what string, err error, p rbac.Permission, on rbac.Scope) {
			t.Helper()
			var denied *rbac.DeniedError
			switch {
			case !errors.As(err, &denied):
				t.Errorf("constrained %t: %s: %v, not a DeniedError", constrained, what, err)
			case denied.Permission != p || denied.Scope != on || !strings.Contains(denied.Reason, hook):
				t.Errorf("constrained %t: %s: %+v, not of %s on %s by %s", constrained, what, *denied, p, on.Key(), hook)
			case strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "ValidateGrant"):
				t.Errorf("constrained %t: %s: the message names the hook: %v", constrained, what, err)
			}
		}
		change := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}
		refused("a change by an actor passing past what a check converts", h.authz.Apply(ctx, heavy, cluster, change), grantC, cluster.Scope())
		if !constrained {
			continue
		}
		refused("a check of a resource tagged past what a check converts", h.authz.Authorize(ctx, u, login, tagged), login, cluster.Scope())
		_, err := h.authz.Reachable(ctx, heavy, login, "t1", "cluster")
		refused("a search by a subject passing past what a check converts", err, login, rbac.TenantRoot("t1"))
	}
}

// holdingItself is a Struct one of whose fields, self, holds it.
func holdingItself() *structpb.Struct {
	s := &structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewStringValue("b")}}
	s.Fields["self"] = structpb.NewStructValue(s)
	return s
}

// A hook is given a copy of a protobuf message among the attributes, as of anything else, which
// cloning it made: but cloning keeps no record of what it copied, so a message holding itself, as
// a Struct one of whose fields holds it, recursed until the stack overflowed, which ends the
// process, and one reaching another twice copied it for each path to it. The copy keeps each
// message it copies, as it keeps maps, lists and pointers, so it holds itself where the original
// does and is otherwise what cloning makes: equal, and its own, its bytes and unknown fields too,
// and each nil message a list holds a new one of its own, though each is the same nil.
func TestCopyingAMessageForAHookCopiesEachMessageItReachesOnce(t *testing.T) {
	self, shared := holdingItself(), structpb.NewStringValue("x")
	unknown := &structpb.Struct{}
	unknown.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	packed, err := anypb.New(wrapperspb.Bytes([]byte("b")))
	if err != nil {
		t.Fatal(err)
	}
	attributes := map[string]any{
		"self": self, "twice": &structpb.ListValue{Values: []*structpb.Value{shared, shared}}, "dynamic": dynamicStruct(),
		"packed": packed, "bytes": wrapperspb.Bytes([]byte("b")), "at": timestamppb.Now(), "unknown": unknown,
		"nils": &structpb.ListValue{Values: []*structpb.Value{nil, nil}},
	}
	copied := rbac.DeepCopy(attributes)
	if s, ok := copied["self"].(*structpb.Struct); !ok || s == self || s.Fields["self"].GetStructValue() != s {
		t.Error("a Struct holding itself was copied as another")
	} else if s.Fields["a"] = structpb.NewStringValue("c"); self.Fields["a"].GetStringValue() != "b" {
		t.Error("a write to the copy reached the original")
	}
	if l, ok := copied["twice"].(*structpb.ListValue); !ok || l.Values[0] != l.Values[1] || l.Values[0] == shared {
		t.Error("a value a list holds twice was copied but once")
	}
	if l, ok := copied["nils"].(*structpb.ListValue); !ok || len(l.Values) != 2 || l.Values[0] == l.Values[1] {
		t.Error("nil values a list holds were copied as one")
	}
	if d, ok := copied["dynamic"].(*dynamicpb.Message); !ok || d == attributes["dynamic"] {
		t.Error("a message of a dynamic type holding itself was copied as another")
	} else {
		fields, value := d.Descriptor().Fields().ByName("fields"), (&structpb.Value{}).ProtoReflect().Descriptor().Fields().ByName("struct_value")
		if v := d.Get(fields).Map().Get(protoreflect.ValueOfString("self").MapKey()).Message(); v.Get(value).Message().Interface() != d {
			t.Error("a copied message of a dynamic type doesn't hold itself")
		}
	}
	for _, name := range []string{"packed", "bytes", "at", "unknown"} {
		m, _ := attributes[name].(proto.Message)
		if c, ok := copied[name].(proto.Message); !ok || c == m || !proto.Equal(c, m) || len(m.ProtoReflect().GetUnknown()) != len(c.ProtoReflect().GetUnknown()) {
			t.Errorf("%s copied as %v", name, copied[name])
		}
	}
	b, _ := copied["bytes"].(*wrapperspb.BytesValue)
	if was, _ := attributes["bytes"].(*wrapperspb.BytesValue); b == nil || &b.Value[0] == &was.Value[0] {
		t.Error("the copy shares the bytes")
	}
}

// A message of a host's type that is its own reflection, as one embedding a dynamic message is, was
// copied for a hook as the dynamic message its type makes: a hook given one in an any read another
// type than the host passed, and a list, a field or a map of the host's type couldn't hold the copy,
// which panicked. It is copied as any other pointer of its type, once however it is reached, its
// message a copy of its own, and as the message its type makes only where a dynamic message's field
// holds it, which the copy of one reached first there doesn't stand for.
func TestCopyingAMessageThatIsItsOwnReflectionKeepsItsType(t *testing.T) {
	type holder struct{ M *reflecting }
	m := &reflecting{dynamicStruct()}
	value := dynamicpb.NewMessage((&structpb.Value{}).ProtoReflect().Descriptor())
	value.Set(value.Descriptor().Fields().ByName("struct_value"), protoreflect.ValueOfMessage(m))
	inside := dynamicpb.NewMessage((&structpb.Struct{}).ProtoReflect().Descriptor())
	inside.Mutable(inside.Descriptor().Fields().ByName("fields")).Map().Set(protoreflect.ValueOfString("m").MapKey(), protoreflect.ValueOfMessage(value))
	copied := rbac.DeepCopy(map[string]any{
		"one": m, "many": []*reflecting{m, m}, "field": holder{m}, "keyed": map[string]*reflecting{"m": m},
		"inside first": []any{inside, []*reflecting{m}},
	})
	one, _ := copied["one"].(*reflecting)
	if one == nil || one == m || one.Message == nil || one.Message == m.Message {
		t.Fatalf("a %T was copied as %#v", m, copied["one"])
	}
	many, _ := copied["many"].([]*reflecting)
	field, _ := copied["field"].(holder)
	keyed, _ := copied["keyed"].(map[string]*reflecting)
	first, _ := copied["inside first"].([]any)
	if len(many) != 2 || many[0] != one || many[1] != one || field.M != one || keyed["m"] != one || len(first) != 2 {
		t.Fatalf("a %T reached by many paths was copied as %#v, %#v, %#v and %#v", m, many, field, keyed, first)
	}
	if after, _ := first[1].([]*reflecting); len(after) != 1 || after[0] != one {
		t.Errorf("a %T reached after a dynamic message holding it was copied as %#v", m, first[1])
	}
	d, _ := first[0].(*dynamicpb.Message)
	if d == nil || d == inside {
		t.Fatalf("a dynamic message holding a %T was copied as %#v", m, first[0])
	}
	held := d.Get(d.Descriptor().Fields().ByName("fields")).Map().Get(protoreflect.ValueOfString("m").MapKey()).Message()
	if c := held.Get(held.Descriptor().Fields().ByName("struct_value")).Message(); !c.IsValid() || c.Interface() == m || c.Interface() == one {
		t.Errorf("a dynamic message holding a %T holds a copy %#v", m, c.Interface())
	}
}

// A message of a host's type whose type makes its own, though it promotes New from the dynamic
// message it embeds, was copied for a hook as the message New made: a hook given one in an any read
// a dynamic message, and a list, a field or a map of the host's type couldn't hold the copy, which
// panicked. It is copied as the message its type makes, once however it is reached, and an empty
// one a dynamic message's list holds as one of its type too.
func TestCopyingAMessageWhoseTypeMakesItsOwnKeepsItsType(t *testing.T) {
	type holder struct{ M *typedReflecting }
	m := &typedReflecting{dynamicStruct()}
	listed := dynamicpb.NewMessage((&structpb.ListValue{}).ProtoReflect().Descriptor())
	empty, _ := dynamicpb.NewMessageType((&structpb.Value{}).ProtoReflect().Descriptor()).Zero().(*dynamicpb.Message)
	listed.Mutable(listed.Descriptor().Fields().ByName("values")).List().Append(protoreflect.ValueOfMessage(&typedReflecting{empty}))
	var copied map[string]any
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("copying a %T panicked: %v", m, r)
			}
		}()
		copied = rbac.DeepCopy(map[string]any{
			"one": m, "many": []*typedReflecting{m}, "field": holder{m}, "keyed": map[string]*typedReflecting{"m": m}, "listed": listed,
		})
	}()
	one, _ := copied["one"].(*typedReflecting)
	many, _ := copied["many"].([]*typedReflecting)
	field, _ := copied["field"].(holder)
	keyed, _ := copied["keyed"].(map[string]*typedReflecting)
	if one == nil || one == m || one.Message == nil || one.Message == m.Message || len(many) != 1 || many[0] != one || field.M != one || keyed["m"] != one {
		t.Errorf("a %T was copied as %#v, %#v, %#v and %#v", m, copied["one"], many, field, keyed)
	}
	if l, _ := copied["listed"].(*dynamicpb.Message); l == nil || l == listed {
		t.Errorf("a dynamic message holding an empty %T was copied as %#v", m, copied["listed"])
	} else if values := l.Get(l.Descriptor().Fields().ByName("values")).List(); values.Len() != 1 {
		t.Errorf("a dynamic message holding an empty %T was copied holding %d", m, values.Len())
	} else if c, ok := values.Get(0).Message().Interface().(*typedReflecting); !ok || c.Message == empty {
		t.Errorf("an empty %T a dynamic message holds was copied as %#v", m, values.Get(0).Message().Interface())
	}
}

// A hook's copy of a host's type that is its own reflection by a generated message's it embeds
// copied protobuf's state of the message as any other value, apart from the message it lay in, so a
// hook reading the copy read past it; and one reflecting a message of a type keeping no such state
// shared the host's message, so a hook's write reached the host. Each reflection is copied as the
// reflection of a copy of the message it reflects, once however it is reached, read as the host's
// was and written apart from it.
func TestCopyingAHostTypeReflectingAGeneratedMessageCopiesTheMessage(t *testing.T) {
	at := &timestamppb.Timestamp{Seconds: 12345, Nanos: 6}
	seconds := at.ProtoReflect().Descriptor().Fields().ByName("seconds")
	wides := &wideMessages{Items: []*wideMessage{{}}}
	items := wides.ProtoReflect().Descriptor().Fields().ByName("items")
	m, w := &reflected{at.ProtoReflect()}, &reflected{wides.ProtoReflect()}
	copied := rbac.DeepCopy(map[string]any{"m": m, "many": []*reflected{m, w}, "reflection": at.ProtoReflect()})
	c, _ := copied["m"].(*reflected)
	many, _ := copied["many"].([]*reflected)
	if c == nil || c == m || c.Message == m.Message || len(many) != 2 || many[0] != c || many[1] == w || many[1].Message == w.Message {
		t.Fatalf("a %T reflecting a generated message was copied as %#v and %#v", m, copied["m"], copied["many"])
	}
	if got := c.Get(seconds).Int(); got != 12345 {
		t.Errorf("the copy of a %T reflecting a timestamp of 12,345 seconds reads %d", m, got)
	}
	if r, _ := copied["reflection"].(protoreflect.Message); r == nil || r == at.ProtoReflect() || r.Interface() != c.Message.Interface() {
		t.Errorf("a timestamp's reflection held beside a %T reflecting it was copied as %#v", m, copied["reflection"])
	}
	c.Set(seconds, protoreflect.ValueOfInt64(1))
	if l := many[1].Mutable(items).List(); l.Len() == 1 {
		l.Append(protoreflect.ValueOfMessage((&wideMessage{}).ProtoReflect()))
	} else {
		t.Errorf("the copy of a %T reflecting a message holding one item holds %d", w, l.Len())
	}
	if at.Seconds != 12345 || len(wides.Items) != 1 {
		t.Errorf("a write to the copies reached the host's messages: %v, %d items", at, len(wides.Items))
	}
}

// A constraint is given a host's type that is its own reflection by a generated message's it embeds
// as a copy of its own, which reads as the host's does, and which it writes to apart from the host.
func TestAConstraintIsGivenAHostTypeReflectingAGeneratedMessage(t *testing.T) {
	at := &timestamppb.Timestamp{Seconds: 12345}
	seconds := at.ProtoReflect().Descriptor().Fields().ByName("seconds")
	var read []int64
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "frozen", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Subject == nil {
				return false, nil
			}
			r, ok := in.Subject.Attributes["session"].(*reflected)
			if ok {
				read = append(read, r.Get(seconds).Int())
				r.Set(seconds, protoreflect.ValueOfInt64(1))
			}
			return ok, nil
		}}}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	u := h.as(t, "u")
	u.Attributes = map[string]any{"session": &reflected{at.ProtoReflect()}}
	if allowed(t, h, u, login, cluster) {
		t.Error("a constraint denying a subject holding the host's type didn't deny")
	}
	if len(read) != 1 || read[0] != 12345 || at.Seconds != 12345 {
		t.Errorf("a constraint given a timestamp of 12,345 seconds read %v, and the host's holds %d", read, at.Seconds)
	}
}

// A hook's copy copies each value in place before what it holds, as setting a value does, so one
// holding a lock, as a mutex, a WaitGroup, an atomic value or protobuf's own state does, or an
// unsafe pointer, as a reflect.Value does, or holding in a field it can't set more than setting it
// whole copies, as a pointer, a slice or another package's state, was copied so: a copy of a lock or
// of another package's state, or one sharing the host's. Each is refused, and the call with it, but
// a struct's unexported fields holding no more than setting them copies, a time among them, and the
// fields of an unexported struct it embeds, which are copied in turn.
func TestAHookCopyRefusesWhatItCantCopyInPlace(t *testing.T) {
	x := 1
	type locked struct {
		Mu sync.Mutex
		M  map[string]int
	}
	type marked struct {
		A int
		_ [0]sync.Mutex
	}
	type keyed struct {
		Mu sync.Mutex
		K  string
	}
	for name, v := range map[string]any{
		"a struct holding a mutex beside a map": locked{}, "a pointer to a mutex": &sync.Mutex{}, "a mutex": sync.Mutex{},
		"a slice of mutexes": []sync.Mutex{{}}, "an array of a struct holding a WaitGroup": [1]struct{ W sync.WaitGroup }{},
		"an atomic int": &atomic.Int64{}, "a struct marked never to be copied": marked{A: 1},
		"a map keyed by a struct holding a mutex": map[keyed]int{{K: "a"}: 1}, "a message held by value": []structpb.Value{{}},
		"a reflect.Value": reflect.ValueOf(1), "an unsafe pointer": unsafe.Pointer(&x),
		"a map keyed by a struct holding an unsafe pointer": map[struct{ P unsafe.Pointer }]int{{unsafe.Pointer(&x)}: 1},
		"a struct holding a slice it can't set":             struct{ tags []string }{[]string{"a"}},
		"a struct embedding a pointer it can't set":         struct{ *claims }{&claims{Roles: []string{"a"}}},
		"a nil message's reflection":                        struct{ R protoreflect.Message }{(*timestamppb.Timestamp)(nil).ProtoReflect()},
	} {
		if rbac.Copies(map[string]any{"v": v}) {
			t.Errorf("%s was copied", name)
		}
	}
	type padded struct {
		A int
		_ [8]byte
	}
	type unexported struct {
		n    int
		at   time.Time
		Tags []string
	}
	for name, v := range map[string]any{
		"a struct of unexported scalars and a time": unexported{n: 1, at: time.Unix(1, 0), Tags: []string{"a"}},
		"a padded struct":                                padded{A: 1},
		"a struct embedding an unexported one":           account{claims: claims{Roles: []string{"a"}}, Name: "n"},
		"a time":                                         time.Unix(1, 0),
		"a lock's interface holding none":                struct{ L sync.Locker }{},
		"empty arrays of mutexes, which conditions read": [][0]sync.Mutex{{}}, "an array of empty arrays of mutexes": [2][0]sync.Mutex{},
		// An empty array of funcs, which holds none, marks a struct only never to be compared.
		"a struct marked never to be compared": struct {
			A int
			_ [0]func()
		}{A: 1},
	} {
		if !rbac.Copies(map[string]any{"v": v}) {
			t.Errorf("%s wasn't copied", name)
		}
	}
}

// A copy finds what copying a struct or an array costs, whether it shares one, whether it can hold
// one and whether hashing one reads more than it holds in place by walking its type, once for each
// type, and none of the types an empty array would hold, as it holds none: each found for each value,
// and along each path through such arrays, copying 100 values of a type nesting two empty arrays of
// the type before it 20 deep took 19.6 s, and walking the type alone 640 ms. Copying values of a
// type nesting an empty array of the one before it 32 deep, in a slice, a map and a map's key, and
// a map of empty arrays of a type nesting arrays of one 32 deep, walks a few types, of those holding
// them, not the 32 the arrays would hold.
func TestACopyWalksNoTypeAnEmptyArrayWouldHold(t *testing.T) {
	n := freshTypes.Add(1)
	nested, deep := reflect.StructOf([]reflect.StructField{{Name: fmt.Sprint("A", n), Type: reflect.TypeFor[int]()}}), reflect.TypeFor[int]()
	var empty reflect.Type
	for range 32 {
		empty = reflect.ArrayOf(0, nested)
		nested = reflect.StructOf([]reflect.StructField{{Name: fmt.Sprint("A", n), Type: empty}, {Name: "B", Type: reflect.TypeFor[int]()}})
		deep = reflect.StructOf([]reflect.StructField{{Name: fmt.Sprint("A", n), Type: reflect.ArrayOf(1, deep)}})
	}
	key := reflect.StructOf([]reflect.StructField{{Name: "K", Type: reflect.TypeFor[int]()}, {Name: "E", Type: empty}})
	keyed := reflect.MakeMap(reflect.MapOf(key, reflect.TypeFor[int]()))
	keyed.SetMapIndex(reflect.New(key).Elem(), reflect.ValueOf(1))
	attributes := map[string]any{"l": reflect.MakeSlice(reflect.SliceOf(nested), 2, 2).Interface(), "k": keyed.Interface()}
	for name, of := range map[string]reflect.Type{"m": empty, "d": reflect.ArrayOf(0, deep)} {
		m := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), of))
		m.SetMapIndex(reflect.ValueOf("a"), reflect.New(of).Elem())
		attributes[name] = m.Interface()
	}
	walked := rbac.CountTypesWalked(t)
	if copied := rbac.Copies(attributes); !copied || *walked > 16 {
		t.Errorf("copied %t, walking %d types", copied, *walked)
	}
}

// freshTypes numbers the types a test makes that no copy has walked, each run.
var freshTypes atomic.Int64

// spinLock is a lock of the host's own: a pointer to it locks and unlocks, as one to a mutex does.
type spinLock uint32

func (*spinLock) Lock()   {}
func (*spinLock) Unlock() {}

// A hook's copy shared a channel or a func with the host where it held one but in a struct's
// unexported field: a constraint sending on its copy's channel sent on the host's, and calling its
// func ran the host's closure. And a lock of the host's own, as an integer a pointer to which spins,
// was copied alone, in an array, a slice of arrays or a map of arrays, and refused in an array of
// arrays, so every constrained call was refused, though conditions read it wherever it lay. Each,
// and an unsafe pointer, is refused wherever it lies, nil too, alone, in an array, a slice, a map's
// value or key, a struct's field, or what a pointer or an interface holds, and conditions read none
// of them, as no hook can be given them; an empty array holds none of them, and is read and copied,
// and so is the host's own integer that isn't a lock, wherever it lies, but where no condition reads
// what holds it.
func TestConvertingAndCopyingRefuseAChannelAFuncOrALockWhereverItLies(t *testing.T) {
	ch, x := make(chan int, 1), 1
	type count uint32
	// held are values holding v, each as what it is held by.
	held := func(v any) map[string]any {
		e := reflect.ValueOf(v)
		of := func(t reflect.Type) reflect.Value { return reflect.New(t).Elem() }
		array, arrays := of(reflect.ArrayOf(2, e.Type())), of(reflect.ArrayOf(2, reflect.ArrayOf(2, e.Type())))
		array.Index(1).Set(e)
		arrays.Index(1).Set(array)
		pointer, field := reflect.New(e.Type()), of(reflect.StructOf([]reflect.StructField{{Name: "V", Type: e.Type()}}))
		pointer.Elem().Set(e)
		field.Field(0).Set(e)
		slice := reflect.Append(of(reflect.SliceOf(e.Type())), e)
		valued := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), e.Type()))
		valued.SetMapIndex(reflect.ValueOf("a"), e)
		arrayed := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), array.Type()))
		arrayed.SetMapIndex(reflect.ValueOf("a"), array)
		holders := map[string]any{
			"alone": v, "in an array": array.Interface(), "in an array of arrays": arrays.Interface(), "in a slice": slice.Interface(),
			"in a map": valued.Interface(), "in a map of arrays": arrayed.Interface(), "behind a pointer": pointer.Interface(),
			"in a struct": field.Interface(), "in an interface in a list": []any{v},
		}
		if e.Type().Comparable() {
			for by, key := range map[string]reflect.Value{"as a map's key": e, "in an array as a map's key": array, "in a struct as a map's key": field} {
				keyed := reflect.MakeMap(reflect.MapOf(key.Type(), reflect.TypeFor[int]()))
				keyed.SetMapIndex(key, reflect.ValueOf(1))
				holders[by] = keyed.Interface()
			}
			holders["as a key an interface holds"] = map[any]int{v: 1}
		}
		return holders
	}
	for name, v := range map[string]any{
		"a channel": ch, "a nil channel": (chan int)(nil), "a func": func() { x++ }, "a nil func": (func())(nil),
		"a lock of the host's own": spinLock(1), "an unsafe pointer": unsafe.Pointer(&x),
	} {
		for by, attribute := range held(v) {
			attributes := map[string]any{"v": attribute, "ok": true}
			if _, evaluated := rbac.EvaluateConditionOf(t, `request.attributes.ok == true`, nil, nil, attributes); evaluated {
				t.Errorf("%s %s: a condition read its kind", name, by)
			}
			if rbac.Copies(attributes) {
				t.Errorf("%s %s: a hook was given a copy", name, by)
			}
		}
		empty := reflect.New(reflect.ArrayOf(0, reflect.TypeOf(v))).Elem().Interface()
		attributes := map[string]any{"v": empty, "ok": true}
		if held, _ := rbac.EvaluateConditionOf(t, `request.attributes.v == [] && request.attributes.ok`, nil, nil, attributes); !held || !rbac.Copies(attributes) {
			t.Errorf("an empty array of %s: read %t, copied %t", name, held, rbac.Copies(attributes))
		}
	}
	// No condition reads a struct, nor a map keyed by an array or a struct, whatever they hold.
	unread := map[string]bool{"in a struct": true, "in an array as a map's key": true, "in a struct as a map's key": true}
	for by, attribute := range held(count(1)) {
		attributes := map[string]any{"v": attribute, "ok": true}
		if held, _ := rbac.EvaluateConditionOf(t, `request.attributes.ok == true`, nil, nil, attributes); !held && !unread[by] {
			t.Errorf("the host's own integer %s: a condition couldn't read its kind", by)
		}
		if !rbac.Copies(attributes) {
			t.Errorf("the host's own integer %s: no hook was given a copy", by)
		}
	}
}

// A check asks each constraint, and a change ValidateGrant, about copies of the attributes, a
// message holding itself among them too: each is asked, rather than the process ending as copying
// it overflowed the stack.
func TestAHookIsAskedAboutAMessageHoldingItself(t *testing.T) {
	asked := map[string]bool{}
	holds := func(attributes map[string]any) bool {
		m, ok := attributes["meta"].(*structpb.Struct)
		return ok && m.Fields["self"].GetStructValue() == m
	}
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "meta", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			asked["constraint"] = asked["constraint"] || in.Resource != nil && holds(in.Resource.Attributes)
			return false, nil
		}}}
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked["ValidateGrant"] = asked["ValidateGrant"] || holds(in.Actor.Attributes)
			return validate(ctx, q, in)
		}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "alice"))
	r := cluster
	r.Attributes = map[string]any{"meta": holdingItself()}
	if !allowed(t, h, h.as(t, "alice"), login, r) {
		t.Error("a check whose resource holds a message holding itself")
	}
	owner := h.as(t, "owner")
	owner.Attributes = map[string]any{"meta": holdingItself()}
	if err := h.authz.Apply(t.Context(), owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("bob")}}}); err != nil {
		t.Fatal(err)
	}
	if !asked["constraint"] || !asked["ValidateGrant"] {
		t.Errorf("asked %v", asked)
	}
}

// A constraint is given copies of the attributes, which held a message of a host's type that is its
// own reflection as the dynamic message the type makes: one freezing a subject holding the host's
// type in an any didn't deny, and Authorize panicked out of the package copying a list of them. It
// is given them as the host's type.
func TestAConstraintIsGivenAMessageThatIsItsOwnReflectionAsTheHostsType(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "frozen", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Subject == nil {
				return false, nil
			}
			_, one := in.Subject.Attributes["one"].(*reflecting)
			many, _ := in.Subject.Attributes["many"].([]*reflecting)
			return one || len(many) > 0, nil
		}}}
	})
	owner := h.as(t, "owner")
	for name, attributes := range map[string]map[string]any{
		"in an any": {"one": &reflecting{dynamicStruct()}}, "in a list of its type": {"many": []*reflecting{{dynamicStruct()}}},
	} {
		owner.Attributes = attributes
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("checking a subject holding such a message %s panicked: %v", name, r)
				}
			}()
			if allowed(t, h, owner, login, cluster) {
				t.Errorf("a constraint freezing a subject holding such a message %s didn't deny", name)
			}
		}()
	}
}

// A hook is given copies of what the host passes, which copying recursed into as deep as it nests: a
// list nested three million deep overflowed the stack, which no recover catches, ending the process
// wherever a hook was asked about it, though no condition reads it past 10,000 deep. A copy is its
// own twice as deep as any condition reads, and a value nesting deeper isn't copied, so the call is
// refused, failing closed, rather than a hook being given its zero value there. It runs in a child
// process, on a smaller stack, which copying a list or a message nested a hundred thousand deep
// overflowed.
func TestAHookIsAskedAboutAValueNestedDeep(t *testing.T) {
	if os.Getenv("RBAC_HOOK_VALUE_NESTED_DEEP") != "" {
		debug.SetMaxStack(32 << 20)
		nested := func(n int) (any, []any) {
			var listed any = "x"
			var levels []any
			for range n {
				listed = []any{listed}
				levels = append(levels, listed)
			}
			return listed, levels
		}
		message := structpb.NewStringValue("x")
		for range 100_000 {
			message = structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{message}})
		}
		deep, _ := nested(100_000)
		for name, v := range map[string]any{"a list": deep, "a message": message} {
			if rbac.Copies(map[string]any{"v": v}) {
				t.Errorf("%s nested a hundred thousand deep was copied", name)
			}
		}
		// Twice as deep as a condition reads, its own, and whole.
		listed, levels := nested(19_990)
		copied := rbac.DeepCopy(map[string]any{"listed": listed})
		held := map[*any]int{}
		for i, l := range levels {
			if l, ok := l.([]any); ok {
				held[&l[0]] = len(levels) - i
			}
		}
		at, depth := copied["listed"], 0
		for l, _ := at.([]any); len(l) > 0; l, _ = at.([]any) {
			if deep, ok := held[&l[0]]; ok {
				t.Fatalf("a list %d deep was shared", deep)
			}
			at, depth = l[0], depth+1
		}
		if at != "x" || depth != len(levels) {
			t.Errorf("the copy of a list nested %d deep ends %d deep in %#v", len(levels), depth, at)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAHookIsAskedAboutAValueNestedDeep$")
	cmd.Env = append(os.Environ(), "RBAC_HOOK_VALUE_NESTED_DEEP=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%v\n%.2000s", err, out)
	}
}

// link is a host's value a hook reads, as a chain of approvals.
type link struct {
	Next  *link
	Value int
}

// chained is a chain of n links ending in one holding value, and its ith link.
func chained(n, i, value int) (head, ith *link) {
	head = &link{Value: value}
	for j := n - 1; j > 0; j-- {
		head = &link{Next: head}
		if j == i {
			ith = head
		}
	}
	return head, ith
}

// last is the value at the end of the chain from l.
func last(l *link) int {
	for ; l.Next != nil; l = l.Next {
	}
	return l.Value
}

// Past twice as deep as a condition reads, a hook's copy held the zero value, or the copy of a
// value it reached less deep before, as the order a map's entries came in decided: where a map held
// a chain nesting past it and, less deep, a link of the same chain, the link's copy ended in the
// chain's last value on one call and in nothing on the next, so a constraint reading it denied one
// and allowed the other. A value nesting past it along any path, wherever a value it reaches twice
// was reached first, isn't copied, in every order, and one nesting less is copied whole.
func TestAHookIsGivenAValueReachedAtTwoDepthsAlikeOnEveryCall(t *testing.T) {
	head, mid := chained(10_000, 2_500, 7)
	short, shortMid := chained(9_000, 2_500, 7)
	// Lists nested in lists, and Values in ListValues, reached less deep too.
	var listed, listedMid any = "x", nil
	for i := range 20_000 {
		if listed = []any{listed}; i == 15_000 {
			listedMid = listed
		}
	}
	valued, valuedMid := structpb.NewStringValue("x"), (*structpb.Value)(nil)
	for i := range 10_000 {
		if valued = structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{valued}}); i == 7_500 {
			valuedMid = valued
		}
	}
	for range 40 {
		for name, attributes := range map[string]map[string]any{
			"pointers": {"a": head, "b": mid}, "lists": {"a": listed, "b": listedMid}, "messages": {"a": valued, "b": valuedMid},
		} {
			if rbac.Copies(attributes) {
				t.Fatalf("a chain of %s nesting 20,000 deep, reached less deep too, was copied", name)
			}
		}
		copied := rbac.DeepCopy(map[string]any{"a": short, "b": shortMid})
		a, _ := copied["a"].(*link)
		b, _ := copied["b"].(*link)
		if a == nil || b == nil || last(a) != 7 || last(b) != 7 {
			t.Fatal("a chain nesting 18,000 deep, reached less deep too, wasn't copied whole")
		}
	}

	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "approved", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			l, _ := in.Subject.Attributes["approval"].(*link)
			return l != nil && last(l) == 7, nil
		}}}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	u := h.as(t, "u")
	u.Attributes = map[string]any{"chain": head, "approval": mid}
	for i := range 40 {
		if allowed(t, h, u, login, cluster) {
			t.Fatalf("call %d: a constraint denying the chain's last value allowed it", i)
		}
	}
}

// ringed is attributes holding, each under four names, two values each holding the other, and a
// chain of n values leading to the second of them: two links, two lists or two Structs.
func ringed(shape string, n int) map[string]any {
	var ring, chain any
	switch shape {
	case "links":
		a := &link{Value: 1}
		b := &link{Next: a, Value: 2}
		a.Next = b
		for ; n > 0; n-- {
			b = &link{Next: b}
		}
		ring, chain = a, b
	case "lists":
		a := []any{nil}
		b := []any{a}
		a[0] = b
		for ring, chain = a, b; n > 0; n-- {
			chain = []any{chain}
		}
	case "messages":
		a := &structpb.Struct{Fields: map[string]*structpb.Value{}}
		b := &structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewStructValue(a)}}
		a.Fields["b"] = structpb.NewStructValue(b)
		held := structpb.NewStructValue(b)
		for ; n > 0; n-- {
			held = structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{held}})
		}
		ring, chain = a, held
	}
	attributes := map[string]any{}
	for i := range 4 {
		attributes[fmt.Sprint("ring", i)], attributes[fmt.Sprint("chain", i)] = ring, chain
	}
	return attributes
}

// A hook's copy of a value holding itself nested as deep as the path it took around the cycle,
// which turned on where it entered it, and so on the order a map's entries came in: two links
// holding each other, beside a chain of 9,998 links to the second, were copied whole on one call
// and refused on the next, as were lists and Structs, so a constraint was asked on one call and
// the call refused on the next. One holding itself is refused where it reaches 20,000 maps, lists,
// pointers, structs, arrays and messages, counting each time it reaches one, and a message a
// pointer reaches apart from the pointer, as a path around the cycle could nest that deep in some
// order, in every order, shallow or not, and copied whole where it reaches fewer.
func TestAHookIsGivenAValueHoldingItselfAlikeOnEveryCall(t *testing.T) {
	for _, c := range []struct {
		shape string
		from  int
	}{{"links", 9_997}, {"lists", 19_996}, {"messages", 9_996}} {
		for n := c.from; n < c.from+3; n++ {
			attributes := ringed(c.shape, n)
			copies := rbac.Copies(attributes)
			for range 12 {
				if rbac.Copies(attributes) != copies {
					t.Fatalf("%s holding each other, beside a chain of %d to them, were copied on one call and refused on another", c.shape, n)
				}
			}
		}
	}
	if !rbac.Copies(ringed("links", 9_000)) {
		t.Error("links holding each other, beside a chain of 9,000, weren't copied")
	}
	// The attributes, the list holding the rest, the Struct and the message it is, each time a
	// pointer reaches it, the three Values it holds, and the list of lists and the lists it holds:
	// 20,000 for 19,992 lists, whether the copy reaches them first or last, or 19,990 where it
	// reaches the Struct twice.
	self := holdingItself()
	lists := func(n int) []any {
		l := make([]any, n)
		for i := range l {
			l[i] = []any{}
		}
		return l
	}
	for _, c := range []struct {
		name string
		held func(lists []any) []any
		past int
	}{
		{"after", func(l []any) []any { return []any{l, self} }, 19_992},
		{"before", func(l []any) []any { return []any{self, l} }, 19_992},
		{"twice before", func(l []any) []any { return []any{self, self, l} }, 19_990},
	} {
		for n := c.past - 1; n <= c.past; n++ {
			if rbac.Copies(map[string]any{"held": c.held(lists(n))}) != (n < c.past) {
				t.Errorf("a Struct holding itself %s a list of %d lists was copied %t", c.name, n, n >= c.past)
			}
		}
	}
	// Reached twice, a list or a map holds nothing of itself.
	tags, labels := []string{"a"}, map[string]any{"b": 1}
	if !rbac.Copies(map[string]any{"lists": lists(20_000), "tags": tags, "again": []any{tags, labels}, "labels": labels}) {
		t.Error("a list and a map reached twice beside a list of 20,000 lists weren't copied")
	}

	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "none", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
			return false, nil
		}}}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	u := h.as(t, "u")
	u.Attributes = ringed("links", 9_998)
	for i := range 20 {
		if allowed(t, h, u, login, cluster) {
			t.Fatalf("call %d asking a constraint about links holding each other, beside a chain of 9,998, was allowed", i)
		}
	}
}

// session is a host's type embedding a generated message, as a host wraps one to add fields.
type session struct {
	*timestamppb.Timestamp
	Frozen bool
}

type sessions struct{ Current *session }

// A constraint is given a host's type that embeds a protobuf message as that type, wherever it is
// held: cloned as the message it embeds, it would read as another type, or not fit where it is.
func TestAConstraintIsGivenAHostTypeEmbeddingAMessageAsItIs(t *testing.T) {
	frozen := func(v any) bool {
		switch v := v.(type) {
		case *session:
			return v.Frozen
		case []*session:
			return len(v) == 1 && v[0].Frozen
		case sessions:
			return v.Current.Frozen
		}
		return false
	}
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "frozen", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Subject != nil && frozen(in.Subject.Attributes["session"]), nil
		}}}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	s := &session{Timestamp: timestamppb.Now(), Frozen: true}
	for name, v := range map[string]any{"itself": s, "in a typed slice": []*session{s}, "in a struct": sessions{Current: s}} {
		u := h.as(t, "u")
		u.Attributes = map[string]any{"session": v}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: the check panicked: %v", name, r)
				}
			}()
			if allowed(t, h, u, login, cluster) {
				t.Errorf("%s: the constraint was given another type than the frozen session", name)
			}
		}()
	}
}

// envelope is a host's type embedding the message interface, so a message by the methods it
// promotes, whatever it holds.
type envelope struct {
	proto.Message
	Frozen bool
}

// A host's type embedding the message interface holding none is given as it is: asked for the
// message it holds, it panics.
func TestAConstraintIsGivenAHostTypeEmbeddingNoMessageAsItIs(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "frozen", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			e, ok := in.Subject.Attributes["envelope"].(*envelope)
			return ok && e.Frozen, nil
		}}}
	})
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	for name, m := range map[string]proto.Message{"none": nil, "a message": timestamppb.Now()} {
		u := h.as(t, "u")
		u.Attributes = map[string]any{"envelope": &envelope{Message: m, Frozen: true}}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: the check panicked: %v", name, r)
				}
			}()
			if allowed(t, h, u, login, cluster) {
				t.Errorf("%s: the constraint was given another type than the frozen envelope", name)
			}
		}()
	}
}

func TestAHostWritingToTheActorItIsAskedAboutChangesNothing(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		// A hook that fills in what it reads, as one loading the stored actor might.
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if in.Actor.Attributes != nil {
				in.Actor.Attributes["team"] = "sre"
			}
			return validate(ctx, q, in)
		}
	})
	// lead changes grants on the cluster while on the dev team, and logs in to it.
	admin := grant(cluster.Scope(), "cluster.admin", rbac.User, "lead")
	admin.Condition = rbac.Condition{Expression: `subject.attributes.team == "dev"`}
	h.seed(t, admin, grant(cluster.Scope(), "cluster.login", rbac.User, "lead"))
	lead := rbac.Subject{Principal: h.as(t, "lead").Principal, Attributes: map[string]any{"team": "dev"}}
	h.as(t, "x")
	if err := h.authz.Apply(t.Context(), lead, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("x")}}}); err != nil {
		t.Fatalf("a change whose host wrote to the actor it was asked about: %v", err)
	}
	if lead.Attributes["team"] != "dev" {
		t.Fatalf("the host wrote to the actor the change was given: %v", lead.Attributes)
	}
}

func TestFilterScalesWithResourceGrants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE fleet (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO fleet SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'workspace:w' || (i % 50), 'org:o1', 'tenant:t1']
		FROM generate_series(1, 20000) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `CREATE INDEX ON fleet USING gin (path); ANALYZE fleet`); err != nil {
		t.Fatal(err)
	}
	// A subject holding a grant on every tenth cluster, as on everything it created.
	for batch := range 2 {
		var grants []rbac.Grant
		for i := range 1000 {
			id := fmt.Sprintf("c%d", (batch*1000+i+1)*10)
			grants = append(grants, grant(rbac.Scope{Type: "cluster", ID: id}, "cluster.login", rbac.User, "creator"))
		}
		h.seed(t, grants...)
	}
	pred, err := h.authz.Filter(ctx, h.as(t, "creator"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 2000 {
		t.Fatalf("Filter found %d, %v", n, err)
	}
	rows, err := h.pool.Query(ctx, "EXPLAIN SELECT id FROM fleet WHERE "+pred.SQL+" ORDER BY id LIMIT 50", pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	hashed := strings.Join(plan, "\n")
	// A subject with a few still finds its rows through the GIN index, rather than read them all.
	h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c7"}, "cluster.login", rbac.User, "few"))
	pred, err = h.authz.Filter(ctx, h.as(t, "few"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 1 {
		t.Fatalf("Filter found %d, %v", n, err)
	}
	rows, err = h.pool.Query(ctx, "EXPLAIN SELECT count(*) FROM fleet WHERE "+pred.SQL, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	if plan, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(plan, "\n")
	if !strings.Contains(text, "Bitmap Index Scan") {
		t.Fatalf("Filter's plan for a subject with one resource grant:\n%s", text)
	}
	// Each row's own key is looked up in a hash of the subject's grants, not compared with each:
	// one hashed subquery more than for a subject with one, whose plan hashes the denies on clusters.
	if strings.Count(hashed, "hashed SubPlan") <= strings.Count(text, "hashed SubPlan") {
		t.Fatalf("Filter's plan for a subject with many resource grants:\n%s", hashed)
	}
}

// The tenant's grants are on the one scope a row of it has, so with no container types there is
// nothing above it for Filter to overlap, however many grants the subject holds there.
func TestFilterListsTheTenantWithoutContainers(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.ContainerTypes = nil })
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE tenants (tenant text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	root := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	if _, err := h.pool.Exec(ctx, `INSERT INTO tenants VALUES ($1, $2)`, root.Tenant, h.path(t, root)); err != nil {
		t.Fatal(err)
	}
	var groups []string
	var grants []rbac.Grant
	for i := range 9 {
		g := fmt.Sprintf("g%d", i)
		groups = append(groups, g)
		grants = append(grants, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.Group, g))
	}
	h.seed(t, grants...)
	s := h.as(t, "u", groups...)
	pred, err := h.authz.Filter(ctx, s, "tenant:view", "t1", rbac.TenantScope, rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, "SELECT count(*) FROM tenants WHERE "+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 1 {
		t.Fatalf("Filter found %d, %v", n, err)
	}
	if !allowed(t, h, s, "tenant:view", root) {
		t.Fatal("Authorize should agree")
	}
}

func TestConditionsReadWhatIsDeclared(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.Attributes = rbac.Attributes{
			Resource: map[string]rbac.AttributeType{"env": rbac.AttrString, "size": rbac.AttrInt, "labels": rbac.AttrStringMap, "tags": rbac.AttrStrings},
			Request:  map[string]rbac.AttributeType{"mfa": rbac.AttrBool, "at": rbac.AttrTimestamp, "age": rbac.AttrDuration, "score": rbac.AttrDouble},
		}
	})
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for _, expr := range []string{
		`resource.attributes.env == "dev"`,
		`has(resource.attributes.env) && resource.attributes.size > 2`,
		`resource.attributes.labels["team"] == "core" && "gpu" in resource.attributes.tags`,
		`request.attributes.mfa && request.attributes.at < request.time + request.attributes.age && request.attributes.score > 0.5`,
		// Subject attributes aren't declared, so any is read.
		`subject.attributes.department == "eng" && resource.type == "cluster" && action == "cluster:login"`,
	} {
		ok := b
		ok.Condition.Expression = expr
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{ok}}); err != nil {
			t.Errorf("%s: %v", expr, err)
		}
	}
	for _, expr := range []string{
		`resource.attributes.envv == "dev"`,
		`resource.attributes.size == "big"`,
		`resource.attributes["env"] == "dev"`,
		`resource.lables == "dev"`,
		`request.attributes.mfa == "yes"`,
		`request.attributes.ip == "10.0.0.1"`,
	} {
		bad := b
		bad.Condition.Expression = expr
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{bad}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", expr, err)
		}
	}
	// Declared, an attribute is still read from the request as passed.
	dev := cluster
	dev.Attributes = map[string]any{"env": "dev"}
	if !allowed(t, h, h.as(t, "u"), login, dev) || allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("a declared attribute should decide as passed, and one not passed fail")
	}
	// Denies and requirements are checked alike.
	guarded := rbac.Deny{
		ID: "d", Principals: []rbac.Principal{{Kind: rbac.Public}}, Permissions: []rbac.Permission{root},
		Condition: rbac.Condition{Expression: `resource.attributes.enviroment == "prod"`},
	}
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	if err := h.authz.SetDeny(ctx, h.as(t, "owner"), cluster, guarded); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a deny reading an undeclared attribute: %v", err)
	}
	e := rbac.Eligibility{
		Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour,
		Requires: `request.attributes.mfaa == true`,
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a requirement reading an undeclared attribute: %v", err)
	}
}

func TestNewRejectsBadAttributes(t *testing.T) {
	h := setup(t)
	for name, attrs := range map[string]rbac.Attributes{
		"a name with a dash": {Resource: map[string]rbac.AttributeType{"cost-center": rbac.AttrString}},
		"a reserved word":    {Request: map[string]rbac.AttributeType{"in": rbac.AttrBool}},
		"an unknown type":    {Subject: map[string]rbac.AttributeType{"level": "integer"}},
	} {
		if _, err := rbac.New(h.pool, rbac.Config{Catalog: catalog, ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil }, Attributes: attrs}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestDeniesNameWhatTheCatalogHas(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"))
	for _, p := range []rbac.Permission{"cluster:logn", "clustr:*", "bucket:read"} {
		d := rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.Public}}, Permissions: []rbac.Permission{p}}
		if err := h.authz.SetDeny(t.Context(), h.as(t, "owner"), cluster, d); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a deny of %s: %v", p, err)
		}
	}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.Public}}, Permissions: []rbac.Permission{"cluster:*", "workspace:view"}}
	if err := h.authz.SetDeny(t.Context(), h.as(t, "owner"), cluster, d); err != nil {
		t.Fatal(err)
	}
}

func TestADenyNamesOnlyKindsTheHostDeclares(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
	})
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "guardian"), grant(cluster.Scope(), "cluster.login", "service_account", "sa"))
	guardian := h.as(t, "guardian")
	sa := h.member(t, rbac.Principal{Kind: "service_account", ID: "sa"})
	typo := rbac.Principal{Kind: "service_acount", ID: "sa"}
	for name, d := range map[string]rbac.Deny{
		"naming":    {ID: "d", Principals: []rbac.Principal{typo}, Permissions: []rbac.Permission{login}},
		"exempting": {ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{typo}, Permissions: []rbac.Permission{login}},
	} {
		if err := h.authz.SetDeny(ctx, guardian, cluster, d); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a deny %s a kind the host doesn't declare: %v", name, err)
		}
	}
	if ds, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil || len(ds) != 0 {
		t.Fatalf("Denies = %+v, %v", ds, err)
	}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{sa.Principal}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, sa, login, cluster) {
		t.Fatal("a deny naming a declared kind binds it")
	}
}

func TestChangesAreBounded(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	many := func(n int) []rbac.Binding {
		bs := make([]rbac.Binding, n)
		for i := range bs {
			bs[i] = rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: fmt.Sprintf("u%d", i)}}
		}
		return bs
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: many(rbac.MaxBindings), Revoke: many(1)}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a change past the limit: %v", err)
	}
	imports := make([]rbac.Grant, rbac.MaxBindings+1)
	for i, b := range many(len(imports)) {
		imports[i] = rbac.Grant{Scope: cluster.Scope(), Binding: b}
	}
	if err := h.authz.Import(ctx, host, "t1", imports); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an import past the limit: %v", err)
	}
	// A change to more principals than it locks one by one locks the tenant instead, rather than
	// fill the lock table every session shares.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: many(200)}); err != nil {
		t.Fatal(err)
	}
	var locks int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()`).Scan(&locks); err != nil {
		t.Fatal(err)
	}
	if locks > 2 {
		t.Fatalf("a change to 200 principals holds %d advisory locks", locks)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Holders lists those that are members, the owner and the 200 once they join.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id)
		SELECT 't1', 'user', 'u' || i FROM generate_series(0, 199) AS i`); err != nil {
		t.Fatal(err)
	}
	if holders, err := h.authz.Holders(ctx, login, cluster); err != nil || len(holders) != 201 {
		t.Fatalf("Holders = %d, %v", len(holders), err)
	}
}

func TestAPrincipalHoldsARoleABoundedNumberOfTimes(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	until := func(from, n int) []rbac.Binding {
		bs := make([]rbac.Binding, n)
		for i := range bs {
			bs[i] = rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, ExpiresAt: h.now.Add(time.Duration(from+i+1) * time.Hour)}
		}
		return bs
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: until(0, rbac.MaxGrantsPerRole)}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: until(rbac.MaxGrantsPerRole, 1)}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a grant past the limit: %v", err)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: until(rbac.MaxGrantsPerRole, 1)[0]}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an import past the limit: %v", err)
	}
	e := rbac.Eligibility{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(ctx, h.as(t, "u"), cluster, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "x"}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an activation past the limit: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != rbac.MaxGrantsPerRole {
		t.Fatalf("Grants = %d, %v", len(got), err)
	}
	// Granting one held again stays possible at the limit.
	again := until(0, 1)[0]
	again.Note = "renewed"
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{again}}); err != nil {
		t.Fatalf("a new note at the limit: %v", err)
	}
	// Grants that have ended don't count.
	h.now = h.now.Add(time.Duration(rbac.MaxGrantsPerRole) * time.Hour)
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: until(0, 1)}); err != nil {
		t.Fatalf("a grant once the others ended: %v", err)
	}
}

// The locks of two tenants never meet, though an id may hold '/': a change in one never waits for
// a change in another.
func TestChangesInTwoTenantsNeverShareALock(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// In tenant acme, the lock of user x/group:g, which joined its tenant's and its id would name
	// tenant acme/user:x's lock of group g.
	if err := h.authz.WithTx(tx).SetMemberships(ctx, host, "acme", []rbac.Membership{{Principal: identity("x/group:g")}}); err != nil {
		t.Fatal(err)
	}
	other, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	if _, err := other.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(other).DeletePrincipal(ctx, host, "acme/user:x", groupOf("g")); err != nil {
		t.Errorf("a change in tenant acme/user:x waited for one in tenant acme: %v", err)
	}
}

// A change reaching the tables through a search_path that names another schema first takes the
// same locks as one that names theirs alone, so it waits for them: two imports that each fill half
// the bound on a role's grants can't both commit past it.
func TestChangesThroughAnotherSearchPathWaitForTheSameLocks(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// A schema of the host's own, first in the other pool's search_path, holding none of the tables.
	other := schema + "_host"
	if _, err := h.pool.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{other}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+pgx.Identifier{other}.Sanitize()+` CASCADE`)
	})
	cfg, err := pgxpool.ParseConfig(os.Getenv(pgtest.URLEnv))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{other}.Sanitize() + ", " + pgx.Identifier{schema}.Sanitize()
	cfg.ConnConfig.RuntimeParams["application_name"] = other
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	elsewhere, err := rbac.New(pool, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.as(t, "u")
	half := func(from int) []rbac.Grant {
		gs := make([]rbac.Grant, rbac.MaxGrantsPerRole/2+1)
		for i := range gs {
			gs[i] = grant(cluster.Scope(), "cluster.login", rbac.User, "u")
			gs[i].ExpiresAt = h.now.Add(time.Duration(from+i+1) * time.Hour)
		}
		return gs
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).Import(ctx, host, "t1", half(0)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- elsewhere.Import(ctx, host, "t1", half(100)) }()
	// Commit once the other import has finished or waits on a lock.
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			done <- err
			waiting = true
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity
				WHERE application_name = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory')`, other).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("the other import, past the bound once the first committed: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) > rbac.MaxGrantsPerRole {
		t.Fatalf("u holds cluster.login %d times: %v", len(got), err)
	}
}

// craftedGroup is a group id crafted, by inverting the last block of PostgreSQL's
// hashtextextended, which keyed the locks before, so that the key it gave the group's lock in
// tenant t1 was tenant t2's own, for tables in a schema named public.
const craftedGroup = "aaaaaLmKAMirG.F0/"

// A tenant's admin naming a group for another tenant's lock holds no change there back while it
// changes the group: a lock's key is its name's SHA-256, which no id is found to match.
func TestAGroupNamedForAnotherTenantsLockHoldsNoChangeThereBack(t *testing.T) {
	ctx := t.Context()
	// In a database of the test's own, as the key named the schema, whose name the id was crafted for.
	_, database := pgtest.Database(t, "TEMPLATE template0")
	cfg, err := pgxpool.ParseConfig(database)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h := groupedOn(t, pool)
	var collided bool
	if err := pool.QueryRow(ctx, `SELECT hashtextextended($1, 0) = hashtextextended($2, 0)`,
		"6:public/rbac/scope/2:t1/group:"+craftedGroup, "6:public/rbac/tenant/2:t2/").Scan(&collided); err != nil || !collided {
		t.Fatalf("the group's old key isn't t2's: %v", err)
	}
	admin := h.as(t, "groups")
	if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: craftedGroup}); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: craftedGroup, Name: "renamed"}); err != nil {
		t.Fatal(err)
	}
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(ctx) }()
	if _, err := other.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(other).SetMemberships(ctx, host, "t2", []rbac.Membership{{Principal: identity("someone")}}); err != nil {
		t.Errorf("a change in t2 waited for t1's admin changing group %q: %v", craftedGroup, err)
	}
}

// Locks of different names have different keys: a name gives the schema and the tenant each with
// its length, so no two names are one text split otherwise between the schema, the kind, the
// tenant and the key, and a key is the first 8 bytes of its name's SHA-256.
func TestLocksOfDifferentNamesHaveDifferentKeys(t *testing.T) {
	type name struct{ schema, kind, tenant, key string }
	seen := map[int64]name{}
	check := func(n name) {
		t.Helper()
		k := rbac.LockKey(n.schema, n.kind, n.tenant, n.key)
		if other, ok := seen[k]; ok && other != n {
			t.Fatalf("%+v and %+v have the key %d", n, other, k)
		}
		seen[k] = n
	}
	for _, n := range []name{
		// A group id crafted so that hashtextextended keyed its lock as another tenant's own, in the
		// schema it was crafted for, and that tenant's lock.
		{"public", "scope", "t1", "group:" + craftedGroup},
		{"public", "tenant", "t2", ""},
		// Migrate's lock named the schema without its length, so one schema's could be another's
		// scope lock, as a schema's name holding another's lock name would be without it.
		{"3:abc/rbac/scope/2:t2/rbac:x", "migrate", "", ""},
		{"abc", "scope", "t2", "rbac:x/rbac/migrate"},
		{"a/rbac/tenant/0:/x", "scope", "", ""},
		{"a", "tenant", "", "x/rbac/scope/0:/"},
		{"", "migrate", "", ""},
		{"", "tenant", "", ""},
		{"", "exclusive", "", ""},
	} {
		check(n)
	}
	kinds := []string{"tenant", "exclusive", "nesting", "scope", "principal", "migrate"}
	rng := mathrand.New(mathrand.NewPCG(1, 2))
	text := func() string {
		b := make([]byte, rng.IntN(7))
		for i := range b {
			b[i] = "a1:/"[rng.IntN(4)]
		}
		return string(b)
	}
	for range 20000 {
		n := name{text(), kinds[rng.IntN(len(kinds))], text(), text()}
		check(name{n.schema, kinds[rng.IntN(len(kinds))], n.tenant, n.key})
		// The same text split at each byte between the tenant and the key, and between the schema
		// and the tenant, which only the lengths tell apart.
		for joined, i := n.tenant+n.key, 0; i <= len(joined); i++ {
			check(name{n.schema, n.kind, joined[:i], joined[i:]})
		}
		for joined, i := n.schema+n.tenant, 0; i <= len(joined); i++ {
			check(name{joined[:i], n.kind, joined[i:], n.key})
		}
	}
}

// A lock no key names, a tenant's own, its exclusive values', its nesting's or Migrate's, takes its
// key as two int4 keys, and a scope's or a principal's as one bigint key, which PostgreSQL holds
// apart: so a scope or a principal whose bigint key no hash keeps from being a tenant's, as one an
// actor names to match it, holds none of that tenant's changes back. A session holding each lock's
// 64 bits in the other form holds back nothing, and in its own form, what takes it.
func TestATenantsOwnLocksMeetNoLockOfAKey(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	change := func(tx pgx.Tx) error {
		return h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")})
	}
	migrate := func(tx pgx.Tx) error { return rbac.Migrate(ctx, tx) }
	// Deleting groups takes the nesting lock, as nesting one does.
	nesting := func(tx pgx.Tx) error { return h.authz.WithTx(tx).DeleteGroups(ctx, host, "t1", []string{"g"}) }
	for _, c := range []struct {
		lock   string
		key    int64
		bigint bool
		run    func(pgx.Tx) error
	}{
		{"the tenant's", rbac.LockKey(schema, "tenant", "t1", ""), false, change},
		{"its exclusive values'", rbac.LockKey(schema, "exclusive", "t1", ""), false, change},
		{"its nesting's", rbac.LockKey(schema, "nesting", "t1", ""), false, nesting},
		{"Migrate's", rbac.LockKey(schema, "migrate", "", ""), false, migrate},
		{"a scope's", rbac.LockKey(schema, "scope", "t1", cluster.Scope().Key()), true, change},
		{"a principal's", rbac.LockKey(schema, "principal", "t1", "user:u"), true, change},
	} {
		for _, bigint := range []bool{true, false} {
			holder, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if bigint {
				_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, c.key)
			} else {
				_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int4, $2::int4)`, int32(c.key>>32), int32(c.key))
			}
			if err != nil {
				t.Fatal(err)
			}
			waits, wait, as := bigint == c.bigint, "1s", "two int4s"
			if waits {
				wait = "100ms"
			}
			if bigint {
				as = "one bigint"
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, wait); err != nil {
				t.Fatal(err)
			}
			err = c.run(tx)
			_, _ = tx.Rollback(ctx), holder.Rollback(ctx)
			switch {
			case waits && !errors.Is(err, rbac.ErrConflict):
				t.Errorf("%s lock's key held as %s didn't hold back what takes it: %v", c.lock, as, err)
			case !waits && err != nil:
				t.Errorf("%s lock's key held as %s held back what takes it: %v", c.lock, as, err)
			}
		}
	}
}

// A change to the tables of one schema takes no lock named for another's, as another
// application's, though the process's last change took its locks there: it reads where the tables
// are as it takes them, and takes all of its own.
func TestChangesInTwoSchemasNeverShareALock(t *testing.T) {
	first, second := setup(t), setup(t)
	ctx := t.Context()
	member := []rbac.Membership{{Principal: identity("u")}}
	held, err := first.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Rollback(ctx) }()
	if err := first.authz.WithTx(held).SetMemberships(ctx, host, "t1", member); err != nil {
		t.Fatal(err)
	}
	tx, err := second.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`); err != nil {
		t.Fatal(err)
	}
	if err := second.authz.WithTx(tx).SetMemberships(ctx, host, "t1", member); err != nil {
		t.Fatalf("a change to the second schema's tables waited for one to the first's: %v", err)
	}
	keys := func(h *harness) map[int64]int16 {
		var schema string
		if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
			t.Fatal(err)
		}
		return map[int64]int16{rbac.LockKey(schema, "tenant", "t1", ""): 2, rbac.LockKey(schema, "principal", "t1", "user:u"): 1}
	}
	if got, want := advisoryHeld(t, tx), keys(second); !maps.Equal(got, want) {
		t.Errorf("the second schema's change holds %v, not its own %v (the first's are %v)", got, want, keys(first))
	}
}

// advisoryHeld is each advisory lock tx holds, by its 64 bits, and whether it takes them as one
// bigint (1) or two int4s (2).
func advisoryHeld(t *testing.T, tx pgx.Tx) map[int64]int16 {
	t.Helper()
	rows, err := tx.Query(t.Context(), `SELECT classid, objid, objsubid FROM pg_locks
		WHERE locktype = 'advisory' AND granted AND pid = pg_backend_pid()`)
	if err != nil {
		t.Fatal(err)
	}
	held := map[int64]int16{}
	var high, low uint32
	var form int16
	if _, err := pgx.ForEachRow(rows, []any{&high, &low, &form}, func() error {
		held[int64(uint64(high)<<32|uint64(low))] = form
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return held
}

// A change whose locks are keyed for the schema the process's last were taken in takes every one,
// though the schema is renamed while it waits for one of them: the statements after that wait find
// the tables in a schema of another name and take none, so it takes them all again, named by the
// schema its batch read first, rather than go on without them.
func TestAChangeTakesEveryLockThoughItsSchemaIsRenamedAsItWaits(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	scopes, principals := []string{cluster.Scope().Key()}, []string{"user:u"}
	// So the process's last locks were taken in this schema.
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error { return rbac.Lock(ctx, tx, "t1", scopes, principals) }); err != nil {
		t.Fatal(err)
	}
	holder, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1::bigint)`, rbac.LockKey(schema, "scope", "t1", scopes[0])); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid() FROM set_config('lock_timeout', '5s', true)`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- rbac.Lock(ctx, tx, "t1", scopes, principals) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("the change didn't wait for the scope's lock: %v", err)
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity
				WHERE pid = $1 AND wait_event_type = 'Lock' AND wait_event = 'advisory')`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	rename := func(from, to string) error {
		ctx := context.WithoutCancel(ctx)
		return pgx.BeginFunc(ctx, h.pool, func(admin pgx.Tx) error {
			_, err := admin.Exec(ctx, `SET LOCAL lock_timeout = '1s'; ALTER SCHEMA `+pgx.Identifier{from}.Sanitize()+` RENAME TO `+pgx.Identifier{to}.Sanitize())
			return err
		})
	}
	renamed := schema + "_renamed"
	if err := rename(schema, renamed); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rename(renamed, schema); err != nil {
			t.Error(err)
		}
	}()
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := map[int64]int16{
		rbac.LockKey(schema, "tenant", "t1", ""):               2,
		rbac.LockKey(schema, "scope", "t1", scopes[0]):         1,
		rbac.LockKey(schema, "principal", "t1", principals[0]): 1,
	}
	got := advisoryHeld(t, tx)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, want) {
		t.Errorf("the change holds %v, not every lock of its own %v", got, want)
	}
}

func TestTrustedWritesNameTheirActor(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	for name, actor := range map[string]rbac.Principal{
		"no one":             {},
		"a group":            {Kind: rbac.Group, ID: "g"},
		"the public":         {Kind: rbac.Public},
		"an undeclared kind": {Kind: "robot", ID: "r"},
	} {
		if err := h.authz.Import(ctx, actor, "t1", []rbac.Grant{g}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Import as %s: %v", name, err)
		}
		if err := h.authz.DeleteScope(ctx, actor, "t1", cluster.Scope()); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteScope as %s: %v", name, err)
		}
		if err := h.authz.DeletePrincipalEverywhere(ctx, actor, g.Principal); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeletePrincipalEverywhere as %s: %v", name, err)
		}
	}
	h.events = nil
	h.seed(t, g)
	got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{g.Principal}})
	if err != nil || len(got) != 1 || got[0].CreatedBy != host || len(h.events) != 1 || h.events[0].Actor != host {
		t.Fatalf("an imported grant should name its actor: %+v, %+v, %v", got, h.events, err)
	}
	h.events = nil
	if err := h.authz.DeletePrincipal(ctx, host, "t1", g.Principal); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || h.events[0].Actor != host || len(h.events[0].Revoked) != 1 {
		t.Fatalf("a delete should name its actor: %+v", h.events)
	}
}

func TestApplyRespectsConstraints(t *testing.T) {
	h := setup(t, constrain("managed elsewhere", grantC))
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "admin"))
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for _, actor := range []string{"admin", "owner"} {
		if err := h.authz.Apply(t.Context(), h.as(t, actor), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s changed access that a constraint removes: %v", actor, err)
		}
	}
}

func TestImportKeepsTheLastOfRepeatedGrants(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	again, later := g, g
	again.Note = "the last"
	later.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g, again, later)
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Principals: []rbac.Principal{g.Principal}})
	if err != nil || len(got) != 2 || got[0].Note != "the last" || !got[1].ExpiresAt.Equal(later.ExpiresAt) {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestNewCopiesTheCatalog(t *testing.T) {
	roles := slices.Clone(catalog)
	roles[2].Permissions = slices.Clone(roles[2].Permissions)
	h := setup(t, func(c *rbac.Config) { c.Catalog = roles })
	// In place, as a caller sharing the slice would.
	roles[2].Permissions[0] = root
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	reach, err := h.authz.Reachable(t.Context(), h.as(t, "u"), root, "t1", "cluster")
	if err != nil || len(reach.Scopes) != 0 {
		t.Fatalf("changing the catalog after New reached %+v, %v", reach, err)
	}
	if got := h.authz.BuiltinRoles("cluster"); len(got) != 3 || slices.Contains(got[2].Permissions, root) {
		t.Fatalf("Roles(cluster) = %+v", got)
	}
	if got := h.authz.BuiltinRoles("workspace"); len(got) != len(catalog) {
		t.Fatalf("every role can be granted on a container, Roles(workspace) = %d", len(got))
	}
}

func TestApplyIsIdempotentAndReportsOnlyChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for range 2 {
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.events) != 1 || len(h.events[0].Granted) != 1 || h.events[0].Actor != (rbac.Principal{Kind: rbac.User, ID: "owner"}) {
		t.Fatalf("events = %+v", h.events)
	}
	b.ExpiresAt = h.now.Add(time.Hour)
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || !h.events[1].Granted[0].ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatalf("a new expiry should be reported: %+v", h.events)
	}
}

// colliding is setup on a pool whose statements find hashtextextended in the test's schema before
// PostgreSQL's, where it gives a text's length: the key index on grants, made with it, tells no
// two conditions of one length apart, as it can't two whose hashes collide.
func colliding(t *testing.T) *harness {
	t.Helper()
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	var schema string
	if err := pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION hashtextextended(text, bigint) RETURNS bigint
		LANGUAGE sql IMMUTABLE PARALLEL SAFE RETURN pg_catalog.length($1)`); err != nil {
		t.Fatal(err)
	}
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{schema}.Sanitize() + ", pg_catalog"
	shadowed, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(shadowed.Close)
	return setupOn(t, shadowed)
}

// Two grants of one role to one principal on one scope, from one source until one time, whose
// conditions differ but share the length and hash the store tells grants apart by, can't stand
// side by side: granting one beside the other stored, or both at once, is refused as invalid,
// never made as nothing or failed as the store's error, while granting one again as it is stored,
// or one whose condition is of another length, is made.
func TestAGrantWhoseConditionTheStoreCantTellFromAnothersIsInvalid(t *testing.T) {
	h := colliding(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	on := func(condition string) rbac.Binding {
		return rbac.Binding{Role: "cluster.login", Principal: identity("u"), Condition: rbac.Condition{Expression: condition}}
	}
	sre, dev := on(`subject.attributes.team == "sre"`), on(`subject.attributes.team == "dev"`)
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{sre}}); err != nil {
		t.Fatal(err)
	}
	invalid := func(what string, err error, of rbac.Principal) {
		t.Helper()
		var bad *rbac.InvalidError
		if !errors.As(err, &bad) || bad.Binding.Principal != of || !strings.Contains(bad.Reason, "length and hash") {
			t.Errorf("%s: %v", what, err)
		}
	}
	invalid("granting one beside the other stored", h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{dev}}), dev.Principal)
	invalid("importing one beside the other stored", h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: dev}}), dev.Principal)
	v := func(b rbac.Binding) rbac.Binding {
		b.Principal = identity("v")
		return b
	}
	invalid("granting both at once", h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{v(dev), v(sre)}}), identity("v"))
	h.events = nil
	sre.Note = "again"
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{sre}}); err != nil || len(h.events) != 1 {
		t.Errorf("granting one again with a new note: %v, %+v", err, h.events)
	}
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{sre}}); err != nil || len(h.events) != 1 {
		t.Errorf("granting one again as it is stored: %v, %+v", err, h.events)
	}
	longer := on(`subject.attributes.team == "infra"`)
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{longer}}); err != nil {
		t.Errorf("granting one of another length: %v", err)
	}
	grants, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("u"), identity("v")}})
	if err != nil {
		t.Fatal(err)
	}
	var conditions []string
	for _, g := range grants {
		conditions = append(conditions, g.Principal.ID+" "+g.Condition.Expression)
	}
	slices.Sort(conditions)
	if want := []string{"u " + longer.Condition.Expression, "u " + sre.Condition.Expression}; !slices.Equal(conditions, want) {
		t.Errorf("the grants are %q, not %q", conditions, want)
	}
}

func TestOnChangeErrorRollsBack(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error { return errors.New("audit down") }
	})
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err == nil {
		t.Fatal("the hook's error should fail the change")
	}
	if allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("a change whose audit failed must not be stored")
	}
}

func TestWithTxCommitsWithTheHost(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for _, commit := range []bool{false, true} {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.authz.WithTx(tx).Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
			t.Fatal(err)
		}
		if commit {
			err = tx.Commit(ctx)
		} else {
			err = tx.Rollback(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		if got := allowed(t, h, h.as(t, "u"), login, cluster); got != commit {
			t.Fatalf("commit=%v: grant present=%v", commit, got)
		}
	}
}

func TestHooksSeeTheHostsTransaction(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			p := in.Binding.Principal
			var member bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM members WHERE id = $1)`, p.ID).Scan(&member); err != nil {
				return err
			}
			if !member {
				return rbac.ErrInvalid
			}
			return nil
		}
	})
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE members (id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO members VALUES ('new')`); err != nil {
		t.Fatal(err)
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "new"}}
	if err := h.authz.WithTx(tx).Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("granting a member added earlier in the transaction: %v", err)
	}
}

func TestGrantsAndDeletes(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.seed(t,
		grant(cluster.Scope(), "cluster.login", rbac.User, "u"),
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.sudo", rbac.Group, "g"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "v"),
	)
	got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope(), {Type: "workspace", ID: "w1"}}})
	if err != nil || len(got) != 3 {
		t.Fatalf("by scope: %v, %v", got, err)
	}
	got, err = h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.Group, ID: "g"}}})
	if err != nil || len(got) != 1 || got[0].Role != "cluster.sudo" {
		t.Fatalf("by principal: %v, %v", got, err)
	}
	if _, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatal("an unfiltered listing should be refused")
	}

	h.events = nil
	if err := h.authz.DeletePrincipal(ctx, host, "t1", rbac.Principal{Kind: rbac.Group, ID: "g"}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteScope(ctx, host, "t1", cluster.Scope()); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || len(h.events[0].Revoked) != 1 || len(h.events[1].Revoked) != 2 {
		t.Fatalf("deletes should report what they removed: %+v", h.events)
	}
	if err := h.authz.DeleteTenant(ctx, host, "t1"); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "v"), login, cluster) {
		t.Fatal("a deleted tenant's grants should be gone")
	}
}

func TestMigrateIsRepeatable(t *testing.T) {
	h := setup(t)
	if err := rbac.Migrate(t.Context(), h.pool); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateNeedsASchema(t *testing.T) {
	pool := pgtest.Open(t, "pool_max_conns=1")
	if _, err := pool.Exec(t.Context(), `SET search_path = rbac_no_such_schema`); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(t.Context(), pool); err == nil || !strings.Contains(err.Error(), "no schema in the search_path") {
		t.Fatalf("migrating where the search_path names no schema that exists: %v", err)
	}
}

// A database that isn't UTF8 can hold text that isn't UTF-8, which history would record and no
// export could chain.
func TestMigrateNeedsUTF8(t *testing.T) {
	_, database := pgtest.Database(t, "TEMPLATE template0 ENCODING 'SQL_ASCII' LOCALE 'C'")
	pool := pgtest.OpenIn(t, database, "")
	if err := rbac.Migrate(t.Context(), pool); err == nil || !strings.Contains(err.Error(), "UTF8") {
		t.Fatalf("migrating a database encoded as SQL_ASCII: %v", err)
	}
}

// A session whose standard_conforming_strings is off reads a backslash in a literal as an escape:
// the tables migrated there, by Migrate or by a host's own tool, check what they check with it on.
func TestMigratingMeansTheSameWhateverStandardConformingStrings(t *testing.T) {
	ctx := t.Context()
	// Each read on its own pool, whose search_path names its schema, so none is qualified, and
	// written out as standard SQL, which a session with it off writes a backslash of in two; but
	// rbac_migrations', which a host's tool doesn't make. An index's predicate and a column's
	// default hold literals as a check does.
	constraints := func(pool *pgxpool.Pool) map[string]string {
		t.Helper()
		defs := map[string]string{}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL standard_conforming_strings = on`); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT 'constraint ' || c.relname || '.' || k.conname, pg_get_constraintdef(k.oid)
				FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = k.connamespace
				WHERE n.nspname = current_schema() AND c.relname <> 'rbac_migrations'
				UNION ALL
				SELECT 'index ' || i.relname, pg_get_indexdef(i.oid, 0, true)
				FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class c ON c.oid = x.indrelid
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE n.nspname = current_schema() AND c.relname <> 'rbac_migrations'
				UNION ALL
				SELECT 'default ' || c.relname || '.' || a.attname, pg_get_expr(d.adbin, d.adrelid)
				FROM pg_attrdef d JOIN pg_class c ON c.oid = d.adrelid JOIN pg_namespace n ON n.oid = c.relnamespace
				JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
				WHERE n.nspname = current_schema() AND c.relname <> 'rbac_migrations'`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var name, def string
				if err := rows.Scan(&name, &def); err != nil {
					return err
				}
				defs[name] = def
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return defs
	}
	want := constraints(setup(t).pool)
	migrated := pgtest.Open(t, "standard_conforming_strings=off")
	if err := rbac.Migrate(ctx, migrated); err != nil {
		t.Fatal(err)
	}
	applied := pgtest.Open(t, "standard_conforming_strings=off")
	migrateFiles(t, applied, "", "")
	for how, pool := range map[string]*pgxpool.Pool{"Migrate": migrated, "a host's tool": applied} {
		got := constraints(pool)
		for name, def := range want {
			if got[name] != def {
				t.Errorf("migrated by %s, %s is %q, not %q", how, name, got[name], def)
			}
		}
		if len(got) != len(want) {
			t.Errorf("migrated by %s, the tables have %d constraints, indexes and defaults, not %d", how, len(got), len(want))
		}
		_, err := pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'customXadmin', '{cluster:view}', '{cluster}')`)
		if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.ConstraintName != "rbac_roles_id_check" {
			t.Errorf("migrated by %s, the roles' id check didn't refuse customXadmin: %v", how, err)
		}
		for i, p := range []string{"cluster:login", "cluster:*"} {
			if _, err := pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				VALUES ('t1', 'cluster', 'c1', $1, '{public:}', $2)`, fmt.Sprint("d", i), []string{p}); err != nil {
				t.Errorf("migrated by %s, a deny of %s: %v", how, p, err)
			}
		}
	}
}

// What a migration means can't hang on the session's standard_conforming_strings, as a host's
// tool applies it: none holds a backslash, which writes a dot in a pattern as [.] instead.
func TestNoMigrationHoldsABackslash(t *testing.T) {
	for name, sql := range migrationSQL(t) {
		for i, line := range strings.Split(sql, "\n") {
			if strings.Contains(line, `\`) {
				t.Errorf("%s:%d holds a backslash: %s", name, i+1, line)
			}
		}
	}
}

// migrationSQL is each migration's SQL by its file's name.
func migrationSQL(t *testing.T) map[string]string {
	t.Helper()
	files, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqls := make(map[string]string, len(files))
	for _, name := range files {
		sql, err := fs.ReadFile(rbac.Migrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		sqls[name] = string(sql)
	}
	return sqls
}

// Migrate applies every migration with standard_conforming_strings on, whatever the session's, and
// leaves a host's transaction with it as it was.
func TestMigrateReadsItsMigrationsAsStandardSQL(t *testing.T) {
	ctx := t.Context()
	sqls := migrationSQL(t)
	tracer := &settingTracer{setting: "standard_conforming_strings", of: map[string]string{}, seen: map[string]string{}}
	for name, sql := range sqls {
		tracer.of[sql] = name
	}
	cfg := pgtest.Open(t, "standard_conforming_strings=off").Config().ConnConfig
	cfg.Tracer = tracer
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := rbac.Migrate(ctx, tx); err != nil {
		t.Fatal(err)
	}
	for name := range sqls {
		if got := tracer.seen[name]; got != "on" {
			t.Errorf("%s applied with standard_conforming_strings %q", name, got)
		}
	}
	var after string
	if err := tx.QueryRow(ctx, `SHOW standard_conforming_strings`).Scan(&after); err != nil || after != "off" {
		t.Errorf("after Migrate, the host's transaction has standard_conforming_strings %q, %v", after, err)
	}
}

// Migrate bounds the locks its migrations wait for only in a transaction of its own, and leaves a
// host's transaction with its lock_timeout as it was.
func TestMigrateLeavesAHostsLockTimeoutAsItWas(t *testing.T) {
	ctx := t.Context()
	tx, err := pgtest.Open(t, "").Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '7s'`); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := tx.QueryRow(ctx, `SHOW lock_timeout`).Scan(&after); err != nil || after != "7s" {
		t.Errorf("after Migrate, the host's transaction has lock_timeout %q, %v", after, err)
	}
}

// settingTracer records, as each statement of those in of is sent, the setting as the server last
// reported it.
type settingTracer struct {
	setting string
	of      map[string]string
	seen    map[string]string
}

func (s *settingTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if name, ok := s.of[data.SQL]; ok {
		s.seen[name] = conn.PgConn().ParameterStatus(s.setting)
	}
	return ctx
}

func (*settingTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestCreatorsGetARoleInTheHostsTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	ws := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w9", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The host creates the workspace and gives its creator a role on it, in one transaction.
	authz := h.authz.WithTx(tx)
	creator := []rbac.Grant{
		grant(ws.Scope(), "workspace.admin", rbac.User, "maker"),
		grant(ws.Scope(), "cluster.login", rbac.User, "maker"),
	}
	if err := authz.Import(ctx, host, "t1", creator); err != nil {
		t.Fatal(err)
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "friend"}}
	if err := authz.Apply(ctx, h.as(t, "maker"), ws, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("the creator sharing what it holds: %v", err)
	}
	if err := authz.Apply(ctx, h.as(t, "maker"), ws, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: b.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("the creator granting more than its role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	inside := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c9", Ancestors: []rbac.Scope{ws.Scope(), {Type: "org", ID: "o1"}}}
	if !allowed(t, h, h.as(t, "friend"), login, inside) {
		t.Fatal("a grant on the new workspace should reach its clusters")
	}
}

func TestAFailedPrincipalLookupFailsTheChange(t *testing.T) {
	h := setup(t)
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "unreachable"}}
	err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, errLookup) || errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a lookup failure should fail the change as it is, not as invalid input: %v", err)
	}
}

func TestHooksCanUseTheBusyPool(t *testing.T) {
	pool := pgtest.Open(t, "pool_max_conns=1")
	if err := rbac.Migrate(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	creator(t, pool)
	h := &harness{ctx: t.Context(), pool: pool}
	query := func(ctx context.Context) error {
		var one int
		return pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	guard := rbac.RoleDefinition{ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, ResourceTypes: []string{"cluster"}}
	authz, err := rbac.New(pool, rbac.Config{
		Catalog:        append(slices.Clone(catalog), guard),
		ContainerTypes: []string{"org", "workspace"},
		ValidateGrant:  func(ctx context.Context, _ rbac.DB, _ rbac.GrantInput) error { return query(ctx) },
		Constraints: []rbac.Constraint{{Name: "lookup", Deny: func(ctx context.Context, _ rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			return false, query(ctx)
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("a hook on the pool the change runs on: %v", err)
	}
	tenant := rbac.TenantRoot("t1")
	if err := authz.Import(ctx, host, "t1", []rbac.Grant{grant(tenant, "tenant.roles", rbac.User, "owner"), grant(tenant, "cluster.login", rbac.User, "owner")}); err != nil {
		t.Fatal(err)
	}
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := authz.SetRole(ctx, h.as(t, "owner"), "t1", r); err != nil {
		t.Fatalf("a hook on the pool a role's definition runs on: %v", err)
	}
	if err := authz.DeleteRole(ctx, h.as(t, "owner"), "t1", r.ID); err != nil {
		t.Fatalf("a hook on the pool a role's deletion runs on: %v", err)
	}
	if err := authz.Import(ctx, host, "t1", []rbac.Grant{grant(tenant, "guard", rbac.User, "owner")}); err != nil {
		t.Fatal(err)
	}
	d := rbac.Deny{ID: "d", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	if err := authz.SetDeny(ctx, h.as(t, "owner"), cluster, d); err != nil {
		t.Fatalf("a hook on the pool a deny is set on: %v", err)
	}
	if err := authz.DeleteDeny(ctx, h.as(t, "owner"), cluster, d.ID); err != nil {
		t.Fatalf("a hook on the pool a deny is deleted on: %v", err)
	}
}

func TestAGrantBesideAnExpiredOneRecordsItsOwnActor(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	h.now = h.now.Add(2 * time.Hour)
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}})
	if err != nil || len(got) != 1 || got[0].CreatedBy != (rbac.Principal{Kind: rbac.User, ID: "owner"}) {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestSubjectsAreAnonymousOrOneIdentity(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"))
	for name, s := range map[string]rbac.Subject{
		"a group":              {Principal: rbac.Principal{Kind: rbac.Group, ID: "g"}},
		"the tenant's members": {Principal: rbac.TenantMembers("t1")},
		"an undeclared kind":   {Principal: rbac.Principal{Kind: "robot", ID: "r"}},
		"no id":                {Principal: rbac.Principal{Kind: rbac.User}},
	} {
		if err := h.authz.Authorize(t.Context(), s, login, cluster); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := h.authz.Reachable(t.Context(), s, login, "t1", "cluster"); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Reachable %v", name, err)
		}
		if _, err := h.authz.Filter(t.Context(), s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Filter %v", name, err)
		}
		if _, err := h.authz.Permissions(t.Context(), s, cluster); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Permissions %v", name, err)
		}
		if _, err := h.authz.Explain(t.Context(), s, login, cluster); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Explain %v", name, err)
		}
		if err := h.authz.Apply(t.Context(), s, cluster, rbac.Change{}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Apply of no change %v", name, err)
		}
	}
	if !allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("a user is one of the tenant's members")
	}
	if allowed(t, h, rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "v"}}, login, cluster) {
		t.Fatal("an identity in no tenant is one of the tenant's members")
	}
}

func TestAncestorsMustBeContainers(t *testing.T) {
	h := setup(t)
	job := rbac.Resource{Tenant: "t1", Type: "job", ID: "j1", Ancestors: []rbac.Scope{cluster.Scope()}}
	if err := h.authz.Authorize(t.Context(), h.as(t, "owner"), "job:view", job); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a resource under a non-container: %v", err)
	}
}

func TestEscalationCoversEveryTypeAGrantReaches(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "multi.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster", "job"},
		})
	})
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "workspace.admin", rbac.User, "m"),
		grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.admin", rbac.User, "m"),
	)
	b := rbac.Binding{Role: "multi.view", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	// On the workspace the grant reaches jobs too, where m holds nothing.
	if err := h.authz.Apply(t.Context(), h.as(t, "m"), workspace, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a role for types the actor doesn't hold: %v", err)
	}
	// On one cluster it reaches only that cluster, where m holds cluster:view.
	if err := h.authz.Apply(t.Context(), h.as(t, "m"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("granting on a resource the actor holds it on: %v", err)
	}
}

func TestConcurrentChangesToAScopeAllCommit(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	bind := func(id string) rbac.Binding {
		return rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: id}}
	}
	ids := []string{"a", "b", "c", "d"}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := range 8 {
		wg.Go(func() {
			for i := range 8 {
				var c rbac.Change
				for j, id := range ids {
					if (w+i+j)%2 == 0 {
						c.Grant = append(c.Grant, bind(id))
					} else {
						c.Revoke = append(c.Revoke, bind(id))
					}
				}
				if w%2 == 1 {
					slices.Reverse(c.Grant)
					slices.Reverse(c.Revoke)
				}
				if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, c); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestDeleteScopeRemovesAGrantMadeWhileItWaits(t *testing.T) {
	// With 64 other scopes, the delete waits on the tenant's lock rather than the scope's.
	for _, others := range []int{0, 64} {
		t.Run(fmt.Sprint(others), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			scopes := []rbac.Scope{cluster.Scope()}
			for i := range others {
				scopes = append(scopes, rbac.Scope{Type: "cluster", ID: fmt.Sprintf("x%d", i)})
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
			if err := h.authz.WithTx(tx).Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- h.authz.DeleteScopes(ctx, host, "t1", scopes) }()
			commitOnceWaitedOn(t, h, tx, done)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, h.as(t, "u"), login, cluster) {
				t.Fatal("a grant made while its scope was deleted outlived the delete")
			}
		})
	}
}

// DeleteScopes removes a deny on its scopes that a change taking a principal out of the deny's
// exemptions, which takes no lock of the scope's, changed while the delete waited for it: the delete
// finds it again by its key, where by a ctid, which the change moved, it would pass over it.
func TestDeleteScopesRemovesADenyChangedWhileItWaits(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{public:}', '{user:p}', '{cluster:root}')`); err != nil {
		t.Fatal(err)
	}
	h.as(t, "p")
	// p leaves the tenant, and its exemption, in a transaction that holds the deny until it ends.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).DeletePrincipal(ctx, host, "t1", identity("p")); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope()}) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("DeleteScopes waited for nothing p's removal holds: %v", err)
		default:
		}
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ds, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
	if err != nil || len(ds) > 0 {
		t.Fatalf("denies left on a scope deleted: %+v, %v", ds, err)
	}
}

func TestDeletingScopesAndAPrincipalOnThemAtOnceNeverDeadlocks(t *testing.T) {
	for name, deletePrincipal := range map[string]func(ctx context.Context, h *harness) error{
		"DeletePrincipal": func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipal(ctx, host, "t1", identity("p"))
		},
		"DeletePrincipalEverywhere": func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, identity("p"))
		},
	} {
		for _, held := range []string{"rbac_grants", "rbac_eligibilities"} {
			for rows, both := range map[string]bool{"in it alone": false, "in both tables": true} {
				t.Run(fmt.Sprintf("%s, %s held, rows %s", name, held, rows), func(t *testing.T) {
					h := setup(t)
					ctx := t.Context()
					scopes := make([]rbac.Scope, 60)
					for i := range scopes {
						scopes[i] = rbac.Scope{Type: "cluster", ID: fmt.Sprintf("c%02d", i)}
					}
					// p's grants and eligibilities on each scope, written in the reverse of the scopes'
					// order, so reading them by principal meets them the other way round.
					for i := range slices.Backward(scopes) {
						if held == "rbac_grants" || both {
							if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
								VALUES ('t1', 'cluster', $1, 'user', 'p', 'cluster.login')`, scopes[i].ID); err != nil {
								t.Fatal(err)
							}
						}
						if held == "rbac_eligibilities" || both {
							if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
								VALUES ('t1', 'cluster', $1, 'user', 'p', 'cluster.login', 60)`, scopes[i].ID); err != nil {
								t.Fatal(err)
							}
						}
					}
					// A transaction holding the row on the middle scope stops both deletes there, each
					// holding what it deleted before it, until it ends.
					hold, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = hold.Rollback(ctx) }()
					var pid int
					if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
						t.Fatal(err)
					}
					if _, err := hold.Exec(ctx, `SELECT FROM `+held+` WHERE tenant = 't1' AND scope = 'cluster:c30' FOR UPDATE`); err != nil {
						t.Fatal(err)
					}
					errs := make(chan error, 2)
					go func() { errs <- h.authz.DeleteScopes(ctx, host, "t1", scopes) }()
					go func() { errs <- deletePrincipal(ctx, h) }()
					for waiting := 0; waiting < 2; {
						if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
							SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
							UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
							SELECT count(*) FROM waiting`, pid).Scan(&waiting); err != nil {
							t.Fatal(err)
						}
					}
					if err := hold.Rollback(ctx); err != nil {
						t.Fatal(err)
					}
					for range 2 {
						if err := <-errs; err != nil {
							t.Errorf("deleting the scopes and a principal on them at once: %v", err)
						}
					}
				})
			}
		}
	}
}

func TestDeletingGroupsAndWhatTheyReachAtOnceNeverDeadlocks(t *testing.T) {
	for name, c := range map[string]struct {
		// rows are what both deletes remove, and held is the scope of a deny the first stops at,
		// holding what it removed before it.
		rows         []string
		held         rbac.Scope
		first, other func(ctx context.Context, h *harness) error
	}{
		"DeletePrincipal of a member granted on the group": {
			rows: []string{
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'group', 'g', 'user', 'p', 'cluster.login')`,
				`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g', 'user', 'p')`,
			},
			held: rbac.Scope{Type: rbac.GroupScope, ID: "g"},
			first: func(ctx context.Context, h *harness) error {
				return h.authz.DeleteGroups(ctx, host, "t1", []string{"g"})
			},
			other: func(ctx context.Context, h *harness) error {
				return h.authz.DeletePrincipal(ctx, host, "t1", identity("p"))
			},
		},
		"DeleteScopes of a scope the group holds": {
			rows: []string{
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c7', 'group', 'g', 'cluster.login')`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds) VALUES ('t1', 'cluster', 'c7', 'group', 'g', 'cluster.login', 60)`,
			},
			held: rbac.Scope{Type: "cluster", ID: "c7"},
			first: func(ctx context.Context, h *harness) error {
				return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{{Type: "cluster", ID: "c7"}})
			},
			other: func(ctx context.Context, h *harness) error {
				return h.authz.DeleteGroups(ctx, host, "t1", []string{"g"})
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			h.groups(t, "g")
			for _, q := range c.rows {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				VALUES ('t1', $1, $2, 'held', '{public:}', '{cluster:login}')`, c.held.Type, c.held.ID); err != nil {
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
			if _, err := hold.Exec(ctx, `SELECT FROM rbac_denies WHERE tenant = 't1' AND id = 'held' FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			// Until n wait on the hold, or one is done, as the other is once it waits for nothing the
			// first holds.
			errs := make(chan error, 2)
			done := 0
			waiting := func(n int) {
				for blocked := 0; blocked < n; {
					select {
					case err := <-errs:
						if err != nil {
							t.Errorf("a delete run while the other waited: %v", err)
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
			go func() { errs <- c.first(ctx, h) }()
			waiting(1)
			go func() { errs <- c.other(ctx, h) }()
			waiting(2)
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			for ; done < 2; done++ {
				if err := <-errs; err != nil {
					t.Errorf("deleting groups and what they reach at once: %v", err)
				}
			}
		})
	}
}

// DeletePrincipal takes an identity out of the approvers and exemptions it locked alone: an
// eligibility or a deny naming it that commits while the removal waits for those, which no lock of
// the identity's keeps out, is left naming it for a later removal, rather than locked out of order.
// So removing two identities that a row committed so names both, as the other removal holds it,
// doesn't deadlock.
func TestRemovingIdentitiesARowNamesBothNeverDeadlocks(t *testing.T) {
	early, late := rbac.Scope{Type: "cluster", ID: "a"}, rbac.Scope{Type: "cluster", ID: "b"}
	for name, c := range map[string]struct {
		// held is a row u's removal waits for, and committed one sorting before it that commits
		// meanwhile, each naming u and v; names reads whom the row on a scope names.
		held, committed heldRow
		names           string
	}{
		"eligibilities both approve": {
			held:      eligibilityRow(late, identity("q"), "cluster.sudo", "user:u", "user:v"),
			committed: eligibilityRow(early, identity("q"), "cluster.sudo", "user:u", "user:v"),
			names:     `SELECT approvers FROM rbac_eligibilities WHERE tenant = 't1' AND scope = $1`,
		},
		"denies exempting both": {
			held:      denyRow(late, "d", []string{"public:"}, []string{"user:u", "user:v"}, "cluster:login"),
			committed: denyRow(early, "d", []string{"public:"}, []string{"user:u", "user:v"}, "cluster:login"),
			names:     `SELECT exempt FROM rbac_denies WHERE tenant = 't1' AND scope = $1`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h.as(t, "u")
			h.as(t, "v")
			if _, err := h.pool.Exec(ctx, c.held.seed, c.held.seedArgs...); err != nil {
				t.Fatal(err)
			}
			hold, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hold.Rollback(context.WithoutCancel(ctx)) }()
			var pid int
			if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(ctx, c.held.hold, c.held.holdArgs...); err != nil {
				t.Fatal(err)
			}
			errs := make(chan error, 2)
			// Until n sessions wait on the hold, through others too.
			waiting := func(n int) {
				t.Helper()
				for blocked := 0; blocked < n; {
					select {
					case err := <-errs:
						t.Fatalf("a removal returned while the row was held: %v", err)
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
			go func() { errs <- h.authz.DeletePrincipal(ctx, host, "t1", identity("u")) }()
			waiting(1)
			if _, err := h.pool.Exec(ctx, c.committed.seed, c.committed.seedArgs...); err != nil {
				t.Fatal(err)
			}
			// v's removal locks the row committed, and waits for the one held behind u's.
			go func() { errs <- h.authz.DeletePrincipal(ctx, host, "t1", identity("v")) }()
			waiting(2)
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := <-errs; err != nil {
					t.Errorf("removing two identities a row committed meanwhile names: %v", err)
				}
			}
			names := func(s rbac.Scope) []string {
				t.Helper()
				var ks []string
				if err := h.pool.QueryRow(ctx, c.names, s.Key()).Scan(&ks); err != nil && !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal(err)
				}
				return ks
			}
			if got := names(late); len(got) > 0 {
				t.Errorf("the row both removals held names %v", got)
			}
			if got := names(early); !slices.Equal(got, []string{"user:u"}) {
				t.Errorf("the row committed while u's removal waited names %v, want u alone, left for a later removal", got)
			}
			if err := h.authz.DeletePrincipal(ctx, host, "t1", identity("u")); err != nil {
				t.Fatal(err)
			}
			if got := names(early); len(got) > 0 {
				t.Errorf("removing u again leaves the row committed naming %v", got)
			}
		})
	}
}

// heldRow is a row a test writes with seed and holds alone with hold, each run with its args.
type heldRow struct {
	name               string
	seed, hold         string
	seedArgs, holdArgs []any
}

func grantRow(s rbac.Scope, p rbac.Principal, role string) heldRow {
	args := []any{s.Type, s.ID, string(p.Kind), p.ID, role}
	return heldRow{
		name:     fmt.Sprintf("grant of %s to %s:%s on %s", role, p.Kind, p.ID, s.Key()),
		seed:     `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', $1, $2, $3, $4, $5)`,
		hold:     `SELECT FROM rbac_grants WHERE tenant = 't1' AND scope_type = $1 AND scope_id = $2 AND principal_kind = $3 AND principal_id = $4 AND role = $5 FOR UPDATE`,
		seedArgs: args, holdArgs: args,
	}
}

func eligibilityRow(s rbac.Scope, p rbac.Principal, role string, approvers ...string) heldRow {
	args := []any{s.Type, s.ID, string(p.Kind), p.ID, role}
	return heldRow{
		name: fmt.Sprintf("eligibility for %s of %s:%s on %s", role, p.Kind, p.ID, s.Key()),
		seed: `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			VALUES ('t1', $1, $2, $3, $4, $5, 3600, $6)`,
		hold:     `SELECT FROM rbac_eligibilities WHERE tenant = 't1' AND scope_type = $1 AND scope_id = $2 AND principal_kind = $3 AND principal_id = $4 AND role = $5 FOR UPDATE`,
		seedArgs: append(slices.Clone(args), append([]string{}, approvers...)), holdArgs: args,
	}
}

func denyRow(s rbac.Scope, id string, principals, exempt []string, permission string) heldRow {
	args := []any{s.Type, s.ID, id}
	return heldRow{
		name: fmt.Sprintf("deny %s on %s", id, s.Key()),
		seed: `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', $1, $2, $3, $4, $5, ARRAY[$6])`,
		hold:     `SELECT FROM rbac_denies WHERE tenant = 't1' AND scope_type = $1 AND scope_id = $2 AND id = $3 FOR UPDATE`,
		seedArgs: append(slices.Clone(args), principals, append([]string{}, exempt...), permission), holdArgs: args,
	}
}

func membershipRow(p rbac.Principal) heldRow {
	args := []any{string(p.Kind), p.ID}
	return heldRow{
		name:     fmt.Sprintf("membership of %s:%s", p.Kind, p.ID),
		seed:     `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', $1, $2)`,
		hold:     `SELECT FROM rbac_memberships WHERE tenant = 't1' AND principal_kind = $1 AND principal_id = $2 FOR UPDATE`,
		seedArgs: args, holdArgs: args,
	}
}

func placeRow(group string, p rbac.Principal) heldRow {
	args := []any{group, string(p.Kind), p.ID}
	return heldRow{
		name:     fmt.Sprintf("place of %s:%s in %s", p.Kind, p.ID, group),
		seed:     `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', $1, $2, $3)`,
		hold:     `SELECT FROM rbac_members WHERE tenant = 't1' AND group_id = $1 AND principal_kind = $2 AND principal_id = $3 FOR UPDATE`,
		seedArgs: args, holdArgs: args,
	}
}

// A change holding several rows of its tables locks them in one order, of the tables and of each
// table's rows by their keys, in the C collation their columns sort in, whatever the plan: a
// statement locking rows sorts what its keys found and locks each by its key in a nested loop over
// them (lockedInOrder), so no plan, generic or for its arguments, or with the planner's other ways
// off, takes them in an index's or the table's order. Each row is written in the reverse of that
// order, keyed so that the order by principal, or in the database's collation, differs, and held by
// a transaction of its own, which ends once the change waits for it: so the change waits for each
// in turn, in the order it locks them.
func TestChangesLockRowsInTheOrderOfTheirTables(t *testing.T) {
	big, small, onGroup := rbac.Scope{Type: "cluster", ID: "B"}, rbac.Scope{Type: "cluster", ID: "a"}, rbac.Scope{Type: rbac.GroupScope, ID: "g"}
	p, q, x, y, z, g := identity("p"), identity("q"), identity("x"), identity("y"), identity("Z"), groupOf("g")
	for _, c := range []struct {
		name string
		// rows are in the order the change locks them, and extra written beside them.
		rows  []heldRow
		extra []string
		call  func(ctx context.Context, h *harness) error
	}{{
		name: "DeleteScopes",
		rows: []heldRow{
			eligibilityRow(big, z, "cluster.sudo"), eligibilityRow(small, x, "cluster.sudo"),
			denyRow(big, "e", []string{"public:"}, nil, "cluster:login"), denyRow(small, "d", []string{"public:"}, nil, "cluster:login"),
			denyRow(small, "e", []string{"public:"}, nil, "cluster:login"),
			grantRow(big, z, "cluster.login"), grantRow(big, x, "cluster.login"), grantRow(small, z, "cluster.login"), grantRow(small, x, "cluster.login"),
		},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{small, big})
		},
	}, {
		name: "DeletePrincipal of an identity",
		rows: []heldRow{
			eligibilityRow(big, p, "cluster.sudo"), eligibilityRow(small, p, "cluster.sudo"), eligibilityRow(small, q, "cluster.sudo", "user:p"),
			denyRow(big, "d", []string{"public:"}, []string{"user:p"}, "cluster:login"), denyRow(small, "e", []string{"user:q"}, []string{"user:p"}, "cluster:login"),
			membershipRow(p),
			placeRow("G", p), placeRow("g", p),
			grantRow(big, p, "cluster.login"), grantRow(small, p, "cluster.login"),
		},
		extra: []string{`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'G'), ('t1', 'g')`},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipal(ctx, host, "t1", p)
		},
	}, {
		name: "DeletePrincipal of a group",
		rows: []heldRow{
			eligibilityRow(big, g, "cluster.sudo"), eligibilityRow(small, g, "cluster.sudo"), eligibilityRow(small, q, "cluster.sudo", "group:g"),
			denyRow(big, "d", []string{"public:"}, []string{"group:g"}, "cluster:login"),
			placeRow("G", g), placeRow("h", g),
			grantRow(big, g, "cluster.login"), grantRow(small, g, "cluster.login"),
		},
		extra: []string{`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'G'), ('t1', 'g'), ('t1', 'h')`},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeletePrincipal(ctx, host, "t1", g)
		},
	}, {
		name: "DeleteGroups",
		rows: []heldRow{
			eligibilityRow(big, g, "cluster.sudo"), eligibilityRow(small, g, "cluster.sudo"), eligibilityRow(small, q, "cluster.sudo", "group:g"),
			eligibilityRow(onGroup, z, "group.owner"),
			denyRow(big, "d", []string{"public:"}, []string{"group:g"}, "cluster:login"), denyRow(small, "d", []string{"group:g", "user:q"}, nil, "cluster:login"),
			denyRow(onGroup, "d", []string{"user:q"}, nil, "group:manage"),
			placeRow("G", g), placeRow("g", z), placeRow("g", y),
			grantRow(big, g, "cluster.login"), grantRow(small, g, "cluster.login"), grantRow(onGroup, z, "group.owner"),
		},
		extra: []string{`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'G'), ('t1', 'g')`},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeleteGroups(ctx, host, "t1", []string{"g"})
		},
	}, {
		name: "Apply revoking",
		rows: []heldRow{grantRow(big, z, "cluster.login"), grantRow(big, x, "cluster.login"), grantRow(big, y, "cluster.login")},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.Apply(ctx, rbac.Subject{Principal: identity("manager")}, rbac.Resource{Tenant: "t1", Type: big.Type, ID: big.ID},
				rbac.Change{Revoke: []rbac.Binding{
					{Role: "cluster.login", Principal: y}, {Role: "cluster.login", Principal: x}, {Role: "cluster.login", Principal: z},
				}})
		},
	}, {
		name: "DeleteGrants",
		rows: []heldRow{grantRow(big, z, "cluster.login"), grantRow(big, x, "cluster.login"), grantRow(small, z, "cluster.login"), grantRow(small, x, "cluster.login")},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{
				grant(small, "cluster.login", rbac.User, "x"), grant(small, "cluster.login", rbac.User, "Z"),
				grant(big, "cluster.login", rbac.User, "x"), grant(big, "cluster.login", rbac.User, "Z"),
			})
		},
	}, {
		name: "DeleteRole",
		rows: []heldRow{
			eligibilityRow(big, x, "custom.x"), eligibilityRow(small, z, "custom.x"),
			grantRow(big, z, "custom.x"), grantRow(big, x, "custom.x"), grantRow(small, z, "custom.x"),
		},
		extra: []string{`INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.x', '{cluster:view}', '{cluster}')`},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.DeleteRole(ctx, rbac.Subject{Principal: identity("manager")}, "t1", "custom.x")
		},
	}, {
		name: "SetMemberships",
		rows: []heldRow{membershipRow(z), membershipRow(x), membershipRow(y)},
		call: func(ctx context.Context, h *harness) error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: y, Note: "n"}, {Principal: x, Note: "n"}, {Principal: z, Note: "n"}})
		},
	}} {
		for _, mode := range []string{
			"plan_cache_mode=force_generic_plan", "plan_cache_mode=force_custom_plan",
			"enable_nestloop=off&enable_sort=off&enable_hashagg=off&enable_material=off&enable_memoize=off&enable_indexscan=off",
		} {
			t.Run(c.name+", "+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				// The change runs on the pool's one connection, and the holds each on one of others'.
				h := groupedOn(t, pgtest.Open(t, "pool_max_conns=1&"+mode))
				h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "manager"), grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "manager"),
					grant(big, "cluster.admin", rbac.User, "manager"), grant(small, "cluster.admin", rbac.User, "manager"))
				h.as(t, "manager")
				for _, q := range c.extra {
					if _, err := h.pool.Exec(ctx, q); err != nil {
						t.Fatal(err)
					}
				}
				for _, r := range slices.Backward(c.rows) {
					if _, err := h.pool.Exec(ctx, r.seed, r.seedArgs...); err != nil {
						t.Fatalf("%s: %v", r.name, err)
					}
				}
				var pid int32
				if err := h.pool.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					t.Fatal(err)
				}
				cfg := h.pool.Config().Copy()
				cfg.MaxConns = int32(len(c.rows) + 1)
				others, err := pgxpool.NewWithConfig(ctx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer others.Close()
				holds, of := make([]pgx.Tx, len(c.rows)), map[int32]int{}
				for i, r := range c.rows {
					if holds[i], err = others.Begin(ctx); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = holds[i].Rollback(context.WithoutCancel(ctx)) }()
					var held int32
					if err := holds[i].QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&held); err != nil {
						t.Fatal(err)
					}
					of[held] = i
					if tag, err := holds[i].Exec(ctx, r.hold, r.holdArgs...); err != nil || tag.RowsAffected() != 1 {
						t.Fatalf("holding the %s: %v, %v", r.name, tag, err)
					}
				}
				done := make(chan error, 1)
				go func() { done <- c.call(ctx, h) }()
				var waited []string
				for len(waited) < len(c.rows) {
					select {
					case err := <-done:
						t.Fatalf("the change returned %v having waited for %q", err, waited)
					default:
					}
					var blocking []int32
					if err := others.QueryRow(ctx, `SELECT pg_blocking_pids($1)`, pid).Scan(&blocking); err != nil {
						t.Fatalf("waiting for %q: %v", waited, err)
					}
					if len(blocking) == 0 {
						continue
					}
					i, ok := of[blocking[0]]
					if !ok || len(blocking) > 1 {
						t.Fatalf("the change waits for sessions %v", blocking)
					}
					waited = append(waited, c.rows[i].name)
					if err := holds[i].Rollback(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				var want []string
				for _, r := range c.rows {
					want = append(want, r.name)
				}
				if !slices.Equal(waited, want) {
					t.Errorf("the change locked\n%s\nwant\n%s", strings.Join(waited, "\n"), strings.Join(want, "\n"))
				}
			})
		}
	}
}

func TestDeleteScopesHoldsBoundedLocks(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	scopes := make([]rbac.Scope, 200)
	var grants []rbac.Grant
	for i := range scopes {
		scopes[i] = rbac.Scope{Type: "cluster", ID: fmt.Sprintf("x%d", i)}
		grants = append(grants, grant(scopes[i], "cluster.login", rbac.User, "u"))
	}
	h.seed(t, grants...)
	locks := func(tx pgx.Tx) int {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'advisory'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, c := range []struct {
		scopes         []rbac.Scope
		locks, revoked int
	}{
		// One lock for each scope and the tenant's shared, or past 64 the tenant's alone, held to the end.
		{scopes[:3], 4, 3},
		// A scope listed again, as on the paths of resources under one container, is locked once.
		{slices.Repeat(scopes[:3], 30), 4, 3},
		{scopes, 1, len(scopes)},
	} {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		h.events = nil
		// As a host deleting a workspace and everything under it, in the transaction that deletes them.
		if err := h.authz.WithTx(tx).DeleteScopes(ctx, host, "t1", c.scopes); err != nil {
			t.Fatal(err)
		}
		if got := locks(tx); got != c.locks {
			t.Errorf("deleting %d scopes holds %d locks, want %d", len(c.scopes), got, c.locks)
		}
		if len(h.events) != 1 || len(h.events[0].Revoked) != c.revoked {
			t.Errorf("deleting %d scopes reported %+v", len(c.scopes), h.events)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.DeleteScopes(ctx, host, "t1", scopes); err != nil {
		t.Fatal(err)
	}
	if gs, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(gs) != 0 {
		t.Fatalf("grants left: %v, %v", gs, err)
	}
	if err := h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{rbac.TenantRoot("t2")}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("another tenant's scope: %v", err)
	}
	if err := h.authz.DeleteScopes(ctx, rbac.Principal{}, "t1", nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("no scopes as no one: %v", err)
	}
}

func TestMigratingAtOnce(t *testing.T) {
	files, err := fs.Glob(rbac.Migrations(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Where transactions default to SERIALIZABLE too, whose snapshot predates the lock a replica
	// waits for. A few rounds each, so the replicas overlap.
	for _, params := range []string{"", "default_transaction_isolation=serializable"} {
		for range 3 {
			pool := pgtest.Open(t, params)
			errs := make(chan error, 2)
			for range 2 {
				go func() { errs <- rbac.Migrate(t.Context(), pool) }()
			}
			for range 2 {
				if err := <-errs; err != nil {
					t.Fatalf("two replicas migrating one schema at once (%q): %v", params, err)
				}
			}
			var versions int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM rbac_migrations`).Scan(&versions); err != nil {
				t.Fatal(err)
			}
			if versions != len(files) {
				t.Fatalf("recorded %d migrations, want %d", versions, len(files))
			}
		}
	}
}

func TestSearchesKeepToContainersAboveAResource(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "job.view", Permissions: []rbac.Permission{"job:view"}, ResourceTypes: []string{"cluster", "job"},
		})
	})
	ctx := t.Context()
	job := rbac.Resource{Tenant: "t1", Type: "job", ID: "j1", Ancestors: []rbac.Scope{cluster.Scope()}}
	if _, err := h.authz.Path(job); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a path under a resource that isn't a container: %v", err)
	}
	// A host that builds paths itself lists the job under its cluster anyway.
	if _, err := h.pool.Exec(ctx, `CREATE TABLE jobs (tenant text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO jobs VALUES ('t1', ARRAY['job:j1', 'cluster:c1', 'tenant:t1'])`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "job.view", rbac.User, "friend"))

	pred, err := h.authz.Filter(ctx, h.as(t, "friend"), "job:view", "t1", "job", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("Filter keeps a job through a grant on the cluster above it")
	}
	reach, err := h.authz.Reachable(ctx, h.as(t, "friend"), "job:view", "t1", "job")
	if err != nil {
		t.Fatal(err)
	}
	if reach.All || len(reach.Scopes) > 0 {
		t.Errorf("Reachable reaches jobs through a grant on a cluster: %+v", reach)
	}
}

func TestTenantMembersAndThePublicNeverGetAGrantPermission(t *testing.T) {
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}} {
		t.Run(string(p.Kind), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			// As if a role granted to them gained cluster:grant in a later catalog.
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				VALUES ('t1', 'workspace', 'w1', $1, $2, 'cluster.admin')`, p.Kind, p.ID); err != nil {
				t.Fatal(err)
			}
			member := h.as(t, "member")
			// A role that gives cluster:grant is privileged and can't be public, so a grant of it to
			// either gives nothing at all.
			if allowed(t, h, member, root, cluster) {
				t.Fatal("the grant's other permissions")
			}
			if allowed(t, h, member, grantC, cluster) {
				t.Error("Authorize: cluster:grant")
			}
			if d, err := h.authz.Explain(ctx, member, grantC, cluster); err != nil || d.Allowed {
				t.Errorf("Explain: %+v, %v", d, err)
			}
			perms, err := h.authz.Permissions(ctx, member, cluster)
			if err != nil || slices.Contains(perms, grantC) {
				t.Errorf("Permissions: %v, %v", perms, err)
			}
			holders, err := h.authz.Holders(ctx, grantC, cluster)
			if err != nil || slices.Contains(holderPrincipals(holders), p) {
				t.Errorf("Holders: %v, %v", holders, err)
			}
			reach, err := h.authz.Reachable(ctx, member, grantC, "t1", "cluster")
			if err != nil || reach.All || len(reach.Scopes) > 0 {
				t.Errorf("Reachable: %+v, %v", reach, err)
			}
			if _, err := h.pool.Exec(ctx, `CREATE TABLE cs (tenant text NOT NULL, path text[] NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO cs VALUES ('t1', $1)`, h.path(t, cluster)); err != nil {
				t.Fatal(err)
			}
			for _, perm := range []rbac.Permission{root, grantC} {
				pred, err := h.authz.Filter(ctx, member, perm, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				if err != nil {
					t.Fatal(err)
				}
				var n int
				if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM cs WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Errorf("Filter %s: %d clusters, want none", perm, n)
				}
			}
			b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
			if err := h.authz.Apply(ctx, member, cluster, rbac.Change{Revoke: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("Apply: %v", err)
			}
		})
	}
}

func TestConcurrentChangesAcrossScopesAllCommit(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	ctx := t.Context()
	bind := func(id string) rbac.Binding {
		return rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: id}}
	}
	ws := rbac.Scope{Type: "workspace", ID: "w1"}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	run := func(change func(i int) error) {
		wg.Go(func() {
			for i := range 8 {
				if err := change(i); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	for w := range 4 {
		run(func(i int) error {
			c := rbac.Change{Grant: []rbac.Binding{bind("a")}, Revoke: []rbac.Binding{bind("b")}}
			if (w+i)%2 == 0 {
				c.Grant, c.Revoke = c.Revoke, c.Grant
			}
			return h.authz.Apply(ctx, h.as(t, "owner"), cluster, c)
		})
	}
	for range 2 {
		run(func(int) error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{
				grant(cluster.Scope(), "cluster.login", rbac.User, "a"),
				grant(cluster.Scope(), "cluster.login", rbac.User, "b"),
				grant(ws, "cluster.login", rbac.User, "a"),
			})
		})
	}
	// One principal's roles, revoked and granted in turn, against deleting the principal.
	sudo := rbac.Binding{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "a"}}
	for w := range 2 {
		run(func(i int) error {
			c := rbac.Change{Grant: []rbac.Binding{sudo}, Revoke: []rbac.Binding{bind("a")}}
			if (w+i)%2 == 0 {
				c.Grant, c.Revoke = c.Revoke, c.Grant
			}
			return h.authz.Apply(ctx, h.as(t, "owner"), cluster, c)
		})
	}
	for range 2 {
		run(func(int) error {
			return h.authz.DeletePrincipal(ctx, host, "t1", rbac.Principal{Kind: rbac.User, ID: "a"})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestHostTransactionsDeletingAPrincipalDontDeadlock(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	ctx := t.Context()
	other := cluster
	other.ID = "c2"
	gone := rbac.Principal{Kind: rbac.User, ID: "gone"}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "gone"), grant(other.Scope(), "cluster.admin", rbac.User, "owner"))
	// Each transaction changes its own cluster, then both delete the same user.
	var applied, wg sync.WaitGroup
	applied.Add(2)
	errs := make(chan error, 2)
	for i, r := range []rbac.Resource{cluster, other} {
		wg.Go(func() {
			errs <- pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
				authz := h.authz.WithTx(tx)
				b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: fmt.Sprintf("u%d", i)}}
				err := authz.Apply(ctx, h.as(t, "owner"), r, rbac.Change{Grant: []rbac.Binding{b}})
				applied.Done()
				if err != nil {
					return err
				}
				applied.Wait()
				return authz.DeletePrincipal(ctx, host, "t1", gone)
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestChangesOnASerializableDatabase(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "default_transaction_isolation=serializable"))
	// On the pool, and on a host's wrapper around it that is only a DB, whose Begin begins at the
	// default.
	wrapped, err := rbac.New(struct{ rbac.DB }{h.pool}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range []*rbac.Authorizer{h.authz, wrapped} {
		u := rbac.Principal{Kind: rbac.User, ID: fmt.Sprint("u", i)}
		if err := a.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: u}}}); err != nil {
			t.Fatalf("a change where transactions default to SERIALIZABLE, on DB %d: %v", i, err)
		}
		if !allowed(t, h, h.as(t, u.ID), login, cluster) {
			t.Fatal("the grant should be stored")
		}
	}
}

// On a host's wrapper around its own transaction, whose Begin gives a savepoint, which can't take
// another isolation, changes and reads of several statements run in that transaction at its
// isolation, as under WithTx: what a change makes, a read sees, and the host's rollback undoes.
func TestAWrapperAroundAHostsTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a, err := rbac.New(struct{ rbac.DB }{tx}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: u.Principal}}}); err != nil {
		t.Fatalf("a change: %v", err)
	}
	holders, err := a.Holders(ctx, login, cluster)
	if err != nil || !slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == u.Principal }) {
		t.Fatalf("Holders = %+v, %v", holders, err)
	}
	if reach, err := a.Reachable(ctx, u, login, "t1", "cluster"); err != nil || !slices.Contains(reach.Scopes, cluster.Scope()) {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	if d, err := a.Explain(ctx, u, login, cluster); err != nil || !d.Allowed {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, u, login, cluster) {
		t.Fatal("the change outlived the host's transaction")
	}
}

// A change and a read of several statements run in a transaction of their own on a pool, a
// connection, or a wrapper around either, whatever the database's default isolation, and on the
// host's transaction under WithTx or through a wrapper whose Begin gives a savepoint of it, at any
// isolation, before or after its first query: a savepoint may set the isolation its transaction
// already has, so setting the one a change or a read needs can't tell one at that isolation from a
// transaction of its own.
func TestATransactionOfItsOwnIsToldFromAHostsAtAnyIsolation(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	serializable := pgtest.Open(t, "default_transaction_isolation=serializable")
	conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	check := func(name string, db rbac.DB, own bool, change, read string) {
		t.Helper()
		if got, level, err := rbac.Transacted(ctx, db); err != nil || got != own || level != change {
			t.Errorf("a change on %s: own %t at %q, %v; want own %t at %q", name, got, level, err, own, change)
		}
		a, err := rbac.New(db, h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got, level, err := rbac.Snapshotted(ctx, a); err != nil || got != own || level != read {
			t.Errorf("a read on %s: own %t at %q, %v; want own %t at %q", name, got, level, err, own, read)
		}
	}
	for name, db := range map[string]rbac.DB{
		"a pool": h.pool, "a connection": conn, "a wrapper around a pool": struct{ rbac.DB }{h.pool},
		"a wrapper around a connection":                                      struct{ rbac.DB }{conn},
		"a wrapper around a pool where transactions default to SERIALIZABLE": struct{ rbac.DB }{serializable},
	} {
		check(name, db, true, "read committed", "repeatable read, read only")
	}
	for _, level := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead, pgx.Serializable} {
		for _, queried := range []bool{false, true} {
			tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: level})
			if err != nil {
				t.Fatal(err)
			}
			if queried {
				if _, err := tx.Exec(ctx, `SELECT FROM rbac_grants LIMIT 1`); err != nil {
					t.Fatal(err)
				}
			}
			for name, db := range map[string]rbac.DB{"the host's transaction": tx, "a wrapper around the host's transaction": hostTx{tx}} {
				check(fmt.Sprintf("%s at %s, queried %t", name, level, queried), db, false, string(level), string(level))
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestDeadlockedHostTransactionsConflict(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	ctx := t.Context()
	other := cluster
	other.ID = "c2"
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "owner"), grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "owner"),
		grant(other.Scope(), "cluster.admin", rbac.User, "owner"))
	// Each changes a cluster, holding its tenant's lock shared, then defines a role, which takes
	// it alone: each waits on the other, and PostgreSQL fails one.
	var applied, wg sync.WaitGroup
	applied.Add(2)
	errs := make(chan error, 2)
	for i, r := range []rbac.Resource{cluster, other} {
		wg.Go(func() {
			errs <- pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
				authz := h.authz.WithTx(tx)
				b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: fmt.Sprintf("u%d", i)}}
				err := authz.Apply(ctx, h.as(t, "owner"), r, rbac.Change{Grant: []rbac.Binding{b}})
				applied.Done()
				if err != nil {
					return err
				}
				applied.Wait()
				role := rbac.RoleDefinition{ID: rbac.Role(fmt.Sprintf("custom.r%d", i)), Permissions: []rbac.Permission{login}, ResourceTypes: []string{"cluster"}}
				return authz.SetRole(ctx, h.as(t, "owner"), "t1", role)
			})
		})
	}
	wg.Wait()
	close(errs)
	var conflicts int
	for err := range errs {
		switch {
		case errors.Is(err, rbac.ErrConflict):
			conflicts++
		case err != nil:
			t.Errorf("a deadlock should match ErrConflict: %v", err)
		}
	}
	if conflicts != 1 {
		t.Fatalf("%d transactions refused for the deadlock, want 1", conflicts)
	}
}

// waitedFor waits until some session waits for a lock on table, in the test's schema.
func waitedFor(t *testing.T, h *harness, table string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var waiting bool
		if err := h.pool.QueryRow(t.Context(), `SELECT EXISTS (SELECT FROM pg_locks WHERE NOT granted AND relation = $1::regclass)`, table).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session waited for %s", table)
		}
	}
}

// PostgreSQL refusing a call for a race matches ErrConflict wherever in the call it refused it, not
// only in a change's transaction: here every call waits for a lock past its session's
// lock_timeout, as for a migration holding every table, in the reads a change makes before its
// transaction, in a read, and in a change's transaction alike.
func TestEveryCallRefusedForALockItCouldntTakeConflicts(t *testing.T) {
	// So Migrate gives way at once, rather than try again for seconds.
	rbac.SetMigrateAttempts(t, 1, 0)
	h := setupOn(t, pgtest.Open(t, "lock_timeout=10"), withLabels, banks)
	ctx := t.Context()
	owner, ann := h.as(t, "owner"), h.as(t, "ann")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	granted := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "ann")}
	members := []rbac.Member{{Group: "g", Principal: ann.Principal}}
	onCluster := rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}
	calls := []struct {
		name string
		call func() error
	}{
		{"Apply", func() error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
		}},
		{"Import", func() error { return h.authz.Import(ctx, host, "t1", granted) }},
		{"SetDeny", func() error {
			return h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{ann.Principal}, Permissions: []rbac.Permission{login}})
		}},
		{"DeleteDeny", func() error { return h.authz.DeleteDeny(ctx, owner, cluster, "d") }},
		{"SetEligibility", func() error {
			return h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.login", Principal: ann.Principal, MaxDuration: time.Hour})
		}},
		{"DeleteEligibility", func() error { return h.authz.DeleteEligibility(ctx, owner, cluster, "cluster.login", ann.Principal) }},
		{"Activate", func() error {
			return second(h.authz.Activate(ctx, ann, cluster, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "on call"}))
		}},
		{"Deactivate", func() error { return h.authz.Deactivate(ctx, ann, cluster, "cluster.login") }},
		{"DeleteGrants", func() error { return h.authz.DeleteGrants(ctx, host, "t1", granted) }},
		{"DeleteScope", func() error { return h.authz.DeleteScope(ctx, host, "t1", cluster.Scope()) }},
		{"DeleteScopes", func() error { return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope()}) }},
		{"DeletePrincipal", func() error { return h.authz.DeletePrincipal(ctx, host, "t1", ann.Principal) }},
		{"DeletePrincipalEverywhere", func() error { return h.authz.DeletePrincipalEverywhere(ctx, host, ann.Principal) }},
		{"DeleteTenant", func() error { return h.authz.DeleteTenant(ctx, host, "t1") }},
		{"DeleteExpired", func() error { return second(h.authz.DeleteExpired(ctx)) }},
		{"SetMemberships", func() error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: ann.Principal}})
		}},
		{"SetGroup", func() error { return h.authz.SetGroup(ctx, owner, "t1", rbac.GroupDefinition{ID: "g"}) }},
		{"ImportGroups", func() error { return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "g"}}) }},
		{"DeleteGroup", func() error { return h.authz.DeleteGroup(ctx, owner, "t1", "g") }},
		{"DeleteGroups", func() error { return h.authz.DeleteGroups(ctx, host, "t1", []string{"g"}) }},
		{"ImportMembers", func() error { return h.authz.ImportMembers(ctx, host, "t1", members) }},
		{"ChangeMembers", func() error { return h.authz.ChangeMembers(ctx, owner, "t1", members, nil) }},
		{"DeleteMembers", func() error { return h.authz.DeleteMembers(ctx, host, "t1", members) }},
		{"SetRole", func() error {
			return h.authz.SetRole(ctx, owner, "t1", rbac.RoleDefinition{ID: "custom.r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}})
		}},
		{"DeleteRole", func() error { return h.authz.DeleteRole(ctx, owner, "t1", "custom.r") }},
		{"Authorize", func() error { return h.authz.Authorize(ctx, ann, view, cluster) }},
		{"Explain", func() error { return second(h.authz.Explain(ctx, ann, view, cluster)) }},
		{"Permissions", func() error { return second(h.authz.Permissions(ctx, ann, cluster)) }},
		{"Holders", func() error { return second(h.authz.Holders(ctx, view, cluster)) }},
		{"Reachable", func() error { return second(h.authz.Reachable(ctx, ann, view, "t1", "cluster")) }},
		{"Filter", func() error {
			return second(h.authz.Filter(ctx, ann, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1))
		}},
		{"Holding", func() error { return second(h.authz.Holding(ctx, "t1", ann)) }},
		{"Grantable", func() error { return second(h.authz.Grantable(ctx, owner, cluster)) }},
		{"Grants", func() error { return second(h.authz.Grants(ctx, "t1", onCluster)) }},
		{"Denies", func() error { return second(h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})) }},
		{"Eligibilities", func() error { return second(h.authz.Eligibilities(ctx, "t1", onCluster)) }},
		{"Conflicts", func() error { return second(h.authz.Conflicts(ctx, "t1")) }},
		{"Memberships", func() error { return second(h.authz.Memberships(ctx, "t1", nil)) }},
		{"MembershipsOf", func() error { return second(h.authz.MembershipsOf(ctx, ann.Principal)) }},
		{"Groups", func() error { return second(h.authz.Groups(ctx, "t1")) }},
		{"Members", func() error { return second(h.authz.Members(ctx, "t1", "g")) }},
		{"GroupsOf", func() error { return second(h.authz.GroupsOf(ctx, "t1", ann.Principal)) }},
		{"CustomRoles", func() error { return second(h.authz.CustomRoles(ctx, "t1")) }},
		{"Roles", func() error { return second(h.authz.Roles(ctx, "t1", "cluster")) }},
		{"AsOf", func() error { return h.authz.AsOf(ctx, "t1", h.now, func(*rbac.Authorizer) error { return nil }) }},
		{"History", func() error {
			_, _, err := h.authz.History(ctx, rbac.Cursor{}, 10)
			return err
		}},
		{"Export", func() error {
			_, _, err := h.authz.Export(ctx, rbac.Checkpoint{}, 10, key)
			return err
		}},
		{"PruneHistory", func() error { return second(rbac.PruneHistory(ctx, h.pool, h.now, rbac.Cursor{TxID: 1, ID: 1})) }},
		{"Migrate", func() error { return rbac.Migrate(ctx, h.pool) }},
	}
	// Every exported call that reads the database is here, so one added without mapping its races
	// fails below.
	checked := map[string]bool{}
	for _, c := range calls {
		checked[c.name] = true
	}
	authz := reflect.TypeFor[*rbac.Authorizer]()
	for i := range authz.NumMethod() {
		if m := authz.Method(i); m.Type.NumIn() > 1 && m.Type.In(1) == reflect.TypeFor[context.Context]() && !checked[m.Name] {
			t.Errorf("Authorizer.%s isn't checked for a lock it couldn't take", m.Name)
		}
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			// Held for this call alone, so no lock stands for longer than its wait.
			held, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := held.Exec(ctx, `SET LOCAL lock_timeout = 0; LOCK TABLE rbac_grants, rbac_roles, rbac_denies, rbac_eligibilities,
				rbac_memberships, rbac_groups, rbac_members, rbac_history, rbac_migrations IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			err = c.call()
			if pg := (*pgconn.PgError)(nil); !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "55P03" {
				t.Errorf("%s refused for a lock it couldn't take: %v", c.name, err)
			}
		})
	}
}

// Under WithTx, the reads a change makes before its savepoint run on the host's transaction itself,
// so they can deadlock with a migration holding the package's tables that waits for a table the
// host's transaction holds: PostgreSQL ends the change, which matches ErrConflict as one it ends in
// the savepoint does, and the host's transaction is left aborted, to be run again from its start.
func TestAChangeDeadlockedBeforeItsSavepointConflicts(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, ann := h.as(t, "owner"), h.as(t, "ann")
	if _, err := h.pool.Exec(ctx, `CREATE TABLE host_rows (id int)`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE host_rows IN EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	migration, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = migration.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := migration.Exec(ctx, `LOCK TABLE rbac_grants IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	applied := make(chan error, 1)
	go func() {
		applied <- h.authz.WithTx(tx).Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
	}()
	// The change waits for the migration first, so its deadlock_timeout passes first and PostgreSQL
	// ends it, not the migration.
	waitedFor(t, h, "rbac_grants")
	locked := make(chan error, 1)
	go func() {
		_, err := migration.Exec(ctx, `LOCK TABLE host_rows IN ACCESS EXCLUSIVE MODE`)
		locked <- err
	}()
	err = <-applied
	if pg := (*pgconn.PgError)(nil); !errors.Is(err, rbac.ErrConflict) || !errors.As(err, &pg) || pg.Code != "40P01" {
		t.Fatalf("a change PostgreSQL ended as a deadlock before its savepoint: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1`); err == nil {
		t.Error("the host's transaction ran a statement after the deadlock")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-locked; err != nil {
		t.Fatal(err)
	}
}

// A hook's error that wraps PostgreSQL's refusal of a statement for a race, as a deadlock of a query
// it ran, matches ErrConflict too, wherever the hook runs, still wrapping the host's own error, and
// OnRefused isn't told of it: ValidateGrant, asked before a change's transaction, and a constraint a
// check asks. So does one that wraps or joins the race after another of PostgreSQL's errors, where
// errors.As finds only that one, or after a thousand others, or ten thousand values each equal to
// the one before, and one that holds it as errors.As reads it, through an As method; one holding no
// race doesn't.
func TestAHooksErrorForARaceConflicts(t *testing.T) {
	errPolicy := errors.New("policy lookup failed")
	deadlock := &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
	duplicate := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	var hookErr error
	var refusals []rbac.Refusal
	h := setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(context.Context, rbac.DB, rbac.GrantInput) error { return hookErr }
		c.Constraints = []rbac.Constraint{{Name: "policy", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Permission == view {
				return false, hookErr
			}
			return false, nil
		}}}
		c.OnRefused = func(_ context.Context, r rbac.Refusal) { refusals = append(refusals, r) }
	})
	ctx := t.Context()
	ann := h.as(t, "ann")
	calls := func() map[string]error {
		return map[string]error{
			"Apply":     h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}}),
			"Authorize": h.authz.Authorize(ctx, ann, view, cluster),
		}
	}
	for how, race := range map[string]error{
		"wrapped":                        fmt.Errorf("%w: %w", errPolicy, deadlock),
		"wrapped after another":          fmt.Errorf("%w: %w; %w", errPolicy, duplicate, deadlock),
		"joined after another":           errors.Join(errPolicy, duplicate, deadlock),
		"joined before another":          errors.Join(deadlock, duplicate, errPolicy),
		"nested after another":           errors.Join(errPolicy, duplicate, fmt.Errorf("retrying: %w", deadlock)),
		"held through As":                errors.Join(duplicate, heldAsError{errPolicy, deadlock}),
		"joined after a thousand others": errors.Join(slices.Concat([]error{errPolicy}, slices.Repeat([]error{duplicate}, 1000), []error{deadlock})...),
		// Past those an ordinary tree holds, where each error is read once: the last is read, as it
		// wraps another error, though it reads as the others.
		"joined after ten thousand values": errors.Join(slices.Concat([]error{errPolicy},
			slices.Repeat([]error{valueWrapError{"retrying", duplicate}}, 10000), []error{valueWrapError{"retrying", deadlock}})...),
	} {
		hookErr = race
		for name, err := range calls() {
			if !errors.Is(err, rbac.ErrConflict) || !errors.Is(err, errPolicy) || errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("%s, whose hook failed for a race %s: %.1000v", name, how, err)
			}
		}
	}
	if len(refusals) > 0 {
		t.Errorf("OnRefused was told of a race: %+v", refusals)
	}
	hookErr = errors.Join(errPolicy, duplicate)
	for name, err := range calls() {
		if errors.Is(err, rbac.ErrConflict) || !errors.Is(err, errPolicy) {
			t.Errorf("%s, whose hook failed for no race: %v", name, err)
		}
	}
}

// heldAsError is a host's error that holds PostgreSQL's as errors.As reads it, through its As
// method, rather than by wrapping it.
type heldAsError struct {
	error
	pg *pgconn.PgError
}

func (e heldAsError) Unwrap() error { return e.error }

func (e heldAsError) As(target any) bool {
	pg, ok := target.(**pgconn.PgError)
	if ok {
		*pg = e.pg
	}
	return ok
}

// A hook's error nesting thousands of values that wrap errors, rather than pointers, is read in time
// growing with its depth, as errors.Is reads it, not with its square, as it would be if each error
// read were remembered from the first, which compares it whole, all it wraps too.
func TestAHooksErrorNestingValuesIsReadInItsDepth(t *testing.T) {
	var err error = &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
	for i := range 5000 {
		err = valueWrapError{fmt.Sprint("try ", i), err}
	}
	start := time.Now()
	got := rbac.Conflicted(err)
	if elapsed := time.Since(start); !errors.Is(got, rbac.ErrConflict) || elapsed > time.Second {
		t.Fatalf("a race under 5,000 values took %v to find: %.100v", elapsed, got)
	}
}

// valueWrapError is a host's error that wraps another as a value, not a pointer.
type valueWrapError struct {
	msg string
	err error
}

func (e valueWrapError) Error() string { return e.msg }
func (e valueWrapError) Unwrap() error { return e.err }

// A hook's error whose tree holds itself, as a host's type wrapping itself by mistake can, through
// Unwrap or joined beside itself, is read round only so far, and from then on each of its errors
// once, wherever a call reads it, and the call returns: matching ErrConflict where it holds a race,
// as errors.As reads one, or ErrConflict, before itself or after, ErrConflict first in what the call
// returns, so errors.Is finds it there, as it wouldn't past the error holding itself; and a change
// ValidateGrant refuses beside it is refused as invalid, which OnRefused is told of, but of no
// other. Each kind of error runs in a child process, so one read forever, or until the stack
// overflows, which kills the process, fails this test rather than the test binary, and each call
// there is given a while.
func TestAHooksErrorHoldingItselfIsReadOnce(t *testing.T) {
	if how := os.Getenv("RBAC_HOOK_ERROR_HOLDING_ITSELF"); how != "" {
		// So that reading it forever overflows the stack in a moment rather than a gigabyte.
		debug.SetMaxStack(64 << 20)
		var pg *pgconn.PgError
		var held error
		switch {
		case strings.Contains(how, "a race"):
			pg = &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
			held = pg
		case strings.Contains(how, "a conflict"):
			held = fmt.Errorf("an earlier change: %w", rbac.ErrConflict)
		}
		race := held != nil
		hookErr := error(&wrapsItselfError{pg})
		if strings.HasPrefix(how, "joining") {
			hookErr = &joinsItselfError{held, strings.HasSuffix(how, "after")}
		}
		down, lost := rbac.Scope{Type: "cluster", ID: "down"}, rbac.Scope{Type: rbac.GroupScope, ID: "lost"}
		manager := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
		var constraintErr, validateErr error
		refusals := 0
		h := labeled(t, func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), groupMembers, manager)
			validate := c.ValidateGrant
			c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
				return cmp.Or(validateErr, validate(ctx, q, in))
			}
			c.Constraints = append(c.Constraints, rbac.Constraint{Name: "policy", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) {
				return false, constraintErr
			}})
			resourceOf := c.ResourceOf
			c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
				if s == down || s == lost {
					return rbac.Resource{}, hookErr
				}
				return resourceOf(ctx, tenant, s)
			}
			c.OnRefused = func(context.Context, rbac.Refusal) { refusals++ }
		})
		ctx := t.Context()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}')`); err != nil {
			t.Fatal(err)
		}
		h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"),
			grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.sudo", rbac.User, "admin"),
			grant(down, "cluster.login", rbac.Group, "ops"), grant(down, "custom.viewer", rbac.User, "u"))
		h.join(t, "u")
		h.groups(t, "lost")
		if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("u")}, {Group: "lost", Principal: identity("u")}}); err != nil {
			t.Fatal(err)
		}
		admin, ann, owner := h.as(t, "admin"), h.as(t, "ann"), h.as(t, "owner")
		h.hold(t, "admin", "level:high")
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		apply := func() error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
		}
		// Each call's error is read by the test in the while it is given, as a call that returns it
		// unmapped would have errors.Is read it forever.
		read := func(name string, call func() error, refused bool) {
			t.Log(name)
			before := refusals
			type got struct {
				err                 error
				conflicted, invalid bool
			}
			done := make(chan got, 1)
			go func() {
				err := call()
				g := got{err: err}
				if race {
					g.conflicted = errors.Is(err, rbac.ErrConflict)
				}
				if refused {
					g.invalid = errors.Is(err, rbac.ErrInvalid)
				}
				done <- g
			}()
			select {
			case g := <-done:
				if g.err == nil || g.conflicted != race || g.invalid != refused || (refusals > before) != refused {
					t.Errorf("%s, whose hook's error is %s itself: %v", name, how, g.err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("%s, whose hook's error is %s itself, read it forever", name, how)
			}
			constraintErr, validateErr = nil, nil
		}
		constraintErr = hookErr
		read("Authorize, through a constraint", func() error { return h.authz.Authorize(ctx, ann, view, cluster) }, false)
		constraintErr = hookErr
		read("Apply, through a constraint", apply, false)
		validateErr = hookErr
		read("Apply, through ValidateGrant", apply, false)
		validateErr = errors.Join(rbac.ErrInvalid, hookErr)
		read("Apply, refused by ValidateGrant", apply, true)
		read("ChangeMembers, reading the group", func() error {
			return h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "lost", Principal: identity("u")}})
		}, false)
		read("ChangeMembers, reading a scope the group has access on", func() error {
			return h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "ops", Principal: identity("u")}})
		}, false)
		read("DeleteRole, reading a scope it is granted on", func() error { return h.authz.DeleteRole(ctx, admin, "t1", "custom.viewer") }, false)
		read("Checkpoint.Sign, through the signer", func() error { return second(rbac.Genesis("g").Sign(racedSigner{key, hookErr})) }, false)
		return
	}
	pgtest.URL(t)
	for _, how := range []string{"wrapping a race", "joining a race", "joining a race after", "joining a conflict after", "wrapping", "joining"} {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAHooksErrorHoldingItselfIsReadOnce$", "-test.v")
		cmd.Env = append(os.Environ(), "RBAC_HOOK_ERROR_HOLDING_ITSELF="+how)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Errorf("%s: %v\n%.4000s", how, err, out)
		}
	}
}

// wrapsItselfError wraps itself, and holds PostgreSQL's error as errors.As reads it, if any.
type wrapsItselfError struct{ pg *pgconn.PgError }

func (*wrapsItselfError) Error() string   { return "wraps itself" }
func (e *wrapsItselfError) Unwrap() error { return e }

func (e *wrapsItselfError) As(target any) bool {
	pg, ok := target.(**pgconn.PgError)
	if ok && e.pg != nil {
		*pg = e.pg
		return true
	}
	return false
}

// joinsItselfError joins itself and the error it holds, if any, before it or after.
type joinsItselfError struct {
	held  error
	after bool
}

func (*joinsItselfError) Error() string { return "joins itself" }

func (e *joinsItselfError) Unwrap() []error {
	switch {
	case e.held == nil:
		return []error{e}
	case e.after:
		return []error{e, e.held}
	}
	return []error{e.held, e}
}

func TestPublicAccess(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer) })
	ctx := t.Context()
	resources := hostTable(t, h)
	public := rbac.Principal{Kind: rbac.Public}
	h.seed(t,
		grant(workspace.Scope(), "workspace.admin", rbac.User, "admin"),
		grant(workspace.Scope(), "cluster.admin", rbac.User, "admin"),
	)
	if err := h.authz.Apply(ctx, h.as(t, "admin"), workspace, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.viewer", Principal: public}}}); err != nil {
		t.Fatalf("granting a public role to the public: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "admin"), workspace, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: public}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting a role not marked public to the public: %v", err)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.Public, "")}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing a role not marked public for the public: %v", err)
	}

	anonymous := rbac.Subject{}
	stranger := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "stranger"}}
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's member": stranger, "a member": h.as(t, "nobody")} {
		if !allowed(t, h, s, view, cluster) {
			t.Errorf("%s: no public access", name)
		}
		if allowed(t, h, s, login, cluster) || allowed(t, h, s, root, cluster) {
			t.Errorf("%s: more than the public role gives", name)
		}
		if perms, err := h.authz.Permissions(ctx, s, cluster); err != nil || !slices.Equal(perms, []rbac.Permission{view}) {
			t.Errorf("%s: Permissions = %v, %v", name, perms, err)
		}
		listingsAgree(t, h, resources, s, view)
		listingsAgree(t, h, resources, s, grantC)
	}
	if d, err := h.authz.Explain(ctx, anonymous, view, cluster); err != nil || len(d.Grants) != 1 || d.Grants[0].Principal != public {
		t.Errorf("Explain = %+v, %v", d, err)
	}
	if holders, err := h.authz.Holders(ctx, view, cluster); err != nil || !slices.Contains(holderPrincipals(holders), public) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's member": stranger} {
		if err := h.authz.Apply(ctx, s, workspace, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s changed access: %v", name, err)
		}
	}

	if err := h.authz.DeletePrincipal(ctx, host, "t1", public); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("deleting the public's grants should end public access")
	}
}

func TestADenyBindsAnIdentityThatIsntAMember(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, guardRole) })
	ctx := t.Context()
	resources := hostTable(t, h)
	// Everyone signed in may view, and a deny on one cluster names one who isn't a member.
	o1 := rbac.Scope{Type: "org", ID: "o1"}
	signedIn := grant(o1, "cluster.viewer", rbac.Public, "")
	signedIn.Condition = rbac.Condition{Expression: `subject.id != ""`}
	h.seed(t, signedIn, grant(resources[0].Scope(), "guard", rbac.User, "guardian"))
	stranger := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "stranger"}}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{stranger.Principal}, Permissions: []rbac.Permission{view}}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), resources[0], d); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, stranger, view, resources[0]) || !allowed(t, h, stranger, view, resources[1]) {
		t.Fatal("a deny naming an identity should bind it, member or not")
	}
	if dec, err := h.authz.Explain(ctx, stranger, view, resources[0]); err != nil || dec.DeniedBy == "" {
		t.Fatalf("Explain = %+v, %v", dec, err)
	}
	// Where anyone may view, signed in or not, the lists keep to the deny too.
	h.seed(t, grant(o1, "cluster.viewer", rbac.Public, ""))
	listingsAgree(t, h, resources, stranger, view)
}

func TestAPublicGrantGivesOnlyWhileItsRoleIsPublic(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer) })
	ctx := t.Context()
	resources := hostTable(t, h)
	public := rbac.Principal{Kind: rbac.Public}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.viewer", rbac.Public, ""))

	// As if a later catalog made the role privileged, which a public role can't be.
	viewer.Public, viewer.Privileged, viewer.Permissions = false, true, []rbac.Permission{view, root}
	later, err := rbac.New(h.pool, rbac.Config{
		Catalog: append(slices.Clone(catalog), viewer), ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
		Now:           func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.authz = later
	for name, s := range map[string]rbac.Subject{"anonymous": {}, "a member": h.as(t, "nobody")} {
		if allowed(t, h, s, view, cluster) || allowed(t, h, s, root, cluster) {
			t.Errorf("%s: a grant to the public of a role no longer public gives", name)
		}
		if perms, err := h.authz.Permissions(ctx, s, cluster); err != nil || len(perms) != 0 {
			t.Errorf("%s: Permissions = %v, %v", name, perms, err)
		}
		for _, p := range []rbac.Permission{view, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
	if holders, err := h.authz.Holders(ctx, root, cluster); err != nil || slices.Contains(holderPrincipals(holders), public) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
}

func TestHostsCanRefusePublicAccess(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), viewer)
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			p := in.Binding.Principal
			if p.Kind == rbac.Public {
				return fmt.Errorf("%w: public access is off", rbac.ErrInvalid)
			}
			return nil
		}
	})
	b := rbac.Binding{Role: "cluster.viewer", Principal: rbac.Principal{Kind: rbac.Public}}
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a public grant the host refuses: %v", err)
	}
}

func TestMachineIdentities(t *testing.T) {
	const machine rbac.PrincipalKind = "service_account"
	h := setup(t, func(c *rbac.Config) { c.PrincipalKinds = []rbac.PrincipalKind{machine} })
	ctx := t.Context()
	ci := h.member(t, rbac.Principal{Kind: machine, ID: "ci"})
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.admin", Principal: ci.Principal}}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, ci, root, cluster) {
		t.Fatal("a service account holds what it is granted")
	}
	if allowed(t, h, h.as(t, "ci"), root, cluster) {
		t.Fatal("a user with the service account's id holds its grants")
	}

	h.events = nil
	u := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := h.authz.Apply(ctx, ci, cluster, rbac.Change{Grant: []rbac.Binding{u}}); err != nil {
		t.Fatalf("a service account changing access: %v", err)
	}
	if len(h.events) != 1 || h.events[0].Actor != ci.Principal {
		t.Fatalf("events = %+v", h.events)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u.Principal}}); err != nil || len(got) != 1 || got[0].CreatedBy != ci.Principal {
		t.Fatalf("Grants = %+v, %v", got, err)
	}

	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"))
	if !allowed(t, h, h.member(t, rbac.Principal{Kind: machine, ID: "bot"}), login, cluster) {
		t.Fatal("a service account is one of the tenant's members")
	}

	robot := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: "robot", ID: "r"}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{robot}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting an undeclared kind: %v", err)
	}
	// A kind the host stops declaring can still be revoked, and holds nothing, its own grants nor
	// its groups'.
	h.member(t, ci.Principal, "bots")
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "bots"))
	undeclared, err := rbac.New(h.pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if holders, err := undeclared.Holders(ctx, root, cluster); err != nil || slices.Contains(holderPrincipals(holders), ci.Principal) {
		t.Fatalf("Holders lists a kind no longer declared: %v, %v", holders, err)
	}
	revoke := rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.admin", Principal: ci.Principal}}}
	if err := undeclared.Apply(ctx, h.as(t, "owner"), cluster, revoke); err != nil {
		t.Fatalf("revoking a kind no longer declared: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{ci.Principal}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestTheTableRefusesMalformedPrincipals(t *testing.T) {
	h := setup(t)
	for _, p := range []rbac.Principal{
		{Kind: rbac.Public, ID: "x"},
		{Kind: rbac.Members, ID: "t2"},
		{Kind: rbac.Members},
		{Kind: rbac.User},
		{Kind: "Service Account", ID: "x"},
		{Kind: rbac.PrincipalKind(strings.Repeat("k", 64)), ID: "x"},
	} {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'cluster', 'c1', $1, $2, 'cluster.login')`, p.Kind, p.ID); err == nil {
			t.Errorf("stored a grant to %+v", p)
		}
	}
	if err := h.authz.DeletePrincipal(t.Context(), host, "t1", rbac.Principal{}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("DeletePrincipal of no one: %v", err)
	}
}

func TestTheTableKeepsOneActivation(t *testing.T) {
	h := setup(t)
	for i := range 2 {
		_, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at)
			VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.sudo', $1, $2)`, rbac.SourceActivation, h.now.Add(time.Duration(i+1)*time.Hour))
		if (err == nil) != (i == 0) {
			t.Fatalf("activation %d of one role on one scope: %v", i+1, err)
		}
	}
}

func TestGrantableRolesLimitWhatAManagerChanges(t *testing.T) {
	access := rbac.RoleDefinition{
		ID: "cluster.access", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"},
		GrantableRoles: []rbac.Role{"cluster.login"},
	}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), access) })
	ctx := t.Context()
	h.seed(t,
		grant(cluster.Scope(), "cluster.access", rbac.User, "manager"),
		grant(cluster.Scope(), "cluster.sudo", rbac.User, "y"),
	)
	b := func(role rbac.Role, id string) rbac.Binding {
		return rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: id}}
	}
	apply := func(c rbac.Change) error { return h.authz.Apply(ctx, h.as(t, "manager"), cluster, c) }
	if err := apply(rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}}); err != nil {
		t.Fatalf("granting a listed role without holding it: %v", err)
	}
	if !allowed(t, h, h.as(t, "x"), login, cluster) {
		t.Fatal("the listed role should be granted")
	}
	if err := apply(rbac.Change{Grant: []rbac.Binding{b("cluster.access", "z")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting an unlisted role whose permissions the manager holds: %v", err)
	}
	if err := apply(rbac.Change{Revoke: []rbac.Binding{b("cluster.sudo", "y")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("revoking an unlisted role: %v", err)
	}
	if err := apply(rbac.Change{Revoke: []rbac.Binding{b("cluster.login", "x")}}); err != nil {
		t.Fatalf("revoking a listed role: %v", err)
	}

	roles := func(s rbac.Subject) []rbac.Role {
		t.Helper()
		got, err := h.authz.Grantable(ctx, s, cluster)
		if err != nil {
			t.Fatal(err)
		}
		var ids []rbac.Role
		for _, r := range got {
			ids = append(ids, r.ID)
		}
		return ids
	}
	if got := roles(h.as(t, "manager")); !slices.Equal(got, []rbac.Role{"cluster.login"}) {
		t.Errorf("the manager's Grantable = %v", got)
	}
	if got := roles(h.as(t, "owner")); !slices.Equal(got, []rbac.Role{"cluster.admin", "cluster.sudo", "cluster.login", "cluster.access"}) {
		t.Errorf("the admin's Grantable = %v", got)
	}
	if got := roles(h.as(t, "y")); len(got) != 0 {
		t.Errorf("Grantable without a grant permission = %v", got)
	}
}

func TestGrantableAppliesConstraints(t *testing.T) {
	h := setup(t, constrain("managed elsewhere", grantC))
	if got, err := h.authz.Grantable(t.Context(), h.as(t, "owner"), cluster); err != nil || len(got) != 0 {
		t.Fatalf("Grantable where a constraint removes cluster:grant = %v, %v", got, err)
	}
}

func TestIdentitiesFromOtherTenants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// A guest, such as from another tenant, in this one's group of partners.
	partner := h.guest(t, "partner", "partners")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"))
	if allowed(t, h, partner, login, cluster) {
		t.Fatal("another tenant's member is one of this tenant's members")
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "cluster.login", Principal: partner.Principal},
	}}); err != nil {
		t.Fatalf("granting an identity from another tenant: %v", err)
	}
	if !allowed(t, h, partner, login, cluster) {
		t.Fatal("a grant to another tenant's member should reach it")
	}
	h.groups(t, "partners")
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.Group, ID: "partners"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, partner, root, cluster) {
		t.Fatal("a grant to another tenant's group should reach its members")
	}
	outsider := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "outsider2"}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{outsider}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an identity the host doesn't let in: %v", err)
	}

	if err := h.authz.Import(ctx, host, "t2", []rbac.Grant{grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "partner")}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, partner.Principal); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || h.events[0].Tenant != "t1" || h.events[1].Tenant != "t2" {
		t.Fatalf("one change per tenant: %+v", h.events)
	}
	for _, tenant := range []string{"t1", "t2"} {
		if got, err := h.authz.Grants(ctx, tenant, rbac.GrantFilter{Principals: []rbac.Principal{partner.Principal}}); err != nil || len(got) != 0 {
			t.Fatalf("%s: Grants = %+v, %v", tenant, got, err)
		}
	}
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}, {}} {
		if err := h.authz.DeletePrincipalEverywhere(ctx, host, p); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeletePrincipalEverywhere(%+v): %v", p, err)
		}
	}
}

func TestGrantingARoleNeedsItsPowerToChangeGrants(t *testing.T) {
	share := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	helpdesk := rbac.RoleDefinition{ID: "cluster.helpdesk", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.sudo"}}
	access := rbac.RoleDefinition{ID: "cluster.access", Permissions: []rbac.Permission{view, login, root, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	relay := rbac.RoleDefinition{ID: "cluster.relay", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.relay", "cluster.login"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), share, helpdesk, access, relay) })
	ctx := t.Context()
	h.seed(t,
		grant(cluster.Scope(), "cluster.share", rbac.User, "sharer"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "sharer"),
		grant(workspace.Scope(), "workspace.admin", rbac.User, "m"),
		grant(workspace.Scope(), "cluster.access", rbac.User, "m"),
	)
	self := func(id string, role rbac.Role) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: id}}}}
	}

	// Holding what a role lists isn't holding what its holders may grant through it, and the
	// refusal names what the actor lacks.
	var denied *rbac.DeniedError
	if err := h.authz.Apply(ctx, h.as(t, "sharer"), cluster, self("sharer", "cluster.helpdesk")); !errors.As(err, &denied) || denied.Permission != root {
		t.Fatalf("granting a role that lets its holders grant sudo, without root: %v", err)
	}
	// A grant permission limited to some roles isn't the unlimited one a role without a list gives.
	if err := h.authz.Apply(ctx, h.as(t, "m"), workspace, self("m", "cluster.admin")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("turning a limited grant permission into an unlimited one: %v", err)
	}
	creator := rbac.Binding{Role: "cluster.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "owner"}}
	if err := h.authz.Apply(ctx, h.as(t, "m"), cluster, rbac.Change{Revoke: []rbac.Binding{creator}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a limited manager revoking a role it doesn't list: %v", err)
	}
	// A role listing itself and roles the actor may grant needs nothing more: its holders pass
	// on only what it gives.
	if err := h.authz.Apply(ctx, h.as(t, "sharer"), cluster, self("x", "cluster.relay")); err != nil {
		t.Fatalf("granting a role that lists itself: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "x"), cluster, self("y", "cluster.relay")); err != nil {
		t.Fatalf("a holder passing the role on: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "x"), cluster, self("y", "cluster.sudo")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a holder granting a role it doesn't list: %v", err)
	}
	if got, err := h.authz.Grantable(ctx, h.as(t, "sharer"), cluster); err != nil || slices.ContainsFunc(got, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.helpdesk" }) {
		t.Fatalf("Grantable offers a role whose listed roles the actor can't grant: %v, %v", got, err)
	}
}

func TestAListedRoleCountsOnlyWhereItCanBeGranted(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "workspace.viewer", Permissions: []rbac.Permission{"workspace:view"}, ResourceTypes: []string{"workspace"}}
	// Its cluster:grant can't hand out the workspace role it lists: a cluster can't take it.
	manager := rbac.RoleDefinition{
		ID: "manager", Permissions: []rbac.Permission{"workspace:grant", grantC}, ResourceTypes: []string{"workspace", "cluster"},
		GrantableRoles: []rbac.Role{"workspace.viewer"},
	}
	clusters := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, manager, clusters) })
	org := rbac.Scope{Type: "org", ID: "o1"}
	h.seed(t, grant(org, "workspace.admin", rbac.User, "a"), grant(org, "cluster.share", rbac.User, "a"))
	b := rbac.Binding{Role: "manager", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(t.Context(), h.as(t, "a"), workspace, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("granting a role whose listed role only workspaces take: %v", err)
	}
}

func TestRolesListingEachOtherAreDecidedOnce(t *testing.T) {
	var ids []rbac.Role
	for i := range 12 {
		ids = append(ids, rbac.Role(fmt.Sprintf("cluster.team%d", i)))
	}
	var team []rbac.RoleDefinition
	for _, id := range ids {
		team = append(team, rbac.RoleDefinition{ID: id, Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: ids})
	}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), team...) })
	// Each role is checked once per grant: along every order they reach each other in, this
	// would take hours.
	got, err := h.authz.Grantable(t.Context(), h.as(t, "owner"), cluster)
	if err != nil || len(got) != len(h.authz.BuiltinRoles("cluster")) {
		t.Fatalf("Grantable = %d roles, %v", len(got), err)
	}
}

// What a refused grant checked on its way is forgotten, as some passed only while it was in
// progress: a later grant in the same change resting on it is decided afresh.
func TestARefusedGrantProvesNothingForTheNext(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// custom.a lists custom.b, which lists it back; custom.a also gives root, which lead lacks.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES
		('t1', 'custom.a', '{cluster:grant,cluster:root}', '{cluster}', '{custom.b}'),
		('t1', 'custom.b', '{cluster:grant,cluster:view}', '{cluster}', '{custom.a}'),
		('t1', 'custom.lead', '{cluster:view,cluster:login,cluster:grant}', '{cluster}', '{}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.lead", rbac.User, "lead"))
	lead := h.as(t, "lead")
	err := h.authz.Apply(ctx, lead, cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "custom.a", Principal: identity("p1")}, {Role: "custom.b", Principal: identity("p2")},
	}})
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("want both grants refused, got %v", err)
	}
	var refused []string
	for _, e := range joined.Unwrap() {
		var denied *rbac.DeniedError
		if errors.As(e, &denied) {
			refused = append(refused, denied.Reason)
		}
	}
	if len(refused) != 2 || !strings.Contains(refused[1], "grant custom.b") {
		t.Fatalf("granting custom.b, whose holders may grant custom.a, after custom.a was refused: %q", refused)
	}
}

// A refused grant's reason names the constraint its own decision found removing what it lacks,
// whatever order the change lists its grants in: not one that a grant before or after it found
// removing the same permission on another type, where the actor never held it for this one's, nor,
// where two constraints each remove it on a type of their own, the other; and one removing the
// power to change grants that a role it grants gives, where the actor holds that power.
func TestARefusalNamesOnlyTheConstraintThatRemovedWhatItLacks(t *testing.T) {
	onWorkspaces, onClusters, granting := "no root on workspaces", "no root on clusters", "no granting on clusters"
	removing := func(name string, p rbac.Permission, on string) rbac.Constraint {
		return rbac.Constraint{Name: name, Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == p && in.ResourceType == on, nil
		}}
	}
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{removing(onWorkspaces, root, "workspace"), removing(onClusters, root, "cluster"), removing(granting, grantC, "cluster")}
	})
	ctx := t.Context()
	// custom.c needs root for clusters, custom.w and custom.v for workspaces, and custom.g the power
	// to change grants on clusters.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES
		('t1', 'custom.hold', '{workspace:view,workspace:grant,cluster:root}', '{workspace}'),
		('t1', 'custom.both', '{workspace:view,workspace:grant,cluster:root,cluster:grant}', '{workspace,cluster}'),
		('t1', 'custom.c', '{cluster:root}', '{cluster}'),
		('t1', 'custom.w', '{cluster:root}', '{workspace}'),
		('t1', 'custom.v', '{workspace:view,cluster:root}', '{workspace}'),
		('t1', 'custom.g', '{cluster:grant}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	// lead holds root for workspaces alone, and boss for clusters too, and the power there.
	lead, boss := h.as(t, "lead"), h.as(t, "boss")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'workspace', 'w1', 'user', 'lead', 'custom.hold'), ('t1', 'workspace', 'w1', 'user', 'boss', 'custom.both')`); err != nil {
		t.Fatal(err)
	}
	orders := [][]rbac.Role{{}}
	for range 4 {
		var longer [][]rbac.Role
		for _, order := range orders {
			for _, role := range []rbac.Role{"custom.c", "custom.w", "custom.v", "custom.g"} {
				if !slices.Contains(order, role) {
					longer = append(longer, append(slices.Clone(order), role))
				}
			}
		}
		orders = longer
	}
	for _, actor := range []struct {
		s rbac.Subject
		// clusters is what custom.c's refusal names, and grants custom.g's.
		clusters, grants string
	}{{lead, "", ""}, {boss, onClusters, granting}} {
		want := map[rbac.Role]string{"custom.c": actor.clusters, "custom.w": onWorkspaces, "custom.v": onWorkspaces, "custom.g": actor.grants}
		for _, order := range orders {
			var grants []rbac.Binding
			for i, role := range order {
				grants = append(grants, rbac.Binding{Role: role, Principal: identity(fmt.Sprint("p", i))})
			}
			err := h.authz.Apply(ctx, actor.s, workspace, rbac.Change{Grant: grants})
			joined, ok := err.(interface{ Unwrap() []error })
			if !ok || len(joined.Unwrap()) != len(order) {
				t.Fatalf("%s granting %v: want each refused, got %v", actor.s.Principal.ID, order, err)
			}
			for i, e := range joined.Unwrap() {
				var denied *rbac.DeniedError
				if !errors.As(e, &denied) {
					t.Fatalf("%s granting %v: %v", actor.s.Principal.ID, order, e)
				}
				named := ""
				for _, c := range []string{onWorkspaces, onClusters, granting} {
					if strings.Contains(denied.Reason, c) {
						named = c
					}
				}
				if named != want[order[i]] {
					t.Errorf("%s granting %v, %s refused naming %q, not %q: %s", actor.s.Principal.ID, order, order[i], named, want[order[i]], denied.Reason)
				}
			}
		}
	}
}

// Grantable and Apply read what the actor holds for each permission and type once, whatever the
// number of roles they decide that give it, and a role it holds giving many permissions once too,
// rather than for each role, permission and type.
func TestDecidingManyLargeRolesReadsWhatTheActorHoldsOnce(t *testing.T) {
	const types, verbs, roles = 10, 10, 30
	var ts []string
	var perms []rbac.Permission
	for i := range types {
		ty := fmt.Sprintf("t%02d", i)
		ts = append(ts, ty)
		for v := range verbs {
			perms = append(perms, rbac.Permission(fmt.Sprintf("%s:v%02d", ty, v)))
		}
	}
	all := append([]rbac.Permission{rbac.GrantPermission(rbac.TenantScope)}, perms...)
	for _, ty := range ts {
		all = append(all, rbac.GrantPermission(ty))
	}
	everything := rbac.RoleDefinition{ID: "everything", Permissions: all, ResourceTypes: append(slices.Clone(ts), rbac.TenantScope), Privileged: true}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = []rbac.RoleDefinition{everything}
		c.ContainerTypes = []string{"org"}
		c.Constraints = []rbac.Constraint{{Name: "none", Deny: func(context.Context, rbac.DB, rbac.ConstraintInput) (bool, error) { return false, nil }}}
	})
	ctx := t.Context()
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	h.seed(t, grant(tenant.Scope(), everything.ID, rbac.User, "boss"))
	boss := h.as(t, "boss")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		SELECT 't1', 'custom.r' || i, $1::text[], $2::text[] FROM generate_series(1, $3) i`, perms, ts, roles); err != nil {
		t.Fatal(err)
	}
	read := 0
	rbac.SetReadingEntries(t, func(n int) { read += n })
	offered, err := h.authz.Grantable(ctx, boss, tenant)
	if err != nil || len(offered) != roles+1 {
		t.Fatalf("Grantable offered %d roles: %v", len(offered), err)
	}
	// Each permission for each list of types its roles are for: what the actor's grants give, and
	// what the constraints answered; and the held role's entries once.
	once := len(perms)*types + len(all)*(types+1)
	if read > 3*once {
		t.Errorf("Grantable read %d entries deciding %d roles of %d permissions for %d types", read, roles+1, len(perms), types)
	}
	var c rbac.Change
	for _, r := range offered[1:] {
		c.Grant = append(c.Grant, rbac.Binding{Role: r.ID, Principal: identity("target")})
	}
	h.as(t, "target")
	read = 0
	if err := h.authz.Apply(ctx, boss, tenant, c); err != nil {
		t.Fatal(err)
	}
	// Its roles' permissions and types again in its transaction, but what the constraints answered,
	// and each role as it is then with the role as it was.
	if read > 3*once+4*roles*(len(perms)+types) {
		t.Errorf("Apply read %d entries granting %d roles of %d permissions for %d types", read, roles, len(perms), types)
	}
	if !allowed(t, h, h.as(t, "target"), perms[len(perms)-1], rbac.Resource{Tenant: "t1", Type: ts[types-1], ID: "x"}) {
		t.Error("the roles granted give nothing")
	}
}

func TestManyGrantsOfARoleAreDecidedOnce(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// Roles each listing many of the others, whose power to grant them a grant of one hands on, the
	// last giving root too, and one for whoever may grant them all but that.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
		SELECT 't1', 'custom.r' || i, '{cluster:view,cluster:login,cluster:grant}'::text[] || CASE WHEN i = 199 THEN '{cluster:root}' ELSE '{}' END::text[],
		  '{cluster}'::text[], ARRAY(SELECT 'custom.r' || ((i + j) % 200) FROM generate_series(1, 64) j)
		FROM generate_series(0, 199) i
		UNION ALL SELECT 't1', 'custom.lead', '{cluster:view,cluster:login,cluster:grant}', '{cluster}', '{}'`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.lead", rbac.User, "lead"))
	owner, lead := h.as(t, "owner"), h.as(t, "lead")
	checks := 0
	rbac.SetCheckingRole(t, func() { checks++ })
	n := 0
	// The roles a change granting binding(i) to each of count principals checks, before its
	// transaction and in it.
	apply := func(actor rbac.Subject, binding func(i int) rbac.Binding, count int) int {
		t.Helper()
		var c rbac.Change
		for j := range count {
			n++
			b := binding(j)
			b.Principal = identity(fmt.Sprintf("p%d", n))
			c.Grant = append(c.Grant, b)
		}
		checks = 0
		if err := h.authz.Apply(ctx, actor, cluster, c); err != nil && (actor.Principal != lead.Principal || !errors.Is(err, rbac.ErrDenied)) {
			t.Fatal(err)
		}
		return checks
	}
	const few = 10
	first := func(int) rbac.Binding { return rbac.Binding{Role: "custom.r0"} }
	for _, tc := range []struct {
		name    string
		actor   rbac.Subject
		binding func(int) rbac.Binding
		many    int
	}{
		{"granting one role listing many", owner, first, rbac.MaxBindings},
		// What one grant proved holds for the others: each role is checked for the first alone.
		{"granting each role listing many", owner, func(i int) rbac.Binding { return rbac.Binding{Role: rbac.Role(fmt.Sprintf("custom.r%d", i))} }, 200},
		// The owner holds what it grants for good and under no condition, so how long each grant
		// lasts and its condition tell none apart.
		{"granting one role listing many, each until its own time", owner, func(i int) rbac.Binding {
			return rbac.Binding{Role: "custom.r0", ExpiresAt: h.now.Add(time.Duration(i+1) * time.Second)}
		}, rbac.MaxBindings},
		{"granting one role listing many, each under its own condition", owner, func(i int) rbac.Binding {
			return rbac.Binding{Role: "custom.r0", Condition: rbac.Condition{Expression: fmt.Sprintf(`request.attributes.ticket == "T-%d"`, i)}}
		}, 100},
		// A refusal, found once all the others are checked, is found once too.
		{"refusing a role listing many", lead, first, rbac.MaxBindings},
		{"refusing a role listing many, each until its own time", lead, func(i int) rbac.Binding {
			return rbac.Binding{Role: "custom.r0", ExpiresAt: h.now.Add(time.Duration(i+1) * time.Second)}
		}, rbac.MaxBindings},
	} {
		small := apply(tc.actor, tc.binding, few)
		if small == 0 {
			t.Fatalf("%s: no role checked", tc.name)
		}
		if large := apply(tc.actor, tc.binding, tc.many); large > small {
			t.Errorf("%s checked %d roles for %d principals and %d for %d", tc.name, small, few, large, tc.many)
		}
	}
}

// A change to the members of a group granted a role on many scopes decides the role once where
// the actor holds what it grants alike on each: what it proved on one holds on the others.
func TestMembersGainingARoleOnManyScopesAreDecidedOnce(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
		SELECT 't1', 'custom.r' || i, '{cluster:view,cluster:login,cluster:grant}', '{cluster}',
		  ARRAY(SELECT 'custom.r' || ((i + j) % 100) FROM generate_series(1, 64) j)
		FROM generate_series(0, 99) i`); err != nil {
		t.Fatal(err)
	}
	gs := []rbac.Grant{
		grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "lead"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"),
		grant(rbac.Scope{Type: "cluster", ID: "x0"}, "custom.r0", rbac.Group, "one"),
	}
	for i := range 20 {
		gs = append(gs, grant(rbac.Scope{Type: "cluster", ID: fmt.Sprintf("x%d", i)}, "custom.r0", rbac.Group, "many"))
	}
	h.seed(t, gs...)
	lead := h.as(t, "lead")
	checks := 0
	rbac.SetCheckingRole(t, func() { checks++ })
	n := 0
	// The roles adding count members to group checks, each until its own time, before the change's
	// transaction and in it.
	add := func(group string, count int) int {
		t.Helper()
		var ms []rbac.Member
		var joined []rbac.Membership
		for j := range count {
			n++
			p := identity(fmt.Sprintf("m%d", n))
			ms = append(ms, rbac.Member{Group: group, Principal: p, ExpiresAt: h.now.Add(time.Duration(j+1) * time.Second)})
			joined = append(joined, rbac.Membership{Principal: p})
		}
		if err := h.authz.SetMemberships(ctx, host, "t1", joined); err != nil {
			t.Fatal(err)
		}
		checks = 0
		if err := h.authz.ChangeMembers(ctx, lead, "t1", ms, nil); err != nil {
			t.Fatal(err)
		}
		return checks
	}
	one := add("one", 1)
	if one == 0 {
		t.Fatal("no role checked")
	}
	if many := add("many", 50); many > one {
		t.Errorf("adding a member to a group granted a role on one scope checked %d roles, and fifty to one granted it on twenty %d", one, many)
	}
}

// Grants of a role each ending at its own time are each decided where what the actor holds until
// then differs, but what each proved is kept without copying what the others did, so deciding each
// costs about as much however many there are.
func TestGrantsEndingApartAreDecidedInTimeAsTheyAreMany(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	const few, many = 10, 300
	// A chain of roles, each listing the next, so a grant of the first checks them all; and what the
	// owner holds for good, held besides until each hour to come, written around the bound on them.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
		SELECT 't1', 'custom.s' || i, '{cluster:view,cluster:login,cluster:grant}', '{cluster}', ARRAY['custom.s' || ((i + 1) % 100)]
		FROM generate_series(0, 99) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		SELECT 't1', 'cluster', 'c1', 'user', 'owner', 'cluster.admin', $1::timestamptz + i * interval '1 hour' FROM generate_series(1, $2::int) i`,
		h.now, many); err != nil {
		t.Fatal(err)
	}
	owner := h.as(t, "owner")
	// The checks are as many for each grant either way, so it is what keeping them takes that shows a
	// copy for each: the heap deciding a change allocates, which copies would grow with its square.
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
	// What deciding a change granting the chain's first role to count principals, each until an hour
	// later than the last, allocates, before its transaction and in it.
	apply := func(count int) uint64 {
		t.Helper()
		var c rbac.Change
		for j := range count {
			n++
			c.Grant = append(c.Grant, rbac.Binding{Role: "custom.s0", Principal: identity(fmt.Sprintf("p%d", n)), ExpiresAt: h.now.Add(time.Duration(j+1) * time.Hour)})
		}
		allocated = 0
		if err := h.authz.Apply(ctx, owner, cluster, c); err != nil {
			t.Fatal(err)
		}
		return allocated
	}
	small, large := apply(few), apply(many)
	if large > 3*many/few*small {
		t.Errorf("deciding %d grants ending apart allocated %d bytes, and %d for %d", few, small, large, many)
	}
}

// Grants of a role each ending at its own time are decided once where what the actor holds until
// each differs only in how many grants of one kind last: an actor in many groups, each granted the
// same role until an hour of its own, granting a role that lists a chain of others to as many
// principals, each until an hour later than the last, checks the chain as often as for one grant.
func TestGrantsEndingApartAreDecidedOnceWhereTheActorsGrantsAreAlike(t *testing.T) {
	const groups, chain = 60, 30
	h := setup(t)
	ctx := t.Context()
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
		SELECT 't1', 'custom.s' || i, '{cluster:view,cluster:login,cluster:grant}', '{cluster}', ARRAY['custom.s' || ((i + 1) % $2::int)]
		FROM generate_series(0, $2::int - 1) i WHERE $1::int > 0`,
		`INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'og' || i FROM generate_series(1, $1::int) i WHERE $2::int > 0`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', 'boss' WHERE $1::int + $2::int > 0`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) SELECT 't1', 'og' || i, 'user', 'boss' FROM generate_series(1, $1::int) i WHERE $2::int > 0`,
	} {
		if _, err := h.pool.Exec(ctx, q, groups, chain); err != nil {
			t.Fatal(err)
		}
	}
	// Each group holds the admin role until an hour of its own, written around the bound on them.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		SELECT 't1', 'cluster', 'c1', 'group', 'og' || i, 'cluster.admin', $1::timestamptz + i * interval '1 hour' FROM generate_series(1, $2::int) i`,
		h.now, groups); err != nil {
		t.Fatal(err)
	}
	boss := rbac.Subject{Principal: identity("boss")}
	checks, n := 0, 0
	rbac.SetCheckingRole(t, func() { checks++ })
	// The roles a change granting the chain's first role to count principals, each until an hour
	// later than the last, checks before its transaction and in it.
	apply := func(count int) int {
		t.Helper()
		var c rbac.Change
		for j := range count {
			n++
			c.Grant = append(c.Grant, rbac.Binding{Role: "custom.s0", Principal: identity(fmt.Sprintf("p%d", n)), ExpiresAt: h.now.Add(time.Duration(j+1) * time.Hour)})
		}
		checks = 0
		if err := h.authz.Apply(ctx, boss, cluster, c); err != nil {
			t.Fatal(err)
		}
		return checks
	}
	if one, many := apply(1), apply(groups); many != one {
		t.Errorf("granting a role to one principal checked %d roles, and to %d, each ending an hour after the last, %d", one, groups, many)
	}
}

// Grants ending apart that the actor's grants decide apart, as each of its roles ends at another
// hour, read each of its grants once for each permission and power they ask about, whatever end
// each asks about: so each grant of the actor's that gives none of it costs a change the same
// however many grants it decides and roles they list.
func TestGrantsEndingApartReadEachOfTheActorsGrantsOnceForWhatTheyAsk(t *testing.T) {
	const kinds, chain = 10, 10
	read := map[int]int{}
	for _, others := range []int{50, 250} {
		t.Run(fmt.Sprint(others), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			// Roles alike but for their ids, each held until an hour of its own; a chain of roles each
			// listing the next; and grants on the cluster's workspace giving nothing they ask about.
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
				SELECT 't1', 'custom.s' || i, '{cluster:view,cluster:login,cluster:grant}', '{cluster}', ARRAY['custom.s' || ((i + 1) % $1::int)]
				FROM generate_series(0, $1::int - 1) i`, []any{chain}},
				{`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
				SELECT 't1', 'custom.k' || i, '{cluster:view,cluster:login,cluster:grant}', '{cluster}' FROM generate_series(1, $1::int) i`, []any{kinds}},
				{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
				SELECT 't1', 'cluster', 'c1', 'user', 'boss', 'custom.k' || i, $2::timestamptz + i * interval '1 hour'
				FROM generate_series(1, $1::int) i`, []any{kinds, h.now}},
				{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
				SELECT 't1', 'workspace', 'w1', 'user', 'boss', 'workspace.admin', $2::timestamptz + (1000 + i) * interval '1 hour'
				FROM generate_series(1, $1::int) i`, []any{others, h.now}},
			} {
				if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			boss := h.as(t, "boss")
			var c rbac.Change
			for j := range kinds {
				c.Grant = append(c.Grant, rbac.Binding{Role: "custom.s0", Principal: identity(fmt.Sprintf("p%d", j)), ExpiresAt: h.now.Add(time.Duration(j+1) * time.Hour)})
			}
			rbac.SetReadingEntries(t, func(k int) { read[others] += k })
			if err := h.authz.Apply(ctx, boss, cluster, c); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Before the change's transaction and in it, a few questions each: what the chain's roles give,
	// the power to grant them, and the power to change grants there.
	if each := (read[250] - read[50]) / 200; each > 16 {
		t.Errorf("deciding %d grants of a chain of %d roles read each grant of the actor's giving none of them %d times", kinds, chain, each)
	}
}

// What a change granting many decides of each grant, a role once for each condition and end the
// actor's grants tell apart and what one proved holding for the others, is what deciding that
// grant alone decides, under its own condition, by those of the actor's grants that each last until
// it ends, in random tenants: the actor's
// grants of built-in and custom roles, listing others or not, on the cluster's path, its own, its
// groups', one through a place that ends, and the tenant's members', each until an hour of its own
// or for good, some under a condition; and a constraint removing root on workspaces.
func TestGrantsDecidedTogetherAreDecidedAsEachAlone(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), granter, lister)
		c.Constraints = []rbac.Constraint{{Name: "no root on workspaces", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == root && in.ResourceType == "workspace", nil
		}}}
	})
	ctx := t.Context()
	h.groups(t, "g1", "g2")
	boss := h.as(t, "boss", "g1", "g2")
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND group_id = 'g2'`, h.now.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	mfa := `request.attributes.mfa == true`
	perms := []string{"cluster:view", "cluster:login", "cluster:root", "cluster:grant", "workspace:view", "workspace:grant"}
	custom := []rbac.Role{"custom.a", "custom.b", "custom.c", "custom.d"}
	roles := append([]rbac.Role{"cluster.admin", "cluster.sudo", "cluster.login", "cluster.granter", "cluster.lister", "workspace.admin"}, custom...)
	principals := []rbac.Principal{boss.Principal, boss.Principal, {Kind: rbac.Group, ID: "g1"}, {Kind: rbac.Group, ID: "g2"}, rbac.TenantMembers("t1")}
	on := []rbac.Resource{cluster, workspace}
	path := []rbac.Scope{cluster.Scope(), workspace.Scope(), {Type: "org", ID: "o1"}, rbac.TenantRoot("t1")}
	until := func(rng *mathrand.Rand, hours int) time.Time {
		if rng.IntN(4) == 0 {
			return time.Time{}
		}
		return h.now.Add(time.Duration(1+rng.IntN(hours)) * time.Hour)
	}
	allowed, refused := 0, 0
	for seed := range uint64(50) {
		rng := mathrand.New(mathrand.NewPCG(seed, seed))
		for _, clear := range []string{`DELETE FROM rbac_grants WHERE tenant = 't1'`, `DELETE FROM rbac_roles WHERE tenant = 't1'`} {
			if _, err := h.pool.Exec(ctx, clear); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range custom {
			var ps []string
			for _, p := range perms {
				if rng.IntN(2) == 0 {
					ps = append(ps, p)
				}
			}
			types := []string{"cluster"}
			if rng.IntN(2) == 0 {
				types = append(types, "workspace")
			}
			lists := []string{}
			if rng.IntN(2) == 0 {
				lists = append(lists, string(roles[rng.IntN(len(roles))]))
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', $1, $2, $3, $4)`,
				id, append(ps, "cluster:grant"), types, lists); err != nil {
				t.Fatal(err)
			}
		}
		for range 4 + rng.IntN(9) {
			s, p := path[rng.IntN(len(path))], principals[rng.IntN(len(principals))]
			condition := ""
			if rng.IntN(4) == 0 {
				condition = mfa
			}
			ends := until(rng, 8)
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at, condition)
				VALUES ('t1', $1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, s.Type, s.ID, p.Kind, p.ID, roles[rng.IntN(len(roles))],
				pgtype.Timestamptz{Time: ends, Valid: !ends.IsZero()}, condition); err != nil {
				t.Fatal(err)
			}
		}
		var grants []rbac.Binding
		for i := range 12 {
			b := rbac.Binding{Role: roles[rng.IntN(len(roles))], Principal: identity(fmt.Sprint("p", i)), ExpiresAt: until(rng, 10)}
			b.Condition.Expression = []string{"", "", mfa, `request.attributes.site == "lab"`}[rng.IntN(4)]
			grants = append(grants, b)
		}
		for _, r := range on {
			together, alone := rbac.GrantsDecided(t, ctx, h.authz, boss, r, grants)
			for i, b := range grants {
				if together[i] != alone[i] {
					t.Errorf("seed %d, %s on %s: decided with the others, it lacks %+v; alone, %+v", seed, b.Role, r.Scope().Key(), together[i], alone[i])
				}
				if alone[i].Lacks == "" {
					allowed++
				} else {
					refused++
				}
			}
		}
	}
	// So that grants allowed and grants refused are both compared.
	if allowed == 0 || refused == 0 {
		t.Errorf("of the grants decided, %d were allowed and %d refused", allowed, refused)
	}
}

// What a change granting many decides of each grant is what deciding it alone decides by those of
// the actor's grants that each last until it ends, in random tenants of more than its grants: its
// places in groups, one through another, and its membership of the tenant, each ending at an hour
// of its own or never; its grants and activations through itself, its groups, the tenant's members
// and the public, of roles privileged, public, listing others, or giving label values and an
// exclusive dimension's, some under conditions reading the request, the action, the resource or
// the subject; and denies on the path binding it, a group it is in or the members, some exempting
// it, some under a condition. Each grant is made until an end of the actor's grants, a microsecond
// either side of one, another time or for good, on each scope of the path, on requests meeting one
// condition or another; and of a grant refused as a constraint removes what it lacks, that one,
// where two remove root on types of their own, which the actor's roles list in any order.
func TestGrantsDecidedTogetherAreDecidedAsEachAloneWhateverTheActorHolds(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	removing := func(on string) rbac.Constraint {
		return rbac.Constraint{Name: "no root on " + on, Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == root && in.ResourceType == on, nil
		}}
	}
	h := setup(t, compartments, banks, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), granter, lister, viewer)
		c.Constraints = []rbac.Constraint{removing("workspace"), removing(rbac.TenantScope)}
	})
	ctx := t.Context()
	// boss is in g1, g2 and g4, and in g3 through g4.
	boss := h.as(t, "boss", "g1", "g2", "g4")
	h.groups(t, "g3")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g3', 'group', 'g4')`); err != nil {
		t.Fatal(err)
	}
	places := [][2]string{{"g1", "user:boss"}, {"g2", "user:boss"}, {"g4", "user:boss"}, {"g3", "group:g4"}}
	mfa, lab := `request.attributes.mfa == true`, `request.attributes.site == "lab"`
	heldUnder := []string{"", "", "", mfa, lab, `subject.id == "boss"`, `action != "cluster:root"`, `resource.type == "cluster"`}
	grantedUnder := []string{"", "", mfa, lab, `subject.id == "boss"`, `action != "cluster:root"`, `request.attributes.n == 1`}
	perms := []string{
		"cluster:view", "cluster:login", "cluster:root", "cluster:grant", "workspace:view", "workspace:grant", "tenant:view", "tenant:grant",
		"comp:c00", "comp:c01", "bank:a", "bank:b",
	}
	types := []string{"cluster", "workspace", rbac.TenantScope}
	custom := []rbac.Role{"custom.a", "custom.b", "custom.c", "custom.d", "custom.e"}
	roles := append([]rbac.Role{
		"cluster.admin", "cluster.sudo", "cluster.login", "cluster.granter", "cluster.lister", "cluster.viewer", "workspace.admin",
		"tenant.admin", "compartment", "bank.a", "bank.b", "bank.release",
	}, custom...)
	powers := []rbac.Role{"cluster.admin", "cluster.granter", "cluster.lister", "workspace.admin", "tenant.admin", "custom.a", "custom.b"}
	principals := []rbac.Principal{
		boss.Principal, boss.Principal,
		{Kind: rbac.Group, ID: "g1"},
		{Kind: rbac.Group, ID: "g2"},
		{Kind: rbac.Group, ID: "g3"},
		{Kind: rbac.Group, ID: "g4"},
		rbac.TenantMembers("t1"),
		{Kind: rbac.Public},
	}
	path := []rbac.Scope{cluster.Scope(), workspace.Scope(), {Type: "org", ID: "o1"}, rbac.TenantRoot("t1")}
	on := []rbac.Resource{cluster, workspace, tenantT1}
	someHours := func(rng *mathrand.Rand) pgtype.Timestamptz {
		if rng.IntN(3) == 0 {
			return pgtype.Timestamptz{}
		}
		return pgtype.Timestamptz{Time: h.now.Add(time.Duration(1+rng.IntN(8)) * time.Hour), Valid: true}
	}
	allowed, refused, apart, named := 0, 0, 0, map[string]bool{}
	for seed := range uint64(200) {
		rng := mathrand.New(mathrand.NewPCG(seed, seed))
		for _, clear := range []string{`DELETE FROM rbac_grants WHERE tenant = 't1'`, `DELETE FROM rbac_roles WHERE tenant = 't1'`, `DELETE FROM rbac_denies WHERE tenant = 't1'`} {
			if _, err := h.pool.Exec(ctx, clear); err != nil {
				t.Fatal(err)
			}
		}
		var ends []time.Time
		ending := func(at pgtype.Timestamptz) pgtype.Timestamptz {
			if at.Valid {
				ends = append(ends, at.Time)
			}
			return at
		}
		for _, p := range places {
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $3 WHERE tenant = 't1' AND group_id = $1 AND principal = $2`,
				p[0], p[1], ending(someHours(rng))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:boss'`, ending(someHours(rng))); err != nil {
			t.Fatal(err)
		}
		for i, id := range custom {
			var ps, ts []string
			// The first may grant any role on every type, giving more or less.
			if i == 0 {
				ps, ts = []string{"workspace:grant", "tenant:grant"}, types
			}
			for _, p := range perms {
				if rng.IntN(3) == 0 {
					ps = append(ps, p)
				}
			}
			for _, rt := range types {
				if rng.IntN(2) == 0 {
					ts = append(ts, rt)
				}
			}
			ts = append(ts, "cluster")
			rng.Shuffle(len(ts), func(i, j int) { ts[i], ts[j] = ts[j], ts[i] })
			lists := []string{}
			if i > 0 && rng.IntN(2) == 0 {
				lists = append(lists, string(roles[rng.IntN(len(roles))]))
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles, privileged, public)
				VALUES ('t1', $1, $2, $3, $4, $5, $6)`, id, append(ps, "cluster:grant"), ts, lists, rng.IntN(4) == 0, rng.IntN(3) == 0); err != nil {
				t.Fatal(err)
			}
		}
		// The power to change grants on every scope, through boss or a group it is in, so what it may
		// grant there turns on what else it holds, and until when.
		// In one tenant in four, the actor holds little else, and that power for good, so a role held
		// through the members and the public below is what decides.
		sparse := seed%4 == 0
		power, powerEnds, others := principals[1+rng.IntN(5)], someHours(rng), 6+rng.IntN(15)
		if sparse {
			powerEnds, others = pgtype.Timestamptz{}, rng.IntN(3)
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
			VALUES ('t1', 'tenant', 't1', $1, $2, 'custom.a', $3)`, power.Kind, power.ID, ending(powerEnds)); err != nil {
			t.Fatal(err)
		}
		var holds []rbac.Role
		var paired []time.Time
		for range others {
			s, p, role := path[rng.IntN(len(path))], principals[rng.IntN(len(principals))], roles[rng.IntN(len(roles))]
			if rng.IntN(2) == 0 {
				role = powers[rng.IntN(len(powers))]
			}
			holds = append(holds, role)
			expires, source := ending(someHours(rng)), ""
			if p == boss.Principal && expires.Valid && rng.IntN(3) == 0 {
				source = rbac.SourceActivation
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, condition)
				VALUES ('t1', $1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING`, s.Type, s.ID, p.Kind, p.ID, role, source, expires,
				heldUnder[rng.IntN(len(heldUnder))]); err != nil {
				t.Fatal(err)
			}
		}
		// A role through the tenant's members and the public, each until its own time: the public
		// carries only a public one, and the members no privileged one.
		if sparse || rng.IntN(2) == 0 {
			s, role := path[rng.IntN(len(path))], []rbac.Role{"cluster.login", "workspace.admin", "tenant.admin", "compartment", roles[rng.IntN(len(roles))]}[rng.IntN(5)]
			holds = append(holds, role)
			for _, p := range principals[6:] {
				expires := ending(someHours(rng))
				if expires.Valid {
					paired = append(paired, expires.Time)
				}
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
					VALUES ('t1', $1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`, s.Type, s.ID, p.Kind, p.ID, role, expires); err != nil {
					t.Fatal(err)
				}
			}
		}
		for i := range rng.IntN(4) {
			s := path[rng.IntN(len(path))]
			bound := []string{"user:boss", "group:g1", "group:g3", "members:t1", "public:"}[rng.IntN(5)]
			exempt := []string{}
			if bound != "user:boss" && rng.IntN(3) == 0 {
				exempt = []string{[]string{"user:boss", "group:g2"}[rng.IntN(2)]}
			}
			removes := []string{"cluster:root", "cluster:grant", "cluster:*", "workspace:grant", "tenant:grant", "bank:*", "comp:c00", "comp:*"}
			condition := []string{"", "", `request.attributes.mfa == false`, `action == "cluster:login"`}[rng.IntN(4)]
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions, condition)
				VALUES ('t1', $1, $2, $3, $4, $5, $6, $7)`, s.Type, s.ID, fmt.Sprint("d", i), []string{bound}, exempt,
				[]string{removes[rng.IntN(len(removes))], removes[rng.IntN(len(removes))]}, condition); err != nil {
				t.Fatal(err)
			}
		}
		until := func() time.Time {
			switch n := rng.IntN(8); {
			case n == 0:
				return time.Time{}
			case n == 1 || len(ends) == 0:
				return h.now.Add(time.Duration(1+rng.IntN(10*60)) * time.Minute)
			case sparse && len(paired) > 0 && n < 5:
				return paired[rng.IntN(len(paired))].Add(time.Duration(rng.IntN(3)-1) * time.Microsecond)
			}
			return ends[rng.IntN(len(ends))].Add(time.Duration(rng.IntN(3)-1) * time.Microsecond)
		}
		var grants []rbac.Binding
		for i := range 16 {
			b := rbac.Binding{Role: roles[rng.IntN(len(roles))], Principal: identity(fmt.Sprint("p", i)), ExpiresAt: until()}
			if rng.IntN(2) == 0 {
				b.Role = holds[rng.IntN(len(holds))]
			}
			b.Condition.Expression = grantedUnder[rng.IntN(len(grantedUnder))]
			grants = append(grants, b)
		}
		request := rbac.WithRequest(ctx, map[string]any{"mfa": rng.IntN(2) == 0, "site": []string{"lab", "home"}[rng.IntN(2)]})
		for _, r := range on {
			together, alone := rbac.GrantsDecided(t, request, h.authz, boss, r, grants)
			byEnd := map[string]map[rbac.Permission]bool{}
			for i, b := range grants {
				if together[i] != alone[i] {
					t.Errorf("seed %d, %s under %q until %v on %s: decided with the others, it lacks %+v; alone, %+v",
						seed, b.Role, b.Condition.Expression, b.ExpiresAt, r.Scope().Key(), together[i], alone[i])
				}
				if alone[i].Lacks == "" {
					allowed++
				} else {
					refused++
				}
				named[alone[i].By] = true
				k := string(b.Role) + " " + b.Condition.Expression
				if byEnd[k] == nil {
					byEnd[k] = map[rbac.Permission]bool{}
				}
				byEnd[k][alone[i].Lacks] = true
			}
			for _, decided := range byEnd {
				if len(decided) > 1 {
					apart++
				}
			}
		}
	}
	// So that grants allowed and refused are compared, grants of a role under one condition that the
	// actor's grants decide apart for their ends, and refusals by each constraint.
	if allowed == 0 || refused == 0 || apart == 0 || !named["no root on workspace"] || !named["no root on tenant"] {
		t.Errorf("of the grants decided, %d were allowed and %d refused, and %d roles were decided apart for their ends; refused by %v",
			allowed, refused, apart, named)
	}
}

func TestDeletePrincipalEverywhereAcrossManyTenants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	support := rbac.Principal{Kind: rbac.User, ID: "support"}
	const tenants = 70
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 'x' || g, 'tenant', 'x' || g, 'user', 'support', 'cluster.login' FROM generate_series(1, $1::int) g`, tenants); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, support); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_grants WHERE principal = 'user:support'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d grants left, %v", left, err)
	}
	if len(h.events) != tenants {
		t.Fatalf("%d changes, want one per tenant", len(h.events))
	}
	// A group is its tenant's, so another with its id elsewhere isn't it.
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, rbac.Principal{Kind: rbac.Group, ID: "support"}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a group everywhere: %v", err)
	}
}

// roleAdmin is a tenant admin who may define roles and holds every cluster permission.
func roleAdmin(t *testing.T, h *harness) rbac.Subject {
	t.Helper()
	root := rbac.TenantRoot("t1")
	h.seed(t,
		grant(root, "tenant.roles", rbac.User, "admin"),
		grant(root, "tenant.admin", rbac.User, "admin"),
		grant(root, "cluster.admin", rbac.User, "admin"),
	)
	return h.as(t, "admin")
}

func TestCustomRoles(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	operator := rbac.RoleDefinition{ID: "custom.operator", Name: "Operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	h.events = nil
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Roles) != 1 || h.events[0].Roles[0].ID != operator.ID || h.events[0].Actor != admin.Principal {
		t.Fatalf("events = %+v", h.events)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil || len(h.events) != 1 {
		t.Fatalf("defining a role again as it is reported a change: %+v, %v", h.events, err)
	}
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{{Role: operator.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "op"}}}}); err != nil {
		t.Fatalf("granting a custom role: %v", err)
	}
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, operator.ID, rbac.User, "op"))
	op := h.as(t, "op")
	if !allowed(t, h, op, login, cluster) || allowed(t, h, op, root, cluster) {
		t.Fatal("a custom role should give what it lists and nothing more")
	}
	for _, p := range []rbac.Permission{login, root} {
		listingsAgree(t, h, resources, op, p)
	}
	if perms, err := h.authz.Permissions(ctx, op, cluster); err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, login, cluster); err != nil || !slices.Contains(holderPrincipals(holders), op.Principal) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
	if d, err := h.authz.Explain(ctx, op, login, cluster); err != nil || !d.Allowed || d.Grants[0].Role != operator.ID {
		t.Errorf("Explain = %+v, %v", d, err)
	}

	// Replacing it changes what its grants give.
	operator.Permissions = append(operator.Permissions, root)
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, op, root, cluster) {
		t.Fatal("a replaced role's grants should give what it gives now")
	}
	listingsAgree(t, h, resources, op, root)

	roles, err := h.authz.Roles(ctx, "t1", "cluster")
	if err != nil || len(roles) != 4 || roles[3].ID != operator.ID || !slices.Contains(roles[3].Permissions, root) {
		t.Fatalf("Roles = %+v, %v", roles, err)
	}
	if !roles[3].Privileged {
		t.Fatal("a custom role giving root, which only privileged roles give, should be privileged")
	}
	// As Roles lists it, its name too, for an access screen to show.
	if grantable, err := h.authz.Grantable(ctx, admin, cluster); err != nil || !slices.ContainsFunc(grantable, func(r rbac.RoleDefinition) bool {
		return r.ID == operator.ID && r.Name == operator.Name
	}) {
		t.Fatalf("Grantable = %+v, %v", grantable, err)
	}
	if err := h.authz.Import(ctx, host, "t2", []rbac.Grant{grant(rbac.TenantRoot("t2"), operator.ID, rbac.User, "op")}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting a custom role in a tenant that doesn't define it: %v", err)
	}

	h.events = nil
	if err := h.authz.DeleteRole(ctx, admin, "t1", operator.ID); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Revoked) != 2 || !slices.Equal(h.events[0].DeletedRoles, []rbac.Role{operator.ID}) {
		t.Fatalf("events = %+v", h.events)
	}
	if allowed(t, h, op, login, cluster) {
		t.Fatal("a deleted role's grants should be gone")
	}
	if custom, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(custom) != 0 {
		t.Fatalf("CustomRoles = %+v, %v", custom, err)
	}

	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteTenant(ctx, host, "t1"); err != nil {
		t.Fatal(err)
	}
	if custom, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(custom) != 0 {
		t.Fatalf("a deleted tenant's custom roles: %+v, %v", custom, err)
	}
	if len(h.events) != 1 || !slices.Equal(h.events[0].DeletedRoles, []rbac.Role{operator.ID}) {
		t.Fatalf("events = %+v", h.events)
	}
}

// A custom role gives at most MaxRoleEntries permissions and is for at most as many types, as the
// table holds, however many the catalog has: past either, defining one is invalid, not a failure of
// the database.
func TestACustomRoleListsAtMostMaxRoleEntries(t *testing.T) {
	var perms []rbac.Permission
	for _, p := range longestPermissions(rbac.MaxRoleEntries + 1) {
		perms = append(perms, rbac.Permission(p))
	}
	types := longestNames("t", rbac.MaxRoleEntries+1)
	wide := rbac.RoleDefinition{ID: "wide", Permissions: perms, ResourceTypes: types}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), wide) })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), wide.ID, rbac.User, "admin"))
	admin := h.as(t, "admin")
	for _, r := range []rbac.RoleDefinition{
		{ID: "custom.many", Permissions: perms, ResourceTypes: types[:1]},
		{ID: "custom.many", Permissions: perms[:1], ResourceTypes: types},
	} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a role of %d permissions for %d types: %v", len(r.Permissions), len(r.ResourceTypes), err)
		}
	}
	for _, r := range []rbac.RoleDefinition{
		{ID: "custom.many", Permissions: perms[:rbac.MaxRoleEntries], ResourceTypes: types[:1]},
		{ID: "custom.many", Permissions: perms[:1], ResourceTypes: types[:rbac.MaxRoleEntries]},
	} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Errorf("a role of %d permissions for %d types: %v", len(r.Permissions), len(r.ResourceTypes), err)
		}
	}
}

// Whether a custom role is privileged is read a permission at a time, against the types each is
// unprivileged on: so a tenant's 300 roles of 1,000 permissions are listed about as fast for 50
// types each as for one. Each permission read against each type, twice, the 50 took 680 ms.
func TestACustomRolesPrivilegeIsReadAPermissionAtATime(t *testing.T) {
	var perms []rbac.Permission
	var types []string
	for i := range 50 {
		types = append(types, fmt.Sprintf("t%02d", i))
		for j := range 20 {
			perms = append(perms, rbac.Permission(fmt.Sprintf("t%02d:v%02d", i, j)))
		}
	}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "big", Permissions: perms, ResourceTypes: types})
	})
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		SELECT 'one', 'custom.r' || i, $1::text[], $2::text[] FROM generate_series(1, 300) i
		UNION ALL SELECT 'every', 'custom.r' || i, $1::text[], $3::text[] FROM generate_series(1, 300) i`, perms, types[:1], types); err != nil {
		t.Fatal(err)
	}
	took := map[string]time.Duration{}
	// Each runs first in every other round, so a stretch of load meets both alike.
	order := []string{"one", "every"}
	for range 7 {
		for _, tenant := range order {
			start := time.Now()
			roles, err := h.authz.CustomRoles(ctx, tenant)
			if err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); took[tenant] == 0 || d < took[tenant] {
				took[tenant] = d
			}
			if len(roles) != 300 || roles[0].Privileged {
				t.Fatalf("%s: %d roles, the first privileged %t", tenant, len(roles), roles[0].Privileged)
			}
		}
		slices.Reverse(order)
	}
	if one, every := took["one"], took["every"]; every > 3*one+20*time.Millisecond {
		t.Errorf("listing 300 custom roles of %d permissions took %v for one type each and %v for %d", len(perms), one, every, len(types))
	}
}

func TestDefiningARoleChecksTheActor(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	tenant := rbac.TenantRoot("t1")
	h.seed(t,
		grant(tenant, "tenant.roles", rbac.User, "limited"),
		grant(tenant, "cluster.login", rbac.User, "limited"),
		grant(tenant, "cluster.admin", rbac.User, "no-roles"),
	)
	sudo := rbac.RoleDefinition{ID: "custom.sudo", Permissions: []rbac.Permission{view, login, root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, h.as(t, "limited"), "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role with permissions the actor doesn't hold: %v", err)
	}
	if err := h.authz.SetRole(ctx, h.as(t, "no-roles"), "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role without tenant:define-roles: %v", err)
	}
	if err := h.authz.SetRole(ctx, rbac.Subject{}, "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an anonymous subject defining a role: %v", err)
	}
	for name, r := range map[string]rbac.RoleDefinition{
		"no prefix":                 {ID: "sudo", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}},
		"an unknown permission":     {ID: "custom.fly", Permissions: []rbac.Permission{"cluster:fly"}, ResourceTypes: []string{"cluster"}},
		"an unknown type":           {ID: "custom.rocket", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"rocket"}},
		"an unknown grantable role": {ID: "custom.g", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"custom.nope"}},
		"public root-level control": {ID: "custom.root", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}, Public: true},
		"grantable roles without a grant permission": {
			ID: "custom.d", Permissions: []rbac.Permission{rbac.DefineRoles}, ResourceTypes: []string{"tenant"}, GrantableRoles: []rbac.Role{"cluster.login"},
		},
	} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}} {
		if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: tenant, Binding: rbac.Binding{Role: "tenant.roles", Principal: p}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("letting %s define roles: %v", p.Kind, err)
		}
	}
	if err := h.authz.DeleteRole(ctx, h.as(t, "limited"), "t1", "cluster.admin"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a built-in role: %v", err)
	}

	// Who may only hand a role out can't redefine it with more than it holds.
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{"tenant:grant"}, ResourceTypes: []string{"tenant"}, GrantableRoles: []rbac.Role{viewer.ID}}
	for _, r := range []rbac.RoleDefinition{viewer, lister} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(tenant, lister.ID, rbac.User, "helper"), grant(tenant, "tenant.roles", rbac.User, "helper"))
	wider := viewer
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, h.as(t, "helper"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("redefining a role the actor may only hand out: %v", err)
	}
	// Nor can one who holds a role widen it, or what it hands out.
	h.seed(t, grant(tenant, viewer.ID, rbac.User, "helper"))
	if err := h.authz.SetRole(ctx, h.as(t, "helper"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("widening a role the actor holds: %v", err)
	}
	more := lister
	more.GrantableRoles = []rbac.Role{"cluster.admin"}
	if err := h.authz.SetRole(ctx, h.as(t, "helper"), "t1", more); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("widening what a role the actor holds hands out: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", viewer.ID); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a role another lists: %v", err)
	}

	// A custom role that hands out narrower ones.
	access := rbac.RoleDefinition{ID: "custom.access", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	if err := h.authz.SetRole(ctx, admin, "t1", access); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), access.ID, rbac.User, "manager"))
	b := func(role rbac.Role) rbac.Binding {
		return rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	}
	if err := h.authz.Apply(ctx, h.as(t, "manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.login")}}); err != nil {
		t.Fatalf("a custom role's grantable role: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.sudo")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a role a custom role doesn't list: %v", err)
	}
}

func TestDefiningRolesRespectsConstraints(t *testing.T) {
	h := setup(t, constrain("roles are managed elsewhere", rbac.DefineRoles))
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(t.Context(), admin, "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role a constraint forbids: %v", err)
	}
}

func TestPublicCustomRoles(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.SetRole(ctx, admin, "t1", viewer); err != nil {
		t.Fatal(err)
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	if err := h.authz.Apply(ctx, admin, tenant, rbac.Change{Grant: []rbac.Binding{{Role: viewer.ID, Principal: rbac.Principal{Kind: rbac.Public}}}}); err != nil {
		t.Fatal(err)
	}
	anonymous := rbac.Subject{}
	if !allowed(t, h, anonymous, view, cluster) {
		t.Fatal("a public custom role should reach anonymous subjects")
	}
	listingsAgree(t, h, resources, anonymous, view)
	viewer.Public = false
	if err := h.authz.SetRole(ctx, admin, "t1", viewer); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("a grant to the public should give nothing once its custom role isn't public")
	}
	listingsAgree(t, h, resources, anonymous, view)
	if holders, err := h.authz.Holders(ctx, view, cluster); err != nil || slices.Contains(holderPrincipals(holders), rbac.Principal{Kind: rbac.Public}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

// Filter reads which custom roles give through a grant to the public when it is called, and its
// condition keeps of them those still public when the host's query runs, so one no longer public
// by then gives nothing, as it gives Authorize nothing.
func TestAFilterConditionKeepsNothingThroughACustomRoleNoLongerPublic(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	hostTable(t, h)
	admin := roleAdmin(t, h)
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.SetRole(ctx, admin, "t1", viewer); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), viewer.ID, rbac.Public, ""))
	anonymous := rbac.Subject{}
	pred, err := h.authz.Filter(ctx, anonymous, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	kept := func() []string {
		t.Helper()
		rows, err := h.pool.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY 1`, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	if ids := kept(); len(ids) == 0 {
		t.Fatal("a public custom role granted to the public should reach anonymous subjects")
	}
	viewer.Public = false
	if err := h.authz.SetRole(ctx, admin, "t1", viewer); err != nil {
		t.Fatal(err)
	}
	if ids := kept(); len(ids) > 0 || allowed(t, h, anonymous, view, cluster) {
		t.Errorf("a condition built while its custom role was public kept %v once it wasn't", ids)
	}
}

func TestDeleteRoleRemovesAGrantMadeWhileItWaits(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	operator := rbac.RoleDefinition{ID: "custom.operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	b := rbac.Binding{Role: operator.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "op"}}
	if err := h.authz.WithTx(tx).Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteRole(ctx, admin, "t1", operator.ID) }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 0 {
		t.Fatalf("a grant made while its role was deleted outlived it: %+v, %v", got, err)
	}
}

func TestApplyRefusesARoleChangedWhileItWaits(t *testing.T) {
	operator := rbac.RoleDefinition{ID: "custom.operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	moved := operator
	moved.Permissions, moved.ResourceTypes = []rbac.Permission{"tenant:view"}, []string{"tenant"}
	for name, change := range map[string]func(ctx context.Context, a *rbac.Authorizer, admin rbac.Subject) error{
		"deleted": func(ctx context.Context, a *rbac.Authorizer, admin rbac.Subject) error {
			return a.DeleteRole(ctx, admin, "t1", operator.ID)
		},
		"no longer for clusters": func(ctx context.Context, a *rbac.Authorizer, admin rbac.Subject) error {
			return a.SetRole(ctx, admin, "t1", moved)
		},
	} {
		t.Run(name, func(t *testing.T) { applyWhileTheRoleChanges(t, operator, change) })
	}
}

func applyWhileTheRoleChanges(t *testing.T, operator rbac.RoleDefinition, change func(context.Context, *rbac.Authorizer, rbac.Subject) error) {
	t.Helper()
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	// The host changes the role in its transaction, which holds the tenant until it commits.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := change(ctx, h.authz.WithTx(tx), admin); err != nil {
		t.Fatal(err)
	}
	b := rbac.Binding{Role: operator.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "op"}}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{b}}) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("Apply didn't wait for the role's change: %v", err)
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting a role changed while the change waited: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

// A custom role lists only roles one of its `<type>:grant` permissions, on a type it is for, lets
// its holders grant, as roles that can be granted on that type. One none reaches would hand nothing
// on, so the actor's power to grant it went unchecked, though the listing kept it from being
// deleted: an actor who may grant on clusters alone listed a workspace role.
func TestARoleListsOnlyRolesItsGrantPermissionsReach(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "lead"), grant(tenant, "cluster.admin", rbac.User, "lead"))
	lead := h.as(t, "lead")
	if err := h.authz.Apply(ctx, lead, workspace, rbac.Change{Grant: []rbac.Binding{{Role: "workspace.admin", Principal: identity("x")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a workspace role with the power to grant on clusters alone: %v", err)
	}
	for name, r := range map[string]rbac.RoleDefinition{
		"a role for clusters listing a workspace role": {
			ID: "custom.x", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"workspace.admin"},
		},
		"a role whose power to grant is on a type it isn't for": {
			ID: "custom.y", Permissions: []rbac.Permission{view, "workspace:grant"}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"},
		},
	} {
		if err := h.authz.SetRole(ctx, lead, "t1", r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	live := rbac.RoleDefinition{ID: "custom.z", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	if err := h.authz.SetRole(ctx, lead, "t1", live); err != nil {
		t.Errorf("a role for clusters listing a cluster role: %v", err)
	}
}

// A role keeps a listing that already hands nothing on as it is stored, as one of a role narrowed
// since, one a catalog change left so, or one written around the package: setting it again as it is
// read changes nothing, and renaming it needs only the power to define it. A listing that hands
// nothing on and that the change adds, or makes so by changing the role, is refused.
func TestARoleKeepsAListingThatAlreadyHandsNothingOn(t *testing.T) {
	later := rbac.RoleDefinition{ID: "custom.later", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	for how, inert := range map[string]func(t *testing.T, h *harness) *rbac.Authorizer{
		"the role it lists narrowed": func(t *testing.T, h *harness) *rbac.Authorizer {
			t.Helper()
			admin := roleAdmin(t, h)
			listing := lister
			listing.GrantableRoles = []rbac.Role{later.ID}
			narrowed := later
			narrowed.Permissions, narrowed.ResourceTypes = []rbac.Permission{rbac.DefineRoles}, []string{"tenant"}
			for _, r := range []rbac.RoleDefinition{later, listing, narrowed} {
				if err := h.authz.SetRole(t.Context(), admin, "t1", r); err != nil {
					t.Fatal(err)
				}
			}
			return h.authz
		},
		"a catalog change": func(t *testing.T, h *harness) *rbac.Authorizer {
			t.Helper()
			listing := lister
			listing.GrantableRoles = []rbac.Role{"cluster.login"}
			if err := h.authz.SetRole(t.Context(), roleAdmin(t, h), "t1", listing); err != nil {
				t.Fatal(err)
			}
			moved := slices.Clone(catalog)
			for i, r := range moved {
				if r.ID == "cluster.login" {
					moved[i].ResourceTypes = []string{"workspace"}
				}
			}
			authz, err := rbac.New(h.pool, func() rbac.Config { c := h.cfg; c.Catalog = moved; return c }())
			if err != nil {
				t.Fatal(err)
			}
			return authz
		},
		"written around the package": func(t *testing.T, h *harness) *rbac.Authorizer {
			t.Helper()
			if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, privileged, grantable_roles)
				VALUES ('t1', 'custom.lister', '{cluster:view,cluster:grant}', '{cluster}', true, '{workspace.admin}')`); err != nil {
				t.Fatal(err)
			}
			return h.authz
		},
	} {
		t.Run(how, func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "tenant.roles", rbac.User, "lead"), grant(tenant, "cluster.admin", rbac.User, "lead"))
			lead := h.as(t, "lead")
			authz := inert(t, h)
			roles, err := authz.CustomRoles(ctx, "t1")
			i := slices.IndexFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == lister.ID })
			if err != nil || i < 0 {
				t.Fatalf("CustomRoles = %+v, %v", roles, err)
			}
			h.events = nil
			if err := authz.SetRole(ctx, lead, "t1", roles[i]); err != nil || len(h.events) != 0 {
				t.Errorf("setting the role again as it is read: %v, %+v", err, h.events)
			}
			renamed := roles[i]
			renamed.Name = "Lister"
			if err := authz.SetRole(ctx, lead, "t1", renamed); err != nil || len(h.events) != 1 {
				t.Errorf("renaming the role: %v, %+v", err, h.events)
			}
			adding := renamed
			adding.GrantableRoles = append(slices.Clone(adding.GrantableRoles), "tenant.admin")
			if err := authz.SetRole(ctx, lead, "t1", adding); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("adding a listing that hands nothing on beside it: %v", err)
			}
		})
	}
	// Listed through a power to grant on workspaces, which narrowing the role takes away.
	h := setup(t)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "lead"), grant(tenant, "cluster.admin", rbac.User, "lead"))
	lead := h.as(t, "lead")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, privileged, grantable_roles)
		VALUES ('t1', 'custom.lister', '{cluster:grant,cluster:view,workspace:grant}', '{cluster,workspace}', true, '{workspace.admin}')`); err != nil {
		t.Fatal(err)
	}
	narrowed := lister
	narrowed.GrantableRoles = []rbac.Role{"workspace.admin"}
	if err := h.authz.SetRole(ctx, lead, "t1", narrowed); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("narrowing a role so that a role it lists is handed on nowhere: %v", err)
	}
	narrowed.GrantableRoles = nil
	if err := h.authz.SetRole(ctx, lead, "t1", narrowed); err != nil {
		t.Errorf("narrowing a role and the roles it lists: %v", err)
	}
}

func TestRedefiningAListedRoleNeedsThePowerToGrantIt(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	tenant := rbac.TenantRoot("t1")
	// May define roles and holds root on every cluster, but may change no grants.
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "definer"), grant(tenant, "cluster.sudo", rbac.User, "definer"))
	definer := h.as(t, "definer")
	// Listed for clusters while they take it, and then narrowed so that they no longer do: the
	// listing hands nothing on until it is redefined for clusters again.
	later := rbac.RoleDefinition{ID: "custom.later", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{later.ID}}
	for _, r := range []rbac.RoleDefinition{later, lister} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	later.Permissions, later.ResourceTypes = []rbac.Permission{rbac.DefineRoles}, []string{"tenant"}
	if err := h.authz.SetRole(ctx, definer, "t1", later); err != nil {
		t.Fatalf("narrowing a listed role so that the role listing it hands it out nowhere: %v", err)
	}
	h.seed(t, grant(cluster.Scope(), lister.ID, rbac.User, "manager"))
	sudo := later
	sudo.Permissions, sudo.ResourceTypes = []rbac.Permission{view, login, root}, []string{"cluster"}
	if err := h.authz.SetRole(ctx, definer, "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("letting a role's holders grant root without the power to grant it: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "manager"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: later.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "manager"}}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting the listed role on a cluster: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", sudo); err != nil {
		t.Fatalf("redefining a listed role with the power to grant it: %v", err)
	}
}

func TestPublicCustomRolesGiveOnlyWhatUnprivilegedRolesGiveOnEachType(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "files.reader", Permissions: []rbac.Permission{"data:read"}, ResourceTypes: []string{"bucket"}},
			rbac.RoleDefinition{ID: "secrets.admin", Permissions: []rbac.Permission{"data:read"}, ResourceTypes: []string{"secret"}, Privileged: true},
		)
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "secrets.admin", rbac.User, "admin"))
	secrets := rbac.RoleDefinition{ID: "custom.secrets", Permissions: []rbac.Permission{"data:read"}, ResourceTypes: []string{"secret"}, Public: true}
	if err := h.authz.SetRole(ctx, admin, "t1", secrets); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a public role giving what only a privileged role gives on its type: %v", err)
	}
	secrets.Public = false
	if err := h.authz.SetRole(ctx, admin, "t1", secrets); err != nil {
		t.Fatal(err)
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || !roles[0].Privileged {
		t.Fatalf("a role giving what only a privileged role gives on its type should be privileged: %+v, %v", roles, err)
	}
}

func TestCustomRolesFollowTheCatalog(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login, root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, op.ID, rbac.User, "op"))
	// The host deploys a catalog that no longer gives root.
	without := slices.Clone(catalog)
	for i, r := range without {
		without[i].Permissions = slices.DeleteFunc(slices.Clone(r.Permissions), func(p rbac.Permission) bool { return p == root })
	}
	// It still checks root, which no role gives now.
	later, err := rbac.New(h.pool, rbac.Config{
		Catalog: without, ContainerTypes: []string{"org", "workspace"}, Permissions: declaring(without, root),
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Authorize(ctx, h.as(t, "op"), root, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a custom role giving a permission the catalog dropped: %v", err)
	}
	if reach, err := later.Reachable(ctx, h.as(t, "op"), root, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	pred, err := later.Filter(ctx, h.as(t, "op"), root, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 0 {
		t.Fatalf("Filter kept %d clusters, %v", n, err)
	}
	if holders, err := later.Holders(ctx, root, resources[0]); err != nil || slices.Contains(holderPrincipals(holders), rbac.Principal{Kind: rbac.User, ID: "op"}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	if perms, err := later.Permissions(ctx, h.as(t, "op"), cluster); err != nil || slices.Contains(perms, root) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	// A host that doesn't say what it checks checks what the catalog gives, so asking about root is
	// a mistake, as asking about a misspelled permission is.
	undeclared, err := rbac.New(h.pool, rbac.Config{
		Catalog: without, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := undeclared.Authorize(ctx, h.as(t, "op"), root, cluster); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a permission the catalog dropped and the host doesn't declare: %v", err)
	}
	if roles, err := later.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || slices.Contains(roles[0].Permissions, root) {
		t.Fatalf("CustomRoles = %+v, %v", roles, err)
	}
	if err := later.Authorize(ctx, h.as(t, "op"), login, cluster); err != nil {
		t.Fatalf("what the catalog still has: %v", err)
	}
}

func TestPublicCustomRolesFollowTheCatalog(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	pub := rbac.RoleDefinition{ID: "custom.pub", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.SetRole(ctx, admin, "t1", pub); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), pub.ID, rbac.Public, ""))
	// The host deploys a catalog where only privileged roles give login, while one that isn't
	// still gives view: the role is no longer public, though view on its own could be.
	later := slices.Clone(catalog)
	for i := range later {
		later[i].Privileged = later[i].Privileged || later[i].ID == "cluster.login"
	}
	later = append(later, rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}})
	authz, err := rbac.New(h.pool, rbac.Config{
		Catalog: later, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.authz = authz
	anonymous := rbac.Subject{}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("a grant to the public should give nothing once its role is no longer public")
	}
	listingsAgree(t, h, resources, anonymous, view)
	if holders, err := h.authz.Holders(ctx, view, cluster); err != nil || slices.Contains(holderPrincipals(holders), rbac.Principal{Kind: rbac.Public}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

func TestDefiningRolesIsCanonicalBoundedAndMarksPrivilege(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{login, view, view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	r.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil || len(h.events) != 0 {
		t.Fatalf("the same role reordered changed it: %+v, %v", h.events, err)
	}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.sudo"}}
	if err := h.authz.SetRole(ctx, admin, "t1", lister); err != nil {
		t.Fatal(err)
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(roles) != 2 || !roles[0].Privileged || roles[1].Privileged {
		t.Fatalf("a role handing out sudo should be privileged, one giving login and view not: %+v, %v", roles, err)
	}
	// Handing out a privileged custom role is privileged too, though workspace:grant isn't.
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.admin", rbac.User, "admin"))
	rooted := rbac.RoleDefinition{ID: "custom.rooted", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}}
	relay := rbac.RoleDefinition{ID: "custom.relay", Permissions: []rbac.Permission{"workspace:grant"}, ResourceTypes: []string{"workspace"}, GrantableRoles: []rbac.Role{rooted.ID}}
	for _, d := range []rbac.RoleDefinition{rooted, relay} {
		if err := h.authz.SetRole(ctx, admin, "t1", d); err != nil {
			t.Fatal(err)
		}
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || roles[len(roles)-2].ID != relay.ID || !roles[len(roles)-2].Privileged {
		t.Fatalf("a role handing out a privileged custom role should be privileged: %+v, %v", roles, err)
	}
	fill := func(from, to int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
			SELECT 't1', 'custom.filler' || i, '{cluster:view}', '{cluster}' FROM generate_series($1::int, $2::int) AS i`, from, to); err != nil {
			t.Fatal(err)
		}
	}
	fill(1, 65)
	many := rbac.RoleDefinition{ID: "custom.many", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}}
	for i := range 65 {
		many.GrantableRoles = append(many.GrantableRoles, rbac.Role(fmt.Sprintf("custom.filler%d", i+1)))
	}
	if err := h.authz.SetRole(ctx, admin, "t1", many); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a role listing 65 roles: %v", err)
	}
	fill(66, 296)
	extra := rbac.RoleDefinition{ID: "custom.extra", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", extra); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a tenant's 301st custom role: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatalf("redefining a role in a full tenant: %v", err)
	}
}

func TestDeletingARoleRespectsConstraints(t *testing.T) {
	stop := false
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "managed elsewhere", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			p := in.Permission
			return stop && p == grantC, nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), op.ID, rbac.User, "op"))
	stop = true
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("deleting a role revokes grants a constraint keeps: %v", err)
	}
	gutted := op
	gutted.Permissions, gutted.ResourceTypes = []rbac.Permission{"tenant:view"}, []string{"tenant"}
	if err := h.authz.SetRole(ctx, admin, "t1", gutted); !errors.Is(err, rbac.ErrDenied) || !allowed(t, h, h.as(t, "op"), view, cluster) {
		t.Fatalf("redefining a role changes grants a constraint keeps: %v", err)
	}
	renamed := op
	renamed.Name = "Operator"
	if err := h.authz.SetRole(ctx, admin, "t1", renamed); err != nil {
		t.Fatalf("renaming a role changes no grant: %v", err)
	}
	stop = false
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); err != nil {
		t.Fatalf("deleting a role that doesn't exist: %v", err)
	}
}

// A role, a deny and an eligibility stored around the package, as a seed or a restore can write
// them, with their lists in another order than the package sorts them into, or with a repeat, are
// the ones the package would store: renaming the role is no redefinition, so a freeze of changes to
// its grants doesn't stop it, and setting each again as it is read changes nothing. Compared element
// by element with the sorted request, the rename was refused, and each set again was a change.
func TestListsStoredInAnotherOrderAreTheSame(t *testing.T) {
	for _, stored := range []string{`{cluster:view,cluster:login}`, `{cluster:login,cluster:view,cluster:login}`} {
		t.Run(stored, func(t *testing.T) {
			frozen := false
			h := setup(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), guardRole)
				c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					return frozen && in.Permission == grantC, nil
				}}}
			})
			ctx := t.Context()
			h.seed(t, grant(tenantT1.Scope(), "tenant.roles", rbac.User, "definer"), grant(tenantT1.Scope(), "cluster.login", rbac.User, "definer"),
				grant(cluster.Scope(), "guard", rbac.User, "guardian"))
			definer, guardian, owner := h.as(t, "definer"), h.as(t, "guardian"), h.as(t, "owner")
			h.as(t, "m")
			h.as(t, "lead")
			for _, sql := range []string{
				`INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.ops', '` + stored + `', '{cluster,cluster}')`,
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
					VALUES ('t1', 'cluster', 'c1', 'd', '{user:m,user:lead,user:m}', '{}', '` + stored + `')`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					VALUES ('t1', 'cluster', 'c1', 'user', 'm', 'cluster.login', 3600, '{user:owner,user:lead,user:owner}')`,
			} {
				if _, err := h.pool.Exec(ctx, sql); err != nil {
					t.Fatal(err)
				}
			}
			h.seed(t, grant(cluster.Scope(), "custom.ops", rbac.User, "m"))
			roles, err := h.authz.CustomRoles(ctx, "t1")
			if err != nil || len(roles) != 1 {
				t.Fatalf("CustomRoles = %+v, %v", roles, err)
			}
			denies, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
			if err != nil || len(denies) != 1 {
				t.Fatalf("Denies = %+v, %v", denies, err)
			}
			eligible, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
			if err != nil || len(eligible) != 1 {
				t.Fatalf("Eligibilities = %+v, %v", eligible, err)
			}
			h.events = nil
			if err := h.authz.SetDeny(ctx, guardian, cluster, denies[0]); err != nil {
				t.Errorf("setting the deny again as it is read: %v", err)
			}
			if err := h.authz.SetEligibility(ctx, owner, cluster, eligible[0]); err != nil {
				t.Errorf("setting the eligibility again as it is read: %v", err)
			}
			frozen = true
			if err := h.authz.SetRole(ctx, definer, "t1", roles[0]); err != nil {
				t.Errorf("setting the role again as it is read, under a freeze of its grants: %v", err)
			}
			if len(h.events) != 0 {
				t.Errorf("setting them again as they are read changed %+v", h.events)
			}
			renamed := roles[0]
			renamed.Name = "Operations"
			if err := h.authz.SetRole(ctx, definer, "t1", renamed); err != nil || len(h.events) != 1 {
				t.Errorf("renaming the role under a freeze of its grants: %v, %+v", err, h.events)
			}
			narrowed := renamed
			narrowed.Permissions = []rbac.Permission{view}
			if err := h.authz.SetRole(ctx, definer, "t1", narrowed); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("narrowing the role under a freeze of its grants: %v", err)
			}
		})
	}
}

func TestGrantableDropsWhatARefusedRolesChecksAssumed(t *testing.T) {
	// Deciding first passes second only while first is being checked, then fails on root.
	first := rbac.RoleDefinition{ID: "cluster.first", Permissions: []rbac.Permission{view, grantC, root}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.second"}}
	second := rbac.RoleDefinition{ID: "cluster.second", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.first"}}
	share := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, login, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), first, second, share) })
	h.seed(t, grant(cluster.Scope(), "cluster.share", rbac.User, "sharer"))
	got, err := h.authz.Grantable(t.Context(), h.as(t, "sharer"), cluster)
	if err != nil || slices.ContainsFunc(got, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.second" }) {
		t.Fatalf("Grantable offers a role whose holders could grant root: %v, %v", got, err)
	}
	if !slices.ContainsFunc(got, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.share" }) {
		t.Fatalf("Grantable = %v", got)
	}
}

func TestChangesNeedReadCommitted(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	// A member before the transaction's snapshot, which the first change in it takes.
	owner := h.as(t, "owner")
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authz := h.authz.WithTx(tx)
	for name, change := range map[string]func() error{
		"Apply":       func() error { return authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{b}}) },
		"Import":      func() error { return authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}) },
		"DeleteScope": func() error { return authz.DeleteScope(ctx, host, "t1", cluster.Scope()) },
	} {
		if err := change(); err == nil || !strings.Contains(err.Error(), "READ COMMITTED") {
			t.Errorf("%s in a REPEATABLE READ transaction: %v", name, err)
		}
	}
}

func TestAGrantPermissionIsAPowerOnlyWhereTheGrantReachesItsType(t *testing.T) {
	both := rbac.RoleDefinition{ID: "both", Permissions: []rbac.Permission{view, grantC, "workspace:grant"}, ResourceTypes: []string{"cluster", "workspace"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), both) })
	ctx := t.Context()
	h.seed(t,
		grant(workspace.Scope(), "workspace.admin", rbac.User, "owner"),
		grant(cluster.Scope(), "both", rbac.User, "holder"),
	)
	b := rbac.Binding{Role: "both", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	// On a cluster, workspace:grant changes no grants: the grantee holds it there as a plain
	// permission, which the owner, who holds it only for workspaces, doesn't.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a plain permission the actor holds only for another type: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "holder"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("granting a role the actor holds on the same cluster: %v", err)
	}
}

func TestDefiningARoleDerivesPrivilegeAndChecksTheActorFirst(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	plain := rbac.RoleDefinition{ID: "custom.plain", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Privileged: true}
	if err := h.authz.SetRole(ctx, admin, "t1", plain); err != nil {
		t.Fatal(err)
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || roles[0].Privileged {
		t.Fatalf("a role giving only what unprivileged roles give should not be privileged: %+v, %v", roles, err)
	}
	// Public and marked privileged, though nothing it gives is: the flag is derived.
	public := plain
	public.ID, public.Public = "custom.public", true
	if err := h.authz.SetRole(ctx, admin, "t1", public); err != nil {
		t.Fatalf("a public role marked privileged that gives nothing privileged: %v", err)
	}
	// Characters, not bytes, as the table counts them.
	named := plain
	named.ID, named.Name = "custom.named", strings.Repeat("역", 128)
	if err := h.authz.SetRole(ctx, admin, "t1", named); err != nil {
		t.Fatalf("a name of 128 characters: %v", err)
	}
	// Past its limit, or text PostgreSQL refuses.
	for _, name := range []string{strings.Repeat("n", 129), "a\x00b", "\xff"} {
		bad := plain
		bad.Name = name
		if err := h.authz.SetRole(ctx, admin, "t1", bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("a name %q: %v", name, err)
		}
	}
	// A character split between the name and the description is valid only joined.
	split := plain
	split.Name, split.Description = "\xe4\xb8", "\xad"
	if err := h.authz.SetRole(ctx, admin, "t1", split); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a character split between name and description: %v", err)
	}
	// Refused for who it is, not for what it asked: it learns nothing of the catalog.
	guess := rbac.RoleDefinition{ID: "custom.guess", Permissions: []rbac.Permission{"cluster:fly"}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, h.as(t, "nobody"), "t1", guess); !errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an actor who may not define roles probing the catalog: %v", err)
	}
}

func TestRedefiningARoleForATypeAgainRespectsConstraints(t *testing.T) {
	stop := false
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bucket.reader", Permissions: []rbac.Permission{"bucket:read"}, ResourceTypes: []string{"bucket", "cluster"}})
		c.Constraints = []rbac.Constraint{{Name: "managed elsewhere", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			p := in.Permission
			return stop && p == "bucket:grant", nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "bucket.reader", rbac.User, "admin"))
	reader := rbac.RoleDefinition{ID: "custom.reader", Permissions: []rbac.Permission{"bucket:read"}, ResourceTypes: []string{"bucket", "cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", reader); err != nil {
		t.Fatal(err)
	}
	bucket := rbac.Resource{Tenant: "t1", Type: "bucket", ID: "b1"}
	h.seed(t, grant(bucket.Scope(), reader.ID, rbac.User, "u"))
	narrowed := reader
	narrowed.ResourceTypes = []string{"cluster"}
	if err := h.authz.SetRole(ctx, admin, "t1", narrowed); err != nil {
		t.Fatal(err)
	}
	stop = true
	// Its grant on the bucket gives nothing now, and would give again.
	if err := h.authz.SetRole(ctx, admin, "t1", reader); !errors.Is(err, rbac.ErrDenied) || allowed(t, h, h.as(t, "u"), "bucket:read", bucket) {
		t.Fatalf("bringing back grants on a type a constraint keeps: %v", err)
	}
}

func TestARoleThatChangesAccessIsPrivileged(t *testing.T) {
	var asked []rbac.GrantInput
	h := setup(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.admin", rbac.User, "admin"))
	// workspace.admin, though the catalog doesn't mark it, changes grants, as tenant.roles defines
	// roles: managing access is privileged.
	for _, id := range []rbac.Role{"workspace.admin", "tenant.roles"} {
		if r, ok := h.authz.BuiltinRole(id); !ok || !r.Privileged {
			t.Errorf("%s: %+v", id, r)
		}
	}
	lead := rbac.RoleDefinition{
		ID: "custom.lead", Permissions: []rbac.Permission{"workspace:view", "workspace:grant"}, ResourceTypes: []string{"workspace"},
		GrantableRoles: []rbac.Role{"custom.viewer"},
	}
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{"workspace:view"}, ResourceTypes: []string{"workspace"}}
	for _, r := range []rbac.RoleDefinition{viewer, lead} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	roles, err := h.authz.CustomRoles(ctx, "t1")
	if err != nil || len(roles) != 2 || !roles[0].Privileged || roles[1].Privileged {
		t.Fatalf("CustomRoles = %+v, %v", roles, err)
	}
	asked = nil
	if err := h.authz.Apply(ctx, admin, workspace, rbac.Change{Grant: []rbac.Binding{{Role: lead.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || !asked[0].Role.Privileged {
		t.Fatalf("asked = %+v", asked)
	}
}

func TestRedefiningARoleAsksTheHostAboutItsGrants(t *testing.T) {
	robot := rbac.PrincipalKind("service_account")
	var asked []rbac.GrantInput
	var meanwhile func(ctx context.Context, q rbac.DB) error
	h := setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{robot}
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			if meanwhile != nil {
				do := meanwhile
				meanwhile = nil
				if err := do(ctx, q); err != nil {
					return err
				}
			}
			// A host's policy: service accounts and the public hold no privileged role.
			if (in.Binding.Principal.Kind == robot || in.Binding.Principal.Kind == rbac.Public) && in.Role.Privileged {
				return fmt.Errorf("%w: service accounts and the public hold no privileged role", rbac.ErrInvalid)
			}
			return nil
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	bot := h.member(t, rbac.Principal{Kind: robot, ID: "ci"})
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{{Role: op.ID, Principal: bot.Principal}, {Role: op.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, admin, cluster, rbac.Eligibility{Role: op.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "e"}, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// Giving root through op would give it to the service account, which the host refuses.
	asked = nil
	widened := op
	widened.Permissions = []rbac.Permission{view, login, root}
	err := h.authz.SetRole(ctx, admin, "t1", widened)
	var ie *rbac.InvalidError
	if !errors.As(err, &ie) || ie.Binding.Principal != bot.Principal {
		t.Fatalf("widening a role a service account holds to give root: %v", err)
	}
	if allowed(t, h, bot, root, cluster) {
		t.Fatal("a refused redefinition gave root")
	}
	// Each grant and the eligibility, as the role will be.
	if len(asked) != 3 || slices.ContainsFunc(asked, func(in rbac.GrantInput) bool {
		return in.Via != rbac.ViaRedefinition || !in.Role.Privileged || !slices.Contains(in.Role.Permissions, root) || in.Actor.Principal != admin.Principal
	}) {
		t.Fatalf("asked = %+v", asked)
	}
	// Renaming it gives nothing more, so asks about nothing.
	asked = nil
	renamed := op
	renamed.Name = "Operator"
	if err := h.authz.SetRole(ctx, admin, "t1", renamed); err != nil || len(asked) != 0 {
		t.Fatalf("renaming: %v, asked %+v", err, asked)
	}
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: op.ID, Principal: bot.Principal}}}); err != nil {
		t.Fatal(err)
	}
	// A grant made while the redefinition waits wasn't asked about, so it refuses the redefinition,
	// to be tried again.
	meanwhile = func(ctx context.Context, q rbac.DB) error {
		_, err := q.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'cluster', 'c1', 'service_account', 'ci', 'custom.op')`)
		return err
	}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant made meanwhile: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("tried again: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'service_account:ci'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("widening a role only those the host lets hold root hold: %v", err)
	}
	if !allowed(t, h, h.as(t, "u"), root, cluster) {
		t.Fatal("the redefinition should give what it gives")
	}
	// Narrowing it gives nothing more, so asks about nothing, even a grant the host would refuse
	// now, such as one made before its policy.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'service_account', 'ci', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	asked = nil
	narrowed := widened
	narrowed.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, admin, "t1", narrowed); err != nil || len(asked) != 0 {
		t.Fatalf("narrowing: %v, asked %+v", err, asked)
	}
	// A grant to the public gives nothing once its role isn't public, so making a public role
	// privileged asks nothing about it.
	pub := rbac.RoleDefinition{ID: "custom.pub", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.SetRole(ctx, admin, "t1", pub); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{{Role: pub.ID, Principal: rbac.Principal{Kind: rbac.Public}}}}); err != nil {
		t.Fatal(err)
	}
	asked = nil
	pub.Public, pub.Permissions = false, []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, admin, "t1", pub); err != nil || len(asked) != 0 {
		t.Fatalf("making a public role privileged: %v, asked %+v", err, asked)
	}
	if allowed(t, h, rbac.Subject{}, view, cluster) {
		t.Fatal("a grant to the public of a role no longer public gave access")
	}
}

func TestAGrantAskedAboutBeforeItsRoleIsRedefinedIsTriedAgain(t *testing.T) {
	robot := rbac.PrincipalKind("service_account")
	var h *harness
	var admin rbac.Subject
	// widenOn is how the grant is made that, once the host was asked about it, finds its role
	// widened to give root before its transaction: as another change would commit meanwhile.
	var widenOn rbac.Via
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	h = setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{robot}
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Binding.Principal.Kind == robot && in.Role.Privileged {
				return fmt.Errorf("%w: service accounts hold no privileged role", rbac.ErrInvalid)
			}
			if in.Via == widenOn {
				widenOn = ""
				widened := op
				widened.Permissions = []rbac.Permission{view, login, root}
				return h.authz.SetRole(ctx, admin, "t1", widened)
			}
			return nil
		}
	})
	ctx := t.Context()
	h.groups(t, "bots")
	admin = roleAdmin(t, h)
	// Eligible through a group, which the host lets hold a privileged role, so redefining isn't
	// refused for the eligibility; activating, the service account is.
	bot := h.member(t, rbac.Principal{Kind: robot, ID: "ci"}, "bots")
	b := rbac.Binding{Role: op.ID, Principal: bot.Principal}
	for _, via := range []rbac.Via{rbac.ViaApply, rbac.ViaImport, rbac.ViaActivation} {
		if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
			t.Fatal(err)
		}
		if via == rbac.ViaActivation {
			if err := h.authz.SetEligibility(ctx, admin, cluster, rbac.Eligibility{Role: op.ID, Principal: rbac.Principal{Kind: rbac.Group, ID: "bots"}, MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
		}
		grantOne := func() error {
			switch via {
			case rbac.ViaApply:
				return h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{b}})
			case rbac.ViaImport:
				return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}})
			default:
				_, err := h.authz.Activate(ctx, bot, cluster, rbac.Activation{Role: op.ID, Duration: time.Hour, Justification: "deploy"})
				return err
			}
		}
		widenOn = via
		if err := grantOne(); !errors.Is(err, rbac.ErrConflict) {
			t.Fatalf("%s of %s once widened since the host was asked: %v", via, op.ID, err)
		}
		if held, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{bot.Principal}}); err != nil || len(held) > 0 {
			t.Fatalf("%s of %s stored a grant the host was never asked about as it gives: %v, %+v", via, op.ID, err, held)
		}
		if err := grantOne(); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("%s of %s tried again: %v", via, op.ID, err)
		}
	}
}

func TestRedefiningARoleAsksAboutEachWayItsGrantsGiveMore(t *testing.T) {
	var asked []rbac.GrantInput
	var meanwhile func(ctx context.Context) error
	h := setup(t, func(c *rbac.Config) {
		// Gives view on workspaces too, so a custom role giving it can be for both types.
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "multi.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster", "workspace"}})
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			asked = append(asked, in)
			if meanwhile != nil {
				do := meanwhile
				meanwhile = nil
				return do(ctx)
			}
			return nil
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "multi.view", rbac.User, "admin"), grant(tenant, "workspace.admin", rbac.User, "admin"))
	// set defines r and returns whom the host was asked about.
	set := func(r rbac.RoleDefinition) []rbac.Principal {
		t.Helper()
		asked = nil
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		var whom []rbac.Principal
		for _, in := range asked {
			whom = append(whom, in.Binding.Principal)
		}
		return whom
	}
	give := func(on rbac.Resource, b rbac.Binding) {
		t.Helper()
		if err := h.authz.Apply(ctx, admin, on, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
			t.Fatal(err)
		}
	}
	want := func(what string, got []rbac.Principal, want ...rbac.Principal) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Fatalf("%s asked about %+v, not %+v", what, got, want)
		}
	}
	u := rbac.Principal{Kind: rbac.User, ID: "u"}

	// More types: a grant on a workspace reaches the role's new type there.
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	set(op)
	give(workspace, rbac.Binding{Role: op.ID, Principal: u})
	op.ResourceTypes = []string{"cluster", "workspace"}
	want("adding a type", set(op), u)
	op.ResourceTypes = []string{"cluster"}
	want("dropping a type", set(op))

	// More permissions, asking about none of the grants that give nothing: one expired, and one to
	// a kind the host doesn't declare.
	brief := rbac.Principal{Kind: rbac.User, ID: "brief"}
	give(cluster, rbac.Binding{Role: op.ID, Principal: brief, ExpiresAt: h.now.Add(time.Hour)})
	h.now = h.now.Add(2 * time.Hour)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'gone', 'x', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	op.Permissions = []rbac.Permission{view, login}
	// A grant whose note changes while the redefinition waits isn't the one the host was asked about.
	meanwhile = func(ctx context.Context) error {
		return h.authz.Apply(ctx, admin, workspace, rbac.Change{Grant: []rbac.Binding{{Role: op.ID, Principal: u, Note: "ticket"}}})
	}
	if err := h.authz.SetRole(ctx, admin, "t1", op); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant's note changed meanwhile: %v", err)
	}
	want("adding a permission", set(op), u)

	// Public: a grant to the public gives once its role is public again.
	pub := rbac.RoleDefinition{ID: "custom.pub", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	set(pub)
	give(cluster, rbac.Binding{Role: pub.ID, Principal: rbac.Principal{Kind: rbac.Public}})
	pub.Public = false
	want("making a role private", set(pub))
	pub.Public = true
	want("making a role public", set(pub), rbac.Principal{Kind: rbac.Public})

	// A grant on a cluster gives nothing once its role isn't for clusters, so widening it asks
	// nothing about that grant.
	ws := rbac.RoleDefinition{ID: "custom.ws", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster", "workspace"}}
	set(ws)
	give(cluster, rbac.Binding{Role: ws.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "v"}})
	ws.ResourceTypes = []string{"workspace"}
	set(ws)
	ws.Public = true
	want("widening a role not for the grant's scope", set(ws))

	// Grantable roles: listing another, or none, which lets holders grant any role they hold.
	g := rbac.Principal{Kind: rbac.User, ID: "g"}
	granter := rbac.RoleDefinition{ID: "custom.granter", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	set(granter)
	give(cluster, rbac.Binding{Role: granter.ID, Principal: g})
	granter.GrantableRoles = []rbac.Role{"cluster.login", op.ID}
	want("listing another role", set(granter), g)
	granter.GrantableRoles = []rbac.Role{"cluster.login"}
	want("listing fewer roles", set(granter))
	granter.GrantableRoles = nil
	want("listing none", set(granter), g)
}

func TestARoleRenamedOrNarrowedWhileAGrantWaitsIsGranted(t *testing.T) {
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	var h *harness
	var admin rbac.Subject
	var meanwhile *rbac.RoleDefinition
	h = setup(t, func(c *rbac.Config) {
		c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if r := meanwhile; r != nil && in.Via == rbac.ViaApply {
				meanwhile = nil
				return h.authz.SetRole(ctx, admin, "t1", *r)
			}
			return nil
		}
	})
	ctx := t.Context()
	admin = roleAdmin(t, h)
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	renamed, narrowed := op, op
	renamed.Name = "Operator"
	narrowed.Permissions = []rbac.Permission{view}
	for i, r := range []rbac.RoleDefinition{renamed, narrowed} {
		meanwhile = &r
		b := rbac.Binding{Role: op.ID, Principal: rbac.Principal{Kind: rbac.User, ID: fmt.Sprint("u", i)}}
		if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
			t.Fatalf("granting a role %s meanwhile, which gives no more: %v", []string{"renamed", "narrowed"}[i], err)
		}
	}
}

func TestARoleHandingOutAPrivilegedOneIsPrivilegedHoweverItIsGranted(t *testing.T) {
	seen := map[rbac.Via]bool{}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "workspace.owner", Permissions: []rbac.Permission{"workspace:view", "workspace:grant", "workspace:delete"}, ResourceTypes: []string{"workspace"}, Privileged: true,
		})
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Role.ID == "custom.a" {
				seen[in.Via] = in.Role.Privileged
			}
			return nil
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.owner", rbac.User, "admin"))
	ws := []string{"workspace"}
	// a gives nothing privileged itself, but hands out b, which does.
	b := rbac.RoleDefinition{ID: "custom.b", Permissions: []rbac.Permission{"workspace:view", "workspace:delete"}, ResourceTypes: ws}
	a := rbac.RoleDefinition{ID: "custom.a", Permissions: []rbac.Permission{"workspace:grant"}, ResourceTypes: ws, GrantableRoles: []rbac.Role{b.ID}}
	for _, d := range []rbac.RoleDefinition{b, a} {
		if err := h.authz.SetRole(ctx, admin, "t1", d); err != nil {
			t.Fatal(err)
		}
	}
	x := rbac.Principal{Kind: rbac.User, ID: "x"}
	if err := h.authz.Apply(ctx, admin, workspace, rbac.Change{Grant: []rbac.Binding{{Role: a.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "y"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, admin, workspace, rbac.Eligibility{Role: a.ID, Principal: x, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), workspace, rbac.Activation{Role: a.ID, Duration: time.Minute, Justification: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), a.ID, rbac.User, "z")}); err != nil {
		t.Fatal(err)
	}
	for _, via := range []rbac.Via{rbac.ViaApply, rbac.ViaEligibility, rbac.ViaActivation, rbac.ViaImport} {
		if privileged, asked := seen[via]; !asked || !privileged {
			t.Errorf("%s: asked %t, privileged %t", via, asked, privileged)
		}
	}
}

func TestDefiningARoleCreatedWhileItWaitsAsksTheConstraintsAgain(t *testing.T) {
	h := setup(t, constrain("managed elsewhere", grantC))
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	// The host creates the role and grants it in its transaction, which holds the tenant until it
	// commits; creating a role changes no grant, so the constraint doesn't stop it.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), op.ID, rbac.User, "op")}); err != nil {
		t.Fatal(err)
	}
	wider := op
	wider.Permissions = []rbac.Permission{view, login}
	// The host's transaction, whose locks SetRole waits on, not another's on the server.
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.SetRole(ctx, admin, "t1", wider) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("SetRole didn't wait for the host: %v", err)
		default:
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE wait_event_type = 'Lock' AND wait_event = 'advisory' AND $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, rbac.ErrConflict) || allowed(t, h, h.as(t, "op"), login, cluster) {
		t.Fatalf("replacing a role created while the change waited, past the constraint: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("asked again, the constraint stops it: %v", err)
	}
}

// Under the tenant's lock SetRole and DeleteRole decide the actor's power to define roles, its
// label values and the denies binding it as of one moment, though DeleteExpired, which takes no
// lock, can delete what binds it between their statements. Here a deny of changing grants on the
// cluster the role is granted on, naming the group that lets the actor define roles, is set while
// the change waits for the tenant, and once its transaction has read the actor's authority,
// DeleteExpired, by a clock past the end of the actor's place in that group but for the change's
// still in force, removes it: at no moment did the actor hold the power and escape the deny, so the
// change is tried again, or where a deny below the tenant bound the actor before, so the change
// read the cluster from the host then, refused. Read apart, the deny after the place was removed,
// the role was changed, and its grant on the cluster revoked or narrowed.
func TestARoleChangeDecidesThePowerAndTheDenyItActsByAsOfOneMoment(t *testing.T) {
	r := rbac.RoleDefinition{ID: "custom.r", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	for _, bound := range []bool{false, true} {
		for name, change := range map[string]func(h *harness, actor rbac.Subject) error{
			"narrowing it": func(h *harness, actor rbac.Subject) error {
				narrowed := r
				narrowed.Permissions = []rbac.Permission{view}
				return h.authz.SetRole(h.ctx, actor, "t1", narrowed)
			},
			"deleting it": func(h *harness, actor rbac.Subject) error { return h.authz.DeleteRole(h.ctx, actor, "t1", r.ID) },
		} {
			testRoleChangeAsOfOneMoment(t, r, bound, name, change)
		}
	}
}

// testRoleChangeAsOfOneMoment is TestARoleChangeDecidesThePowerAndTheDenyItActsByAsOfOneMoment's
// change to r, where bound, by an actor a deny on another cluster binds before the change.
func testRoleChangeAsOfOneMoment(t *testing.T, r rbac.RoleDefinition, bound bool, name string, change func(h *harness, actor rbac.Subject) error) {
	t.Helper()
	t.Run(fmt.Sprintf("%s, bound below before %t", name, bound), func(t *testing.T) {
		h := setup(t)
		ctx := t.Context()
		admin := roleAdmin(t, h)
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
		h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "v"), grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.Group, "admins"),
			grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "x"))
		x := h.as(t, "x")
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
				VALUES ('t1', 'admins', 'user', 'x', $1)`, h.now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		// Of another permission, so it stops nothing.
		if bound {
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					VALUES ('t1', 'cluster', 'c2', 'rootless', '{user:x}', ARRAY[$1::text])`, root); err != nil {
				t.Fatal(err)
			}
		}
		// The host's transaction holds the tenant, so the change waits for it once it has checked
		// what it can before.
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
		if err := rbac.Lock(ctx, tx, "t1", nil, nil); err != nil {
			t.Fatal(err)
		}
		var pid int32
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Fatal(err)
		}
		armed := make(chan struct{})
		var expired int64
		var expiring error
		rbac.SetReadingRoles(t, func() {
			select {
			case <-armed:
			default:
				return
			}
			if expiring != nil || expired > 0 {
				return
			}
			// Past the place's end, on the clock DeleteExpired reads; the change has read its own.
			h.now = h.now.Add(2 * time.Hour)
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			expired, expiring = h.authz.DeleteExpired(bounded)
		})
		done := make(chan error, 1)
		go func() { done <- change(h, x) }()
		waitUntil := time.Now().Add(30 * time.Second)
		for waiting := false; !waiting; {
			select {
			case err := <-done:
				t.Fatalf("the change didn't wait for the host: %v", err)
			default:
			}
			if time.Now().After(waitUntil) {
				t.Fatal("the change never waited for the host's transaction")
			}
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity
					WHERE wait_event_type = 'Lock' AND wait_event = 'advisory' AND $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				VALUES ('t1', 'cluster', 'c1', 'frozen', '{group:admins}', ARRAY[$1::text])`, grantC); err != nil {
			t.Fatal(err)
		}
		close(armed)
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("the change didn't end once the host's transaction did")
		}
		if expiring != nil || expired == 0 {
			t.Fatalf("DeleteExpired removed %d rows while the change ran: %v", expired, expiring)
		}
		var denied *rbac.DeniedError
		if refused := errors.As(err, &denied) && denied.Permission == grantC; bound && !refused || !bound && !errors.Is(err, rbac.ErrConflict) {
			t.Errorf("custom.r was changed by an actor that held the power to define roles and escaped the deny at no moment: %v", err)
		}
		var perms []string
		if err := h.pool.QueryRow(ctx, `SELECT permissions FROM rbac_roles WHERE tenant = 't1' AND id = $1`, r.ID).Scan(&perms); err != nil ||
			!slices.Equal(perms, []string{string(login), string(view)}) {
			t.Errorf("custom.r gives %v, %v", perms, err)
		}
		var grants int
		if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_grants WHERE tenant = 't1' AND role = $1`, r.ID).Scan(&grants); err != nil || grants != 1 {
			t.Errorf("custom.r is granted %d times, %v", grants, err)
		}
	})
}

// pastExpiry is a call an actor in groups admins and frozen makes, by the power group admins gives
// it, which a deny naming frozen removes.
type pastExpiry struct {
	mutate []func(*rbac.Config)
	// seed grants group admins the power, and writes what else the call needs.
	seed func(t *testing.T, h *harness)
	// deny writes the deny naming frozen, of denied, which refuses the call.
	deny   string
	denied rbac.Permission
	// call makes it, as x, and kept reports whether a change left what it changes as it was.
	call func(t *testing.T, h *harness, x rbac.Subject) error
	kept string
	// check is set for a read, which has no transaction to set the deny in or to read in once
	// DeleteExpired has run.
	check bool
}

// A call decides no earlier than DeleteExpired has deleted by, which removes ended places in groups,
// passing over those another transaction holds, before ended memberships, in transactions of its
// own, by its own clock. Here the actor's place in admins, through which it holds the power the call
// needs, ends in an hour, and its place in frozen, which a deny of that power names, in two; and
// DeleteExpired, by a clock three hours on, removes the place in frozen and passes over the one in
// admins, which another transaction holds. A call reading the actor by the time it read before,
// either before DeleteExpired, as the host's clock is behind its own, or in its transaction once it
// has read the time it decides at, while it reads its actor, found the actor in admins and in no
// group a deny names: it held the power and escaped the deny at no moment, so the call is refused,
// as by the power that had ended by DeleteExpired's clock, or tried again. Read by its own time, the
// change was made, and the check allowed.
func TestACallDecidesNoEarlierThanDeleteExpiredDeletedBy(t *testing.T) {
	const (
		onTenant = `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'tenant', 't1', 'freeze', '{group:frozen}', ARRAY[$1::text])`
		onW1     = `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`
	)
	tenant := rbac.TenantRoot("t1")
	granting := func(t *testing.T, h *harness) {
		t.Helper()
		h.seed(t, grant(tenant, "cluster.admin", rbac.Group, "admins"))
		h.as(t, "v")
	}
	// Denies' own permission no deny removes, but a label refuses a deny on its scope to one without
	// its values, which a deny of the value naming frozen removes.
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	guarding := func(t *testing.T, h *harness) {
		t.Helper()
		h.seed(t, grant(tenant, guardRole.ID, rbac.Group, "admins"))
		h.hold(t, "x", "level:high")
		h.as(t, "v")
	}
	defining := func(t *testing.T, h *harness) {
		t.Helper()
		h.seed(t, grant(tenant, "tenant.roles", rbac.Group, "admins"), grant(tenant, "cluster.login", rbac.User, "x"))
	}
	logging := func(t *testing.T, h *harness) {
		t.Helper()
		h.seed(t, grant(tenant, "cluster.login", rbac.Group, "admins"))
	}
	guards := []func(*rbac.Config){withLabels, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) }}
	allowedBy := func(ok bool) error {
		if ok {
			return nil
		}
		return rbac.ErrDenied
	}
	for name, c := range map[string]pastExpiry{
		"Apply": {
			seed: granting, deny: onW1, denied: grantC,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.Apply(h.ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("v"), ExpiresAt: h.now.Add(30 * time.Minute)}}})
			},
			kept: `SELECT NOT EXISTS (SELECT FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:v')`,
		},
		"SetEligibility": {
			// What an eligibility hands on is held for good, as only the power to grant isn't.
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				granting(t, h)
				h.seed(t, grant(tenant, "cluster.login", rbac.User, "x"))
			},
			deny: onW1, denied: grantC,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.SetEligibility(h.ctx, x, cluster, rbac.Eligibility{Role: "cluster.login", Principal: identity("v"), MaxDuration: time.Hour, ExpiresAt: h.now.Add(30 * time.Minute)})
			},
			kept: `SELECT NOT EXISTS (SELECT FROM rbac_eligibilities WHERE tenant = 't1' AND principal = 'user:v')`,
		},
		"DeleteEligibility": {
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				granting(t, h)
				if _, err := h.pool.Exec(h.ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
					VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.login', 3600)`); err != nil {
					t.Fatal(err)
				}
			},
			deny: onW1, denied: grantC,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.DeleteEligibility(h.ctx, x, cluster, "cluster.login", identity("v"))
			},
			kept: `SELECT EXISTS (SELECT FROM rbac_eligibilities WHERE tenant = 't1' AND principal = 'user:v')`,
		},
		"SetDeny": {
			mutate: guards, seed: guarding, deny: onTenant, denied: "level:high",
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.SetDeny(h.ctx, x, secret, rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("v")}, Permissions: []rbac.Permission{root}})
			},
			kept: `SELECT NOT EXISTS (SELECT FROM rbac_denies WHERE tenant = 't1' AND id = 'd')`,
		},
		"DeleteDeny": {
			mutate: guards,
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				guarding(t, h)
				if _, err := h.pool.Exec(h.ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					VALUES ('t1', 'cluster', 'c1', 'd', '{user:v}', ARRAY[$1::text])`, root); err != nil {
					t.Fatal(err)
				}
			},
			deny: onTenant, denied: "level:high",
			call: func(_ *testing.T, h *harness, x rbac.Subject) error { return h.authz.DeleteDeny(h.ctx, x, secret, "d") },
			kept: `SELECT EXISTS (SELECT FROM rbac_denies WHERE tenant = 't1' AND id = 'd')`,
		},
		"SetRole": {
			seed: defining, deny: onTenant, denied: rbac.DefineRoles,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.SetRole(h.ctx, x, "t1", rbac.RoleDefinition{ID: "custom.r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}})
			},
			kept: `SELECT NOT EXISTS (SELECT FROM rbac_roles WHERE tenant = 't1')`,
		},
		"DeleteRole": {
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				defining(t, h)
				if _, err := h.pool.Exec(h.ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.r', ARRAY[$1::text], '{cluster}')`, view); err != nil {
					t.Fatal(err)
				}
			},
			deny: onTenant, denied: rbac.DefineRoles,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.DeleteRole(h.ctx, x, "t1", "custom.r")
			},
			kept: `SELECT EXISTS (SELECT FROM rbac_roles WHERE tenant = 't1' AND id = 'custom.r')`,
		},
		"ChangeMembers": {
			mutate: []func(*rbac.Config){func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers) }},
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				h.seed(t, grant(tenant, groupMembers.ID, rbac.Group, "admins"))
				h.groups(t, "crew")
				h.as(t, "v")
			},
			deny: onTenant, denied: rbac.GroupMembers,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.ChangeMembers(h.ctx, x, "t1", []rbac.Member{{Group: "crew", Principal: identity("v")}}, nil)
			},
			kept: `SELECT NOT EXISTS (SELECT FROM rbac_members WHERE tenant = 't1' AND group_id = 'crew')`,
		},
		"DeleteGroup": {
			mutate: []func(*rbac.Config){func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
			}},
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				h.seed(t, grant(tenant, "tenant.groups", rbac.Group, "admins"))
				h.groups(t, "ops")
			},
			deny: onTenant, denied: rbac.ManageGroups,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.DeleteGroup(h.ctx, x, "t1", "ops")
			},
			kept: `SELECT EXISTS (SELECT FROM rbac_groups WHERE tenant = 't1' AND id = 'ops')`,
		},
		"Authorize": {
			seed: logging, deny: onW1, denied: login, check: true,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				return h.authz.Authorize(h.ctx, x, login, cluster)
			},
		},
		"Explain": {
			seed: logging, deny: onW1, denied: login, check: true,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				d, err := h.authz.Explain(h.ctx, x, login, cluster)
				if err != nil {
					return err
				}
				return allowedBy(d.Allowed)
			},
		},
		"Permissions": {
			seed: logging, deny: onW1, denied: login, check: true,
			call: func(_ *testing.T, h *harness, x rbac.Subject) error {
				ps, err := h.authz.Permissions(h.ctx, x, cluster)
				if err != nil {
					return err
				}
				return allowedBy(slices.Contains(ps, login))
			},
		},
		"Filter": {
			seed: func(t *testing.T, h *harness) {
				t.Helper()
				logging(t, h)
				hostTable(t, h)
			},
			deny: onW1, denied: login, check: true,
			// Of the host's clusters, c0 is in w1.
			call: func(t *testing.T, h *harness, x rbac.Subject) error {
				t.Helper()
				return allowedBy(slices.Contains(listed(t, h, x, login), "c0"))
			},
		},
		"Reachable": {
			seed: logging, deny: onW1, denied: login, check: true,
			call: func(t *testing.T, h *harness, x rbac.Subject) error {
				t.Helper()
				reached, _ := reachedBy(t, h, []rbac.Resource{cluster}, x, login)
				return allowedBy(len(reached) > 0)
			},
		},
	} {
		for _, during := range []bool{false, true} {
			if during && c.check {
				continue
			}
			t.Run(fmt.Sprintf("%s, in its transaction %t", name, during), func(t *testing.T) {
				h := setup(t, c.mutate...)
				ctx := t.Context()
				h.groups(t, "admins", "frozen")
				c.seed(t, h)
				x := h.as(t, "x", "admins", "frozen")
				exec := func(q string, args ...any) {
					t.Helper()
					if _, err := h.pool.Exec(ctx, q, args...); err != nil {
						t.Fatal(err)
					}
				}
				exec(`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'admins'`, h.now.Add(time.Hour))
				exec(`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`, h.now.Add(2*time.Hour))
				deny := func() { exec(c.deny, c.denied) }
				expired := false
				expire := func() {
					expired = true
					// Another transaction holds x's place in admins, as a change ending it that is then
					// refused does, so DeleteExpired passes over it.
					l, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = l.Rollback(context.WithoutCancel(ctx)) }()
					if _, err := l.Exec(ctx, `SELECT FROM rbac_members WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'admins' FOR UPDATE`); err != nil {
						t.Fatal(err)
					}
					h.now = h.now.Add(3 * time.Hour)
					bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					n, err := h.authz.DeleteExpired(bounded)
					var places []string
					if err == nil {
						err = h.pool.QueryRow(bounded, `SELECT coalesce(array_agg(group_id ORDER BY group_id), '{}') FROM rbac_members
							WHERE tenant = 't1' AND principal = 'user:x'`).Scan(&places)
					}
					if err != nil || n == 0 || !slices.Equal(places, []string{"admins"}) {
						t.Errorf("DeleteExpired removed %d rows, leaving x in %v: %v", n, places, err)
					}
				}
				if during {
					// Set once the change has checked the actor before its transaction, as it takes its
					// locks; DeleteExpired runs as it reads its actor there.
					rbac.BeforeStatement(t, "pg_advisory_xact_lock", true, deny)
					rbac.BeforeStatement(t, rbac.HeldMarker, false, expire)
				} else {
					deny()
					expire()
					// The call's clock, behind DeleteExpired's.
					h.now = h.now.Add(-3 * time.Hour)
				}
				err := c.call(t, h, x)
				if !expired {
					t.Fatal("DeleteExpired didn't run while the change read its actor")
				}
				if !errors.Is(err, rbac.ErrDenied) && (c.check || !errors.Is(err, rbac.ErrConflict)) {
					t.Errorf("x acted by its place in admins, which ended before its place in frozen, which the deny binds it by: at no moment did it hold the power and escape the deny: %v", err)
				}
				if c.kept != "" {
					var kept bool
					if err := h.pool.QueryRow(ctx, c.kept).Scan(&kept); err != nil || !kept {
						t.Errorf("the change was made: %v", err)
					}
				}
			})
		}
	}
}

// As TestACallDecidesNoEarlierThanDeleteExpiredDeletedBy, through a membership: DeleteExpired
// removes ended places in groups before ended memberships, and passes over a membership another
// transaction holds, as a change adding its identity to a group holds the membership it joins with.
// Here the actor's own grant, which it holds only while its membership is, gives the power, and its
// membership ends in an hour, its place in frozen, which a deny names, in two: read in the change's
// transaction once DeleteExpired, by a clock three hours on, has removed the place, the actor held
// the power and escaped the deny at no moment.
func TestAChangeDecidesNoEarlierThanDeleteExpiredDeletedByPastAMembershipItPassedOver(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "frozen")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "x"), grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "y"))
	x := h.as(t, "x", "frozen")
	h.as(t, "v")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x'`, h.now.Add(time.Hour))
	exec(`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`, h.now.Add(2*time.Hour))
	change := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("v"), ExpiresAt: h.now.Add(30 * time.Minute)}}}
	l, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := l.Exec(ctx, `SELECT FROM rbac_memberships WHERE tenant = 't1' AND principal = 'user:x' FOR SHARE`); err != nil {
		t.Fatal(err)
	}
	rbac.BeforeStatement(t, "pg_advisory_xact_lock", true, func() {
		exec(`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`, grantC)
	})
	var expired int64
	var expiring error
	rbac.BeforeStatement(t, rbac.HeldMarker, false, func() {
		h.now = h.now.Add(3 * time.Hour)
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		expired, expiring = h.authz.DeleteExpired(bounded)
	})
	err = h.authz.Apply(ctx, x, cluster, change)
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_members WHERE tenant = 't1' AND principal = 'user:x'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if expiring != nil || expired == 0 || left != 0 {
		t.Fatalf("DeleteExpired removed %d rows, leaving x in %d groups: %v", expired, left, expiring)
	}
	if !errors.Is(err, rbac.ErrDenied) && !errors.Is(err, rbac.ErrConflict) {
		t.Errorf("x granted on c1 by its own grant, held only while its membership was, which ended before its place in frozen, which the deny binds it by: at no moment did it hold the power and escape the deny: %v", err)
	}
	var denied *rbac.DeniedError
	if err := h.authz.Apply(ctx, h.as(t, "y", "frozen"), cluster, change); !errors.As(err, &denied) {
		t.Errorf("the deny didn't stop y, in frozen: %v", err)
	}
}

// As TestACallDecidesNoEarlierThanDeleteExpiredDeletedBy, for an approver of an activation on a
// labeled scope, who must be one of the approvers holding the label's values: here it is an approver
// by its place in approvers, which ends in an hour, and a deny of its value names frozen, its place
// in which ends in two.
func TestAnApproverIsCheckedNoEarlierThanDeleteExpiredDeletedBy(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	for _, during := range []bool{false, true} {
		t.Run(fmt.Sprintf("in its transaction %t", during), func(t *testing.T) {
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
			h.hold(t, "owner", "level:high")
			u := h.as(t, "u")
			h.hold(t, "u", "level:high")
			approver := h.as(t, "approver", "approvers", "frozen")
			h.hold(t, "approver", "level:high")
			if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), secret, rbac.Eligibility{
				Role: "cluster.login", Principal: u.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("approvers")},
			}); err != nil {
				t.Fatal(err)
			}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:approver' AND group_id = 'approvers'`, h.now.Add(time.Hour))
			exec(`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:approver' AND group_id = 'frozen'`, h.now.Add(2*time.Hour))
			deny := func() {
				exec(`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					VALUES ('t1', 'tenant', 't1', 'freeze', '{group:frozen}', '{level:high}')`)
			}
			expired := false
			expire := func() {
				expired = true
				l, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = l.Rollback(context.WithoutCancel(ctx)) }()
				if _, err := l.Exec(ctx, `SELECT FROM rbac_members WHERE tenant = 't1' AND principal = 'user:approver' AND group_id = 'approvers' FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				h.now = h.now.Add(3 * time.Hour)
				bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				n, err := h.authz.DeleteExpired(bounded)
				var places []string
				if err == nil {
					err = h.pool.QueryRow(bounded, `SELECT coalesce(array_agg(group_id ORDER BY group_id), '{}') FROM rbac_members
						WHERE tenant = 't1' AND principal = 'user:approver'`).Scan(&places)
				}
				if err != nil || n == 0 || !slices.Equal(places, []string{"approvers"}) {
					t.Errorf("DeleteExpired removed %d rows, leaving the approver in %v: %v", n, places, err)
				}
			}
			if during {
				rbac.BeforeStatement(t, "pg_advisory_xact_lock", true, deny)
				rbac.BeforeStatement(t, rbac.HeldMarker, false, expire)
			} else {
				deny()
				expire()
				h.now = h.now.Add(-3 * time.Hour)
			}
			_, err := h.authz.Activate(ctx, u, secret, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "on call", Approver: approver})
			if !expired {
				t.Fatal("DeleteExpired didn't run while the activation read its approver")
			}
			if !errors.Is(err, rbac.ErrDenied) && !errors.Is(err, rbac.ErrConflict) {
				t.Errorf("approved by one that was an approver and escaped the deny of the label's value at no moment: %v", err)
			}
			var activated bool
			if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE tenant = 't1' AND source = 'activation')`).Scan(&activated); err != nil || activated {
				t.Errorf("u activated the role: %v", err)
			}
		})
	}
}

// DeleteExpired records with each batch the latest time a row it removes ended at, and a read
// decides no earlier than the latest recorded: a run removing what ended sooner leaves it, one
// removing nothing records nothing, and runs don't wait for each other, one in a host's transaction
// left open too.
func TestDeleteExpiredKeepsTheLatestTimeItDeletedByWithoutWaiting(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	base := h.now
	x := h.as(t, "x")
	ending := func(by time.Duration) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
			VALUES ('t1', 'cluster', 'c1', 'user', 'y', 'cluster.login', $1)`, base.Add(by)); err != nil {
			t.Fatal(err)
		}
	}
	ending(30 * time.Minute)
	ending(90 * time.Minute)
	ending(150 * time.Minute)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	h.now = base.Add(time.Hour)
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	h.now = base.Add(3 * time.Hour)
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := h.authz.DeleteExpired(bounded); err != nil {
		t.Fatalf("DeleteExpired waited for one in a host's transaction: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	h.now = base.Add(2 * time.Hour)
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 0 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	latest := func() (time.Time, int) {
		t.Helper()
		var latest time.Time
		var rows int
		if err := h.pool.QueryRow(ctx, `SELECT max(until), count(*) FROM rbac_expired`).Scan(&latest, &rows); err != nil {
			t.Fatal(err)
		}
		return latest, rows
	}
	if at, rows := latest(); !at.Equal(base.Add(150*time.Minute)) || rows != 2 {
		t.Errorf("DeleteExpired recorded %d times, the latest %v", rows, at)
	}
	ending(45 * time.Minute)
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	if at, rows := latest(); !at.Equal(base.Add(150*time.Minute)) || rows > 2 {
		t.Errorf("DeleteExpired recorded %d times, the latest %v", rows, at)
	}
	// A grant DeleteExpired never saw, ended by the latest time, gives nothing to a check by an
	// earlier clock.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', $1)`, base.Add(120*time.Minute)); err != nil {
		t.Fatal(err)
	}
	h.now = base
	if allowed(t, h, x, login, cluster) {
		t.Error("a check by a clock behind the latest time DeleteExpired deleted by read a grant ended by then")
	}
}

// A call decides later than its own clock only where DeleteExpired removed a row that ended after
// it: here a run by a clock three hours on removes y's login, which ended half an hour before, and
// passes over z's, which ends in two hours and another transaction holds. A check by the earlier
// clock still reads z's login, and a change, which such a run commits beside as it ends, isn't tried
// again.
func TestACallDecidesByItsOwnClockWhereDeleteExpiredRemovedNothingEndingAfterIt(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprintf("a change %t", change), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			base := h.now
			h.groups(t, "admins")
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.Group, "admins"))
			x, z := h.as(t, "x", "admins"), h.as(t, "z")
			h.as(t, "v")
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
				VALUES ('t1', 'cluster', 'c1', 'user', 'z', 'cluster.login', $1)`, base.Add(2*time.Hour)); err != nil {
				t.Fatal(err)
			}
			expired := false
			expire := func() {
				expired = true
				if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
					VALUES ('t1', 'cluster', 'c1', 'user', 'y', 'cluster.login', $1)`, base.Add(-30*time.Minute)); err != nil {
					t.Error(err)
					return
				}
				expireHolding(t, h, `SELECT FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:z'`)
				h.now = base
			}
			if !change {
				expire()
				if !allowed(t, h, z, login, cluster) {
					t.Error("a check by its own clock read z's login, which ends in two hours, as ended")
				}
				return
			}
			// As the change reads, last, whether a run committed since it read its actor.
			rbac.BeforeStatement(t, "clock_timestamp()) END FROM rbac_expired", false, expire)
			err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("v"), ExpiresAt: base.Add(30 * time.Minute)}}})
			if !expired {
				t.Fatal("DeleteExpired didn't run as the change ended")
			}
			if err != nil {
				t.Errorf("a change was refused once DeleteExpired removed only what had ended before its time: %v", err)
			}
		})
	}
}

// As of a time, a read decides at that time, whatever DeleteExpired has deleted by since: here x's
// login, as of the time AsOf reads, ends 200 ms after it was granted, and DeleteExpired has since
// removed it by the database's clock, by which a check behind it decides.
func TestAsOfDecidesAtItsTimeWhateverDeleteExpiredDeletedBy(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.now = dbNow(t, h)
	x := h.as(t, "x")
	var expires time.Time
	if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', statement_timestamp() + interval '200 milliseconds')
		RETURNING expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	at := committedAt(t, h, `entity = 'grant' AND principal = 'user:x'`)
	if !at.Before(expires) {
		t.Fatalf("x's grant committed at %v, once it had expired at %v", at, expires)
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Until it expires by the database's clock, which DeleteExpired records no time past.
	if _, err := h.pool.Exec(bounded, `SELECT pg_sleep(extract(epoch FROM $1 - clock_timestamp()))`, expires); err != nil {
		t.Fatal(err)
	}
	was := h.now
	h.now = dbNow(t, h)
	if n, err := h.authz.DeleteExpired(bounded); err != nil || n == 0 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	h.now = was
	if allowed(t, h, x, login, cluster) {
		t.Fatal("a check decided earlier than DeleteExpired deleted by")
	}
	err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, x, login, cluster) })
	if err != nil {
		t.Errorf("as of a time the grant was in force, it wasn't: %v", err)
	}
}

// DeleteExpired records no time past the database's clock, which its batches delete by too: by a
// clock a year ahead, as a host's set wrong, every later call of every host would otherwise decide a
// year on, every grant ending before then read as ended, for good, as the latest time only moves on.
// Here it removes y's grant, which ended by the database's clock, and not x's, which ends in an
// hour.
func TestDeleteExpiredRecordsNoTimePastTheDatabasesClock(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.now = dbNow(t, h)
	x := h.as(t, "x")
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{
		Role: "cluster.login", Principal: x.Principal, ExpiresAt: h.now.Add(time.Hour),
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'y', 'cluster.login', $1)`, h.now); err != nil {
		t.Fatal(err)
	}
	now := h.now
	h.now = now.AddDate(1, 0, 0)
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	var latest time.Time
	if err := h.pool.QueryRow(ctx, `SELECT max(until) FROM rbac_expired`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if after := dbNow(t, h); latest.After(after) {
		t.Errorf("DeleteExpired by a clock a year ahead recorded %v, past the database's clock, %v", latest, after)
	}
	h.now = now
	if !allowed(t, h, x, login, cluster) {
		t.Error("a check decided as late as the clock a year ahead DeleteExpired ran by")
	}
}

// A time in rbac_expired past the database's clock, which only a role that may disable the table's
// triggers can write, or the database's clock going back can leave there, moves no call past that
// clock: otherwise every later call of every host decided at it, for good. Here a deny of root on c1
// names contractors, u's place in which ends in five years, v holds sudo there from four years on,
// both hold high, and u login. Once the table holds a time at the end of 9999, u is still denied root,
// v still holds no sudo, as AsOf of the same moment says, Holders still leaves u out, and Filter's
// condition still keeps no row u may not have root on, and still keeps the row it may log in to.
func TestATimePastTheDatabasesClockInExpiredMovesNoCallPastIt(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	h.now = dbNow(t, h)
	h.groups(t, "contractors")
	u, v := h.as(t, "u", "contractors"), h.as(t, "v")
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "u"), rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
		Role: "cluster.sudo", Principal: v.Principal,
		Condition: rbac.Condition{Expression: fmt.Sprintf(`request.time >= timestamp(%q)`, h.now.AddDate(4, 0, 0).UTC().Format(time.RFC3339))},
	}})
	h.hold(t, "u", "level:high")
	h.hold(t, "v", "level:high")
	c1 := cluster
	c1.Labels = rbac.Label{"level": {"high"}}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:u' AND group_id = 'contractors'`, []any{h.now.AddDate(5, 0, 0)}},
		{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'cluster', 'c1', 'no-root', '{group:contractors}', ARRAY[$1::text])`, []any{root}},
		{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
		{`INSERT INTO secrets VALUES ('t1', 'c1', $1, '{level:high}')`, []any{h.path(t, c1)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	listed := func(s rbac.Subject, p rbac.Permission) []string {
		t.Helper()
		pred, err := h.authz.Filter(ctx, s, p, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	decided := func(when string) {
		t.Helper()
		if err := h.authz.Authorize(ctx, u, root, c1); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s, the deny on contractors no longer binds u: %v", when, err)
		}
		if err := h.authz.Authorize(ctx, v, root, c1); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s, v holds sudo, which it holds only four years on: %v", when, err)
		}
		var now time.Time
		if err := h.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		var uAsOf, vAsOf error
		if err := h.authz.AsOf(ctx, "t1", now, func(a *rbac.Authorizer) error {
			uAsOf, vAsOf = a.Authorize(ctx, u, root, c1), a.Authorize(ctx, v, root, c1)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(uAsOf, rbac.ErrDenied) || !errors.Is(vAsOf, rbac.ErrDenied) {
			t.Errorf("%s, AsOf of now allows u root (%v) or v root (%v)", when, uAsOf, vAsOf)
		}
		holders, err := h.authz.Holders(ctx, root, c1)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(holders, func(o rbac.Holder) bool { return o.Principal == u.Principal }) {
			t.Errorf("%s, Holders lists u, whom the deny on contractors binds", when)
		}
		if ids := listed(u, root); len(ids) > 0 {
			t.Errorf("%s, Filter's condition keeps %v for u's root, which the deny on contractors denies", when, ids)
		}
		if ids := listed(u, login); !slices.Equal(ids, []string{"c1"}) {
			t.Errorf("%s, Filter's condition keeps %v for u's login, not c1", when, ids)
		}
	}
	decided("before the time past the clock")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// As a role that may disable the trigger refusing such a time, where there is one.
	refusing := func(change string) string {
		return `DO $$ BEGIN
			IF EXISTS (SELECT FROM pg_trigger WHERE tgrelid = 'rbac_expired'::regclass AND tgname = 'rbac_expired_until') THEN
			  ALTER TABLE rbac_expired ` + change + ` TRIGGER rbac_expired_until;
			END IF;
		END $$`
	}
	for _, sql := range []string{refusing("DISABLE"), `INSERT INTO rbac_expired (until) VALUES ('9999-12-30 23:59:59.999999+00')`, refusing("ENABLE ALWAYS")} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	decided("once rbac_expired holds a time past the database's clock")
}

// A check decides no earlier than a time DeleteExpired recorded after its statement began, which a
// statement sees where it takes its snapshot later, as one sent in a simple query does once it has
// waited for a lock as it was planned: bounded by the clock as the statement began, it decided
// before what the run removed had ended, by the state the run left, which no moment held. Here x
// logs in on the tenant, by its membership, and a deny of login on w1 names frozen. The check waits
// for a lock on the denies; meanwhile x's membership ends, and then its place in frozen, which
// DeleteExpired removes, passing over the membership, which another transaction holds. Decided at
// the time its statement began, x would hold login by its membership and escape the deny, though
// at no moment was it a member out of frozen.
func TestACheckDecidesNoEarlierThanATimeDeleteExpiredRecordedAfterItsStatementBegan(t *testing.T) {
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeSimpleProtocol, pgx.QueryExecModeCacheStatement} {
		t.Run(mode.String(), func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			h.groups(t, "frozen")
			x := h.as(t, "x", "frozen")
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "x"))
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`, login); err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, x, login, cluster) {
				t.Fatal("x may log in to c1 while it is in frozen, which the deny binds it by")
			}
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cfg := h.pool.Config()
			cfg.ConnConfig.DefaultQueryExecMode = mode
			pool, err := pgxpool.NewWithConfig(bounded, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			// By a clock behind every time below, so it decides at the time DeleteExpired recorded.
			readerCfg, base := h.cfg, h.now
			readerCfg.Now = func() time.Time { return base }
			reader, err := rbac.New(pool, readerCfg)
			if err != nil {
				t.Fatal(err)
			}
			locker, err := h.pool.Begin(bounded)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = locker.Rollback(context.WithoutCancel(ctx)) }()
			var pid int32
			if _, err := locker.Exec(bounded, `LOCK TABLE rbac_denies IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			if err := locker.QueryRow(bounded, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- reader.Authorize(bounded, x, login, cluster) }()
			for waiting := false; !waiting; {
				select {
				case err := <-done:
					t.Fatalf("the check didn't wait for the lock on the denies: %v", err)
				default:
					if err := h.pool.QueryRow(bounded, `SELECT EXISTS (SELECT FROM pg_stat_activity
						WHERE $1::int = ANY(pg_blocking_pids(pid)) AND query LIKE '%rbac_expired%')`, pid).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The membership ends after the check's statement began, and the place after it.
			var ended time.Time
			if err := h.pool.QueryRow(bounded, `UPDATE rbac_memberships SET expires_at = clock_timestamp()
				WHERE tenant = 't1' AND principal = 'user:x' RETURNING expires_at`).Scan(&ended); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(bounded, `UPDATE rbac_members SET expires_at = $1
				WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`, ended.Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			for passed := false; !passed; {
				if err := h.pool.QueryRow(bounded, `SELECT clock_timestamp() > $1`, ended.Add(time.Millisecond)).Scan(&passed); err != nil {
					t.Fatal(err)
				}
			}
			holder, err := h.pool.Begin(bounded)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = holder.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := holder.Exec(bounded, `SELECT FROM rbac_memberships WHERE tenant = 't1' AND principal = 'user:x' FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			h.now = ended.Add(time.Hour)
			if n, err := h.authz.DeleteExpired(bounded); err != nil || n != 1 {
				t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
			}
			if err := locker.Rollback(bounded); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("x may log in to c1 by its membership, which ended before its place in frozen, which DeleteExpired removed after the check began: %v", err)
			}
		})
	}
}

// rbac_expired refuses a time past the database's clock, whoever writes it, the table's owner too,
// and through rbac_expired_through, which DeleteExpired records by, and isn't truncated: no write but
// one by a role that may disable its triggers can leave such a time there.
func TestExpiredRefusesATimePastTheDatabasesClock(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	past := dbNow(t, h).Add(-time.Hour)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_expired (until) VALUES ($1)`, past); err != nil {
		t.Fatal(err)
	}
	future := dbNow(t, h).Add(time.Hour)
	for _, w := range []struct {
		sql  string
		code string
	}{
		{`INSERT INTO rbac_expired (until) VALUES ($1)`, "23514"},
		{`UPDATE rbac_expired SET until = $1`, "23514"},
		{`SELECT rbac_expired_through($1)`, "23514"},
		{`TRUNCATE rbac_expired`, "0A000"},
	} {
		var args []any
		if strings.Contains(w.sql, "$1") {
			args = []any{future}
		}
		if _, err := h.pool.Exec(ctx, w.sql, args...); sqlState(err) != w.code {
			t.Errorf("%s = %v, not refused as %s", w.sql, err, w.code)
		}
	}
	var latest time.Time
	if err := h.pool.QueryRow(ctx, `SELECT max(until) FROM rbac_expired`).Scan(&latest); err != nil || !latest.Equal(past) {
		t.Errorf("rbac_expired's latest time is %v, not %v: %v", latest, past, err)
	}
}

// History records every write to rbac_expired, as the entity expired in no tenant, keyed by its
// row's id: the time each of DeleteExpired's batches adds, the times it deletes as later ones
// supersede them, and a write around the package, as no one's. Here DeleteExpired by a clock an hour
// on removes y's grant, which ended half an hour on, and by one two hours on z's, which ended an hour
// and a half on.
func TestHistoryRecordsEveryWriteToExpired(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	base := h.now
	for id, ends := range map[string]time.Duration{"y": 30 * time.Minute, "z": 90 * time.Minute} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
			VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login', $2)`, id, base.Add(ends)); err != nil {
			t.Fatal(err)
		}
	}
	for _, by := range []time.Duration{time.Hour, 2 * time.Hour} {
		h.now = base.Add(by)
		if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
			t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
		}
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_expired (until) VALUES ($1)`, base.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var user string
	if err := h.pool.QueryRow(ctx, `SELECT current_user`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	at := func(d time.Duration) string { return expiredTime(base.Add(d)) }
	got := expiredRecords(t, h.pool)
	if len(got) != 4 {
		t.Fatalf("history records rbac_expired's writes as %+v", got)
	}
	// The first, which the second run deleted, has no row left to read its id from.
	want := []expiredRecord{
		{got[0].key, at(30 * time.Minute), "create", "DeleteExpired", user},
		{got[0].key, at(30 * time.Minute), "delete", "DeleteExpired", user},
		{expiredID(t, h.pool, base.Add(90*time.Minute)), at(90 * time.Minute), "create", "DeleteExpired", user},
		{expiredID(t, h.pool, base.Add(10*time.Minute)), at(10 * time.Minute), "create", "", user},
	}
	if !slices.Equal(got, want) {
		t.Errorf("history records rbac_expired's writes as %+v, want %+v", got, want)
	}
}

// Each row of rbac_expired is recorded, and pruned, on its own, by its id, as two can hold one
// time: here two runs beside each other each add it, as neither sees the other's, and a later run
// deletes one, passing over the other, which another transaction holds, so it stays. A prune past
// all of it deletes every record of the one deleted, and keeps the one still there's. Keyed by the
// time, the delete of one read as the end of both, and the prune deleted the record of the one
// still there.
func TestHistoryRecordsAndPrunesEachRowOfExpiredOnItsOwn(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	at := dbNow(t, h).Add(-time.Hour)
	var runs []pgx.Tx
	for range 2 {
		run, err := h.pool.Begin(bounded)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = run.Rollback(context.WithoutCancel(ctx)) }()
		if _, err := run.Exec(bounded, `SELECT rbac_expired_through($1)`, at); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run)
	}
	for _, run := range runs {
		if err := run.Commit(bounded); err != nil {
			t.Fatal(err)
		}
	}
	var ids []string
	if err := h.pool.QueryRow(bounded, `SELECT array_agg(id::text ORDER BY id) FROM rbac_expired WHERE until = $1`, at).Scan(&ids); err != nil || len(ids) != 2 {
		t.Fatalf("two runs beside each other left %v rows of their time: %v", ids, err)
	}
	deleted, kept := ids[0], ids[1]
	holder, err := h.pool.Begin(bounded)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := holder.Exec(bounded, `SELECT FROM rbac_expired WHERE id = $1 FOR UPDATE`, kept); err != nil {
		t.Fatal(err)
	}
	later := at.Add(30 * time.Minute)
	if _, err := h.pool.Exec(bounded, `SELECT rbac_expired_through($1)`, later); err != nil {
		t.Fatal(err)
	}
	if err := holder.Rollback(bounded); err != nil {
		t.Fatal(err)
	}
	var user string
	if err := h.pool.QueryRow(ctx, `SELECT current_user`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	latest := expiredID(t, h.pool, later)
	want := []expiredRecord{
		{deleted, expiredTime(at), "create", "", user},
		{kept, expiredTime(at), "create", "", user},
		{deleted, expiredTime(at), "delete", "", user},
		{latest, expiredTime(later), "create", "", user},
	}
	if got := expiredRecords(t, h.pool); !slices.Equal(got, want) {
		t.Fatalf("history records rbac_expired's writes as %+v, want %+v", got, want)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), exported(t, h)); err != nil {
		t.Fatal(err)
	}
	if got, want := expiredRecords(t, h.pool), []expiredRecord{want[1], want[3]}; !slices.Equal(got, want) {
		t.Errorf("once pruned, history records rbac_expired's writes as %+v, want %+v", got, want)
	}
}

// expireHolding runs DeleteExpired by a clock three hours on, leaving h.now there, while another
// transaction holds the row held selects, which the run passes over.
func expireHolding(t *testing.T, h *harness, held string) {
	t.Helper()
	ctx := t.Context()
	l, err := h.pool.Begin(ctx)
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = l.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := l.Exec(ctx, held+" FOR UPDATE"); err != nil {
		t.Error(err)
		return
	}
	h.now = h.now.Add(3 * time.Hour)
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if n, err := h.authz.DeleteExpired(bounded); err != nil || n == 0 {
		t.Errorf("DeleteExpired removed %d rows: %v", n, err)
	}
}

// Holders lists who may do p no earlier than DeleteExpired deleted by, as a check decides it: here x
// holds login through its place in admins, which ends in an hour, and a deny of login names frozen,
// its place in which ends in two; DeleteExpired, by a clock three hours on, removes the place in
// frozen and passes over the one in admins, which another transaction holds. Listed by the earlier
// clock, x would be a holder, though at no moment did it hold login and escape the deny.
func TestHoldersListNoEarlierThanDeleteExpiredDeletedBy(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "admins", "frozen")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Group, "admins"))
	x := h.as(t, "x", "admins", "frozen")
	for _, q := range []struct {
		sql string
		arg any
	}{
		{`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'admins'`, h.now.Add(time.Hour)},
		{`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`, h.now.Add(2 * time.Hour)},
		{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`, login},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.arg); err != nil {
			t.Fatal(err)
		}
	}
	expireHolding(t, h, `SELECT FROM rbac_members WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'admins'`)
	h.now = h.now.Add(-3 * time.Hour)
	holders, err := h.authz.Holders(ctx, login, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(holders, func(o rbac.Holder) bool { return o.Principal == x.Principal }) {
		t.Errorf("Holders listed x, by its place in admins, which ended before its place in frozen, which the deny binds it by: %+v", holders)
	}
}

// Filter's condition with the label column keeps no row once DeleteExpired, by a time past the end
// of a place of the subject's that Filter read with its label holding, has run before the query,
// which then decides its grants and denies at that time: here x holds high until an hour on, and
// login on the tenant for good, and a deny of login on w1 names frozen, its place in which ends in
// two. DeleteExpired, by a clock three hours on, removes the place between Filter and the query: by
// Filter's holding and the query's denies, x would list c0, high and in w1, though at no moment did
// it hold high and escape the deny.
func TestFilterKeepsNoRowByALabelHoldingOfAnEarlierTimeThanItsQuery(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	h.groups(t, "frozen")
	x := h.as(t, "x", "frozen")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "x"))
	h.hold(t, "x", "level:high")
	c0 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c0", Ancestors: cluster.Ancestors, Labels: rbac.Label{"level": {"high"}}}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rbac_grants SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND role = 'level.high'`, []any{h.now.Add(time.Hour)}},
		{`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`, []any{h.now.Add(2 * time.Hour)}},
		{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`, []any{login}},
		{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
		{`INSERT INTO secrets VALUES ('t1', 'c0', $1, '{level:high}')`, []any{h.path(t, c0)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	pred, err := h.authz.Filter(ctx, x, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(3 * time.Hour)
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if n, err := h.authz.DeleteExpired(bounded); err != nil || n == 0 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) > 0 {
		t.Errorf("Filter's condition kept %v by x's holding of high, which ended before its place in frozen, which the deny binds it by: %v", ids, err)
	}
}

// Filter's condition with the label column keeps its rows once DeleteExpired, by a later time than
// Filter's, has run before the query, while no place of the subject's in a group, nor its
// membership, has ended by that time: its keys, and the denies binding it by them, are then those
// of Filter's time, so the rows the query keeps it could read then. Here x and w hold high and login
// on the tenant for good, x's place in crew ends in two hours, and w's membership and places don't
// end; y's grant ends in half of one. Once DeleteExpired by a clock an hour on has removed y's
// grant, the query still lists c0 for x; once DeleteExpired by a clock three hours on has removed
// x's place, it lists nothing for x, and still c0 for w.
func TestFilterKeepsItsRowsWhileTheSubjectsPlacesLastPastDeleteExpired(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	h.groups(t, "crew")
	x, w := h.as(t, "x", "crew"), h.as(t, "w", "crew")
	h.as(t, "y")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "x"), grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "y"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "w"))
	h.hold(t, "x", "level:high")
	h.hold(t, "w", "level:high")
	c0 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c0", Ancestors: cluster.Ancestors, Labels: rbac.Label{"level": {"high"}}}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'crew'`, []any{h.now.Add(2 * time.Hour)}},
		{`UPDATE rbac_grants SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:y'`, []any{h.now.Add(30 * time.Minute)}},
		{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
		{`INSERT INTO secrets VALUES ('t1', 'c0', $1, '{level:high}')`, []any{h.path(t, c0)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	filter := func(s rbac.Subject) rbac.Predicate {
		t.Helper()
		pred, err := h.authz.Filter(ctx, s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return pred
	}
	ofX, ofW := filter(x), filter(w)
	base := h.now
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	expire := func(by time.Duration) {
		t.Helper()
		h.now = base.Add(by)
		if n, err := h.authz.DeleteExpired(bounded); err != nil || n == 0 {
			t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
		}
	}
	listed := func(pred rbac.Predicate) []string {
		t.Helper()
		rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	expire(time.Hour)
	if ids := listed(ofX); !slices.Equal(ids, []string{"c0"}) {
		t.Errorf("once DeleteExpired removed y's grant, Filter's condition for x kept %v, not c0", ids)
	}
	expire(3 * time.Hour)
	if ids := listed(ofX); len(ids) > 0 {
		t.Errorf("once DeleteExpired removed x's place in crew, Filter's condition for x kept %v", ids)
	}
	if ids := listed(ofW); !slices.Equal(ids, []string{"c0"}) {
		t.Errorf("once DeleteExpired removed x's place in crew, Filter's condition for w, whose membership and places don't end, kept %v, not c0", ids)
	}
}

// Filter's condition with the label column keeps its rows once DeleteExpired has removed a place of
// the subject's in a group that another path keeps it in for good: its keys, and the grants and denies
// they reach, are what they were. Here x holds high, crew logs in on the tenant, and x is in crew for
// good, by its place from no source or through team, and by a place from the host's directory until
// an hour on, which DeleteExpired by a clock two hours on removes between Filter and the query.
func TestFilterKeepsItsRowsOnceAPlaceAnotherPathOutlastsEnded(t *testing.T) {
	for name, groups := range map[string][]string{"from another source": {"crew"}, "through a group": {"team"}} {
		t.Run(name, func(t *testing.T) {
			h := labeled(t)
			ctx := t.Context()
			h.groups(t, "crew", "team")
			x := h.as(t, "x", groups...)
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Group, "crew"))
			h.hold(t, "x", "level:high")
			c0 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c0", Ancestors: cluster.Ancestors, Labels: rbac.Label{"level": {"high"}}}
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'crew', 'group', 'team')`, nil},
				{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, expires_at) VALUES ('t1', 'crew', 'user', 'x', 'directory', $1)`, []any{h.now.Add(time.Hour)}},
				{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
				{`INSERT INTO secrets VALUES ('t1', 'c0', $1, '{level:high}')`, []any{h.path(t, c0)}},
			} {
				if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			cols := rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}
			pred, err := h.authz.Filter(ctx, x, login, "t1", "cluster", cols, 1)
			if err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(2 * time.Hour)
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if n, err := h.authz.DeleteExpired(bounded); err != nil || n != 1 {
				t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
			}
			if !allowed(t, h, x, login, c0) {
				t.Fatal("x may no longer log in to c0")
			}
			rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
			if err != nil {
				t.Fatal(err)
			}
			if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(ids, []string{"c0"}) {
				t.Errorf("once DeleteExpired removed x's place in crew from the directory, which another path keeps it in for good, Filter's condition kept %v, not c0: %v", ids, err)
			}
		})
	}
}

// As TestFilterKeepsNoRowByALabelHoldingOfAnEarlierTimeThanItsQuery, through the subject's
// membership: here anyone may view the tenant's clusters, and a deny of view on w1 names the
// tenant's members, which x is until two hours on, holding high by its own grant. DeleteExpired, by
// a clock three hours on, removes the membership between Filter and the query: by Filter's holding
// and the query's denies, x would list c0, high and in w1, though at no moment did it hold high and
// escape the deny.
func TestFilterKeepsNoRowOnceTheSubjectsMembershipEndedBeforeItsQuery(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer) })
	ctx := t.Context()
	x := h.as(t, "x")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.viewer", rbac.Public, ""))
	h.hold(t, "x", "level:high")
	c0 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c0", Ancestors: cluster.Ancestors, Labels: rbac.Label{"level": {"high"}}}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE rbac_memberships SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x'`, []any{h.now.Add(2 * time.Hour)}},
		{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'workspace', 'w1', 'members', '{members:t1}', ARRAY[$1::text])`, []any{view}},
		{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
		{`INSERT INTO secrets VALUES ('t1', 'c0', $1, '{level:high}')`, []any{h.path(t, c0)}},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	pred, err := h.authz.Filter(ctx, x, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(3 * time.Hour)
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if n, err := h.authz.DeleteExpired(bounded); err != nil || n == 0 {
		t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
	}
	rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) > 0 {
		t.Errorf("Filter's condition kept %v by x's holding of high, which it held only while a member, which the deny binds it as: %v", ids, err)
	}
}

// As TestFilterKeepsNoRowByALabelHoldingOfAnEarlierTimeThanItsQuery, through crew's place in frozen,
// where x is in crew, and through x's own place there while its membership is suspended, which
// gives it only what the public is granted and leaves it bound by a deny naming its groups. Here
// the public may view the tenant's clusters for good and holds high until an hour on, and a deny of
// view on w1 names frozen, the place in which ends in two. DeleteExpired, by a clock three hours
// on, removes the place between Filter and the query: by Filter's holding and the query's denies,
// x would list c0, high and in w1, though at no moment did it hold high and escape the deny.
func TestFilterKeepsNoRowOnceAPlaceTheSubjectIsBoundThroughEndedBeforeItsQuery(t *testing.T) {
	for _, c := range []struct {
		name      string
		groups    []string
		place     string
		suspended bool
	}{
		{
			name:   "of a group it is in",
			groups: []string{"crew"},
			place:  `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at) VALUES ('t1', 'frozen', 'group', 'crew', $1)`,
		},
		{
			name:      "while suspended",
			groups:    []string{"frozen"},
			place:     `UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'frozen'`,
			suspended: true,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
			high := rbac.RoleDefinition{ID: "level.everyone", Permissions: []rbac.Permission{"level:high"}, ResourceTypes: []string{rbac.TenantScope}, Public: true}
			h := labeled(t, func(cfg *rbac.Config) { cfg.Catalog = append(slices.Clone(cfg.Catalog), viewer, high) })
			ctx := t.Context()
			h.groups(t, "frozen")
			x := h.as(t, "x", c.groups...)
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.viewer", rbac.Public, ""), grant(rbac.TenantRoot("t1"), "level.everyone", rbac.Public, ""))
			c0 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c0", Ancestors: cluster.Ancestors, Labels: rbac.Label{"level": {"high"}}}
			for _, q := range []struct {
				sql  string
				args []any
			}{
				{c.place, []any{h.now.Add(2 * time.Hour)}},
				{`UPDATE rbac_memberships SET suspended = $1 WHERE tenant = 't1' AND principal = 'user:x'`, []any{c.suspended}},
				{`UPDATE rbac_grants SET expires_at = $1 WHERE tenant = 't1' AND role = 'level.everyone'`, []any{h.now.Add(time.Hour)}},
				{`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'workspace', 'w1', 'freeze', '{group:frozen}', ARRAY[$1::text])`, []any{view}},
				{`CREATE TABLE secrets (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`, nil},
				{`INSERT INTO secrets VALUES ('t1', 'c0', $1, '{level:high}')`, []any{h.path(t, c0)}},
			} {
				if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
					t.Fatal(err)
				}
			}
			pred, err := h.authz.Filter(ctx, x, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
			if err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(3 * time.Hour)
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if n, err := h.authz.DeleteExpired(bounded); err != nil || n != 2 {
				t.Fatalf("DeleteExpired removed %d rows: %v", n, err)
			}
			rows, err := h.pool.Query(ctx, `SELECT id FROM secrets WHERE `+pred.SQL, pred.Args...)
			if err != nil {
				t.Fatal(err)
			}
			if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) > 0 {
				t.Errorf("Filter's condition kept %v by x's holding of high, which ended before the place in frozen, which the deny binds it by: %v", ids, err)
			}
		})
	}
}

// A change decides what it gives at the time it decides what its actor acts by, so DeleteExpired, by
// a later time, committing once the change has read its actor, has it tried again: here x may grant
// bank.b through its place in admins, which ends in an hour, and ann holds bank:a through her place
// in a-team, which ends in two. DeleteExpired, by a clock three hours on, removes her place and
// passes over x's, which another transaction holds, as the change reads whether ann would hold two
// values of bank. By the change's time she held bank:a, and by the run's x held no power: at no
// moment could x give her bank:b alone.
func TestAChangeChecksExclusiveValuesNoEarlierThanDeleteExpiredDeletedBy(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.groups(t, "admins", "a-team")
	h.seed(t, grant(root, "tenant.admin", rbac.Group, "admins"), grant(root, "bank.b", rbac.Group, "admins"), grant(root, "bank.a", rbac.Group, "a-team"))
	x := h.as(t, "x", "admins")
	h.as(t, "ann", "a-team")
	for _, q := range []struct {
		group, principal string
		ends             time.Duration
	}{{"admins", "user:x", time.Hour}, {"a-team", "user:ann", 2 * time.Hour}} {
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND principal = $2 AND group_id = $3`,
			h.now.Add(q.ends), q.principal, q.group); err != nil {
			t.Fatal(err)
		}
	}
	expired := false
	rbac.BeforeStatement(t, rbac.ExcludesMarker, false, func() {
		expired = true
		expireHolding(t, h, `SELECT FROM rbac_members WHERE tenant = 't1' AND principal = 'user:x' AND group_id = 'admins'`)
	})
	err := h.authz.Apply(ctx, x, tenantT1, rbac.Change{Grant: []rbac.Binding{{Role: "bank.b", Principal: identity("ann"), ExpiresAt: h.now.Add(30 * time.Minute)}}})
	if !expired {
		t.Fatal("DeleteExpired didn't run as the change read whether ann would hold two values of bank")
	}
	if !errors.Is(err, rbac.ErrConflict) {
		t.Errorf("x gave ann bank:b by its place in admins, which ended before her place in a-team, which gave her bank:a: %v", err)
	}
	var given bool
	if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:ann' AND role = 'bank.b')`).Scan(&given); err != nil || given {
		t.Errorf("ann was given bank.b: %v", err)
	}
}

// A change reads the standing of what it grants to, which the host was asked about, as of the time
// it decides at: an identity whose membership has ended is in none of its groups, as Members lists
// them, and is no member itself, whether or not DeleteExpired has removed it and its places. So a
// DeleteExpired removing them while the host is asked changes nothing the host could read, and the
// change isn't tried again for it.
func TestAChangeStandsByTheMembershipsInForce(t *testing.T) {
	for _, how := range []string{"ChangeMembers nesting", "Apply to the group", "Apply to the identity"} {
		t.Run(how, func(t *testing.T) {
			var meanwhile func(ctx context.Context) error
			named := groupOf("crew")
			if how == "Apply to the identity" {
				named = identity("u")
			}
			h := grouped(t, func(c *rbac.Config) {
				c.ValidateGrant = func(ctx context.Context, _ rbac.DB, in rbac.GrantInput) error {
					if do := meanwhile; do != nil && in.Binding.Principal == named {
						meanwhile = nil
						return do(ctx)
					}
					return nil
				}
			})
			ctx := t.Context()
			h.groups(t, "crew")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "staff"))
			if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}, {Principal: identity("w")}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}, {Group: "crew", Principal: identity("w")}}); err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(2 * time.Hour)
			if members, err := h.authz.Members(ctx, "t1", "crew"); err != nil || len(members) != 1 {
				t.Fatalf("Members(crew) = %+v, %v: u has left", members, err)
			}
			ran := false
			meanwhile = func(ctx context.Context) error {
				ran = true
				bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				n, err := h.authz.DeleteExpired(bounded)
				if err == nil && n == 0 {
					err = errors.New("DeleteExpired removed nothing")
				}
				return err
			}
			var err error
			switch how {
			case "ChangeMembers nesting":
				err = h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "staff", Principal: groupOf("crew")}}, nil)
			default:
				err = h.authz.Apply(ctx, h.as(t, "manager"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: named}}})
			}
			if !ran {
				t.Fatal("the host wasn't asked about the change")
			}
			if err != nil {
				t.Errorf("refused though what the host was asked about is as it was: %v", err)
			}
		})
	}
}

func TestPublicCustomRolesThatChangeAccessGiveNothingInSearches(t *testing.T) {
	share := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), share) })
	ctx := t.Context()
	resources := hostTable(t, h)
	// Stored by the host, past SetRole, which refuses a public role that changes access.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, public)
		VALUES ('t1', 'custom.open', '{cluster:view,cluster:grant}', '{cluster}', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'tenant', 't1', 'public', '', 'custom.open')`); err != nil {
		t.Fatal(err)
	}
	anonymous := rbac.Subject{}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("a public grant of a role that changes access should give nothing")
	}
	listingsAgree(t, h, resources, anonymous, view)
	if holders, err := h.authz.Holders(ctx, view, cluster); err != nil || slices.Contains(holderPrincipals(holders), rbac.Principal{Kind: rbac.Public}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

func conditional(role rbac.Role, id, expr string) rbac.Binding {
	return rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: id}, Condition: rbac.Condition{Title: "t", Expression: expr}}
}

func TestConditions(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	dev := cluster
	dev.Attributes = map[string]any{"env": "dev"}
	prod := cluster
	prod.Attributes = map[string]any{"env": "prod"}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		conditional("cluster.login", "c", `resource.attributes.env == "dev"`),
		conditional("cluster.login", "late", `request.time < timestamp("2026-01-01T13:00:00Z")`),
		conditional("cluster.login", "mfa", `request.attributes.mfa == true`),
		conditional("cluster.login", "ops", `subject.attributes.dept == "ops"`),
		conditional("cluster.login", "viewer", `action == "cluster:view"`),
	}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ctx  context.Context
		s    rbac.Subject
		p    rbac.Permission
		r    rbac.Resource
		want bool
	}{
		{"a resource attribute that holds", ctx, h.as(t, "c"), login, dev, true},
		{"one that doesn't", ctx, h.as(t, "c"), login, prod, false},
		{"one the host didn't pass", ctx, h.as(t, "c"), login, cluster, false},
		{"before a time", ctx, h.as(t, "late"), login, cluster, true},
		{"a request attribute", rbac.WithRequest(ctx, map[string]any{"mfa": true}), h.as(t, "mfa"), login, cluster, true},
		{"without it", ctx, h.as(t, "mfa"), login, cluster, false},
		{"a subject attribute", ctx, rbac.Subject{Principal: h.as(t, "ops").Principal, Attributes: map[string]any{"dept": "ops"}}, login, cluster, true},
		{"the action it names", ctx, h.as(t, "viewer"), view, cluster, true},
		{"another action", ctx, h.as(t, "viewer"), login, cluster, false},
	}
	for _, c := range cases {
		err := h.authz.Authorize(c.ctx, c.s, c.p, c.r)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := err == nil; got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		d, err := h.authz.Explain(c.ctx, c.s, c.p, c.r)
		if err != nil || d.Allowed != c.want || (c.want && d.Grants[0].Condition.Expression == "") {
			t.Errorf("%s: Explain = %+v, %v", c.name, d, err)
		}
	}
	h.now = h.now.Add(2 * time.Hour)
	if allowed(t, h, h.as(t, "late"), login, cluster) {
		t.Error("a condition on the time should stop holding")
	}
	if perms, err := h.authz.Permissions(ctx, h.as(t, "viewer"), cluster); err != nil || !slices.Equal(perms, []rbac.Permission{view}) {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	// An unconditional grant beside a conditional one allows on its own: on the workspace, since
	// one on the cluster would replace it.
	h.seed(t, grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.login", rbac.User, "c"))
	if !allowed(t, h, h.as(t, "c"), login, prod) {
		t.Error("an unconditional grant should allow whatever its neighbor's condition says")
	}
}

func TestConditionsAreCheckedWhenGranted(t *testing.T) {
	h := setup(t)
	long := strings.Repeat("true && ", 600) + "true"
	for name, expr := range map[string]string{
		"a syntax error":          `resource.attributes.env ==`,
		"not a bool":              `1 + 1`,
		"too long":                long,
		"an unknown variable":     `user.name == "x"`,
		"a pattern too large":     `resource.id.matches("` + strings.Repeat(`[a-z]{1000}`, 2) + `")`,
		"a long literal repeated": `resource.id.matches("(?:` + strings.Repeat("a", 400) + `){9}")`,
		"a pattern not literal":   `resource.id.matches("[a-z]{1000}" + "")`,
		"a pattern that's wrong":  `matches(resource.id, "(")`,
	} {
		err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}})
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	titled := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, Condition: rbac.Condition{Title: "t"}}
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{titled}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a title without an expression: %v", err)
	}
	titledLong := conditional("cluster.login", "x", "true")
	titledLong.Condition.Title = strings.Repeat("t", 129)
	described := conditional("cluster.login", "x", "true")
	described.Condition.Description = strings.Repeat("d", 2049)
	for _, b := range []rbac.Binding{titledLong, described} {
		if err := h.authz.Import(t.Context(), host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a title or description too long: %v", err)
		}
	}
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", `resource.id.matches("^c[0-9]{1,3}$")`)}}); err != nil {
		t.Fatalf("a small pattern: %v", err)
	}
	if !allowed(t, h, h.as(t, "x"), login, cluster) {
		t.Error("a small pattern that matches should allow")
	}
}

func TestAConditionTooCostlyIsFalse(t *testing.T) {
	h := setup(t)
	var xs []string
	for i := range 200 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	expr := list + ".all(x, " + list + ".all(y, true))"
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "x"), login, cluster) {
		t.Fatal("a condition past its cost limit should be false")
	}
	// Comparing values counts what they hold, not only how many there are.
	labels := map[string]any{"env": "dev"}
	for i := range 20000 {
		labels[fmt.Sprint("k", i)] = fmt.Sprint(i)
	}
	large := cluster
	large.Attributes = map[string]any{"nested": []any{labels}, "labels": labels}
	h.seed(t,
		rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.login", "compares", `resource.attributes.nested == resource.attributes.nested`)},
		rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.login", "finds", `"env" in resource.attributes.labels && resource.attributes.labels.env == "dev"`)},
	)
	if allowed(t, h, h.as(t, "compares"), login, large) {
		t.Error("comparing large nested values should be past the cost limit")
	}
	if !allowed(t, h, h.as(t, "finds"), login, large) {
		t.Error("finding a key in a large map should cost no more than the key")
	}
}

func TestSearchesLeaveConditionalGrantsToTheHost(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	// Unconditional on workspace w1, beside a conditional one, and conditional on org o2.
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.login", rbac.User, "both"),
		rbac.Grant{Scope: rbac.Scope{Type: "workspace", ID: "w1"}, Binding: conditional("cluster.sudo", "both", "true")},
		rbac.Grant{Scope: rbac.Scope{Type: "org", ID: "o2"}, Binding: conditional("cluster.login", "both", "true")},
	)
	reach, err := h.authz.Reachable(ctx, h.as(t, "both"), login, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reach.Scopes, []rbac.Scope{{Type: "workspace", ID: "w1"}}) || !slices.Equal(reach.Conditional, []rbac.Scope{{Type: "org", ID: "o2"}}) {
		t.Fatalf("Reachable = %+v", reach)
	}
	pred, err := h.authz.Filter(ctx, h.as(t, "both"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, "SELECT id FROM clusters WHERE "+pred.SQL+" ORDER BY id", pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	// Every row Filter keeps, Authorize allows; the conditional ones Authorize allows too.
	for _, r := range resources {
		if slices.Contains(got, r.ID) && !allowed(t, h, h.as(t, "both"), login, r) {
			t.Errorf("Filter kept %s, which Authorize refuses", r.ID)
		}
	}
	if !slices.Equal(got, []string{"c0"}) {
		t.Errorf("Filter kept %v, want only the unconditionally reached c0", got)
	}
	// Holders lists it, marked as holding only under a condition.
	if holders, err := h.authz.Holders(ctx, login, resources[2]); err != nil || len(holders) != 1 || holders[0].Principal.ID != "both" || !holders[0].Conditional {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
	if !allowed(t, h, h.as(t, "both"), login, resources[2]) {
		t.Error("Authorize should allow through the conditional grant")
	}
}

func TestConditionalGrantsInChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	mfa := `request.attributes.mfa == true`
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.admin", "admin", mfa)})
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(ctx, h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access through a condition that doesn't hold: %v", err)
	}
	withMFA := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	// Held only under a condition, a permission can't be handed on without it.
	if err := h.authz.Apply(withMFA, h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("dropping the condition the actor holds a role under: %v", err)
	}
	same := b
	same.Condition = rbac.Condition{Expression: mfa}
	// Its power to change grants holds only where its condition does.
	if err := h.authz.Apply(ctx, h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{same}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access through a condition that doesn't hold now: %v", err)
	}
	if err := h.authz.Apply(withMFA, h.as(t, "admin"), cluster, rbac.Change{Grant: []rbac.Binding{same}}); err != nil {
		t.Fatalf("handing on a permission under the same condition: %v", err)
	}
	h.events = nil
	other := same
	other.Condition = rbac.Condition{Title: "office", Expression: `request.attributes.office == true`}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{other}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || h.events[0].Granted[0].Condition != other.Condition {
		t.Fatalf("a grant under another condition should be reported: %+v", h.events)
	}
	// It is another grant, beside the first.
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 2 ||
		!slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.Condition == other.Condition }) ||
		!slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.Condition == same.Condition }) {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestAConditionalPowerIsHandedOnOnlyUnderItsCondition(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	mfa := `request.attributes.mfa == true`
	withMFA := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	admin := roleAdmin(t, h)
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	granter := rbac.RoleDefinition{ID: "custom.granter", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}}
	for _, r := range []rbac.RoleDefinition{lister, granter} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	// The power to change grants only with a second factor; everything else cluster.admin gives,
	// without one.
	h.seed(t,
		rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.admin", "p", mfa)},
		grant(cluster.Scope(), "cluster.sudo", rbac.User, "p"),
		rbac.Grant{Scope: cluster.Scope(), Binding: conditional(lister.ID, "p", mfa)},
		grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "definer"),
		rbac.Grant{Scope: rbac.TenantRoot("t1"), Binding: conditional("cluster.admin", "definer", mfa)},
	)
	for _, role := range []rbac.Role{"cluster.admin", lister.ID, granter.ID} {
		self := rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "p"}}
		if err := h.authz.Apply(withMFA, h.as(t, "p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("granting %s without the condition of the power it gives: %v", role, err)
		}
		self.Condition = rbac.Condition{Expression: mfa}
		self.Principal.ID = "x"
		if err := h.authz.Apply(withMFA, h.as(t, "p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); err != nil {
			t.Errorf("granting %s under the condition of the power it gives: %v", role, err)
		}
	}
	wider := granter
	wider.ID = "custom.wider"
	if err := h.authz.SetRole(withMFA, h.as(t, "definer"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("defining a role that gives a power held only under a condition: %v", err)
	}
}

func TestARoleAConditionalGrantListsIsGrantedOnlyUnderItsCondition(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	mfa := `request.attributes.mfa == true`
	withMFA := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"custom.lister", "cluster.sudo"}}
	if err := h.authz.SetRole(ctx, roleAdmin(t, h), "t1", lister); err != nil {
		t.Fatal(err)
	}
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(lister.ID, "p", mfa)})
	// With a second factor once, p would otherwise grant itself sudo, or the lister, without one.
	for _, role := range []rbac.Role{"cluster.sudo", lister.ID} {
		self := rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "p"}}
		if err := h.authz.Apply(withMFA, h.as(t, "p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("granting %s through a conditional listing without its condition: %v", role, err)
		}
		other := rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, Condition: rbac.Condition{Expression: mfa}}
		if err := h.authz.Apply(withMFA, h.as(t, "p"), cluster, rbac.Change{Grant: []rbac.Binding{other}}); err != nil {
			t.Errorf("granting %s through a conditional listing under its condition: %v", role, err)
		}
	}
	if allowed(t, h, h.as(t, "p"), root, cluster) {
		t.Error("p should hold root only through a grant it may not make")
	}
	if roles, err := h.authz.Grantable(withMFA, h.as(t, "p"), cluster); err != nil || len(roles) != 0 {
		t.Errorf("Grantable offers only what the actor may grant unconditionally: %v, %v", roles, err)
	}
	revoke := rbac.Binding{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(withMFA, h.as(t, "p"), cluster, rbac.Change{Revoke: []rbac.Binding{revoke}}); err != nil {
		t.Errorf("revoking a role a conditional grant lists while its condition holds: %v", err)
	}
}

func TestAConditionalRightToDefineRolesHoldsOnlyUnderItsCondition(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t,
		rbac.Grant{Scope: tenant, Binding: conditional("tenant.roles", "definer", `request.attributes.mfa == true`)},
		grant(tenant, "cluster.admin", rbac.User, "definer"),
	)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, h.as(t, "definer"), "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role without the condition the right to holds under: %v", err)
	}
	if err := h.authz.SetRole(rbac.WithRequest(ctx, map[string]any{"mfa": true}), h.as(t, "definer"), "t1", r); err != nil {
		t.Fatalf("defining a role with it: %v", err)
	}
}

// spending is a condition of nearly the longest that is false, for each i another, which spends all
// a condition may: what a check pays for it is about a third of what the conditions it reads on a
// scope may cost together.
func spending(i int) string {
	var xs []string
	for j := range 276 {
		xs = append(xs, fmt.Sprint(j))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	return fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", list, list, i)
}

// storeAround writes grants in t1 as a migration might, around the bounds a change checks, as on
// what the conditions a check reads on a scope cost together.
func storeAround(t *testing.T, h *harness, grants ...rbac.Grant) {
	t.Helper()
	var groups, scopeTypes, scopeIDs, kinds, ids, roles, conditions []string
	for _, g := range grants {
		if g.Principal.Kind == rbac.Group {
			groups = append(groups, g.Principal.ID)
		}
		scopeTypes, scopeIDs = append(scopeTypes, g.Scope.Type), append(scopeIDs, g.Scope.ID)
		kinds, ids = append(kinds, string(g.Principal.Kind)), append(ids, g.Principal.ID)
		roles, conditions = append(roles, string(g.Role)), append(conditions, g.Condition.Expression)
	}
	h.groups(t, groups...)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, condition)
		SELECT 't1', * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])`,
		scopeTypes, scopeIDs, kinds, ids, roles, conditions); err != nil {
		t.Fatal(err)
	}
}

// A third party able to grant a subject a role, its groups, or the tenant's members, adds what the
// conditions a check reads on a scope may cost beside a conditional grant it can't revoke: refused
// once they would cost more together, and evaluated whole with it otherwise, so the grant goes on
// giving what it gave.
func TestAGrantBesideOneTheActorCantRevokeLeavesItGiving(t *testing.T) {
	helpdesk := rbac.RoleDefinition{
		ID: "cluster.helpdesk", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"},
		GrantableRoles: []rbac.Role{"cluster.login"},
	}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), helpdesk) })
	ctx := t.Context()
	sudo := grant(cluster.Scope(), "cluster.sudo", rbac.User, "v")
	sudo.Condition = rbac.Condition{Expression: `request.attributes.mfa == true && request.attributes.network == "corp" && request.attributes.device != "unmanaged"`}
	h.seed(t, sudo, grant(cluster.Scope(), "cluster.helpdesk", rbac.User, "desk"))
	h.groups(t, "staff")
	v, desk := h.as(t, "v", "staff"), h.as(t, "desk")
	req := rbac.WithRequest(ctx, map[string]any{"mfa": true, "network": "corp", "device": "managed"})
	if err := h.authz.Authorize(req, v, login, cluster); err != nil {
		t.Fatalf("before: %v", err)
	}
	if err := h.authz.Apply(ctx, desk, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.sudo", Principal: v.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("the helpdesk revoking sudo: %v", err)
	}
	// Each shorter than the sudo grant's, and so evaluated before it, and costing all a condition may.
	l := "[1,2,3,4,5,6,7,8]"
	refused := map[rbac.Principal]bool{}
	for i := range 8 {
		for _, p := range []rbac.Principal{v.Principal, groupOf("staff"), rbac.TenantMembers("t1")} {
			expr := fmt.Sprintf(`%s.all(a,%s.all(b,%s.all(c,%s.all(d,a>%d))))`, l, l, l, l, -1-i)
			err := h.authz.Apply(ctx, desk, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: p, Condition: rbac.Condition{Expression: expr}}}})
			switch {
			case errors.Is(err, rbac.ErrInvalid):
				refused[p] = true
			case err != nil:
				t.Fatal(err)
			}
		}
	}
	if len(refused) != 3 {
		t.Errorf("refused costly conditions only for %v", refused)
	}
	if d, err := h.authz.Explain(req, v, login, cluster); err != nil || !d.Allowed {
		t.Fatalf("grants the helpdesk made stopped one it can't revoke giving login: %+v, %v", d, err)
	}
}

// An actor's power to change grants, held under a condition, is decided as a check is: conditional
// grants beside it, as by an admin of a scope below, who can't revoke it, leave it giving that power.
func TestAPowerBesideGrantsTheActorCantRevokeLeavesItGiving(t *testing.T) {
	helpdesk := rbac.RoleDefinition{
		ID: "cluster.helpdesk", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"},
		GrantableRoles: []rbac.Role{"cluster.login"},
	}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), helpdesk) })
	ctx := t.Context()
	mfa := rbac.Condition{Expression: `request.attributes.mfa == true && request.attributes.network == "corp" && request.attributes.device != "unmanaged"`}
	admin := grant(workspace.Scope(), "cluster.admin", rbac.User, "v")
	admin.Condition = mfa
	h.seed(t, admin)
	h.groups(t, "staff")
	v, owner := h.as(t, "v", "staff"), h.as(t, "owner")
	// The cluster's admin gives v and its group the power to grant login there, each under a condition
	// of its own, shorter than the workspace grant's, and so evaluated before it, and costing all one
	// may.
	l := "[1,2,3,4,5,6,7,8]"
	refused := map[rbac.Principal]bool{}
	for i := range 8 {
		for j, p := range []rbac.Principal{v.Principal, groupOf("staff")} {
			expr := fmt.Sprintf(`%s.all(a,%s.all(b,%s.all(c,%s.all(d,a>%d))))`, l, l, l, l, -1-i-10*j)
			err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.helpdesk", Principal: p, Condition: rbac.Condition{Expression: expr}}}})
			switch {
			case errors.Is(err, rbac.ErrInvalid):
				refused[p] = true
			case err != nil:
				t.Fatal(err)
			}
		}
	}
	if len(refused) != 2 {
		t.Errorf("refused costly conditions only for %v", refused)
	}
	req := rbac.WithRequest(ctx, map[string]any{"mfa": true, "network": "corp", "device": "managed"})
	if err := h.authz.Apply(req, v, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("w"), Condition: mfa}}}); err != nil {
		t.Fatalf("grants the cluster's admin made stopped one it can't revoke giving the power to grant: %v", err)
	}
}

// What the conditions a check reads on a scope cost together is bounded where they are stored, each
// distinct one counted once: an identity's grants', of any role, and those of the grants to groups,
// the tenant's members and the public, which reach many, together. Another identity's, another
// scope's and an expired grant's count apart.
func TestTheConditionsACheckReadsOnAScopeAreBoundedWhereTheyAreStored(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.groups(t, "g1", "g2")
	apply := func(on rbac.Resource, bs ...rbac.Binding) error {
		return h.authz.Apply(ctx, owner, on, rbac.Change{Grant: bs})
	}
	under := func(role rbac.Role, p rbac.Principal, expr string) rbac.Binding {
		return rbac.Binding{Role: role, Principal: p, Condition: rbac.Condition{Expression: expr}}
	}
	// Three of the longest fit; a fourth doesn't, whatever its role.
	for i := range 3 {
		if err := apply(cluster, under("cluster.login", identity("u"), spending(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := apply(cluster, under("cluster.sudo", identity("u"), spending(3))); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an identity's fourth costly condition on a scope: %v", err)
	}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: under("cluster.sudo", identity("u"), spending(3))}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing it: %v", err)
	}
	// One it has counts once, and an unconditional grant costs nothing.
	if err := apply(cluster, under("cluster.sudo", identity("u"), spending(0)), rbac.Binding{Role: "cluster.sudo", Principal: identity("u")}); err != nil {
		t.Fatalf("a condition the identity has on the scope: %v", err)
	}
	// Another identity's, and the identity's on another scope, count apart.
	if err := apply(cluster, under("cluster.login", identity("w"), spending(3))); err != nil {
		t.Fatalf("another identity's: %v", err)
	}
	ws := workspace
	h.seed(t, grant(ws.Scope(), "workspace.admin", rbac.User, "owner"), grant(ws.Scope(), "cluster.admin", rbac.User, "owner"))
	if err := apply(ws, under("cluster.login", identity("u"), spending(3))); err != nil {
		t.Fatalf("the identity's on another scope: %v", err)
	}
	// Grants to groups, the members and the public share one bound on a scope.
	for i, p := range []rbac.Principal{groupOf("g1"), groupOf("g2"), rbac.TenantMembers("t1")} {
		if err := apply(cluster, under("cluster.login", p, spending(10+i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := apply(cluster, under("cluster.login", groupOf("g1"), spending(13))); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a fourth costly condition of grants that reach many: %v", err)
	}
	// A grant that has expired costs a check nothing.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET expires_at = $1 WHERE principal = 'group:g2'`, h.now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := apply(cluster, under("cluster.login", groupOf("g1"), spending(13))); err != nil {
		t.Fatalf("beside an expired one: %v", err)
	}
}

// The conditions of grants from a source the host owns are bounded apart from the tenant's, as their
// number is: neither the tenant's admins, filling what a check reads together on a scope, can stop
// the host storing a conditional grant there, nor the host them. A check evaluates both whole.
func TestAHostsSourceIsBoundedApartFromTheTenantsGrants(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.groups(t, "staff")
	under := func(p rbac.Principal, expr string) rbac.Binding {
		return rbac.Binding{Role: "cluster.login", Principal: p, Condition: rbac.Condition{Expression: expr}}
	}
	fromHost := func(b rbac.Binding) error {
		b.Source = "directory"
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}})
	}
	for _, p := range []rbac.Principal{identity("u"), groupOf("staff")} {
		// The tenant's admins fill what a check reads of the tenant's grants.
		for i := range 3 {
			if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{under(p, spending(i))}}); err != nil {
				t.Fatal(err)
			}
		}
		if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{under(p, spending(3))}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("%s: the tenant's fourth: %v", p.ID, err)
		}
		// The host stores its own beside them, as many, and the last costliest.
		for i := range 2 {
			if err := fromHost(under(p, spending(10+i))); err != nil {
				t.Fatalf("%s: the host's, beside the tenant's: %v", p.ID, err)
			}
		}
		if err := fromHost(under(p, "true || "+spending(19))); err != nil {
			t.Fatalf("%s: the host's third: %v", p.ID, err)
		}
		if err := fromHost(under(p, spending(13))); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("%s: the host's fourth: %v", p.ID, err)
		}
	}
	// Filled so on every scope of the cluster's path, a check reads them all, and reaches the
	// costliest, which holds.
	n := 100
	for _, scope := range []rbac.Scope{workspace.Scope(), {Type: "org", ID: "o1"}, rbac.TenantRoot("t1")} {
		var more []rbac.Grant
		for _, p := range []rbac.Principal{identity("u"), groupOf("staff")} {
			for i := range 6 {
				// Each its own, as a check pays for one condition once.
				n++
				b := under(p, spending(n))
				if i >= 3 {
					b.Source = "directory"
				}
				more = append(more, rbac.Grant{Scope: scope, Binding: b})
			}
		}
		if err := h.authz.Import(ctx, host, "t1", more); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := h.authz.Explain(ctx, h.as(t, "u", "staff"), login, cluster); err != nil || len(d.Grants) != 2 {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
}

// Where conditions stored before there were bounds cost more than a check may spend, a change that
// adds none, as one changing a note, granting one held again, moving one from a grant it revokes to
// one it grants or restoring them as they are, isn't refused; one adding a condition is.
func TestAChangePastTheBoundIsRefusedOnlyForAConditionItAdds(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	var grants []rbac.Grant
	for i := range 4 {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
		g.Condition = rbac.Condition{Expression: spending(i)}
		grants = append(grants, g)
	}
	storeAround(t, h, grants...)
	for i := range 4 {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
			VALUES ('t1', 'cluster', 'c1', $1, $2, $3, $4)`, fmt.Sprint("d", i), []string{"user:v"}, []string{string(login)}, spending(i)); err != nil {
			t.Fatal(err)
		}
	}
	owner := h.as(t, "owner")
	under := func(role rbac.Role, note, expr string) error {
		return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{
			Role: role, Principal: identity("u"), Note: note, Condition: rbac.Condition{Expression: expr},
		}}})
	}
	deny := func(id, name, expr string) error {
		return h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
			ID: id, Name: name, Principals: []rbac.Principal{identity("v")}, Permissions: []rbac.Permission{login},
			Condition: rbac.Condition{Expression: expr},
		})
	}
	var moved string
	if err := h.pool.QueryRow(ctx, `SELECT id FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u' AND condition = $1`,
		spending(3)).Scan(&moved); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"a note":                         under("cluster.login", "on call", spending(0)),
		"another role, a condition held": under("cluster.sudo", "", spending(1)),
		"restoring them":                 h.authz.Import(ctx, host, "t1", grants),
		"a condition moved to another role": h.authz.Apply(ctx, owner, cluster, rbac.Change{
			Revoke: []rbac.Binding{{ID: moved, Role: "cluster.login", Principal: identity("u")}},
			Grant:  []rbac.Binding{{Role: "cluster.sudo", Principal: identity("u"), Condition: rbac.Condition{Expression: spending(3)}}},
		}),
		"a deny's name":            deny("d0", "renamed", spending(0)),
		"a deny, a condition held": deny("d4", "", spending(2)),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, err := range map[string]error{
		"a grant's costly condition": under("cluster.login", "", spending(9)),
		"a grant's cheap condition":  under("cluster.login", "", "true"),
		"a deny's condition":         deny("d5", "", "true"),
		"a deny's changed condition": deny("d0", "", spending(9)),
	} {
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("adding %s: %v", name, err)
		}
	}
}

// Conditions stored past the bound before there were bounds can be many, and learning what one can
// cost compiles it: a change among them, under its locks, compiles no more of them than it takes to
// find them past the bound.
func TestAChangePastTheBoundCompilesFewOfTheConditionsThere(t *testing.T) {
	h := setup(t)
	var grants []rbac.Grant
	for i := range 40 {
		g := grant(cluster.Scope(), "cluster.login", rbac.Group, fmt.Sprintf("g%02d", i))
		g.Condition = rbac.Condition{Expression: spending(i)}
		grants = append(grants, g)
	}
	storeAround(t, h, grants...)
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{
		Role: "cluster.sudo", Principal: groupOf("g00"), Condition: rbac.Condition{Expression: spending(0)},
	}}}); err != nil {
		t.Fatal(err)
	}
	if n := rbac.Limits(h.authz); n > 5 {
		t.Errorf("the change compiled %d of the conditions there", n)
	}
}

// A conditional grant to a group on a scope is bounded with the conditions of the conditional
// grants there to groups, the tenant's members and the public, which it reads before it writes and
// again after by an index of conditional grants alone (rbac_grants_conditional): so it reads no
// more of the grants than an unconditional grant does, however many unconditional grants to groups
// the scope holds, under a custom plan and a generic one, by statistics from once those were made,
// from before, or from when the scope's grants were all conditional ones, in a database of the
// tenant alone or beside many small tenants. Read through the scope's index, which holds whether a
// grant is conditional but not its condition, each grant to a group there was read from the table:
// with 80,000, a conditional grant to one more took 39 ms, and an unconditional one 7.
func TestAConditionalGrantToAGroupReadsOnlyTheConditionalGrantsThere(t *testing.T) {
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	for _, analyzed := range []string{"after", "before", "conditional"} {
		for _, beside := range []string{"alone", "crowded"} {
			t.Run(analyzed+"/"+beside, func(t *testing.T) {
				h := growing(t, beside == "crowded", "rbac_grants", "rbac_groups")
				ctx := t.Context()
				analyze := func() {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `ANALYZE rbac_grants, rbac_groups`); err != nil {
						t.Fatal(err)
					}
				}
				h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "admin"))
				admin := h.as(t, "admin")
				h.groups(t, "target")
				// Conditional grants to groups there, under one condition, which the read finds.
				if _, err := h.pool.Exec(ctx, `WITH g AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'c' || i FROM generate_series(1, 300) i RETURNING id)
					INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, condition)
					SELECT 't1', 'tenant', 't1', 'group', id, 'cluster.login', 'request.attributes.level > 0' FROM g`); err != nil {
					t.Fatal(err)
				}
				if analyzed == "conditional" {
					analyze()
				}
				n := 0
				others := func(more int) {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `WITH g AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'many' || i FROM generate_series($1::int, $2::int) i RETURNING id)
						INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) SELECT 't1', 'tenant', 't1', 'group', id, 'cluster.login' FROM g`,
						n, n+more-1); err != nil {
						t.Fatal(err)
					}
					n += more
				}
				read := func(plan, condition string) int64 {
					t.Helper()
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					planAs(ctx, t, tx, plan)
					pages := -pagesRead(ctx, t, tx, "rbac_grants")
					b := rbac.Binding{Role: "cluster.login", Principal: groupOf("target"), Condition: rbac.Condition{Expression: condition}}
					if err := h.authz.WithTx(tx).Apply(ctx, admin, tenant, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
						t.Fatal(err)
					}
					return pages + pagesRead(ctx, t, tx, "rbac_grants")
				}
				// What a conditional grant reads beyond what an unconditional one does, its conditions',
				// under each plan.
				beyond := func() map[string]int64 {
					t.Helper()
					by := map[string]int64{}
					for _, plan := range plans {
						by[plan] = read(plan, `request.attributes.level > 9`) - read(plan, "")
					}
					return by
				}
				// Its statements planned while the tenant holds the conditional grants alone, as a
				// session does that first changes them then.
				beyond()
				others(500)
				if analyzed == "before" {
					analyze()
				}
				few := beyond()
				others(20000)
				if analyzed == "after" {
					analyze()
				}
				for plan, many := range beyond() {
					if many > few[plan]*3/2+deeper {
						t.Errorf("under %s, a conditional grant to a group on the tenant read %d pages of the grants more than an unconditional one beside 500 unconditional grants to groups there, and %d beside 20,500",
							plan, few[plan], many)
					}
				}
			})
		}
	}
}

// A group's eligibility with a requirement is bounded with the requirements of the groups'
// eligibilities for its role on its scope, which it reads by an index of the eligibilities with a
// requirement alone (rbac_eligibilities_requires): so the rows and index entries of the
// eligibilities it reads don't grow with the scope's others, of its role without a requirement or of
// other roles, under a custom plan and a generic one, by statistics from once those were made, from
// before, or from when the scope's eligibilities all had requirements, in a database of the tenant
// alone or beside many small tenants. By the scope's index, each eligibility on the scope was read
// from the table.
func TestAGroupsRequirementReadsOnlyTheRequirementsThere(t *testing.T) {
	for _, analyzed := range []string{"after", "before", "required"} {
		for _, beside := range []string{"alone", "crowded"} {
			t.Run(analyzed+"/"+beside, func(t *testing.T) {
				h := growing(t, beside == "crowded", "rbac_eligibilities")
				ctx := t.Context()
				analyze := func() {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `ANALYZE rbac_eligibilities`); err != nil {
						t.Fatal(err)
					}
				}
				owner := h.as(t, "owner")
				h.groups(t, "target")
				// Requirements of groups' eligibilities for the role there, all one, which the read finds.
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, requires)
					SELECT 't1', 'cluster', 'c1', 'group', 'r' || i, 'cluster.sudo', 3600, 'request.attributes.level > 0' FROM generate_series(1, 300) i`); err != nil {
					t.Fatal(err)
				}
				if analyzed == "required" {
					analyze()
				}
				n := 0
				// Eligibilities of groups there without a requirement, half of them of the role and half
				// of another.
				others := func(more int) {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
						SELECT 't1', 'cluster', 'c1', 'group', 'many' || i, role, 3600 FROM generate_series($1::int, $2::int) i, unnest('{cluster.sudo,cluster.login}'::text[]) AS role`,
						n, n+more/2-1); err != nil {
						t.Fatal(err)
					}
					n += more / 2
				}
				read := func(plan string) int64 {
					t.Helper()
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					planAs(ctx, t, tx, plan)
					rows := -scanned(ctx, t, tx, "rbac_eligibilities")
					if err := h.authz.WithTx(tx).SetEligibility(ctx, owner, cluster, rbac.Eligibility{
						Role: "cluster.sudo", Principal: groupOf("target"), MaxDuration: time.Hour, Requires: `request.attributes.level > 9`,
					}); err != nil {
						t.Fatal(err)
					}
					return rows + scanned(ctx, t, tx, "rbac_eligibilities")
				}
				reads := func() map[string]int64 {
					t.Helper()
					by := map[string]int64{}
					for _, plan := range plans {
						by[plan] = read(plan)
					}
					return by
				}
				// Its statements planned while the scope holds the requirements alone, as a session
				// does that first changes them then.
				reads()
				others(500)
				if analyzed == "before" {
					analyze()
				}
				few := reads()
				others(10000)
				if analyzed == "after" {
					analyze()
				}
				for plan, many := range reads() {
					if many > few[plan]*3/2 {
						t.Errorf("under %s, a group's eligibility with a requirement read %d rows and entries of the eligibilities beside 500 others there, and %d beside 10,500",
							plan, few[plan], many)
					}
				}
			})
		}
	}
}

// plans are the plans a session makes of a statement, as plan_cache_mode names them: one for the
// arguments of each run, and one for all of them, which the first run under it makes and later runs
// reuse until what the statement reads is analyzed again.
var plans = []string{"force_custom_plan", "force_generic_plan"}

// growing is setupOn, or where crowded, crowded, for a test of what a change reads of tables as
// they grow: on one connection, so a statement's generic plan is made once for all of the test's
// reads, with autovacuum off for the tables, so they are analyzed only as the test says, and their
// writes unrecorded, as recording tens of thousands in history takes seconds that what a change
// reads of the tables themselves doesn't turn on.
func growing(t *testing.T, crowd bool, tables ...string) *harness {
	t.Helper()
	pool := pgtest.Open(t, "pool_max_conns=1")
	open := setupOn
	if crowd {
		open = crowded
	}
	h := open(t, pool)
	for _, table := range tables {
		if _, err := pool.Exec(t.Context(), `ALTER TABLE `+table+` SET (autovacuum_enabled = off), DISABLE TRIGGER USER`); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// planAs has tx's statements planned as plan, a plan_cache_mode, until it ends.
func planAs(ctx context.Context, t *testing.T, tx pgx.Tx, plan string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plan); err != nil {
		t.Fatal(err)
	}
}

// Bounding a scope's conditions and requirements reads them with sequential scans, bitmap scans and
// sorting off, but leaves the host's transaction its own settings.
func TestBoundingConditionsLeavesTheHostItsPlannerSettings(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.groups(t, "crew")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = on; SET LOCAL enable_bitmapscan = on; SET LOCAL enable_sort = on`); err != nil {
		t.Fatal(err)
	}
	authz := h.authz.WithTx(tx)
	mfa := rbac.Condition{Expression: `request.attributes.mfa == true`}
	if err := authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: groupOf("crew"), Condition: mfa}}}); err != nil {
		t.Fatal(err)
	}
	if err := authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("crew"), MaxDuration: time.Hour, Requires: mfa.Expression}); err != nil {
		t.Fatal(err)
	}
	var seq, bitmap, sort string
	if err := tx.QueryRow(ctx, `SELECT current_setting('enable_seqscan'), current_setting('enable_bitmapscan'), current_setting('enable_sort')`).
		Scan(&seq, &bitmap, &sort); err != nil || seq != "on" || bitmap != "on" || sort != "on" {
		t.Fatalf("enable_seqscan = %q, enable_bitmapscan = %q, enable_sort = %q, %v", seq, bitmap, sort, err)
	}
}

// A read that turns a planner setting off for its own statements puts the host's back under WithTx
// where it fails, as one of its statements refused before it was sent, where the call's ctx is done
// once those have run, as pgx sends nothing on a done ctx, or where it panics, which a host can
// recover from and go on in its transaction: here Holders' read of its holders' label values, with
// JIT off for it. The host's transaction, which goes on past the call, kept JIT off until it ended.
func TestAReadLeavesTheHostItsPlannerSettingsWhereItFails(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	h.as(t, "u")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	for name, holders := range map[string]func(t *testing.T, tx pgx.Tx) error{
		"refused": func(t *testing.T, tx pgx.Tx) error {
			t.Helper()
			_, err := h.authz.WithTx(&refusingTx{Tx: tx, sql: "WITH idents AS MATERIALIZED"}).Holders(ctx, login, secret)
			if err != nil && !strings.Contains(err.Error(), refused) {
				t.Fatal(err)
			}
			return err
		},
		"done": func(t *testing.T, tx pgx.Tx) error {
			t.Helper()
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			// Once the statement reading the values has run.
			rbac.SetMatchingKeys(t, func(int) { cancel() })
			_, _ = h.authz.WithTx(tx).Holders(call, login, secret)
			return call.Err()
		},
		"panicked": func(t *testing.T, tx pgx.Tx) (err error) {
			t.Helper()
			rbac.SetMatchingKeys(t, func(int) { panic(refused) })
			defer func() {
				if r := recover(); r != nil {
					if r != refused {
						t.Errorf("the host recovered %v, not the read's panic", r)
					}
					err = fmt.Errorf("a panic in Holders: %v", r)
				}
			}()
			_, err = h.authz.WithTx(tx).Holders(ctx, login, secret)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			if _, err := tx.Exec(ctx, `SET LOCAL jit = on`); err != nil {
				t.Fatal(err)
			}
			if err := holders(t, tx); err == nil {
				t.Fatal("Holders read its holders' label values")
			}
			var jit string
			if err := tx.QueryRow(ctx, `SELECT current_setting('jit')`).Scan(&jit); err != nil || jit != "on" {
				t.Errorf("jit = %q, %v, once Holders failed", jit, err)
			}
		})
	}
}

// A read planned with settings of its own leaves its session as it found it however it ends, so a
// pool's next caller, or a host's transaction going on, plans with the host's: where it reads, where
// its statement fails on the server, where its reading of the rows fails, and where that panics,
// which the host recovers from. On the pool, and in the host's transaction or a savepoint of it, the
// host rolling back to that where the call failed; and on a DB that sends no batches, which wraps
// either. A panic left the batch unread, so the pool never had its connection back, and the host's
// transaction could run nothing more. So too for a read whose rows its caller reads on, closing them
// as it ends (QueriedIndexed).
func TestAReadPlannedAloneLeavesItsSessionAsItFoundItHoweverItEnds(t *testing.T) {
	ctx := t.Context()
	schema := pgtest.Open(t, "pool_max_conns=1").Config()
	const panicked = "the read panicked"
	ends := map[string]struct {
		sql  string
		read func(pgx.Rows) error
	}{
		"it reads": {`SELECT current_setting('enable_seqscan')`, func(rows pgx.Rows) error {
			var during string
			if _, err := pgx.ForEachRow(rows, []any{&during}, func() error { return nil }); err != nil {
				return err
			}
			if during != "off" {
				return fmt.Errorf("enable_seqscan = %q as it read", during)
			}
			return nil
		}},
		"its statement fails": {`SELECT 1 / (SELECT 0)`, func(rows pgx.Rows) error {
			_, err := pgx.ForEachRow(rows, nil, func() error { return nil })
			return err
		}},
		"its read fails": {`SELECT 1`, func(rows pgx.Rows) error { return errors.New("the read failed") }},
		"its read panics": {`SELECT 1`, func(rows pgx.Rows) error {
			rows.Next()
			panic(panicked)
		}},
	}
	on := map[string]func(pool *pgxpool.Pool, tx pgx.Tx) rbac.DB{
		"the pool":                               func(pool *pgxpool.Pool, _ pgx.Tx) rbac.DB { return pool },
		"a DB that sends no batches on the pool": func(pool *pgxpool.Pool, _ pgx.Tx) rbac.DB { return unbatched{pool} },
		"the host's transaction":                 func(_ *pgxpool.Pool, tx pgx.Tx) rbac.DB { return tx },
		"a DB that sends no batches on the host's transaction": func(_ *pgxpool.Pool, tx pgx.Tx) rbac.DB { return hostTx{tx} },
	}
	ways := map[string]func(ctx context.Context, q rbac.DB, read func(pgx.Rows) error, sql string) error{
		"planned": func(ctx context.Context, q rbac.DB, read func(pgx.Rows) error, sql string) error {
			return rbac.Planned(ctx, q, read, sql)
		},
		"read on": func(ctx context.Context, q rbac.DB, read func(pgx.Rows) error, sql string) error {
			rows, err := rbac.QueriedIndexed(ctx, q, sql)
			if err != nil {
				return err
			}
			defer rows.Close()
			if err := read(rows); err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		},
	}
	for way, read := range ways {
		for name, db := range on {
			for how, end := range ends {
				t.Run(way+" on "+name+", where "+how, func(t *testing.T) {
					bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
					defer cancel()
					// A pool of one connection of its own, which closes only once it has it back.
					pool, err := pgxpool.NewWithConfig(bounded, schema)
					if err != nil {
						t.Fatal(err)
					}
					defer func() {
						closed := make(chan struct{})
						go func() {
							pool.Close()
							close(closed)
						}()
						select {
						case <-closed:
						case <-time.After(10 * time.Second):
							t.Error("the pool never had its connection back")
						}
					}()
					var host pgx.Tx
					if strings.Contains(name, "host's transaction") {
						var err error
						if host, err = pool.Begin(bounded); err != nil {
							t.Fatal(err)
						}
						defer func() { _ = host.Rollback(context.WithoutCancel(ctx)) }()
						if _, err := host.Exec(bounded, `SAVEPOINT before`); err != nil {
							t.Fatal(err)
						}
					}
					err = func() (err error) {
						defer func() {
							if r := recover(); r != nil {
								if r != panicked {
									panic(r)
								}
								err = errors.New(panicked)
							}
						}()
						return read(bounded, db(pool, host), end.read, end.sql)
					}()
					if (err == nil) != (how == "it reads") {
						t.Fatalf("the read returned %v", err)
					}
					// As a host whose call failed, back to before it, but where it panicked after its
					// statements ran, which the host goes on from.
					if err != nil && host != nil && how != "its read panics" {
						if _, err := host.Exec(bounded, `ROLLBACK TO SAVEPOINT before`); err != nil {
							t.Fatal(err)
						}
					}
					var q rbac.DB = pool
					if host != nil {
						q = host
					}
					var seqscan string
					if err := q.QueryRow(bounded, `SELECT current_setting('enable_seqscan')`).Scan(&seqscan); err != nil || seqscan != "on" {
						t.Errorf("enable_seqscan = %q, %v, once the read ended", seqscan, err)
					}
				})
			}
		}
	}
}

// A read planned with settings of its own, on a pool, runs with them and leaves them as they were,
// whichever way the host has its pool send statements: each sends a batch as one transaction, its
// statements before one Sync, or in one simple query, so what the first sets for the transaction
// alone holds as the read runs, and where it fails, the rollback puts it back.
func TestAReadPlannedAloneHoldsItsSettingsInEveryWayAPoolSendsStatements(t *testing.T) {
	ctx := t.Context()
	schema := pgtest.Open(t, "pool_max_conns=1").Config()
	for _, mode := range []pgx.QueryExecMode{
		pgx.QueryExecModeCacheStatement, pgx.QueryExecModeCacheDescribe, pgx.QueryExecModeDescribeExec,
		pgx.QueryExecModeExec, pgx.QueryExecModeSimpleProtocol,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cfg := schema.Copy()
			cfg.ConnConfig.DefaultQueryExecMode = mode
			pool, err := pgxpool.NewWithConfig(bounded, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			// Twice, as a statement a connection has prepared runs again.
			for range 2 {
				var during string
				if err := rbac.Planned(bounded, pool, func(rows pgx.Rows) error {
					_, err := pgx.ForEachRow(rows, []any{&during}, func() error { return nil })
					return err
				}, `SELECT current_setting('enable_seqscan') WHERE $1::text[] IS NOT NULL`, []string{"t1"}); err != nil || during != "off" {
					t.Fatalf("enable_seqscan = %q, %v, as it read", during, err)
				}
				if err := rbac.Planned(bounded, pool, func(rows pgx.Rows) error {
					_, err := pgx.ForEachRow(rows, nil, func() error { return nil })
					return err
				}, `SELECT 1 / (SELECT 0)`); err == nil {
					t.Fatal("a statement dividing by zero ran")
				}
				// So too a read whose rows its caller reads on (QueriedIndexed).
				rows, err := rbac.QueriedIndexed(bounded, pool, `SELECT current_setting('enable_seqscan') WHERE $1::text[] IS NOT NULL`, []string{"t1"})
				if err == nil {
					during, err = pgx.CollectExactlyOneRow(rows, pgx.RowTo[string])
				}
				if err != nil || during != "off" {
					t.Fatalf("enable_seqscan = %q, %v, as its rows were read", during, err)
				}
				if rows, err := rbac.QueriedIndexed(bounded, pool, `SELECT 1 / (SELECT 0)`); err == nil {
					if _, err = pgx.CollectRows(rows, pgx.RowTo[int32]); err == nil {
						t.Fatal("a statement dividing by zero ran")
					}
				}
				var seqscan string
				if err := pool.QueryRow(bounded, `SELECT current_setting('enable_seqscan')`).Scan(&seqscan); err != nil || seqscan != "on" {
					t.Fatalf("enable_seqscan = %q, %v, once the reads ended", seqscan, err)
				}
			}
		})
	}
}

// unbatched is a host's own DB around a pool that sends no batches.
type unbatched struct{ pool *pgxpool.Pool }

func (u unbatched) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return u.pool.Exec(ctx, sql, args...)
}

func (u unbatched) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return u.pool.Query(ctx, sql, args...)
}

func (u unbatched) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return u.pool.QueryRow(ctx, sql, args...)
}

func (u unbatched) Begin(ctx context.Context) (pgx.Tx, error) { return u.pool.Begin(ctx) }

// refusingTx is a transaction whose queries, and batches, holding sql fail before they are sent.
type refusingTx struct {
	pgx.Tx
	sql string
}

// refused is why refusingTx refuses a query.
const refused = "refused before it was sent"

func (tx *refusingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if strings.Contains(sql, tx.sql) {
		return nil, errors.New(refused)
	}
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx *refusingTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	for _, q := range b.QueuedQueries {
		if strings.Contains(q.SQL, tx.sql) {
			return refusedBatch{}
		}
	}
	return tx.Tx.SendBatch(ctx, b)
}

// refusedBatch is a batch refusingTx refused, whose every result is the refusal.
type refusedBatch struct{}

func (refusedBatch) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New(refused)
}

func (refusedBatch) Query() (pgx.Rows, error) { return nil, errors.New(refused) }

func (b refusedBatch) QueryRow() pgx.Row { return refusedRow{} }

func (refusedBatch) Close() error { return errors.New(refused) }

// refusedRow is a row refusingTx refused.
type refusedRow struct{}

func (refusedRow) Scan(...any) error { return errors.New(refused) }

// scanned is how many rows of table tx has read by scanning it, whole or through a bitmap, and how
// many entries of its indexes by scanning them, as an index scan finds each row it fetches.
func scanned(ctx context.Context, t *testing.T, tx pgx.Tx, table string) int64 {
	t.Helper()
	var n int64
	if err := tx.QueryRow(ctx, `SELECT sum(pg_stat_get_xact_tuples_returned(oid)) + sum(pg_stat_get_xact_tuples_fetched(oid)) FILTER (WHERE oid = $1::regclass)
		FROM pg_class WHERE oid = $1::regclass OR oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = $1::regclass)`, table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Conditions stored around the bounds can cost more than a check may spend: it spends a bounded
// budget on them, the cheapest first, and refuses what still needs one.
func TestACheckSpendsABoundedBudgetOnConditionsStoredAroundTheBounds(t *testing.T) {
	h := setup(t)
	grants := func(prefix string, expr func(i int) string) []string {
		var groups []string
		var grants []rbac.Grant
		for i := range 30 {
			g := fmt.Sprintf("%s%02d", prefix, i)
			groups = append(groups, g)
			// The one that holds costs the most to compile, so it is evaluated last.
			e := expr(i)
			if i == 29 {
				e = "true || " + spending(0)
			}
			grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
				Role: "cluster.login", Principal: groupOf(g), Condition: rbac.Condition{Expression: e},
			}})
		}
		storeAround(t, h, grants...)
		return groups
	}
	groups := grants("g", spending)
	if !allowed(t, h, h.as(t, "one", "g29"), login, cluster) {
		t.Fatal("a condition that holds should allow")
	}
	// Spent on the grants before it, the check never reaches the one that holds, and says so.
	if d, err := h.authz.Explain(t.Context(), h.as(t, "many", groups...), login, cluster); err != nil || d.Allowed || !strings.Contains(d.Reason, "cost more than a check may spend") {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	if allowed(t, h, h.as(t, "many", groups...), login, cluster) {
		t.Fatal("a check should stop spending on conditions past its budget")
	}
	// One condition decides the same for a request, so however many grants have it, a check pays
	// to evaluate it once and reaches the one that holds.
	same := grants("s", func(int) string { return spending(1) })
	if !allowed(t, h, h.as(t, "many", same...), login, cluster) {
		t.Fatal("a check paid for one condition again for each grant that has it")
	}
}

// longFalse is a condition near the longest, false but for the contractors it lists, which may cost
// all a condition may to evaluate, as it reads the request's attributes whole.
func longFalse(i int) string {
	const reading = ` || dyn(request.attributes).exists(k, k == "-")`
	var b strings.Builder
	b.WriteString("subject.id in [")
	for j := 0; ; j++ {
		item := fmt.Sprintf("%q,", fmt.Sprintf("contractor-%d-%04d", i, j))
		if b.Len()+len(item)+1+len(reading) > rbac.MaxExpression-8 {
			break
		}
		b.WriteString(item)
	}
	return strings.TrimSuffix(b.String(), ",") + "]" + reading
}

func TestAPathsConditionalDeniesAreEvaluatedWhole(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"))
	deny := func(on rbac.Resource, id string, i int) error {
		return h.authz.SetDeny(ctx, guardian, on, rbac.Deny{
			ID: id, Principals: []rbac.Principal{rbac.TenantMembers("t1")},
			Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: longFalse(i)},
		})
	}
	// Three of the longest that may cost all a condition may fit a scope; a fourth could leave a
	// check's budget short of them, so it is refused rather than stored to deny everyone they name.
	for i := range 3 {
		// Each its own, as a check pays to compile each distinct condition once.
		for j, on := range []rbac.Resource{cluster, workspace} {
			if err := deny(on, fmt.Sprint("d", i), 10*j+i); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := deny(cluster, "d3", 3); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a scope's fourth long conditional deny: %v", err)
	}
	if err := deny(cluster, "d2", 4); err != nil {
		t.Fatalf("replacing one of them: %v", err)
	}
	// Six on the cluster's path, false for these subjects, which a check evaluates whole.
	for _, s := range []rbac.Subject{h.as(t, "owner"), h.as(t, "u")} {
		if !allowed(t, h, s, login, cluster) {
			t.Fatalf("%s denied by conditions that don't hold for it", s.Principal.ID)
		}
	}
	// Explain, Permissions and the escalation checks spend on denies apart from grants too.
	if d, err := h.authz.Explain(ctx, h.as(t, "u"), login, cluster); err != nil || !d.Allowed {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	if perms, err := h.authz.Permissions(ctx, h.as(t, "u"), cluster); err != nil || !slices.Contains(perms, login) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}}}); err != nil {
		t.Fatalf("granting what the denies leave the actor: %v", err)
	}
	if !allowed(t, h, h.as(t, "contractor-1-0007"), view, cluster) || allowed(t, h, h.as(t, "contractor-1-0007"), login, cluster) {
		t.Fatal("a deny should bind whom its condition names")
	}
	// A deny whose condition can't be evaluated denies, and Explain says why. Cheap, it fits beside
	// three of the longest that may cost all a condition may.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
		ID: "mfa", Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}},
		Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: "request.attributes.mfa != true"},
	}); err != nil {
		t.Fatalf("a cheap conditional deny beside them: %v", err)
	}
	if d, err := h.authz.Explain(ctx, h.as(t, "u"), login, cluster); err != nil || d.Allowed || !strings.Contains(d.Reason, "couldn't be evaluated") || strings.Contains(d.Reason, "budget") {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	// Denies stored before their scope was bounded can cost more than a check may spend: the one
	// it can't pay for denies, and Explain says the budget decided.
	for i := range 20 {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
			VALUES ('t1', 'cluster', 'c1', $1, $2, $3, $4)`,
			fmt.Sprint("old", i), []string{string(rbac.Members) + ":t1"}, []string{string(login)}, longFalse(20+i)); err != nil {
			t.Fatal(err)
		}
	}
	if d, err := h.authz.Explain(ctx, h.as(t, "owner"), login, cluster); err != nil || d.Allowed || !strings.Contains(d.Reason, "within the check's budget") {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
}

func TestADeepPathsConditionalDeniesAreEvaluatedWhole(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"))
	chain := []rbac.Scope{{Type: "workspace", ID: "w1"}}
	for i := 2; i <= 5; i++ {
		chain = append(chain, rbac.Scope{Type: "workspace", ID: fmt.Sprint("w", i)})
	}
	chain = append(chain, rbac.Scope{Type: "org", ID: "o1"})
	deep := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c1", Ancestors: chain}
	// Three of the longest on seven of the eight scopes on its path: more than four scopes' worth.
	ons := []rbac.Resource{deep, {Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}}
	for i := range 5 {
		ons = append(ons, rbac.Resource{Tenant: "t1", Type: "workspace", ID: chain[i].ID, Ancestors: chain[i+1:]})
	}
	for j, on := range ons {
		for i := range 3 {
			if err := h.authz.SetDeny(ctx, guardian, on, rbac.Deny{
				ID: fmt.Sprint("d", i), Principals: []rbac.Principal{rbac.TenantMembers("t1")},
				Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: longFalse(10*j + i)},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !allowed(t, h, h.as(t, "u"), login, deep) {
		t.Fatal("denied by conditions that don't hold for it")
	}
	if !allowed(t, h, h.as(t, "contractor-1-0007"), view, deep) || allowed(t, h, h.as(t, "contractor-1-0007"), login, deep) {
		t.Fatal("a deny should bind whom its condition names")
	}
}

// Permissions reads each deny's list once for all the permissions it decides, each decided by the
// denies listing it or its wildcard alone, as Authorize decides it: compared with every deny's list
// for each, 300 permissions beside 400 denies of 256 other entries took 300 ms, each comparison
// making the permission's wildcard anew.
func TestPermissionsReadEachDenysListOnce(t *testing.T) {
	var held, others []rbac.Permission
	for i := range 300 {
		held = append(held, rbac.Permission(fmt.Sprintf("cluster:p%03d", i)))
	}
	for i := range rbac.MaxDenyEntries {
		others = append(others, rbac.Permission(fmt.Sprintf("cluster:o%03d", i)))
	}
	const few = 30
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "many", Permissions: held, ResourceTypes: []string{"cluster"}},
			rbac.RoleDefinition{ID: "few", Permissions: held[:few], ResourceTypes: []string{"cluster"}},
		)
	})
	ctx := rbac.WithRequest(t.Context(), map[string]any{"mfa": true, "all": false})
	h.seed(t, grant(cluster.Scope(), "many", rbac.User, "m"), grant(cluster.Scope(), "few", rbac.User, "f"), grant(cluster.Scope(), "many", rbac.User, "x"))
	m, f, x := h.as(t, "m"), h.as(t, "f"), h.as(t, "x")
	deny := func(s rbac.Scope, id string, principal string, perms []rbac.Permission, condition string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
			VALUES ('t1', $1, $2, $3, ARRAY[$4], $5::text[], $6)`, s.Type, s.ID, id, principal, perms, condition); err != nil {
			t.Fatal(err)
		}
	}
	// On each scope of the path, denies binding everyone of permissions no one holds, half of them
	// conditional.
	n := 0
	for _, s := range append([]rbac.Scope{cluster.Scope(), rbac.TenantRoot("t1")}, cluster.Ancestors...) {
		for i := range rbac.MaxDenies - 4 {
			deny(s, fmt.Sprint("o", i), "public:", others, []string{"", "request.attributes.mfa != true"}[i%2])
			n++
		}
	}
	// And on the cluster, denies binding x alone of what it holds, of each request: one listing a
	// permission twice, as a row written around the package can, and some every permission on a type,
	// one of them a permission too.
	deny(cluster.Scope(), "a", "user:x", []rbac.Permission{"cluster:*"}, "request.attributes.all == true")
	deny(cluster.Scope(), "b", "user:x", []rbac.Permission{held[4], "cluster:*"}, "request.attributes.all == true")
	deny(cluster.Scope(), "p001", "user:x", held[1:2], "")
	deny(cluster.Scope(), "p002", "user:x", []rbac.Permission{held[2], held[2]}, "request.attributes.mfa == true")
	deny(cluster.Scope(), "p003", "user:x", []rbac.Permission{"workspace:*", held[3]}, "request.attributes.mfa == false")
	for _, r := range []struct {
		mfa, all bool
		want     []rbac.Permission
	}{{true, false, []rbac.Permission{held[0], held[3], held[4]}}, {false, false, []rbac.Permission{held[0], held[2], held[4]}}, {true, true, nil}} {
		c := rbac.WithRequest(t.Context(), map[string]any{"mfa": r.mfa, "all": r.all})
		perms, err := h.authz.Permissions(c, x, cluster)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range held[:5] {
			err := h.authz.Authorize(c, x, p, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				t.Fatal(err)
			}
			if listed := slices.Contains(perms, p); listed != slices.Contains(r.want, p) || listed != (err == nil) {
				t.Errorf("with mfa %v and all %v, Permissions lists %s: %v, Authorize: %v", r.mfa, r.all, p, listed, err)
			}
		}
	}
	listing := func(s rbac.Subject, want int) {
		t.Helper()
		if perms, err := h.authz.Permissions(ctx, s, cluster); err != nil || len(perms) != want {
			t.Fatalf("Permissions = %d permissions, %v", len(perms), err)
		}
	}
	allocs := func(s rbac.Subject, want int) float64 {
		t.Helper()
		return testing.AllocsPerRun(3, func() { listing(s, want) })
	}
	// Reading the denies allocates alike for both, and each permission decided more allocates no more
	// as the denies grow: compared with each deny's list, it allocated twice for each.
	if more := (allocs(m, len(held)) - allocs(f, few)) / float64(len(held)-few); more > float64(n)/4 {
		t.Errorf("Permissions allocates %.0f times more for each permission beside %d denies", more, n)
	}
	read := 0
	rbac.SetReadingDenies(t, func(k int) { read += k })
	reads := func(s rbac.Subject, want int) int {
		t.Helper()
		read = 0
		listing(s, want)
		return read
	}
	// Nor reads any more of them: compared with each deny's list, it read every one for each.
	if more := (reads(m, len(held)) - reads(f, few)) / (len(held) - few); more > n*rbac.MaxDenyEntries/4 {
		t.Errorf("Permissions reads %d entries of denies more for each permission beside %d denies of %d", more, n, rbac.MaxDenyEntries)
	}
}

// A change's read of its actor's authority decides each permission the actor hands on by the
// denies listing it alone, as Permissions does: compared with every deny's list for each, an actor
// granting a role of 300 permissions beside 368 denies of 256 others read 85 million entries of
// them, in 350 ms, and indexed, 750,000, in 36. Each is decided as before: by a deny listing it, it
// twice or the wildcard covering it, under each request, and by one the actor is exempt from only
// until a time.
func TestAChangeReadsEachDenysListOnceForWhatItHandsOn(t *testing.T) {
	var held, others []rbac.Permission
	for i := range 300 {
		held = append(held, rbac.Permission(fmt.Sprintf("cluster:p%03d", i)))
	}
	for i := range rbac.MaxDenyEntries {
		others = append(others, rbac.Permission(fmt.Sprintf("cluster:o%03d", i)))
	}
	const few = 30
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "many", Permissions: held, ResourceTypes: []string{"cluster"}},
			rbac.RoleDefinition{ID: "few", Permissions: held[:few], ResourceTypes: []string{"cluster"}},
			rbac.RoleDefinition{ID: "late", Permissions: held[201:], ResourceTypes: []string{"cluster"}},
		)
	})
	request := func(mfa string, wild bool) context.Context {
		return rbac.WithRequest(t.Context(), map[string]any{"mfa": mfa, "wild": wild})
	}
	ctx := request("yes", false)
	var seeded []rbac.Grant
	for _, id := range []string{"m", "x"} {
		seeded = append(seeded, grant(cluster.Scope(), "many", rbac.User, id), grant(cluster.Scope(), "cluster.admin", rbac.User, id))
	}
	h.seed(t, seeded...)
	// Both on call for an hour, which exempts them from some denies until then.
	m, x := h.as(t, "m", "oncall"), h.as(t, "x", "oncall")
	hour := h.now.Add(time.Hour)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $1 WHERE tenant = 't1' AND group_id = 'oncall'`, hour); err != nil {
		t.Fatal(err)
	}
	deny := func(s rbac.Scope, id, principal string, exempt []string, perms []rbac.Permission, condition string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions, condition)
			VALUES ('t1', $1, $2, $3, ARRAY[$4], $5::text[], $6::text[], $7)`, s.Type, s.ID, id, principal, append([]string{}, exempt...), perms, condition); err != nil {
			t.Fatal(err)
		}
	}
	// On each scope of the path, denies binding everyone of permissions no one holds, half of them
	// conditional, and a quarter exempting those on call, until then.
	n := 0
	for _, s := range append([]rbac.Scope{cluster.Scope(), rbac.TenantRoot("t1")}, cluster.Ancestors...) {
		for i := range rbac.MaxDenies - 8 {
			var exempt []string
			if i%4 == 3 {
				exempt = []string{"group:oncall"}
			}
			deny(s, fmt.Sprint("o", i), "public:", exempt, others, []string{"", "request.attributes.mfa != 'yes'"}[i%2])
			n++
		}
	}
	// And on the cluster, denies binding x alone of what it holds, each read once x has been asked
	// about more than a few: of every permission on the type, but only for one; of one permission,
	// and another type's; of one listed twice; of one under any request; and of one x is exempt from
	// while on call.
	deny(cluster.Scope(), "w", "user:x", nil, []rbac.Permission{"cluster:*"}, `request.attributes.wild == true && action == "cluster:p100"`)
	deny(cluster.Scope(), "a", "user:x", nil, []rbac.Permission{"workspace:*", held[120]}, "request.attributes.mfa == 'no'")
	deny(cluster.Scope(), "b", "user:x", nil, []rbac.Permission{held[150], held[150]}, "request.attributes.mfa == 'yes'")
	deny(cluster.Scope(), "c", "user:x", nil, held[200:201], "")
	deny(cluster.Scope(), "e", "user:x", []string{"group:oncall"}, held[250:251], "")
	granted := 0
	granting := func(ctx context.Context, actor rbac.Subject, role rbac.Role, until time.Time) error {
		t.Helper()
		granted++
		to := h.as(t, fmt.Sprint("to", granted)).Principal
		return h.authz.Apply(ctx, actor, cluster, rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: to, ExpiresAt: until}}})
	}
	for _, c := range []struct {
		mfa  string
		wild bool
		role rbac.Role
		// until is when the grant ends, and lacks what x can't hand on, the first the role gives.
		until time.Time
		lacks rbac.Permission
	}{
		{"yes", true, "many", time.Time{}, held[100]},
		{"yes", false, "many", time.Time{}, held[150]},
		{"no", false, "many", time.Time{}, held[120]},
		{"maybe", false, "many", time.Time{}, held[200]},
		{"maybe", false, "late", time.Time{}, held[250]},
		{"maybe", false, "late", hour.Add(time.Microsecond), held[250]},
		{"maybe", false, "late", hour, ""},
	} {
		ctx := request(c.mfa, c.wild)
		err := granting(ctx, x, c.role, c.until)
		var denied *rbac.DeniedError
		switch {
		case c.lacks == "" && err != nil:
			t.Errorf("x granting %s until %v under mfa %q: %v", c.role, c.until, c.mfa, err)
		case c.lacks != "" && (!errors.As(err, &denied) || denied.Permission != c.lacks):
			t.Errorf("x granting %s until %v under mfa %q and wild %v: %v, want it to lack %s", c.role, c.until, c.mfa, c.wild, err, c.lacks)
		}
		// As a check of each decides it now, while x is on call.
		for _, p := range []rbac.Permission{held[100], held[120], held[150], held[200], held[250], held[299]} {
			removed := p == held[200] || p == held[100] && c.wild || p == held[120] && c.mfa == "no" || p == held[150] && c.mfa == "yes"
			if err := h.authz.Authorize(ctx, x, p, cluster); removed != errors.Is(err, rbac.ErrDenied) || !removed && err != nil {
				t.Errorf("under mfa %q and wild %v, Authorize of %s: %v", c.mfa, c.wild, p, err)
			}
		}
	}
	read := 0
	rbac.SetReadingDenies(t, func(k int) { read += k })
	reads := func(role rbac.Role) int {
		t.Helper()
		read = 0
		if err := granting(ctx, m, role, time.Time{}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	// Each permission handed on more reads no more of the denies as they grow: compared with each
	// deny's list, it read each binding m twice in each phase, and each m is exempt from until then.
	if more := (reads("many") - reads("few")) / (len(held) - few); more > n*rbac.MaxDenyEntries/4 {
		t.Errorf("granting a role reads %d entries of denies more for each permission beside %d denies of %d", more, n, rbac.MaxDenyEntries)
	}
}

func TestEachPermissionIsDecidedOnItsOwnBudgets(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	var xs []string
	for i := range 34 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	// Five conditional denies of every cluster permission on each of the cluster, its workspace and
	// the tenant, each false and costing nearly all a condition may, its inner list charged for its
	// elements each time a step builds it, and each step for its macro's &&.
	for j, on := range []rbac.Resource{cluster, workspace, {Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}} {
		for i := range 5 {
			expr := fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", list, list, 10*j+i)
			if err := h.authz.SetDeny(ctx, guardian, on, rbac.Deny{
				ID: fmt.Sprint("d", i), Principals: []rbac.Principal{rbac.TenantMembers("t1")},
				Permissions: []rbac.Permission{"cluster:*"}, Condition: rbac.Condition{Expression: expr},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if d, err := h.authz.Explain(ctx, h.as(t, "owner"), root, cluster); err != nil || !d.Allowed {
		t.Fatalf("conditions that don't hold should leave the owner root: %+v, %v", d.Reason, err)
	}
	// Listing what the owner may do decides each permission as checking it would.
	perms, err := h.authz.Permissions(ctx, h.as(t, "owner"), cluster)
	if err != nil || !slices.Equal(perms, []rbac.Permission{grantC, login, root, view}) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	// And handing each on.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); err != nil {
		t.Fatalf("handing on what the denies leave: %v", err)
	}
	// And on a budget of its own for its grants' conditions: costly ones stored around the bounds
	// that don't hold and, costliest, one that does, which one budget for both permissions the role
	// gives never reaches.
	grants := []rbac.Grant{{Scope: cluster.Scope(), Binding: conditional("cluster.login", "c", "true || "+spending(0))}}
	for i := range 20 {
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.login", "c", spending(i+1))})
	}
	storeAround(t, h, grants...)
	for _, p := range []rbac.Permission{login, view} {
		if !allowed(t, h, h.as(t, "c"), p, cluster) {
			t.Fatalf("a condition that holds should allow %s", p)
		}
	}
	if perms, err := h.authz.Permissions(ctx, h.as(t, "c"), cluster); err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Fatalf("Permissions under conditions = %v, %v", perms, err)
	}
}

func TestConditionalGrantsDecideWhateverTheirIDs(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	// Stored around the bounds, so a check's budget runs out before it evaluates them all.
	var grants []rbac.Grant
	for _, b := range []struct {
		role rbac.Role
		id   string
	}{{"cluster.login", "u"}, {guardRole.ID, "g"}} {
		for i := range 30 {
			grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(b.role, b.id, spending(i))})
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(b.role, b.id, "true")})
	}
	storeAround(t, h, grants...)
	// The grant that holds read first by id, then last: the cheapest is evaluated first either way.
	for _, ids := range [][2]string{
		{"00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000001"},
		{"ffffffff-ffff-ffff-ffff-ffffffffffff", "ffffffff-ffff-ffff-ffff-fffffffffffe"},
	} {
		for i, principal := range []string{"user:u", "user:g"} {
			tag, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET id = $1 WHERE principal = $2 AND condition = 'true'`, ids[i], principal)
			if err != nil || tag.RowsAffected() != 1 {
				t.Fatalf("moving %s's grant that holds: %v, %v", principal, tag, err)
			}
		}
		if !allowed(t, h, h.as(t, "u"), login, cluster) {
			t.Fatalf("with the grant that holds at %s, denied", ids[0])
		}
		if perms, err := h.authz.Permissions(ctx, h.as(t, "u"), cluster); err != nil || !slices.Contains(perms, login) {
			t.Fatalf("Permissions = %v, %v", perms, err)
		}
		// The escalation checks read the actor's grants in the same order.
		if err := h.authz.SetDeny(ctx, h.as(t, "g"), cluster, rbac.Deny{
			ID: "d", Principals: []rbac.Principal{{Kind: rbac.User, ID: "z"}}, Permissions: []rbac.Permission{login},
		}); err != nil {
			t.Fatalf("with the grant that holds at %s, SetDeny: %v", ids[1], err)
		}
	}
}

func TestExplainSpendsTheBudgetAsAuthorizeDoes(t *testing.T) {
	workspace := rbac.Scope{Type: "workspace", ID: "w1"}
	// The grant that holds is read first in one order of scopes and principals, and last in the
	// other, of grants stored around the bounds.
	for _, holds := range []int{0, 29} {
		h := setup(t)
		var groups []string
		var grants []rbac.Grant
		for i := range 30 {
			g := fmt.Sprintf("g%02d", i)
			groups = append(groups, g)
			scope, expr := cluster.Scope(), spending(i)
			if i == holds {
				expr = "true || " + spending(0)
			}
			if (i == holds) == (holds == 0) {
				scope = workspace
			}
			grants = append(grants, rbac.Grant{Scope: scope, Binding: rbac.Binding{
				Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
			}})
		}
		storeAround(t, h, grants...)
		s := h.as(t, "many", groups...)
		d, err := h.authz.Explain(t.Context(), s, login, cluster)
		if a := allowed(t, h, s, login, cluster); err != nil || d.Allowed != a {
			t.Errorf("the grant that holds read as %d: Authorize = %v, Explain = %+v, %v", holds, a, d, err)
		}
	}
}

func TestACheckDecidesAsItWouldWhateverIsCompiled(t *testing.T) {
	h := setup(t)
	var xs []string
	for i := range 400 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	var groups []string
	var grants []rbac.Grant
	// Cheap to evaluate and costly to compile, and stored around the bounds, so the check's budget
	// runs out on compiling them.
	for i := range 45 {
		g := fmt.Sprintf("g%02d", i)
		groups = append(groups, g)
		expr := fmt.Sprintf(`%s.all(x, x >= 0) && %d == 0`, list, i+1)
		// The one that holds costs the most to compile, so it is evaluated last.
		if i == 44 {
			expr = "true || " + expr
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
			Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
		}})
	}
	storeAround(t, h, grants...)
	// Each checked alone, they are compiled for h.authz; another Authorizer compiles them as it
	// checks.
	for _, g := range groups {
		allowed(t, h, h.as(t, "in-"+g, g), login, cluster)
	}
	fresh, err := rbac.New(h.pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
		Now:           func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	s := h.as(t, "many", groups...)
	compiled := allowed(t, h, s, login, cluster)
	for i := range 2 {
		err := fresh.Authorize(t.Context(), s, login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		if (err == nil) != compiled {
			t.Errorf("check %d with nothing compiled: %v, with everything compiled: %v", i, err == nil, compiled)
		}
	}
}

func TestAMatchCostsWhatItsPatternCompilesTo(t *testing.T) {
	h := setup(t)
	// A short pattern that compiles to about a thousand instructions, matched against a long string.
	expr := `!"` + strings.Repeat("a", 1900) + `".matches(".{498}b")`
	if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "x"), login, cluster) {
		t.Error("a match past the cost limit should be false")
	}
}

func TestAConditionIsTextPostgreSQLStores(t *testing.T) {
	h := setup(t)
	for _, c := range []rbac.Condition{
		{Title: "a\x00b", Expression: "true"},
		{Description: "\xff", Expression: "true"},
		{Expression: `"` + "\xff" + `" != ""`},
	} {
		b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, Condition: c}
		if err := h.authz.Apply(t.Context(), h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply(%q) = %v", c, err)
		}
		if err := h.authz.Import(t.Context(), host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Import(%q) = %v", c, err)
		}
	}
}

// guarded sets up a guardian who may set denies anywhere in the tenant, configured as mutate says.
func guarded(t *testing.T, mutate ...func(*rbac.Config)) (*harness, rbac.Subject) {
	t.Helper()
	guard := rbac.RoleDefinition{
		ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("tenant"), rbac.DenyPermission("workspace"), rbac.DenyPermission("cluster")},
		ResourceTypes: []string{"tenant", "workspace", "cluster"},
	}
	h := setup(t, append([]func(*rbac.Config){func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guard) }}, mutate...)...)
	h.seed(t, grant(rbac.TenantRoot("t1"), "guard", rbac.User, "guardian"))
	return h, h.as(t, "guardian")
}

func TestDenies(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	h.seed(t,
		grant(workspace.Scope(), "cluster.sudo", rbac.Group, "contractors"),
		grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.sudo", rbac.User, "named"),
	)
	contractor, lead := h.as(t, "c", "contractors"), h.as(t, "lead", "contractors")
	d := rbac.Deny{
		ID: "no-root", Name: "No root for contractors", Permissions: []rbac.Permission{root},
		Principals: []rbac.Principal{{Kind: rbac.Group, ID: "contractors"}, {Kind: rbac.User, ID: "named"}},
		Exempt:     []rbac.Principal{{Kind: rbac.User, ID: "lead"}},
	}
	h.events = nil
	if err := h.authz.SetDeny(ctx, guardian, workspace, d); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Denies) != 1 || h.events[0].Denies[0].ID != "no-root" {
		t.Fatalf("events = %+v", h.events)
	}
	reordered := d
	reordered.Principals = []rbac.Principal{d.Principals[1], d.Principals[0], d.Principals[1]}
	if err := h.authz.SetDeny(ctx, guardian, workspace, reordered); err != nil || len(h.events) != 1 {
		t.Fatalf("setting a deny again, reordered: %v, events = %+v", err, h.events)
	}
	if allowed(t, h, contractor, root, cluster) || allowed(t, h, h.as(t, "named"), root, cluster) {
		t.Fatal("a deny should remove what it lists from whom it names, whatever their grants give")
	}
	if !allowed(t, h, contractor, login, cluster) || !allowed(t, h, lead, root, cluster) {
		t.Fatal("a deny should leave what it doesn't list, and those it exempts")
	}
	if dec, err := h.authz.Explain(ctx, contractor, root, cluster); err != nil || dec.Allowed || !strings.Contains(dec.DeniedBy, "no-root") {
		t.Fatalf("Explain = %+v, %v", dec, err)
	}
	if perms, err := h.authz.Permissions(ctx, contractor, cluster); err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, root, cluster); err != nil || slices.ContainsFunc(holderPrincipals(holders), func(p rbac.Principal) bool { return p.ID == "named" || p.ID == "c" }) ||
		!slices.Contains(holderPrincipals(holders), lead.Principal) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	for _, s := range []rbac.Subject{contractor, lead, h.as(t, "named")} {
		listingsAgree(t, h, resources, s, root)
	}
	reach, err := h.authz.Reachable(ctx, contractor, root, "t1", "cluster")
	if err != nil || !slices.Equal(reach.Except, []rbac.Scope{workspace.Scope()}) {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	if got, err := h.authz.Denies(ctx, "t1", []rbac.Scope{workspace.Scope()}); err != nil || len(got) != 1 || got[0].CreatedBy != guardian.Principal {
		t.Fatalf("Denies = %+v, %v", got, err)
	}

	// Every permission on a type, for everyone, across the tenant.
	all := rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{"cluster:*"}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	if err := h.authz.SetDeny(ctx, guardian, tenant, all); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "owner"), view, cluster) || allowed(t, h, rbac.Subject{}, view, cluster) {
		t.Fatal("a deny of cluster:* to the public should remove every cluster permission from everyone")
	}
	if reach, err := h.authz.Reachable(ctx, h.as(t, "owner"), view, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Fatalf("Reachable under a tenant-wide deny = %+v, %v", reach, err)
	}
	listingsAgree(t, h, resources, h.as(t, "owner"), view)
	if err := h.authz.DeleteDeny(ctx, guardian, tenant, "freeze"); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, h.as(t, "owner"), view, cluster) {
		t.Fatal("deleting a deny should end it")
	}
	if err := h.authz.DeleteScope(ctx, host, "t1", workspace.Scope()); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Denies(ctx, "t1", []rbac.Scope{workspace.Scope()}); err != nil || len(got) != 0 {
		t.Fatalf("a deleted scope's denies: %+v, %v", got, err)
	}
}

func TestAConditionalDenyFailsClosed(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	d := rbac.Deny{
		ID: "vpn", Permissions: []rbac.Permission{login}, Principals: []rbac.Principal{rbac.TenantMembers("t1")},
		Condition: rbac.Condition{Title: "VPN only", Expression: `request.attributes.vpn != true`},
	}
	if err := h.authz.SetDeny(ctx, guardian, workspace, d); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Denies(ctx, "t1", []rbac.Scope{workspace.Scope()}); err != nil || len(got) != 1 || got[0].Condition != d.Condition {
		t.Fatalf("a deny's condition read back: %+v, %v", got, err)
	}
	check := func(attrs map[string]any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, attrs), h.as(t, "owner"), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	if check(nil) {
		t.Fatal("a deny whose condition can't be evaluated should deny")
	}
	if check(map[string]any{"vpn": false}) {
		t.Fatal("a deny whose condition holds should deny")
	}
	if !check(map[string]any{"vpn": true}) {
		t.Fatal("a deny whose condition doesn't hold should leave access")
	}
	reach, err := h.authz.Reachable(ctx, h.as(t, "owner"), login, "t1", "cluster")
	if err != nil || !slices.Equal(reach.ConditionalExcept, []rbac.Scope{workspace.Scope()}) || len(reach.Conditional) > 0 || len(reach.Except) > 0 {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	// Someone the deny names but nothing reaches has nothing to check one by one.
	if reach, err := h.authz.Reachable(ctx, h.as(t, "nobody"), login, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes)+len(reach.Conditional)+len(reach.ConditionalExcept) > 0 {
		t.Fatalf("Reachable without grants = %+v, %v", reach, err)
	}
	resources := hostTable(t, h)
	for _, s := range []rbac.Subject{h.as(t, "owner"), h.as(t, "nobody")} {
		listingsAgree(t, h, resources, s, login)
	}
}

func TestNoDenyLocksOutAGuardAbove(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	h.seed(t, grant(workspace.Scope(), "guard", rbac.User, "local"))
	lockout := rbac.Deny{
		ID: "lockout", Permissions: []rbac.Permission{"workspace:*", "cluster:*"},
		Principals: []rbac.Principal{rbac.TenantMembers("t1")},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "local"), workspace, lockout); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, h.as(t, "owner"), view, cluster) {
		t.Fatal("a deny of cluster:* should remove the cluster's permissions")
	}
	for _, r := range []rbac.Resource{workspace, cluster} {
		if !allowed(t, h, guardian, rbac.DenyPermission(r.Type), r) {
			t.Fatalf("a type's wildcard removed %s from the guardian", rbac.DenyPermission(r.Type))
		}
	}
	if perms, err := h.authz.Permissions(ctx, guardian, workspace); err != nil || !slices.Contains(perms, rbac.DenyPermission("workspace")) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, rbac.DenyPermission("workspace"), workspace); err != nil || !slices.Contains(holderPrincipals(holders), guardian.Principal) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	listingsAgree(t, h, resources, guardian, rbac.DenyPermission("cluster"))
	listingsAgree(t, h, resources, h.as(t, "owner"), view)
	if reach, err := h.authz.Reachable(ctx, guardian, rbac.DenyPermission("workspace"), "t1", "workspace"); err != nil || !reach.All || len(reach.Except) > 0 {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	if err := h.authz.DeleteDeny(ctx, guardian, workspace, "lockout"); err != nil {
		t.Fatalf("the guardian above lifting a deny set below: %v", err)
	}
	if !allowed(t, h, h.as(t, "owner"), view, cluster) {
		t.Fatal("a lifted deny should end")
	}
}

func TestNoStoredDenyRemovesThePowerToSetDenies(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	// On the workspace too, which reaching everything already, Reachable doesn't list.
	h.seed(t, grant(workspace.Scope(), "guard", rbac.User, "guardian"))
	resources := hostTable(t, h)
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	// Rows written around the package, and past what the table checks of them: one listing what a
	// deny of an undeniable permission was once matched as, and others listing one.
	if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_denies DROP CONSTRAINT rbac_denies_permissions_deniable`); err != nil {
		t.Fatal(err)
	}
	for i, perms := range []string{"{-}", "{cluster:deny}", "{tenant:deny,workspace:deny}"} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			VALUES ('t1', 'tenant', 't1', $1, '{public:}', $2)`, fmt.Sprint("odd", i), perms); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []rbac.Resource{cluster, workspace, tenant} {
		p := rbac.DenyPermission(r.Type)
		if !allowed(t, h, guardian, p, r) {
			t.Errorf("a stored deny removed %s", p)
		}
		if d, err := h.authz.Explain(ctx, guardian, p, r); err != nil || !d.Allowed {
			t.Errorf("Explain(%s) = %+v, %v", p, d, err)
		}
		if perms, err := h.authz.Permissions(ctx, guardian, r); err != nil || !slices.Contains(perms, p) {
			t.Errorf("Permissions = %v, %v", perms, err)
		}
		if holders, err := h.authz.Holders(ctx, p, r); err != nil || !slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == guardian.Principal && !x.MaybeDenied }) {
			t.Errorf("Holders(%s) = %+v, %v", p, holders, err)
		}
		if reach, err := h.authz.Reachable(ctx, guardian, p, "t1", r.Type); err != nil || !reach.All || len(reach.Scopes)+len(reach.Conditional)+len(reach.Except)+len(reach.ConditionalExcept) > 0 {
			t.Errorf("Reachable(%s) = %+v, %v", p, reach, err)
		}
	}
	listingsAgree(t, h, resources, guardian, rbac.DenyPermission("cluster"))
	for i := range 3 {
		if err := h.authz.DeleteDeny(ctx, guardian, tenant, fmt.Sprint("odd", i)); err != nil {
			t.Errorf("lifting a stored deny of the power to lift it: %v", err)
		}
	}
}

func TestADenyStoresOnlyPermissionsADenyRemoves(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	insert := func(perms []*string) error {
		_, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			VALUES ('t1', 'cluster', 'c1', 'd', '{public:}', $1)`, perms)
		return err
	}
	text := func(ps ...string) []*string {
		out := make([]*string, len(ps))
		for i := range ps {
			out[i] = &ps[i]
		}
		return out
	}
	for _, perms := range [][]*string{
		text("-"), text("cluster:deny"), text("cluster:login", "workspace:deny"), text("cluster:Login"), text("cluster"),
		text(":login"), text("cluster:login "), text(""), text("cluster:login", ""), append(text("cluster:login"), nil),
		// One element that reads as two permissions joined, which no check matches.
		text("cluster:login,cluster:root"), text("cluster:view", "cluster:login,workspace:*"),
	} {
		var pg *pgconn.PgError
		if err := insert(perms); !errors.As(err, &pg) || pg.Code != "23514" {
			t.Errorf("a deny of %v stored: %v", perms, err)
		}
	}
	if err := insert(text("cluster:login", "workspace:*", "cluster:root-ish")); err != nil {
		t.Fatalf("a deny of permissions and a type's every one: %v", err)
	}
}

func TestADenyRecordsWhoChangedIt(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "guard", rbac.User, "second"))
	d := rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
		t.Fatal(err)
	}
	read := func() rbac.Deny {
		t.Helper()
		got, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
		if err != nil || len(got) != 1 {
			t.Fatalf("Denies = %+v, %v", got, err)
		}
		return got[0]
	}
	if got := read(); got.CreatedBy != guardian.Principal || got.UpdatedBy != guardian.Principal {
		t.Fatalf("a new deny: %+v", got)
	}
	// Setting it again unchanged is not a change.
	if err := h.authz.SetDeny(ctx, h.as(t, "second"), cluster, d); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.UpdatedBy != guardian.Principal {
		t.Fatalf("an unchanged deny: %+v", got)
	}
	d.Name = "No root"
	if err := h.authz.SetDeny(ctx, h.as(t, "second"), cluster, d); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.CreatedBy != guardian.Principal || got.UpdatedBy != (rbac.Principal{Kind: rbac.User, ID: "second"}) || got.UpdatedAt.Before(got.CreatedAt) {
		t.Fatalf("a changed deny: %+v", got)
	}
}

func TestDeniesBindChanges(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	owner := rbac.Principal{Kind: rbac.User, ID: "owner"}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{owner}}); err != nil {
		t.Fatal(err)
	}
	b := func(role rbac.Role) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}}}
	}
	// Denied root, the owner doesn't hold it to hand on.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, b("cluster.sudo")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a permission a deny removes from the actor: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, b("cluster.login")); err != nil {
		t.Fatalf("granting what no deny removes: %v", err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "frozen", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{owner}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, b("cluster.login")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access a deny removes: %v", err)
	}
}

func TestAConditionalDenyBindsWhatAContainerHandsOn(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.seed(t, grant(workspace.Scope(), "workspace.admin", rbac.User, "x"), grant(workspace.Scope(), "cluster.sudo", rbac.User, "x"))
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	x := rbac.Principal{Kind: rbac.User, ID: "x"}
	for _, d := range []rbac.Deny{
		{ID: "on-clusters", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x}, Condition: rbac.Condition{Expression: `resource.type == "cluster"`}},
		{ID: "off-vpn", Permissions: []rbac.Permission{login}, Principals: []rbac.Principal{x}, Condition: rbac.Condition{Expression: `request.attributes.vpn != true`}},
	} {
		if err := h.authz.SetDeny(ctx, guardian, tenant, d); err != nil {
			t.Fatal(err)
		}
	}
	b := func(role rbac.Role) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "y"}}}}
	}
	vpn := rbac.WithRequest(ctx, map[string]any{"vpn": true})
	// On a workspace the deny reads no cluster, but the grant reaches its clusters.
	if err := h.authz.Apply(vpn, h.as(t, "x"), workspace, b("cluster.sudo")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("handing on through a container what a deny reading the resource removes: %v", err)
	}
	// One that reads only the request is decided for it.
	if err := h.authz.Apply(ctx, h.as(t, "x"), workspace, b("cluster.login")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("handing on off the VPN what a deny removes off it: %v", err)
	}
	if err := h.authz.Apply(vpn, h.as(t, "x"), workspace, b("cluster.login")); err != nil {
		t.Fatalf("handing on on the VPN what a deny removes only off it: %v", err)
	}
}

func TestADenyOnChangingGrantsStopsRedefiningRoles(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	h.seed(t, grant(tenant.Scope(), "tenant.roles", rbac.User, "x"), grant(tenant.Scope(), "cluster.sudo", rbac.User, "x"))
	r := rbac.RoleDefinition{ID: "custom.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, h.as(t, "x"), "t1", r); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"))
	if err := h.authz.SetDeny(ctx, guardian, tenant, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{{Kind: rbac.User, ID: "x"}}}); err != nil {
		t.Fatal(err)
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, h.as(t, "x"), "t1", wider); !errors.Is(err, rbac.ErrDenied) || allowed(t, h, h.as(t, "y"), root, cluster) {
		t.Fatalf("changing what a role's grants give, denied changing them: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, h.as(t, "x"), "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("revoking a role's grants, denied changing them: %v", err)
	}
	other := rbac.RoleDefinition{ID: "custom.other", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, h.as(t, "x"), "t1", other); err != nil {
		t.Fatalf("defining a role no grant has yet: %v", err)
	}
}

// viewing gives view on clusters and workspaces, on either.
var viewing = rbac.RoleDefinition{ID: "viewing", Permissions: []rbac.Permission{view, "workspace:view"}, ResourceTypes: []string{"cluster", "workspace"}}

func withViewing(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewing) }

// narrowedOff is x, who may define roles and holds what they give on clusters and workspaces, and
// custom.r, which x granted y on c1 and then narrowed to give only on workspaces, so that grant
// gives nothing. The catalog has viewing (withViewing).
func narrowedOff(t *testing.T, h *harness) (rbac.Subject, rbac.RoleDefinition) {
	t.Helper()
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "x"), grant(tenant, "cluster.admin", rbac.User, "x"), grant(tenant, "workspace.admin", rbac.User, "x"),
		grant(tenant, viewing.ID, rbac.User, "x"))
	x, y := h.as(t, "x"), h.as(t, "y")
	r := rbac.RoleDefinition{ID: "custom.r", Permissions: []rbac.Permission{view, "workspace:view"}, ResourceTypes: []string{"cluster", "workspace"}}
	if err := h.authz.SetRole(ctx, x, "t1", r); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: y.Principal}}}); err != nil {
		t.Fatal(err)
	}
	r.ResourceTypes = []string{"workspace"}
	if err := h.authz.SetRole(ctx, x, "t1", r); err != nil {
		t.Fatal(err)
	}
	return x, r
}

// Revoking a grant of a role on a cluster is a change to grants there even once the role, narrowed
// off clusters, gives nothing through it: a deny on the tenant, or a constraint, that stops x
// changing grants on clusters stops x deleting the role or redefining it, as it stops Apply
// revoking that grant.
func TestAFreezeOnChangingGrantsOnATypeARoleWasNarrowedOffStopsChangingIt(t *testing.T) {
	for _, by := range []string{"deny", "constraint"} {
		t.Run(by, func(t *testing.T) {
			frozen := false
			h, guardian := guarded(t, withViewing, func(c *rbac.Config) {
				c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					return frozen && in.Permission == grantC, nil
				}}}
			})
			ctx := t.Context()
			x, r := narrowedOff(t, h)
			if by == "deny" {
				tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
				if err := h.authz.SetDeny(ctx, guardian, tenant, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{x.Principal}}); err != nil {
					t.Fatal(err)
				}
			}
			frozen = by == "constraint"
			y := rbac.Principal{Kind: rbac.User, ID: "y"}
			if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: r.ID, Principal: y}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("revoking the grant on c1 under the freeze: %v", err)
			}
			narrower := r
			narrower.Permissions = []rbac.Permission{"workspace:view"}
			if err := h.authz.SetRole(ctx, x, "t1", narrower); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("redefining a role granted on c1 under the freeze: %v", err)
			}
			if err := h.authz.DeleteRole(ctx, x, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("deleting a role granted on c1 under the freeze: %v", err)
			}
			grants, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{y}})
			if err != nil || len(grants) != 1 || grants[0].Scope != cluster.Scope() {
				t.Fatalf("y's grants: %+v, %v", grants, err)
			}
		})
	}
}

// The constraints are asked before a change's transaction alone, so a role deleted while it is
// granted on a cluster, the constraints not asked about clusters, as it was redefined for them and
// back meanwhile, is tried again, and then stopped where they freeze changes to grants there.
func TestARoleGrantedMeanwhileOnATypeTheConstraintsWerentAskedAboutIsTriedAgain(t *testing.T) {
	frozen := false
	var meanwhile func(context.Context) error
	h := setup(t, withViewing, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "freeze", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == "workspace:grant" {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return false, err
				}
			}
			return frozen && in.Permission == grantC, nil
		}}}
	})
	ctx := t.Context()
	x, r := narrowedOff(t, h)
	y := rbac.Principal{Kind: rbac.User, ID: "y"}
	if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: r.ID, Principal: y}}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		wide := r
		wide.ResourceTypes = []string{"cluster", "workspace"}
		if err := h.authz.SetRole(ctx, x, "t1", wide); err != nil {
			return err
		}
		if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: y}}}); err != nil {
			return err
		}
		err := h.authz.SetRole(ctx, x, "t1", r)
		frozen = true
		return err
	}
	if err := h.authz.DeleteRole(ctx, x, "t1", r.ID); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("deleting a role granted on c1 meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the role should have been granted on c1 meanwhile")
	}
	if err := h.authz.DeleteRole(ctx, x, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again under the freeze: %v", err)
	}
}

// A deny on the tenant set while a change to a role narrowed off clusters waits, which stops x
// changing grants on workspaces, which the role is for, or on clusters, as its grant on c1 is still
// a grant on a cluster, stops it under the tenant's lock.
func TestADenyOnTheTenantSetWhileAChangeToARoleNarrowedOffATypeWaitsStopsIt(t *testing.T) {
	for _, c := range []struct {
		change string
		frozen rbac.Permission
	}{{"redefining", grantC}, {"deleting", grantC}, {"redefining", "workspace:grant"}, {"deleting", "workspace:grant"}} {
		t.Run(c.change+" under "+string(c.frozen), func(t *testing.T) {
			var meanwhile func(context.Context) error
			h, guardian := guarded(t, withViewing, func(cfg *rbac.Config) {
				cfg.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if do := meanwhile; do != nil && in.Permission == "workspace:grant" {
						meanwhile = nil
						return false, do(ctx)
					}
					return false, nil
				}}}
			})
			ctx := t.Context()
			x, r := narrowedOff(t, h)
			meanwhile = func(ctx context.Context) error {
				tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
				return h.authz.SetDeny(ctx, guardian, tenant, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{c.frozen}, Principals: []rbac.Principal{x.Principal}})
			}
			var err error
			if c.change == "deleting" {
				err = h.authz.DeleteRole(ctx, x, "t1", r.ID)
			} else {
				narrower := r
				narrower.Permissions = []rbac.Permission{"workspace:view"}
				err = h.authz.SetRole(ctx, x, "t1", narrower)
			}
			if !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("%s a role granted on c1 while a deny on the tenant removing %s is set: %v", c.change, c.frozen, err)
			}
			if meanwhile != nil {
				t.Fatal("the deny should have been set meanwhile")
			}
			y := rbac.Principal{Kind: rbac.User, ID: "y"}
			grants, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{y}})
			if err != nil || len(grants) != 1 || grants[0].Scope != cluster.Scope() {
				t.Fatalf("y's grants: %+v, %v", grants, err)
			}
		})
	}
}

// definer is x, who may define roles and holds sudo and admin on every cluster, for good, and a
// custom role giving view on clusters it defined.
func definer(t *testing.T, h *harness) (rbac.Subject, rbac.RoleDefinition) {
	t.Helper()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "x"), grant(tenant, "cluster.sudo", rbac.User, "x"), grant(tenant, "cluster.admin", rbac.User, "x"))
	x := h.as(t, "x")
	r := rbac.RoleDefinition{ID: "custom.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(t.Context(), x, "t1", r); err != nil {
		t.Fatal(err)
	}
	return x, r
}

// A deny on a workspace keeps x from handing on root under it, as granting there; redefining a role
// granted there to give root would hand it on just the same.
func TestADenyBelowTheTenantStopsARedefinitionHandingOnWhatItRemoves(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	x, r := definer(t, h)
	y := h.as(t, "y")
	if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	other := rbac.RoleDefinition{ID: "custom.other", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, x, "t1", other); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"), grant(elsewhere.Scope(), other.ID, rbac.User, "y"))
	if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: y.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting root under the deny: %v", err)
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrDenied) || allowed(t, h, y, root, cluster) {
		t.Fatalf("redefining a role granted under the deny to give root: %v", err)
	}
	// Granted where no deny removes root, it gives root.
	other.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, x, "t1", other); err != nil || !allowed(t, h, y, root, elsewhere) {
		t.Fatalf("redefining a role granted outside the deny to give root: %v", err)
	}
	// Widened by what the deny doesn't remove, it gives that.
	wider.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, x, "t1", wider); err != nil || !allowed(t, h, y, login, cluster) {
		t.Fatalf("redefining a role granted under the deny to give login: %v", err)
	}
}

// A grant to the tenant's members of a privileged role gives nothing, so narrowing the role so that
// it no longer is gives them what it gives, as granting it to them would: a deny on the workspace
// that grant is on, which keeps x from handing on what it gives there, stops it, as it stops Apply
// there. A deny where only a grant to an identity is, which gives no more, stops nothing.
func TestADenyWhereTheMembersHoldARoleNoLongerPrivilegedStopsNarrowingIt(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	x, r := definer(t, h)
	member := h.as(t, "m")
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	// Privileged, as it gives root, and granted to the members, as a catalog change would leave it.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.op', '{cluster:view,cluster:root}', '{cluster}');
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES
		  ('t1', 'workspace', 'w1', 'members', 't1', 'custom.op'), ('t1', 'cluster', 'c2', 'user', 'y', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	noView := rbac.Deny{ID: "no-view", Permissions: []rbac.Permission{view}, Principals: []rbac.Principal{x.Principal}}
	if err := h.authz.SetDeny(ctx, guardian, workspace, noView); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, x, workspace, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: rbac.TenantMembers("t1")}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting view to the members under the deny: %v", err)
	}
	narrowed := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, x, "t1", narrowed); !errors.As(err, &denied) || denied.Scope != workspace.Scope() || allowed(t, h, member, view, cluster) {
		t.Fatalf("narrowing a role the members hold under the deny so that it is no longer privileged: %v", err)
	}
	if err := h.authz.DeleteDeny(ctx, guardian, workspace, noView.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, elsewhere, noView); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetRole(ctx, x, "t1", narrowed); err != nil || !allowed(t, h, member, view, cluster) {
		t.Fatalf("narrowing it under a deny only where a grant to an identity is: %v", err)
	}
}

// What the narrowing checked of the denies where the members' grant is before its transaction it
// checks again under the tenant's lock, so a deny set there while the host is asked about that
// grant stops it. A deny elsewhere binds x, so the workspace was read before the transaction.
func TestADenySetWhileANarrowingTheMembersGainByWaitsStopsIt(t *testing.T) {
	var meanwhile func(context.Context) error
	h, guardian := guarded(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaRedefinition {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return err
				}
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	x, _ := definer(t, h)
	member := h.as(t, "m")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.op', '{cluster:view,cluster:root}', '{cluster}');
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'workspace', 'w1', 'members', 't1', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	if err := h.authz.SetDeny(ctx, guardian, elsewhere, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-view", Permissions: []rbac.Permission{view}, Principals: []rbac.Principal{x.Principal}})
	}
	narrowed := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, x, "t1", narrowed); !errors.As(err, &denied) || denied.Scope != workspace.Scope() || allowed(t, h, member, view, cluster) {
		t.Fatalf("narrowing a role the members hold while a deny is set where they hold it: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the deny should have been set meanwhile")
	}
}

// A grant to the tenant's members of a privileged role gives nothing, but a catalog change that has
// the role no longer be privileged gives them what it gives then, and asks no one: so a deny on the
// workspace that grant is on, which keeps x from handing on login there, stops x widening the role
// to give login, as it would were the role not privileged, and the members never log in there.
func TestADenyWhereTheMembersHoldAPrivilegedRoleStopsWideningIt(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	x, _ := definer(t, h)
	member := h.as(t, "m")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.op', '{cluster:view,cluster:root}', '{cluster}');
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'workspace', 'w1', 'members', 't1', 'custom.op')`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-login", Permissions: []rbac.Permission{login}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	wider := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view, login, root}, ResourceTypes: []string{"cluster"}}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.As(err, &denied) || denied.Scope != workspace.Scope() || denied.Permission != login {
		t.Fatalf("widening a privileged role the members hold under the deny: %v", err)
	}
	cfg := h.cfg
	cfg.Catalog = slices.Clone(cfg.Catalog)
	for i, r := range cfg.Catalog {
		if r.ID == "cluster.sudo" {
			cfg.Catalog[i].Privileged = false
		}
	}
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.Authorize(ctx, member, login, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a member logs in under the deny once the catalog has the role no longer be privileged: %v", err)
	}
}

// A scope the host no longer has is read as stored, before the transaction, only where the change
// gives nothing more: where a role listing the role is granted there while the change waits, its
// holders may hand the role on there as it will be, and where the tenant's members are granted it
// there, as a host whose catalog has it not be privileged may, a catalog change that has it no
// longer be gives them what it will give, so the change is refused under the tenant's lock, to be
// tried again, and trying again fails with the host's error.
func TestAScopeTheHostNoLongerHasThatARedefinitionComesToReachRefusesIt(t *testing.T) {
	gone := rbac.Scope{Type: "cluster", ID: "gone"}
	for _, tc := range []struct {
		name string
		// permissions are what custom.op gives, and wider what it is redefined to give.
		permissions string
		wider       []rbac.Permission
		// meanwhile is the grant made while the change waits.
		meanwhile string
	}{
		{"a role listing it is granted there", "{cluster:view}", []rbac.Permission{view, login}, `('t1', 'cluster', 'gone', 'user', 'z', 'custom.lister')`},
		// It gives root, so is privileged, and a grant of it to the members gives them nothing.
		{"the members are granted it there", "{cluster:view,cluster:root}", []rbac.Permission{view, login, root}, `('t1', 'cluster', 'gone', 'members', 't1', 'custom.op')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h, guardian := guarded(t, func(c *rbac.Config) {
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s == gone {
						return rbac.Resource{}, fmt.Errorf("%w: %s", rbac.ErrNotFound, s.Key())
					}
					return resourceOf(ctx, tenant, s)
				}
				validate := c.ValidateGrant
				c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
					if do := meanwhile; do != nil && in.Via == rbac.ViaRedefinition {
						meanwhile = nil
						if err := do(ctx); err != nil {
							return err
						}
					}
					return validate(ctx, q, in)
				}
			})
			ctx := t.Context()
			x, _ := definer(t, h)
			// custom.op isn't Public, so its grant to the public on gone gives nothing, before or after;
			// custom.lister lets its holders grant it, and is granted nowhere yet.
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES
				('t1', 'custom.op', $1, '{cluster}', '{}'), ('t1', 'custom.lister', '{cluster:grant,cluster:view}', '{cluster}', '{custom.op}')`, tc.permissions); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES
				('t1', 'cluster', 'gone', 'public', '', 'custom.op'), ('t1', 'cluster', 'c2', 'user', 'y', 'custom.op')`); err != nil {
				t.Fatal(err)
			}
			// A deny elsewhere binds x, so the scopes are read before the transaction.
			elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c3"}
			if err := h.authz.SetDeny(ctx, guardian, elsewhere, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			meanwhile = func(ctx context.Context) error {
				_, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES `+tc.meanwhile)
				return err
			}
			wider := rbac.RoleDefinition{ID: "custom.op", Permissions: tc.wider, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("widening a role granted on a scope the host no longer has, where %s while it waits: %v", tc.name, err)
			}
			if meanwhile != nil {
				t.Fatal("the grant should have been made meanwhile")
			}
			if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrNotFound) {
				t.Fatalf("trying again: %v", err)
			}
		})
	}
}

// A deny on a container, or on the resource itself, that removes x's power to change grants there
// stops x changing what a role granted there gives, or revoking it by deleting the role, as it
// stops Apply there.
func TestADenyBelowTheTenantOnChangingGrantsStopsRedefiningAndDeletingARoleGrantedThere(t *testing.T) {
	for _, on := range []rbac.Resource{workspace, cluster} {
		t.Run(on.Type, func(t *testing.T) {
			h, guardian := guarded(t)
			ctx := t.Context()
			x, r := definer(t, h)
			y := h.as(t, "y")
			h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"))
			if err := h.authz.SetDeny(ctx, guardian, on, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: r.ID, Principal: y.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("revoking under the freeze: %v", err)
			}
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrDenied) || allowed(t, h, y, root, cluster) {
				t.Fatalf("widening a role granted under the freeze: %v", err)
			}
			narrower := r
			narrower.Permissions = []rbac.Permission{login}
			if err := h.authz.SetRole(ctx, x, "t1", narrower); !errors.Is(err, rbac.ErrDenied) || !allowed(t, h, y, view, cluster) {
				t.Fatalf("narrowing a role granted under the freeze: %v", err)
			}
			if err := h.authz.DeleteRole(ctx, x, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) || !allowed(t, h, y, view, cluster) {
				t.Fatalf("deleting a role granted under the freeze: %v", err)
			}
		})
	}
}

// A deny whose condition reads the resource removes root under a workspace from x on one cluster
// only: a role granted on that cluster and on another under the same workspace can't be widened to
// give it, as x can't grant root on that one.
func TestADenyOnOneResourceStopsARedefinitionGrantedOnItAndOnOthers(t *testing.T) {
	c2 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2", Ancestors: cluster.Ancestors}
	h, guardian := guarded(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == c2.Scope() {
				return c2, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	x, r := definer(t, h)
	y := h.as(t, "y")
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"), grant(c2.Scope(), r.ID, rbac.User, "y"))
	d := rbac.Deny{ID: "no-root-on-c2", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}, Condition: rbac.Condition{Expression: `resource.id == "c2"`}}
	if err := h.authz.SetDeny(ctx, guardian, workspace, d); err != nil {
		t.Fatal(err)
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: y.Principal}}}
	if err := h.authz.Apply(ctx, x, c2, sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting root on c2: %v", err)
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.As(err, &denied) || denied.Scope != c2.Scope() || allowed(t, h, y, root, c2) {
		t.Fatalf("widening a role granted on c1 and c2 to give root: %v", err)
	}
}

// A redefinition decides the scopes that x's grants and the denies on their paths can't tell apart
// once, and tells them apart by every id whole: where the denies on cluster a's path, joined with
// spaces, would read as the one on b's, whose workspace's id holds them, as an id holds any text,
// the deny on b's path removing root from x still keeps x from widening r to give root, granted on
// both or held through a role listing it granted on both. So does a deny on a's path whose
// condition, which can read a, tells a apart by its id, where that id would read as part of b's.
func TestARedefinitionTellsApartScopesWhoseDeniesReadAlikeJoined(t *testing.T) {
	type deny struct {
		on        rbac.Resource
		id        string
		p         rbac.Permission
		condition string
	}
	ws := func(id string) rbac.Resource { return rbac.Resource{Tenant: "t1", Type: "workspace", ID: id} }
	in := func(id, workspace string) rbac.Resource {
		return rbac.Resource{Tenant: "t1", Type: "cluster", ID: id, Ancestors: []rbac.Scope{ws(workspace).Scope()}}
	}
	// Each joins as "workspace:x i cluster:a j ".
	a, b := in("a", "x"), in("b", "x i cluster:a")
	joined := []deny{{ws("x"), "i", "workspace:view", ""}, {a, "j", "workspace:view", ""}, {ws("x i cluster:a"), "j", root, ""}}
	// Each joins as "workspace:x i |cluster:a j ", a's with its scope after its denies.
	spaced, barred := in("a j ", "x"), in("b", "x i |cluster:a")
	conditioned := []deny{{ws("x"), "i", "workspace:view", `resource.id == "none"`}, {ws("x i |cluster:a"), "j", root, ""}}
	for _, c := range []struct {
		name   string
		a, b   rbac.Resource
		denies []deny
		listed bool
	}{
		{"granted", a, b, joined, false},
		{"listed", a, b, joined, true},
		{"beside a condition", spaced, barred, conditioned, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, guardian := guarded(t, func(cfg *rbac.Config) {
				resourceOf := cfg.ResourceOf
				cfg.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					for _, r := range []rbac.Resource{c.a, c.b} {
						if s == r.Scope() {
							return r, nil
						}
					}
					return resourceOf(ctx, tenant, s)
				}
			})
			ctx := t.Context()
			x, r := definer(t, h)
			h.as(t, "y")
			z := h.as(t, "z")
			granted := r
			if c.listed {
				granted = listing(t, h, x, r)
			}
			h.seed(t, grant(c.a.Scope(), granted.ID, rbac.User, "y"), grant(c.b.Scope(), granted.ID, rbac.User, "z"))
			for _, d := range c.denies {
				deny := rbac.Deny{ID: d.id, Permissions: []rbac.Permission{d.p}, Principals: []rbac.Principal{x.Principal}, Condition: rbac.Condition{Expression: d.condition}}
				if err := h.authz.SetDeny(ctx, guardian, d.on, deny); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.authz.Apply(ctx, x, c.b, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: z.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("granting root on b: %v", err)
			}
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			holder := z
			if c.listed {
				holder = h.as(t, "w")
				if err := h.authz.Apply(ctx, z, c.b, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: holder.Principal}}}); err != nil {
					t.Fatal(err)
				}
			}
			var denied *rbac.DeniedError
			if !errors.As(err, &denied) || denied.Scope != c.b.Scope() || allowed(t, h, holder, root, c.b) {
				t.Fatalf("widening a role to give root past the deny on b's path: %v", err)
			}
		})
	}
}

// A deny's condition is evaluated within a budget for each scope of the path, so conditions stored
// past their bound, as before there were bounds, that a container's path can't pay for remove what
// they would there, as they keep x from granting root on workspace w, while on a container below
// it, whose longer path pays for them, they hold false. The two read the same grants and denies,
// but a redefinition decides each by its own budget: widening r, granted on both, to give root is
// refused on w, as Apply there is.
func TestARedefinitionDecidesAContainerByItsOwnPathsBudget(t *testing.T) {
	w := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w"}
	// Read before w, so a decision of the scopes alike would be its.
	below := rbac.Resource{Tenant: "t1", Type: "workspace", ID: "a", Ancestors: []rbac.Scope{w.Scope()}}
	h, _ := guarded(t, func(cfg *rbac.Config) {
		resourceOf := cfg.ResourceOf
		cfg.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			for _, r := range []rbac.Resource{w, below} {
				if s == r.Scope() {
					return r, nil
				}
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	x, r := definer(t, h)
	y, z := h.as(t, "y"), h.as(t, "z")
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.admin", rbac.User, "x"), grant(below.Scope(), r.ID, rbac.User, "y"), grant(w.Scope(), r.ID, rbac.User, "z"))
	// Each costs about a fifth of a scope's budget to compile, at 8 a byte, and holds false for x:
	// eleven are past two scopes' budgets, and within three.
	for i := range 11 {
		expr := fmt.Sprintf("subject.id == %q", fmt.Sprint(i, strings.Repeat("q", 2000)))
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
			VALUES ('t1', 'workspace', 'w', $1, '{user:x}', $2, $3)`, fmt.Sprint("d", i), []string{string(root)}, expr); err != nil {
			t.Fatal(err)
		}
	}
	sudo := func(on rbac.Resource, to rbac.Subject) error {
		return h.authz.Apply(ctx, x, on, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: to.Principal}}})
	}
	var denied *rbac.DeniedError
	if err := sudo(w, z); !errors.As(err, &denied) || denied.Permission != root {
		t.Fatalf("granting root on w: %v", err)
	}
	if err := sudo(below, y); err != nil {
		t.Fatalf("granting root below w: %v", err)
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	in := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c", Ancestors: []rbac.Scope{w.Scope()}}
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.As(err, &denied) || denied.Scope != w.Scope() || allowed(t, h, z, root, in) {
		t.Fatalf("widening a role to give root past the denies on w: %v", err)
	}
}

// What SetRole and DeleteRole checked of the scopes a role is granted on before their transactions
// they check again under the tenant's lock, so a deny below the tenant set meanwhile stops them.
func TestADenySetWhileARedefinitionWaitsStopsIt(t *testing.T) {
	var meanwhile func(context.Context) error
	h, guardian := guarded(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if do := meanwhile; do != nil && in.Via == rbac.ViaRedefinition {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return err
				}
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	x, r := definer(t, h)
	y := h.as(t, "y")
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"))
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}})
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrConflict) || allowed(t, h, y, root, cluster) {
		t.Fatalf("widening a role while a deny below the tenant is set: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the deny should have been set meanwhile")
	}
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
}

func TestADenySetWhileADeletionWaitsStopsIt(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	x, r := definer(t, h)
	y := h.as(t, "y")
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "y"))
	// The deny is set in a transaction that holds the tenant until it commits.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteRole(ctx, x, "t1", r.ID) }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; !errors.Is(err, rbac.ErrConflict) || !allowed(t, h, y, view, cluster) {
		t.Fatalf("deleting a role while a deny below the tenant is set: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, x, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
}

// changingRoles are SetRole widening custom.r and DeleteRole deleting it, by admin (roleAdmin), on
// a, each as a change a test counts the pages of.
func changingRoles(ctx context.Context, admin rbac.Subject) map[string]func(a *rbac.Authorizer) error {
	return map[string]func(a *rbac.Authorizer) error{
		"widening": func(a *rbac.Authorizer) error {
			return a.SetRole(ctx, admin, "t1", rbac.RoleDefinition{ID: "custom.r", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}})
		},
		"deleting": func(a *rbac.Authorizer) error { return a.DeleteRole(ctx, admin, "t1", "custom.r") },
	}
}

// pagesChanging is how many pages of each of tables change reads, in a transaction it rolls back.
func pagesChanging(ctx context.Context, t *testing.T, h *harness, change func(a *rbac.Authorizer) error, tables ...string) map[string]int64 {
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
	if err := change(h.authz.WithTx(tx)); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		pages[table] += pagesRead(ctx, t, tx, table)
	}
	return pages
}

// SetRole and DeleteRole read, of the grants, those of the role they change under a generic plan
// too, where role = ANY(ids) is a skip scan of the key index across the tenant's every grant.
func TestChangingARoleUnderAGenericPlanReadsOnlyItsGrants(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.as(t, "u")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.r', '{cluster:view}', '{cluster}'), ('t1', 'custom.other', '{cluster:view}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.r", rbac.User, "u"))
	// Others hold the other custom role on a cluster each.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', id, 'user', id, 'custom.other' FROM others`, "rbac_grants")
	}
	changes := changingRoles(ctx, admin)
	others(500)
	few := map[string]int64{}
	for what, change := range changes {
		few[what] = pagesChanging(ctx, t, h, change, "rbac_grants")["rbac_grants"]
	}
	others(4500)
	for what, change := range changes {
		if many := pagesChanging(ctx, t, h, change, "rbac_grants")["rbac_grants"]; many > few[what]*3/2+deeper {
			t.Errorf("%s a role read %d pages of grants beside 500 grants of another custom role, and %d beside 5000", what, few[what], many)
		}
	}
}

// SetRole and DeleteRole of a role granted somewhere read, of the denies, only those naming the
// actor, for whether one below the tenant binds it, under a generic plan and planned for their
// arguments alike: no btree finds a key in an array, so they read every deny in the tenant.
func TestChangingARoleReadsOnlyTheDeniesNamingTheActor(t *testing.T) {
	for _, plan := range []string{"generic", "custom"} {
		t.Run(plan, func(t *testing.T) {
			h := crowded(t, pgtest.Open(t, "plan_cache_mode=force_"+plan+"_plan"))
			ctx := t.Context()
			admin := roleAdmin(t, h)
			h.as(t, "u")
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.r', '{cluster:view}', '{cluster}')`); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(cluster.Scope(), "custom.r", rbac.User, "u"))
			// Others are denied root on a cluster each.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{cluster:root}' FROM others`, "rbac_denies")
			}
			changes := changingRoles(ctx, admin)
			others(500)
			few := map[string]int64{}
			for what, change := range changes {
				few[what] = pagesChanging(ctx, t, h, change, "rbac_denies")["rbac_denies"]
			}
			others(4500)
			for what, change := range changes {
				if many := pagesChanging(ctx, t, h, change, "rbac_denies")["rbac_denies"]; many > few[what]*3/2+deeper {
					t.Errorf("%s a role read %d pages of denies beside 500 denying others, and %d beside 5000", what, few[what], many)
				}
			}
		})
	}
}

// listing is a custom role x defines whose holders may grant r on clusters without holding it.
func listing(t *testing.T, h *harness, x rbac.Subject, r rbac.RoleDefinition) rbac.RoleDefinition {
	t.Helper()
	l := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{r.ID}}
	if err := h.authz.SetRole(t.Context(), x, "t1", l); err != nil {
		t.Fatal(err)
	}
	return l
}

// A role granted under a workspace that lists r lets its holders grant r there without holding it,
// so widening r hands on there what r will give, as granting r there would: a deny on the
// workspace that removes it from x, or x's power to change grants there, stops it.
func TestADenyBelowTheTenantStopsARedefinitionHandedOnByARoleListingIt(t *testing.T) {
	for name, removed := range map[string]rbac.Permission{"root": root, "the power to change grants": grantC} {
		t.Run(name, func(t *testing.T) {
			h, guardian := guarded(t)
			ctx := t.Context()
			x, r := definer(t, h)
			l := listing(t, h, x, r)
			y, z := h.as(t, "y"), h.as(t, "z")
			h.seed(t, grant(workspace.Scope(), l.ID, rbac.User, "y"))
			if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "d", Permissions: []rbac.Permission{removed}, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if applied := h.authz.Apply(ctx, y, cluster, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: z.Principal}}}); applied != nil {
				t.Fatal(applied)
			}
			if !errors.Is(err, rbac.ErrDenied) || allowed(t, h, z, root, cluster) {
				t.Fatalf("widening a role that one granted under the deny lists: %v", err)
			}
		})
	}
	// Listed by a role granted where no deny binds x, it is widened.
	h, guardian := guarded(t)
	ctx := t.Context()
	x, r := definer(t, h)
	l := listing(t, h, x, r)
	h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c2"}, l.ID, rbac.User, "y"))
	if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "d", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	r.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, x, "t1", r); err != nil {
		t.Fatalf("widening a role listed only outside the deny: %v", err)
	}
}

// What SetRole checked of the scopes a role listing the one it redefines is granted on it checks
// again under the tenant's lock, so a deny set there meanwhile stops it.
func TestADenySetWhileARedefinitionHandedOnByARoleListingItWaitsStopsIt(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	x, r := definer(t, h)
	l := listing(t, h, x, r)
	h.seed(t, grant(workspace.Scope(), l.ID, rbac.User, "y"))
	// The deny is set in a transaction that holds the tenant until it commits.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
		t.Fatal(err)
	}
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	done := make(chan error, 1)
	go func() { done <- h.authz.SetRole(ctx, x, "t1", wider) }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("widening a role that one granted under the workspace lists while a deny is set there: %v", err)
	}
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("tried again: %v", err)
	}
}

// A role listing one that lists r lets its holders grant that one, whose holders may then grant r,
// so widening r hands on through it too, wherever it is granted: a deny there that removes from x
// what r will give stops it.
func TestADenyBelowTheTenantStopsARedefinitionHandedOnThroughARoleListingOneListingIt(t *testing.T) {
	for _, on := range []rbac.Scope{workspace.Scope(), {Type: "cluster", ID: "c2"}} {
		t.Run(on.Key(), func(t *testing.T) {
			h, guardian := guarded(t)
			ctx := t.Context()
			x, r := definer(t, h)
			l := listing(t, h, x, r)
			outer := rbac.RoleDefinition{ID: "custom.outer", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{l.ID}}
			if err := h.authz.SetRole(ctx, x, "t1", outer); err != nil {
				t.Fatal(err)
			}
			y, z, w := h.as(t, "y"), h.as(t, "z"), h.as(t, "w")
			h.seed(t, grant(on, outer.ID, rbac.User, "y"))
			if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{ID: "no-root", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if on != workspace.Scope() {
				if err != nil {
					t.Fatalf("widening a role listed through one granted only outside the deny: %v", err)
				}
				return
			}
			for _, c := range []struct {
				by   rbac.Subject
				role rbac.Role
				to   rbac.Principal
			}{{y, l.ID, z.Principal}, {z, r.ID, w.Principal}} {
				if applied := h.authz.Apply(ctx, c.by, cluster, rbac.Change{Grant: []rbac.Binding{{Role: c.role, Principal: c.to}}}); applied != nil {
					t.Fatal(applied)
				}
			}
			if !errors.Is(err, rbac.ErrDenied) || allowed(t, h, w, root, cluster) {
				t.Fatalf("widening a role listed by one that a role granted under the deny lists: %v", err)
			}
		})
	}
}

// removedInW1 configures a constraint removing p from x on workspace w1 and the resources under it,
// as one telling containers apart does, and asked of no resource, as one that may remove it on any
// does: asked of the tenant, which has no ancestors, it removes nothing. It tells asked of each
// question first, where set, and fails with what that returns.
func removedInW1(p rbac.Permission, asked func(context.Context, rbac.ConstraintInput) error) func(*rbac.Config) {
	return func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "x-in-w1", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if asked != nil {
				if err := asked(ctx, in); err != nil {
					return false, err
				}
			}
			if in.Permission != p || in.Subject == nil || in.Subject.Principal.ID != "x" {
				return false, nil
			}
			r := in.Resource
			return r == nil || r.Scope() == workspace.Scope() || slices.Contains(r.Ancestors, workspace.Scope()), nil
		}}}
	}
}

// removedInW1Alone is removedInW1 written for resources alone, as one guarding against a nil
// Resource is: asked of no resource, it removes nothing, though ConstraintInput asks it to answer
// true there.
func removedInW1Alone(p rbac.Permission) func(*rbac.Config) {
	return func(c *rbac.Config) {
		removedInW1(p, nil)(c)
		removes := c.Constraints[0].Deny
		c.Constraints[0].Deny = func(ctx context.Context, q rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Resource == nil {
				return false, nil
			}
			return removes(ctx, q, in)
		}
	}
}

// removalsInW1 are removedInW1 and removedInW1Alone of p, by how each answers of no resource.
func removalsInW1(p rbac.Permission) []struct {
	name      string
	configure func(*rbac.Config)
} {
	return []struct {
		name      string
		configure func(*rbac.Config)
	}{{"answering for any resource", removedInW1(p, nil)}, {"written for resources alone", removedInW1Alone(p)}}
}

// A constraint removing root from x in w1, though not asked of the tenant above it, keeps x from
// handing root on there, as Apply granting it there; so it stops x widening a role granted there to
// give root, which hands root on there just the same, as a deny there does, however it answers of no
// resource, as Apply never asks it so. Granted only where the constraint removes nothing, the role is
// widened.
func TestAConstraintOnAScopeStopsARedefinitionHandingOnWhatItRemovesThere(t *testing.T) {
	for _, removal := range removalsInW1(root) {
		for _, on := range []rbac.Resource{cluster, {Tenant: "t1", Type: "cluster", ID: "c2"}} {
			t.Run(removal.name+"/"+on.ID, func(t *testing.T) {
				h := setup(t, removal.configure)
				ctx := t.Context()
				x, r := definer(t, h)
				y := h.as(t, "y")
				h.seed(t, grant(on.Scope(), r.ID, rbac.User, "y"))
				if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: y.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
					t.Fatalf("granting root in w1: %v", err)
				}
				wider := r
				wider.Permissions = []rbac.Permission{view, root}
				err := h.authz.SetRole(ctx, x, "t1", wider)
				if on.ID != cluster.ID {
					if err != nil || !allowed(t, h, y, root, on) {
						t.Fatalf("widening a role granted only outside w1 to give root: %v", err)
					}
					return
				}
				var denied *rbac.DeniedError
				if !errors.As(err, &denied) || denied.Permission != root || denied.Scope != cluster.Scope() || !strings.Contains(denied.Reason, "x-in-w1") ||
					allowed(t, h, y, root, cluster) {
					t.Fatalf("widening a role granted in w1 to give root: %v", err)
				}
			})
		}
	}
}

// A role granted in w1 that lists r lets its holders grant r there without holding it, so widening r
// hands on there what r will give: the constraint removing root from x in w1 stops it, however it
// answers of no resource. Listed by a role granted only outside w1, r is widened, and handed on
// there.
func TestAConstraintOnAScopeStopsARedefinitionHandedOnByARoleListingIt(t *testing.T) {
	for _, removal := range removalsInW1(root) {
		for _, on := range []rbac.Resource{cluster, {Tenant: "t1", Type: "cluster", ID: "c2"}} {
			t.Run(removal.name+"/"+on.ID, func(t *testing.T) {
				h := setup(t, removal.configure)
				ctx := t.Context()
				x, r := definer(t, h)
				l := listing(t, h, x, r)
				y, z := h.as(t, "y"), h.as(t, "z")
				h.seed(t, grant(on.Scope(), l.ID, rbac.User, "y"))
				wider := r
				wider.Permissions = []rbac.Permission{view, root}
				err := h.authz.SetRole(ctx, x, "t1", wider)
				if applied := h.authz.Apply(ctx, y, on, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: z.Principal}}}); applied != nil {
					t.Fatal(applied)
				}
				if on.ID != cluster.ID {
					if err != nil || !allowed(t, h, z, root, on) {
						t.Fatalf("widening a role listed only outside w1 to give root: %v", err)
					}
					return
				}
				var denied *rbac.DeniedError
				if !errors.As(err, &denied) || denied.Permission != root || denied.Scope != cluster.Scope() || allowed(t, h, z, root, cluster) {
					t.Fatalf("widening a role that one granted in w1 lists to give root: %v", err)
				}
			})
		}
	}
}

// A grant to the tenant's members of a privileged role gives nothing, so narrowing the role so that
// it no longer is hands on to them what it gives where they hold it: a constraint removing view
// from x in w1, where they do, stops it, as it stops Apply granting them view there, however it
// answers of no resource. Held by them only outside w1, the role is narrowed.
func TestAConstraintWhereTheMembersHoldARoleNoLongerPrivilegedStopsNarrowingIt(t *testing.T) {
	for _, removal := range removalsInW1(view) {
		for _, on := range []rbac.Scope{workspace.Scope(), {Type: "cluster", ID: "c2"}} {
			t.Run(removal.name+"/"+on.Key(), func(t *testing.T) {
				h := setup(t, removal.configure)
				ctx := t.Context()
				x, r := definer(t, h)
				member := h.as(t, "m")
				// Privileged, as it gives root, and granted to the members, as a catalog change would leave it.
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.op', '{cluster:view,cluster:root}', '{cluster}')`); err != nil {
					t.Fatal(err)
				}
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				VALUES ('t1', $1, $2, 'members', 't1', 'custom.op')`, on.Type, on.ID); err != nil {
					t.Fatal(err)
				}
				if err := h.authz.Apply(ctx, x, workspace, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: rbac.TenantMembers("t1")}}}); !errors.Is(err, rbac.ErrDenied) {
					t.Fatalf("granting the members view in w1: %v", err)
				}
				narrowed := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
				err := h.authz.SetRole(ctx, x, "t1", narrowed)
				if on != workspace.Scope() {
					if err != nil || !allowed(t, h, member, view, rbac.Resource{Tenant: "t1", Type: on.Type, ID: on.ID}) {
						t.Fatalf("narrowing a role the members hold only outside w1: %v", err)
					}
					return
				}
				var denied *rbac.DeniedError
				if !errors.As(err, &denied) || denied.Permission != view || denied.Scope != workspace.Scope() || allowed(t, h, member, view, cluster) {
					t.Fatalf("narrowing a role the members hold in w1 so that it is no longer privileged: %v", err)
				}
			})
		}
	}
}

// A role listing r, granted on w1, hands r on there only where its grant gives its holders the
// power to grant r: by a `<type>:grant` it gives for that type, on scopes of the type w1 reaches. So
// one for clusters that gives workspace:grant too lets its holders grant r on the clusters in w1, but
// on no workspace, and a constraint freezing workspaces in w1 doesn't stop widening r, as it doesn't
// stop Apply granting r on a cluster there; nor does one removing root from x in w1 stop widening r
// to give root where the role listing it gives tenant:grant, as nothing in w1 is a tenant.
func TestARoleListingARedefinitionWhereItHandsNothingOnDoesntStopIt(t *testing.T) {
	for _, c := range []struct {
		name      string
		lister    rbac.RoleDefinition
		configure func(*rbac.Config)
		// onC1 is whether its holders may grant r on c1.
		onC1 bool
	}{
		{"a power it gives for another type", rbac.RoleDefinition{Permissions: []rbac.Permission{grantC, "workspace:grant"}, ResourceTypes: []string{"cluster"}}, removedInW1Alone("workspace:grant"), true},
		{"a tenant from a workspace", rbac.RoleDefinition{Permissions: []rbac.Permission{"tenant:grant"}, ResourceTypes: []string{rbac.TenantScope}}, removedInW1Alone(root), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := setup(t, c.configure)
			ctx := t.Context()
			x, r := definer(t, h)
			y, z := h.as(t, "y"), h.as(t, "z")
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', 'custom.lister', $1, $2, $3)`,
				c.lister.Permissions, c.lister.ResourceTypes, []string{string(r.ID)}); err != nil {
				t.Fatal(err)
			}
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "tenant.admin", rbac.User, "x"), grant(tenant, "workspace.admin", rbac.User, "x"), grant(workspace.Scope(), "custom.lister", rbac.User, "y"))
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			if err := h.authz.SetRole(ctx, x, "t1", wider); err != nil {
				t.Fatalf("widening a role that one granted on w1 lists where its holders may grant it on no scope the constraint names: %v", err)
			}
			for _, on := range []rbac.Resource{workspace, cluster} {
				err := h.authz.Apply(ctx, y, on, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: z.Principal}}})
				if want := on.ID == cluster.ID && c.onC1; (err == nil) != want || err != nil && !errors.Is(err, rbac.ErrDenied) {
					t.Errorf("y granting it on %s: %v", on.ID, err)
				}
			}
		})
	}
}

// What the constraints answered before SetRole's transaction it reads back under the tenant's lock,
// so a role listing the one it widens, granted in w1 while the change waited, which they weren't
// asked about, refuses it, to be tried again, and then the constraint removing root from x in w1
// stops it: whether they were asked about each scope the role gives more on, as where it is granted
// outside w1, or about none, as where it gives more nowhere.
func TestARoleListingARedefinitionGrantedMeanwhileWhereAConstraintRemovesWhatItGivesIsTriedAgain(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprintf("granted outside w1 %t", before), func(t *testing.T) {
			var meanwhile func(context.Context) error
			// The freezes are asked after the scopes the change reaches are read, and before the
			// constraints are asked about them.
			h := setup(t, removedInW1(root, func(ctx context.Context, in rbac.ConstraintInput) error {
				if do := meanwhile; do != nil && in.Permission == "workspace:grant" {
					meanwhile = nil
					return do(ctx)
				}
				return nil
			}))
			ctx := t.Context()
			x, r := definer(t, h)
			l := listing(t, h, x, r)
			z, w := h.as(t, "z"), h.as(t, "w")
			if before {
				h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "c2"}, r.ID, rbac.User, "y"))
			}
			meanwhile = func(ctx context.Context) error {
				return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), l.ID, rbac.User, "z")})
			}
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("widening a role that one granted in w1 while the change waited lists: %v", err)
			}
			if meanwhile != nil {
				t.Fatal("the role listing it should have been granted in w1 meanwhile")
			}
			if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("tried again: %v", err)
			}
			if applied := h.authz.Apply(ctx, z, cluster, rbac.Change{Grant: []rbac.Binding{{Role: r.ID, Principal: w.Principal}}}); applied != nil {
				t.Fatal(applied)
			}
			if allowed(t, h, w, root, cluster) {
				t.Fatal("root was handed on in w1 through the role listing it")
			}
		})
	}
}

// Without Config.ResourceOf, a scope a redefinition gives more on whose containers the host doesn't
// store is asked of no resource, so a constraint that may remove what it hands on on any of them, as
// one removing root from x in w1 answers there, stops widening the role to give it wherever the role
// is granted; widening it by what the constraint removes nowhere it doesn't stop.
func TestWithoutResourceOfAConstraintThatMayRemoveWhatARedefinitionHandsOnAnywhereStopsIt(t *testing.T) {
	h := setup(t, removedInW1(root, nil), func(c *rbac.Config) { c.ResourceOf = nil })
	ctx := t.Context()
	x, r := definer(t, h)
	y := h.as(t, "y")
	elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c2"}
	h.seed(t, grant(elsewhere.Scope(), r.ID, rbac.User, "y"))
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	var denied *rbac.DeniedError
	if err := h.authz.SetRole(ctx, x, "t1", wider); !errors.As(err, &denied) || denied.Permission != root || allowed(t, h, y, root, elsewhere) {
		t.Fatalf("widening a role to give root with no scope told apart: %v", err)
	}
	wider.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, x, "t1", wider); err != nil || !allowed(t, h, y, login, elsewhere) {
		t.Fatalf("widening it to give login: %v", err)
	}
}

// A redefinition asks the host about each scope it gives more on once, however many grants of the
// role and of roles listing it are there: Config.ResourceOf, and the constraints about each
// permission it hands on there, whose answers it reads back under the tenant's lock. It asks about
// the scopes whatever the constraints would answer of no resource, which it never asks them about
// what it hands on.
func TestARedefinitionAsksTheHostAboutEachScopeItGivesMoreOnOnce(t *testing.T) {
	resolved := map[rbac.Scope]int{}
	asked := map[string]int{}
	var anywhere []rbac.Permission
	h := setup(t, removedInW1(root, func(_ context.Context, in rbac.ConstraintInput) error {
		switch {
		case in.Resource != nil:
			asked[fmt.Sprintf("%s %s %s", in.Resource.Scope().Key(), in.Permission, in.ResourceType)]++
		case in.Permission == root || in.Permission == login:
			anywhere = append(anywhere, in.Permission)
		}
		return nil
	}), func(c *rbac.Config) {
		of := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			resolved[s]++
			return of(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	x, r := definer(t, h)
	l := listing(t, h, x, r)
	other := rbac.RoleDefinition{ID: "custom.other", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, x, "t1", other); err != nil {
		t.Fatal(err)
	}
	scopes := []rbac.Scope{{Type: "cluster", ID: "c2"}, {Type: "cluster", ID: "c3"}, {Type: "org", ID: "o2"}}
	var grants []rbac.Grant
	for _, s := range scopes {
		for _, p := range []string{"y", "z"} {
			h.as(t, p)
			grants = append(grants, grant(s, r.ID, rbac.User, p), grant(s, other.ID, rbac.User, p))
		}
	}
	h.as(t, "w")
	h.seed(t, append(grants, grant(scopes[0], l.ID, rbac.User, "w"))...)
	clear(resolved)
	clear(asked)
	wider := r
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.SetRole(ctx, x, "t1", wider); err != nil {
		t.Fatal(err)
	}
	for _, s := range scopes {
		if k := s.Key() + " " + string(root) + " cluster"; resolved[s] != 1 || asked[k] != 1 {
			t.Errorf("%s: Config.ResourceOf asked %d times, the constraint about root %d", s.Key(), resolved[s], asked[k])
		}
	}
	if len(resolved) != len(scopes) {
		t.Errorf("Config.ResourceOf asked about %v", resolved)
	}
	for k, n := range asked {
		if n > 1 {
			t.Errorf("the constraint was asked about %s %d times", k, n)
		}
	}
	clear(resolved)
	clear(asked)
	other.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, x, "t1", other); err != nil {
		t.Fatal(err)
	}
	for _, s := range scopes {
		if k := s.Key() + " " + string(login) + " cluster"; resolved[s] != 1 || asked[k] != 1 {
			t.Errorf("widened by what the constraint removes nowhere, %s: Config.ResourceOf asked %d times, the constraint about login %d", s.Key(), resolved[s], asked[k])
		}
	}
	if len(anywhere) > 0 {
		t.Errorf("the constraint was asked of no resource about %v", anywhere)
	}
}

// Without Config.ResourceOf, a scope stored whole, as where the host has no containers and its
// resources no attributes, is what Apply is given there: so a redefinition asks the constraints about
// it, not of no resource, and one telling resources apart by id stops widening a role granted on c1
// to give root, as it stops Apply granting root there, though it removes nothing of no resource.
func TestWithoutResourceOfAConstraintIsAskedAboutAScopeStoredWhole(t *testing.T) {
	c1 := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c1"}
	for _, on := range []rbac.Resource{c1, {Tenant: "t1", Type: "cluster", ID: "c2"}} {
		t.Run(on.ID, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) {
				c.ResourceOf, c.ContainerTypes, c.Attributes = nil, nil, rbac.Attributes{Resource: map[string]rbac.AttributeType{}}
				c.Constraints = []rbac.Constraint{{Name: "x-on-c1", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					return in.Permission == root && in.Subject != nil && in.Subject.Principal.ID == "x" && in.Resource != nil && in.Resource.Scope() == c1.Scope(), nil
				}}}
			})
			ctx := t.Context()
			x, r := definer(t, h)
			y := h.as(t, "y")
			if err := h.authz.Apply(ctx, x, c1, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: y.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("granting root on c1: %v", err)
			}
			h.seed(t, grant(on.Scope(), r.ID, rbac.User, "y"))
			wider := r
			wider.Permissions = []rbac.Permission{view, root}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if on.ID != c1.ID {
				if err != nil || !allowed(t, h, y, root, on) {
					t.Fatalf("widening a role granted only on c2 to give root: %v", err)
				}
				return
			}
			var denied *rbac.DeniedError
			if !errors.As(err, &denied) || denied.Permission != root || denied.Scope != c1.Scope() || allowed(t, h, y, root, c1) {
				t.Fatalf("widening a role granted on c1 to give root: %v", err)
			}
		})
	}
}

// On a resource, Apply decides a role for the resource's type alone, so a `<type>:grant` the role
// gives of another of its types is a permission like any other there, which a constraint can remove
// for that type: widening a role granted on c1 to give workspace:grant hands it on there, so a
// constraint removing it from x for clusters in w1 stops it, as it stops Apply granting the role
// there, though x may change grants on workspaces. Granted only on c2, outside w1, it is widened.
func TestAConstraintOnAResourceStopsARedefinitionHandingOnAPowerOfAnotherTypeThere(t *testing.T) {
	const grantW rbac.Permission = "workspace:grant"
	for _, on := range []rbac.Resource{cluster, {Tenant: "t1", Type: "cluster", ID: "c2"}} {
		t.Run(on.ID, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) {
				c.Constraints = []rbac.Constraint{{Name: "x-grant-w-on-clusters-in-w1", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if in.Permission != grantW || in.ResourceType != "cluster" || in.Subject == nil || in.Subject.Principal.ID != "x" {
						return false, nil
					}
					r := in.Resource
					return r == nil || r.Scope() == workspace.Scope() || slices.Contains(r.Ancestors, workspace.Scope()), nil
				}}}
			})
			ctx := t.Context()
			x, r := definer(t, h)
			y, z := h.as(t, "y"), h.as(t, "z")
			// x may change grants on workspaces, and holds workspace:grant on clusters too, as the wider role gives it.
			wider := rbac.RoleDefinition{ID: r.ID, Permissions: []rbac.Permission{view, grantW}, ResourceTypes: []string{"cluster", "workspace"}}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, privileged) VALUES ('t1', 'custom.both', $1, $2, true)`,
				wider.Permissions, wider.ResourceTypes); err != nil {
				t.Fatal(err)
			}
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "workspace.admin", rbac.User, "x"), grant(tenant, "custom.both", rbac.User, "x"), grant(on.Scope(), r.ID, rbac.User, "y"))
			if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "custom.both", Principal: z.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("granting workspace:grant on c1: %v", err)
			}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if on.ID != cluster.ID {
				if err != nil || !allowed(t, h, y, grantW, on) {
					t.Fatalf("widening a role granted only outside w1 to give workspace:grant: %v", err)
				}
				return
			}
			var denied *rbac.DeniedError
			if !errors.As(err, &denied) || denied.Permission != grantW || denied.Scope != cluster.Scope() || !strings.Contains(denied.Reason, "x-grant-w-on-clusters-in-w1") ||
				allowed(t, h, y, grantW, cluster) {
				t.Fatalf("widening a role granted on c1 to give workspace:grant: %v", err)
			}
		})
	}
}

// A grant on a resource gives what its role gives for that resource's type alone, and Apply asks the
// constraints so: a role for clusters and workspaces granted on c1, widened to give workspace:view,
// hands nothing more on there for workspaces, so a constraint removing workspace:view from x for
// workspaces in w1 doesn't stop it, as it doesn't stop Apply granting the role as it will be on c1.
// Granted on w1, which reaches workspaces, it is stopped, as Apply there is.
func TestAConstraintOnAnotherTypeDoesntStopARedefinitionGrantedOnAResource(t *testing.T) {
	const viewW rbac.Permission = "workspace:view"
	for _, on := range []rbac.Resource{cluster, workspace} {
		t.Run(on.ID, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) {
				c.Constraints = []rbac.Constraint{{Name: "x-view-workspaces-in-w1", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if in.Permission != viewW || in.ResourceType != "workspace" || in.Subject == nil || in.Subject.Principal.ID != "x" {
						return false, nil
					}
					r := in.Resource
					return r == nil || r.Scope() == workspace.Scope() || slices.Contains(r.Ancestors, workspace.Scope()), nil
				}}}
			})
			ctx := t.Context()
			x, _ := definer(t, h)
			y, z := h.as(t, "y"), h.as(t, "z")
			r := rbac.RoleDefinition{ID: "custom.both", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster", "workspace"}}
			wider := rbac.RoleDefinition{ID: r.ID, Permissions: []rbac.Permission{view, viewW}, ResourceTypes: r.ResourceTypes}
			// x holds what the wider role gives for both its types, and may change grants on workspaces.
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.all', $1, $2)`,
				wider.Permissions, wider.ResourceTypes); err != nil {
				t.Fatal(err)
			}
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "custom.all", rbac.User, "x"), grant(tenant, "workspace.admin", rbac.User, "x"))
			if err := h.authz.SetRole(ctx, x, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(on.Scope(), r.ID, rbac.User, "y"))
			applied := h.authz.Apply(ctx, x, on, rbac.Change{Grant: []rbac.Binding{{Role: "custom.all", Principal: z.Principal}}})
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if on.ID == cluster.ID {
				if applied != nil || err != nil || !allowed(t, h, y, view, cluster) {
					t.Fatalf("widening a role granted on c1 by what it gives for workspaces: Apply %v, SetRole %v", applied, err)
				}
				return
			}
			var denied *rbac.DeniedError
			if !errors.Is(applied, rbac.ErrDenied) || !errors.As(err, &denied) || denied.Permission != viewW || denied.Scope != workspace.Scope() ||
				!strings.Contains(denied.Reason, "x-view-workspaces-in-w1") || allowed(t, h, y, viewW, workspace) {
				t.Fatalf("widening a role granted on w1 to give workspace:view: Apply %v, SetRole %v", applied, err)
			}
		})
	}
}

// A constraint freezing changes to grants in w1, though written for resources alone, which asked of
// no resource stops nothing, stops x widening a role granted there, which changes what grants there
// give, as it stops Apply changing grants there. Granted only outside w1, the role is widened.
func TestAFreezeOnAScopeStopsARedefinitionGivingMoreThere(t *testing.T) {
	for _, on := range []rbac.Resource{cluster, {Tenant: "t1", Type: "cluster", ID: "c2"}} {
		t.Run(on.ID, func(t *testing.T) {
			h := setup(t, removedInW1Alone(grantC))
			ctx := t.Context()
			x, r := definer(t, h)
			y, z := h.as(t, "y"), h.as(t, "z")
			if err := h.authz.Apply(ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: z.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("granting in w1: %v", err)
			}
			h.seed(t, grant(on.Scope(), r.ID, rbac.User, "y"))
			wider := r
			wider.Permissions = []rbac.Permission{view, login}
			err := h.authz.SetRole(ctx, x, "t1", wider)
			if on.ID != cluster.ID {
				if err != nil || !allowed(t, h, y, login, on) {
					t.Fatalf("widening a role granted only outside w1: %v", err)
				}
				return
			}
			var denied *rbac.DeniedError
			if !errors.As(err, &denied) || denied.Permission != grantC || denied.Scope != cluster.Scope() || !strings.Contains(denied.Reason, "x-in-w1") ||
				allowed(t, h, y, login, cluster) {
				t.Fatalf("widening a role granted in w1: %v", err)
			}
		})
	}
}

func TestExplainNamesTheDenyAuthorizeDoes(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	d := func(id string) rbac.Deny {
		return rbac.Deny{ID: id, Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	}
	if err := h.authz.SetDeny(ctx, guardian, rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, d("a")); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d("z")); err != nil {
		t.Fatal(err)
	}
	// The anonymous subject too, whom no grant can give root, and an identity that isn't a member.
	for _, s := range []rbac.Subject{h.as(t, "owner"), {}, {Principal: rbac.Principal{Kind: rbac.User, ID: "stranger"}}} {
		err := h.authz.Authorize(ctx, s, root, cluster)
		dec, xerr := h.authz.Explain(ctx, s, root, cluster)
		var denied *rbac.DeniedError
		if xerr != nil || !errors.As(err, &denied) || denied.Reason != dec.Reason {
			t.Fatalf("%v: Authorize: %v; Explain: %+v, %v", s.Principal, err, dec, xerr)
		}
		if strings.Contains(err.Error(), "deny") || strings.Contains(err.Error(), "tenant:t1") {
			t.Fatalf("a refusal's message should name no policy: %v", err)
		}
	}
}

func TestSettingADenyIsChecked(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	d := rbac.Deny{ID: "d", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	for name, s := range map[string]rbac.Subject{"without the deny permission": h.as(t, "owner"), "anonymous": {}} {
		if err := h.authz.SetDeny(ctx, s, cluster, d); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]rbac.Deny{
		"a malformed id":         {ID: "Not Valid", Permissions: d.Permissions, Principals: d.Principals},
		"no principals":          {ID: "d", Permissions: d.Permissions},
		"no permissions":         {ID: "d", Principals: d.Principals},
		"a malformed permission": {ID: "d", Permissions: []rbac.Permission{"root"}, Principals: d.Principals},
		"a malformed principal":  {ID: "d", Permissions: d.Permissions, Principals: []rbac.Principal{{Kind: rbac.User}}},
		"a broken condition":     {ID: "d", Permissions: d.Permissions, Principals: d.Principals, Condition: rbac.Condition{Expression: "1 +"}},
		"a condition with a NUL": {ID: "d", Permissions: d.Permissions, Principals: d.Principals, Condition: rbac.Condition{Expression: "request.attributes.x == \"a\x00b\""}},
		"the deny permission":    {ID: "d", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, Principals: d.Principals},
	} {
		if err := h.authz.SetDeny(ctx, guardian, cluster, bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}} {
		if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: rbac.TenantRoot("t1"), Binding: rbac.Binding{Role: "guard", Principal: p}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("letting %s set denies: %v", p.Kind, err)
		}
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		SELECT 't1', 'cluster', 'c1', 'filler' || i, '{public:}', '{cluster:root}' FROM generate_series(1, 100) AS i`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a scope's 101st deny: %v", err)
	}
}

func TestADenyCantExemptEveryoneItNames(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	named := rbac.Principal{Kind: rbac.User, ID: "named"}
	h.seed(t,
		grant(cluster.Scope(), "cluster.login", rbac.User, "named"),
		grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"),
	)
	public, members := rbac.Principal{Kind: rbac.Public}, rbac.TenantMembers("t1")
	// Every subject is the public and every member the tenant's members, so these would bind no one.
	for name, d := range map[string]rbac.Deny{
		"the public exempt":                    {Principals: []rbac.Principal{named}, Exempt: []rbac.Principal{public}},
		"the public exempt from itself":        {Principals: []rbac.Principal{public}, Exempt: []rbac.Principal{public}},
		"members exempt from a deny on others": {Principals: []rbac.Principal{named}, Exempt: []rbac.Principal{members}},
		"members exempt from itself":           {Principals: []rbac.Principal{members}, Exempt: []rbac.Principal{members}},
		"one both named and exempt":            {Principals: []rbac.Principal{named}, Exempt: []rbac.Principal{named}},
	} {
		d.ID, d.Permissions = "no-login", []rbac.Permission{login}
		if err := h.authz.SetDeny(ctx, guardian, cluster, d); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if stored, err := h.authz.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil || len(stored) > 0 {
		t.Fatalf("a deny refused should not be stored: %v, %v", stored, err)
	}
	// Anyone but the tenant's members: only those who aren't.
	d := rbac.Deny{ID: "members-only", Principals: []rbac.Principal{public}, Exempt: []rbac.Principal{members}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "visitor"))
	guest := h.guest(t, "visitor")
	if !allowed(t, h, h.as(t, "named"), login, cluster) || allowed(t, h, guest, login, cluster) {
		t.Fatal("a deny on the public exempting members should bind only those who aren't members")
	}
	listingsAgree(t, h, resources, h.as(t, "named"), login)
	listingsAgree(t, h, resources, guest, login)
	// The grant to the members, exempt, gives it.
	if holders, err := h.authz.Holders(ctx, login, cluster); err != nil || !slices.Contains(holderPrincipals(holders), members) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

func TestNotesOnGrants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, Note: "INC-42: debugging the scheduler"}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	b.Note = "INC-43"
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || h.events[0].Granted[0].Note != "INC-43" {
		t.Fatalf("a new note should be reported: %+v", h.events)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 1 || got[0].Note != "INC-43" {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
	for _, note := range []string{strings.Repeat("n", 2049), "a\x00b", "\xff"} {
		bad := b
		bad.Note = note
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{bad}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a note %q: %v", note[:min(len(note), 8)], err)
		}
	}
}

// An eligibility's MaxDuration is in whole seconds, rounded down, and bounded as it is stored: a
// year and a fraction of a second is a year, which was refused as longer, and less than a second is
// none.
func TestAnEligibilitysLongestActivationIsBoundedAsStored(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	set := func(i int, d time.Duration) error {
		return h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.login", Principal: h.as(t, fmt.Sprint("e", i)).Principal, MaxDuration: d})
	}
	for i, c := range []struct{ d, stored time.Duration }{
		{rbac.MaxActivation, rbac.MaxActivation},
		{rbac.MaxActivation + 999*time.Millisecond, rbac.MaxActivation},
		{1500 * time.Millisecond, time.Second},
	} {
		h.events = nil
		if err := set(i, c.d); err != nil || len(h.events) != 1 || h.events[0].Eligible[0].MaxDuration != c.stored {
			t.Errorf("an eligibility for %v: %v, events %+v", c.d, err, h.events)
		}
	}
	for i, d := range []time.Duration{999 * time.Millisecond, rbac.MaxActivation + time.Second, -1500 * time.Millisecond} {
		if err := set(10+i, d); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("an eligibility for %v: %v", d, err)
		}
	}
}

func TestEligibleGrants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	oncall := rbac.Eligibility{
		Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.Group, ID: "oncall"}, MaxDuration: time.Hour,
		Requires: `request.attributes.mfa == true`, Note: "on call",
	}
	h.groups(t, "oncall")
	h.events = nil
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, oncall); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Eligible) != 1 || h.events[0].Eligible[0].MaxDuration != time.Hour {
		t.Fatalf("events = %+v", h.events)
	}
	pager := h.as(t, "pager", "oncall")
	if allowed(t, h, pager, root, cluster) {
		t.Fatal("an eligibility should give nothing until activated")
	}
	mfa := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	for name, c := range map[string]struct {
		ctx  context.Context
		s    rbac.Subject
		on   rbac.Resource
		role rbac.Role
		d    time.Duration
		why  string
		want error
	}{
		"no justification":         {mfa, pager, cluster, "cluster.sudo", 30 * time.Minute, "", rbac.ErrInvalid},
		"longer than it may":       {mfa, pager, cluster, "cluster.sudo", 2 * time.Hour, "x", rbac.ErrDenied},
		"longer than a year":       {mfa, pager, cluster, "cluster.sudo", 367 * 24 * time.Hour, "x", rbac.ErrInvalid},
		"as long as time allows":   {mfa, pager, cluster, "cluster.sudo", time.Duration(1<<63 - 1), "x", rbac.ErrInvalid},
		"without what it requires": {ctx, pager, cluster, "cluster.sudo", 30 * time.Minute, "x", rbac.ErrDenied},
		"not eligible":             {mfa, h.as(t, "other"), cluster, "cluster.sudo", 30 * time.Minute, "x", rbac.ErrDenied},
		"outside the group":        {mfa, h.as(t, "colleague", "day-shift"), cluster, "cluster.sudo", 30 * time.Minute, "x", rbac.ErrDenied},
		"another role":             {mfa, pager, cluster, "cluster.admin", 30 * time.Minute, "x", rbac.ErrDenied},
		"another scope":            {mfa, pager, workspace, "cluster.sudo", 30 * time.Minute, "x", rbac.ErrDenied},
		"a member the tenant refuses": {
			mfa, h.as(t, "outsider", "oncall"), cluster, "cluster.sudo", 30 * time.Minute, "x", rbac.ErrInvalid,
		},
	} {
		if _, err := h.authz.Activate(c.ctx, c.s, c.on, rbac.Activation{Role: c.role, Duration: c.d, Justification: c.why}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope(), workspace.Scope()}}); err != nil || len(got) != 1 {
		t.Fatalf("refused activations should store nothing: %+v, %v", got, err)
	}
	h.events = nil
	g, err := h.authz.Activate(mfa, pager, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 30 * time.Minute, Justification: "INC-7: disk full"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Principal != pager.Principal || g.Note != "INC-7: disk full" || !g.ExpiresAt.Equal(h.now.Add(30*time.Minute)) {
		t.Fatalf("activated %+v", g)
	}
	if g.Source != rbac.SourceActivation || g.ID == "" || g.CreatedBy != pager.Principal {
		t.Fatalf("an activation is a grant of its own, made by whoever activated: %+v", g)
	}
	if len(h.events) != 1 || len(h.events[0].Granted) != 1 || h.events[0].Granted[0].Source != rbac.SourceActivation ||
		h.events[0].Actor != pager.Principal {
		t.Fatalf("events = %+v", h.events)
	}
	if !allowed(t, h, pager, root, cluster) {
		t.Fatal("an activated role should give its permissions")
	}
	// Activating again keeps one activation, recording the request its end rests on: a shorter one
	// changes nothing and reports nothing, and a longer one replaces it.
	h.events = nil
	if g, err := h.authz.Activate(mfa, pager, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 10 * time.Minute, Justification: "again"}); err != nil ||
		!g.ExpiresAt.Equal(h.now.Add(30*time.Minute)) || g.Note != "INC-7: disk full" || len(h.events) != 0 {
		t.Fatalf("a shorter activation: %+v, %v, events %+v", g, err, h.events)
	}
	if g, err := h.authz.Activate(mfa, pager, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 45 * time.Minute, Justification: "longer"}); err != nil ||
		!g.ExpiresAt.Equal(h.now.Add(45*time.Minute)) || g.Note != "longer" {
		t.Fatalf("a longer activation: %+v, %v", g, err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{pager.Principal}}); err != nil || len(got) != 1 {
		t.Fatalf("activating again should add no grant: %+v, %v", got, err)
	}
	h.now = h.now.Add(46 * time.Minute)
	if allowed(t, h, pager, root, cluster) {
		t.Fatal("an activation should end")
	}
	// Once it has ended, activating again makes a new grant, with a new id, still one row.
	first := g
	if g, err := h.authz.Activate(mfa, pager, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 5 * time.Minute, Justification: "anew"}); err != nil ||
		!g.ExpiresAt.Equal(h.now.Add(5*time.Minute)) || g.ID == first.ID || !g.CreatedAt.After(first.CreatedAt) {
		t.Fatalf("activating once ended: %+v, %v", g, err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Revoke: []rbac.Binding{first.Binding}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, pager, root, cluster) {
		t.Fatal("revoking the ended activation by its id shouldn't end the new one")
	}
	h.now = h.now.Add(6 * time.Minute)
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || len(got) != 1 || got[0].Note != "on call" {
		t.Fatalf("Eligibilities = %+v, %v", got, err)
	}
	if err := h.authz.DeleteEligibility(ctx, h.as(t, "nobody"), cluster, "cluster.sudo", oncall.Principal); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("ending an eligibility without the power to revoke the role: %v", err)
	}
	if err := h.authz.DeleteEligibility(ctx, h.as(t, "owner"), cluster, "cluster.sudo", rbac.Principal{Kind: rbac.Group}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("ending a malformed principal's eligibility: %v", err)
	}
	if err := h.authz.DeleteEligibility(ctx, h.as(t, "owner"), cluster, "cluster.sudo", oncall.Principal); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(mfa, pager, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 30 * time.Minute, Justification: "x"}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("activating a revoked eligibility: %v", err)
	}
}

func TestSettingAnEligibilityIsChecked(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	e := rbac.Eligibility{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "nobody"), cluster, e); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("without the power to grant the role: %v", err)
	}
	for name, bad := range map[string]rbac.Eligibility{
		"the tenant's members":        {Role: e.Role, Principal: rbac.TenantMembers("t1"), MaxDuration: time.Hour},
		"the public":                  {Role: e.Role, Principal: rbac.Principal{Kind: rbac.Public}, MaxDuration: time.Hour},
		"no duration":                 {Role: e.Role, Principal: e.Principal},
		"longer than a year":          {Role: e.Role, Principal: e.Principal, MaxDuration: 400 * 24 * time.Hour},
		"a role the scope can't take": {Role: "workspace.admin", Principal: e.Principal, MaxDuration: time.Hour},
		"a broken requirement":        {Role: e.Role, Principal: e.Principal, MaxDuration: time.Hour, Requires: "1 +"},
		"a requirement with a NUL":    {Role: e.Role, Principal: e.Principal, MaxDuration: time.Hour, Requires: "true // \x00"},
		"a requirement that isn't UTF-8": {
			Role: e.Role, Principal: e.Principal, MaxDuration: time.Hour, Requires: "request.attributes.x == \"\xff\"",
		},
	} {
		if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, approvers := range map[string][]rbac.Principal{
		"too many approvers":          approvers(rbac.MaxApprovers + 1),
		"the public approves":         {{Kind: rbac.Public}},
		"a nameless approver":         {{Kind: rbac.Group}},
		"an undeclared kind approves": {{Kind: "robot", ID: "r"}},
	} {
		bad := e
		bad.Approvers = approvers
		if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A role held under a condition is activated beside it, and the conditional grant stays.
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.sudo", "x", "false")})
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "x"}); err != nil {
		t.Fatalf("activating beside a conditional grant: %v", err)
	}
	if !allowed(t, h, h.as(t, "x"), root, cluster) {
		t.Fatal("the activation should give the role where the condition doesn't")
	}
	got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{e.Principal}})
	if err != nil || len(got) != 2 || !slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.Condition.Expression == "false" }) {
		t.Fatalf("the conditional grant should stay: %+v, %v", got, err)
	}
}

// approvers is n different approvers.
func approvers(n int) []rbac.Principal {
	ps := make([]rbac.Principal, n)
	for i := range ps {
		ps[i] = rbac.Principal{Kind: rbac.User, ID: fmt.Sprintf("a%d", i)}
	}
	return ps
}

func TestActivationsNeedTheirApprovers(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	e := rbac.Eligibility{
		Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour,
		Approvers: []rbac.Principal{{Kind: rbac.Group, ID: "leads"}, {Kind: rbac.User, ID: "x"}},
	}
	h.groups(t, "leads")
	h.groups(t, "sre")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	ask := rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-9"}
	for name, approver := range map[string]rbac.Subject{
		"no approver":           {},
		"approving their own":   h.as(t, "x", "leads"),
		"not among approvers":   h.as(t, "peer", "devs"),
		"an approver's ex-team": h.as(t, "lead"),
	} {
		withApprover := ask
		withApprover.Approver = approver
		if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, withApprover); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if allowed(t, h, h.as(t, "x"), root, cluster) {
		t.Fatal("an unapproved activation should give nothing")
	}
	// An approver is a subject like any other: one of a kind the host doesn't declare can't act.
	undeclared := ask
	undeclared.Approver = rbac.Subject{Principal: rbac.Principal{Kind: "robot", ID: "r"}}
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, undeclared); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("an approver of an undeclared kind: %v", err)
	}
	ask.Approver = h.as(t, "lead", "leads")
	g, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, ask)
	if err != nil {
		t.Fatal(err)
	}
	if g.ApprovedBy != (rbac.Principal{Kind: rbac.User, ID: "lead"}) || g.CreatedBy != (rbac.Principal{Kind: rbac.User, ID: "x"}) {
		t.Fatalf("an approved activation records its approver and activator: %+v", g)
	}
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || len(got) != 1 || len(got[0].Approvers) != 2 {
		t.Fatalf("Eligibilities = %+v, %v", got, err)
	}
	// Where an eligibility needs no approval, an approver passed anyway isn't recorded, though
	// another for the role would need theirs.
	free := rbac.Eligibility{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.Group, ID: "sre"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, free); err != nil {
		t.Fatal(err)
	}
	// One that doesn't extend the approved activation leaves it as approved, its justification too.
	shorter := rbac.Activation{Role: "cluster.sudo", Duration: 30 * time.Second, Justification: "INC-9 again"}
	if g, err := h.authz.Activate(ctx, h.as(t, "x", "sre"), cluster, shorter); err != nil ||
		g.ApprovedBy != ask.Approver.Principal || g.Note != "INC-9" || !g.ExpiresAt.Equal(h.now.Add(time.Minute)) {
		t.Fatalf("an unapproved activation that doesn't extend an approved one: %+v, %v", g, err)
	}
	// One that does rests its end on its own request, which needed no approval.
	ask.Duration = 2 * time.Minute
	if g, err := h.authz.Activate(ctx, h.as(t, "x", "sre"), cluster, ask); err != nil || g.ApprovedBy != (rbac.Principal{}) {
		t.Fatalf("an activation needing no approval: %+v, %v", g, err)
	}
}

func TestDeactivating(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	e := rbac.Eligibility{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "x"), grant(workspace.Scope(), "cluster.login", rbac.User, "y"))
	for range 2 {
		if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "x"}); err != nil {
			t.Fatal(err)
		}
		h.now = h.now.Add(time.Second)
	}
	if err := h.authz.Deactivate(ctx, h.as(t, "y"), cluster, "cluster.login"); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.Deactivate(ctx, h.as(t, "x"), cluster, "cluster.login"); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Revoked) != 1 || h.events[0].Actor != h.as(t, "x").Principal {
		t.Fatalf("events = %+v", h.events)
	}
	got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{e.Principal}})
	if err != nil || len(got) != 1 || got[0].Source != "" {
		t.Fatalf("deactivating should end only the activations: %+v, %v", got, err)
	}
	if err := h.authz.Deactivate(ctx, rbac.Subject{}, cluster, "cluster.login"); err != nil {
		t.Fatalf("deactivating as no one: %v", err)
	}
}

func TestGrantsAddUp(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	scope := []rbac.Scope{cluster.Scope()}
	held := func() []rbac.Grant {
		t.Helper()
		got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: scope, Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	apply := func(c rbac.Change) {
		t.Helper()
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, c); err != nil {
			t.Fatal(err)
		}
	}
	standing := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	untilSoon := standing
	untilSoon.ExpiresAt = h.now.Add(time.Hour)
	apply(rbac.Change{Grant: []rbac.Binding{standing}})
	apply(rbac.Change{Grant: []rbac.Binding{untilSoon}})
	if got := held(); len(got) != 2 {
		t.Fatalf("a grant with an expiry should stand beside the one without: %+v", got)
	}
	h.now = h.now.Add(2 * time.Hour)
	if !allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("granting until a time shouldn't narrow a standing grant")
	}
	// The same grant again changes its note and who last changed it, not its id.
	first := held()[0]
	again := standing
	again.Note = "ticket 12"
	if err := h.authz.Apply(ctx, h.as(t, "admin2"), cluster, rbac.Change{Grant: []rbac.Binding{again}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("someone without the power to grant: %v", err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "admin2"))
	h.events = nil
	if err := h.authz.Apply(ctx, h.as(t, "admin2"), cluster, rbac.Change{Grant: []rbac.Binding{again}}); err != nil {
		t.Fatal(err)
	}
	got := held()
	if len(got) != 1 || got[0].ID != first.ID || got[0].Note != "ticket 12" || got[0].UpdatedBy != h.as(t, "admin2").Principal ||
		got[0].CreatedBy != first.CreatedBy {
		t.Fatalf("the same grant again: %+v, was %+v", got, first)
	}
	if len(h.events) != 1 || len(h.events[0].Granted) != 1 {
		t.Fatalf("a new note is a change: %+v", h.events)
	}
	// Two conditions are two grants, each allowing where it holds: replacing the role's grants with
	// them ends the unconditional one.
	a, b := standing, standing
	a.Condition.Expression, b.Condition.Expression = `request.attributes.vpn == true`, `request.attributes.office == true`
	apply(rbac.Change{Revoke: []rbac.Binding{standing}, Grant: []rbac.Binding{a, b}})
	for _, attr := range []string{"vpn", "office"} {
		if err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{attr: true}), h.as(t, "u"), login, cluster); err != nil {
			t.Errorf("each conditional grant should allow where its own condition holds (%s): %v", attr, err)
		}
	}
	if got := held(); len(got) != 2 || slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.Condition.Expression == "" }) {
		t.Fatalf("a change replacing a role with conditional grants should end the unconditional one: %+v", got)
	}
	// A source of its own is another grant.
	synced := standing
	synced.Source = "sync/directory"
	apply(rbac.Change{Grant: []rbac.Binding{synced}})
	if got := held(); len(got) != 3 {
		t.Fatalf("a source should be a grant of its own: %+v", got)
	}
	// Revoking a role from a source removes its grants from that source, whatever their condition.
	apply(rbac.Change{Revoke: []rbac.Binding{standing}})
	if got := held(); len(got) != 1 || got[0].Source != synced.Source {
		t.Fatalf("after revoking the direct grants: %+v", got)
	}
	// An id picks one grant; with another source or role it revokes nothing.
	apply(rbac.Change{Grant: []rbac.Binding{standing, a}})
	byID := held()
	victim := byID[slices.IndexFunc(byID, func(g rbac.Grant) bool { return g.Condition.Expression == a.Condition.Expression })]
	wrongRole := victim.Binding
	wrongRole.Role = "cluster.admin"
	apply(rbac.Change{Revoke: []rbac.Binding{wrongRole}})
	if got := held(); len(got) != 3 {
		t.Fatalf("an id with another role should revoke nothing: %+v", got)
	}
	idOnly := rbac.Binding{ID: victim.ID, Principal: victim.Principal}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Revoke: []rbac.Binding{idOnly}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a revoke by id without its role, which would revoke nothing: %v", err)
	}
	apply(rbac.Change{Revoke: []rbac.Binding{victim.Binding}})
	if got := held(); len(got) != 2 || slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.ID == victim.ID }) {
		t.Fatalf("revoking by id: %+v", got)
	}
	// Revoking and granting at once replaces the role's grants, keeping one granted again as it is.
	kept := held()[slices.IndexFunc(held(), func(g rbac.Grant) bool { return g.Source == "" })]
	untilLater := standing
	untilLater.ExpiresAt = h.now.Add(time.Hour)
	apply(rbac.Change{Revoke: []rbac.Binding{standing}, Grant: []rbac.Binding{standing, untilLater}})
	got = held()
	if len(got) != 3 || !slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.ID == kept.ID }) {
		t.Fatalf("a grant granted again in a replacing change should keep its id: %+v", got)
	}
	apply(rbac.Change{Revoke: []rbac.Binding{standing}, Grant: []rbac.Binding{untilLater}})
	if got := held(); len(got) != 2 || slices.ContainsFunc(got, func(g rbac.Grant) bool { return g.Source == "" && g.ExpiresAt.IsZero() }) {
		t.Fatalf("a grant with another expiry isn't spared: %+v", got)
	}
	activated := rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{Role: "cluster.login", Principal: standing.Principal, Source: rbac.SourceActivation}}
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{activated}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("importing an activation: %v", err)
	}
	for name, bad := range map[string]rbac.Binding{
		"the activation source":   {Role: "cluster.login", Principal: standing.Principal, Source: rbac.SourceActivation},
		"a source with uppercase": {Role: "cluster.login", Principal: standing.Principal, Source: "Sync"},
		"a source too long":       {Role: "cluster.login", Principal: standing.Principal, Source: "s" + strings.Repeat("x", 63)},
	} {
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{bad}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestActivatingRespectsConstraints(t *testing.T) {
	stop := false
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "frozen", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			p := in.Permission
			return stop && p == grantC, nil
		}}}
	})
	ctx := t.Context()
	e := rbac.Eligibility{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	stop = true
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "x"}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("activating under a freeze on grant changes: %v", err)
	}
}

func TestEligibilitiesGoWithWhatTheyName(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	e := rbac.Eligibility{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, e.Principal); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{e.Principal}}); err != nil || len(got) != 0 {
		t.Fatalf("after deleting the principal everywhere: %+v, %v", got, err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteScope(ctx, host, "t1", cluster.Scope()); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || len(got) != 0 {
		t.Fatalf("after deleting the scope: %+v, %v", got, err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "owner"), grant(cluster.Scope(), "cluster.admin", rbac.User, "owner2"))
	e.ExpiresAt = h.now.Add(time.Hour)
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour)
	// Set again once expired, it is as new: who set it, and when.
	e.ExpiresAt = h.now.Add(time.Hour)
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner2"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{e.Principal}}); err != nil ||
		len(got) != 1 || got[0].CreatedBy != (rbac.Principal{Kind: rbac.User, ID: "owner2"}) {
		t.Fatalf("an expired eligibility set again: %+v, %v", got, err)
	}
	h.now = h.now.Add(2 * time.Hour)
	if n, err := h.authz.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired = %d, %v", n, err)
	}
}

func TestAnEligibilityCantHandOutMoreThanItsSetterHolds(t *testing.T) {
	share := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, login, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), share) })
	h.seed(t, grant(cluster.Scope(), "cluster.share", rbac.User, "sharer"))
	sudo := rbac.Eligibility{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(t.Context(), h.as(t, "sharer"), cluster, sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("making someone eligible for a role the setter couldn't grant: %v", err)
	}
	loginOnly := sudo
	loginOnly.Role = "cluster.login"
	if err := h.authz.SetEligibility(t.Context(), h.as(t, "sharer"), cluster, loginOnly); err != nil {
		t.Fatalf("making someone eligible for a role the setter could grant: %v", err)
	}
}

func TestAnActivationEndsByItsEligibility(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	e := rbac.Eligibility{
		Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: 366 * 24 * time.Hour,
		ExpiresAt: h.now.Add(10 * time.Minute),
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: "cluster.sudo", Duration: 300 * 24 * time.Hour, Justification: "x"}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("activating past the eligibility's end: %v", err)
	}
	if g, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: "cluster.sudo", Duration: 10 * time.Minute, Justification: "x"}); err != nil || !g.ExpiresAt.Equal(e.ExpiresAt) {
		t.Fatalf("activating until the eligibility's end: %+v, %v", g, err)
	}
}

func TestDeletingARoleEndsItsEligibilities(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	operator := rbac.RoleDefinition{ID: "custom.operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	e := rbac.Eligibility{Role: operator.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, MaxDuration: time.Hour}
	if err := h.authz.SetEligibility(ctx, admin, cluster, e); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteRole(ctx, admin, "t1", operator.ID); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Ineligible) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	// Defined again with its id, a role isn't activated through an eligibility for the one deleted.
	operator.Permissions = append(operator.Permissions, root)
	if err := h.authz.SetRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authz.Activate(ctx, h.as(t, "x"), cluster, rbac.Activation{Role: operator.ID, Duration: time.Minute, Justification: "x"}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("activating a role deleted and defined again: %v", err)
	}
}

// racing is a pool on which change commits just before the first statement, or batch holding one,
// that reads the table reading names, or denies where it names none, as another session's change
// would commit between two of a read's statements.
type racing struct {
	*pgxpool.Pool
	reading string
	change  func()
}

func (r *racing) race(sql string) {
	if do := r.change; do != nil && strings.Contains(sql, cmp.Or(r.reading, "rbac_denies")) {
		r.change = nil
		do()
	}
}

func (r *racing) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	r.race(sql)
	return r.Pool.Query(ctx, sql, args...)
}

func (r *racing) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	r.race(sql)
	return r.Pool.QueryRow(ctx, sql, args...)
}

func (r *racing) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	r.raceBatch(b)
	return r.Pool.SendBatch(ctx, b)
}

// raceBatch races before a batch holding a statement race would race before.
func (r *racing) raceBatch(b *pgx.Batch) {
	for _, q := range b.QueuedQueries {
		r.race(q.SQL)
	}
}

func (r *racing) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := r.Pool.BeginTx(ctx, opts)
	return &racingTx{Tx: tx, r: r}, err
}

func (r *racing) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := r.Pool.Begin(ctx)
	return &racingTx{Tx: tx, r: r}, err
}

type racingTx struct {
	pgx.Tx
	r *racing
}

func (tx *racingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.r.race(sql)
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx *racingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.r.race(sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func (tx *racingTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	tx.r.raceBatch(b)
	return tx.Tx.SendBatch(ctx, b)
}

func TestAReadOfSeveralStatementsReadsOneSnapshot(t *testing.T) {
	// Each starts as before, and the change makes it as after, so a read that mixed the two would
	// answer what neither was.
	for _, c := range []struct {
		name          string
		before, after string
		read          func(t *testing.T, a *rbac.Authorizer, u rbac.Subject)
	}{{
		// Allowed through ops before; after, u isn't in ops, which a deny now names.
		name:   "Explain",
		before: `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'group', 'ops', 'cluster.login')`,
		after: `DELETE FROM rbac_members WHERE principal = 'user:u';
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'cluster', 'c1', 'd', '{group:ops}', '{cluster:login}')`,
		read: func(t *testing.T, a *rbac.Authorizer, u rbac.Subject) {
			t.Helper()
			if d, err := a.Explain(t.Context(), u, login, cluster); err != nil || !d.Allowed {
				t.Errorf("Explain = %+v, %v", d, err)
			}
		},
	}, {
		// Granted and denied before; after, neither.
		name: "Reachable",
		before: `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login');
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'cluster', 'c1', 'd', '{user:u}', '{cluster:login}')`,
		after: `DELETE FROM rbac_grants WHERE principal = 'user:u'; DELETE FROM rbac_denies`,
		read: func(t *testing.T, a *rbac.Authorizer, u rbac.Subject) {
			t.Helper()
			if reach, err := a.Reachable(t.Context(), u, login, "t1", "cluster"); err != nil || len(reach.Except) == 0 {
				t.Errorf("Reachable = %+v, %v", reach, err)
			}
		},
	}, {
		// In ops, granted, and in contractors, denied, before; after, in neither.
		name: "Holders",
		before: `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'group', 'ops', 'cluster.login');
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions) VALUES ('t1', 'cluster', 'c1', 'd', '{group:contractors}', '{cluster:login}')`,
		after: `DELETE FROM rbac_members WHERE principal = 'user:u'`,
		read: func(t *testing.T, a *rbac.Authorizer, u rbac.Subject) {
			t.Helper()
			if holders, err := a.Holders(t.Context(), login, cluster); err != nil || slices.Contains(holderPrincipals(holders), u.Principal) {
				t.Errorf("Holders = %+v, %v", holders, err)
			}
		},
	}} {
		// On a pool, and on a host's wrapper around one that is only a DB, as one tracing its
		// statements can be, whose Begin begins at the database's default.
		for name, wrap := range map[string]func(*racing) rbac.DB{
			"pool":    func(r *racing) rbac.DB { return r },
			"wrapper": func(r *racing) rbac.DB { return struct{ rbac.DB }{r} },
		} {
			t.Run(c.name+" on a "+name, func(t *testing.T) {
				h := setup(t)
				u := h.as(t, "u", "ops", "contractors")
				if _, err := h.pool.Exec(t.Context(), c.before); err != nil {
					t.Fatal(err)
				}
				db := &racing{Pool: h.pool}
				db.change = func() {
					if _, err := h.pool.Exec(t.Context(), c.after); err != nil {
						t.Error(err)
					}
				}
				a, err := rbac.New(wrap(db), h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				c.read(t, a, u)
				if db.change != nil {
					t.Fatal("the read never read denies")
				}
			})
		}
	}
}

// uncommitting is a pool whose transactions fail to commit, as one whose context ends after its
// last statement does.
type uncommitting struct{ *pgxpool.Pool }

var errCommit = errors.New("commit failed")

func (u uncommitting) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := u.Pool.BeginTx(ctx, opts)
	return uncommittedTx{tx}, err
}

type uncommittedTx struct{ pgx.Tx }

func (uncommittedTx) Commit(context.Context) error { return errCommit }

func TestAReadWhoseSnapshotFailsToCommitAnswersNothing(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	a, err := rbac.New(uncommitting{h.pool}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := a.Explain(ctx, u, login, cluster); !errors.Is(err, errCommit) || d.Allowed || len(d.Grants) > 0 {
		t.Errorf("Explain = %+v, %v", d, err)
	}
	if reach, err := a.Reachable(ctx, u, login, "t1", "cluster"); !errors.Is(err, errCommit) || reach.All || len(reach.Scopes) > 0 {
		t.Errorf("Reachable = %+v, %v", reach, err)
	}
	if holders, err := a.Holders(ctx, login, cluster); !errors.Is(err, errCommit) || len(holders) > 0 {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
}

func TestReadsUnderWithTxSeeTheHostsTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authz := h.authz.WithTx(tx)
	if err := authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if d, err := authz.Explain(ctx, u, login, cluster); err != nil || !d.Allowed {
		t.Errorf("Explain = %+v, %v", d, err)
	}
	if reach, err := authz.Reachable(ctx, u, login, "t1", "cluster"); err != nil || !slices.Contains(reach.Scopes, cluster.Scope()) {
		t.Errorf("Reachable = %+v, %v", reach, err)
	}
	if holders, err := authz.Holders(ctx, login, cluster); err != nil || !slices.Contains(holderPrincipals(holders), u.Principal) {
		t.Errorf("Holders = %+v, %v", holders, err)
	}
}

func TestAnIDThatIsNoTextIsInvalid(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	long := strings.Repeat("x", rbac.MaxID+1)
	for _, id := range []string{"c\x00", "c\xff", long} {
		r := cluster
		r.ID = id
		if err := h.authz.Authorize(ctx, owner, view, r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a resource id %q: %v", id[:min(len(id), 8)], err)
		}
		if err := h.authz.Authorize(ctx, rbac.Subject{Principal: identity(id)}, view, cluster); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a subject id %q: %v", id[:min(len(id), 8)], err)
		}
		if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity(id)}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a grant to %q: %v", id[:min(len(id), 8)], err)
		}
		if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity(id)}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a membership of %q: %v", id[:min(len(id), 8)], err)
		}
		if _, err := h.authz.Memberships(ctx, id, nil); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a tenant %q: %v", id[:min(len(id), 8)], err)
		}
		// Reads and removals by an id are refused too, rather than reach PostgreSQL.
		scope, p := rbac.Scope{Type: "cluster", ID: id}, identity(id)
		member := rbac.Member{Group: "g", Principal: p}
		for name, err := range map[string]error{
			"Grants":        second(h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{scope}})),
			"Eligibilities": second(h.authz.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{p}})),
			"Denies":        second(h.authz.Denies(ctx, "t1", []rbac.Scope{scope})),
			"Memberships":   second(h.authz.Memberships(ctx, "t1", []rbac.Principal{p})),
			"MembershipsOf": second(h.authz.MembershipsOf(ctx, p)),
			"Groups":        second(h.authz.Groups(ctx, id)),
			"Members":       second(h.authz.Members(ctx, id, "g")),
			"GroupsOf":      second(h.authz.GroupsOf(ctx, "t1", p)),
			"CustomRoles":   second(h.authz.CustomRoles(ctx, id)),
			"DeleteGroups":  h.authz.DeleteGroups(ctx, host, "t1", []string{id}),
			"DeleteMembers": h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{member}),
			"ChangeMembers": h.authz.ChangeMembers(ctx, owner, "t1", nil, []rbac.Member{member}),
			"OnBehalfOf": h.authz.SetMemberships(rbac.WithAudit(ctx, rbac.Audit{OnBehalfOf: p}), host, "t1",
				[]rbac.Membership{{Principal: identity("someone")}}),
		} {
			if !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("%s by %q: %v", name, id[:min(len(id), 8)], err)
			}
		}
	}
	// As is a role, a source, a grant's ID, a deny's id or a kind a call names by.
	for _, id := range []string{"c\x00", "c\xff"} {
		role, u := rbac.Role("custom."+id), identity("u")
		for name, err := range map[string]error{
			"Apply's revoke":         h.authz.Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: role, Principal: u}}}),
			"DeleteGrants by source": h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{Role: "cluster.login", Principal: u, Source: id}}}),
			"DeleteGrants by ID":     h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: rbac.Binding{ID: id, Role: "cluster.login", Principal: u}}}),
			"DeleteEligibility":      h.authz.DeleteEligibility(ctx, owner, cluster, role, u),
			"Activate":               second(h.authz.Activate(ctx, owner, cluster, rbac.Activation{Role: role, Duration: time.Minute, Justification: "work"})),
			"Deactivate":             h.authz.Deactivate(ctx, owner, cluster, role),
			"DeleteRole":             h.authz.DeleteRole(ctx, owner, "t1", role),
			"DeleteDeny":             h.authz.DeleteDeny(ctx, owner, cluster, id),
			"MembershipsOf":          second(h.authz.MembershipsOf(ctx, rbac.Principal{Kind: rbac.PrincipalKind(id), ID: "u"})),
		} {
			if !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("%s by %q: %v", name, id, err)
			}
		}
	}
	// A constraint can ask about the anonymous, who are in no group and no tenant, and are granted
	// nothing and eligible for nothing of their own, alone or beside others.
	anonymous := rbac.GrantFilter{Principals: []rbac.Principal{{}}}
	if grants, err := h.authz.Grants(ctx, "t1", anonymous); err != nil || len(grants) > 0 {
		t.Errorf("Grants of the anonymous = %v, %v", grants, err)
	}
	if es, err := h.authz.Eligibilities(ctx, "t1", anonymous); err != nil || len(es) > 0 {
		t.Errorf("Eligibilities of the anonymous = %v, %v", es, err)
	}
	beside := rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}, Principals: []rbac.Principal{{}, owner.Principal}}
	if grants, err := h.authz.Grants(ctx, "t1", beside); err != nil || len(grants) != 1 || grants[0].Principal != owner.Principal {
		t.Errorf("Grants of the anonymous and the owner = %v, %v", grants, err)
	}
	if groups, err := h.authz.GroupsOf(ctx, "t1", rbac.Principal{}); err != nil || len(groups) > 0 {
		t.Errorf("GroupsOf the anonymous = %v, %v", groups, err)
	}
	if ms, err := h.authz.MembershipsOf(ctx, rbac.Principal{}); err != nil || len(ms) > 0 {
		t.Errorf("MembershipsOf the anonymous = %v, %v", ms, err)
	}
	if ms, err := h.authz.Memberships(ctx, "t1", []rbac.Principal{{}}); err != nil || len(ms) > 0 {
		t.Errorf("Memberships of the anonymous = %v, %v", ms, err)
	}
}

// second is the error of a call that returns a value too.
func second[T any](_ T, err error) error { return err }

func TestHoldersAsksAConstraintOnTheSubjectAboutEachHolder(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
		// As the docs say: removed where the subject could be one, so where it is nil too.
		c.Constraints = []rbac.Constraint{{Name: "no login for machines", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == login && (in.Subject == nil || in.Subject.Principal.Kind == "service_account"), nil
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	ci := rbac.Principal{Kind: "service_account", ID: "ci"}
	h.member(t, ci)
	h.seed(t, grant(cluster.Scope(), "cluster.login", ci.Kind, ci.ID), grant(cluster.Scope(), "cluster.login", rbac.Members, "t1"))
	holders, err := h.authz.Holders(ctx, login, cluster)
	if err != nil {
		t.Fatal(err)
	}
	// Asked without the request's attributes, a constraint answers for any, so the machine may be
	// refused, not must be, as may some of the members, and the owner can't be.
	maybe := map[rbac.Principal]bool{}
	for _, h := range holders {
		maybe[h.Principal] = h.MaybeDenied
	}
	if want := map[rbac.Principal]bool{ci: true, rbac.TenantMembers("t1"): true, owner.Principal: false}; !maps.Equal(maybe, want) {
		t.Fatalf("Holders = %+v", holders)
	}
}

func TestACheckReadsAGrantAndItsCustomRoleAsOfOneMoment(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), op.ID, rbac.User, "op"))
	operator := h.as(t, "op")
	// Between the reads, its grant is revoked and then its role widened, which no grant then asks of.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), op.ID, rbac.User, "op")}); err != nil {
			t.Error(err)
		}
		widened := op
		widened.Permissions = []rbac.Permission{view, login, root}
		if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
			t.Error(err)
		}
	})
	if allowed(t, h, operator, root, cluster) {
		t.Fatal("a revoked grant gave what its role was widened to after")
	}
}

// Grantable reads the actor's grants and the custom roles in one statement, as a check reads a
// grant with its role.
func TestGrantableReadsAGrantAndItsCustomRoleAsOfOneMoment(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	lead := rbac.RoleDefinition{ID: "custom.lead", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	if err := h.authz.SetRole(ctx, admin, "t1", lead); err != nil {
		t.Fatal(err)
	}
	held := grant(cluster.Scope(), lead.ID, rbac.User, "lead")
	h.seed(t, held)
	actor := h.as(t, "lead")
	// Once its grants are read, its grant is revoked and then its role widened.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{held}); err != nil {
			t.Error(err)
		}
		widened := lead
		widened.GrantableRoles = []rbac.Role{"cluster.login", "cluster.sudo"}
		if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
			t.Error(err)
		}
	})
	roles, err := h.authz.Grantable(ctx, actor, cluster)
	if err != nil || !once {
		t.Fatal(err)
	}
	if slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.sudo" }) {
		t.Fatalf("Grantable = %+v: a revoked grant offered what its role was widened to list after", roles)
	}
}

// A check compares expiry and gives conditions request.time at one time, so a grant ending as it
// runs can't meet a condition of a later moment. Here u's grant ends 30 seconds in, and a deny
// binds u for a minute, so at no moment may u log in. Once the check has read the grant, the clock
// passes the deny's end.
func TestACheckComparesExpiryAndRequestTimeAtOneTime(t *testing.T) {
	for name, may := range map[string]func(t *testing.T, h *harness, u rbac.Subject) bool{
		"Authorize": func(t *testing.T, h *harness, u rbac.Subject) bool {
			t.Helper()
			return allowed(t, h, u, login, cluster)
		},
		"Permissions": func(t *testing.T, h *harness, u rbac.Subject) bool {
			t.Helper()
			perms, err := h.authz.Permissions(t.Context(), u, cluster)
			if err != nil {
				t.Fatal(err)
			}
			return slices.Contains(perms, login)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
			start := h.now
			ends, lifts := start.Add(30*time.Second), start.Add(time.Minute)
			u := h.as(t, "u")
			held := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
			held.ExpiresAt = ends
			h.seed(t, held, grant(cluster.Scope(), guardRole.ID, rbac.User, "guardian"))
			if err := h.authz.SetDeny(t.Context(), h.as(t, "guardian"), cluster, rbac.Deny{
				ID: "freeze", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{login},
				Condition: rbac.Condition{Expression: `request.time < timestamp("` + lifts.Format(time.RFC3339) + `")`},
			}); err != nil {
				t.Fatal(err)
			}
			for _, at := range []time.Time{start, ends, lifts} {
				h.now = at
				if may(t, h, u) {
					t.Fatalf("at %v, with the clock still, u may log in", at)
				}
			}
			h.now = start
			passed := false
			rbac.SetReadingRoles(t, func() {
				if !passed {
					passed = true
					h.now = lifts
				}
			})
			if may(t, h, u) {
				t.Error("u may log in, which no moment allowed")
			}
			if !passed {
				t.Fatal("the check reached no hook")
			}
		})
	}
}

// timedChanges are changes x makes by a power, on c1 or the tenant, giving the permission denied
// names: Apply granting v cluster.sudo, which the power's role lists, so it hands it on for good
// whatever the power's end; and ChangeMembers adding v to crew, a group holding nothing.
var timedChanges = map[string]struct {
	power  rbac.Grant
	denied rbac.Permission
	change func(h *harness, x rbac.Subject) error
}{
	"Apply": {grant(cluster.Scope(), lister.ID, rbac.User, "x"), grantC, func(h *harness, x rbac.Subject) error {
		return h.authz.Apply(h.ctx, x, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("v")}}})
	}},
	"ChangeMembers": {grant(rbac.TenantRoot("t1"), groupMembers.ID, rbac.User, "x"), rbac.GroupMembers, func(h *harness, x rbac.Subject) error {
		return h.authz.ChangeMembers(h.ctx, x, "t1", []rbac.Member{{Group: "crew", Principal: identity("v")}}, nil)
	}},
}

// timedChange is setup for x to make a timed change by power, which ends 30 seconds in.
func timedChange(t *testing.T, power rbac.Grant) (h *harness, x rbac.Subject, ends time.Time) {
	t.Helper()
	h = setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), lister, groupMembers) })
	ends = h.now.Add(30 * time.Second)
	power.ExpiresAt = ends
	h.seed(t, power)
	h.groups(t, "crew")
	h.as(t, "v")
	return h, h.as(t, "x"), ends
}

// A change compares expiry and gives conditions request.time at one time under its locks, so the
// actor's power ending as it runs can't meet a condition of a later moment. Here x's power ends 30
// seconds in, and a deny of it binding x for a minute commits once the change has checked x before
// its transaction, so from then on no moment allows the change. Once the transaction has read x's
// power, the clock passes the deny's end.
func TestAChangeComparesExpiryAndRequestTimeAtOneTime(t *testing.T) {
	for name, c := range timedChanges {
		t.Run(name, func(t *testing.T) {
			h, x, ends := timedChange(t, c.power)
			ctx := t.Context()
			start := h.now
			lifts := start.Add(time.Minute)
			freeze := func() {
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
					VALUES ('t1', 'tenant', 't1', 'freeze', '{user:x}', $1, $2)`,
					[]string{string(c.denied)}, `request.time < timestamp("`+lifts.Format(time.RFC3339)+`")`); err != nil {
					t.Error(err)
				}
			}
			freeze()
			for _, at := range []time.Time{start, ends, lifts} {
				h.now = at
				if err := c.change(h, x); !errors.Is(err, rbac.ErrDenied) {
					t.Fatalf("at %v, with the clock still: %v", at, err)
				}
			}
			if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_denies WHERE tenant = 't1' AND id = 'freeze'`); err != nil {
				t.Fatal(err)
			}
			h.now = start
			committed, passed := false, false
			rbac.SetReadingRoles(t, func() {
				// The change's transaction holds a connection of the test's pool; its reads before it
				// hold none once read.
				switch {
				case h.pool.Stat().AcquiredConns() == 0:
					if !committed {
						committed = true
						freeze()
					}
				case !passed:
					passed = true
					h.now = lifts
				}
			})
			err := c.change(h, x)
			if !passed {
				t.Fatalf("the change read x's power in its transaction without reaching the hook: %v", err)
			}
			if !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("the change was made, which no moment since the deny allowed: %v", err)
			}
		})
	}
}

// A change decides again under its locks at the time it is made, not the time it began: here x's
// power ends once the change has checked it before its transaction, so the change is refused.
func TestAChangeDecidesUnderItsLocksAtTheTimeItIsMade(t *testing.T) {
	for name, c := range timedChanges {
		t.Run(name, func(t *testing.T) {
			h, x, ends := timedChange(t, c.power)
			passed := false
			rbac.SetReadingRoles(t, func() {
				if h.pool.Stat().AcquiredConns() == 0 && !passed {
					passed = true
					h.now = ends
				}
			})
			err := c.change(h, x)
			if !passed {
				t.Fatalf("the change read x's power before its transaction without reaching the hook: %v", err)
			}
			if !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("the change was made once x's power had ended: %v", err)
			}
		})
	}
}

// Each call reads the host's clock once, where it first needs the time, so every statement it makes
// and every condition it evaluates are of one moment, and a change once more in each of its
// transactions, under its locks: one that first needs it in its transaction, to pick what it holds
// of what is in force, reads it there, and again once it holds it all. The count is exact: a change
// that reads it before its transaction and only once would decide under its locks at the time it
// began. Each call here reads through several statements, conditions and label values; one that
// needs no time reads none.
func TestEachCallReadsTheClockOnceAndAChangeAgainUnderItsLocks(t *testing.T) {
	reads := 0
	tenantGroups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	h := labeled(t, banks, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), tenantGuard, groupMembers, tenantGroups, guardRole)
		now := c.Now
		c.Now = func() time.Time {
			reads++
			return now()
		}
	})
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	admin := roleAdmin(t, h)
	h.seed(t, grant(tenant, tenantGuard.ID, rbac.User, "admin"), grant(tenant, groupMembers.ID, rbac.User, "admin"),
		grant(tenant, tenantGroups.ID, rbac.User, "admin"), grant(cluster.Scope(), guardRole.ID, rbac.User, "admin"))
	h.hold(t, "admin", "level:high")
	since := `timestamp("2000-01-01T00:00:00Z")`
	high := grant(tenant, "level.high", rbac.User, "u")
	high.Condition = rbac.Condition{Expression: `request.time > ` + since}
	h.seed(t, high, grant(cluster.Scope(), "cluster.login", rbac.Group, "crew"))
	u := h.as(t, "u", "crew")
	v := h.as(t, "v")
	if err := h.authz.SetDeny(ctx, admin, tenantT1, rbac.Deny{
		ID: "past", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{"level:mid"},
		Condition: rbac.Condition{Expression: `request.time < ` + since},
	}); err != nil {
		t.Fatal(err)
	}
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	second := func(_ any, err error) error { return err }
	for _, c := range []struct {
		name  string
		reads int
		call  func() error
	}{
		{"Authorize", 1, func() error { return h.authz.Authorize(ctx, u, login, secret) }},
		{"Explain", 1, func() error { return second(h.authz.Explain(ctx, u, login, secret)) }},
		{"Permissions", 1, func() error { return second(h.authz.Permissions(ctx, u, secret)) }},
		{"Holders", 1, func() error { return second(h.authz.Holders(ctx, login, secret)) }},
		{"Reachable", 1, func() error { return second(h.authz.Reachable(ctx, u, login, "t1", "cluster")) }},
		{"Filter", 1, func() error {
			return second(h.authz.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1))
		}},
		{"Holding", 1, func() error { return second(h.authz.Holding(ctx, "t1", u)) }},
		{"Grantable", 1, func() error { return second(h.authz.Grantable(ctx, admin, secret)) }},
		{"Conflicts", 1, func() error { return second(h.authz.Conflicts(ctx, "t1")) }},
		{"Grants", 1, func() error {
			return second(h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}))
		}},
		{"Memberships", 1, func() error { return second(h.authz.Memberships(ctx, "t1", nil)) }},
		{"Members", 1, func() error { return second(h.authz.Members(ctx, "t1", "crew")) }},
		{"GroupsOf", 1, func() error { return second(h.authz.GroupsOf(ctx, "t1", u.Principal)) }},
		{"Apply", 2, func() error {
			return h.authz.Apply(ctx, admin, secret, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: v.Principal}}})
		}},
		{"Import", 2, func() error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"DeleteGrants", 0, func() error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"SetEligibility", 2, func() error {
			return h.authz.SetEligibility(ctx, admin, secret, rbac.Eligibility{Role: "cluster.login", Principal: v.Principal, MaxDuration: time.Hour})
		}},
		{"Activate", 2, func() error {
			return second(h.authz.Activate(ctx, v, secret, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "on call"}))
		}},
		{"Deactivate", 0, func() error { return h.authz.Deactivate(ctx, v, secret, "cluster.login") }},
		{"DeleteEligibility", 2, func() error { return h.authz.DeleteEligibility(ctx, admin, secret, "cluster.login", v.Principal) }},
		{"SetDeny", 2, func() error {
			return h.authz.SetDeny(ctx, admin, secret, rbac.Deny{ID: "d", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{root}})
		}},
		{"DeleteDeny", 2, func() error { return h.authz.DeleteDeny(ctx, admin, secret, "d") }},
		{"SetRole", 2, func() error {
			return h.authz.SetRole(ctx, admin, "t1", rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{login}, ResourceTypes: []string{"cluster"}})
		}},
		{"DeleteRole", 2, func() error { return h.authz.DeleteRole(ctx, admin, "t1", "custom.op") }},
		{"SetGroup", 2, func() error { return h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "team"}) }},
		{"ImportGroups", 0, func() error { return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "squad"}}) }},
		{"ChangeMembers", 2, func() error {
			return h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "team", Principal: v.Principal}}, nil)
		}},
		{"ImportMembers", 2, func() error {
			return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "squad", Principal: v.Principal}})
		}},
		{"DeleteMembers", 2, func() error {
			return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "squad", Principal: v.Principal}})
		}},
		{"DeleteGroup", 2, func() error { return h.authz.DeleteGroup(ctx, admin, "t1", "team") }},
		{"DeleteGroups", 2, func() error { return h.authz.DeleteGroups(ctx, host, "t1", []string{"squad"}) }},
		{"SetMemberships", 2, func() error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("w")}})
		}},
		{"DeleteScopes", 0, func() error { return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{workspace.Scope()}) }},
		{"DeletePrincipal", 0, func() error { return h.authz.DeletePrincipal(ctx, host, "t1", v.Principal) }},
		{"DeletePrincipalEverywhere", 0, func() error { return h.authz.DeletePrincipalEverywhere(ctx, host, identity("w")) }},
		{"DeleteExpired", 1, func() error { return second(h.authz.DeleteExpired(ctx)) }},
	} {
		reads = 0
		if err := c.call(); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if reads != c.reads {
			t.Errorf("%s read the clock %d times, not %d", c.name, reads, c.reads)
		}
	}
}
