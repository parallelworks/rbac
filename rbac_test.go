package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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

func setup(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return setupOn(t, pgtest.Open(t, ""), mutate...)
}

// setupOn is setup on a pool of the test's own.
func setupOn(t *testing.T, pool *pgxpool.Pool, mutate ...func(*rbac.Config)) *harness {
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
	creator(t, pool)
	return h
}

// creator grants "owner" the cluster's admin role, around the hooks a test configures.
func creator(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'owner', 'cluster.admin')`); err != nil {
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

// Filter's condition leaves out the resources denies on thousands of them, or of the workspaces
// they are in, cover in about the time it takes for a few: a row's own key is looked up in a hash of
// the denies on resources of its type, and each of its keys in one object of those on containers and
// the tenant. Overlapping each row with every deny would cost it thousands of comparisons, and a
// tenant's admins can set them.
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
			// The time Filter's condition takes to count the rows once n of them are denied, the
			// fastest of a few, so a stall of the database's in one doesn't count.
			listed := func(n int) time.Duration {
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
				var fastest time.Duration
				for i := range 3 {
					start := time.Now()
					var kept int
					if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM fleet WHERE `+pred.SQL, pred.Args...).Scan(&kept); err != nil || kept != rows-n {
						t.Fatalf("Filter kept %d of %d rows with %d denied, %v", kept, rows, n, err)
					}
					if took := time.Since(start); i == 0 || took < fastest {
						fastest = took
					}
				}
				return fastest
			}
			few := listed(40)
			if many := listed(4000); many > 10*few && many > 100*time.Millisecond {
				t.Fatalf("Filter's condition took %v with 40 %ss denied, and %v with 4000", few, on, many)
			}
		})
	}
}

// A subject holding a grant on each of thousands of workspaces, as one on each it created, lists a
// page of them, or of the clusters in them, in about the time it takes for a few: past 128 grants,
// each of a row's keys is looked up in one object of them. Overlapping each row with every grant
// would cost it thousands of comparisons, and the index, which merges the rows each finds, as many
// for each row it finds.
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
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	u := h.as(t, "u")
	lists := []struct {
		resourceType, table string
		p                   rbac.Permission
	}{{"workspace", "spaces", "workspace:view"}, {"cluster", "fleet", login}}
	held := 0
	// The time a page of 50 of each table's rows takes once u holds n workspaces, the fastest of a
	// few, so a stall of the database's in one doesn't count.
	pages := func(n int) []time.Duration {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'workspace', 'w' || i, 'user', 'u', r FROM generate_series($1 + 1, $2) i, unnest('{workspace.admin,cluster.login}'::text[]) r`,
			held, n); err != nil {
			t.Fatal(err)
		}
		held = n
		var took []time.Duration
		for _, l := range lists {
			pred, err := h.authz.Filter(ctx, u, l.p, "t1", l.resourceType, rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
			if err != nil {
				t.Fatal(err)
			}
			var kept int
			if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM `+l.table+` WHERE `+pred.SQL, pred.Args...).Scan(&kept); err != nil || kept != n {
				t.Fatalf("Filter kept %d %ss of %d, %v", kept, l.resourceType, n, err)
			}
			var fastest time.Duration
			for i := range 3 {
				start := time.Now()
				rows, err := h.pool.Query(ctx, `SELECT id FROM `+l.table+` WHERE `+pred.SQL+` ORDER BY id LIMIT 50`, pred.Args...)
				if err != nil {
					t.Fatal(err)
				}
				if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) != min(n, 50) {
					t.Fatalf("a page of %d %ss, %v", len(ids), l.resourceType, err)
				}
				if d := time.Since(start); i == 0 || d < fastest {
					fastest = d
				}
			}
			took = append(took, fastest)
		}
		return took
	}
	few := pages(40)
	for i, many := range pages(4000) {
		if many > 10*few[i] && many > 100*time.Millisecond {
			t.Errorf("a page of %ss took %v with 40 workspaces granted, and %v with 4000", lists[i].resourceType, few[i], many)
		}
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
	// Each row's own key is looked up in a hash of the subject's grants, not compared with each.
	if text := strings.Join(plan, "\n"); !strings.Contains(text, "hashed SubPlan") {
		t.Fatalf("Filter's plan for a subject with many resource grants:\n%s", text)
	}
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
	if text := strings.Join(plan, "\n"); !strings.Contains(text, "Bitmap Index Scan") {
		t.Fatalf("Filter's plan for a subject with one resource grant:\n%s", text)
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
			// Commit only once DeleteScopes has either finished or is waiting on a lock.
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
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, h.as(t, "u"), login, cluster) {
				t.Fatal("a grant made while its scope was deleted outlived the delete")
			}
		})
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
	done := make(chan error, 1)
	go func() { done <- h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{b}}) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("Apply didn't wait for the role's change: %v", err)
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
		t.Fatalf("granting a role changed while the change waited: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
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
	// Clusters can't take it yet, so listing it for clusters needs no power over it.
	later := rbac.RoleDefinition{ID: "custom.later", Permissions: []rbac.Permission{rbac.DefineRoles}, ResourceTypes: []string{"tenant"}}
	if err := h.authz.SetRole(ctx, definer, "t1", later); err != nil {
		t.Fatal(err)
	}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{later.ID}}
	if err := h.authz.SetRole(ctx, admin, "t1", lister); err != nil {
		t.Fatal(err)
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
	done := make(chan error, 1)
	go func() { done <- h.authz.SetRole(ctx, admin, "t1", wider) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("SetRole didn't wait for the host: %v", err)
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
	if err := <-done; !errors.Is(err, rbac.ErrConflict) || allowed(t, h, h.as(t, "op"), login, cluster) {
		t.Fatalf("replacing a role created while the change waited, past the constraint: %v", err)
	}
	if err := h.authz.SetRole(ctx, admin, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("asked again, the constraint stops it: %v", err)
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

func TestACheckSpendsABoundedBudgetOnConditions(t *testing.T) {
	h := setup(t)
	var xs []string
	for i := range 90 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	costly := func(i int) string { return fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", list, list, i) }
	grants := func(prefix string, expr func(i int) string) []string {
		var groups []string
		var grants []rbac.Grant
		for i := range 20 {
			g := fmt.Sprintf("%s%02d", prefix, i)
			groups = append(groups, g)
			// The one that holds costs the most to compile, so it is evaluated last.
			e := expr(i)
			if i == 19 {
				e = "true || " + costly(0)
			}
			grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
				Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: e},
			}})
		}
		h.seed(t, grants...)
		return groups
	}
	groups := grants("g", costly)
	if !allowed(t, h, h.as(t, "one", "g19"), login, cluster) {
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
	same := grants("s", func(int) string { return costly(1) })
	if !allowed(t, h, h.as(t, "many", same...), login, cluster) {
		t.Fatal("a check paid for one condition again for each grant that has it")
	}
}

func longFalse(i int) string {
	var b strings.Builder
	b.WriteString("subject.id in [")
	for j := 0; ; j++ {
		item := fmt.Sprintf("%q,", fmt.Sprintf("contractor-%d-%04d", i, j))
		if b.Len()+len(item)+1 > rbac.MaxExpression-8 {
			break
		}
		b.WriteString(item)
	}
	return strings.TrimSuffix(b.String(), ",") + "]"
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
	// Three of the longest fit a scope; a fourth could leave a check's budget short of them, so it
	// is refused rather than stored to deny everyone they name.
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
	// A deny whose condition can't be evaluated denies, and Explain says why.
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{
		ID: "mfa", Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}},
		Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: "request.attributes.mfa != true"},
	}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a scope's conditional denies past the bound: %v", err)
	}
	if err := h.authz.SetDeny(ctx, guardian, workspace, rbac.Deny{
		ID: "d0", Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}},
		Permissions: []rbac.Permission{login}, Condition: rbac.Condition{Expression: "request.attributes.mfa != true"},
	}); err != nil {
		t.Fatal(err)
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

func TestEachPermissionIsDecidedOnItsOwnBudgets(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	var xs []string
	for i := range 38 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	// Five conditional denies of every cluster permission on each of the cluster, its workspace and
	// the tenant, each costly to evaluate and false.
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
	// And on a budget of its own for its grants' conditions: four costly ones that don't hold and,
	// costliest, one that does, which one budget for both permissions the role gives never reaches.
	var ys []string
	for i := range 90 {
		ys = append(ys, fmt.Sprint(i))
	}
	long := "[" + strings.Join(ys, ",") + "]"
	costly := func(i int) string { return fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", long, long, i) }
	grants := []rbac.Grant{{Scope: cluster.Scope(), Binding: conditional("cluster.login", "c", "true || "+costly(0))}}
	for i := range 4 {
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.login", "c", costly(i+1))})
	}
	h.seed(t, grants...)
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
	var xs []string
	for i := range 90 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	var grants []rbac.Grant
	for _, b := range []struct {
		role rbac.Role
		id   string
	}{{"cluster.login", "u"}, {guardRole.ID, "g"}} {
		for i := range 19 {
			grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(b.role, b.id, fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", list, list, i))})
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(b.role, b.id, "true")})
	}
	h.seed(t, grants...)
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
	var xs []string
	for i := range 90 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	costly := func(i int) string { return fmt.Sprintf("%s.all(x, %s.all(y, x >= -%d)) && false", list, list, i) }
	workspace := rbac.Scope{Type: "workspace", ID: "w1"}
	// The grant that holds is read first in one order of scopes and principals, and last in the
	// other.
	for _, holds := range []int{0, 19} {
		h := setup(t)
		var groups []string
		var grants []rbac.Grant
		for i := range 20 {
			g := fmt.Sprintf("g%02d", i)
			groups = append(groups, g)
			scope, expr := cluster.Scope(), costly(i)
			if i == holds {
				expr = "true || " + costly(0)
			}
			if (i == holds) == (holds == 0) {
				scope = workspace
			}
			grants = append(grants, rbac.Grant{Scope: scope, Binding: rbac.Binding{
				Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
			}})
		}
		h.seed(t, grants...)
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
	for i := range 21 {
		g := fmt.Sprintf("g%02d", i)
		groups = append(groups, g)
		expr := fmt.Sprintf(`%s.all(x, x >= 0) && %d == 0`, list, i+1)
		// The one that holds costs the most to compile, so it is evaluated last.
		if i == 20 {
			expr = "true || " + expr
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
			Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
		}})
	}
	// Storing them compiled them for h.authz; another Authorizer compiles them as it checks.
	h.seed(t, grants...)
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

// guarded sets up a guardian who may set denies anywhere in the tenant.
func guarded(t *testing.T) (*harness, rbac.Subject) {
	t.Helper()
	guard := rbac.RoleDefinition{
		ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("tenant"), rbac.DenyPermission("workspace"), rbac.DenyPermission("cluster")},
		ResourceTypes: []string{"tenant", "workspace", "cluster"},
	}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guard) })
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

// racing is a pool on which change commits just before the first statement that reads denies, as
// another session's change would commit between two of a read's statements.
type racing struct {
	*pgxpool.Pool
	change func()
}

func (r *racing) race(sql string) {
	if do := r.change; do != nil && strings.Contains(sql, "rbac_denies") {
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
	// A constraint can ask about the anonymous, who are in no group and no tenant.
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
