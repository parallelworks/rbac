package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/foundation/pgdb"
	"github.com/parallelworks/foundation/pgdb/pgdbtest"
	"github.com/parallelworks/foundation/rbac"
)

const urlEnv = "FOUNDATION_TEST_DATABASE_URL"

var errLookup = errors.New("membership lookup failed")

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

// A cluster in workspace w1 of org o1. setup grants "owner" its admin role, as a host does
// for whoever creates one.
var cluster = rbac.Resource{
	Tenant: "t1", Type: "cluster", ID: "c1",
	Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}},
}

var workspace = rbac.Resource{Tenant: "t1", Type: "workspace", ID: "w1", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}

type harness struct {
	pool   *pgxpool.Pool
	authz  *rbac.Authorizer
	now    time.Time
	events []rbac.ChangeEvent
}

func setup(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	pool := pgdbtest.Migrated(t, urlEnv, pgdb.Migrations{})
	if err := rbac.Migrate(t.Context(), pool, nil); err != nil {
		t.Fatal(err)
	}
	h := &harness{pool: pool, now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	cfg := rbac.Config{
		Catalog:        catalog,
		ContainerTypes: []string{"org", "workspace"},
		ValidatePrincipal: func(_ context.Context, _ rbac.DB, tenant string, p rbac.Principal) error {
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
	}
	for _, m := range mutate {
		m(&cfg)
	}
	authz, err := rbac.New(pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.authz = authz
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
		c.Constraints = []rbac.Constraint{{Name: name, Deny: func(_ context.Context, _ rbac.DB, _, _ string, q rbac.Permission) (bool, error) {
			return q == p, nil
		}}}
	}
}

func (h *harness) seed(t *testing.T, grants ...rbac.Grant) {
	t.Helper()
	if err := h.authz.Import(t.Context(), "t1", grants); err != nil {
		t.Fatal(err)
	}
}

func grant(scope rbac.Scope, role rbac.Role, kind rbac.PrincipalKind, id string) rbac.Grant {
	return rbac.Grant{Scope: scope, Binding: rbac.Binding{Role: role, Principal: rbac.Principal{Kind: kind, ID: id}}}
}

func user(id string, groups ...string) rbac.Subject {
	return rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: id}, Groups: groups, Tenants: []string{"t1"}}
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
	ok := func(context.Context, rbac.DB, string, rbac.Principal) error { return nil }
	for name, cfg := range map[string]rbac.Config{
		"no principal check":    {Catalog: catalog},
		"duplicate role":        {Catalog: append(slices.Clone(catalog), catalog[0]), ValidatePrincipal: ok},
		"bad permission":        {Catalog: []rbac.RoleDefinition{{ID: "r", Permissions: []rbac.Permission{"login"}, ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"no permissions":        {Catalog: []rbac.RoleDefinition{{ID: "r", ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"bad container":         {Catalog: catalog, ContainerTypes: []string{"tenant"}, ValidatePrincipal: ok},
		"a kind every host has": {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{rbac.Group}, ValidatePrincipal: ok},
		"a malformed kind":      {Catalog: catalog, PrincipalKinds: []rbac.PrincipalKind{"Service Account"}, ValidatePrincipal: ok},
		"a public admin role": {Catalog: []rbac.RoleDefinition{{
			ID: "r", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, Public: true,
		}}, ValidatePrincipal: ok},
		"a grantable role not in the catalog": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "r", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"nope"},
		}), ValidatePrincipal: ok},
		"grantable roles without a grant permission": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"},
		}), ValidatePrincipal: ok},
		"a built-in role named like a custom one": {Catalog: append(slices.Clone(catalog), rbac.RoleDefinition{
			ID: "custom.r", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"},
		}), ValidatePrincipal: ok},
		"a public privileged role": {Catalog: []rbac.RoleDefinition{{
			ID: "r", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}, Privileged: true, Public: true,
		}}, ValidatePrincipal: ok},
		"unnamed constraint": {Catalog: catalog, ValidatePrincipal: ok, Constraints: []rbac.Constraint{{
			Deny: func(context.Context, rbac.DB, string, string, rbac.Permission) (bool, error) { return true, nil },
		}}},
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
	if err := h.authz.Import(t.Context(), "t2", []rbac.Grant{
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
		{"on the resource", user("direct"), login, true},
		{"not more than the role", user("direct"), root, false},
		{"through a group on the workspace", user("someone", "ws-sudo"), root, true},
		{"on the org", user("org-user"), login, true},
		{"on the tenant", user("tenant-user"), login, true},
		{"on another workspace", user("elsewhere"), login, false},
		{"a role for another type", user("ws-admin"), view, false},
		{"no grant", user("nobody"), view, false},
		{"a grant in another tenant", user("elsewhere-tenant"), login, false},
		{"the creator's role", user("owner"), root, true},
	}
	for _, c := range cases {
		if got := allowed(t, h, c.s, c.p, cluster); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if !allowed(t, h, user("ws-admin"), "workspace:grant", workspace) {
		t.Error("workspace admin on the org should hold workspace:grant on its workspaces")
	}
}

func TestTenantMembersAndExpiry(t *testing.T) {
	h := setup(t)
	g := grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	if !allowed(t, h, user("anyone"), login, cluster) {
		t.Fatal("a grant to the tenant's members should reach any member")
	}
	h.now = h.now.Add(2 * time.Hour)
	if allowed(t, h, user("anyone"), login, cluster) {
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
	if allowed(t, h, user("owner"), root, cluster) || allowed(t, h, user("u"), root, cluster) {
		t.Fatal("a constraint should remove root from every grant")
	}
	d, err := h.authz.Explain(t.Context(), user("u"), root, cluster)
	if err != nil || d.Allowed || d.DeniedBy != "no root" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	d, err = h.authz.Explain(t.Context(), user("u"), login, cluster)
	if err != nil || !d.Allowed || len(d.Grants) != 1 || d.Grants[0].Role != "cluster.sudo" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	perms, err := h.authz.Permissions(t.Context(), user("u"), cluster)
	if err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	perms, err = h.authz.Permissions(t.Context(), user("owner"), cluster)
	if err != nil || !slices.Equal(perms, []rbac.Permission{grantC, login, view}) {
		t.Fatalf("admin's Permissions = %v, %v", perms, err)
	}
}

func TestMalformedInputIsAnErrorNotAnAllow(t *testing.T) {
	h := setup(t)
	bad := cluster
	bad.ID = ""
	if err := h.authz.Authorize(t.Context(), user("owner"), login, bad); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a resource with no id: %v", err)
	}
	if err := h.authz.Authorize(t.Context(), user("owner"), "login", cluster); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a malformed permission: %v", err)
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Ancestors: []rbac.Scope{{Type: "workspace", ID: "w1"}}}
	if err := h.authz.Authorize(t.Context(), user("u"), "tenant:grant", tenant); !errors.Is(err, rbac.ErrInvalid) {
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
	for _, s := range []rbac.Subject{user("u1", "g1"), user("u2"), user("all"), user("owner3"), user("nobody")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

func TestListingsApplyConstraints(t *testing.T) {
	h := setup(t, constrain("no root", root))
	resources := hostTable(t, h)
	h.seed(t,
		grant(rbac.Scope{Type: "org", ID: "o2"}, "cluster.sudo", rbac.User, "u2"),
		grant(rbac.Scope{Type: "cluster", ID: "c3"}, "cluster.admin", rbac.User, "owner3"),
	)
	for _, s := range []rbac.Subject{user("owner3"), user("u2")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

// listingsAgree checks Filter and Reachable against Authorize, resource by resource.
func listingsAgree(t *testing.T, h *harness, resources []rbac.Resource, s rbac.Subject, p rbac.Permission) {
	t.Helper()
	pred, err := h.authz.Filter(t.Context(), s, p, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(t.Context(), "SELECT id FROM clusters WHERE "+pred.SQL+" ORDER BY id", pred.Args...)
	if err != nil {
		t.Fatalf("%s: %v", pred.SQL, err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, r := range resources {
		if allowed(t, h, s, p, r) {
			want = append(want, r.ID)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("%v %s: Filter %v, Authorize %v", s.Principal, p, got, want)
	}

	reach, err := h.authz.Reachable(t.Context(), s, p, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	for _, r := range resources {
		// As Reach says a host reads it.
		holds := func(scopes []rbac.Scope) bool {
			return slices.ContainsFunc(scopes, func(sc rbac.Scope) bool { return slices.Contains(h.path(t, r), sc.Key()) })
		}
		var in bool
		switch {
		case holds(reach.Except):
		case holds(reach.Conditional):
			in = allowed(t, h, s, p, r)
		default:
			in = reach.All || holds(reach.Scopes)
		}
		if in {
			reached = append(reached, r.ID)
		}
	}
	if !slices.Equal(reached, want) {
		t.Errorf("%v %s: Reachable %v, Authorize %v", s.Principal, p, reached, want)
	}
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
	if err := h.authz.Import(ctx, r.Tenant, []rbac.Grant{grant(r.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
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

func TestHolders(t *testing.T) {
	h := setup(t)
	h.seed(t,
		grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.sudo", rbac.Group, "admins"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "u"),
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1"),
	)
	got, err := h.authz.Holders(t.Context(), cluster, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbac.Principal{{Kind: rbac.Group, ID: "admins"}, {Kind: rbac.User, ID: "owner"}}
	if !slices.Equal(got, want) {
		t.Errorf("Holders(root) = %v, want %v", got, want)
	}
	got, err = h.authz.Holders(t.Context(), cluster, login)
	if err != nil || len(got) != 4 {
		t.Errorf("Holders(login) = %v, %v", got, err)
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
	err := h.authz.Apply(ctx, user("ws-admin"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}})
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting what the actor doesn't hold: %v", err)
	}
	// Holds sudo on clusters here and may change access: can hand on login and sudo, not admin.
	if err := h.authz.Apply(ctx, user("manager"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x"), b("cluster.sudo", "y")}}); err != nil {
		t.Fatalf("granting what the actor holds: %v", err)
	}
	if err := h.authz.Apply(ctx, user("manager"), workspace, rbac.Change{Grant: []rbac.Binding{b("cluster.admin", "z")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting more than the actor holds: %v", err)
	}
	// No grant permission on the cluster itself.
	if err := h.authz.Apply(ctx, user("manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access without cluster:grant: %v", err)
	}
	// The creator's admin role holds every permission, so it may grant any role.
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.admin", "z")}}); err != nil {
		t.Fatalf("the creator: %v", err)
	}
	if !allowed(t, h, user("y"), root, cluster) || !allowed(t, h, user("z"), root, cluster) {
		t.Fatal("the grants should give what they say")
	}
	// Revoking needs only the grant permission.
	if err := h.authz.Apply(ctx, user("ws-admin"), workspace, rbac.Change{Revoke: []rbac.Binding{b("cluster.sudo", "y")}}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if allowed(t, h, user("y"), root, cluster) {
		t.Fatal("revoked access should be gone")
	}
}

func TestAGrantOutlivesTheActorsAccess(t *testing.T) {
	h := setup(t)
	temp := grant(rbac.Scope{Type: "workspace", ID: "w1"}, "workspace.admin", rbac.User, "temp")
	temp.ExpiresAt = h.now.Add(time.Hour)
	access := grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.User, "temp")
	access.ExpiresAt = temp.ExpiresAt
	h.seed(t, temp, access)
	forever := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "friends"}}
	if err := h.authz.Apply(t.Context(), user("temp"), workspace, rbac.Change{Grant: []rbac.Binding{forever}}); err != nil {
		t.Fatalf("access for an hour granting for good: %v", err)
	}
	h.now = h.now.Add(2 * time.Hour)
	if allowed(t, h, user("temp"), login, cluster) || !allowed(t, h, user("f", "friends"), login, cluster) {
		t.Fatal("the grant should outlive the access of whoever made it")
	}
}

func TestApplyValidatesEveryBinding(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "nope", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}},
		{Role: "workspace.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}},
		{Role: "cluster.admin", Principal: rbac.TenantMembers("t1")},
		{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "outsider1"}},
		{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, ExpiresAt: h.now.Add(-time.Minute)},
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
	if len(invalid) != 5 || !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("got %d invalid bindings: %v", len(invalid), err)
	}
	if len(h.events) != 0 {
		t.Fatal("an invalid change must store nothing")
	}
}

func TestApplyReportsARoleTheScopeCantTakeAsInvalid(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "admin"))
	b := rbac.Binding{Role: "workspace.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	err := h.authz.Apply(t.Context(), user("admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, rbac.ErrInvalid) || errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a role a cluster can't take: %v", err)
	}
}

func TestApplyChecksTheActorBeforePrincipals(t *testing.T) {
	asked := 0
	h := setup(t, func(c *rbac.Config) {
		c.ValidatePrincipal = func(context.Context, rbac.DB, string, rbac.Principal) error {
			asked++
			return errors.New("not a member")
		}
	})
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "someone"}}
	err := h.authz.Apply(t.Context(), user("nobody"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) || asked != 0 {
		t.Fatalf("a refused actor got %v after %d principal lookups", err, asked)
	}
}

func TestApplyAsksAboutEachPrincipalOnce(t *testing.T) {
	asked := 0
	h := setup(t, func(c *rbac.Config) {
		c.ValidatePrincipal = func(context.Context, rbac.DB, string, rbac.Principal) error {
			asked++
			return nil
		}
	})
	p := rbac.Principal{Kind: rbac.User, ID: "u"}
	c := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: p}, {Role: "cluster.sudo", Principal: p}}}
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, c); err != nil || asked != 1 {
		t.Fatalf("Apply = %v after %d principal lookups", err, asked)
	}
}

func TestApplyRespectsConstraints(t *testing.T) {
	h := setup(t, constrain("managed elsewhere", grantC))
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "admin"))
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for _, actor := range []string{"admin", "owner"} {
		if err := h.authz.Apply(t.Context(), user(actor), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s changed access that a constraint removes: %v", actor, err)
		}
	}
}

func TestImportKeepsTheLastOfRepeatedGrants(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	later := g
	later.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g, later)
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Principals: []rbac.Principal{g.Principal}})
	if err != nil || len(got) != 1 || !got[0].ExpiresAt.Equal(later.ExpiresAt) {
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
	reach, err := h.authz.Reachable(t.Context(), user("u"), root, "t1", "cluster")
	if err != nil || len(reach.Scopes) != 0 {
		t.Fatalf("changing the catalog after New reached %+v, %v", reach, err)
	}
	if got := h.authz.Roles("cluster"); len(got) != 3 || slices.Contains(got[2].Permissions, root) {
		t.Fatalf("Roles(cluster) = %+v", got)
	}
	if got := h.authz.Roles("workspace"); len(got) != len(catalog) {
		t.Fatalf("every role can be granted on a container, Roles(workspace) = %d", len(got))
	}
}

func TestApplyIsIdempotentAndReportsOnlyChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	for range 2 {
		if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.events) != 1 || len(h.events[0].Granted) != 1 || h.events[0].Actor != (rbac.Principal{Kind: rbac.User, ID: "owner"}) {
		t.Fatalf("events = %+v", h.events)
	}
	b.ExpiresAt = h.now.Add(time.Hour)
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
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
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err == nil {
		t.Fatal("the hook's error should fail the change")
	}
	if allowed(t, h, user("u"), login, cluster) {
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
		if err := h.authz.WithTx(tx).Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
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
		if got := allowed(t, h, user("u"), login, cluster); got != commit {
			t.Fatalf("commit=%v: grant present=%v", commit, got)
		}
	}
}

func TestHooksSeeTheHostsTransaction(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.ValidatePrincipal = func(ctx context.Context, q rbac.DB, _ string, p rbac.Principal) error {
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
	if err := h.authz.WithTx(tx).Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
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
	if err := h.authz.DeletePrincipal(ctx, "t1", rbac.Principal{Kind: rbac.Group, ID: "g"}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteScope(ctx, "t1", cluster.Scope()); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 2 || len(h.events[0].Revoked) != 1 || len(h.events[1].Revoked) != 2 {
		t.Fatalf("deletes should report what they removed: %+v", h.events)
	}
	if err := h.authz.DeleteTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, user("v"), login, cluster) {
		t.Fatal("a deleted tenant's grants should be gone")
	}
}

func TestMigrateIsRepeatable(t *testing.T) {
	h := setup(t)
	if err := rbac.Migrate(t.Context(), h.pool, nil); err != nil {
		t.Fatal(err)
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
	if err := authz.Import(ctx, "t1", creator); err != nil {
		t.Fatal(err)
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "friend"}}
	if err := authz.Apply(ctx, user("maker"), ws, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("the creator sharing what it holds: %v", err)
	}
	if err := authz.Apply(ctx, user("maker"), ws, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: b.Principal}}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("the creator granting more than its role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	inside := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "c9", Ancestors: []rbac.Scope{ws.Scope(), {Type: "org", ID: "o1"}}}
	if !allowed(t, h, user("friend"), login, inside) {
		t.Fatal("a grant on the new workspace should reach its clusters")
	}
}

func TestAFailedPrincipalLookupFailsTheChange(t *testing.T) {
	h := setup(t)
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "unreachable"}}
	err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}})
	if !errors.Is(err, errLookup) || errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a lookup failure should fail the change as it is, not as invalid input: %v", err)
	}
}

func TestHooksCanUseTheBusyPool(t *testing.T) {
	pool := pgdbtest.Open(t, urlEnv, "pool_max_conns=1")
	if err := pgdb.Migrate(t.Context(), pool, pgdb.Migrations{}); err != nil {
		t.Fatal(err)
	}
	if err := rbac.Migrate(t.Context(), pool, nil); err != nil {
		t.Fatal(err)
	}
	creator(t, pool)
	query := func(ctx context.Context) error {
		var one int
		return pool.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	authz, err := rbac.New(pool, rbac.Config{
		Catalog:           catalog,
		ContainerTypes:    []string{"org", "workspace"},
		ValidatePrincipal: func(ctx context.Context, _ rbac.DB, _ string, _ rbac.Principal) error { return query(ctx) },
		Constraints: []rbac.Constraint{{Name: "lookup", Deny: func(ctx context.Context, _ rbac.DB, _, _ string, _ rbac.Permission) (bool, error) {
			return false, query(ctx)
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("a hook on the pool the change runs on: %v", err)
	}
	tenant := rbac.TenantRoot("t1")
	if err := authz.Import(ctx, "t1", []rbac.Grant{grant(tenant, "tenant.roles", rbac.User, "owner"), grant(tenant, "cluster.login", rbac.User, "owner")}); err != nil {
		t.Fatal(err)
	}
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := authz.DefineRole(ctx, user("owner"), "t1", r); err != nil {
		t.Fatalf("a hook on the pool a role's definition runs on: %v", err)
	}
	if err := authz.DeleteRole(ctx, user("owner"), "t1", r.ID); err != nil {
		t.Fatalf("a hook on the pool a role's deletion runs on: %v", err)
	}
}

func TestReGrantingAnExpiredGrantRecordsTheNewActor(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	h.now = h.now.Add(2 * time.Hour)
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}})
	if err != nil || len(got) != 1 || got[0].CreatedBy != (rbac.Principal{Kind: rbac.User, ID: "owner"}) {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestSubjectsAreAnonymousOrOneIdentity(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1"))
	for name, s := range map[string]rbac.Subject{
		"groups and no identity":   {Groups: []string{"service"}},
		"a tenant and no identity": {Tenants: []string{"t1"}},
		"an empty tenant":          {Principal: rbac.Principal{Kind: rbac.User, ID: "u"}, Tenants: []string{""}},
		"a group":                  {Principal: rbac.Principal{Kind: rbac.Group, ID: "g"}, Tenants: []string{"t1"}},
		"the tenant's members":     {Principal: rbac.TenantMembers("t1")},
		"an undeclared kind":       {Principal: rbac.Principal{Kind: "robot", ID: "r"}, Tenants: []string{"t1"}},
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
	if !allowed(t, h, user("u"), login, cluster) {
		t.Fatal("a user is one of the tenant's members")
	}
	if allowed(t, h, rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}, login, cluster) {
		t.Fatal("an identity in no tenant is one of the tenant's members")
	}
}

func TestAncestorsMustBeContainers(t *testing.T) {
	h := setup(t)
	job := rbac.Resource{Tenant: "t1", Type: "job", ID: "j1", Ancestors: []rbac.Scope{cluster.Scope()}}
	if err := h.authz.Authorize(t.Context(), user("owner"), "job:view", job); !errors.Is(err, rbac.ErrInvalid) {
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
	if err := h.authz.Apply(t.Context(), user("m"), workspace, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a role for types the actor doesn't hold: %v", err)
	}
	// On one cluster it reaches only that cluster, where m holds cluster:view.
	if err := h.authz.Apply(t.Context(), user("m"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
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
				if err := h.authz.Apply(t.Context(), user("owner"), cluster, c); err != nil {
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
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}
	if err := h.authz.WithTx(tx).Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteScope(ctx, "t1", cluster.Scope()) }()
	// Commit only once DeleteScope has either finished or is waiting on the scope's lock.
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
	if allowed(t, h, user("u"), login, cluster) {
		t.Fatal("a grant made while its scope was deleted outlived the delete")
	}
}

func TestMigrateRunsBeforeTheApplication(t *testing.T) {
	pool := pgdbtest.Open(t, urlEnv, "")
	if err := rbac.Migrate(t.Context(), pool, nil); err != nil {
		t.Fatalf("rbac's tables before the schema exists: %v", err)
	}
	if err := pgdb.Migrate(t.Context(), pool, pgdb.Migrations{}); err != nil {
		t.Fatal(err)
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

	pred, err := h.authz.Filter(ctx, user("friend"), "job:view", "t1", "job", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
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
	reach, err := h.authz.Reachable(ctx, user("friend"), "job:view", "t1", "job")
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
			member := user("member")
			// A role that gives cluster:grant can't be public, so a grant of it to the public
			// gives nothing at all.
			others := 0
			if p.Kind == rbac.Tenant {
				others = 1
			}
			if allowed(t, h, member, root, cluster) != (others == 1) {
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
			holders, err := h.authz.Holders(ctx, cluster, grantC)
			if err != nil || slices.Contains(holders, p) {
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
			for perm, want := range map[rbac.Permission]int{root: others, grantC: 0} {
				pred, err := h.authz.Filter(ctx, member, perm, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				if err != nil {
					t.Fatal(err)
				}
				var n int
				if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM cs WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != want {
					t.Errorf("Filter %s: %d clusters, want %d", perm, n, want)
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
			return h.authz.Apply(ctx, user("owner"), cluster, c)
		})
	}
	for range 2 {
		run(func(int) error {
			return h.authz.Import(ctx, "t1", []rbac.Grant{
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
			return h.authz.Apply(ctx, user("owner"), cluster, c)
		})
	}
	for range 2 {
		run(func(int) error { return h.authz.DeletePrincipal(ctx, "t1", rbac.Principal{Kind: rbac.User, ID: "a"}) })
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
				err := authz.Apply(ctx, user("owner"), r, rbac.Change{Grant: []rbac.Binding{b}})
				applied.Done()
				if err != nil {
					return err
				}
				applied.Wait()
				return authz.DeletePrincipal(ctx, "t1", gone)
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
	if err := h.authz.Apply(ctx, user("admin"), workspace, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.viewer", Principal: public}}}); err != nil {
		t.Fatalf("granting a public role to the public: %v", err)
	}
	if err := h.authz.Apply(ctx, user("admin"), workspace, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: public}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting a role not marked public to the public: %v", err)
	}
	if err := h.authz.Import(ctx, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.Public, "")}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("importing a role not marked public for the public: %v", err)
	}

	anonymous := rbac.Subject{}
	stranger := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "stranger"}, Tenants: []string{"t2"}}
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's member": stranger, "a member": user("nobody")} {
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
	if holders, err := h.authz.Holders(ctx, cluster, view); err != nil || !slices.Contains(holders, public) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's member": stranger} {
		if err := h.authz.Apply(ctx, s, workspace, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s changed access: %v", name, err)
		}
	}

	if err := h.authz.DeletePrincipal(ctx, "t1", public); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("deleting the public's grants should end public access")
	}
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
		ValidatePrincipal: func(context.Context, rbac.DB, string, rbac.Principal) error { return nil },
		Now:               func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.authz = later
	for name, s := range map[string]rbac.Subject{"anonymous": {}, "a member": user("nobody")} {
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
	if holders, err := h.authz.Holders(ctx, cluster, root); err != nil || slices.Contains(holders, public) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
}

func TestHostsCanRefusePublicAccess(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), viewer)
		c.ValidatePrincipal = func(_ context.Context, _ rbac.DB, _ string, p rbac.Principal) error {
			if p.Kind == rbac.Public {
				return fmt.Errorf("%w: public access is off", rbac.ErrInvalid)
			}
			return nil
		}
	})
	b := rbac.Binding{Role: "cluster.viewer", Principal: rbac.Principal{Kind: rbac.Public}}
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a public grant the host refuses: %v", err)
	}
}

func TestMachineIdentities(t *testing.T) {
	const machine rbac.PrincipalKind = "service_account"
	h := setup(t, func(c *rbac.Config) { c.PrincipalKinds = []rbac.PrincipalKind{machine} })
	ctx := t.Context()
	ci := rbac.Subject{Principal: rbac.Principal{Kind: machine, ID: "ci"}, Tenants: []string{"t1"}}
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.admin", Principal: ci.Principal}}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, ci, root, cluster) {
		t.Fatal("a service account holds what it is granted")
	}
	if allowed(t, h, user("ci"), root, cluster) {
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

	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1"))
	if !allowed(t, h, rbac.Subject{Principal: rbac.Principal{Kind: machine, ID: "bot"}, Tenants: []string{"t1"}}, login, cluster) {
		t.Fatal("a service account is one of the tenant's members")
	}

	robot := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: "robot", ID: "r"}}
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{robot}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting an undeclared kind: %v", err)
	}
	// A kind the host stops declaring can still be revoked.
	undeclared, err := rbac.New(h.pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidatePrincipal: func(context.Context, rbac.DB, string, rbac.Principal) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if holders, err := undeclared.Holders(ctx, cluster, root); err != nil || slices.Contains(holders, ci.Principal) {
		t.Fatalf("Holders lists a kind no longer declared: %v, %v", holders, err)
	}
	revoke := rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.admin", Principal: ci.Principal}}}
	if err := undeclared.Apply(ctx, user("owner"), cluster, revoke); err != nil {
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
		{Kind: rbac.Tenant, ID: "t2"},
		{Kind: rbac.Tenant},
		{Kind: rbac.User},
		{Kind: "Service Account", ID: "x"},
		{Kind: rbac.PrincipalKind(strings.Repeat("k", 64)), ID: "x"},
	} {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'cluster', 'c1', $1, $2, 'cluster.login')`, p.Kind, p.ID); err == nil {
			t.Errorf("stored a grant to %+v", p)
		}
	}
	if err := h.authz.DeletePrincipal(t.Context(), "t1", rbac.Principal{}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("DeletePrincipal of no one: %v", err)
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
	apply := func(c rbac.Change) error { return h.authz.Apply(ctx, user("manager"), cluster, c) }
	if err := apply(rbac.Change{Grant: []rbac.Binding{b("cluster.login", "x")}}); err != nil {
		t.Fatalf("granting a listed role without holding it: %v", err)
	}
	if !allowed(t, h, user("x"), login, cluster) {
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
	if got := roles(user("manager")); !slices.Equal(got, []rbac.Role{"cluster.login"}) {
		t.Errorf("the manager's Grantable = %v", got)
	}
	if got := roles(user("owner")); !slices.Equal(got, []rbac.Role{"cluster.admin", "cluster.sudo", "cluster.login", "cluster.access"}) {
		t.Errorf("the admin's Grantable = %v", got)
	}
	if got := roles(user("y")); len(got) != 0 {
		t.Errorf("Grantable without a grant permission = %v", got)
	}
}

func TestGrantableAppliesConstraints(t *testing.T) {
	h := setup(t, constrain("managed elsewhere", grantC))
	if got, err := h.authz.Grantable(t.Context(), user("owner"), cluster); err != nil || len(got) != 0 {
		t.Fatalf("Grantable where a constraint removes cluster:grant = %v, %v", got, err)
	}
}

func TestIdentitiesFromOtherTenants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	partner := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "partner"}, Groups: []string{"partners"}, Tenants: []string{"t2"}}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.sudo", rbac.Tenant, "t1"))
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "cluster.login", Principal: partner.Principal},
	}}); err != nil {
		t.Fatalf("granting an identity from another tenant: %v", err)
	}
	if !allowed(t, h, partner, login, cluster) {
		t.Fatal("a grant to another tenant's member should reach it")
	}
	if allowed(t, h, partner, root, cluster) {
		t.Fatal("another tenant's member is one of this tenant's members")
	}
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{
		{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.Group, ID: "partners"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, partner, root, cluster) {
		t.Fatal("a grant to another tenant's group should reach its members")
	}
	outsider := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "outsider2"}}
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{outsider}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an identity the host doesn't let in: %v", err)
	}

	if err := h.authz.Import(ctx, "t2", []rbac.Grant{grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "partner")}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeletePrincipalEverywhere(ctx, partner.Principal); err != nil {
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
		if err := h.authz.DeletePrincipalEverywhere(ctx, p); !errors.Is(err, rbac.ErrInvalid) {
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
	if err := h.authz.Apply(ctx, user("sharer"), cluster, self("sharer", "cluster.helpdesk")); !errors.As(err, &denied) || denied.Permission != root {
		t.Fatalf("granting a role that lets its holders grant sudo, without root: %v", err)
	}
	// A grant permission limited to some roles isn't the unlimited one a role without a list gives.
	if err := h.authz.Apply(ctx, user("m"), workspace, self("m", "cluster.admin")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("turning a limited grant permission into an unlimited one: %v", err)
	}
	creator := rbac.Binding{Role: "cluster.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "owner"}}
	if err := h.authz.Apply(ctx, user("m"), cluster, rbac.Change{Revoke: []rbac.Binding{creator}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a limited manager revoking a role it doesn't list: %v", err)
	}
	// A role listing itself and roles the actor may grant needs nothing more: its holders pass
	// on only what it gives.
	if err := h.authz.Apply(ctx, user("sharer"), cluster, self("x", "cluster.relay")); err != nil {
		t.Fatalf("granting a role that lists itself: %v", err)
	}
	if err := h.authz.Apply(ctx, user("x"), cluster, self("y", "cluster.relay")); err != nil {
		t.Fatalf("a holder passing the role on: %v", err)
	}
	if err := h.authz.Apply(ctx, user("x"), cluster, self("y", "cluster.sudo")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a holder granting a role it doesn't list: %v", err)
	}
	if got, err := h.authz.Grantable(ctx, user("sharer"), cluster); err != nil || slices.ContainsFunc(got, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.helpdesk" }) {
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
	if err := h.authz.Apply(t.Context(), user("a"), workspace, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
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
	got, err := h.authz.Grantable(t.Context(), user("owner"), cluster)
	if err != nil || len(got) != len(h.authz.Roles("cluster")) {
		t.Fatalf("Grantable = %d roles, %v", len(got), err)
	}
}

func TestDeletePrincipalEverywhereAcrossManyTenants(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	support := rbac.Principal{Kind: rbac.Group, ID: "support"}
	const tenants = 70
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 'x' || g, 'tenant', 'x' || g, 'group', 'support', 'cluster.login' FROM generate_series(1, $1::int) g`, tenants); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeletePrincipalEverywhere(ctx, support); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_grants WHERE principal = 'group:support'`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d grants left, %v", left, err)
	}
	if len(h.events) != tenants {
		t.Fatalf("%d changes, want one per tenant", len(h.events))
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
	return user("admin")
}

func TestCustomRoles(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	operator := rbac.RoleDefinition{ID: "custom.operator", Name: "Operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	h.events = nil
	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Roles) != 1 || h.events[0].Roles[0].ID != operator.ID || h.events[0].Actor != admin.Principal {
		t.Fatalf("events = %+v", h.events)
	}
	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil || len(h.events) != 1 {
		t.Fatalf("defining a role again as it is reported a change: %+v, %v", h.events, err)
	}
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{{Role: operator.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "op"}}}}); err != nil {
		t.Fatalf("granting a custom role: %v", err)
	}
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, operator.ID, rbac.User, "op"))
	op := user("op")
	if !allowed(t, h, op, login, cluster) || allowed(t, h, op, root, cluster) {
		t.Fatal("a custom role should give what it lists and nothing more")
	}
	for _, p := range []rbac.Permission{login, root} {
		listingsAgree(t, h, resources, op, p)
	}
	if perms, err := h.authz.Permissions(ctx, op, cluster); err != nil || !slices.Equal(perms, []rbac.Permission{login, view}) {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, cluster, login); err != nil || !slices.Contains(holders, op.Principal) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
	if d, err := h.authz.Explain(ctx, op, login, cluster); err != nil || !d.Allowed || d.Grants[0].Role != operator.ID {
		t.Errorf("Explain = %+v, %v", d, err)
	}

	// Replacing it changes what its grants give.
	operator.Permissions = append(operator.Permissions, root)
	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, op, root, cluster) {
		t.Fatal("a replaced role's grants should give what it gives now")
	}
	listingsAgree(t, h, resources, op, root)

	roles, err := h.authz.RolesIn(ctx, "t1", "cluster")
	if err != nil || len(roles) != 4 || roles[3].ID != operator.ID || !slices.Contains(roles[3].Permissions, root) {
		t.Fatalf("RolesIn = %+v, %v", roles, err)
	}
	if !roles[3].Privileged {
		t.Fatal("a custom role giving root, which only privileged roles give, should be privileged")
	}
	if grantable, err := h.authz.Grantable(ctx, admin, cluster); err != nil || !slices.ContainsFunc(grantable, func(r rbac.RoleDefinition) bool { return r.ID == operator.ID }) {
		t.Fatalf("Grantable = %+v, %v", grantable, err)
	}
	if err := h.authz.Import(ctx, "t2", []rbac.Grant{grant(rbac.TenantRoot("t2"), operator.ID, rbac.User, "op")}); !errors.Is(err, rbac.ErrInvalid) {
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

	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.DeleteTenant(ctx, "t1"); err != nil {
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
	if err := h.authz.DefineRole(ctx, user("limited"), "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role with permissions the actor doesn't hold: %v", err)
	}
	if err := h.authz.DefineRole(ctx, user("no-roles"), "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role without tenant:define-roles: %v", err)
	}
	if err := h.authz.DefineRole(ctx, rbac.Subject{}, "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
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
		if err := h.authz.DefineRole(ctx, admin, "t1", r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}} {
		if err := h.authz.Import(ctx, "t1", []rbac.Grant{{Scope: tenant, Binding: rbac.Binding{Role: "tenant.roles", Principal: p}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("letting %s define roles: %v", p.Kind, err)
		}
	}
	if err := h.authz.DeleteRole(ctx, user("limited"), "t1", "cluster.admin"); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a built-in role: %v", err)
	}

	// Who may only hand a role out can't redefine it with more than it holds.
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{"tenant:grant"}, ResourceTypes: []string{"tenant"}, GrantableRoles: []rbac.Role{viewer.ID}}
	for _, r := range []rbac.RoleDefinition{viewer, lister} {
		if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(tenant, lister.ID, rbac.User, "helper"), grant(tenant, "tenant.roles", rbac.User, "helper"))
	wider := viewer
	wider.Permissions = []rbac.Permission{view, root}
	if err := h.authz.DefineRole(ctx, user("helper"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("redefining a role the actor may only hand out: %v", err)
	}
	// Nor can one who holds a role widen it, or what it hands out.
	h.seed(t, grant(tenant, viewer.ID, rbac.User, "helper"))
	if err := h.authz.DefineRole(ctx, user("helper"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("widening a role the actor holds: %v", err)
	}
	more := lister
	more.GrantableRoles = []rbac.Role{"cluster.admin"}
	if err := h.authz.DefineRole(ctx, user("helper"), "t1", more); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("widening what a role the actor holds hands out: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", viewer.ID); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("deleting a role another lists: %v", err)
	}

	// A custom role that hands out narrower ones.
	access := rbac.RoleDefinition{ID: "custom.access", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.login"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", access); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), access.ID, rbac.User, "manager"))
	b := func(role rbac.Role) rbac.Binding {
		return rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	}
	if err := h.authz.Apply(ctx, user("manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.login")}}); err != nil {
		t.Fatalf("a custom role's grantable role: %v", err)
	}
	if err := h.authz.Apply(ctx, user("manager"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.sudo")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a role a custom role doesn't list: %v", err)
	}
}

func TestDefiningRolesRespectsConstraints(t *testing.T) {
	h := setup(t, constrain("roles are managed elsewhere", rbac.DefineRoles))
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(t.Context(), admin, "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role a constraint forbids: %v", err)
	}
}

func TestPublicCustomRoles(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.DefineRole(ctx, admin, "t1", viewer); err != nil {
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
	if err := h.authz.DefineRole(ctx, admin, "t1", viewer); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, anonymous, view, cluster) {
		t.Fatal("a grant to the public should give nothing once its custom role isn't public")
	}
	listingsAgree(t, h, resources, anonymous, view)
	if holders, err := h.authz.Holders(ctx, cluster, view); err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.Public}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

func TestDeleteRoleRemovesAGrantMadeWhileItWaits(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	operator := rbac.RoleDefinition{ID: "custom.operator", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil {
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
			return a.DefineRole(ctx, admin, "t1", moved)
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
	if err := h.authz.DefineRole(ctx, admin, "t1", operator); err != nil {
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
	definer := user("definer")
	// Clusters can't take it yet, so listing it for clusters needs no power over it.
	later := rbac.RoleDefinition{ID: "custom.later", Permissions: []rbac.Permission{rbac.DefineRoles}, ResourceTypes: []string{"tenant"}}
	if err := h.authz.DefineRole(ctx, definer, "t1", later); err != nil {
		t.Fatal(err)
	}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{later.ID}}
	if err := h.authz.DefineRole(ctx, admin, "t1", lister); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), lister.ID, rbac.User, "manager"))
	sudo := later
	sudo.Permissions, sudo.ResourceTypes = []rbac.Permission{view, login, root}, []string{"cluster"}
	if err := h.authz.DefineRole(ctx, definer, "t1", sudo); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("letting a role's holders grant root without the power to grant it: %v", err)
	}
	if err := h.authz.Apply(ctx, user("manager"), cluster, rbac.Change{Grant: []rbac.Binding{{Role: later.ID, Principal: rbac.Principal{Kind: rbac.User, ID: "manager"}}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("granting the listed role on a cluster: %v", err)
	}
	if err := h.authz.DefineRole(ctx, admin, "t1", sudo); err != nil {
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
	if err := h.authz.DefineRole(ctx, admin, "t1", secrets); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a public role giving what only a privileged role gives on its type: %v", err)
	}
	secrets.Public = false
	if err := h.authz.DefineRole(ctx, admin, "t1", secrets); err != nil {
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
	if err := h.authz.DefineRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, op.ID, rbac.User, "op"))
	// The host deploys a catalog that no longer gives root.
	without := slices.Clone(catalog)
	for i, r := range without {
		without[i].Permissions = slices.DeleteFunc(slices.Clone(r.Permissions), func(p rbac.Permission) bool { return p == root })
	}
	later, err := rbac.New(h.pool, rbac.Config{
		Catalog: without, ContainerTypes: []string{"org", "workspace"},
		ValidatePrincipal: func(context.Context, rbac.DB, string, rbac.Principal) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Authorize(ctx, user("op"), root, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a custom role giving a permission the catalog dropped: %v", err)
	}
	if reach, err := later.Reachable(ctx, user("op"), root, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}
	pred, err := later.Filter(ctx, user("op"), root, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 0 {
		t.Fatalf("Filter kept %d clusters, %v", n, err)
	}
	if holders, err := later.Holders(ctx, resources[0], root); err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.User, ID: "op"}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	if roles, err := later.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || slices.Contains(roles[0].Permissions, root) {
		t.Fatalf("CustomRoles = %+v, %v", roles, err)
	}
	if err := later.Authorize(ctx, user("op"), login, cluster); err != nil {
		t.Fatalf("what the catalog still has: %v", err)
	}
}

func TestPublicCustomRolesFollowTheCatalog(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	admin := roleAdmin(t, h)
	pub := rbac.RoleDefinition{ID: "custom.pub", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}, Public: true}
	if err := h.authz.DefineRole(ctx, admin, "t1", pub); err != nil {
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
		ValidatePrincipal: func(context.Context, rbac.DB, string, rbac.Principal) error { return nil },
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
	if holders, err := h.authz.Holders(ctx, cluster, view); err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.Public}) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
}

func TestARoleListingItselfIsPrivilegedOnlyForWhatItIs(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "workspace.owner", Permissions: []rbac.Permission{"workspace:view", "workspace:grant", "workspace:delete"}, ResourceTypes: []string{"workspace"}, Privileged: true,
		})
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.owner", rbac.User, "admin"))
	r := rbac.RoleDefinition{ID: "custom.self", ResourceTypes: []string{"workspace"}, GrantableRoles: []rbac.Role{"custom.self"}}
	for _, perms := range [][]rbac.Permission{{"workspace:view", "workspace:grant", "workspace:delete"}, {"workspace:view", "workspace:grant"}} {
		r.Permissions = perms
		if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil {
			t.Fatal(err)
		}
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || roles[0].Privileged {
		t.Fatalf("a role listing itself should stop being privileged with what made it so: %+v, %v", roles, err)
	}
}

func TestDefiningRolesIsCanonicalBoundedAndMarksPrivilege(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{login, view, view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	r.Permissions = []rbac.Permission{view, login}
	if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil || len(h.events) != 0 {
		t.Fatalf("the same role reordered changed it: %+v, %v", h.events, err)
	}
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"cluster.sudo"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", lister); err != nil {
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
		if err := h.authz.DefineRole(ctx, admin, "t1", d); err != nil {
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
	if err := h.authz.DefineRole(ctx, admin, "t1", many); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a role listing 65 roles: %v", err)
	}
	fill(66, 296)
	extra := rbac.RoleDefinition{ID: "custom.extra", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", extra); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a tenant's 301st custom role: %v", err)
	}
	if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil {
		t.Fatalf("redefining a role in a full tenant: %v", err)
	}
}

func TestDeletingARoleRespectsConstraints(t *testing.T) {
	stop := false
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "managed elsewhere", Deny: func(_ context.Context, _ rbac.DB, _, _ string, p rbac.Permission) (bool, error) {
			return stop && p == grantC, nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	op := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), op.ID, rbac.User, "op"))
	stop = true
	if err := h.authz.DeleteRole(ctx, admin, "t1", op.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("deleting a role revokes grants a constraint keeps: %v", err)
	}
	gutted := op
	gutted.Permissions, gutted.ResourceTypes = []rbac.Permission{"tenant:view"}, []string{"tenant"}
	if err := h.authz.DefineRole(ctx, admin, "t1", gutted); !errors.Is(err, rbac.ErrDenied) || !allowed(t, h, user("op"), view, cluster) {
		t.Fatalf("redefining a role changes grants a constraint keeps: %v", err)
	}
	renamed := op
	renamed.Name = "Operator"
	if err := h.authz.DefineRole(ctx, admin, "t1", renamed); err != nil {
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
	got, err := h.authz.Grantable(t.Context(), user("sharer"), cluster)
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
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authz := h.authz.WithTx(tx)
	for name, change := range map[string]func() error{
		"Apply":       func() error { return authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}) },
		"Import":      func() error { return authz.Import(ctx, "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}) },
		"DeleteScope": func() error { return authz.DeleteScope(ctx, "t1", cluster.Scope()) },
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
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a plain permission the actor holds only for another type: %v", err)
	}
	if err := h.authz.Apply(ctx, user("holder"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); err != nil {
		t.Fatalf("granting a role the actor holds on the same cluster: %v", err)
	}
}

func TestDefiningARoleDerivesPrivilegeAndChecksTheActorFirst(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	plain := rbac.RoleDefinition{ID: "custom.plain", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Privileged: true}
	if err := h.authz.DefineRole(ctx, admin, "t1", plain); err != nil {
		t.Fatal(err)
	}
	if roles, err := h.authz.CustomRoles(ctx, "t1"); err != nil || len(roles) != 1 || roles[0].Privileged {
		t.Fatalf("a role giving only what unprivileged roles give should not be privileged: %+v, %v", roles, err)
	}
	// Public and marked privileged, though nothing it gives is: the flag is derived.
	public := plain
	public.ID, public.Public = "custom.public", true
	if err := h.authz.DefineRole(ctx, admin, "t1", public); err != nil {
		t.Fatalf("a public role marked privileged that gives nothing privileged: %v", err)
	}
	// Characters, not bytes, as the table counts them.
	named := plain
	named.ID, named.Name = "custom.named", strings.Repeat("역", 128)
	if err := h.authz.DefineRole(ctx, admin, "t1", named); err != nil {
		t.Fatalf("a name of 128 characters: %v", err)
	}
	// Past its limit, or text PostgreSQL refuses.
	for _, name := range []string{strings.Repeat("n", 129), "a\x00b", "\xff"} {
		bad := plain
		bad.Name = name
		if err := h.authz.DefineRole(ctx, admin, "t1", bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("a name %q: %v", name, err)
		}
	}
	// A character split between the name and the description is valid only joined.
	split := plain
	split.Name, split.Description = "\xe4\xb8", "\xad"
	if err := h.authz.DefineRole(ctx, admin, "t1", split); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a character split between name and description: %v", err)
	}
	// Refused for who it is, not for what it asked: it learns nothing of the catalog.
	guess := rbac.RoleDefinition{ID: "custom.guess", Permissions: []rbac.Permission{"cluster:fly"}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.DefineRole(ctx, user("nobody"), "t1", guess); !errors.Is(err, rbac.ErrDenied) || errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an actor who may not define roles probing the catalog: %v", err)
	}
}

func TestRedefiningARoleForATypeAgainRespectsConstraints(t *testing.T) {
	stop := false
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bucket.reader", Permissions: []rbac.Permission{"bucket:read"}, ResourceTypes: []string{"bucket", "cluster"}})
		c.Constraints = []rbac.Constraint{{Name: "managed elsewhere", Deny: func(_ context.Context, _ rbac.DB, _, _ string, p rbac.Permission) (bool, error) {
			return stop && p == "bucket:grant", nil
		}}}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "bucket.reader", rbac.User, "admin"))
	reader := rbac.RoleDefinition{ID: "custom.reader", Permissions: []rbac.Permission{"bucket:read"}, ResourceTypes: []string{"bucket", "cluster"}}
	if err := h.authz.DefineRole(ctx, admin, "t1", reader); err != nil {
		t.Fatal(err)
	}
	bucket := rbac.Resource{Tenant: "t1", Type: "bucket", ID: "b1"}
	h.seed(t, grant(bucket.Scope(), reader.ID, rbac.User, "u"))
	narrowed := reader
	narrowed.ResourceTypes = []string{"cluster"}
	if err := h.authz.DefineRole(ctx, admin, "t1", narrowed); err != nil {
		t.Fatal(err)
	}
	stop = true
	// Its grant on the bucket gives nothing now, and would give again.
	if err := h.authz.DefineRole(ctx, admin, "t1", reader); !errors.Is(err, rbac.ErrDenied) || allowed(t, h, user("u"), "bucket:read", bucket) {
		t.Fatalf("bringing back grants on a type a constraint keeps: %v", err)
	}
}

func TestARoleHandingOutOneThatBecomesPrivilegedIsPrivileged(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{
			ID: "workspace.owner", Permissions: []rbac.Permission{"workspace:view", "workspace:grant", "workspace:delete"}, ResourceTypes: []string{"workspace"}, Privileged: true,
		})
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(rbac.TenantRoot("t1"), "workspace.owner", rbac.User, "admin"))
	ws := []string{"workspace"}
	plain := []rbac.Permission{"workspace:view", "workspace:grant"}
	owner := []rbac.Permission{"workspace:view", "workspace:grant", "workspace:delete"}
	b := rbac.RoleDefinition{ID: "custom.b", Permissions: plain, ResourceTypes: ws}
	a := rbac.RoleDefinition{ID: "custom.a", Permissions: []rbac.Permission{"workspace:grant"}, ResourceTypes: ws, GrantableRoles: []rbac.Role{b.ID}}
	privileged := func() []bool {
		t.Helper()
		roles, err := h.authz.CustomRoles(ctx, "t1")
		if err != nil {
			t.Fatal(err)
		}
		var flags []bool
		for _, r := range roles {
			flags = append(flags, r.Privileged)
		}
		return flags
	}
	define := func(d rbac.RoleDefinition) {
		t.Helper()
		if err := h.authz.DefineRole(ctx, admin, "t1", d); err != nil {
			t.Fatal(err)
		}
	}
	define(b)
	define(a)
	// b, which a lists, comes to give what only a privileged role gives, and lists a back.
	b.Permissions, b.GrantableRoles = owner, []rbac.Role{a.ID}
	define(b)
	if got := privileged(); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("a role handing out one that became privileged: %v", got)
	}
	// a, defined again while b is privileged, is stored privileged. Once b gives nothing
	// privileged, a read clears both, whatever their stored flags say.
	define(a)
	b.Permissions = plain
	define(b)
	if got := privileged(); !slices.Equal(got, []bool{false, false}) {
		t.Fatalf("roles listing each other, neither privileged: %v", got)
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
	if err := h.authz.WithTx(tx).DefineRole(ctx, admin, "t1", op); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).Import(ctx, "t1", []rbac.Grant{grant(cluster.Scope(), op.ID, rbac.User, "op")}); err != nil {
		t.Fatal(err)
	}
	wider := op
	wider.Permissions = []rbac.Permission{view, login}
	done := make(chan error, 1)
	go func() { done <- h.authz.DefineRole(ctx, admin, "t1", wider) }()
	for waiting := false; !waiting; {
		select {
		case err := <-done:
			t.Fatalf("DefineRole didn't wait for the host: %v", err)
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
	if err := <-done; !errors.Is(err, rbac.ErrConflict) || allowed(t, h, user("op"), login, cluster) {
		t.Fatalf("replacing a role created while the change waited, past the constraint: %v", err)
	}
	if err := h.authz.DefineRole(ctx, admin, "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("asked again, the constraint stops it: %v", err)
	}
}

func TestPublicCustomRolesThatChangeAccessGiveNothingInSearches(t *testing.T) {
	share := rbac.RoleDefinition{ID: "cluster.share", Permissions: []rbac.Permission{view, grantC}, ResourceTypes: []string{"cluster"}}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), share) })
	ctx := t.Context()
	resources := hostTable(t, h)
	// Stored by the host, past DefineRole, which refuses a public role that changes access.
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
	if holders, err := h.authz.Holders(ctx, cluster, view); err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.Public}) {
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
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{
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
		{"a resource attribute that holds", ctx, user("c"), login, dev, true},
		{"one that doesn't", ctx, user("c"), login, prod, false},
		{"one the host didn't pass", ctx, user("c"), login, cluster, false},
		{"before a time", ctx, user("late"), login, cluster, true},
		{"a request attribute", rbac.WithRequest(ctx, map[string]any{"mfa": true}), user("mfa"), login, cluster, true},
		{"without it", ctx, user("mfa"), login, cluster, false},
		{"a subject attribute", ctx, rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "ops"}, Tenants: []string{"t1"}, Attributes: map[string]any{"dept": "ops"}}, login, cluster, true},
		{"the action it names", ctx, user("viewer"), view, cluster, true},
		{"another action", ctx, user("viewer"), login, cluster, false},
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
	if allowed(t, h, user("late"), login, cluster) {
		t.Error("a condition on the time should stop holding")
	}
	if perms, err := h.authz.Permissions(ctx, user("viewer"), cluster); err != nil || !slices.Equal(perms, []rbac.Permission{view}) {
		t.Errorf("Permissions = %v, %v", perms, err)
	}
	// An unconditional grant beside a conditional one allows on its own: on the workspace, since
	// one on the cluster would replace it.
	h.seed(t, grant(rbac.Scope{Type: "workspace", ID: "w1"}, "cluster.login", rbac.User, "c"))
	if !allowed(t, h, user("c"), login, prod) {
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
		err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}})
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	titled := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, Condition: rbac.Condition{Title: "t"}}
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{titled}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a title without an expression: %v", err)
	}
	titledLong := conditional("cluster.login", "x", "true")
	titledLong.Condition.Title = strings.Repeat("t", 129)
	described := conditional("cluster.login", "x", "true")
	described.Condition.Description = strings.Repeat("d", 2049)
	for _, b := range []rbac.Binding{titledLong, described} {
		if err := h.authz.Import(t.Context(), "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a title or description too long: %v", err)
		}
	}
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", `resource.id.matches("^c[0-9]{1,3}$")`)}}); err != nil {
		t.Fatalf("a small pattern: %v", err)
	}
	if !allowed(t, h, user("x"), login, cluster) {
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
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, user("x"), login, cluster) {
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
	if allowed(t, h, user("compares"), login, large) {
		t.Error("comparing large nested values should be past the cost limit")
	}
	if !allowed(t, h, user("finds"), login, large) {
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
	reach, err := h.authz.Reachable(ctx, user("both"), login, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reach.Scopes, []rbac.Scope{{Type: "workspace", ID: "w1"}}) || !slices.Equal(reach.Conditional, []rbac.Scope{{Type: "org", ID: "o2"}}) {
		t.Fatalf("Reachable = %+v", reach)
	}
	pred, err := h.authz.Filter(ctx, user("both"), login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
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
		if slices.Contains(got, r.ID) && !allowed(t, h, user("both"), login, r) {
			t.Errorf("Filter kept %s, which Authorize refuses", r.ID)
		}
	}
	if !slices.Equal(got, []string{"c0"}) {
		t.Errorf("Filter kept %v, want only the unconditionally reached c0", got)
	}
	if holders, err := h.authz.Holders(ctx, resources[2], login); err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.User, ID: "both"}) {
		t.Errorf("Holders = %v, %v", holders, err)
	}
	if !allowed(t, h, user("both"), login, resources[2]) {
		t.Error("Authorize should allow through the conditional grant")
	}
}

func TestConditionalGrantsInChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	mfa := `request.attributes.mfa == true`
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: conditional("cluster.admin", "admin", mfa)})
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(ctx, user("admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access through a condition that doesn't hold: %v", err)
	}
	withMFA := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	// Held only under a condition, a permission can't be handed on without it.
	if err := h.authz.Apply(withMFA, user("admin"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("dropping the condition the actor holds a role under: %v", err)
	}
	same := b
	same.Condition = rbac.Condition{Expression: mfa}
	// Its power to change grants holds only where its condition does.
	if err := h.authz.Apply(ctx, user("admin"), cluster, rbac.Change{Grant: []rbac.Binding{same}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access through a condition that doesn't hold now: %v", err)
	}
	if err := h.authz.Apply(withMFA, user("admin"), cluster, rbac.Change{Grant: []rbac.Binding{same}}); err != nil {
		t.Fatalf("handing on a permission under the same condition: %v", err)
	}
	h.events = nil
	other := same
	other.Condition = rbac.Condition{Title: "office", Expression: `request.attributes.office == true`}
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{other}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || h.events[0].Granted[0].Condition != other.Condition {
		t.Fatalf("a new condition should replace the old and be reported: %+v", h.events)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{b.Principal}}); err != nil || len(got) != 1 || got[0].Condition != other.Condition {
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
		if err := h.authz.DefineRole(ctx, admin, "t1", r); err != nil {
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
		if err := h.authz.Apply(withMFA, user("p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("granting %s without the condition of the power it gives: %v", role, err)
		}
		self.Condition = rbac.Condition{Expression: mfa}
		self.Principal.ID = "x"
		if err := h.authz.Apply(withMFA, user("p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); err != nil {
			t.Errorf("granting %s under the condition of the power it gives: %v", role, err)
		}
	}
	wider := granter
	wider.ID = "custom.wider"
	if err := h.authz.DefineRole(withMFA, user("definer"), "t1", wider); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("defining a role that gives a power held only under a condition: %v", err)
	}
}

func TestARoleAConditionalGrantListsIsGrantedOnlyUnderItsCondition(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	mfa := `request.attributes.mfa == true`
	withMFA := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	lister := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{"custom.lister", "cluster.sudo"}}
	if err := h.authz.DefineRole(ctx, roleAdmin(t, h), "t1", lister); err != nil {
		t.Fatal(err)
	}
	h.seed(t, rbac.Grant{Scope: cluster.Scope(), Binding: conditional(lister.ID, "p", mfa)})
	// With a second factor once, p would otherwise grant itself sudo, or the lister, without one.
	for _, role := range []rbac.Role{"cluster.sudo", lister.ID} {
		self := rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "p"}}
		if err := h.authz.Apply(withMFA, user("p"), cluster, rbac.Change{Grant: []rbac.Binding{self}}); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("granting %s through a conditional listing without its condition: %v", role, err)
		}
		other := rbac.Binding{Role: role, Principal: rbac.Principal{Kind: rbac.User, ID: "x"}, Condition: rbac.Condition{Expression: mfa}}
		if err := h.authz.Apply(withMFA, user("p"), cluster, rbac.Change{Grant: []rbac.Binding{other}}); err != nil {
			t.Errorf("granting %s through a conditional listing under its condition: %v", role, err)
		}
	}
	if allowed(t, h, user("p"), root, cluster) {
		t.Error("p should hold root only through a grant it may not make")
	}
	if roles, err := h.authz.Grantable(withMFA, user("p"), cluster); err != nil || len(roles) != 0 {
		t.Errorf("Grantable offers only what the actor may grant unconditionally: %v, %v", roles, err)
	}
	revoke := rbac.Binding{Role: "cluster.sudo", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(withMFA, user("p"), cluster, rbac.Change{Revoke: []rbac.Binding{revoke}}); err != nil {
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
	if err := h.authz.DefineRole(ctx, user("definer"), "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role without the condition the right to holds under: %v", err)
	}
	if err := h.authz.DefineRole(rbac.WithRequest(ctx, map[string]any{"mfa": true}), user("definer"), "t1", r); err != nil {
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
	costly := list + ".all(x, " + list + ".all(y, x >= 0)) && false"
	var groups []string
	var grants []rbac.Grant
	for i := range 20 {
		g := fmt.Sprintf("g%02d", i)
		groups = append(groups, g)
		expr := costly
		if i == 19 {
			expr = "true"
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
			Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
		}})
	}
	h.seed(t, grants...)
	if !allowed(t, h, user("one", "g19"), login, cluster) {
		t.Fatal("a condition that holds should allow")
	}
	// Spent on the grants before it, the check never reaches the one that holds.
	if allowed(t, h, user("many", groups...), login, cluster) {
		t.Fatal("a check should stop spending on conditions past its budget")
	}
}

func TestExplainSpendsTheBudgetAsAuthorizeDoes(t *testing.T) {
	var xs []string
	for i := range 90 {
		xs = append(xs, fmt.Sprint(i))
	}
	list := "[" + strings.Join(xs, ",") + "]"
	costly := list + ".all(x, " + list + ".all(y, x >= 0)) && false"
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
			scope, expr := cluster.Scope(), costly
			if i == holds {
				expr = "true"
			}
			if (i == holds) == (holds == 0) {
				scope = workspace
			}
			grants = append(grants, rbac.Grant{Scope: scope, Binding: rbac.Binding{
				Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
			}})
		}
		h.seed(t, grants...)
		s := user("many", groups...)
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
		if i == 20 {
			expr = "true"
		}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: rbac.Binding{
			Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: g}, Condition: rbac.Condition{Expression: expr},
		}})
	}
	// Storing them compiled them for h.authz; another Authorizer compiles them as it checks.
	h.seed(t, grants...)
	fresh, err := rbac.New(h.pool, rbac.Config{
		Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
		ValidatePrincipal: func(context.Context, rbac.DB, string, rbac.Principal) error { return nil },
		Now:               func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	s := user("many", groups...)
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
	if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{conditional("cluster.login", "x", expr)}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, user("x"), login, cluster) {
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
		if err := h.authz.Apply(t.Context(), user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply(%q) = %v", c, err)
		}
		if err := h.authz.Import(t.Context(), "t1", []rbac.Grant{{Scope: cluster.Scope(), Binding: b}}); !errors.Is(err, rbac.ErrInvalid) {
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
	return h, user("guardian")
}

func TestDenies(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	resources := hostTable(t, h)
	h.seed(t,
		grant(workspace.Scope(), "cluster.sudo", rbac.Group, "contractors"),
		grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.sudo", rbac.User, "named"),
	)
	contractor, lead := user("c", "contractors"), user("lead", "contractors")
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
	if allowed(t, h, contractor, root, cluster) || allowed(t, h, user("named"), root, cluster) {
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
	if holders, err := h.authz.Holders(ctx, cluster, root); err != nil || slices.ContainsFunc(holders, func(p rbac.Principal) bool { return p.ID == "named" || p.ID == "contractors" }) {
		t.Fatalf("Holders = %v, %v", holders, err)
	}
	for _, s := range []rbac.Subject{contractor, lead, user("named")} {
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
	if allowed(t, h, user("owner"), view, cluster) || allowed(t, h, rbac.Subject{}, view, cluster) {
		t.Fatal("a deny of cluster:* to the public should remove every cluster permission from everyone")
	}
	if reach, err := h.authz.Reachable(ctx, user("owner"), view, "t1", "cluster"); err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Fatalf("Reachable under a tenant-wide deny = %+v, %v", reach, err)
	}
	if err := h.authz.DeleteDeny(ctx, guardian, tenant, "freeze"); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, h, user("owner"), view, cluster) {
		t.Fatal("deleting a deny should end it")
	}
	if err := h.authz.DeleteScope(ctx, "t1", workspace.Scope()); err != nil {
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
		Condition: rbac.Condition{Expression: `request.attributes.vpn != true`},
	}
	if err := h.authz.SetDeny(ctx, guardian, workspace, d); err != nil {
		t.Fatal(err)
	}
	check := func(attrs map[string]any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, attrs), user("owner"), login, cluster)
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
	reach, err := h.authz.Reachable(ctx, user("owner"), login, "t1", "cluster")
	if err != nil || !slices.Contains(reach.Conditional, workspace.Scope()) || slices.Contains(reach.Except, workspace.Scope()) {
		t.Fatalf("Reachable = %+v, %v", reach, err)
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
	if err := h.authz.Apply(ctx, user("owner"), cluster, b("cluster.sudo")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("granting a permission a deny removes from the actor: %v", err)
	}
	if err := h.authz.Apply(ctx, user("owner"), cluster, b("cluster.login")); err != nil {
		t.Fatalf("granting what no deny removes: %v", err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "frozen", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{owner}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Apply(ctx, user("owner"), cluster, b("cluster.login")); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing access a deny removes: %v", err)
	}
}

func TestSettingADenyIsChecked(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	d := rbac.Deny{ID: "d", Permissions: []rbac.Permission{root}, Principals: []rbac.Principal{{Kind: rbac.Public}}}
	for name, s := range map[string]rbac.Subject{"without the deny permission": user("owner"), "anonymous": {}} {
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
	} {
		if err := h.authz.SetDeny(ctx, guardian, cluster, bad); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, p := range []rbac.Principal{rbac.TenantMembers("t1"), {Kind: rbac.Public}} {
		if err := h.authz.Import(ctx, "t1", []rbac.Grant{{Scope: rbac.TenantRoot("t1"), Binding: rbac.Binding{Role: "guard", Principal: p}}}); !errors.Is(err, rbac.ErrInvalid) {
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
