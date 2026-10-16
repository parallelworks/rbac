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
}

// A cluster in workspace w1 of org o1, owned by "owner".
var cluster = rbac.Resource{
	Tenant: "t1", Type: "cluster", ID: "c1", Owner: "owner",
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
	return h
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
	return rbac.Subject{Tenant: "t1", Principal: rbac.Principal{Kind: rbac.User, ID: id}, Groups: groups}
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
		{"another tenant", rbac.Subject{Tenant: "t2", Principal: rbac.Principal{Kind: rbac.User, ID: "direct"}}, login, false},
		{"the owner", user("owner"), root, true},
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

func TestConstraintsBindOwnersAndExplain(t *testing.T) {
	h := setup(t, constrain("no root", root))
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"))
	if allowed(t, h, user("owner"), root, cluster) || allowed(t, h, user("u"), root, cluster) {
		t.Fatal("a constraint should remove root from the owner and grants alike")
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
		t.Fatalf("owner's Permissions = %v, %v", perms, err)
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
		tenant text NOT NULL, id text NOT NULL, owner text NOT NULL DEFAULT '', path text[] NOT NULL)`); err != nil {
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
		r := rbac.Resource{Tenant: "t1", Type: "cluster", ID: fmt.Sprintf("c%d", i), Owner: fmt.Sprintf("owner%d", i), Ancestors: chain}
		if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3, $4)`, r.Tenant, r.ID, r.Owner, h.path(t, r)); err != nil {
			t.Fatal(err)
		}
		resources = append(resources, r)
	}
	// Another tenant's cluster, under a workspace with the same id.
	if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ('t2', 'x', '', '{cluster:x,workspace:w1,tenant:t2}')`); err != nil {
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
	)
	for _, s := range []rbac.Subject{user("u1", "g1"), user("u2"), user("all"), user("owner3"), user("nobody")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

func TestListingsApplyConstraintsToOwners(t *testing.T) {
	h := setup(t, constrain("no root", root))
	resources := hostTable(t, h)
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o2"}, "cluster.sudo", rbac.User, "u2"))
	for _, s := range []rbac.Subject{user("owner3"), user("u2")} {
		for _, p := range []rbac.Permission{login, root} {
			listingsAgree(t, h, resources, s, p)
		}
	}
}

// listingsAgree checks Filter and Reachable against Authorize, resource by resource.
func listingsAgree(t *testing.T, h *harness, resources []rbac.Resource, s rbac.Subject, p rbac.Permission) {
	t.Helper()
	pred, err := h.authz.Filter(t.Context(), s, p, "t1", "cluster", rbac.Columns{Tenant: "tenant", Owner: "owner", Path: "path"}, 1)
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
		in := reach.All || (reach.Owned && r.Owner == s.Principal.ID) || slices.ContainsFunc(reach.Scopes, func(sc rbac.Scope) bool {
			return slices.Contains(h.path(t, r), sc.Key())
		})
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
	pred, err := h.authz.Filter(ctx, rbac.Subject{Tenant: r.Tenant, Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}, login, r.Tenant, "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
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
	want := []rbac.Principal{{Kind: rbac.User, ID: "owner"}, {Kind: rbac.Group, ID: "admins"}}
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
	// The owner may grant anything on what they own.
	if err := h.authz.Apply(ctx, user("owner"), cluster, rbac.Change{Grant: []rbac.Binding{b("cluster.admin", "z")}}); err != nil {
		t.Fatalf("owner: %v", err)
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

func TestApplyCapsExpiryAtTheActorsOwn(t *testing.T) {
	h := setup(t)
	temp := grant(rbac.Scope{Type: "workspace", ID: "w1"}, "workspace.admin", rbac.User, "temp")
	// Finer than PostgreSQL keeps it.
	temp.ExpiresAt = h.now.Add(time.Hour + 500*time.Nanosecond)
	h.seed(t, temp, grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.User, "temp"))
	ctx := t.Context()
	forever := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.Group, ID: "friends"}}
	if err := h.authz.Apply(ctx, user("temp"), workspace, rbac.Change{Grant: []rbac.Binding{forever}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a grant outliving the actor's access: %v", err)
	}
	within := forever
	within.ExpiresAt = h.now.Add(30 * time.Minute)
	if err := h.authz.Apply(ctx, user("temp"), workspace, rbac.Change{Grant: []rbac.Binding{within}}); err != nil {
		t.Fatalf("a grant within the actor's access: %v", err)
	}
	until := forever
	until.ExpiresAt = temp.ExpiresAt
	if err := h.authz.Apply(ctx, user("temp"), workspace, rbac.Change{Grant: []rbac.Binding{until}}); err != nil {
		t.Fatalf("a grant ending when the actor's access does: %v", err)
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
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
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
	if err != nil || len(got) != 2 {
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
	if len(h.events) != 2 || len(h.events[0].Revoked) != 1 || len(h.events[1].Revoked) != 1 {
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

func TestContainerOwnersCantGrantBelowThem(t *testing.T) {
	h := setup(t)
	owned := workspace
	owned.Owner = "ws-owner"
	if !allowed(t, h, user("ws-owner"), "workspace:view", owned) {
		t.Fatal("an owner holds every permission on what they own")
	}
	if allowed(t, h, user("ws-owner"), "workspace:grant", owned) {
		t.Fatal("Authorize should agree with Apply that a container's owner can't change its grants")
	}
	if perms, err := h.authz.Permissions(t.Context(), user("ws-owner"), owned); err != nil || slices.Contains(perms, "workspace:grant") {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(t.Context(), owned, "workspace:grant"); err != nil || len(holders) != 0 {
		t.Fatalf("Holders(workspace:grant) = %v, %v", holders, err)
	}
	self := rbac.Binding{Role: "cluster.admin", Principal: rbac.Principal{Kind: rbac.User, ID: "ws-owner"}}
	if err := h.authz.Apply(t.Context(), user("ws-owner"), owned, rbac.Change{Grant: []rbac.Binding{self}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("owning a workspace mustn't grant the clusters in it: %v", err)
	}
	if allowed(t, h, user("ws-owner"), root, cluster) {
		t.Fatal("the workspace's owner gained root on a cluster in it")
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
	got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
	if err != nil || len(got) != 1 || got[0].CreatedBy != (rbac.Principal{Kind: rbac.User, ID: "owner"}) {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestSubjectsAreAnonymousOrOneIdentity(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1"))
	for name, s := range map[string]rbac.Subject{
		"groups and no identity":    {Tenant: "t1", Groups: []string{"service"}},
		"a tenant and no identity":  {Tenant: "t1"},
		"an identity and no tenant": {Principal: rbac.Principal{Kind: rbac.User, ID: "u"}},
		"a group":                   {Tenant: "t1", Principal: rbac.Principal{Kind: rbac.Group, ID: "g"}},
		"the tenant's members":      {Tenant: "t1", Principal: rbac.TenantMembers("t1")},
		"an undeclared kind":        {Tenant: "t1", Principal: rbac.Principal{Kind: "robot", ID: "r"}},
	} {
		if err := h.authz.Authorize(t.Context(), s, login, cluster); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := h.authz.Reachable(t.Context(), s, login, "t1", "cluster"); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Reachable %v", name, err)
		}
		if err := h.authz.Apply(t.Context(), s, cluster, rbac.Change{}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: Apply of no change %v", name, err)
		}
	}
	if !allowed(t, h, user("u"), login, cluster) {
		t.Fatal("a user is one of the tenant's members")
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

func TestOwnersHoldTheCatalogsPermissions(t *testing.T) {
	h := setup(t)
	if !allowed(t, h, user("owner"), root, cluster) {
		t.Fatal("an owner holds every permission a role gives on the type")
	}
	for _, p := range []rbac.Permission{"cluster:delete", "workspace:view"} {
		if allowed(t, h, user("owner"), p, cluster) {
			t.Errorf("an owner holds %s, which no role gives on clusters", p)
		}
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
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "gone"))
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
	// The same ids as t1's admin and the cluster's owner, in another tenant.
	admin2 := rbac.Subject{Tenant: "t2", Principal: rbac.Principal{Kind: rbac.User, ID: "admin"}}
	owner2 := rbac.Subject{Tenant: "t2", Principal: rbac.Principal{Kind: rbac.User, ID: "owner"}}
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's admin": admin2, "another tenant's owner": owner2, "a member": user("nobody")} {
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
	for name, s := range map[string]rbac.Subject{"anonymous": anonymous, "another tenant's admin": admin2} {
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
	ci := rbac.Subject{Tenant: "t1", Principal: rbac.Principal{Kind: machine, ID: "ci"}}
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

	// Only users own resources: a service account with the owner's id is someone else.
	impostor := rbac.Subject{Tenant: "t1", Principal: rbac.Principal{Kind: machine, ID: "owner"}}
	if allowed(t, h, impostor, root, cluster) {
		t.Fatal("a service account with the owner's id owns the cluster")
	}
	if reach, err := h.authz.Reachable(ctx, impostor, root, "t1", "cluster"); err != nil || reach.Owned {
		t.Fatalf("Reachable = %+v, %v", reach, err)
	}

	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Tenant, "t1"))
	if !allowed(t, h, rbac.Subject{Tenant: "t1", Principal: rbac.Principal{Kind: machine, ID: "bot"}}, login, cluster) {
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
