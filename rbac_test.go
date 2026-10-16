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
	return rbac.Subject{Tenant: "t1", User: id, Groups: groups}
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
		"no principal check": {Catalog: catalog},
		"duplicate role":     {Catalog: append(slices.Clone(catalog), catalog[0]), ValidatePrincipal: ok},
		"bad permission":     {Catalog: []rbac.RoleDefinition{{ID: "r", Permissions: []rbac.Permission{"login"}, ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"no permissions":     {Catalog: []rbac.RoleDefinition{{ID: "r", ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"bad container":      {Catalog: catalog, ContainerTypes: []string{"tenant"}, ValidatePrincipal: ok},
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
		{"another tenant", rbac.Subject{Tenant: "t2", User: "direct"}, login, false},
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

func TestEveryoneAndExpiry(t *testing.T) {
	h := setup(t)
	g := grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Everyone, "")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	if !allowed(t, h, user("anyone"), login, cluster) {
		t.Fatal("everyone's grant should reach any user")
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
	pred, err := h.authz.Filter(t.Context(), s, p, "cluster", rbac.Columns{Tenant: "tenant", Owner: "owner", Path: "path"}, 1)
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
		t.Errorf("%s %s: Filter %v, Authorize %v", s.User, p, got, want)
	}

	reach, err := h.authz.Reachable(t.Context(), s, p, "cluster")
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	for _, r := range resources {
		in := reach.All || (reach.Owned && r.Owner == s.User) || slices.ContainsFunc(reach.Scopes, func(sc rbac.Scope) bool {
			return slices.Contains(h.path(t, r), sc.Key())
		})
		if in {
			reached = append(reached, r.ID)
		}
	}
	if !slices.Equal(reached, want) {
		t.Errorf("%s %s: Reachable %v, Authorize %v", s.User, p, reached, want)
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
	pred, err := h.authz.Filter(ctx, rbac.Subject{Tenant: r.Tenant, User: "u"}, login, "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
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
		grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Everyone, ""),
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
		{Role: "cluster.admin", Principal: rbac.Principal{Kind: rbac.Everyone}},
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
	reach, err := h.authz.Reachable(t.Context(), user("u"), root, "cluster")
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
	if len(h.events) != 1 || len(h.events[0].Granted) != 1 || h.events[0].Actor != "owner" {
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
	if err != nil || len(got) != 1 || got[0].CreatedBy != "owner" {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestEveryoneIsOnlyUsers(t *testing.T) {
	h := setup(t)
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Everyone, ""))
	if allowed(t, h, rbac.Subject{Tenant: "t1", Groups: []string{"service"}}, login, cluster) {
		t.Fatal("a subject with no user isn't one of everyone")
	}
	if !allowed(t, h, user("u"), login, cluster) {
		t.Fatal("a user is one of everyone")
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

	pred, err := h.authz.Filter(ctx, user("friend"), "job:view", "job", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
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
	reach, err := h.authz.Reachable(ctx, user("friend"), "job:view", "job")
	if err != nil {
		t.Fatal(err)
	}
	if reach.All || len(reach.Scopes) > 0 {
		t.Errorf("Reachable reaches jobs through a grant on a cluster: %+v", reach)
	}
}

func TestEveryoneNeverGivesAGrantPermission(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// As if a role granted to everyone gained cluster:grant in a later catalog.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'workspace', 'w1', 'everyone', '', 'cluster.admin')`); err != nil {
		t.Fatal(err)
	}
	anyone := user("anyone")
	if !allowed(t, h, anyone, root, cluster) {
		t.Fatal("the grant still gives its other permissions")
	}
	if allowed(t, h, anyone, grantC, cluster) {
		t.Error("Authorize: everyone holds cluster:grant")
	}
	if d, err := h.authz.Explain(ctx, anyone, grantC, cluster); err != nil || d.Allowed {
		t.Errorf("Explain: %+v, %v", d, err)
	}
	perms, err := h.authz.Permissions(ctx, anyone, cluster)
	if err != nil || slices.Contains(perms, grantC) {
		t.Errorf("Permissions: %v, %v", perms, err)
	}
	holders, err := h.authz.Holders(ctx, cluster, grantC)
	if err != nil || slices.Contains(holders, rbac.Principal{Kind: rbac.Everyone}) {
		t.Errorf("Holders: %v, %v", holders, err)
	}
	reach, err := h.authz.Reachable(ctx, anyone, grantC, "cluster")
	if err != nil || reach.All || len(reach.Scopes) > 0 {
		t.Errorf("Reachable: %+v, %v", reach, err)
	}
	if _, err := h.pool.Exec(ctx, `CREATE TABLE cs (tenant text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO cs VALUES ('t1', $1)`, h.path(t, cluster)); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[rbac.Permission]int{root: 1, grantC: 0} {
		pred, err := h.authz.Filter(ctx, anyone, p, "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM cs WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("Filter %s: %d clusters, want %d", p, n, want)
		}
	}
	b := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "x"}}
	if err := h.authz.Apply(ctx, anyone, cluster, rbac.Change{Revoke: []rbac.Binding{b}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("Apply: %v", err)
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
