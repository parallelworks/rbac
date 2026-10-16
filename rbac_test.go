package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/foundation/pgdb"
	"github.com/parallelworks/foundation/pgdb/pgdbtest"
	"github.com/parallelworks/foundation/rbac"
)

const urlEnv = "FOUNDATION_TEST_DATABASE_URL"

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
		ValidatePrincipal: func(_ context.Context, tenant string, p rbac.Principal) error {
			if strings.HasPrefix(p.ID, "outsider") {
				return errors.New("not a member")
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
	ok := func(context.Context, string, rbac.Principal) error { return nil }
	for name, cfg := range map[string]rbac.Config{
		"no principal check": {Catalog: catalog},
		"duplicate role":     {Catalog: append(slices.Clone(catalog), catalog[0]), ValidatePrincipal: ok},
		"bad permission":     {Catalog: []rbac.RoleDefinition{{ID: "r", Permissions: []rbac.Permission{"login"}, ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"no permissions":     {Catalog: []rbac.RoleDefinition{{ID: "r", ResourceTypes: []string{"cluster"}}}, ValidatePrincipal: ok},
		"bad container":      {Catalog: catalog, ContainerTypes: []string{"tenant"}, ValidatePrincipal: ok},
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
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "no root", Deny: func(_ context.Context, _, _ string, p rbac.Permission) (bool, error) {
			return p == root, nil
		}}}
	})
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
		if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3, $4)`, r.Tenant, r.ID, r.Owner, r.Path()); err != nil {
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
				in := reach.All || r.Owner == s.User || slices.ContainsFunc(reach.Scopes, func(sc rbac.Scope) bool {
					return slices.Contains(r.Path(), sc.Key())
				})
				if in {
					reached = append(reached, r.ID)
				}
			}
			if !slices.Equal(reached, want) {
				t.Errorf("%s %s: Reachable %v, Authorize %v", s.User, p, reached, want)
			}
		}
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
	temp.ExpiresAt = h.now.Add(time.Hour)
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
