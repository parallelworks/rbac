package rbac_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
)

// world is a tenant built at random: containers, clusters under them, grants, custom roles and
// denies, with clusters of the same ids in another tenant.
type world struct {
	h           *harness
	clusters    []rbac.Resource
	subjects    []rbac.Subject
	conditional bool
}

func newWorld(t *testing.T, seed uint64, conditional bool) world {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, seed))
	h, guardian := guarded(t)
	ctx := t.Context()
	w := world{h: h, conditional: conditional}
	pick := func(n int) int { return rng.IntN(n) }
	orgs := []rbac.Scope{{Type: "org", ID: "o1"}, {Type: "org", ID: "o2"}, {Type: "org", ID: "o3"}}
	// Workspaces under orgs, and a few under other workspaces.
	var spaces [][]rbac.Scope
	for i := range 6 {
		spaces = append(spaces, []rbac.Scope{{Type: "workspace", ID: fmt.Sprint("w", i)}, orgs[pick(len(orgs))]})
	}
	for i := 6; i < 8; i++ {
		parent := spaces[pick(len(spaces))]
		spaces = append(spaces, append([]rbac.Scope{{Type: "workspace", ID: fmt.Sprint("w", i)}}, parent...))
	}
	if _, err := h.pool.Exec(ctx, `CREATE TABLE clusters (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		var ancestors []rbac.Scope
		switch k := pick(5); {
		case k == 0:
			ancestors = []rbac.Scope{orgs[pick(len(orgs))]}
		case k > 0:
			ancestors = spaces[pick(len(spaces))]
		}
		env := []string{"dev", "prod"}[pick(2)]
		for _, tenant := range []string{"t1", "t2"} {
			r := rbac.Resource{Tenant: tenant, Type: "cluster", ID: fmt.Sprint("c", i), Ancestors: ancestors, Attributes: map[string]any{"env": env}}
			if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
				t.Fatal(err)
			}
			if tenant == "t1" {
				w.clusters = append(w.clusters, r)
			}
		}
	}
	// Custom roles: one narrower than a built-in role, one that gives root alone.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES
		('t1', 'custom.view', '{cluster:view}', '{cluster}'), ('t1', 'custom.root', '{cluster:view,cluster:root}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	users := []string{"u0", "u1", "u2", "u3", "u4", "u5"}
	groups := []string{"g0", "g1", "g2", "g3"}
	principal := func() rbac.Principal {
		switch k := pick(10); {
		case k < 5:
			return rbac.Principal{Kind: rbac.User, ID: users[pick(len(users))]}
		case k < 9:
			return rbac.Principal{Kind: rbac.Group, ID: groups[pick(len(groups))]}
		}
		return rbac.TenantMembers("t1")
	}
	scope := func() rbac.Scope {
		switch k := pick(10); {
		case k < 4:
			return w.clusters[pick(len(w.clusters))].Scope()
		case k < 7:
			return spaces[pick(len(spaces))][0]
		case k < 9:
			return orgs[pick(len(orgs))]
		}
		return rbac.TenantRoot("t1")
	}
	roles := []rbac.Role{"cluster.login", "cluster.sudo", "cluster.admin", "custom.view", "custom.root"}
	var grants []rbac.Grant
	for range 30 {
		g := rbac.Grant{Scope: scope(), Binding: rbac.Binding{Role: roles[pick(len(roles))], Principal: principal()}}
		// The tenant's members can't hold a role that changes access.
		if g.Principal.Kind == rbac.Members && g.Role == "cluster.admin" {
			g.Role = "cluster.sudo"
		}
		switch pick(6) {
		case 0:
			g.ExpiresAt = h.now.Add(time.Hour)
		case 1:
			g.ExpiresAt = h.now.Add(-time.Hour)
		}
		if conditional && pick(3) == 0 {
			g.Condition = rbac.Condition{Expression: []string{`resource.attributes.env == "dev"`, `request.attributes.mfa == true`, `false`}[pick(3)]}
		}
		grants = append(grants, g)
	}
	// Expired grants are stored as the clock passes them: import them before it does.
	now := h.now
	h.now = now.Add(-2 * time.Hour)
	h.seed(t, grants...)
	h.now = now
	for i := range 4 {
		d := rbac.Deny{ID: fmt.Sprint("d", i), Principals: []rbac.Principal{principal()}, Permissions: []rbac.Permission{[]rbac.Permission{login, root, "cluster:*"}[pick(3)]}}
		if pick(3) == 0 {
			d.Exempt = []rbac.Principal{{Kind: rbac.User, ID: users[pick(len(users))]}}
			if d.Exempt[0] == d.Principals[0] {
				d.Exempt = nil
			}
		}
		if conditional && pick(2) == 0 {
			d.Condition = rbac.Condition{Expression: []string{`resource.attributes.env == "prod"`, `request.attributes.mfa != true`}[pick(2)]}
		}
		on := rbac.Resource{Tenant: "t1", Type: "workspace", ID: spaces[i][0].ID, Ancestors: spaces[i][1:]}
		if pick(3) == 0 {
			on = rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
		}
		if err := h.authz.SetDeny(ctx, guardian, on, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		s := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: u}}
		for _, g := range groups {
			if pick(3) == 0 {
				s.Groups = append(s.Groups, g)
			}
		}
		// Most are the tenant's members; one in four is a guest from another.
		if pick(4) > 0 {
			s.Tenants = []string{"t1"}
		}
		w.subjects = append(w.subjects, s)
	}
	w.subjects = append(w.subjects, rbac.Subject{})
	return w
}

// TestListingsAgreeWithChecksInRandomTenants builds tenants at random and checks, for every subject
// and permission, that Filter lists exactly what Authorize allows, or with conditions involved
// never more, and that Reachable, read as a host reads it, agrees with Authorize.
func TestListingsAgreeWithChecksInRandomTenants(t *testing.T) {
	for seed := range uint64(12) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			w := newWorld(t, seed, seed%2 == 1)
			ctx := t.Context()
			for _, s := range w.subjects {
				for _, p := range []rbac.Permission{view, root} {
					var want []string
					for _, r := range w.clusters {
						if allowed(t, w.h, s, p, r) {
							want = append(want, r.ID)
						}
					}
					pred, err := w.h.authz.Filter(ctx, s, p, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
					if err != nil {
						t.Fatal(err)
					}
					rows, err := w.h.pool.Query(ctx, "SELECT id FROM clusters WHERE "+pred.SQL, pred.Args...)
					if err != nil {
						t.Fatalf("%s: %v", pred.SQL, err)
					}
					got, err := pgx.CollectRows(rows, pgx.RowTo[string])
					if err != nil {
						t.Fatal(err)
					}
					slices.SortFunc(got, byNumber)
					extra := slices.DeleteFunc(slices.Clone(got), func(id string) bool { return slices.Contains(want, id) })
					if len(extra) > 0 || !w.conditional && !slices.Equal(got, want) {
						t.Errorf("%+v %s: Filter %v, Authorize %v", s, p, got, want)
					}
					if reached := w.reached(t, s, p); !slices.Equal(reached, want) {
						t.Errorf("%+v %s: Reachable %v, Authorize %v", s, p, reached, want)
					}
				}
			}
		})
	}
}

// reached is what a host listing by Reachable shows: the clusters its scopes reach, checking each
// it says to check.
func (w world) reached(t *testing.T, s rbac.Subject, p rbac.Permission) []string {
	t.Helper()
	reach, err := w.h.authz.Reachable(t.Context(), s, p, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	var reached []string
	for _, r := range w.clusters {
		path := w.h.path(t, r)
		holds := func(scopes []rbac.Scope) bool {
			return slices.ContainsFunc(scopes, func(sc rbac.Scope) bool { return slices.Contains(path, sc.Key()) })
		}
		in := !holds(reach.Except) && (reach.All || holds(reach.Scopes) || holds(reach.Conditional))
		if in && (holds(reach.Conditional) || holds(reach.ConditionalExcept)) {
			in = allowed(t, w.h, s, p, r)
		}
		if in {
			reached = append(reached, r.ID)
		}
	}
	return reached
}

// byNumber orders cluster ids c0, c1, … c19 as the world made them.
func byNumber(x, y string) int {
	var i, j int
	_, _ = fmt.Sscanf(x, "c%d", &i)
	_, _ = fmt.Sscanf(y, "c%d", &j)
	return i - j
}
