package rbac_test

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

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
	users := []string{"u0", "u1", "u2", "u3", "u4", "u5"}
	groups := []string{"g0", "g1", "g2", "g3"}
	h.groups(t, groups...)
	var grants []rbac.Grant
	for i := range 20 {
		ancestors := spaces[pick(len(spaces))]
		if pick(5) == 0 {
			ancestors = []rbac.Scope{orgs[pick(len(orgs))]}
		}
		env := []string{"dev", "prod"}[pick(2)]
		for _, tenant := range []string{"t1", "t2"} {
			r := rbac.Resource{Tenant: tenant, Type: "cluster", ID: fmt.Sprintf("c%02d", i), Ancestors: ancestors, Attributes: map[string]any{"env": env}}
			if _, err := h.pool.Exec(ctx, `INSERT INTO clusters VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r)); err != nil {
				t.Fatal(err)
			}
			if tenant == "t1" {
				w.clusters = append(w.clusters, r)
			}
		}
		// Most are u0's, who holds the admin role a host gives creators on each: more grants on
		// clusters than Filter overlaps with a path, so it also takes the form that looks them up.
		if pick(3) > 0 {
			grants = append(grants, grant(w.clusters[i].Scope(), "cluster.admin", rbac.User, users[0]))
		}
	}
	// Custom roles: one narrower than a built-in role, one that gives root without login.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES
		('t1', 'custom.view', '{cluster:view}', '{cluster}'), ('t1', 'custom.root', '{cluster:view,cluster:root}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
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
		on := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
		switch pick(4) {
		case 0:
			on = w.clusters[pick(len(w.clusters))]
		case 1, 2:
			space := spaces[pick(len(spaces))]
			on = rbac.Resource{Tenant: "t1", Type: "workspace", ID: space[0].ID, Ancestors: space[1:]}
		}
		if err := h.authz.SetDeny(ctx, guardian, on, d); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range users {
		var in []string
		for _, g := range groups {
			if pick(3) == 0 {
				in = append(in, g)
			}
		}
		s := h.as(t, u, in...)
		// Most are the tenant's members; some are guests, and some are only another tenant's.
		switch pick(6) {
		case 0:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET guest = true WHERE tenant = 't1' AND principal = $1`, "user:"+u); err != nil {
				t.Fatal(err)
			}
		case 1:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET tenant = 't2' WHERE tenant = 't1' AND principal = $1`, "user:"+u); err != nil {
				t.Fatal(err)
			}
		}
		w.subjects = append(w.subjects, s)
	}
	w.subjects = append(w.subjects, rbac.Subject{})
	return w
}

// TestListingsAgreeWithChecksInRandomTenants builds tenants at random and checks, for every subject
// and permission, that Reachable, read as a host reads it, agrees with Authorize, asking for
// checks only where a condition is, and that Filter lists what Authorize allows, leaving out only
// what Reachable says to check.
func TestListingsAgreeWithChecksInRandomTenants(t *testing.T) {
	for seed := range uint64(12) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			w := newWorld(t, seed, seed%2 == 1)
			for _, s := range w.subjects {
				for _, p := range []rbac.Permission{view, login, root} {
					want := allowedOf(t, w.h, w.clusters, s, p)
					reached, unchecked := reachedBy(t, w.h, w.clusters, s, p)
					if !slices.Equal(reached, want) {
						t.Errorf("%+v %s: Reachable %v, Authorize %v", s, p, reached, want)
					}
					if !w.conditional && !slices.Equal(unchecked, reached) {
						t.Errorf("%+v %s: Reachable checks some of %v, unchecked %v, with no conditions", s, p, reached, unchecked)
					}
					if got := listed(t, w.h, s, p); !within(got, want) || !within(unchecked, got) {
						t.Errorf("%+v %s: Filter %v, Authorize %v, Reachable unchecked %v", s, p, got, want, unchecked)
					}
				}
			}
		})
	}
}

// within reports whether every one of xs is in ys.
func within(xs, ys []string) bool {
	return !slices.ContainsFunc(xs, func(x string) bool { return !slices.Contains(ys, x) })
}
