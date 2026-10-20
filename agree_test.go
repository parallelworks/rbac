package rbac_test

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/parallelworks/rbac"
)

// world is a tenant built at random: containers, clusters under them, grants, custom roles,
// groups in groups and denies, with clusters of the same ids in another tenant.
type world struct {
	h           *harness
	clusters    []rbac.Resource
	subjects    []rbac.Subject
	conditional bool
	// guests are the users who are guests of t1, outside those who are only another tenant's, and
	// inactive those whose membership of t1 is suspended or ended.
	guests, outside, inactive map[string]bool
}

func newWorld(t *testing.T, seed uint64, conditional bool) world {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, seed))
	h, guardian := guarded(t)
	ctx := t.Context()
	w := world{h: h, conditional: conditional, guests: map[string]bool{}, outside: map[string]bool{}, inactive: map[string]bool{}}
	pick := func(n int) int { return rng.IntN(n) }
	// Groups in groups, denies on the public and exempt groups, and suspended and ended memberships
	// are picked apart, so the rest of each seed's tenant stays as it was.
	extra := rand.New(rand.NewPCG(seed, seed+1))
	more := func(n int) int { return extra.IntN(n) }
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
	h.groups(t, "g0", "g1")
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
	// A privileged role granted to the tenant's members or an ordinary group is refused, but one a
	// catalog change made privileged stays stored, giving nothing: written directly, as it would be.
	strong := func(g rbac.Grant) bool {
		privileged := g.Role == "custom.root" || g.Role == "cluster.sudo" || g.Role == "cluster.admin"
		return !privileged || g.Principal.Kind == rbac.User || g.Principal == rbac.Principal{Kind: rbac.Group, ID: "g0"} ||
			g.Principal == rbac.Principal{Kind: rbac.Group, ID: "g1"}
	}
	for _, g := range grants {
		if strong(g) {
			continue
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at, condition)
			VALUES ('t1', $1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`, g.Scope.Type, g.Scope.ID, g.Principal.Kind, g.Principal.ID, g.Role,
			pgtype.Timestamptz{Time: g.ExpiresAt, Valid: !g.ExpiresAt.IsZero()}, g.Condition.Expression); err != nil {
			t.Fatal(err)
		}
	}
	// Expired grants are stored as the clock passes them: import them before it does.
	now := h.now
	h.now = now.Add(-2 * time.Hour)
	h.seed(t, slices.DeleteFunc(grants, func(g rbac.Grant) bool { return !strong(g) })...)
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
		exempt := groupOf(groups[more(len(groups))])
		switch more(6) {
		case 0:
			d.Principals, d.Exempt = []rbac.Principal{{Kind: rbac.Public}}, []rbac.Principal{rbac.TenantMembers("t1")}
		case 1:
			d.Principals, d.Exempt = []rbac.Principal{{Kind: rbac.Public}}, []rbac.Principal{exempt}
		case 2:
			if d.Principals[0] != exempt {
				d.Exempt = append(d.Exempt, exempt)
			}
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
			w.guests[u] = true
		case 1:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET tenant = 't2' WHERE tenant = 't1' AND principal = $1`, "user:"+u); err != nil {
				t.Fatal(err)
			}
			w.outside[u] = true
		}
		ended := h.now.Add(-time.Hour)
		switch more(6) {
		case 0:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = $1`, "user:"+u); err != nil {
				t.Fatal(err)
			}
			w.inactive[u] = true
		case 1:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET expires_at = $2 WHERE tenant = 't1' AND principal = $1`, "user:"+u, ended); err != nil {
				t.Fatal(err)
			}
			w.inactive[u] = true
		case 2:
			if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $2 WHERE tenant = 't1' AND principal = $1
				AND group_id = (SELECT min(group_id) FROM rbac_members WHERE tenant = 't1' AND principal = $1)`, "user:"+u, ended); err != nil {
				t.Fatal(err)
			}
		}
		w.subjects = append(w.subjects, s)
	}
	// Groups in others, a cycle or a chain too long aside, some of them ended.
	for _, outer := range groups {
		for _, inner := range groups {
			if inner == outer || more(4) > 0 {
				continue
			}
			err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: outer, Principal: groupOf(inner)}})
			switch {
			case errors.Is(err, rbac.ErrInvalid):
				continue
			case err != nil:
				t.Fatal(err)
			}
			if more(4) == 0 {
				if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET expires_at = $3 WHERE tenant = 't1' AND group_id = $1 AND principal = $2`,
					outer, "group:"+inner, h.now.Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
		}
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
			type expected struct {
				s               rbac.Subject
				p               rbac.Permission
				want, unchecked []string
			}
			var expect []expected
			filterAgrees := func(t *testing.T, e expected) {
				t.Helper()
				if got := listed(t, w.h, e.s, e.p); !within(got, e.want) || !within(e.unchecked, got) {
					t.Errorf("%+v %s: Filter %v, Authorize %v, Reachable unchecked %v", e.s, e.p, got, e.want, e.unchecked)
				}
			}
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
					e := expected{s, p, want, unchecked}
					filterAgrees(t, e)
					expect = append(expect, e)
				}
			}
			// As Filter lists for a subject holding many grants on containers.
			t.Run("looking up grants on containers", func(t *testing.T) {
				rbac.SetMaxContainerOverlap(t, 0)
				for _, e := range expect {
					filterAgrees(t, e)
				}
			})
			for _, r := range w.clusters {
				for _, p := range []rbac.Permission{view, login, root} {
					w.holdersAgree(t, p, r)
				}
			}
		})
	}
}

// member reports whether s is one of t1's members: an identity, not a guest, suspended or gone.
func (w world) member(s rbac.Subject) bool {
	id := s.Principal.ID
	return s.Principal != (rbac.Principal{}) && !w.guests[id] && !w.outside[id] && !w.inactive[id]
}

// holdersAgree checks Holders against Authorize for every subject: each holder it lists for sure,
// not under a condition nor perhaps denied, Authorize allows, every member where it is the
// tenant's members and everyone where it is the public, and each subject Authorize allows it
// lists, as itself where its own grants or its groups' allow, with them, or else among the
// tenant's members or as the public. Without conditions, it marks no identity, so a mark can't
// hide one it gets wrong.
func (w world) holdersAgree(t *testing.T, p rbac.Permission, r rbac.Resource) {
	t.Helper()
	holders, err := w.h.authz.Holders(t.Context(), p, r)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[rbac.Principal]rbac.Holder{}
	for _, h := range holders {
		listed[h.Principal] = h
		broad := h.Principal.Kind == rbac.Members || h.Principal.Kind == rbac.Public
		if !w.conditional && (h.Conditional || h.MaybeDenied && !broad) {
			t.Errorf("%s on %s: Holders marks %+v in a tenant without conditions", p, r.ID, h)
		}
		if h.Conditional || h.MaybeDenied {
			continue
		}
		if !broad {
			if !allowed(t, w.h, rbac.Subject{Principal: h.Principal}, p, r) {
				t.Errorf("%s on %s: Holders lists %+v, whom Authorize refuses", p, r.ID, h)
			}
			continue
		}
		for _, s := range w.subjects {
			if (h.Principal.Kind == rbac.Public || w.member(s)) && !allowed(t, w.h, s, p, r) {
				t.Errorf("%s on %s: Holders lists %+v, but Authorize refuses %v", p, r.ID, h, s.Principal)
			}
		}
	}
	for _, s := range w.subjects {
		if !allowed(t, w.h, s, p, r) {
			continue
		}
		holder, itself := listed[s.Principal]
		_, members := listed[rbac.TenantMembers("t1")]
		_, public := listed[rbac.Principal{Kind: rbac.Public}]
		if covered := itself || members && w.member(s) || public; !covered {
			t.Errorf("%s on %s: Authorize allows %v, whom Holders leaves out: %+v", p, r.ID, s.Principal, holders)
		}
		d, err := w.h.authz.Explain(t.Context(), s, p, r)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range d.Grants {
			switch {
			case g.Principal.Kind == rbac.Members || g.Principal.Kind == rbac.Public:
			case !slices.Contains(holder.Grants, g.ID):
				t.Errorf("%s on %s: Authorize allows %v through grant %+v, which Holders doesn't list as its: %+v", p, r.ID, s.Principal, g, holders)
			case g.Principal.Kind == rbac.Group && !slices.Contains(holder.Groups, g.Principal.ID):
				t.Errorf("%s on %s: Authorize allows %v through group %s, which Holders doesn't name: %+v", p, r.ID, s.Principal, g.Principal.ID, holder)
			}
		}
	}
}

// within reports whether every one of xs is in ys.
func within(xs, ys []string) bool {
	return !slices.ContainsFunc(xs, func(x string) bool { return !slices.Contains(ys, x) })
}
