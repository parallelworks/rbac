package rbac_test

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
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

// TestDenyLookupsAgreeWithOverlapsInRandomTenants builds tenants of many denies at random, naming and
// exempting identities, groups in groups, in cycles too, the tenant's members and the public, some
// of them hundreds of principals, of permissions and of every permission on a type. For members,
// guests, suspended members, identities whose membership or places have ended or will, one of
// another tenant, one of none and the anonymous, it checks that every read of the denies binding a
// subject, which looks each of a deny's keys up, finds what the overlap of arrays found
// (DeniesMatched), now and as of a time, and with labels declared, as some deny label values too;
// that Authorize and Explain refuse where one of them binds; and that Filter, Reachable and Holders
// agree with Authorize.
func TestDenyLookupsAgreeWithOverlapsInRandomTenants(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	// The subjects Holders' read of label values found bound by a deny of one, so that read is
	// compared with some.
	valued := 0
	for seed := range uint64(12) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed))
			pick := rng.IntN
			// Label values are denied from a stream of their own, so the rest of each tenant stays as
			// it was.
			more := rand.New(rand.NewPCG(seed, seed+1)).IntN
			h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer) })
			ctx := t.Context()
			// History dates what is written by the database's clock, which AsOf reads by.
			h.now = dbNow(t, h)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			w := world{h: h, guests: map[string]bool{}, outside: map[string]bool{}, inactive: map[string]bool{}}
			orgs := []rbac.Scope{{Type: "org", ID: "o0"}, {Type: "org", ID: "o1"}}
			spaces := [][]rbac.Scope{{{Type: "workspace", ID: "w0"}, orgs[0]}, {{Type: "workspace", ID: "w1"}, orgs[0]}, {{Type: "workspace", ID: "w2"}, orgs[1]}}
			exec(`CREATE TABLE clusters (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`)
			scopes := []string{"tenant:t1", "org:o0", "org:o1", "workspace:w0", "workspace:w1", "workspace:w2"}
			for i := range 6 {
				r := rbac.Resource{Tenant: "t1", Type: "cluster", ID: fmt.Sprint("c", i), Ancestors: spaces[i%len(spaces)]}
				exec(`INSERT INTO clusters VALUES ($1, $2, $3)`, r.Tenant, r.ID, h.path(t, r))
				w.clusters = append(w.clusters, r)
				scopes = append(scopes, r.Scope().Key())
			}
			// None, one passed, or one to come.
			end := func() any {
				switch pick(4) {
				case 0:
					return h.now.Add(-time.Hour)
				case 1:
					return h.now.Add(time.Duration(1+pick(48)) * time.Hour)
				}
				return nil
			}
			groups := []string{"g0", "g1", "g2", "g3", "g4"}
			h.groups(t, groups...)
			for _, outer := range groups {
				for _, inner := range groups {
					if inner != outer && pick(4) == 0 {
						exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at) VALUES ('t1', $1, 'group', $2, $3)`, outer, inner, end())
					}
				}
			}
			// One of each kind in every tenant: a guest, suspended, its membership ended, ending, of
			// another tenant, and members.
			users := []string{"u0", "u1", "u2", "u3", "u4", "u5", "u6"}
			for i, u := range users {
				var in []string
				for _, g := range groups {
					if pick(3) == 0 {
						in = append(in, g)
					}
				}
				w.subjects = append(w.subjects, h.as(t, u, in...))
				for _, g := range in {
					exec(`UPDATE rbac_members SET expires_at = $3 WHERE tenant = 't1' AND group_id = $1 AND principal = $2`, g, "user:"+u, end())
				}
				switch (i + int(seed)) % len(users) {
				case 0:
					exec(`UPDATE rbac_memberships SET guest = true WHERE tenant = 't1' AND principal = $1`, "user:"+u)
					w.guests[u] = true
				case 1:
					exec(`UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = $1`, "user:"+u)
					w.inactive[u] = true
				case 2:
					exec(`UPDATE rbac_memberships SET expires_at = $2 WHERE tenant = 't1' AND principal = $1`, "user:"+u, h.now.Add(-time.Hour))
					w.inactive[u] = true
				case 3:
					exec(`UPDATE rbac_memberships SET expires_at = $2 WHERE tenant = 't1' AND principal = $1`, "user:"+u, h.now.Add(time.Duration(1+pick(48))*time.Hour))
				case 4:
					exec(`UPDATE rbac_memberships SET tenant = 't2' WHERE tenant = 't1' AND principal = $1`, "user:"+u)
					w.outside[u] = true
				}
			}
			w.outside["nobody"] = true
			w.subjects = append(w.subjects, rbac.Subject{Principal: identity("nobody")}, rbac.Subject{})
			grants := []rbac.Grant{
				{Scope: rbac.TenantRoot("t1"), Binding: rbac.Binding{Role: viewer.ID, Principal: rbac.Principal{Kind: rbac.Public}}},
				{Scope: orgs[0], Binding: rbac.Binding{Role: "cluster.login", Principal: rbac.TenantMembers("t1")}},
				grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, users[pick(len(users))]),
			}
			for _, u := range users {
				if pick(3) > 0 {
					scopeType, scopeID, _ := strings.Cut(scopes[pick(len(scopes))], ":")
					grants = append(grants, grant(rbac.Scope{Type: scopeType, ID: scopeID}, "cluster.sudo", rbac.User, u))
				}
			}
			h.seed(t, grants...)
			perms := []rbac.Permission{view, login, root, grantC}
			before := map[string]bool{}
			at := func(s rbac.Subject, p rbac.Permission, on string) string {
				return fmt.Sprint(s.Principal, " ", p, " on ", on)
			}
			for _, s := range w.subjects {
				for _, p := range perms {
					for _, r := range w.clusters {
						before[at(s, p, r.ID)] = allowed(t, h, s, p, r)
					}
				}
			}
			// Each names a few principals, or those and hundreds more, and may exempt a few, or hundreds.
			principal := func() string {
				switch k := pick(20); {
				case k < 7:
					return "user:" + append(slices.Clone(users), "nobody")[pick(len(users)+1)]
				case k < 14:
					return "group:" + groups[pick(len(groups))]
				case k < 17:
					return "members:t1"
				}
				return "public:"
			}
			deniable := []string{"cluster:view", "cluster:login", "cluster:root", "cluster:grant", "cluster:*", "workspace:view", "workspace:grant", "workspace:*", "tenant:grant", "tenant:*"}
			// Few in some tenants, so some subjects are bound by none, and many in others.
			denies := 40 + pick(40)
			if seed%2 == 0 {
				denies = 2 + pick(6)
			}
			type deny struct {
				scopeType, scopeID, id          string
				principals, exempt, permissions []string
			}
			var inserts []deny
			for i := range denies {
				named := map[string]bool{}
				principals, exempt, permissions := []string{}, []string{}, []string{}
				for range 1 + pick(3) {
					if k := principal(); !named[k] {
						named[k] = true
						principals = append(principals, k)
					}
				}
				if pick(3) == 0 {
					for j := range 250 {
						principals = append(principals, fmt.Sprintf("group:x%d_%d", i, j))
					}
				}
				if pick(5) > 1 {
					for range 1 + pick(3) {
						if k := principal(); !named[k] && k != "public:" && (k != "members:t1" || named["public:"]) {
							named[k] = true
							exempt = append(exempt, k)
						}
					}
					if pick(3) == 0 {
						for j := range 250 {
							exempt = append(exempt, fmt.Sprintf("user:y%d_%d", i, j))
						}
					}
				}
				for range 1 + pick(2) {
					if p := deniable[pick(len(deniable))]; !slices.Contains(permissions, p) {
						permissions = append(permissions, p)
					}
				}
				if more(2) == 0 {
					permissions = append(permissions, []string{"level:*", "level:high", "comp:alpha", "rel:release"}[more(4)])
				}
				scopeType, scopeID, _ := strings.Cut(scopes[pick(len(scopes))], ":")
				inserts = append(inserts, deny{scopeType, scopeID, fmt.Sprint("d", i), principals, exempt, permissions})
			}
			insert := func(d deny) {
				t.Helper()
				exec(`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions) VALUES ('t1', $1, $2, $3, $4, $5, $6)`,
					d.scopeType, d.scopeID, d.id, d.principals, d.exempt, d.permissions)
			}
			// A read of the denies anywhere in the tenant answers for all of them at once, so of several
			// binding a subject, any one decides it: those reads are checked with each of the first
			// denies alone too. So is a list, which leaves out a row any deny binding its subject is
			// on the path of, of a deny exempting anyone from view, which identities that aren't
			// active members hold through the public, and whose keys a deny exempts are told apart.
			for _, d := range inserts[:min(len(inserts), 24)] {
				insert(d)
				for _, s := range w.subjects {
					for _, read := range rbac.DeniesAnywhereMatched(t, ctx, h.authz, "t1", s) {
						if !slices.Equal(read.Got, read.Want) {
							t.Errorf("with %s alone, %v: %s read %v, the overlap of arrays %v", d.id, s.Principal, read.Read, read.Got, read.Want)
						}
					}
					if len(d.exempt) == 0 || !slices.Contains(d.permissions, "cluster:view") && !slices.Contains(d.permissions, "cluster:*") {
						continue
					}
					want := allowedOf(t, h, w.clusters, s, view)
					if got := listed(t, h, s, view); !slices.Equal(got, want) {
						t.Errorf("with %s alone, %v %s: Filter %v, Authorize %v", d.id, s.Principal, view, got, want)
					}
					if reached, _ := reachedBy(t, h, w.clusters, s, view); !slices.Equal(reached, want) {
						t.Errorf("with %s alone, %v %s: Reachable %v, Authorize %v", d.id, s.Principal, view, reached, want)
					}
				}
				exec(`DELETE FROM rbac_denies WHERE tenant = 't1'`)
			}
			for _, d := range inserts {
				insert(d)
			}
			matched := func(a *rbac.Authorizer, when string, resources []rbac.Resource, perms []rbac.Permission) map[string][]string {
				t.Helper()
				checked := map[string][]string{}
				for _, s := range w.subjects {
					for _, read := range rbac.DeniesMatched(t, ctx, a, s, w.subjects, resources, perms) {
						if !slices.Equal(read.Got, read.Want) {
							t.Errorf("%s, %v on %q of %q: %s read %v, the overlap of arrays %v", when, s.Principal, read.On, read.Permission, read.Read, read.Got, read.Want)
						}
						if read.Read == "check" {
							checked[at(s, read.Permission, read.On)] = read.Want
						}
						if read.Read == "holders' label values" && len(read.Want) > 0 {
							valued++
						}
					}
				}
				return checked
			}
			checked := matched(h.authz, "now", w.clusters, perms)
			// Holders reads only the denies of a label value or a power to release, of which it finds
			// none where no label is declared.
			cfg := h.cfg
			withLabels(&cfg)
			labeled, err := rbac.New(h.pool, cfg)
			if err != nil {
				t.Fatal(err)
			}
			matched(labeled, "with labels declared", w.clusters[:1], []rbac.Permission{view})
			for _, s := range w.subjects {
				for _, p := range perms {
					for _, r := range w.clusters {
						want := before[at(s, p, r.ID)] && len(checked[at(s, p, r.ID)]) == 0
						if got := allowed(t, h, s, p, r); got != want {
							t.Errorf("%v %s on %s: Authorize allows %v, though it allowed %v before the denies, and these bind it: %v", s.Principal, p, r.ID, got, before[at(s, p, r.ID)], checked[at(s, p, r.ID)])
						}
						// Explain reads the denies apart from Authorize, by keys it passes the statement.
						if d, err := h.authz.Explain(ctx, s, p, r); err != nil || d.Allowed != want {
							t.Errorf("%v %s on %s: Explain allows %v (%v), Authorize %v", s.Principal, p, r.ID, d.Allowed, err, want)
						}
					}
				}
			}
			for _, s := range w.subjects {
				for _, p := range []rbac.Permission{view, login, root} {
					want := allowedOf(t, h, w.clusters, s, p)
					if got := listed(t, h, s, p); !slices.Equal(got, want) {
						t.Errorf("%v %s: Filter %v, Authorize %v", s.Principal, p, got, want)
					}
					if reached, _ := reachedBy(t, h, w.clusters, s, p); !slices.Equal(reached, want) {
						t.Errorf("%v %s: Reachable %v, Authorize %v", s.Principal, p, reached, want)
					}
				}
			}
			for _, r := range w.clusters[:3] {
				for _, p := range []rbac.Permission{view, login, root} {
					w.holdersAgree(t, p, r)
				}
			}
			if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
				matched(a, "as of now", w.clusters[:1], []rbac.Permission{view, root})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if valued == 0 {
		t.Error("no deny of a label value bound a subject, so Holders' read of them was compared with none")
	}
}

// TestDenyLookupsAgreeWithOverlapsOnAnyKeys evaluates the fragments that look a deny's keys up in
// objects of its subject's (keyed, bindsIfRead, exemptForGoodSQL and exemptUntilSQL) beside the
// overlaps of arrays they replaced, on values random tenants rarely hold: null arrays and null keys
// in them, empty ones and empty key sets, keys repeated, and keys jsonb escapes, or that differ only
// in case or in Unicode normalization, as arrays of the C collation the tables hold them in, of the
// database's default and of ICU's root where the server has it; whether a deny binds as each read
// tests it, where its test of the permission or scope is true, false or null; and when an exemption
// ends, for keys a subject is bound by, exempted by or neither, each ending at one of two times or
// never, at random.
func TestDenyLookupsAgreeWithOverlapsOnAnyKeys(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Open(t, "")
	rng := rand.New(rand.NewPCG(1, 2))
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	keys := []string{
		"public:", "members:t1", "user:ann", "user:Ann", "user:ANN", "group:a", "group:A", "group:é", "group:e\u0301",
		"group:ß", "group:ss", "group:SS", `group:"q"`, `group:\`, `group:\\`, `group:\"`, `group:\u0000`, `group:{"a": 1}`, "group:日本",
		"group:\u2028", "group:\U0001F600", "group: ", "group:a ", "group:", "",
	}
	for c := rune(1); c < 0x20; c++ {
		keys = append(keys, "group:"+string(c))
	}
	keys = append(keys, "group:\x7f")
	of := func(ks ...string) []*string {
		ps := make([]*string, len(ks))
		for i := range ks {
			ps[i] = &ks[i]
		}
		return ps
	}
	// A deny's arrays: null, empty, of nulls, of one key with a null or twice, and a few at random.
	arrays := []any{nil, []*string{}, []*string{nil}, []*string{nil, nil}}
	for _, k := range keys {
		arrays = append(arrays, of(k), append(of(k), nil), append([]*string{nil}, of(k)...), of(k, k))
	}
	// A subject's keys, which hold no null: none, one, and a few at random.
	keySets := []any{[]*string{}}
	for _, k := range keys {
		keySets = append(keySets, of(k))
	}
	for range 150 {
		var a []*string
		for range 2 + rng.IntN(3) {
			if rng.IntN(8) == 0 {
				a = append(a, nil)
			} else {
				a = append(a, of(keys[rng.IntN(len(keys))])...)
			}
		}
		arrays = append(arrays, a)
		var s []string
		for range 2 + rng.IntN(5) {
			s = append(s, keys[rng.IntN(len(keys))])
		}
		keySets = append(keySets, of(s...))
	}
	copied := func(table string, rows [][]any, cols ...string) {
		t.Helper()
		defs := []string{"id int"}
		for _, c := range cols {
			defs = append(defs, c+` text[] COLLATE "C"`)
		}
		exec(`CREATE TABLE ` + table + ` (` + strings.Join(defs, ", ") + `)`)
		if _, err := pool.CopyFrom(ctx, pgx.Identifier{table}, append([]string{"id"}, cols...), pgx.CopyFromRows(rows)); err != nil {
			t.Fatal(err)
		}
	}
	numbered := func(values []any) [][]any {
		rows := make([][]any, len(values))
		for i, v := range values {
			rows[i] = []any{i, v}
		}
		return rows
	}
	copied("arrays", numbered(arrays), "keys")
	copied("key_sets", numbered(keySets), "keys")
	mismatched := func(what, sql string, args ...any) {
		t.Helper()
		rows, err := pool.Query(ctx, sql+` LIMIT 5`, args...)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		found, err := pgx.CollectRows(rows, pgx.RowToMap)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		for _, f := range found {
			t.Errorf("%s: the lookup and the overlap disagree on %v", what, f)
		}
	}
	// Every array against every key set, the keys as the tables hold them and in other collations,
	// which compare the same where they are deterministic, as a database's default is.
	collations := []string{`"C"`, `"default"`}
	var icu bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_collation WHERE collname = 'und-x-icu')`).Scan(&icu); err != nil {
		t.Fatal(err)
	}
	if icu {
		collations = append(collations, `"und-x-icu"`)
	}
	for _, c := range collations {
		col, set := "(a.keys COLLATE "+c+")", "SELECT unnest(s.keys) COLLATE "+c
		mismatched("keys in "+c, `SELECT a.keys AS deny, s.keys AS subject FROM arrays a, key_sets s
			WHERE (`+col+` && ARRAY(`+set+`)) IS DISTINCT FROM `+rbac.Keyed(col, set))
	}
	// As each read composes them, its test of the permission or the scope, r, first: a deny passes
	// a read where its condition is true, so only that is compared, and the value of a column. The
	// keys a deny is matched to, b and x, are null only for Explain's read for Holders, of any deny.
	var composed [][]any
	for i := range 4000 {
		b, x := keySets[rng.IntN(len(keySets))], keySets[rng.IntN(len(keySets))]
		if i%10 == 0 {
			b, x = nil, nil
		}
		composed = append(composed, []any{i, arrays[rng.IntN(len(arrays))], arrays[rng.IntN(len(arrays))], b, x})
	}
	copied("denies", composed, "p", "e", "b", "x")
	bound, exempted := "SELECT unnest(d.b)", "SELECT unnest(d.x)"
	for _, read := range []struct{ name, of, overlap, lookup string }{
		{
			"a check's", "d.x IS NOT NULL", `d.p && d.b AND NOT d.e && d.x AND (r)`,
			rbac.BindsIfRead("r", rbac.Keyed("d.p", bound)+" AND NOT "+rbac.Keyed("d.e", exempted)),
		},
		{
			"Explain's", "TRUE", `(d.b IS NULL OR d.p && d.b AND NOT d.e && d.x) AND (r)`,
			rbac.BindsIfRead("r", "(d.b IS NULL OR "+rbac.Keyed("d.p", bound)+" AND NOT "+rbac.Keyed("d.e", exempted)+")"),
		},
		{"a list's", "d.x IS NOT NULL", `NOT d.e && d.x AND (r)`, rbac.BindsIfRead("r", "NOT "+rbac.Keyed("d.e", exempted))},
	} {
		mismatched(read.name, `SELECT d.*, r FROM denies d, (VALUES (true), (false), (NULL)) AS r(r)
			WHERE `+read.of+` AND ((`+read.overlap+`) IS TRUE) <> ((`+read.lookup+`) IS TRUE)`)
	}
	mismatched("the binds column", `SELECT d.* FROM denies d WHERE d.x IS NOT NULL
		AND (NOT d.e && d.x) IS DISTINCT FROM NOT `+rbac.Keyed("d.e", exempted))
	// When an exemption ends, of a subject bound by the public, its identity, perhaps the tenant's
	// members and groups, one named as jsonb escapes it, and exempted by some of those, each ending at
	// one of two times or never, or reached by no path, as lastingSQL reads them; for each deny naming
	// and exempting none, one or two of those or another group, or nulls.
	tricky := "group:\"q\\\né"
	named := []string{"user:u", "public:", "members:t1", "group:a", "group:b", tricky, "group:z"}
	lists := []any{nil, []*string{}, []*string{nil}}
	for i, k := range named {
		lists = append(lists, of(k), append(of(k), nil))
		for _, l := range named[i+1:] {
			lists = append(lists, of(k, l))
		}
	}
	var pairs [][]any
	for i, p := range lists {
		for j, e := range lists {
			pairs = append(pairs, []any{i*len(lists) + j, p, e})
		}
	}
	copied("pairs", pairs, "p", "e")
	at := []time.Time{time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC)}
	until := `WITH bound(k) AS (SELECT unnest($1::text[]) COLLATE "C"), exempted(k) AS (SELECT unnest($2::text[]) COLLATE "C"),
		ends(k, e) AS (SELECT k COLLATE "C", e FROM unnest($3::text[], $4::timestamptz[]) AS e(k, e)), ` +
		rbac.LastingSQL("'t1'::text", "'user:u'::text") + `
		SELECT c.*, $1::text[] AS bound, $2::text[] AS exempted, $3::text[] AS ends, $4::timestamptz[] AS at FROM pairs c WHERE `
	for range 150 {
		bound := []string{"user:u", "public:"}
		for _, k := range []string{"members:t1", "group:a", "group:b", tricky} {
			if rng.IntN(4) > 0 {
				bound = append(bound, k)
			}
		}
		var exempted []string
		for _, k := range bound {
			if rng.IntN(5) < 3 {
				exempted = append(exempted, k)
			}
		}
		var ends []string
		var ending []*time.Time
		for _, k := range []string{"user:u", "group:a", "group:b", tricky} {
			switch n := rng.IntN(4); n {
			case 0:
			case 1:
				ends, ending = append(ends, k), append(ending, nil)
			default:
				ends, ending = append(ends, k), append(ending, &at[n-2])
			}
		}
		args := []any{bound, exempted, ends, ending}
		mismatched("exempt for good", until+`(c.e && ARRAY(SELECT k FROM lasting WHERE exempts AND e IS NULL)) IS DISTINCT FROM `+
			rbac.ExemptForGoodSQL("c.e"), args...)
		mismatched("exempt until", until+`(`+rbac.OverlapUntilSQL("c.p", "c.e")+`) IS DISTINCT FROM (`+rbac.ExemptUntilSQL("c.p", "c.e")+`)`, args...)
		mismatched("a change's exemption", until+`(CASE WHEN c.e && ARRAY(SELECT k FROM exempted) THEN `+rbac.OverlapUntilSQL("c.p", "c.e")+` END)
			IS DISTINCT FROM (CASE WHEN `+rbac.Keyed("c.e", "SELECT k FROM exempted")+` THEN `+rbac.ExemptUntilSQL("c.p", "c.e")+` END)`, args...)
		mismatched("a deny below the tenant", until+`(NOT c.e && ARRAY(SELECT k FROM exempted) OR `+rbac.OverlapUntilSQL("c.p", "c.e")+` IS NOT NULL)
			IS DISTINCT FROM (NOT `+rbac.Keyed("c.e", "SELECT k FROM exempted")+` OR `+rbac.ExemptUntilSQL("c.p", "c.e")+` IS NOT NULL)`, args...)
		if t.Failed() {
			return
		}
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
