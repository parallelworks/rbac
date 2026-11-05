package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/parallelworks/rbac"
)

// storedGrant is a grant or eligibility of a custom role as a redefinition finds it stored: perhaps
// ended, with a condition, an activation, or to a principal no check reads it for.
type storedGrant struct {
	scope       rbac.Scope
	principal   rbac.Principal
	expired     bool
	conditional bool
	activation  bool
	eligibility bool
	id          string
}

func (g storedGrant) String() string {
	kind := "grant"
	switch {
	case g.eligibility:
		kind = "eligibility"
	case g.activation:
		kind = "activation"
	}
	return fmt.Sprintf("%s to %s:%s on %s (expired %t, conditional %t)", kind, g.principal.Kind, g.principal.ID, g.scope.Key(), g.expired, g.conditional)
}

// randomDefinition is a custom role's definition as stored: for clusters and workspaces, or for the
// tenant giving label values, and sometimes Public, privileged or not.
func randomDefinition(rng *rand.Rand, id rbac.Role) rbac.RoleDefinition {
	some := func(of []string) []string {
		var out []string
		for _, x := range of {
			if rng.IntN(2) == 0 {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			out = append(out, of[rng.IntN(len(of))])
		}
		return out
	}
	r := rbac.RoleDefinition{ID: id, Public: rng.IntN(3) == 0}
	perms, types := []string{string(view), string(login), string(root), "workspace:view"}, []string{"cluster", "workspace"}
	if rng.IntN(4) == 0 {
		perms, types = []string{"level:low", "level:high", "tenant:view"}, []string{rbac.TenantScope}
	}
	for _, p := range some(perms) {
		r.Permissions = append(r.Permissions, rbac.Permission(p))
	}
	r.ResourceTypes = some(types)
	return r
}

// redefined is was changed a little, as most redefinitions are: a permission or type added or
// dropped, or Public set or unset.
func redefined(rng *rand.Rand, was rbac.RoleDefinition) rbac.RoleDefinition {
	now := rbac.RoleDefinition{ID: was.ID, Permissions: slices.Clone(was.Permissions), ResourceTypes: slices.Clone(was.ResourceTypes), Public: was.Public}
	perms := []rbac.Permission{view, login, root, "workspace:view"}
	if slices.Equal(was.ResourceTypes, []string{rbac.TenantScope}) {
		perms = []rbac.Permission{"level:low", "level:high", "tenant:view"}
	}
	switch rng.IntN(4) {
	case 0:
		if p := perms[rng.IntN(len(perms))]; !slices.Contains(now.Permissions, p) {
			now.Permissions = append(now.Permissions, p)
		}
	case 1:
		if len(now.Permissions) > 1 {
			now.Permissions = slices.Delete(now.Permissions, 0, 1)
		}
	case 2:
		now.Public = !now.Public
	case 3:
		if !slices.Contains(now.ResourceTypes, rbac.TenantScope) {
			if len(now.ResourceTypes) > 1 {
				now.ResourceTypes = now.ResourceTypes[1:]
			} else {
				now.ResourceTypes = []string{"cluster", "workspace"}
			}
		}
	}
	return now
}

func sortedStrings[T ~string](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = string(x)
	}
	slices.Sort(out)
	return out
}

// Random redefinitions of random custom roles with random grants and eligibilities stored: the host
// is asked about each one whose access, as checks read it, grows, and its scope's denies are
// checked, and about no other but where the role gives more to whomever it is granted. A deny
// also stops a redefinition where a grant giving nothing through its principal, as one to the
// tenant's members of a privileged role, would give more once a catalog change that has the role
// no longer be privileged, or the host declaring its kind, has it give what the role gives, which
// asks no one, or where the role gives more and a role listing it is granted, whose holders may
// then grant it as it will be; and a scope the host no longer has is read as stored only where
// none of these is so. What a grant gives is read by checks of the grant alone in a tenant of its
// own, before and after, and again by a host that made both changes.
func TestRedefinitionsAskAboutAndCheckTheDeniesOfWhatGrantsGain(t *testing.T) {
	everything := rbac.RoleDefinition{
		ID:            "everything",
		Permissions:   []rbac.Permission{view, login, root, grantC, "workspace:view", "workspace:grant", "tenant:view", "tenant:grant"},
		ResourceTypes: []string{"cluster", "workspace", rbac.TenantScope}, Privileged: true,
	}
	var asked []rbac.GrantInput
	gone := map[rbac.Scope]bool{}
	h, guardian := guarded(t, func(c *rbac.Config) {
		c.Labels = []rbac.LabelDimension{{Name: "level", Rule: rbac.Ordered, Values: []string{"low", "high"}}}
		c.PrincipalKinds = []rbac.PrincipalKind{"agent"}
		c.Catalog = append(slices.Clone(c.Catalog), everything,
			rbac.RoleDefinition{ID: "level.low", Permissions: []rbac.Permission{"level:low"}, ResourceTypes: []string{rbac.TenantScope}},
			rbac.RoleDefinition{ID: "level.high", Permissions: []rbac.Permission{"level:high"}, ResourceTypes: []string{rbac.TenantScope}})
		c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaRedefinition {
				asked = append(asked, in)
			}
			return nil
		}
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if gone[s] {
				return rbac.Resource{}, fmt.Errorf("%w: %s", rbac.ErrNotFound, s.Key())
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "x"), grant(tenant, "everything", rbac.User, "x"),
		grant(tenant, "level.low", rbac.User, "x"), grant(tenant, "level.high", rbac.User, "x"))
	x := h.as(t, "x")
	lh := h.as(t, "lh")
	h.groups(t, "g0", "g1")
	// Each grant is read alone in o, by a subject it is to: a member of each group, so that a
	// grant to a group with no members in t1 is read for whom it gives once the group has them, and
	// r1 for one to a kind the host hasn't declared, once it has.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES
		('o', 'user', 'u1'), ('o', 'user', 'u2'), ('o', 'user', 'm0'), ('o', 'user', 'm1'), ('o', 'user', 'mm'), ('o', 'user', 'pu'), ('o', 'agent', 'a1'),
		('o', 'robot', 'r1');
		INSERT INTO rbac_groups (tenant, id) VALUES ('o', 'g0'), ('o', 'g1');
		INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('o', 'g0', 'user', 'm0'), ('o', 'g1', 'user', 'm1')`); err != nil {
		t.Fatal(err)
	}
	// later is the host once a catalog change has every custom role no longer be privileged, as a
	// role that isn't gives each permission on each type, and it declares robot.
	cfg := h.cfg
	cfg.Catalog = append(slices.Clone(cfg.Catalog), rbac.RoleDefinition{
		ID: "open", Permissions: []rbac.Permission{view, login, root, "workspace:view", "tenant:view"}, ResourceTypes: []string{"cluster", "workspace", rbac.TenantScope},
	})
	cfg.PrincipalKinds = append(slices.Clone(cfg.PrincipalKinds), "robot")
	later, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	subjectOf := func(az *rbac.Authorizer, p rbac.Principal) (rbac.Subject, bool) {
		switch p.Kind {
		case rbac.User, "agent":
			return rbac.Subject{Principal: p}, true
		case "robot":
			return rbac.Subject{Principal: p}, az == later
		case rbac.Group:
			return rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "m" + strings.TrimPrefix(p.ID, "g")}}, true
		case rbac.Members:
			return rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "mm"}}, true
		case rbac.Public:
			return rbac.Subject{}, true
		}
		return rbac.Subject{}, false
	}
	// What a grant on a scope gives is read on the scope and what is under it.
	under := func(s rbac.Scope) []rbac.Resource {
		switch s.Type {
		case "cluster":
			return []rbac.Resource{{Tenant: "o", Type: "cluster", ID: s.ID}}
		case "workspace":
			return []rbac.Resource{{Tenant: "o", Type: "workspace", ID: s.ID}, {Tenant: "o", Type: "cluster", ID: "in-" + s.ID, Ancestors: []rbac.Scope{s}}}
		}
		return []rbac.Resource{{Tenant: "o", Type: rbac.TenantScope, ID: "o"}, {Tenant: "o", Type: "cluster", ID: "kr"}, {Tenant: "o", Type: "workspace", ID: "vr"}}
	}
	writeRole := func(tenant string, r rbac.RoleDefinition) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, public) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant, id) DO UPDATE SET permissions = EXCLUDED.permissions, resource_types = EXCLUDED.resource_types, public = EXCLUDED.public`,
			tenant, r.ID, sortedStrings(r.Permissions), sortedStrings(r.ResourceTypes), r.Public); err != nil {
			t.Fatal(err)
		}
	}
	store := func(tenant string, role rbac.Role, g storedGrant) string {
		t.Helper()
		scope := g.scope
		if scope.Type == rbac.TenantScope {
			scope.ID = tenant
		}
		p := g.principal
		if p.Kind == rbac.Members {
			p.ID = tenant
		}
		var expires *time.Time
		switch {
		case g.expired:
			e := h.now.Add(-time.Hour)
			expires = &e
		case g.activation:
			e := h.now.Add(time.Hour)
			expires = &e
		}
		if g.eligibility && tenant == "t1" {
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, 3600, $7) ON CONFLICT DO NOTHING`, tenant, scope.Type, scope.ID, p.Kind, p.ID, role, expires); err != nil {
				t.Fatal(err)
			}
			return ""
		}
		// An eligibility is read in o as the grant activating it would make.
		source, condition := "", ""
		if g.activation {
			source = "activation"
		}
		if g.conditional {
			condition = "true"
		}
		var id string
		if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, condition)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING RETURNING id`, tenant, scope.Type, scope.ID, p.Kind, p.ID, role, source, expires, condition).Scan(&id); err != nil {
			return ""
		}
		return id
	}
	// gives is what g, alone in o, gives through its principal with the role defined as def, as
	// "resource permission" pairs, as az checks it.
	gives := func(az *rbac.Authorizer, def rbac.RoleDefinition, g storedGrant) map[string]bool {
		t.Helper()
		s, ok := subjectOf(az, g.principal)
		if !ok {
			return nil
		}
		if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 'o'; DELETE FROM rbac_roles WHERE tenant = 'o'`); err != nil {
			t.Fatal(err)
		}
		writeRole("o", def)
		g.eligibility = false
		store("o", def.ID, g)
		got := map[string]bool{}
		for _, r := range under(g.scope) {
			ps, err := az.Permissions(ctx, s, r)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range ps {
				got[r.Scope().Key()+" "+string(p)] = true
			}
		}
		return got
	}
	grows := func(was, now map[string]bool) bool {
		for k := range now {
			if !was[k] {
				return true
			}
		}
		return false
	}
	scopes := []rbac.Scope{{Type: "cluster", ID: "k1"}, {Type: "cluster", ID: "k2"}, {Type: "workspace", ID: "v1"}, {Type: "workspace", ID: "v2"}, tenant}
	principals := []rbac.Principal{
		identity("u1"), identity("u2"), groupOf("g1"), groupOf("g0"), rbac.TenantMembers("t1"),
		{Kind: rbac.Public},
		{Kind: "agent", ID: "a1"},
		{Kind: "robot", ID: "r1"},
	}
	ran := 0
	const runs = 120
	for seed := range uint64(runs) {
		rng := rand.New(rand.NewPCG(seed, 85))
		id := rbac.Role(fmt.Sprint("custom.r", seed))
		was := randomDefinition(rng, id)
		now := randomDefinition(rng, id)
		if rng.IntN(2) == 0 {
			now = redefined(rng, was)
		}
		var stored []storedGrant
		for range 1 + rng.IntN(5) {
			g := storedGrant{scope: scopes[rng.IntN(len(scopes))], principal: principals[rng.IntN(len(principals))], expired: rng.IntN(8) == 0, conditional: rng.IntN(6) == 0}
			switch broad := g.principal.Kind == rbac.Members || g.principal.Kind == rbac.Public; {
			case !broad && rng.IntN(5) == 0:
				g.eligibility = true
			case g.principal.Kind == rbac.User && rng.IntN(5) == 0:
				g.activation, g.conditional = true, false
			}
			stored = append(stored, g)
		}
		writeRole("t1", was)
		for i := range stored {
			stored[i].id = store("t1", id, stored[i])
		}
		// Sometimes a role listing it is granted to lh, whose holders may grant it on clusters and
		// workspaces without holding it.
		lister := rbac.Role(fmt.Sprint("custom.l", seed))
		var listedOn []rbac.Scope
		if rng.IntN(3) == 0 {
			listedOn = append(listedOn, scopes[rng.IntN(len(scopes))])
			on := listedOn[0]
			if on.Type == rbac.TenantScope {
				on.ID = "t1"
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', $1, '{cluster:grant,workspace:grant}', '{cluster,workspace}', $2)`, lister, []string{string(id)}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', $1, $2, 'user', 'lh', $3)`, on.Type, on.ID, lister); err != nil {
				t.Fatal(err)
			}
		}
		describe := fmt.Sprintf("seed %d: %v%v public %t to %v%v public %t, %v, listed on %v", seed, was.Permissions, was.ResourceTypes, was.Public, now.Permissions, now.ResourceTypes, now.Public, stored, listedOn)
		cleanup := func() {
			for _, q := range []string{`DELETE FROM rbac_grants WHERE tenant = 't1' AND role = $1`, `DELETE FROM rbac_roles WHERE tenant = 't1' AND id = $1`} {
				if _, err := h.pool.Exec(ctx, q, lister); err != nil {
					t.Fatal(err)
				}
			}
			for _, table := range []string{"rbac_grants", "rbac_eligibilities"} {
				if _, err := h.pool.Exec(ctx, `DELETE FROM `+table+` WHERE tenant = 't1' AND role = $1`, id); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_roles WHERE tenant = 't1' AND id = $1`, id); err != nil {
				t.Fatal(err)
			}
		}
		// Which scopes' denies the redefinition checks: a deny there removing from x every
		// permission the role will give refuses it, naming the scope. The tenant's are checked
		// across it, whatever its grants are, as they would stop granting the role anywhere.
		denied := map[rbac.Scope]bool{}
		observed := map[rbac.Scope]bool{}
		invalid := false
		for _, s := range scopes[:4] {
			var removes []rbac.Permission
			for _, p := range now.Permissions {
				if !strings.HasPrefix(string(p), "level:") {
					removes = append(removes, p)
				}
			}
			if len(removes) == 0 {
				continue
			}
			on := rbac.Resource{Tenant: "t1", Type: s.Type, ID: s.ID}
			if err := h.authz.SetDeny(ctx, guardian, on, rbac.Deny{ID: "probe", Permissions: removes, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			err := h.authz.SetRole(ctx, x, "t1", now)
			var de *rbac.DeniedError
			switch {
			case errors.As(err, &de) && de.Scope == s:
				denied[s] = true
			case errors.Is(err, rbac.ErrInvalid):
				invalid = true
			case err != nil:
				t.Fatalf("%s: under a deny on %s: %v", describe, s.Key(), err)
			}
			observed[s] = true
			if err := h.authz.DeleteDeny(ctx, guardian, on, "probe"); err != nil {
				t.Fatal(err)
			}
			writeRole("t1", was)
		}
		asked = nil
		if err := h.authz.SetRole(ctx, x, "t1", now); errors.Is(err, rbac.ErrInvalid) || invalid {
			cleanup()
			continue
		} else if err != nil {
			t.Fatalf("%s: %v", describe, err)
		}
		ran++
		var after rbac.RoleDefinition
		var perms []string
		if err := h.pool.QueryRow(ctx, `SELECT permissions, resource_types, public FROM rbac_roles WHERE tenant = 't1' AND id = $1`, id).Scan(&perms, &after.ResourceTypes, &after.Public); err != nil {
			t.Fatal(err)
		}
		after.ID = id
		for _, p := range perms {
			after.Permissions = append(after.Permissions, rbac.Permission(p))
		}
		// The role as a whole gives more where a grant of it on the tenant to an identity, or to the
		// public, gives more.
		root := storedGrant{scope: tenant, principal: identity("pu")}
		public := storedGrant{scope: tenant, principal: rbac.Principal{Kind: rbac.Public}}
		more := grows(gives(h.authz, was, root), gives(h.authz, after, root)) || grows(gives(h.authz, was, public), gives(h.authz, after, public))
		isAsked := func(g storedGrant) bool {
			return slices.ContainsFunc(asked, func(in rbac.GrantInput) bool {
				if g.eligibility {
					return in.Binding.ID == "" && in.Scope == g.scope && in.Binding.Principal == g.principal
				}
				return in.Binding.ID != "" && in.Binding.ID == g.id
			})
		}
		// A role for the tenant alone can be granted on a container, where it gives nothing, as no
		// tenant is in one; a redefinition reads it as giving what the role gives.
		reachesNothing := func(g storedGrant) bool {
			return g.scope.Type == "workspace" && slices.Equal(after.ResourceTypes, []string{rbac.TenantScope}) && !slices.ContainsFunc(after.Permissions, func(p rbac.Permission) bool { return strings.HasPrefix(string(p), "level:") })
		}
		inForce := func(g storedGrant) bool { return !g.expired && (g.eligibility || g.id != "") }
		for _, in := range asked {
			if !slices.ContainsFunc(stored, func(g storedGrant) bool {
				return inForce(g) && isAsked(g) && g.scope == in.Scope && g.principal == in.Binding.Principal
			}) {
				t.Errorf("%s: asked about %+v, which is no grant in force", describe, in)
			}
		}
		gains, dormant := map[rbac.Scope]bool{}, map[rbac.Scope]bool{}
		could := map[rbac.Scope]bool{}
		for _, g := range stored {
			if !inForce(g) {
				continue
			}
			before, then := gives(h.authz, was, g), gives(h.authz, after, g)
			// As the host reads it once it has made changes that ask no one: one to the tenant's
			// members gives what the role gives, and one to robot what it gives an identity.
			asWas, asNow := gives(later, was, g), gives(later, after, g)
			_, known := subjectOf(h.authz, g.principal)
			switch gained := grows(before, then); {
			case gained && known && !isAsked(g):
				t.Errorf("%s: %v gains %v but the host wasn't asked about it", describe, g, then)
			case grows(asWas, asNow) && known && g.principal.Kind != rbac.Members && !isAsked(g):
				t.Errorf("%s: %v gains %v once the catalog has the role no longer be privileged, but the host wasn't asked about it", describe, g, asNow)
			case isAsked(g) && (len(then) == 0 && !reachesNothing(g) || !gained && !more):
				t.Errorf("%s: asked about %v, which gives %v as it gave %v", describe, g, then, before)
			}
			if grows(before, then) {
				gains[g.scope] = true
			}
			if grows(asWas, asNow) {
				dormant[g.scope] = true
			}
			if (len(then) > 0 || len(asNow) > 0 || reachesNothing(g)) && (grows(before, then) || grows(asWas, asNow) || more) {
				could[g.scope] = true
			}
		}
		// Where it gives more, lh may grant it as it will be on what is under the scope the role
		// listing it is granted on, which a deny there stops as it stops granting it there.
		handsOn := map[rbac.Scope]bool{}
		for _, s := range listedOn {
			if !more {
				continue
			}
			var on []rbac.Resource
			switch s.Type {
			case "cluster":
				on = []rbac.Resource{{Tenant: "t1", Type: "cluster", ID: s.ID}}
			case "workspace":
				on = []rbac.Resource{{Tenant: "t1", Type: "workspace", ID: s.ID}, {Tenant: "t1", Type: "cluster", ID: "in-" + s.ID, Ancestors: []rbac.Scope{s}}}
			default:
				on = []rbac.Resource{{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, {Tenant: "t1", Type: "cluster", ID: "kr"}, {Tenant: "t1", Type: "workspace", ID: "vr"}}
			}
			for _, r := range on {
				roles, err := h.authz.Grantable(ctx, lh, r)
				if err != nil {
					t.Fatal(err)
				}
				if slices.ContainsFunc(roles, func(d rbac.RoleDefinition) bool { return d.ID == id }) {
					handsOn[s], could[s] = true, true
				}
			}
		}
		for s := range observed {
			switch {
			case handsOn[s] && !denied[s]:
				t.Errorf("%s: a role listing it is granted on %s, whose holders may grant it there as it will be, but a deny there doesn't stop it", describe, s.Key())
			case gains[s] && !denied[s]:
				t.Errorf("%s: a grant on %s gains, but a deny there doesn't stop it", describe, s.Key())
			case dormant[s] && !denied[s]:
				t.Errorf("%s: a grant on %s gains once the catalog has the role no longer be privileged, or the host declares its kind, but a deny there doesn't stop it", describe, s.Key())
			case denied[s] && !could[s]:
				t.Errorf("%s: a deny on %s stops it, where no grant gains", describe, s.Key())
			}
		}
		// With a deny elsewhere binding x, every scope is read: one the host no longer has fails the
		// redefinition where a grant there gains, or would so, and where none could is read as stored.
		var lost []rbac.Scope
		for _, s := range scopes[:4] {
			if rng.IntN(3) == 0 {
				lost = append(lost, s)
			}
		}
		if len(lost) > 0 {
			writeRole("t1", was)
			elsewhere := rbac.Resource{Tenant: "t1", Type: "cluster", ID: "kz"}
			if err := h.authz.SetDeny(ctx, guardian, elsewhere, rbac.Deny{ID: "elsewhere", Permissions: []rbac.Permission{view}, Principals: []rbac.Principal{x.Principal}}); err != nil {
				t.Fatal(err)
			}
			for _, s := range lost {
				gone[s] = true
			}
			err := h.authz.SetRole(ctx, x, "t1", now)
			clear(gone)
			if err := h.authz.DeleteDeny(ctx, guardian, elsewhere, "elsewhere"); err != nil {
				t.Fatal(err)
			}
			switch {
			case errors.Is(err, rbac.ErrNotFound):
				if !slices.ContainsFunc(lost, func(s rbac.Scope) bool { return could[s] }) {
					t.Errorf("%s: with %v gone, the redefinition fails with the host's error, where no grant there gains", describe, lost)
				}
			case err != nil:
				t.Fatalf("%s: with %v gone: %v", describe, lost, err)
			case slices.ContainsFunc(lost, func(s rbac.Scope) bool { return gains[s] || dormant[s] || handsOn[s] }):
				t.Errorf("%s: with %v gone, a grant there gains, or would so, or a role listing it there hands it on, but the redefinition reads it as stored", describe, lost)
			}
		}
		cleanup()
	}
	if ran < runs/2 {
		t.Errorf("only %d of %d redefinitions were valid", ran, runs)
	}
	t.Logf("%d of %d redefinitions were valid", ran, runs)
}

// removal is a constraint removing a permission from x as hosts write one: on what is at or under a
// scope (under), on one resource alone (id), on resources of an attribute (attr), or on what is at
// or under a scope for one type alone (byType); asked of no resource, it removes the permission
// where nilAny is set, as ConstraintInput asks, and otherwise nothing, as one written for resources
// alone does.
type removal struct {
	kind   string
	p      rbac.Permission
	s      rbac.Scope
	rt     string
	nilAny bool
}

func (r removal) String() string {
	return fmt.Sprintf("%s %s %s %s nil %t", r.kind, r.p, r.s.Key(), r.rt, r.nilAny)
}

func (r removal) removes(in rbac.ConstraintInput) bool {
	if in.Permission != r.p || in.Subject == nil || in.Subject.Principal.ID != "x" {
		return false
	}
	on := in.Resource
	if on == nil {
		return r.nilAny
	}
	under := on.Scope() == r.s || slices.Contains(on.Ancestors, r.s)
	switch r.kind {
	case "under":
		return under
	case "id":
		return on.Scope() == r.s
	case "attr":
		return on.Attributes["env"] == "prod"
	}
	return under && in.ResourceType == r.rt
}

var errProbed = errors.New("probed")

// Random widenings of random custom roles, granted, and listed by roles granted, on random scopes,
// under random constraints: SetRole refuses one exactly where Apply of the role as it will be, by
// the same actor, is refused on a scope where a grant of it gives more, or on a scope of a type
// that the holders of a role listing it, or listing one that does, may grant it on there, which a
// constraint answering for what is under the scope it is asked about answers as of that scope; and
// so too when one of these is granted while it waits, after which it is tried again. With
// Config.ResourceOf, and without it where each scope is stored whole.
func TestARedefinitionIsStoppedByAConstraintExactlyWhereApplyGrantingItIs(t *testing.T) {
	everything := rbac.RoleDefinition{
		ID:            "everything",
		Permissions:   []rbac.Permission{view, login, root, grantC, "workspace:view", "workspace:grant", "org:view", "org:grant", "tenant:view", "tenant:grant"},
		ResourceTypes: []string{"cluster", "workspace", "org", rbac.TenantScope}, Privileged: true,
	}
	at := func(typ, id string, attrs map[string]any, above ...rbac.Scope) rbac.Resource {
		return rbac.Resource{Tenant: "t1", Type: typ, ID: id, Ancestors: above, Attributes: attrs}
	}
	prod := map[string]any{"env": "prod"}
	dev := map[string]any{"env": "dev"}
	o1, o2, w1, w2 := rbac.Scope{Type: "org", ID: "o1"}, rbac.Scope{Type: "org", ID: "o2"}, rbac.Scope{Type: "workspace", ID: "w1"}, rbac.Scope{Type: "workspace", ID: "w2"}
	// Label values are decided on the tenant with no attributes, so one passed as prod removes none.
	for _, mode := range []struct {
		name       string
		containers bool
		scopes     []rbac.Resource
	}{
		{"as Config.ResourceOf gives each scope", true, []rbac.Resource{
			at(rbac.TenantScope, "t1", prod), at("org", "o1", dev), at("org", "o2", prod), at("workspace", "w1", dev, o1), at("workspace", "w2", prod, o2),
			at("workspace", "w3", dev), at("cluster", "c1", prod, w1, o1), at("cluster", "c2", dev, w2, o2), at("cluster", "c3", prod, o1), at("cluster", "c4", dev),
		}},
		{"stored whole", false, []rbac.Resource{
			at(rbac.TenantScope, "t1", nil), at("org", "o1", nil), at("workspace", "w1", nil), at("cluster", "c1", nil), at("cluster", "c2", nil), at("cluster", "c3", nil),
		}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var removals []removal
			var meanwhile func(context.Context) error
			resolved := map[rbac.Scope]int{}
			byScope := map[rbac.Scope]rbac.Resource{}
			for _, r := range mode.scopes {
				byScope[r.Scope()] = r
			}
			h := setup(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), everything)
				c.ValidateGrant = func(_ context.Context, _ rbac.DB, in rbac.GrantInput) error {
					if in.Binding.Principal.ID == "sink" {
						return errProbed
					}
					return nil
				}
				c.Constraints = []rbac.Constraint{{Name: "removals", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					// The freezes are asked of no resource after the scopes the change reaches are read.
					if do := meanwhile; do != nil && in.Resource == nil && strings.HasSuffix(string(in.Permission), ":grant") {
						meanwhile = nil
						if err := do(ctx); err != nil {
							return false, err
						}
					}
					return slices.ContainsFunc(removals, func(r removal) bool { return r.removes(in) }), nil
				}}}
				if !mode.containers {
					c.ContainerTypes, c.ResourceOf, c.Attributes = nil, nil, rbac.Attributes{Resource: map[string]rbac.AttributeType{}}
					return
				}
				c.Labels = []rbac.LabelDimension{{Name: "level", Rule: rbac.Ordered, Values: []string{"low", "high"}}}
				c.Catalog = append(c.Catalog, rbac.RoleDefinition{ID: "levels", Permissions: []rbac.Permission{"level:low", "level:high"}, ResourceTypes: []string{rbac.TenantScope}})
				c.ResourceOf = func(_ context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					resolved[s]++
					if r, ok := byScope[s]; ok && tenant == "t1" {
						return r, nil
					}
					return rbac.Resource{}, fmt.Errorf("%w: %s", rbac.ErrNotFound, s.Key())
				}
			})
			ctx := t.Context()
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "tenant.roles", rbac.User, "x"), grant(tenant, "everything", rbac.User, "x"))
			if mode.containers {
				h.seed(t, grant(tenant, "levels", rbac.User, "x"))
			}
			x := h.as(t, "x")
			for _, p := range []string{"y", "y2", "lh", "lh2", "sink"} {
				h.as(t, p)
			}
			contains := func(typ string) bool {
				return typ == rbac.TenantScope || mode.containers && (typ == "org" || typ == "workspace")
			}
			grantable := func(r rbac.RoleDefinition, typ string) bool {
				values := slices.ContainsFunc(r.Permissions, func(p rbac.Permission) bool { return strings.HasPrefix(string(p), "level:") })
				return contains(typ) && !values || slices.Contains(r.ResourceTypes, typ)
			}
			writeRole := func(r rbac.RoleDefinition) {
				t.Helper()
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', $1, $2, $3, $4)
					ON CONFLICT (tenant, id) DO UPDATE SET permissions = EXCLUDED.permissions, resource_types = EXCLUDED.resource_types, grantable_roles = EXCLUDED.grantable_roles`,
					r.ID, sortedStrings(r.Permissions), r.ResourceTypes, sortedStrings(r.GrantableRoles)); err != nil {
					t.Fatal(err)
				}
			}
			listed := []rbac.RoleDefinition{
				{ID: "custom.h1", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}},
				{ID: "custom.h2", Permissions: []rbac.Permission{"workspace:view"}, ResourceTypes: []string{"workspace"}},
			}
			for _, r := range listed {
				writeRole(r)
			}
			// target is where Apply of the role as it will be stands for what a scope reached hands on:
			// the scope itself, or for the holders of a role there granting it on scopes of another type
			// under it, one of that type under it that no constraint names but by what is above it.
			target := func(s rbac.Scope, typ string) rbac.Resource {
				r := byScope[s]
				if s.Type == typ {
					return r
				}
				g := rbac.Resource{Tenant: "t1", Type: typ, ID: "under-" + s.ID, Attributes: r.Attributes}
				if s.Type != rbac.TenantScope {
					g.Ancestors = append([]rbac.Scope{s}, r.Ancestors...)
				}
				return g
			}
			stops, runs, retried := 0, 0, 0
			for seed := range uint64(300) {
				rng := rand.New(rand.NewPCG(seed, 110))
				pick := func(n int) int { return rng.IntN(n) }
				// Sometimes a role for the tenant alone, giving label values.
				perms := []rbac.Permission{view, login, root, grantC, "workspace:view", "workspace:grant", "org:view", "org:grant", "tenant:view"}
				types := []string{"cluster", "workspace", "org"}
				if mode.containers && pick(5) == 0 {
					perms, types = []rbac.Permission{"level:low", "level:high", "tenant:view", "tenant:grant"}, []string{rbac.TenantScope}
				}
				some := func(n int) []int {
					var out []int
					for i := range n {
						if pick(2) == 0 {
							out = append(out, i)
						}
					}
					if len(out) == 0 {
						out = append(out, pick(n))
					}
					return out
				}
				was := rbac.RoleDefinition{ID: "custom.r"}
				for _, i := range some(len(perms)) {
					was.Permissions = append(was.Permissions, perms[i])
				}
				for _, i := range some(len(types)) {
					was.ResourceTypes = append(was.ResourceTypes, types[i])
				}
				now := rbac.RoleDefinition{ID: was.ID, Permissions: slices.Clone(was.Permissions), ResourceTypes: slices.Clone(was.ResourceTypes)}
				for range 1 + pick(2) {
					if p := perms[pick(len(perms))]; !slices.Contains(now.Permissions, p) {
						now.Permissions = append(now.Permissions, p)
					}
				}
				if typ := types[pick(len(types))]; pick(3) == 0 && !slices.Contains(now.ResourceTypes, typ) {
					now.ResourceTypes = append(now.ResourceTypes, typ)
				}
				// It gives more, so every scope it is granted on gains.
				if len(now.Permissions) == len(was.Permissions) && len(now.ResourceTypes) == len(was.ResourceTypes) {
					if i := slices.IndexFunc(perms, func(p rbac.Permission) bool { return !slices.Contains(was.Permissions, p) }); i >= 0 {
						now.Permissions = append(now.Permissions, perms[i])
					} else if i := slices.IndexFunc(types, func(typ string) bool { return !slices.Contains(was.ResourceTypes, typ) }); i >= 0 {
						now.ResourceTypes = append(now.ResourceTypes, types[i])
					} else {
						continue
					}
				}
				for _, l := range listed {
					if pick(4) == 0 {
						now.GrantableRoles = append(now.GrantableRoles, l.ID)
					}
				}
				var grantedOn []rbac.Scope
				for range 1 + pick(3) {
					if s := mode.scopes[pick(len(mode.scopes))].Scope(); grantable(was, s.Type) && !slices.Contains(grantedOn, s) {
						grantedOn = append(grantedOn, s)
					}
				}
				// A role listing it whose holders may grant it on scopes of one type, granted on a scope,
				// and sometimes one listing that: each hands it on where it is granted only where its
				// grant reaches scopes of the type it may grant on, as nothing reaches the tenant but
				// itself, and only by a `<type>:grant` it gives for that type, not one it gives for
				// another, which changes no grants.
				type listing struct {
					role    rbac.RoleDefinition
					on      rbac.Scope
					typ     string
					reaches bool
				}
				reaches := func(on, typ string) bool { return on == typ || contains(on) && typ != rbac.TenantScope }
				var listings []listing
				listedTypes := slices.DeleteFunc(slices.Concat(now.ResourceTypes, []string{"org", "workspace", rbac.TenantScope}), func(typ string) bool { return !grantable(now, typ) })
				if len(listedTypes) > 0 && pick(2) == 0 {
					typ := listedTypes[pick(len(listedTypes))]
					l := rbac.RoleDefinition{ID: "custom.l", Permissions: []rbac.Permission{rbac.GrantPermission(typ)}, ResourceTypes: []string{typ}, GrantableRoles: []rbac.Role{was.ID}}
					if other := listedTypes[pick(len(listedTypes))]; other != typ && pick(2) == 0 {
						l.Permissions = append(l.Permissions, rbac.GrantPermission(other))
					}
					if s := mode.scopes[pick(len(mode.scopes))].Scope(); grantable(l, s.Type) {
						listings = append(listings, listing{l, s, typ, reaches(s.Type, typ)})
						if over := []string{typ, "org", "workspace"}[pick(3)]; pick(3) == 0 && grantable(l, over) {
							l2 := rbac.RoleDefinition{ID: "custom.l2", Permissions: []rbac.Permission{rbac.GrantPermission(over)}, ResourceTypes: []string{over}, GrantableRoles: []rbac.Role{l.ID}}
							if s2 := mode.scopes[pick(len(mode.scopes))].Scope(); grantable(l2, s2.Type) {
								listings = append(listings, listing{l2, s2, typ, reaches(s2.Type, over) && reaches(over, typ)})
							}
						}
					}
				}
				removals = nil
				for range 1 + pick(2) {
					// Mostly of what the role, a role it lists, or one listing it gives.
					given := slices.Clone(now.Permissions)
					for _, l := range listed {
						if slices.Contains(now.GrantableRoles, l.ID) {
							given = append(given, l.Permissions...)
						}
					}
					for _, l := range listings {
						given = append(given, l.role.Permissions...)
					}
					if pick(3) == 0 {
						given = append(slices.Clone(perms), "tenant:grant")
					}
					r := removal{kind: []string{"under", "id", "attr", "byType"}[pick(4)], p: given[pick(len(given))], nilAny: pick(2) == 0}
					// One naming a container by id answers of it what it doesn't of the scopes under it,
					// which a target stands for.
					if r.s = mode.scopes[1+pick(len(mode.scopes)-1)].Scope(); r.kind == "id" && contains(r.s.Type) {
						r.kind = "under"
					}
					r.rt = now.ResourceTypes[pick(len(now.ResourceTypes))]
					// A freeze answering true of no resource stops every redefinition of a role whose
					// grants can be on its type, wherever they are.
					if strings.HasSuffix(string(r.p), ":grant") {
						r.nilAny = false
					}
					removals = append(removals, r)
				}
				// Sometimes the role, or one listing it, is granted on another scope while the change waits.
				var late *rbac.Grant
				if pick(3) == 0 {
					s := mode.scopes[pick(len(mode.scopes))].Scope()
					switch {
					case len(listings) > 0 && pick(2) == 0 && grantable(listings[0].role, s.Type):
						g := grant(s, listings[0].role.ID, rbac.User, "lh2")
						late = &g
					case grantable(was, s.Type):
						g := grant(s, was.ID, rbac.User, "y2")
						late = &g
					}
				}
				describe := fmt.Sprintf("seed %d: %v%v to %v%v listing %v, granted on %v, listed %v, late %v, removals %v",
					seed, was.Permissions, was.ResourceTypes, now.Permissions, now.ResourceTypes, now.GrantableRoles, grantedOn, listings, late, removals)
				writeRole(was)
				var stored []rbac.Grant
				for _, s := range grantedOn {
					stored = append(stored, grant(s, was.ID, rbac.User, "y"))
				}
				for _, l := range listings {
					writeRole(l.role)
					stored = append(stored, grant(l.on, l.role.ID, rbac.User, "lh"))
				}
				h.seed(t, stored...)
				probe := now
				probe.ID = "custom.probe"
				writeRole(probe)
				// refusing is the scopes where Apply of the role as it will be is refused, each by the
				// scope a refusal of the redefinition names.
				refusing := func(granted []rbac.Scope, listings []listing) map[rbac.Scope]bool {
					t.Helper()
					type asked struct {
						on    rbac.Resource
						named rbac.Scope
					}
					var applied []asked
					// A grant on a scope the role as it will be can't be granted on gives nothing more.
					for _, s := range granted {
						if grantable(probe, s.Type) {
							applied = append(applied, asked{byScope[s], s})
						}
					}
					for _, l := range listings {
						if l.reaches {
							applied = append(applied, asked{target(l.on, l.typ), l.on})
						}
					}
					refused := map[rbac.Scope]bool{}
					for _, a := range applied {
						switch err := h.authz.Apply(ctx, x, a.on, rbac.Change{Grant: []rbac.Binding{{Role: probe.ID, Principal: identity("sink")}}}); {
						case errors.Is(err, errProbed):
						case errors.Is(err, rbac.ErrDenied):
							refused[a.named] = true
						default:
							t.Fatalf("%s: Apply on %s: %v", describe, a.on.Scope().Key(), err)
						}
					}
					return refused
				}
				before := refusing(grantedOn, listings)
				after := before
				// A scope it gives more on once the late grant is made, that it didn't before.
				var unasked bool
				if late != nil {
					afterOn, afterListings := slices.Clone(grantedOn), slices.Clone(listings)
					var known []rbac.Scope
					for _, s := range grantedOn {
						if grantable(now, s.Type) {
							known = append(known, s)
						}
					}
					gains := late.Role == was.ID && grantable(now, late.Scope.Type)
					for _, l := range listings {
						if l.reaches {
							known = append(known, l.on)
						}
						if l.role.ID == late.Role {
							afterListings = append(afterListings, listing{l.role, late.Scope, l.typ, reaches(late.Scope.Type, l.typ)})
							gains = gains || reaches(late.Scope.Type, l.typ)
						}
					}
					if late.Role == was.ID {
						afterOn = append(afterOn, late.Scope)
					}
					unasked = gains && !slices.Contains(known, late.Scope)
					after = refusing(afterOn, afterListings)
					meanwhile = func(ctx context.Context) error { return h.authz.Import(ctx, host, "t1", []rbac.Grant{*late}) }
				}
				// The host gives each scope once in each attempt, both before the transaction and under
				// its lock.
				setRole := func() error {
					t.Helper()
					clear(resolved)
					err := h.authz.SetRole(ctx, x, "t1", now)
					for s, n := range resolved {
						if n > 1 {
							t.Errorf("%s: Config.ResourceOf gave %s %d times", describe, s.Key(), n)
						}
					}
					return err
				}
				err := setRole()
				meanwhile = nil
				clean := func() {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND role IN ('custom.r', 'custom.l', 'custom.l2');
						DELETE FROM rbac_roles WHERE tenant = 't1' AND id IN ('custom.r', 'custom.l', 'custom.l2', 'custom.probe')`); err != nil {
						t.Fatal(err)
					}
				}
				if errors.Is(err, rbac.ErrInvalid) {
					clean()
					continue
				}
				runs++
				// Refused before its transaction, it is decided on the scopes it read then; otherwise on
				// those under the tenant's lock, having been tried again where one it gives more on there
				// wasn't asked about.
				decided := before
				switch {
				case late == nil || len(before) > 0:
				case errors.Is(err, rbac.ErrConflict):
					retried++
					err = setRole()
					decided = after
				case unasked:
					t.Errorf("%s: a scope it gives more on was granted on while it waited, but it wasn't tried again: %v", describe, err)
					decided = after
				default:
					decided = after
				}
				var denied *rbac.DeniedError
				switch {
				case err == nil && len(decided) > 0:
					t.Errorf("%s: widened, though Apply granting it as it will be is refused on %v", describe, slices.Collect(maps.Keys(decided)))
				case err == nil:
				case !errors.As(err, &denied):
					t.Fatalf("%s: %v", describe, err)
				case len(decided) == 0:
					t.Errorf("%s: refused, though Apply granting it as it will be is refused nowhere it gives more: %v", describe, err)
				case !decided[denied.Scope] || !strings.Contains(denied.Reason, "removals"):
					t.Errorf("%s: refused on %s, though Apply granting it as it will be is refused on %v: %v", describe, denied.Scope.Key(), slices.Collect(maps.Keys(decided)), err)
				default:
					stops++
				}
				clean()
			}
			if runs < 150 || stops < runs/10 || stops > runs*9/10 || retried < 10 {
				t.Errorf("%d redefinitions were valid, of which constraints stopped %d, and %d were tried again", runs, stops, retried)
			}
			t.Logf("%d redefinitions were valid, of which constraints stopped %d, and %d were tried again", runs, stops, retried)
		})
	}
}
