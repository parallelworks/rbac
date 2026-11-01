package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
)

// The clusters a freeze under workspace w1 covers, and one outside it.
var (
	frozenClusters = []rbac.Resource{
		{Tenant: "t1", Type: "cluster", ID: "k1", Ancestors: []rbac.Scope{workspace.Scope(), {Type: "org", ID: "o1"}}},
		{Tenant: "t1", Type: "cluster", ID: "k2", Ancestors: []rbac.Scope{workspace.Scope(), {Type: "org", ID: "o1"}}},
	}
	thawedCluster = rbac.Resource{Tenant: "t1", Type: "cluster", ID: "k3", Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
)

// frozenWorld is what one random world of groups, places, grants, eligibilities, activations and
// denies holds, by its seed, for a differential of the changes to members a freeze refuses.
type frozenWorld struct {
	h          *harness
	frozen     *bool
	identities []string
	groups     []string
	manager    rbac.Subject
}

// A freeze under a container refuses a change to members only where it changes there what a
// principal holds through its groups, as it refuses Apply changing a grant there, and every change
// taking access away there: each it refuses gives or takes away a grant, eligibility, approval,
// exemption or activation there, binds a principal to a deny there, or changes a place whose group,
// or one it is in, holds one of these there that the principal holds through another place too, as
// Apply revoking a grant held twice is refused; none it allows takes access away there, or gives a
// grant, eligibility or approval. The host's own writes, DeleteMembers and ImportMembers, make
// every change it allows or refuses under the freeze, as none of them checks an actor. Checked
// against random worlds, each change made first without the freeze, and rolled back, to see what it
// changes.
func TestAFreezeRefusesOnlyTheChangesToMembersThatChangeWhatGroupsGiveUnderIt(t *testing.T) {
	for _, by := range []string{"constraint", "deny"} {
		for seed := range uint64(3) {
			t.Run(fmt.Sprintf("%s %d", by, seed), func(t *testing.T) { freezeDifferential(t, by, seed) })
		}
	}
}

func freezeDifferential(t *testing.T, by string, seed uint64) {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, 92))
	frozen := false
	mutate := []func(*rbac.Config){func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			for _, r := range append(slices.Clone(frozenClusters), thawedCluster) {
				if r.Scope() == s {
					return r, nil
				}
			}
			return resourceOf(ctx, tenant, s)
		}
	}}
	if by == "constraint" {
		mutate = append(mutate, freezingUnder(workspace.Scope(), &frozen))
	}
	h := grouped(t, mutate...)
	w := frozenWorld{h: h, frozen: &frozen}
	w.seed(t, rng)
	base := h.now
	for i := range 30 {
		add, remove := w.change(t, rng)
		what := fmt.Sprintf("change %d: add %s, remove %s", i, members(add), members(remove))
		d, ok := w.taking(t, add, remove, base)
		if !ok {
			continue
		}
		taken := slices.Concat(d.lost, d.held, d.named)
		if err := w.hostChange(t, by, add, remove); err != nil {
			t.Errorf("%s: as the host's own writes under the freeze: %v", what, err)
		}
		err := w.frozenChange(t, by, add, remove)
		switch {
		case err == nil && len(taken)+len(d.granted) > 0:
			t.Errorf("%s: allowed under the freeze, yet changes %s", what, strings.Join(slices.Concat(taken, d.granted), ", "))
		case err == nil:
		case !errors.Is(err, rbac.ErrDenied):
			t.Errorf("%s: under the freeze: %v", what, err)
		case len(taken)+len(d.granted) == 0 && w.kept(t, d, add, remove, err):
			t.Logf("%s: refused, though what it changes there is given or kept through another place: %s", what, deniedAs(err))
		case len(taken)+len(d.granted) == 0:
			t.Errorf("%s: refused under the freeze, changing nothing there: %s", what, deniedAs(err))
		case len(d.lost) == 0 && len(d.granted) == 0:
			t.Logf("%s: refused, though no identity loses access there, for %s: %v", what, strings.Join(slices.Concat(d.held, d.named), ", "), err)
		}
	}
}

// kept reports whether a change refused on a scope, though nothing there changes, gives or ends a
// place in a group whose own or whose outer groups' grants, eligibilities, approvals or denies there
// its principal keeps through another place, before and after the change alike.
func (w *frozenWorld) kept(t *testing.T, d diff, add, remove []rbac.Member, err error) bool {
	t.Helper()
	var denied *rbac.DeniedError
	if !errors.As(err, &denied) {
		return false
	}
	rows, err := w.h.pool.Query(t.Context(), `
		SELECT principal FROM rbac_grants WHERE tenant = 't1' AND scope = $1
		UNION SELECT principal FROM rbac_eligibilities WHERE tenant = 't1' AND scope = $1
		UNION SELECT unnest(approvers) FROM rbac_eligibilities WHERE tenant = 't1' AND scope = $1
		UNION SELECT unnest(principals || exempt) FROM rbac_denies WHERE tenant = 't1' AND scope = $1`, denied.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	holders, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range slices.Concat(add, remove) {
		for _, g := range d.up[m.Group] {
			if !slices.Contains(holders, "group:"+g) {
				continue
			}
			everywhere := true
			for k, ids := range d.is {
				if strings.HasPrefix(k, fmt.Sprint(m.Principal)+" ") && (!slices.Contains(ids, g) || !slices.Contains(d.was[k], g)) {
					everywhere = false
				}
			}
			if everywhere {
				return true
			}
		}
	}
	return false
}

func deniedAs(err error) string {
	var d *rbac.DeniedError
	if errors.As(err, &d) {
		return fmt.Sprintf("%s on %s: %s", d.Permission, d.Scope.Key(), d.Reason)
	}
	return err.Error()
}

// seed makes a random world: groups nested in others, identities in them, grants, eligibilities and
// denies of the groups on clusters under the frozen workspace and outside it, the workspace too,
// activations made through the groups, some of whose eligibilities are then deleted, so the
// activations rest on the places alone, and identities' own grants beside those of their groups.
func (w *frozenWorld) seed(t *testing.T, rng *rand.Rand) {
	t.Helper()
	h, ctx := w.h, t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	w.groups = []string{"g1", "g2", "g3", "g4", "g5", "g6"}
	w.identities = []string{"u1", "u2", "u3", "u4", "u5"}
	h.groups(t, w.groups...)
	h.join(t, w.identities...)
	w.manager = h.as(t, "manager")
	clusters := append(slices.Clone(frozenClusters), thawedCluster)
	for _, r := range clusters {
		h.seed(t, grant(r.Scope(), "cluster.admin", rbac.User, "manager"), grant(r.Scope(), "guard", rbac.User, "manager"))
	}
	place := func(group string, p rbac.Principal) {
		exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', $1, $2, $3) ON CONFLICT DO NOTHING`,
			group, p.Kind, p.ID)
	}
	for i, inner := range w.groups {
		for _, outer := range w.groups[i+1:] {
			if rng.Float64() < 0.3 {
				place(outer, groupOf(inner))
			}
		}
	}
	for _, u := range w.identities {
		for _, g := range w.groups[:5] {
			if rng.Float64() < 0.35 {
				place(g, identity(u))
			}
		}
	}
	scopes := []rbac.Scope{workspace.Scope()}
	for _, r := range clusters {
		scopes = append(scopes, r.Scope())
	}
	roles := []string{"cluster.login", "cluster.sudo"}
	for _, r := range clusters {
		for _, g := range w.groups {
			if rng.Float64() < 0.3 {
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', $1, 'group', $2, $3)`,
					r.ID, g, roles[rng.IntN(len(roles))])
			}
			if rng.Float64() < 0.25 {
				exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					VALUES ('t1', 'cluster', $1, 'group', $2, 'cluster.sudo', 3600, '{}')`, r.ID, g)
			}
			// Grants that give nothing: ended, of a role the catalog no longer has, and one whose
			// condition reads an attribute no resource has; and an eligibility that has ended.
			switch rng.IntN(8) {
			case 0:
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
					VALUES ('t1', 'cluster', $1, 'group', $2, 'cluster.login', $3) ON CONFLICT DO NOTHING`, r.ID, g, h.now.Add(-time.Hour))
			case 1:
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', $1, 'group', $2, 'cluster.retired') ON CONFLICT DO NOTHING`, r.ID, g)
			case 2:
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, condition)
					VALUES ('t1', 'cluster', $1, 'group', $2, 'cluster.login', 'resource.attributes.env == "prod"') ON CONFLICT DO NOTHING`, r.ID, g)
			case 3:
				exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers, expires_at)
					VALUES ('t1', 'cluster', $1, 'group', $2, 'cluster.login', 3600, '{}', $3) ON CONFLICT DO NOTHING`, r.ID, g, h.now.Add(-time.Hour))
			}
		}
		for _, u := range w.identities {
			if rng.Float64() < 0.1 {
				exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', $1, 'user', $2, 'cluster.login')`,
					r.ID, u)
			}
		}
		if rng.Float64() < 0.4 {
			approver := w.groups[rng.IntN(len(w.groups))]
			exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
				VALUES ('t1', 'cluster', $1, 'user', 'v', 'cluster.sudo', 3600, ARRAY['group:' || $2])`, r.ID, approver)
		}
	}
	perms := []string{"cluster:login", "cluster:root"}
	for i, s := range scopes {
		for j := range 2 {
			if rng.Float64() >= 0.35 {
				continue
			}
			named := w.groups[rng.IntN(len(w.groups))]
			exempt := []string{}
			if e := w.groups[rng.IntN(len(w.groups))]; e != named && rng.Float64() < 0.5 {
				exempt = append(exempt, "group:"+e)
			}
			principals := []string{"group:" + named}
			if rng.Float64() < 0.3 {
				principals = append(principals, "user:"+w.identities[rng.IntN(len(w.identities))])
			}
			exec(`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions) VALUES ('t1', $1, $2, $3, $4, $5, $6)`,
				s.Type, s.ID, fmt.Sprintf("d%d-%d", i, j), principals, exempt, []string{perms[rng.IntN(len(perms))]})
		}
	}
	// Each identity activates through the groups' eligibilities it can.
	for _, u := range w.identities {
		for _, r := range clusters {
			if rng.Float64() < 0.7 {
				_, err := h.authz.Activate(ctx, rbac.Subject{Principal: identity(u)}, r, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "INC-1"})
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					t.Fatalf("Activate: %v", err)
				}
			}
		}
	}
	rows, err := h.pool.Query(ctx, `SELECT id FROM rbac_eligibilities WHERE tenant = 't1' AND principal_kind = 'group' ORDER BY scope, principal, role`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if rng.Float64() < 0.5 {
			exec(`DELETE FROM rbac_eligibilities WHERE id = $1`, id)
		}
	}
	// A suspended member holds nothing it is granted, but leaving a group still ends what it would
	// hold once the suspension is lifted.
	exec(`UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:u5'`)
}

// change is a random change to the world's members: a place removed, one added, a group nested in
// another, or a place made to end sooner.
func (w *frozenWorld) change(t *testing.T, rng *rand.Rand) (add, remove []rbac.Member) {
	t.Helper()
	rows, err := w.h.pool.Query(t.Context(), `SELECT group_id, principal_kind, principal_id FROM rbac_members WHERE tenant = 't1' ORDER BY 1, 2, 3`)
	if err != nil {
		t.Fatal(err)
	}
	var places []rbac.Member
	var m rbac.Member
	if _, err := pgx.ForEachRow(rows, []any{&m.Group, &m.Principal.Kind, &m.Principal.ID}, func() error {
		places = append(places, m)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 1 + rng.IntN(2) {
		switch op := rng.IntN(4); {
		case op == 0 && len(places) > 0:
			remove = append(remove, places[rng.IntN(len(places))])
		case op == 1:
			add = append(add, rbac.Member{Group: w.groups[rng.IntN(len(w.groups))], Principal: identity(w.identities[rng.IntN(len(w.identities))])})
		case op == 2:
			i := rng.IntN(len(w.groups) - 1)
			j := i + 1 + rng.IntN(len(w.groups)-i-1)
			add = append(add, rbac.Member{Group: w.groups[j], Principal: groupOf(w.groups[i])})
		case len(places) > 0:
			p := places[rng.IntN(len(places))]
			p.ExpiresAt = w.h.now.Add(time.Minute)
			add = append(add, p)
		}
	}
	return add, remove
}

func members(ms []rbac.Member) string {
	var s []string
	for _, m := range ms {
		e := ""
		if !m.ExpiresAt.IsZero() {
			e = " sooner"
		}
		s = append(s, fmt.Sprintf("%s in %s%s", m.Principal.ID, m.Group, e))
	}
	return "[" + strings.Join(s, "; ") + "]"
}

// diff is what a change does on the frozen clusters and the workspace: the access it takes from
// an identity, now or once a place made to end sooner has ended; what it takes from an identity or
// a group through the groups they are in, a grant, eligibility, approval or exemption of theirs or
// an activation; the denies naming one it joins; and the grants, eligibilities and approvals it
// gives one through them.
type diff struct {
	lost, held, named, granted []string
	// was and is are the groups each principal the change names is in, before and after it, at
	// each time read; up is those each group it names is in, and it.
	was, is, up map[string][]string
}

// taking makes the change without the freeze, in a transaction it rolls back, and returns what it
// does there; ok is false where it is refused without the freeze, as for a cycle.
func (w *frozenWorld) taking(t *testing.T, add, remove []rbac.Member, base time.Time) (d diff, ok bool) {
	t.Helper()
	h, ctx := w.h, t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	a := h.authz.WithTx(tx)
	at := []time.Time{base, base.Add(2 * time.Minute)}
	type state struct{ access, held, named map[string]bool }
	read := func() []state {
		var ss []state
		for _, now := range at {
			h.now = now
			s := state{access: map[string]bool{}}
			for _, u := range w.identities {
				for _, r := range frozenClusters {
					for _, p := range []rbac.Permission{view, login, root} {
						err := a.Authorize(ctx, rbac.Subject{Principal: identity(u)}, p, r)
						if err != nil && !errors.Is(err, rbac.ErrDenied) {
							t.Fatal(err)
						}
						s.access[fmt.Sprintf("%s %s on %s at +%s", u, p, r.ID, now.Sub(base))] = err == nil
					}
				}
			}
			s.held, s.named = w.through(ctx, t, tx, a, now, base)
			ss = append(ss, s)
		}
		h.now = base
		return ss
	}
	in := func() map[string][]string {
		got := map[string][]string{}
		for _, now := range at {
			h.now = now
			for _, m := range slices.Concat(add, remove) {
				ids, err := a.GroupsOf(ctx, "t1", m.Principal)
				if err != nil {
					t.Fatal(err)
				}
				got[fmt.Sprint(m.Principal, now)] = ids
			}
		}
		h.now = base
		return got
	}
	d.up = map[string][]string{}
	for _, m := range slices.Concat(add, remove) {
		ids, err := a.GroupsOf(ctx, "t1", groupOf(m.Group))
		if err != nil {
			t.Fatal(err)
		}
		d.up[m.Group] = append(ids, m.Group)
	}
	before := read()
	d.was = in()
	if err := a.ChangeMembers(ctx, w.manager, "t1", add, remove); err != nil {
		h.now = base
		return diff{}, false
	}
	after := read()
	d.is = in()
	for i := range at {
		for k, was := range before[i].access {
			if was && !after[i].access[k] {
				d.lost = append(d.lost, k)
			}
		}
		for k := range before[i].held {
			if !after[i].held[k] {
				d.held = append(d.held, "lost "+k)
			}
		}
		for k := range after[i].held {
			if !before[i].held[k] && !strings.Contains(k, "exemption") {
				d.granted = append(d.granted, "gained "+k)
			}
		}
		for k := range after[i].named {
			if !before[i].named[k] {
				d.named = append(d.named, "named "+k)
			}
		}
	}
	for _, l := range []*[]string{&d.lost, &d.held, &d.named, &d.granted} {
		slices.Sort(*l)
		*l = slices.Compact(*l)
	}
	return d, true
}

// through is what each identity and group holds through the groups it is in at now on the frozen
// clusters and the workspace, read in tx: grants, eligibilities and approvals of those groups,
// exemptions of them from denies, and an identity's activations; and the denies naming one of them.
func (w *frozenWorld) through(ctx context.Context, t *testing.T, tx pgx.Tx, a *rbac.Authorizer, now, base time.Time) (held, named map[string]bool) {
	t.Helper()
	held, named = map[string]bool{}, map[string]bool{}
	frozen := []string{"cluster:k1", "cluster:k2", "workspace:w1"}
	type row struct {
		scope, principal, role string
		approvers              []string
		expires                *time.Time
	}
	query := func(sql string, scan func(pgx.CollectableRow) (row, error)) []row {
		rows, err := tx.Query(ctx, sql, frozen, now)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := pgx.CollectRows(rows, scan)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	grants := query(`SELECT scope_type || ':' || scope_id, principal, role, expires_at FROM rbac_grants
		WHERE tenant = 't1' AND scope_type || ':' || scope_id = ANY($1) AND (expires_at IS NULL OR expires_at > $2)`,
		func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.scope, &x.principal, &x.role, &x.expires)
		})
	eligible := query(`SELECT scope_type || ':' || scope_id, principal, role, approvers FROM rbac_eligibilities
		WHERE tenant = 't1' AND scope_type || ':' || scope_id = ANY($1) AND (expires_at IS NULL OR expires_at > $2)`,
		func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.scope, &x.principal, &x.role, &x.approvers)
		})
	denies := query(`SELECT scope_type || ':' || scope_id, id, '', principals || ('{|}'::text[]) || exempt FROM rbac_denies
		WHERE tenant = 't1' AND scope_type || ':' || scope_id = ANY($1) AND $2::timestamptz IS NOT NULL`,
		func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.scope, &x.principal, &x.role, &x.approvers)
		})
	// A grant or eligibility of a role the catalog doesn't have gives nothing, as checks read it.
	catalog := map[string]bool{}
	for _, r := range w.h.cfg.Catalog {
		catalog[string(r.ID)] = true
	}
	givesNothing := func(r row) bool { return !catalog[r.role] }
	grants, eligible = slices.DeleteFunc(grants, givesNothing), slices.DeleteFunc(eligible, givesNothing)
	var principals []rbac.Principal
	for _, u := range w.identities {
		principals = append(principals, identity(u))
	}
	for _, g := range w.groups {
		principals = append(principals, groupOf(g))
	}
	for _, p := range principals {
		ids, err := a.GroupsOf(ctx, "t1", p)
		if err != nil {
			t.Fatal(err)
		}
		in := map[string]bool{}
		for _, id := range ids {
			if id != p.ID || p.Kind != rbac.Group {
				in["group:"+id] = true
			}
		}
		u := string(p.Kind) + ":" + p.ID
		at := " at +" + now.Sub(base).String()
		for _, g := range grants {
			switch {
			case in[g.principal]:
				held[fmt.Sprintf("%s's %s on %s through %s%s", u, g.role, g.scope, g.principal, at)] = true
			case g.principal == u && g.expires != nil:
				held[fmt.Sprintf("%s's activation of %s on %s until %s%s", u, g.role, g.scope, g.expires.Sub(base), at)] = true
			}
		}
		for _, e := range eligible {
			if in[e.principal] {
				held[fmt.Sprintf("%s's eligibility for %s on %s through %s%s", u, e.role, e.scope, e.principal, at)] = true
			}
			for _, q := range e.approvers {
				if in[q] {
					held[fmt.Sprintf("%s's approval of %s's %s on %s through %s%s", u, e.principal, e.role, e.scope, q, at)] = true
				}
			}
		}
		for _, d := range denies {
			i := slices.Index(d.approvers, "|")
			for _, q := range d.approvers[:i] {
				if in[q] {
					named[fmt.Sprintf("%s by deny %s on %s through %s%s", u, d.principal, d.scope, q, at)] = true
				}
			}
			for _, q := range d.approvers[i+1:] {
				if in[q] {
					held[fmt.Sprintf("%s's exemption from deny %s on %s through %s%s", u, d.principal, d.scope, q, at)] = true
				}
			}
		}
	}
	return held, named
}

// frozenChange makes the change under the freeze, in a transaction it rolls back.
func (w *frozenWorld) frozenChange(t *testing.T, by string, add, remove []rbac.Member) error {
	t.Helper()
	return w.underFreeze(t, by, func(ctx context.Context, a *rbac.Authorizer) error {
		return a.ChangeMembers(ctx, w.manager, "t1", add, remove)
	})
}

// hostChange makes the change as the host's own writes under the freeze, in a transaction it rolls
// back: DeleteMembers removing what it removes, and then ImportMembers adding what it adds, as
// ChangeMembers removes before it adds.
func (w *frozenWorld) hostChange(t *testing.T, by string, add, remove []rbac.Member) error {
	t.Helper()
	return w.underFreeze(t, by, func(ctx context.Context, a *rbac.Authorizer) error {
		if len(remove) > 0 {
			if err := a.DeleteMembers(ctx, host, "t1", remove); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			return a.ImportMembers(ctx, host, "t1", add)
		}
		return nil
	})
}

// underFreeze runs change in a transaction it rolls back, under the freeze: a constraint removing
// the power to change grants under the workspace, or a deny there removing the manager's.
func (w *frozenWorld) underFreeze(t *testing.T, by string, change func(context.Context, *rbac.Authorizer) error) error {
	t.Helper()
	h, ctx := w.h, t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if by == "deny" {
		if _, err := tx.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', 'workspace', 'w1', 'freeze', '{user:manager}', '{}', '{cluster:grant,workspace:grant}')`); err != nil {
			t.Fatal(err)
		}
	}
	*w.frozen = true
	defer func() { *w.frozen = false }()
	return change(ctx, h.authz.WithTx(tx))
}
