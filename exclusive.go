package rbac

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"
)

// exclusive reports whether a dimension is Exclusive, so changes check that none lets an identity
// hold two of its values.
func (a *Authorizer) exclusive() bool {
	for _, ld := range a.labels {
		if ld.exclusive {
			return true
		}
	}
	return false
}

// lockExclusive takes a tenant's lock on exclusive values, before a change's other locks, so two
// changes that each give an identity one of a dimension's values run in turn, and the second's
// check reads the first.
func lockExclusive(ctx context.Context, tx pgx.Tx, tenant string) error {
	b := &pgx.Batch{}
	b.Queue(`SELECT current_setting('transaction_isolation')`)
	b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "exclusive/"+tenant)
	return locked(tx.SendBatch(ctx, b))
}

// twoExclusive returns two values of one exclusive dimension that ps gives, which no one holds at
// once, so a role giving both would give nothing; ok is false where it gives no two.
func twoExclusive(labels map[string]labelDimension, ps []Permission) (p, q Permission, ok bool) {
	first := map[string]Permission{}
	for _, r := range ps {
		t, v := r.parts()
		if !labels[t].exclusiveValue(v) {
			continue
		}
		if f, seen := first[t]; seen && f != r {
			return f, r, true
		}
		first[t] = r
	}
	return "", "", false
}

// exclusiveValue returns the dimension p is a value of, and whether that dimension is exclusive.
func (a *Authorizer) exclusiveValue(p Permission) (string, bool) {
	t, v := p.parts()
	return t, a.labels[t].exclusiveValue(v)
}

// exclusiveValues returns, by role, the values of exclusive dimensions each of roles gives.
func (a *Authorizer) exclusiveValues(roles []RoleDefinition) map[Role][]Permission {
	gives := map[Role][]Permission{}
	for _, r := range roles {
		for _, p := range r.Permissions {
			if _, ok := a.exclusiveValue(p); ok {
				gives[r.ID] = append(gives[r.ID], p)
			}
		}
	}
	return gives
}

// excludedBy returns the exclusive dimensions whose values held grants, as roles defines them,
// could give two of (exclusiveGiven).
func (a *Authorizer) excludedBy(roles book, held []holding) map[string]bool {
	excluded := map[string]bool{}
	for t, vs := range a.exclusiveGiven(roles, held) {
		if len(vs) > 1 {
			excluded[t] = true
		}
	}
	return excluded
}

// exclusiveGiven returns, by exclusive dimension, the values held grants, as roles defines them,
// could give; a role giving one is for the tenant alone. Each grant counts as written, whatever
// its condition, a constraint or a deny, and whether a check would honor it, as changes and
// Conflicts count it, so whether a value is held never turns on the request or the subject's
// attributes, and reading it asks no hook.
func (a *Authorizer) exclusiveGiven(roles book, held []holding) map[string]map[string]bool {
	given := map[string]map[string]bool{}
	for _, h := range held {
		def, ok := roles.role(h.Role)
		if !ok {
			continue
		}
		for _, p := range def.Permissions {
			t, ok := a.exclusiveValue(p)
			if !ok {
				continue
			}
			if given[t] == nil {
				given[t] = map[string]bool{}
			}
			_, v := p.parts()
			given[t][v] = true
		}
	}
	return given
}

// satisfiableByOne reports whether someone holding at most one of an exclusive dimension's values,
// and that one where given has one, could satisfy want, which has values: no one can where given
// has two, which leave none held, or where want, under AllOf, has two.
func (ld labelDimension) satisfiableByOne(given map[string]bool, want []string) bool {
	if len(given) > 1 {
		return false
	}
	one := want[0]
	for v := range given {
		one = v
	}
	switch ld.rule {
	case AnyOf:
		return slices.Contains(want, one)
	case AllOf:
		return !slices.ContainsFunc(want, func(w string) bool { return w != one })
	case Ordered:
		// Never exclusive, as a higher value includes the lower.
	}
	return true
}

// broadExcludes reports whether no one a broad principal stands for can do p to a resource labeled
// l, by the exclusive values the grants on a tenant to it, with the public's it includes, could
// give each of them: where two of a dimension, they hold none, so none holds p where it is one, nor
// passes l where it asks a value of it; and where one, each holds that one or none, so none passes
// l where it asks of that dimension values only another would satisfy.
func (a *Authorizer) broadExcludes(ctx context.Context, tenant string, b Principal, p Permission, l Label) (bool, error) {
	var dims []string
	for t, vs := range l {
		if len(vs) > 0 && a.labels[t].exclusive {
			dims = append(dims, t)
		}
	}
	dim, exclusive := a.exclusiveValue(p)
	if !exclusive && len(dims) == 0 {
		return false, nil
	}
	keys := []string{Principal{Kind: Public}.key()}
	if b.Kind == Members {
		keys = append(keys, b.key())
	}
	// With the custom roles they name, in one statement, as a check reads them: read apart, a grant
	// revoked and its role widened meanwhile could give two values no moment did. Only their
	// permissions, which alone exclusiveGiven reads.
	rows, err := a.db.Query(ctx, `
		WITH held AS (
		  SELECT DISTINCT role FROM rbac_grants WHERE tenant = $1 AND scope_type = 'tenant'
		    AND principal = ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3)
		)
		SELECT h.role, r.id IS NOT NULL, coalesce(r.permissions, '{}')
		FROM held h LEFT JOIN rbac_roles r ON r.tenant = $1 AND r.id = h.role`, tenant, keys, a.cfg.Now())
	if err != nil {
		return false, err
	}
	var held []holding
	var custom []RoleDefinition
	var id string
	var found bool
	var perms []string
	if _, err := pgx.ForEachRow(rows, []any{&id, &found, &perms}, func() error {
		held = append(held, holding{Binding: Binding{Role: Role(id)}})
		if found {
			custom = append(custom, roleFrom(id, "", "", perms, nil, false, false, nil))
		}
		return nil
	}); err != nil {
		return false, err
	}
	readingRoles()
	given := a.exclusiveGiven(a.bookOf(a.current(custom)), held)
	if exclusive && len(given[dim]) > 1 {
		return true, nil
	}
	return slices.ContainsFunc(dims, func(t string) bool { return !a.labels[t].satisfiableByOne(given[t], l[t]) }), nil
}

// Conflict is an identity able to hold two or more values of an exclusive dimension, through any
// grant or eligibility on the tenant, whatever its condition, and its own grants while it is no
// member or guest: a change reaching it is refused until a removal leaves it one, and where its
// grants could give it two now, it holds none of them. The public, for what it holds, is
// Principal{Kind: Public}.
type Conflict struct {
	Principal Principal
	Dimension string
	Values    []Permission
}

// Conflicts lists the identities in a tenant able to hold two values of an exclusive dimension,
// as a catalog change or a dimension made Exclusive leaves them, by principal and dimension. It
// has no limit or cursor, so what it returns grows with them, as after a catalog change that makes
// a role the tenant's members hold give two.
func (a *Authorizer) Conflicts(ctx context.Context, tenant string) ([]Conflict, error) {
	if !validID(tenant) {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if !a.exclusive() {
		return nil, nil
	}
	return snapshot(ctx, a, func(a *Authorizer) ([]Conflict, error) {
		custom, err := a.customRoles(ctx, a.db, tenant)
		if err != nil {
			return nil, err
		}
		gives := a.exclusiveValues(slices.Concat(a.cfg.Catalog, custom))
		// Only those holding a role that gives a value can hold two, so they alone are read.
		roles := []string{}
		for r := range gives {
			roles = append(roles, string(r))
		}
		return a.conflicts(ctx, a.db, tenant, gives, []string{}, roles, 0)
	})
}

// excludes refuses a change, e, that leaves an identity it reaches able to hold two values of an
// exclusive dimension: those whose grants, eligibilities, memberships or places in groups it set,
// those holding a custom role it redefined, and those, by key, whose suspended memberships it
// widened. Denies don't count, so lifting one is no change to check. One able to hold two before
// the change, as after a catalog change, is refused too, as the check reads the tenant as the
// change leaves it.
func (a *Authorizer) excludes(ctx context.Context, tx pgx.Tx, tenant string, e ChangeEvent, widened []string) error {
	gives := a.exclusiveValues(a.cfg.Catalog)
	// The tenant's custom roles are read only for a change that can reach someone, so one granting
	// built-in roles that give no exclusive value reads nothing more under the tenant's lock.
	reaches := func(r Role) bool { return gives[r] != nil || isCustom(r) }
	if !slices.ContainsFunc(e.Granted, func(g Grant) bool { return reaches(g.Role) }) &&
		!slices.ContainsFunc(e.Eligible, func(el Eligibility) bool { return reaches(el.Role) }) &&
		len(e.Roles)+len(e.Memberships)+len(e.Joined)+len(widened) == 0 {
		return nil
	}
	custom, err := a.customRoles(ctx, tx, tenant)
	if err != nil {
		return err
	}
	maps.Copy(gives, a.exclusiveValues(custom))
	// Empty, never nil, which pgx would send as NULL.
	seeds, redefined := []string{}, []string{}
	for _, g := range e.Granted {
		if gives[g.Role] != nil {
			seeds = append(seeds, g.Principal.key())
		}
	}
	for _, el := range e.Eligible {
		if gives[el.Role] != nil {
			seeds = append(seeds, el.Principal.key())
		}
	}
	for _, r := range e.Roles {
		if gives[r.ID] != nil {
			redefined = append(redefined, string(r.ID))
		}
	}
	// A suspended membership holds only what the public does, so suspending one never widens what
	// it holds, and isn't refused even where the public's grants could give two values; but a
	// member's made, renewed or lifted from a guest's suspended will hold more once lifted, which
	// lifting it would then be refused for.
	for _, m := range e.Memberships {
		if !m.Suspended {
			seeds = append(seeds, m.Principal.key())
		}
	}
	seeds = append(seeds, widened...)
	for _, m := range e.Joined {
		seeds = append(seeds, m.Principal.key())
	}
	if len(seeds)+len(redefined) == 0 {
		return nil
	}
	found, err := a.conflicts(ctx, tx, tenant, gives, seeds, redefined, 1)
	if err != nil || len(found) == 0 {
		return err
	}
	who := found[0].Principal.key()
	if found[0].Principal.Kind == Public {
		who = "the public"
	}
	return fmt.Errorf("%w: the change leaves %s able to hold two values of %s, whose values are exclusive", ErrInvalid, who, found[0].Dimension)
}

// conflicts returns up to limit, or with 0 every, conflict of the identities the seeds reach, as
// principal keys, and the holders of the roles in holdersOf, by gives, the exclusive values each
// role gives. Each is read up to its keys as checks read them, and its own grants even while it is
// no member or guest, which it holds once it is one; the anonymous, which holds what the public
// does, is read where the public is reached, as are those no member whose own grants or
// eligibilities give a value, which they hold beside the public's.
func (a *Authorizer) conflicts(ctx context.Context, q DB, tenant string, gives map[Role][]Permission, seeds, holdersOf []string, limit int) ([]Conflict, error) {
	roles, values := []string{}, []string{}
	for r, ps := range gives {
		for _, p := range ps {
			roles, values = append(roles, string(r)), append(values, string(p))
		}
	}
	// The planner can't tell which of targets' branches the seeds reach, so it costs a change's
	// check as if it read every identity in the tenant, past JIT's thresholds where they are in
	// groups: compiling then takes a second for a plan that runs in milliseconds. JIT is off for
	// this statement alone, so a host's transaction under WithTx gets its own setting back.
	var jit string
	if err := q.QueryRow(ctx, `SELECT current_setting('jit'), set_config('jit', 'off', true)`).Scan(&jit, nil); err != nil {
		return nil, err
	}
	// A change's check and the listing of every conflict are statements of their own, so the
	// listing's cost never moves a connection's cached plan for the check to a generic one.
	limited := ""
	if limit > 0 {
		limited = fmt.Sprintf(" LIMIT %d", limit)
	}
	// Each key's values are looked up by key, so a change reads what the identities it reaches
	// hold, not every value held in the tenant, and stops at the first conflict it finds.
	rows, err := q.Query(ctx, `
		WITH RECURSIVE seeds(k) AS (
		  SELECT unnest($2::text[]) COLLATE "C"
		  UNION SELECT principal FROM rbac_grants WHERE tenant = $1 AND role = ANY($3::text[])
		  UNION SELECT principal FROM rbac_eligibilities WHERE tenant = $1 AND role = ANY($3::text[])
		), `+insideSQL(`ARRAY(SELECT substr(k, 7) FROM seeds WHERE k LIKE 'group:%')`, "$4", "NULL", false)+`,
		targets(identity) AS (
		  SELECT k FROM seeds WHERE k NOT LIKE 'group:%' AND k NOT LIKE 'members:%' AND k <> 'public:'
		  UNION SELECT principal FROM inside
		  UNION SELECT principal FROM rbac_memberships WHERE tenant = $1
		    AND EXISTS (SELECT FROM seeds WHERE k IN ('members:' || $1, 'public:'))
		  UNION SELECT o.principal FROM (
		    SELECT principal FROM rbac_grants WHERE tenant = $1 AND role = ANY($5::text[])
		    UNION ALL
		    SELECT principal FROM rbac_eligibilities WHERE tenant = $1 AND role = ANY($5::text[])
		  ) o WHERE o.principal NOT LIKE 'group:%' AND o.principal NOT LIKE 'members:%' AND o.principal <> 'public:'
		    AND EXISTS (SELECT FROM seeds WHERE k = 'public:')
		  UNION SELECT '' WHERE EXISTS (SELECT FROM seeds WHERE k = 'public:')
		), held(identity, value) AS (
		  SELECT t.identity, v.value COLLATE "C" FROM targets t
		  CROSS JOIN LATERAL (WITH RECURSIVE `+keysSQL("$1::text", "t.identity", "$4")+` SELECT k FROM bound) ks
		  CROSS JOIN LATERAL (
		    SELECT role FROM rbac_grants WHERE tenant = $1 AND principal = ks.k AND scope = 'tenant:' || $1 AND role = ANY($5::text[])
		      AND (expires_at IS NULL OR expires_at > $4)
		    UNION ALL
		    SELECT role FROM rbac_eligibilities WHERE tenant = $1 AND principal = ks.k AND scope = 'tenant:' || $1 AND role = ANY($5::text[])
		      AND (expires_at IS NULL OR expires_at > $4)
		  ) g
		  JOIN unnest($5::text[], $6::text[]) AS v(role, value) ON v.role = g.role
		)
		SELECT identity, split_part(value, ':', 1), array_agg(DISTINCT value ORDER BY value) FROM held
		GROUP BY 1, 2 HAVING count(DISTINCT value) > 1 ORDER BY 1, 2`+limited,
		tenant, seeds, holdersOf, a.cfg.Now(), roles, values)
	if err != nil {
		return nil, err
	}
	var found []Conflict
	var c Conflict
	var who string
	var held []string
	_, err = pgx.ForEachRow(rows, []any{&who, &c.Dimension, &held}, func() error {
		c.Principal = Principal{Kind: Public}
		if who != "" {
			c.Principal = parsePrincipal(who)
		}
		c.Values = make([]Permission, len(held))
		for i, v := range held {
			c.Values[i] = Permission(v)
		}
		found = append(found, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, err := q.Exec(ctx, `SELECT set_config('jit', $1, true)`, jit); err != nil {
		return nil, err
	}
	return found, nil
}
