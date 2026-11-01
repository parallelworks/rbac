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
	b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, lockName("exclusive", tenant, ""))
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
		if vs := a.exclusiveIn(r); len(vs) > 0 {
			gives[r.ID] = vs
		}
	}
	return gives
}

// exclusiveIn returns the values of exclusive dimensions r gives, reading each of its permissions.
func (a *Authorizer) exclusiveIn(r RoleDefinition) []Permission {
	readingEntries(len(r.Permissions))
	var vs []Permission
	for _, p := range r.Permissions {
		if _, ok := a.exclusiveValue(p); ok {
			vs = append(vs, p)
		}
	}
	return vs
}

// excludedBy returns the exclusive dimensions whose values held grants, as roles defines them,
// could give two of (exclusiveGiven). Where no dimension is exclusive there are none, and it reads
// no role.
func (a *Authorizer) excludedBy(roles book, held []holding) map[string]bool {
	if !a.exclusive() {
		return nil
	}
	return excludedOf(a.exclusiveOf(roles, held), held)
}

// excludedOf is excludedBy of held by of, the values of exclusive dimensions each role of held
// gives (exclusiveOf), so a decision about many paths reads each role once for all of them.
func excludedOf(of map[Role][]Permission, held []holding) map[string]bool {
	excluded := map[string]bool{}
	for t, vs := range givenOf(of, held) {
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
	return givenOf(a.exclusiveOf(roles, held), held)
}

// exclusiveOf returns, by role, the values of exclusive dimensions each role held grants name
// gives, as roles defines it, and none for one roles doesn't have. Each role's permissions are read
// once however many grants name it: a role can give a thousand, and an actor hold it many times,
// each grant ending at another time.
func (a *Authorizer) exclusiveOf(roles book, held []holding) map[Role][]Permission {
	of := map[Role][]Permission{}
	for _, h := range held {
		if _, read := of[h.Role]; read {
			continue
		}
		var vs []Permission
		if def, ok := roles.role(h.Role); ok {
			vs = a.exclusiveIn(def)
		}
		of[h.Role] = vs
	}
	return of
}

// givenOf is exclusiveGiven of held by of, the values of exclusive dimensions each role of held
// gives (exclusiveOf).
func givenOf(of map[Role][]Permission, held []holding) map[string]map[string]bool {
	given := map[string]map[string]bool{}
	for _, h := range held {
		for _, p := range of[h.Role] {
			t, v := p.parts()
			if given[t] == nil {
				given[t] = map[string]bool{}
			}
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
	// permissions, which alone exclusiveGiven reads, and by key: as of a time, a join to them reads
	// every role's newest version. By the tenant's scope, which the indexes seek beside the
	// principal: by its type, which none holds, it reads every grant they hold in the tenant.
	rows, err := a.db.Query(ctx, `
		WITH held AS (
		  SELECT DISTINCT role FROM rbac_grants WHERE tenant = $1 AND scope = 'tenant:' || $1
		    AND principal = ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3)
		)
		SELECT h.role, r.id IS NOT NULL, coalesce(r.permissions, '{}')
		FROM held h LEFT JOIN (`+byKey(namedCustom("SELECT role FROM held"), "rbac_roles", "id", "id, permissions", "tenant = $1")+`) r
		  ON r.id = h.role`, tenant, keys, a.cfg.Now())
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
// member or guest: a change reaching it, but one that only rewrites what it holds (excludes), is
// refused until a removal leaves it one, and where its grants could give it two now, it holds
// none of them. The public, for what it holds, is Principal{Kind: Public}.
type Conflict struct {
	Principal Principal
	Dimension string
	Values    []Permission
}

// Conflicts lists the identities in a tenant able to hold two values of an exclusive dimension,
// as a catalog change or a dimension made Exclusive leaves them, by principal and dimension. It
// has no limit or cursor, so what it returns grows with them, as after a catalog change that makes
// a role the tenant's members hold give two. It reads the custom roles in the statement that reads
// their grants, so what it lists one moment held, under WithTx at READ COMMITTED too.
func (a *Authorizer) Conflicts(ctx context.Context, tenant string) (_ []Conflict, err error) {
	defer conflicting(&err)
	a = a.still()
	if !validID(tenant) {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if !a.exclusive() {
		return nil, nil
	}
	gives := a.exclusiveValues(a.cfg.Catalog)
	// Only those holding a role that gives a value can hold two, so they alone are read: the
	// built-in ones here, and the custom ones in the statement.
	roles := []string{}
	for r := range gives {
		roles = append(roles, string(r))
	}
	// In a transaction, which holds JIT off for the statement (withoutJIT).
	return snapshot(ctx, a, func(a *Authorizer) ([]Conflict, error) {
		return a.conflicts(ctx, a.db, tenant, gives, []string{}, roles, true, 0)
	})
}

// excludes refuses a change, e, that leaves an identity it reaches able to hold two values of an
// exclusive dimension: those whose grants or eligibilities it set, those holding a custom role it
// redefined, and those, by key, whose memberships or places in groups it widened (g). Denies don't
// count, so lifting one is no change to check, and neither does a membership or place it only
// made end sooner, a removal then, nor a grant, an eligibility or a role it only rewrote. One able
// to hold two before the change, as after a catalog change, is refused too, as the check reads the
// tenant as the change leaves it.
func (a *Authorizer) excludes(ctx context.Context, tx pgx.Tx, tenant string, e ChangeEvent, g gains) error {
	e.Granted = slices.DeleteFunc(slices.Clone(e.Granted), func(gr Grant) bool { return g.rewrote[gr.ID] })
	e.Eligible = slices.DeleteFunc(slices.Clone(e.Eligible), func(el Eligibility) bool { return g.rewrote[eligibilityKey(el)] })
	e.Roles = slices.DeleteFunc(slices.Clone(e.Roles), func(r RoleDefinition) bool { return g.rewrote[string(r.ID)] })
	widened := g.widened
	gives := a.exclusiveValues(a.cfg.Catalog)
	// The tenant's custom roles are read only for a change that can reach someone, so one granting
	// built-in roles that give no exclusive value reads nothing more under the tenant's lock.
	reaches := func(r Role) bool { return gives[r] != nil || isCustom(r) }
	if !slices.ContainsFunc(e.Granted, func(g Grant) bool { return reaches(g.Role) }) &&
		!slices.ContainsFunc(e.Eligible, func(el Eligibility) bool { return reaches(el.Role) }) &&
		len(e.Roles)+len(widened) == 0 {
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
	seeds = append(seeds, widened...)
	if len(seeds)+len(redefined) == 0 {
		return nil
	}
	found, err := a.conflicts(ctx, tx, tenant, gives, seeds, redefined, false, 1)
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
// role gives, and with readCustom, by the tenant's custom roles too, each a giver of the values it
// gives and its holders read, in the statement that reads their grants: read apart, as under WithTx
// at READ COMMITTED each statement reads a moment of its own, a role narrowed and a value granted
// meanwhile would read as a conflict no moment held. Each is read up to its keys as checks read
// them, and its own grants even while it is no member or guest, which it holds once it is one; the
// anonymous, which holds what the public does, is read where the public is reached, as are those
// no member whose own grants or eligibilities give a value, which they hold beside the public's.
func (a *Authorizer) conflicts(ctx context.Context, q DB, tenant string, gives map[Role][]Permission, seeds, holdersOf []string, readCustom bool,
	limit int,
) ([]Conflict, error) {
	roles, values := []string{}, []string{}
	for r, ps := range gives {
		for _, p := range ps {
			roles, values = append(roles, string(r)), append(values, string(p))
		}
	}
	// A change's check and the listing of every conflict are statements of their own, so the
	// listing's cost never moves a connection's cached plan for the check to a generic one.
	limited := ""
	if limit > 0 {
		limited = fmt.Sprintf(" LIMIT %d", limit)
	}
	// The holders of roles are read only where holdersOf names some: in the statement's text, which
	// then plans no read of them. A generic plan can't tell from an empty array to read none. Of
	// custom roles alone, as a redefinition names, they are read a role at a time, through the index
	// leading to custom roles; no index leads to a built-in one, so with one among them, as where every
	// conflict is listed, every grant and eligibility in the tenant is read. Those the statement reads
	// itself (readCustom) are read a role at a time beside them.
	holders, custom := "FALSE", "FALSE"
	switch {
	case slices.ContainsFunc(holdersOf, func(r string) bool { return !isCustom(Role(r)) }):
		holders = "TRUE"
	case len(holdersOf) > 0:
		custom = "TRUE"
	}
	given, args := givenArgs, []any{tenant, seeds, holdersOf, a.cfg.Now(), roles, values}
	if readCustom {
		given, custom = givenWithCustom, "TRUE"
	}
	// The planner can't tell which of targets' branches the seeds reach, so it costs a change's
	// check as if it read every identity in the tenant, past JIT's thresholds where they are in
	// groups: compiling then takes a second for a plan that runs in milliseconds.
	return withoutJIT(ctx, q, func() ([]Conflict, error) {
		return conflictsIn(ctx, q, given, args, holders, custom, limited)
	})
}

// valuesGiven is SQL for the roles giving exclusive values as conflictsIn reads them: with, the
// WITH entry they need, or none; pairs, each role and a value it gives, as v(role, value); gives,
// whether the role of a row read among the tenant's is one of them, and held, one whose holders are
// read; alsoGives, the principals of the rows of those gives leaves out, or none; givesKeys,
// whether the role of a row read by its key is one; and holders, an array of the custom roles
// whose holders are read.
type valuesGiven struct{ with, pairs, gives, held, alsoGives, givesKeys, holders string }

var (
	// givenArgs are the roles and values conflicts is passed, $5 and $6, and the holders of $3, as
	// arrays a statement planned for its arguments reads the elements of, and finds a row's role in
	// by a hash of them.
	givenArgs = valuesGiven{
		pairs: "unnest($5::text[], $6::text[]) AS v(role, value)", gives: "role = ANY($5::text[])", held: "role = ANY($3::text[])",
		givesKeys: "role = ANY($5::text[])", holders: "$3",
	}
	// givenWithCustom are those, with $5 and $6 every built-in role giving a value, and the tenant's
	// custom roles giving any of $6, all a custom role can give of them as current reads it, read
	// with their grants, each a role whose holders are read beside those of $3. The custom ones' rows
	// are read a role at a time (customRoleRows): matched against roles the statement reads, even by
	// IN, which hashes them, a row's role is found by no index, so as of a time every version of every
	// grant in the tenant would be read, not those history's index on roles finds. For each key,
	// whose rows are few, a role is looked up in an array of them all, which IN would hash for each.
	givenWithCustom = valuesGiven{
		with: `custom_given(role, value) AS (
		  SELECT r.id, p.value FROM rbac_roles r CROSS JOIN LATERAL unnest(r.permissions) AS p(value)
		  WHERE r.tenant = $1 AND p.value = ANY($6::text[])
		), given(role, value) AS (
		  SELECT * FROM unnest($5::text[], $6::text[]) UNION ALL SELECT * FROM custom_given
		), `,
		pairs: "given AS v", gives: givenArgs.gives, held: givenArgs.held,
		alsoGives: `
		    UNION ALL
		    SELECT principal FROM (` + customRoleRows(customGiving, "rbac_grants", "principal", "TRUE") + `) cg
		    UNION ALL
		    SELECT principal FROM (` + customRoleRows(customGiving, "rbac_eligibilities", "principal", "TRUE") + `) ce`,
		givesKeys: "role = ANY(ARRAY(SELECT role FROM given))", holders: customGiving,
	}
)

// customGiving is the custom roles givenWithCustom reads as giving values, each once.
const customGiving = "ARRAY(SELECT DISTINCT role FROM custom_given)"

// conflictsIn is conflicts' statement, run with args: of the roles giving values, as given reads
// them, the holders read across the tenant where holders is TRUE, or a role at a time where custom
// is, and limited its LIMIT clause.
func conflictsIn(ctx context.Context, q DB, given valuesGiven, args []any, holders, custom, limited string) ([]Conflict, error) {
	// Each key's values are looked up by key, so a change reads what the identities it reaches
	// hold, not every value held in the tenant, and stops at the first conflict it finds.
	rows, err := q.Query(ctx, `
		WITH RECURSIVE `+given.with+`seeds(k) AS (
		  SELECT unnest($2::text[]) COLLATE "C"
		  UNION SELECT principal FROM rbac_grants WHERE `+holders+` AND tenant = $1 AND `+given.held+`
		  UNION SELECT principal FROM rbac_eligibilities WHERE `+holders+` AND tenant = $1 AND `+given.held+`
		  UNION SELECT principal FROM (`+customRoleRows(given.holders, "rbac_grants", "principal", custom)+`) g
		  UNION SELECT principal FROM (`+customRoleRows(given.holders, "rbac_eligibilities", "principal", custom)+`) e
		), `+insideSQL(`ARRAY(SELECT substr(k, 7) FROM seeds WHERE k LIKE 'group:%')`, "$4", "NULL", false)+`,
		targets(identity) AS (
		  SELECT k FROM seeds WHERE k NOT LIKE 'group:%' AND k NOT LIKE 'members:%' AND k <> 'public:'
		  UNION SELECT principal FROM inside
		  UNION SELECT principal FROM rbac_memberships WHERE tenant = $1
		    AND EXISTS (SELECT FROM seeds WHERE k IN ('members:' || $1, 'public:'))
		  UNION SELECT o.principal FROM (
		    SELECT principal FROM rbac_grants WHERE tenant = $1 AND `+given.gives+`
		    UNION ALL
		    SELECT principal FROM rbac_eligibilities WHERE tenant = $1 AND `+given.gives+given.alsoGives+`
		  ) o WHERE o.principal NOT LIKE 'group:%' AND o.principal NOT LIKE 'members:%' AND o.principal <> 'public:'
		    AND EXISTS (SELECT FROM seeds WHERE k = 'public:')
		  UNION SELECT '' WHERE EXISTS (SELECT FROM seeds WHERE k = 'public:')
		), held(identity, value) AS (
		  SELECT t.identity, v.value COLLATE "C" FROM targets t
		  CROSS JOIN LATERAL (WITH RECURSIVE `+keysSQL("$1::text", "t.identity", "$4")+` SELECT k FROM bound) ks
		  CROSS JOIN LATERAL (
		    SELECT role FROM rbac_grants WHERE tenant = $1 AND principal = ks.k AND scope = 'tenant:' || $1 AND `+given.givesKeys+`
		      AND (expires_at IS NULL OR expires_at > $4)
		    UNION ALL
		    SELECT role FROM rbac_eligibilities WHERE tenant = $1 AND principal = ks.k AND scope = 'tenant:' || $1 AND `+given.givesKeys+`
		      AND (expires_at IS NULL OR expires_at > $4)
		  ) g
		  JOIN `+given.pairs+` ON v.role = g.role
		)
		SELECT identity, split_part(value, ':', 1), array_agg(DISTINCT value ORDER BY value) FROM held
		GROUP BY 1, 2 HAVING count(DISTINCT value) > 1 ORDER BY 1, 2`+limited, args...)
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
	return found, err
}

// withoutJIT is what read reads, statements on q in a transaction, with JIT off for them alone,
// where the planner costs what they read for each of many identities as if they read the whole
// tenant: compiling then takes far longer than running them. The setting is put back after, so a
// host's transaction under WithTx gets its own again.
func withoutJIT[T any](ctx context.Context, q DB, read func() (T, error)) (T, error) {
	var none T
	var jit string
	if err := q.QueryRow(ctx, `SELECT current_setting('jit'), set_config('jit', 'off', true)`).Scan(&jit, nil); err != nil {
		return none, err
	}
	v, err := read()
	if err != nil {
		return none, err
	}
	if _, err := q.Exec(ctx, `SELECT set_config('jit', $1, true)`, jit); err != nil {
		return none, err
	}
	return v, nil
}
