package rbac

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Decision is why a check came out as it did.
type Decision struct {
	Allowed bool
	// Grants are the subject's grants that give the permission.
	Grants []Grant
	// DeniedBy names the constraint or deny policy that removed the permission.
	DeniedBy string
	// Reason says why it was denied, in English, for logs.
	Reason string
}

// Authorize returns nil when the subject may do p to r, and otherwise an error matching
// ErrDenied, or ErrInvalid for malformed input, such as a permission or resource type the host
// doesn't check (Config.Permissions), which can only be a mistake. Any error means no.
func (a *Authorizer) Authorize(ctx context.Context, s Subject, p Permission, r Resource) error {
	d, err := a.decide(ctx, s, p, r, false)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return &DeniedError{Permission: p, Scope: r.Scope(), Reason: d.Reason}
	}
	return nil
}

// Explain decides as Authorize does and says why: the grants that give the permission, or what
// denied it.
func (a *Authorizer) Explain(ctx context.Context, s Subject, p Permission, r Resource) (Decision, error) {
	return a.decide(ctx, s, p, r, true)
}

func (a *Authorizer) decide(ctx context.Context, s Subject, p Permission, r Resource, explain bool) (Decision, error) {
	if err := a.check(r); err != nil {
		return Decision{}, err
	}
	if err := a.askable(p, r.Type); err != nil {
		return Decision{}, err
	}
	if err := a.subject(s); err != nil {
		return Decision{}, err
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Subject: &s, Resource: &r})
	if err != nil {
		return Decision{}, err
	}
	if name != "" {
		return Decision{DeniedBy: name, Reason: "removed by " + name}, nil
	}

	counts := a.counting(p, r.Type)
	if !explain {
		held, ds, err := a.heldOrDenied(ctx, a.db, r.Tenant, s, counts, r.path(), p)
		if err != nil {
			return Decision{}, err
		}
		// What conditions read is built only for a check that reads one, so one a grant decides
		// builds none of it.
		var vars map[string]any
		if len(ds) > 0 {
			vars = a.vars(ctx, s, p, r)
			// A deny decides first, as it binds every grant.
			if d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()), vars); ok {
				return Decision{DeniedBy: d.String(), Reason: d.removal()}, nil
			}
		}
		// A built-in role's unconditional grant decides without reading custom roles or conditions.
		builtin := book{builtin: a.roles}
		for _, h := range held {
			if !h.conditional && gives(builtin, h.Principal, h.Role, p, r.Type) {
				return Decision{Allowed: true}, nil
			}
		}
		roles, err := a.book(ctx, a.db, r.Tenant, roleIDs(held))
		if err != nil {
			return Decision{}, err
		}
		var conditional []holding
		for _, h := range held {
			if !gives(roles, h.Principal, h.Role, p, r.Type) {
				continue
			}
			if !h.conditional {
				return Decision{Allowed: true}, nil
			}
			conditional = append(conditional, h)
		}
		if len(conditional) == 0 {
			return Decision{Reason: "no grant gives it"}, nil
		}
		// Only now, with no unconditional grant to allow, are conditions read and evaluated.
		if err := a.conditionsOf(ctx, a.db, r.Tenant, conditional); err != nil {
			return Decision{}, err
		}
		if vars == nil {
			vars = a.vars(ctx, s, p, r)
		}
		spend := newBudget()
		cheapestFirst(conditional, holding.expression)
		for _, h := range conditional {
			if a.conds.holds(spend, h.Condition.Expression, vars) {
				return Decision{Allowed: true}, nil
			}
		}
		return Decision{Reason: unmet(spend)}, nil
	}

	vars, spend := a.vars(ctx, s, p, r), newBudget()
	keys, err := a.keysOf(ctx, a.db, r.Tenant, s)
	if err != nil {
		return Decision{}, err
	}
	principals := countedOf(keys, counts)
	// As Authorize, which reads no deny for a subject none of whose grants can give p.
	if len(principals) > 0 {
		ds, err := a.deniesOn(ctx, a.db, r.Tenant, bound(keys, s), r.path(), p)
		if err != nil {
			return Decision{}, err
		}
		if d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()), vars); ok {
			return Decision{DeniedBy: d.String(), Reason: d.removal()}, nil
		}
	}
	grants, err := a.heldGrants(ctx, a.db, r.Tenant, principals, r.path())
	if err != nil {
		return Decision{}, err
	}
	roles, err := a.book(ctx, a.db, r.Tenant, roleIDs(grants))
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Reason: "no grant gives it"}
	grants = slices.DeleteFunc(grants, func(g Grant) bool { return !gives(roles, g.Principal, g.Role, p, r.Type) })
	// Evaluated in the order Authorize evaluates them, so a budget runs out where it does for it.
	byCost := slices.Clone(grants)
	cheapestFirst(byCost, Grant.expression)
	held := map[string]bool{}
	for _, g := range byCost {
		held[g.ID] = g.Condition.Expression == "" || a.conds.holds(spend, g.Condition.Expression, vars)
	}
	for _, g := range grants {
		if !held[g.ID] {
			d.Reason = unmet(spend)
			continue
		}
		d.Grants = append(d.Grants, g)
	}
	if len(d.Grants) > 0 {
		d.Allowed, d.Reason = true, ""
	}
	return d, nil
}

// askable returns why p on a resource type isn't something the host checks (Config.Permissions):
// p is malformed or not a permission it has, or the type isn't one a built-in role or one of its
// permissions is for. Such a question is a typo, not a refusal, so it is invalid, as SetRole and
// SetDeny find one in a role or a deny.
func (a *Authorizer) askable(p Permission, resourceType string) error {
	switch {
	case !p.Valid():
		return fmt.Errorf("%w: permission %q is not `type:verb`", ErrInvalid, p)
	case !a.checked[p]:
		return fmt.Errorf("%w: permission %q is not one the host checks", ErrInvalid, p)
	case !a.checkedTypes[resourceType]:
		return fmt.Errorf("%w: resource type %q is not one the host checks", ErrInvalid, resourceType)
	}
	return nil
}

// scopeOf returns why r's type is no scope the host has: not a resource type a check may name, a
// container's or the tenant's, so nothing could be done to it or granted on it.
func (a *Authorizer) scopeOf(r Resource) error {
	if !a.checkedTypes[r.Type] && !a.contains(r.Type) {
		return fmt.Errorf("%w: resource type %q is not one the host checks", ErrInvalid, r.Type)
	}
	return nil
}

// unmet is why no conditional grant allowed, given what is left of the check's budget.
func unmet(spend *budget) string {
	if spend.exhausted {
		return "the conditions of the grants that give it cost more than a check may spend"
	}
	return "no condition of a grant that gives it holds"
}

// gives reports whether a grant of a role to a principal gives p on a resource type. A role
// that no longer exists gives nothing.
func gives(roles book, to Principal, id Role, p Permission, resourceType string) bool {
	def, ok := roles.role(id)
	return ok && def.GrantableOn(resourceType) && def.Gives(p) && to.carries(def, p)
}

// Permissions lists what the subject may do to r, sorted: the AuthZEN action search.
func (a *Authorizer) Permissions(ctx context.Context, s Subject, r Resource) ([]Permission, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if err := a.scopeOf(r); err != nil {
		return nil, err
	}
	if err := a.subject(s); err != nil {
		return nil, err
	}
	held, ds, err := a.heldOrDenied(ctx, a.db, r.Tenant, s, all, r.path(), "")
	if err != nil {
		return nil, err
	}
	roles, err := a.book(ctx, a.db, r.Tenant, roleIDs(held))
	if err != nil {
		return nil, err
	}
	given := map[Permission]bool{}
	var conditional []holding
	for _, h := range held {
		def, ok := roles.role(h.Role)
		switch {
		case !ok || !def.GrantableOn(r.Type):
		case h.conditional:
			conditional = append(conditional, h)
		default:
			for _, p := range def.Permissions {
				given[p] = given[p] || h.Principal.carries(def, p)
			}
		}
	}
	// What a constraint removes is settled first, so no budget is spent on conditions for it.
	removed := map[Permission]bool{}
	isRemoved := func(p Permission) (bool, error) {
		if r, ok := removed[p]; ok {
			return r, nil
		}
		name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Subject: &s, Resource: &r})
		removed[p] = name != ""
		return name != "", err
	}
	// Each permission is decided as Authorize would decide it, on budgets of its own.
	vars, spends := a.vars(ctx, s, "", r), map[Permission]*budget{}
	spendOn := func(p Permission) *budget {
		if spends[p] == nil {
			spends[p] = newBudget()
		}
		return spends[p]
	}
	// A deny is settled before a grant's condition, as checks settle it.
	denied := map[Permission]bool{}
	isDenied := func(p Permission) bool {
		if d, ok := denied[p]; ok {
			return d
		}
		vars["action"] = string(p)
		_, d := a.deniedBy(ds, p, newDenyBudget(r.path()), vars)
		denied[p] = d
		return d
	}
	// Conditions are evaluated only for what no unconditional grant gives, as checks do, the
	// cheapest first.
	if err := a.conditionsOf(ctx, a.db, r.Tenant, conditional); err != nil {
		return nil, err
	}
	cheapestFirst(conditional, holding.expression)
	for _, h := range conditional {
		def, _ := roles.role(h.Role)
		for _, p := range def.Permissions {
			if given[p] || !h.Principal.carries(def, p) {
				continue
			}
			if gone, err := isRemoved(p); err != nil || gone {
				if err != nil {
					return nil, err
				}
				continue
			}
			if isDenied(p) {
				continue
			}
			// A condition reads the action, so it is evaluated for each permission.
			vars["action"] = string(p)
			given[p] = a.conds.holds(spendOn(p), h.Condition.Expression, vars)
		}
	}
	var perms []Permission
	for _, p := range slices.Sorted(maps.Keys(given)) {
		if !given[p] {
			continue
		}
		gone, err := isRemoved(p)
		if err != nil {
			return nil, err
		}
		if !gone && !isDenied(p) {
			perms = append(perms, p)
		}
	}
	return perms, nil
}

// Holders lists every principal holding a role that gives p on r, the tenant's members and the
// public included. The AuthZEN subject search; Members lists a group's members. It
// counts only unconditional grants: whether a conditional one allows depends on the request,
// and Grants lists them with their conditions. It leaves out holders a deny on the path names,
// conditional denies included; a deny naming a group's member or an identity among the tenant's
// members can't be seen through the group or the tenant, so with denies on the path check each
// person with Authorize.
func (a *Authorizer) Holders(ctx context.Context, p Permission, r Resource) ([]Principal, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if err := a.askable(p, r.Type); err != nil {
		return nil, err
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Resource: &r})
	if err != nil || name != "" {
		return nil, err
	}
	roles, custom := a.giving(p, r.Type), a.customGives(p, r.Type)
	if len(roles) == 0 && !custom {
		return nil, nil
	}
	args := append([]any{
		r.Tenant, r.path(), roles, a.cfg.Now(), p.managesAccess(),
		[]string{string(Members), string(Public)},
		string(p), r.Type, a.publicRoles(roles), string(Public),
	}, a.publicArgs(p, r.Type, custom)...)
	rows, err := a.db.Query(ctx, `
		SELECT DISTINCT principal_kind, principal_id FROM rbac_grants
		WHERE tenant = $1 AND scope = ANY($2::text[]) AND role = ANY(`+givingSQL("$3", "$1", "$7", "$8", custom, nil)+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND NOT conditional AND (NOT $5 OR principal_kind <> ALL($6::text[]))
		  AND (principal_kind <> $10 OR role = ANY(`+givingSQL("$9", "$1", "$7", "$8", custom, &publicSQL{"$11", "$12", "$13"})+`))
		ORDER BY principal_kind, principal_id`, args...)
	if err != nil {
		return nil, err
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Principal, error) {
		var p Principal
		err := row.Scan(&p.Kind, &p.ID)
		return p, err
	})
	if err != nil {
		return nil, err
	}
	// Every deny on the path for p, conditional ones counted as denying, as Holders can't read
	// the request they depend on.
	ds, err := a.deniesOn(ctx, a.db, r.Tenant, nil, r.path(), p)
	if err != nil {
		return nil, err
	}
	// A kind the host no longer declares can't act, so its grants give nothing; nor does a grant
	// to the public where no public role can give p, as checks read it.
	public := a.publicGives(p, r.Type)
	return slices.DeleteFunc(found, func(h Principal) bool {
		return !a.known(r.Tenant, h) || h.Kind == Public && !public ||
			slices.ContainsFunc(ds, func(d denial) bool { return d.names(r.Tenant, h) })
	}), nil
}

// Reach is where a subject may do something. A resource, by its path (Authorizer.Path), is
// reachable when its path holds none of Except; All is set or its path holds one of Scopes or
// Conditional; and, if its path holds one of Conditional or ConditionalExcept, Authorize allows
// it.
type Reach struct {
	All    bool
	Scopes []Scope
	// Conditional are the scopes only conditional grants reach, which a search can't evaluate:
	// check the resources under them one by one.
	Conditional []Scope
	// Except are the scopes a deny covers: nothing under them is reachable.
	Except []Scope
	// ConditionalExcept are the scopes a conditional deny covers: a resource under one that is
	// otherwise reachable is checked on its own.
	ConditionalExcept []Scope
}

// Reachable says where the subject may do p to resources of a type in a tenant, for hosts that
// list from a store other than this PostgreSQL. Hosts on the same database use Filter.
func (a *Authorizer) Reachable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (Reach, error) {
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil || removed {
		return Reach{}, err
	}
	custom := a.customGives(p, resourceType)
	if len(roles) == 0 && !custom {
		return Reach{}, nil
	}
	keys, err := a.keysOf(ctx, a.db, tenant, s)
	if err != nil {
		return Reach{}, err
	}
	principals := countedOf(keys, a.counting(p, resourceType))
	if len(principals) == 0 {
		return Reach{}, nil
	}
	reaching := a.reaching(resourceType)
	args := append([]any{
		tenant, principals, roles, a.cfg.Now(), reaching, publicKey, a.publicRoles(roles),
		string(p), resourceType,
	}, a.publicArgs(p, resourceType, custom)...)
	rows, err := a.db.Query(ctx, `
		SELECT scope, bool_and(conditional) FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND role = ANY(`+givingSQL("$3", "$1", "$8", "$9", custom, nil)+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND `+ofTypes("scope", "$5", len(reaching))+`
		  AND (principal <> $6 OR role = ANY(`+givingSQL("$7", "$1", "$8", "$9", custom, &publicSQL{"$10", "$11", "$12"})+`))
		GROUP BY scope ORDER BY scope`, args...)
	if err != nil {
		return Reach{}, err
	}
	var reach Reach
	var key string
	var conditional bool
	if _, err := pgx.ForEachRow(rows, []any{&key, &conditional}, func() error {
		switch {
		case conditional:
			reach.Conditional = append(reach.Conditional, parseScope(key))
		case key == TenantRoot(tenant).Key():
			reach.All = true
		default:
			reach.Scopes = append(reach.Scopes, parseScope(key))
		}
		return nil
	}); err != nil {
		return Reach{}, err
	}
	// A deny only takes away: where no grant reaches, there is nothing to take.
	if !reach.All && len(reach.Scopes)+len(reach.Conditional) == 0 {
		return Reach{}, nil
	}
	// Denies on scopes a resource of the type can have on its path: those of the type, the
	// containers and the tenant.
	perm, wildcard := matchable(p)
	rows, err = a.db.Query(ctx, `
		SELECT scope, bool_or(condition = '') FROM rbac_denies
		WHERE tenant = $1 AND scope_type = ANY($2::text[])
		  AND principals && $3::text[] AND NOT exempt && $3::text[] AND ($4 = ANY(permissions) OR $5 = ANY(permissions))
		GROUP BY scope ORDER BY scope`,
		tenant, reaching, bound(keys, s), perm, wildcard)
	if err != nil {
		return Reach{}, err
	}
	var always bool
	if _, err := pgx.ForEachRow(rows, []any{&key, &always}, func() error {
		if always {
			reach.Except = append(reach.Except, parseScope(key))
		} else {
			reach.ConditionalExcept = append(reach.ConditionalExcept, parseScope(key))
		}
		return nil
	}); err != nil {
		return Reach{}, err
	}
	if slices.Contains(reach.Except, TenantRoot(tenant)) {
		return Reach{}, nil
	}
	if reach.All {
		reach.Scopes, reach.Conditional = nil, nil
	}
	return reach, nil
}

// searchable returns the built-in roles that give p on a resource type, and whether a
// constraint removes p there.
func (a *Authorizer) searchable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (roles []string, removed bool, err error) {
	if tenant == "" || !validName(resourceType) {
		return nil, false, fmt.Errorf("%w: a search needs a tenant and a resource type", ErrInvalid)
	}
	if err := a.askable(p, resourceType); err != nil {
		return nil, false, err
	}
	if err := a.subject(s); err != nil {
		return nil, false, err
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: tenant, ResourceType: resourceType, Permission: p, Subject: &s})
	if err != nil || name != "" {
		return nil, name != "", err
	}
	return a.giving(p, resourceType), false, nil
}

// Columns names the host's columns that Filter reads.
type Columns struct {
	// Tenant is the resource's tenant.
	Tenant string
	// Path is a text[] holding the resource's Authorizer.Path, with a GIN index.
	Path string
}

// Predicate is a SQL condition and its arguments, numbered from the first argument the host
// asked for.
type Predicate struct {
	SQL  string
	Args []any
}

// Filter returns a condition for the host's own query that keeps the resources of a type in a
// tenant the subject may do p to. It reads the grants in the same statement as the rows, so
// sorting and pagination work and nothing changes between deciding and reading. The host's
// query must reach this package's tables (they are in the pool's schema), and column names are
// trusted host code; every value is an argument. It counts only unconditional grants, and leaves
// out every resource a deny covers, conditional ones included, so it never keeps one Authorize
// refuses: Reachable's Conditional and ConditionalExcept name the scopes where that may be too
// strict.
func (a *Authorizer) Filter(ctx context.Context, s Subject, p Permission, tenant, resourceType string, cols Columns, firstArg int) (Predicate, error) {
	if cols.Tenant == "" || cols.Path == "" || firstArg < 1 {
		return Predicate{}, fmt.Errorf("%w: Filter needs the tenant and path columns and a first argument", ErrInvalid)
	}
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil {
		return Predicate{}, err
	}
	counts := a.counting(p, resourceType)
	custom := a.customGives(p, resourceType)
	if removed || s.Principal == (Principal{}) && !counts.public || len(roles) == 0 && !custom {
		return Predicate{SQL: "FALSE"}, nil
	}
	arg := func(i int) string { return fmt.Sprintf("$%d", firstArg+i) }
	perm, wildcard := matchable(p)
	// The subject's principals, read in the statement as its grants and denies are, so a list
	// reads its membership, its groups and what they hold in one snapshot.
	keys := func(of string) string {
		return "ARRAY(WITH RECURSIVE " + keysSQL(arg(1)+"::text", arg(2)+"::text", arg(4)) + " " + of + ")"
	}
	// The subject's grants on the scopes `of` keeps, in the default collation, as the host's
	// path column has it, so its GIN index applies.
	grants := func(of string) string {
		return fmt.Sprintf(`SELECT g.scope COLLATE "default" FROM rbac_grants g
			WHERE g.tenant = %s::text AND g.principal = ANY(%s) AND g.role = ANY(%s)
			  AND (g.expires_at IS NULL OR g.expires_at > %s) AND NOT g.conditional AND %s
			  AND (g.principal <> %s::text OR g.role = ANY(%s))`,
			arg(1), keys(countedKeys(arg(13), arg(17))), givingSQL(arg(3), arg(1), arg(8), arg(9), custom, nil), arg(4), of, arg(6),
			givingSQL(arg(7), arg(1), arg(8), arg(9), custom, &publicSQL{arg(10), arg(11), arg(12)}))
	}
	// The grants' tenant is an argument of its own: the host's tenant column needn't be text,
	// and one argument can't take two types. The grants overlap the path, which the host's GIN
	// index serves. A subject can hold thousands on resources of the type, such as one on each it
	// created, where an overlap would compare each with every key of every row: each reaches only
	// its resource, whose key is its path's first, so then they are looked up in a hash of them,
	// and only containers' and the tenant's overlap. That form can't use the GIN index, so a
	// subject with few keeps the overlap.
	above := a.reaching(resourceType)
	var byKey string
	if !a.contains(resourceType) {
		many, err := a.manyResourceGrants(ctx, tenant, s, counts, resourceType)
		if err != nil {
			return Predicate{}, err
		}
		if many {
			above = slices.DeleteFunc(above, func(t string) bool { return t == resourceType })
			byKey = fmt.Sprintf(`(%s)[1] IN (%s) OR `, cols.Path, grants(ofType("g.scope", arg(9)+"::text")))
		}
	}
	reached := fmt.Sprintf(`(%s%s && ARRAY(%s))`, byKey, cols.Path, grants(ofTypes("g.scope", arg(5), len(above))))
	return Predicate{
		SQL: fmt.Sprintf(`(%s = %s AND %s
			AND NOT %s && ARRAY(SELECT d.scope COLLATE "default" FROM rbac_denies d
			WHERE d.tenant = %s::text AND d.scope_type = ANY(%s::text[])
			  AND d.principals && %[7]s AND NOT d.exempt && %[7]s
			  AND (%[8]s::text = ANY(d.permissions) OR %[9]s::text = ANY(d.permissions))))`,
			cols.Tenant, arg(0), reached, cols.Path, arg(1), arg(16), keys("SELECT k FROM bound"), arg(14), arg(15)),
		Args: append(append([]any{
			tenant, tenant, s.identityKey(), roles, a.cfg.Now(), above, publicKey, a.publicRoles(roles),
			string(p), resourceType,
		}, a.publicArgs(p, resourceType, custom)...), counts.public, perm, wildcard, a.reaching(resourceType), counts.members),
	}, nil
}

// ofTypes is SQL keeping the rows whose scope, col, is of one of the n types in the array argument
// types.
func ofTypes(col, types string, n int) string {
	ranges := make([]string, n)
	for i := range n {
		ranges[i] = ofType(col, fmt.Sprintf("(%s::text[])[%d]", types, i+1))
	}
	return "(" + strings.Join(ranges, " OR ") + ")"
}

// ofType is SQL keeping the rows whose scope, col, is of the type t. A scope is `type:id`, and in
// the C collation the scopes of a type sort from `type:` to just before `type;`, so a btree on the
// scope reads only them, as one on split_part couldn't.
func ofType(col, t string) string {
	return fmt.Sprintf("(%s >= (%s || ':') AND %s < (%s || ';'))", col, t, col, t)
}

// maxOverlap is how many grants on resources of a type Filter overlaps with each row's path:
// about where comparing each with every key of a row costs as much as a lookup in a hash.
const maxOverlap = 8

// manyResourceGrants reports whether s's principals hold more than maxOverlap unconditional grants
// in force on resources of a type, of any role, counting broad ones as counts says: it only picks
// the form of Filter's condition.
func (a *Authorizer) manyResourceGrants(ctx context.Context, tenant string, s Subject, counts broad, resourceType string) (bool, error) {
	var n int
	err := a.db.QueryRow(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$4")+`
		SELECT count(*) FROM (SELECT FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY(ARRAY(`+countedKeys("$6", "$7")+`)) AND `+ofType("scope", "$3::text")+` AND NOT conditional
		  AND (expires_at IS NULL OR expires_at > $4) LIMIT $5) g`,
		tenant, s.identityKey(), resourceType, a.cfg.Now(), maxOverlap+1, counts.public, counts.members).Scan(&n)
	return n > maxOverlap, err
}

// holding is a grant as a check reads it from the key index: whether it has a condition, not
// the condition, which conditionsOf reads when a check needs it.
type holding struct {
	Binding
	scope       string
	conditional bool
}

// heldOrDenied returns the grants on any of scopes, not expired, held by s's principals in a
// tenant, counting broad ones as counts says, and the denies deniesOn reads for all its principals
// and p, or any permission when p is empty, in one statement that reads its membership and groups
// too, so a check is one round trip. The grants' part reads only what the key index holds, so it
// is an index-only scan. Like Explain, it reads no deny for a subject none of whose grants count,
// such as one that isn't a member or guest of the tenant.
func (a *Authorizer) heldOrDenied(ctx context.Context, q DB, tenant string, s Subject, counts broad, scopes []string, p Permission) ([]holding, []denial, error) {
	// The anonymous are the public alone.
	if s.Principal == (Principal{}) && !counts.public {
		return nil, nil, nil
	}
	var perm, wildcard string
	if p != "" {
		perm, wildcard = matchable(p)
	}
	rows, err := q.Query(ctx, `
		WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$4")+`
		SELECT false, id::text, principal, scope, role, expires_at, conditional, NULL::text[], ''
		FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY(ARRAY(`+countedKeys("$7", "$8")+`)) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		UNION ALL
		SELECT true, id, id, scope, '', NULL, condition <> '', permissions, condition
		FROM rbac_denies
		WHERE tenant = $1 AND scope = ANY($3::text[]) AND principals && ARRAY(SELECT k FROM bound) AND NOT exempt && ARRAY(SELECT k FROM bound)
		  AND ($5 = '' OR $5 = ANY(permissions) OR $6 = ANY(permissions)) AND EXISTS (SELECT FROM keys WHERE `+counted("$7", "$8")+`)
		ORDER BY 1, 3, 4, 5, 2`, // grants by principal, scope, role and id; denies by id and scope, as deniesOn
		tenant, s.identityKey(), scopes, a.cfg.Now(), perm, wildcard, counts.public, counts.members)
	if err != nil {
		return nil, nil, err
	}
	var held []holding
	var ds []denial
	var isDeny bool
	var id, principal, scope, role, condition string
	var expires *time.Time
	var conditional bool
	var perms []string
	_, err = pgx.ForEachRow(rows, []any{&isDeny, &id, &principal, &scope, &role, &expires, &conditional, &perms, &condition}, func() error {
		if isDeny {
			d := denial{id: id, scope: scope, condition: condition}
			for _, x := range perms {
				d.permissions = append(d.permissions, Permission(x))
			}
			ds = append(ds, d)
			return nil
		}
		h := holding{Binding: Binding{ID: id, Principal: parsePrincipal(principal), Role: Role(role)}, scope: scope, conditional: conditional}
		if expires != nil {
			h.ExpiresAt = *expires
		}
		held = append(held, h)
		return nil
	})
	return held, ds, err
}

// conditionsOf reads the conditions of the conditional grants among held, in place.
func (a *Authorizer) conditionsOf(ctx context.Context, q DB, tenant string, held []holding) error {
	var ids []string
	for _, h := range held {
		if h.conditional {
			ids = append(ids, h.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// Only the expression: a check reads nothing else of a condition.
	rows, err := q.Query(ctx, `SELECT id::text, condition FROM rbac_grants WHERE id = ANY($1::uuid[]) AND tenant = $2`, ids, tenant)
	if err != nil {
		return err
	}
	found := map[string]string{}
	var id, expr string
	_, err = pgx.ForEachRow(rows, []any{&id, &expr}, func() error {
		found[id] = expr
		return nil
	})
	if err != nil {
		return err
	}
	for i, h := range held {
		if h.conditional {
			// One gone since is read as a condition nothing meets.
			held[i].Condition.Expression = cmp.Or(found[h.ID], "false")
		}
	}
	return nil
}

// heldGrants returns the grants held by any of principals on any of scopes, not expired, in the
// order heldOrDenied reads them, so Explain lists them in a stable order: it spends on their
// conditions cheapest first, as Authorize does.
func (a *Authorizer) heldGrants(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]Grant, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY principal, scope, role, id`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

const grantColumns = `id::text, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at,
	condition_title, condition_description, condition, note, approved_by, created_by, created_at, updated_by, updated_at`

func collectGrants(rows pgx.Rows) ([]Grant, error) {
	return pgx.CollectRows(rows, scanGrant)
}

func scanGrant(row pgx.CollectableRow) (Grant, error) {
	var g Grant
	var expires *time.Time
	var approvedBy, createdBy, updatedBy string
	err := row.Scan(&g.ID, &g.Scope.Type, &g.Scope.ID, &g.Principal.Kind, &g.Principal.ID, &g.Role, &g.Source, &expires,
		&g.Condition.Title, &g.Condition.Description, &g.Condition.Expression, &g.Note,
		&approvedBy, &createdBy, &g.CreatedAt, &updatedBy, &g.UpdatedAt)
	if expires != nil {
		g.ExpiresAt = *expires
	}
	g.ApprovedBy, g.CreatedBy, g.UpdatedBy = parsePrincipal(approvedBy), parsePrincipal(createdBy), parsePrincipal(updatedBy)
	return g, err
}
