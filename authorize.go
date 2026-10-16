package rbac

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
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
// ErrDenied (or ErrInvalid for malformed input). Any error means no.
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
	if !p.Valid() {
		return Decision{}, fmt.Errorf("%w: permission %q is not `type:verb`", ErrInvalid, p)
	}
	if err := a.subject(s); err != nil {
		return Decision{}, err
	}
	name, err := a.denied(ctx, r.Tenant, r.Type, p)
	if err != nil {
		return Decision{}, err
	}
	if name != "" {
		return Decision{DeniedBy: name, Reason: "removed by " + name}, nil
	}

	principals := s.principalsFor(r.Tenant, p, a.publicGives(p, r.Type))
	vars, spend := a.vars(ctx, s, p, r), newBudget()
	if !explain {
		held, ds, err := a.heldOrDenied(ctx, a.db, r.Tenant, principals, s.principals(r.Tenant), r.path(), p)
		if err != nil {
			return Decision{}, err
		}
		// A deny decides first, as it binds every grant.
		if d, ok := a.deniedBy(ds, p, spend, vars); ok {
			return Decision{DeniedBy: d.String(), Reason: "removed by " + d.String()}, nil
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
		for _, h := range conditional {
			if a.conds.holds(spend, h.Condition.Expression, vars) {
				return Decision{Allowed: true}, nil
			}
		}
		return Decision{Reason: "no condition of a grant that gives it holds"}, nil
	}

	ds, err := a.deniesOn(ctx, a.db, r.Tenant, s.principals(r.Tenant), r.path(), p)
	if err != nil {
		return Decision{}, err
	}
	if d, ok := a.deniedBy(ds, p, spend, vars); ok {
		return Decision{DeniedBy: d.String(), Reason: "removed by " + d.String()}, nil
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
	for _, g := range grants {
		if !gives(roles, g.Principal, g.Role, p, r.Type) {
			continue
		}
		if g.Condition.Expression != "" && !a.conds.holds(spend, g.Condition.Expression, vars) {
			d.Reason = "no condition of a grant that gives it holds"
			continue
		}
		d.Grants = append(d.Grants, g)
	}
	if len(d.Grants) > 0 {
		d.Allowed, d.Reason = true, ""
	}
	return d, nil
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
	if err := a.subject(s); err != nil {
		return nil, err
	}
	held, err := a.heldBindings(ctx, a.db, r.Tenant, s.principals(r.Tenant), r.path())
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
		name, err := a.denied(ctx, r.Tenant, r.Type, p)
		removed[p] = name != ""
		return name != "", err
	}
	// Conditions are evaluated only for what no unconditional grant gives, as checks do.
	if err := a.conditionsOf(ctx, a.db, r.Tenant, conditional); err != nil {
		return nil, err
	}
	vars, spend := a.vars(ctx, s, "", r), newBudget()
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
			// A condition reads the action, so it is evaluated for each permission.
			vars["action"] = string(p)
			given[p] = a.conds.holds(spend, h.Condition.Expression, vars)
		}
	}
	ds, err := a.deniesOn(ctx, a.db, r.Tenant, s.principals(r.Tenant), r.path(), "")
	if err != nil {
		return nil, err
	}
	var perms []Permission
	for _, p := range slices.Sorted(maps.Keys(given)) {
		if !given[p] {
			continue
		}
		vars["action"] = string(p)
		if _, ok := a.deniedBy(ds, p, spend, vars); ok {
			continue
		}
		gone, err := isRemoved(p)
		if err != nil {
			return nil, err
		}
		if !gone {
			perms = append(perms, p)
		}
	}
	return perms, nil
}

// Holders lists every principal holding a role that gives p on r, the tenant's members and the
// public included. The AuthZEN subject search; the host expands groups to their members. It
// counts only unconditional grants: whether a conditional one allows depends on the request,
// and Grants lists them with their conditions. It leaves out holders a deny on the path names,
// conditional denies included; a deny naming a group's member or an identity among the tenant's
// members can't be seen through the group or the tenant, so with denies on the path check each
// person with Authorize.
func (a *Authorizer) Holders(ctx context.Context, r Resource, p Permission) ([]Principal, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if !p.Valid() {
		return nil, fmt.Errorf("%w: permission %q is not `type:verb`", ErrInvalid, p)
	}
	name, err := a.denied(ctx, r.Tenant, r.Type, p)
	if err != nil || name != "" {
		return nil, err
	}
	roles, custom := a.giving(p, r.Type), a.customGives(p, r.Type)
	if len(roles) == 0 && !custom {
		return nil, nil
	}
	args := append([]any{
		r.Tenant, r.path(), roles, a.cfg.Now(), p.managesAccess(),
		[]string{string(Tenant), string(Public)},
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
// reachable when its path holds none of Except and, if it holds one of Conditional, Authorize
// allows it; otherwise when All, or its path holds one of Scopes.
type Reach struct {
	All    bool
	Scopes []Scope
	// Conditional are the scopes only conditional grants reach, or a conditional deny covers,
	// which a search can't evaluate: check the resources under them one by one.
	Conditional []Scope
	// Except are the scopes a deny covers: nothing under them is reachable.
	Except []Scope
}

// Reachable says where the subject may do p to resources of a type in a tenant, for hosts that
// list from a store other than this PostgreSQL. Hosts on the same database use Filter.
func (a *Authorizer) Reachable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (Reach, error) {
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil || removed {
		return Reach{}, err
	}
	principals := s.principalsFor(tenant, p, a.publicGives(p, resourceType))
	custom := a.customGives(p, resourceType)
	if len(principals) == 0 || len(roles) == 0 && !custom {
		return Reach{}, nil
	}
	args := append([]any{
		tenant, principals, roles, a.cfg.Now(), a.reaching(resourceType), publicKey, a.publicRoles(roles),
		string(p), resourceType,
	}, a.publicArgs(p, resourceType, custom)...)
	rows, err := a.db.Query(ctx, `
		SELECT scope, bool_and(conditional) FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND role = ANY(`+givingSQL("$3", "$1", "$8", "$9", custom, nil)+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND split_part(scope, ':', 1) = ANY($5::text[])
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
	// Denies on scopes a resource of the type can have on its path: those of the type, the
	// containers and the tenant.
	rows, err = a.db.Query(ctx, `
		SELECT scope, bool_or(condition = '') FROM rbac_denies
		WHERE tenant = $1 AND split_part(scope, ':', 1) = ANY($2::text[])
		  AND principals && $3::text[] AND NOT exempt && $3::text[] AND ($4 = ANY(permissions) OR $5 = ANY(permissions))
		GROUP BY scope ORDER BY scope`,
		tenant, a.reaching(resourceType), s.principals(tenant), string(p), wildcard(p))
	if err != nil {
		return Reach{}, err
	}
	var always bool
	if _, err := pgx.ForEachRow(rows, []any{&key, &always}, func() error {
		if always {
			reach.Except = append(reach.Except, parseScope(key))
		} else {
			reach.Conditional = append(reach.Conditional, parseScope(key))
		}
		return nil
	}); err != nil {
		return Reach{}, err
	}
	if slices.Contains(reach.Except, TenantRoot(tenant)) {
		return Reach{}, nil
	}
	if reach.All {
		reach.Scopes = nil
	}
	return reach, nil
}

// searchable returns the built-in roles that give p on a resource type, and whether a
// constraint removes p there.
func (a *Authorizer) searchable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (roles []string, removed bool, err error) {
	if tenant == "" || !validName(resourceType) {
		return nil, false, fmt.Errorf("%w: a search needs a tenant and a resource type", ErrInvalid)
	}
	if !p.Valid() {
		return nil, false, fmt.Errorf("%w: permission %q is not `type:verb`", ErrInvalid, p)
	}
	if err := a.subject(s); err != nil {
		return nil, false, err
	}
	name, err := a.denied(ctx, tenant, resourceType, p)
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
// refuses: Reachable's Conditional names the scopes where that may be too strict.
func (a *Authorizer) Filter(ctx context.Context, s Subject, p Permission, tenant, resourceType string, cols Columns, firstArg int) (Predicate, error) {
	if cols.Tenant == "" || cols.Path == "" || firstArg < 1 {
		return Predicate{}, fmt.Errorf("%w: Filter needs the tenant and path columns and a first argument", ErrInvalid)
	}
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil {
		return Predicate{}, err
	}
	principals := s.principalsFor(tenant, p, a.publicGives(p, resourceType))
	custom := a.customGives(p, resourceType)
	if removed || len(principals) == 0 || len(roles) == 0 && !custom {
		return Predicate{SQL: "FALSE"}, nil
	}
	arg := func(i int) string { return fmt.Sprintf("$%d", firstArg+i) }
	// The grants' tenant is an argument of its own: the host's tenant column needn't be text,
	// and one argument can't take two types. A tenant-wide grant's scope is the tenant's key,
	// which every path holds, so one overlap covers every scope and the host's GIN index serves
	// it. The keys take the default collation so that index applies.
	return Predicate{
		SQL: fmt.Sprintf(`(%s = %s AND %s && ARRAY(SELECT g.scope COLLATE "default" FROM rbac_grants g
			WHERE g.tenant = %s::text AND g.principal = ANY(%s::text[]) AND g.role = ANY(%s)
			  AND (g.expires_at IS NULL OR g.expires_at > %s) AND NOT g.conditional AND split_part(g.scope, ':', 1) = ANY(%s::text[])
			  AND (g.principal <> %s::text OR g.role = ANY(%s)))
			AND NOT %s && ARRAY(SELECT d.scope COLLATE "default" FROM rbac_denies d
			WHERE d.tenant = %s::text AND split_part(d.scope, ':', 1) = ANY(%s::text[])
			  AND d.principals && %s::text[] AND NOT d.exempt && %s::text[]
			  AND (%s::text = ANY(d.permissions) OR %s::text = ANY(d.permissions))))`,
			cols.Tenant, arg(0), cols.Path, arg(1), arg(2), givingSQL(arg(3), arg(1), arg(8), arg(9), custom, nil), arg(4), arg(5), arg(6),
			givingSQL(arg(7), arg(1), arg(8), arg(9), custom, &publicSQL{arg(10), arg(11), arg(12)}),
			cols.Path, arg(1), arg(5), arg(13), arg(13), arg(8), arg(14)),
		Args: append(append([]any{
			tenant, tenant, principals, roles, a.cfg.Now(), a.reaching(resourceType), publicKey, a.publicRoles(roles),
			string(p), resourceType,
		}, a.publicArgs(p, resourceType, custom)...), s.principals(tenant), wildcard(p)),
	}, nil
}

// holding is a grant as a check reads it from the key index: whether it has a condition, not
// the condition, which conditionsOf reads when a check needs it.
type holding struct {
	Binding
	scope       string
	conditional bool
}

// heldBindings returns the grants held by any of principals on any of scopes, not expired:
// only what the key index holds, so it is an index-only scan.
func (a *Authorizer) heldBindings(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]holding, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT principal, scope, role, expires_at, conditional FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY principal, scope, role`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (holding, error) {
		var h holding
		var principal string
		var expires *time.Time
		err := row.Scan(&principal, &h.scope, &h.Role, &expires, &h.conditional)
		h.Principal = parsePrincipal(principal)
		if expires != nil {
			h.ExpiresAt = *expires
		}
		return h, err
	})
}

// heldOrDenied is heldBindings and deniesOn for p in one statement, so a check is one round
// trip: the grants' part stays an index-only scan.
func (a *Authorizer) heldOrDenied(ctx context.Context, q DB, tenant string, principals, keys, scopes []string, p Permission) ([]holding, []denial, error) {
	if len(principals) == 0 {
		return nil, nil, nil
	}
	t, _ := p.parts()
	rows, err := q.Query(ctx, `
		SELECT false, principal, scope, role, expires_at, conditional, NULL::text[], ''
		FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		UNION ALL
		SELECT true, id, scope, name, NULL, condition <> '', permissions, condition
		FROM rbac_denies
		WHERE tenant = $1 AND scope = ANY($3::text[]) AND principals && $5::text[] AND NOT exempt && $5::text[]
		  AND ($6 = ANY(permissions) OR $7 = ANY(permissions))
		ORDER BY 1, 2, 3, 4`,
		tenant, principals, scopes, a.cfg.Now(), keys, string(p), t+":*")
	if err != nil {
		return nil, nil, err
	}
	var held []holding
	var ds []denial
	var isDeny bool
	var first, scope, third, condition string
	var expires *time.Time
	var conditional bool
	var perms []string
	_, err = pgx.ForEachRow(rows, []any{&isDeny, &first, &scope, &third, &expires, &conditional, &perms, &condition}, func() error {
		if isDeny {
			d := denial{id: first, scope: scope, name: third, condition: condition}
			for _, x := range perms {
				d.permissions = append(d.permissions, Permission(x))
			}
			ds = append(ds, d)
			return nil
		}
		h := holding{Binding: Binding{Principal: parsePrincipal(first), Role: Role(third)}, scope: scope, conditional: conditional}
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
	var principals, scopes, roles []string
	for _, h := range held {
		if h.conditional {
			principals, scopes, roles = append(principals, h.Principal.key()), append(scopes, h.scope), append(roles, string(h.Role))
		}
	}
	if len(principals) == 0 {
		return nil
	}
	// Only the expression: a check reads nothing else of a condition.
	rows, err := q.Query(ctx, `
		SELECT principal, scope, role, condition FROM rbac_grants
		WHERE tenant = $1 AND (principal, scope, role) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))`,
		tenant, principals, scopes, roles)
	if err != nil {
		return err
	}
	type key struct{ principal, scope, role string }
	found := map[key]string{}
	var k key
	var expr string
	_, err = pgx.ForEachRow(rows, []any{&k.principal, &k.scope, &k.role, &expr}, func() error {
		found[k] = expr
		return nil
	})
	if err != nil {
		return err
	}
	for i, h := range held {
		if h.conditional {
			// One gone since is read as a condition nothing meets.
			held[i].Condition.Expression = cmp.Or(found[key{h.Principal.key(), h.scope, string(h.Role)}], "false")
		}
	}
	return nil
}

// heldGrants returns the grants held by any of principals on any of scopes, not expired, in the
// order heldBindings reads them: Explain spends on their conditions in the order Authorize does,
// so a budget runs out where it does for Authorize.
func (a *Authorizer) heldGrants(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]Grant, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY principal, scope, role`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

const grantColumns = `scope_type, scope_id, principal_kind, principal_id, role, expires_at, created_by, created_at,
	condition_title, condition_description, condition`

func collectGrants(rows pgx.Rows) ([]Grant, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Grant, error) {
		var g Grant
		var expires *time.Time
		var createdBy string
		err := row.Scan(&g.Scope.Type, &g.Scope.ID, &g.Principal.Kind, &g.Principal.ID, &g.Role,
			&expires, &createdBy, &g.CreatedAt, &g.Condition.Title, &g.Condition.Description, &g.Condition.Expression)
		if expires != nil {
			g.ExpiresAt = *expires
		}
		g.CreatedBy = parsePrincipal(createdBy)
		return g, err
	})
}
