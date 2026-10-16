package rbac

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Decision is why a check came out as it did.
type Decision struct {
	Allowed bool
	// Grants are the subject's grants that give the permission.
	Grants []Grant
	// DeniedBy names the constraint that removed the permission.
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
	if !explain {
		held, err := a.heldBindings(ctx, a.db, r.Tenant, principals, r.path())
		if err != nil {
			return Decision{}, err
		}
		// A built-in role's grant decides without reading custom roles.
		roles := book{builtin: a.roles}
		for _, b := range held {
			if gives(roles, b.Principal, b.Role, p, r.Type) {
				return Decision{Allowed: true}, nil
			}
		}
		if roles, err = a.book(ctx, a.db, r.Tenant, roleIDs(held)); err != nil {
			return Decision{}, err
		}
		for _, b := range held {
			if isCustom(b.Role) && gives(roles, b.Principal, b.Role, p, r.Type) {
				return Decision{Allowed: true}, nil
			}
		}
		return Decision{Reason: "no grant gives it"}, nil
	}

	grants, err := a.heldGrants(ctx, a.db, r.Tenant, principals, r.path())
	if err != nil {
		return Decision{}, err
	}
	roles, err := a.book(ctx, a.db, r.Tenant, grantRoleIDs(grants))
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Reason: "no grant gives it"}
	for _, g := range grants {
		if gives(roles, g.Principal, g.Role, p, r.Type) {
			d.Grants = append(d.Grants, g)
		}
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
	var candidates []Permission
	for _, b := range held {
		if def, ok := roles.role(b.Role); ok && def.GrantableOn(r.Type) {
			for _, p := range def.Permissions {
				if b.Principal.carries(def, p) {
					candidates = append(candidates, p)
				}
			}
		}
	}
	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	perms := candidates[:0]
	for _, p := range candidates {
		name, err := a.denied(ctx, r.Tenant, r.Type, p)
		if err != nil {
			return nil, err
		}
		if name == "" {
			perms = append(perms, p)
		}
	}
	return perms, nil
}

// Holders lists every principal holding a role that gives p on r, the tenant's members and the
// public included. The AuthZEN subject search; the host expands groups to their members.
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
		  AND (expires_at IS NULL OR expires_at > $4) AND (NOT $5 OR principal_kind <> ALL($6::text[]))
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
	// A kind the host no longer declares can't act, so its grants give nothing; nor does a grant
	// to the public where no public role can give p, as checks read it.
	public := a.publicGives(p, r.Type)
	return slices.DeleteFunc(found, func(h Principal) bool { return !a.known(r.Tenant, h) || h.Kind == Public && !public }), nil
}

// Reach is where a subject may do something: every resource of the type in the tenant, or
// those whose path (Authorizer.Path) holds one of Scopes.
type Reach struct {
	All    bool
	Scopes []Scope
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
		SELECT DISTINCT scope FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND role = ANY(`+givingSQL("$3", "$1", "$8", "$9", custom, nil)+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND split_part(scope, ':', 1) = ANY($5::text[])
		  AND (principal <> $6 OR role = ANY(`+givingSQL("$7", "$1", "$8", "$9", custom, &publicSQL{"$10", "$11", "$12"})+`))
		ORDER BY scope`, args...)
	if err != nil {
		return Reach{}, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return Reach{}, err
	}
	var reach Reach
	for _, k := range keys {
		if k == TenantRoot(tenant).Key() {
			return Reach{All: true}, nil
		}
		reach.Scopes = append(reach.Scopes, parseScope(k))
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
// trusted host code; every value is an argument.
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
			  AND (g.expires_at IS NULL OR g.expires_at > %s) AND split_part(g.scope, ':', 1) = ANY(%s::text[])
			  AND (g.principal <> %s::text OR g.role = ANY(%s))))`,
			cols.Tenant, arg(0), cols.Path, arg(1), arg(2), givingSQL(arg(3), arg(1), arg(8), arg(9), custom, nil), arg(4), arg(5), arg(6),
			givingSQL(arg(7), arg(1), arg(8), arg(9), custom, &publicSQL{arg(10), arg(11), arg(12)})),
		Args: append([]any{
			tenant, tenant, principals, roles, a.cfg.Now(), a.reaching(resourceType), publicKey, a.publicRoles(roles),
			string(p), resourceType,
		}, a.publicArgs(p, resourceType, custom)...),
	}, nil
}

// heldBindings returns the bindings held by any of principals on any of scopes, not expired:
// only what the key index holds, so it is an index-only scan.
func (a *Authorizer) heldBindings(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]Binding, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT principal, role, expires_at FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Binding, error) {
		var b Binding
		var principal string
		var expires *time.Time
		err := row.Scan(&principal, &b.Role, &expires)
		b.Principal = parsePrincipal(principal)
		if expires != nil {
			b.ExpiresAt = *expires
		}
		return b, err
	})
}

// heldGrants returns the grants held by any of principals on any of scopes, not expired.
func (a *Authorizer) heldGrants(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]Grant, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY scope, principal, role`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

const grantColumns = `scope_type, scope_id, principal_kind, principal_id, role, expires_at, created_by, created_at`

func collectGrants(rows pgx.Rows) ([]Grant, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Grant, error) {
		var g Grant
		var expires *time.Time
		var createdBy string
		err := row.Scan(&g.Scope.Type, &g.Scope.ID, &g.Principal.Kind, &g.Principal.ID, &g.Role,
			&expires, &createdBy, &g.CreatedAt)
		if expires != nil {
			g.ExpiresAt = *expires
		}
		g.CreatedBy = parsePrincipal(createdBy)
		return g, err
	})
}
