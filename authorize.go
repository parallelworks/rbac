package rbac

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Decision is why a check came out as it did.
type Decision struct {
	Allowed bool
	// Owner is set when the subject owns the resource, which gives every permission a role gives
	// on its type but changing the grants on a container or the tenant.
	Owner bool
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

// Explain decides as Authorize does and says why: the grants that give the permission,
// ownership, or what denied it.
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
	if s.owns(r) && a.ownerHolds(r.Type, p) {
		return Decision{Allowed: true, Owner: true}, nil
	}

	principals := s.principalsFor(r.Tenant, p, len(a.publicRoles(a.giving(p, r.Type))) > 0)
	if !explain {
		held, err := a.heldBindings(ctx, a.db, r.Tenant, principals, r.path())
		if err != nil {
			return Decision{}, err
		}
		for _, b := range held {
			if a.gives(b.Principal, b.Role, p, r.Type) {
				return Decision{Allowed: true}, nil
			}
		}
		return Decision{Reason: "no grant gives it"}, nil
	}

	grants, err := a.heldGrants(ctx, a.db, r.Tenant, principals, r.path())
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Reason: "no grant gives it"}
	for _, g := range grants {
		if a.gives(g.Principal, g.Role, p, r.Type) {
			d.Grants = append(d.Grants, g)
		}
	}
	if len(d.Grants) > 0 {
		d.Allowed, d.Reason = true, ""
	}
	return d, nil
}

// gives reports whether a grant of a role to a principal gives p on a resource type. A role
// that is no longer in the catalog gives nothing.
func (a *Authorizer) gives(to Principal, id Role, p Permission, resourceType string) bool {
	def, ok := a.roles[id]
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
	var candidates []Permission
	owner := s.owns(r)
	if owner {
		candidates = slices.DeleteFunc(a.permissionsOn(r.Type), func(p Permission) bool { return !a.ownerHolds(r.Type, p) })
	}
	// A container's owner holds its grant permission only through grants.
	if !owner || a.contains(r.Type) {
		held, err := a.heldBindings(ctx, a.db, r.Tenant, s.principals(r.Tenant), r.path())
		if err != nil {
			return nil, err
		}
		for _, b := range held {
			if def, ok := a.roles[b.Role]; ok && def.GrantableOn(r.Type) {
				for _, p := range def.Permissions {
					if b.Principal.carries(def, p) {
						candidates = append(candidates, p)
					}
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

// Holders lists who may do p to r: its owner, and every principal holding a role that gives it
// there, the tenant's members and the public included. The AuthZEN subject search; the host
// expands groups to their members.
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
	var holders []Principal
	if r.Owner != "" && a.ownerHolds(r.Type, p) {
		holders = append(holders, Principal{Kind: User, ID: r.Owner})
	}
	roles := a.giving(p, r.Type)
	if len(roles) == 0 {
		return holders, nil
	}
	rows, err := a.db.Query(ctx, `
		SELECT DISTINCT principal_kind, principal_id FROM rbac_grants
		WHERE tenant = $1 AND scope = ANY($2::text[]) AND role = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4) AND (NOT $5 OR principal_kind <> ALL($6::text[]))
		  AND (principal_kind <> $7 OR role = ANY($8::text[]))
		ORDER BY principal_kind, principal_id`,
		r.Tenant, r.path(), roles, a.cfg.Now(), p.managesAccess(), []string{string(Tenant), string(Public)},
		string(Public), a.publicRoles(roles))
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
	// found is distinct, so only the owner can be listed twice. A kind the host no longer
	// declares can't act, so its grants give nothing.
	found = slices.DeleteFunc(found, func(p Principal) bool { return !a.known(r.Tenant, p) || slices.Contains(holders, p) })
	return append(holders, found...), nil
}

// Reach is where a subject may do something: every resource of the type in the tenant, or
// those whose path (Authorizer.Path) holds one of Scopes.
type Reach struct {
	All    bool
	Scopes []Scope
	// Owned is whether the resources the subject owns are reachable too, which the host adds.
	// It is false when a constraint removes the permission, since that binds owners as well.
	Owned bool
}

// Reachable says where the subject may do p to resources of a type in a tenant, for hosts that
// list from a store other than this PostgreSQL. Hosts on the same database use Filter.
func (a *Authorizer) Reachable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (Reach, error) {
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil || removed {
		return Reach{}, err
	}
	reach := Reach{Owned: s.user(tenant) != "" && a.ownerHolds(resourceType, p)}
	publicRoles := a.publicRoles(roles)
	principals := s.principalsFor(tenant, p, len(publicRoles) > 0)
	if len(roles) == 0 || len(principals) == 0 {
		return reach, nil
	}
	rows, err := a.db.Query(ctx, `
		SELECT DISTINCT scope FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND role = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4) AND split_part(scope, ':', 1) = ANY($5::text[])
		  AND (principal <> $6 OR role = ANY($7::text[]))
		ORDER BY scope`,
		tenant, principals, roles, a.cfg.Now(), a.reaching(resourceType), publicKey, publicRoles)
	if err != nil {
		return Reach{}, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return Reach{}, err
	}
	for _, k := range keys {
		if k == TenantRoot(tenant).Key() {
			return Reach{All: true, Owned: reach.Owned}, nil
		}
		reach.Scopes = append(reach.Scopes, parseScope(k))
	}
	return reach, nil
}

// searchable returns the roles that give p on a resource type, and whether a constraint
// removes p there, from owners too.
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
	// Owner is the resource's owner; empty when resources have none.
	Owner string
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
	publicRoles := a.publicRoles(roles)
	principals := s.principalsFor(tenant, p, len(publicRoles) > 0)
	granted := len(roles) > 0 && len(principals) > 0
	user := s.user(tenant)
	owner := cols.Owner != "" && user != "" && !removed && a.ownerHolds(resourceType, p)
	if !granted && !owner {
		return Predicate{SQL: "FALSE"}, nil
	}

	arg := func(i int) string { return fmt.Sprintf("$%d", firstArg+i) }
	args := []any{tenant}
	var ors []string
	if owner {
		ors = append(ors, fmt.Sprintf("%s = %s", cols.Owner, arg(len(args))))
		args = append(args, user)
	}
	if granted {
		// The grants' tenant is an argument of its own: the host's tenant column needn't be
		// text, and one argument can't take two types.
		tenantArg, principalsArg, rolesArg, nowArg, typesArg := arg(len(args)), arg(len(args)+1), arg(len(args)+2), arg(len(args)+3), arg(len(args)+4)
		publicArg, publicRolesArg := arg(len(args)+5), arg(len(args)+6)
		args = append(args, tenant, principals, roles, a.cfg.Now(), a.reaching(resourceType), publicKey, publicRoles)
		// A tenant-wide grant's scope is the tenant's key, which every path holds, so one
		// overlap covers every scope and the host's GIN index serves it. The keys take the
		// default collation so that index applies.
		ors = append(ors, fmt.Sprintf(`%s && ARRAY(SELECT g.scope COLLATE "default" FROM rbac_grants g
			WHERE g.tenant = %s::text AND g.principal = ANY(%s::text[]) AND g.role = ANY(%s::text[])
			  AND (g.expires_at IS NULL OR g.expires_at > %s) AND split_part(g.scope, ':', 1) = ANY(%s::text[])
			  AND (g.principal <> %s::text OR g.role = ANY(%s::text[])))`,
			cols.Path, tenantArg, principalsArg, rolesArg, nowArg, typesArg, publicArg, publicRolesArg))
	}
	return Predicate{
		SQL:  fmt.Sprintf("(%s = %s AND (%s))", cols.Tenant, arg(0), strings.Join(ors, " OR ")),
		Args: args,
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
