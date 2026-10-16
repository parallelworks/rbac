package rbac

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// CustomPrefix starts every custom role's id, so none can be a built-in role's.
const CustomPrefix = "custom."

// A tenant has at most maxCustomRoles custom roles, each listing at most maxGrantableRoles, so
// the roles a change reads and the delegation it checks stay bounded.
const (
	maxCustomRoles    = 300
	maxGrantableRoles = 64
)

// DefineRoles is the permission to create, replace and delete a tenant's custom roles, held on
// the tenant.
const DefineRoles Permission = "tenant:define-roles"

// book resolves role ids: the built-in catalog, and the custom roles a call has read.
type book struct {
	builtin map[Role]RoleDefinition
	custom  map[Role]RoleDefinition
}

func (b book) role(id Role) (RoleDefinition, bool) {
	if r, ok := b.builtin[id]; ok {
		return r, true
	}
	r, ok := b.custom[id]
	return r, ok
}

func isCustom(id Role) bool { return strings.HasPrefix(string(id), CustomPrefix) }

// book reads, on q, the definitions of the custom roles among ids in a tenant. Without one
// among them it reads nothing.
func (a *Authorizer) book(ctx context.Context, q DB, tenant string, ids []Role) (book, error) {
	b := book{builtin: a.roles}
	var want []string
	for _, id := range ids {
		if isCustom(id) && !slices.Contains(want, string(id)) {
			want = append(want, string(id))
		}
	}
	if len(want) == 0 {
		return b, nil
	}
	rows, err := q.Query(ctx, `SELECT `+roleColumns+` FROM rbac_roles WHERE tenant = $1 AND id = ANY($2::text[])`, tenant, want)
	if err != nil {
		return book{}, err
	}
	roles, err := collectRoles(rows)
	if err != nil {
		return book{}, err
	}
	return a.bookOf(a.current(roles)), nil
}

// bookOf resolves the built-in roles and the custom ones given.
func (a *Authorizer) bookOf(custom []RoleDefinition) book {
	b := book{builtin: a.roles, custom: make(map[Role]RoleDefinition, len(custom))}
	for _, r := range custom {
		b.custom[r.ID] = r
	}
	return b
}

func roleIDs(bindings []Binding) []Role {
	ids := make([]Role, len(bindings))
	for i, b := range bindings {
		ids[i] = b.Role
	}
	return ids
}

func grantRoleIDs(grants []Grant) []Role {
	ids := make([]Role, len(grants))
	for i, g := range grants {
		ids[i] = g.Role
	}
	return ids
}

const roleColumns = `id, name, description, permissions, resource_types, privileged, public, grantable_roles`

func collectRoles(rows pgx.Rows) ([]RoleDefinition, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (RoleDefinition, error) {
		var r RoleDefinition
		var perms, types, grantable []string
		err := row.Scan(&r.ID, &r.Name, &r.Description, &perms, &types, &r.Privileged, &r.Public, &grantable)
		for _, p := range perms {
			r.Permissions = append(r.Permissions, Permission(p))
		}
		r.ResourceTypes = types
		for _, g := range grantable {
			r.GrantableRoles = append(r.GrantableRoles, Role(g))
		}
		return r, err
	})
}

// givingSQL is SQL for the ids of the roles that give perm on a resource type in a tenant: the
// built-in ones in the array argument builtin, and with custom the tenant's custom ones, read in
// the same statement. With public, only roles marked Public.
func givingSQL(builtin, tenant, perm, resourceType string, public, custom bool) string {
	only := ""
	if public {
		only = " AND cr.public"
	}
	// Without custom the subquery stays, constant false, so the statement's arguments are the
	// same and PostgreSQL plans it away.
	return fmt.Sprintf(`(%s::text[] || ARRAY(SELECT cr.id FROM rbac_roles cr WHERE %t AND cr.tenant = %s::text
		AND %s::text = ANY(cr.permissions) AND %s::text = ANY(cr.resource_types)%s))`, builtin, custom, tenant, perm, resourceType, only)
}

// checkCustom returns why a custom role's definition is malformed: its id, and permissions and
// types that no built-in role gives or is for, so a tenant can't invent either. A public one
// gives each permission only on types where a built-in role that isn't privileged gives it, so
// it can't make root-level control public by leaving Privileged unset, nor by pairing a
// permission with a type only privileged roles give it on.
func (a *Authorizer) checkCustom(r RoleDefinition) error {
	if !isCustom(r.ID) || !roleID.MatchString(string(r.ID)) || len(r.ID) == len(CustomPrefix) {
		return fmt.Errorf("%w: a custom role's id is %q and lowercase letters, digits, dots, hyphens and underscores", ErrInvalid, CustomPrefix+"…")
	}
	errs := shape(r)
	for _, p := range r.Permissions {
		if !a.permissions[p] {
			errs = append(errs, fmt.Errorf("permission %q is not one any built-in role gives", p))
			continue
		}
		for _, t := range r.ResourceTypes {
			if r.Public && a.types[t] && !a.unprivileged[permissionOn{p, t}] {
				errs = append(errs, fmt.Errorf("permission %q on %s is given only by privileged roles, so a public role can't give it", p, t))
			}
		}
	}
	for _, t := range r.ResourceTypes {
		if !a.types[t] {
			errs = append(errs, fmt.Errorf("resource type %q is not one any built-in role is for", t))
		}
	}
	if len(r.GrantableRoles) > maxGrantableRoles {
		errs = append(errs, fmt.Errorf("lists more than %d grantable roles", maxGrantableRoles))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: role %q: %w", ErrInvalid, r.ID, errors.Join(errs...))
	}
	return nil
}

// canonical is a copy of r with its lists sorted and without repeats, so a definition reordered
// is the same one.
func canonical(r RoleDefinition) RoleDefinition {
	r = r.clone()
	slices.Sort(r.Permissions)
	r.Permissions = slices.Compact(r.Permissions)
	slices.Sort(r.ResourceTypes)
	r.ResourceTypes = slices.Compact(r.ResourceTypes)
	slices.Sort(r.GrantableRoles)
	r.GrantableRoles = slices.Compact(r.GrantableRoles)
	return r
}

// DefineRole creates a custom role in a tenant, or replaces one, as actor; grants of a replaced
// role give what it gives now. Its id starts with CustomPrefix, and it gives only permissions
// some built-in role gives, on types some built-in role is for. It is Privileged when it gives
// a permission on a type only privileged built-in roles give it on.
//
// The actor needs DefineRoles on the tenant, not removed by a constraint, and every permission
// the role gives there, for each type it is for, as granting it on the tenant would need. Each
// of its GrantableRoles must be a role the actor may grant on the tenant. Replacing a role
// another custom role lists needs the power to grant it as defined wherever that one lists it.
func (a *Authorizer) DefineRole(ctx context.Context, actor Subject, tenant string, r RoleDefinition) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	r = canonical(r)
	if err := a.checkCustom(r); err != nil {
		return err
	}
	// Privileged as the roles that give its permissions on its types are, or as a role it lists
	// is, so a host that confirms privileged grants asks about one that gives or hands out root
	// however it was defined.
	listed, err := a.book(ctx, a.db, tenant, r.GrantableRoles)
	if err != nil {
		return err
	}
	r.Privileged = r.Privileged || a.privileged(r) || slices.ContainsFunc(r.GrantableRoles, func(id Role) bool {
		def, ok := listed.role(id)
		return ok && def.Privileged
	})
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	// Checked in full before the transaction too, so a refused actor never locks the tenant.
	if err := a.mayDefineRoles(ctx, actor, root, &r); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		// Alone in the tenant, so a change in progress checks and commits against one
		// definition of the role.
		if err := lockTenant(ctx, tx, tenant); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayDefine(ctx, tx, actor, root, &r); err != nil {
			return ChangeEvent{}, err
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM rbac_roles WHERE tenant = $1 AND id <> $2`, tenant, r.ID).Scan(&others); err != nil {
			return ChangeEvent{}, err
		}
		if others >= maxCustomRoles {
			return ChangeEvent{}, fmt.Errorf("%w: a tenant has at most %d custom roles", ErrInvalid, maxCustomRoles)
		}
		perms := make([]string, len(r.Permissions))
		for i, p := range r.Permissions {
			perms[i] = string(p)
		}
		grantable := make([]string, len(r.GrantableRoles))
		for i, g := range r.GrantableRoles {
			grantable[i] = string(g)
		}
		tag, err := tx.Exec(ctx, `
			INSERT INTO rbac_roles (tenant, id, name, description, permissions, resource_types, privileged, public, grantable_roles, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
			  permissions = EXCLUDED.permissions, resource_types = EXCLUDED.resource_types,
			  privileged = EXCLUDED.privileged, public = EXCLUDED.public,
			  grantable_roles = EXCLUDED.grantable_roles, updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE (rbac_roles.name, rbac_roles.description, rbac_roles.permissions, rbac_roles.resource_types,
			  rbac_roles.privileged, rbac_roles.public, rbac_roles.grantable_roles) IS DISTINCT FROM
			  (EXCLUDED.name, EXCLUDED.description, EXCLUDED.permissions, EXCLUDED.resource_types,
			  EXCLUDED.privileged, EXCLUDED.public, EXCLUDED.grantable_roles)`,
			tenant, r.ID, r.Name, r.Description, perms, r.ResourceTypes, r.Privileged, r.Public, grantable, actorKey(actor.Principal))
		if err != nil || tag.RowsAffected() == 0 {
			return ChangeEvent{}, err
		}
		return ChangeEvent{Roles: []RoleDefinition{r}}, nil
	})
}

// DeleteRole deletes a tenant's custom role and every grant of it, as actor, who needs
// DefineRoles on the tenant. It refuses a role another custom role lists in GrantableRoles:
// redefine that one first, or a role later defined with the id would be handed out through it.
// Deleting a role that doesn't exist does nothing.
func (a *Authorizer) DeleteRole(ctx context.Context, actor Subject, tenant string, id Role) error {
	if tenant == "" || !isCustom(id) {
		return fmt.Errorf("%w: only a tenant's custom role can be deleted", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	if err := a.mayDefineRoles(ctx, actor, root, nil); err != nil {
		return err
	}
	// Deleting it revokes its grants, so a constraint that stops changes to grants where it can
	// be granted stops deleting it, as it would revoking one by one.
	roles, err := a.book(ctx, a.db, tenant, []Role{id})
	if err != nil {
		return err
	}
	if def, ok := roles.role(id); ok {
		for _, t := range slices.Concat(def.ResourceTypes, a.containerTypes, []string{TenantScope}) {
			name, err := a.denied(ctx, tenant, t, GrantPermission(t))
			if err != nil {
				return err
			}
			if name != "" {
				return &DeniedError{Permission: GrantPermission(t), Scope: root.Scope(), Reason: fmt.Sprintf("removed by %s, which stops revoking %s", name, id)}
			}
		}
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockTenant(ctx, tx, tenant); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayDefine(ctx, tx, actor, root, nil); err != nil {
			return ChangeEvent{}, err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM rbac_roles WHERE tenant = $1 AND id <> $2 AND $2 = ANY(grantable_roles) ORDER BY id`, tenant, id)
		if err != nil {
			return ChangeEvent{}, err
		}
		listing, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return ChangeEvent{}, err
		}
		if len(listing) > 0 {
			return ChangeEvent{}, fmt.Errorf("%w: role %q is a grantable role of %s", ErrInvalid, id, strings.Join(listing, ", "))
		}
		// Only OnChange reads what was removed, which can be every grant of a widely held role.
		var revoked []Grant
		if a.cfg.OnChange == nil {
			_, err = tx.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = $1 AND role = $2`, tenant, id)
		} else if rows, err = tx.Query(ctx, `DELETE FROM rbac_grants WHERE tenant = $1 AND role = $2 RETURNING `+grantColumns, tenant, id); err == nil {
			revoked, err = collectGrants(rows)
		}
		if err != nil {
			return ChangeEvent{}, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM rbac_roles WHERE tenant = $1 AND id = $2`, tenant, id)
		if err != nil || tag.RowsAffected() == 0 {
			return ChangeEvent{Revoked: revoked}, err
		}
		return ChangeEvent{Revoked: revoked, DeletedRoles: []Role{id}}, nil
	})
}

// mayDefineRoles checks, before the transaction, that actor may define a tenant's roles. The
// constraints run here only, as in Apply: a hook that queries the pool while the transaction
// holds a connection can wait forever on a busy pool.
func (a *Authorizer) mayDefineRoles(ctx context.Context, actor Subject, root Resource, r *RoleDefinition) error {
	scope := root.Scope()
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, root.Tenant, TenantScope, DefineRoles)
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "removed by " + name}
	}
	return a.mayDefine(ctx, a.db, actor, root, r)
}

// mayDefine checks that actor holds DefineRoles on the tenant, and with r, that it may define r:
// that it holds everything r gives across the tenant, as granting r there would need, with no
// role it may merely hand out standing in, since defining r changes what its grants give.
func (a *Authorizer) mayDefine(ctx context.Context, q DB, actor Subject, root Resource, r *RoleDefinition) error {
	scope := root.Scope()
	var ids []Role
	if r != nil {
		ids = append([]Role{r.ID}, r.GrantableRoles...)
	}
	au, err := a.authorityOn(ctx, q, actor, root, ids)
	if err != nil {
		return err
	}
	if !au.holds(DefineRoles, TenantScope) {
		return &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "the actor may not define roles here"}
	}
	if r == nil {
		return nil
	}
	// A role r lists is read as it will be, so one that lists itself is read as defined, while
	// the actor's own grants of r give what r gives now: holding r is no license to widen it.
	au.defining = r
	for _, id := range r.GrantableRoles {
		if _, known := au.named(id); !known {
			return fmt.Errorf("%w: role %q: grantable role %q doesn't exist", ErrInvalid, r.ID, id)
		}
	}
	seen := map[string]bool{}
	if p, ok := a.holdsRole(au, *r, r.ResourceTypes, seen); !ok {
		return &DeniedError{Permission: p, Scope: scope, Reason: fmt.Sprintf("the actor can't define %s without holding %s here", r.ID, p)}
	}
	// A role that lists r lets its holders grant r as it will be wherever it can be granted, a
	// power its definer never had to have if r gave less or couldn't be granted there: the
	// actor must have it.
	for _, id := range slices.Sorted(maps.Keys(au.roles.custom)) {
		lister := au.roles.custom[id]
		if id == r.ID || !slices.Contains(lister.GrantableRoles, r.ID) {
			continue
		}
		for _, p := range lister.Permissions {
			t, _ := p.parts()
			if !p.changesGrants() || !a.grantableOn(*r, t) {
				continue
			}
			if missing, ok := a.mayGrant(au, t, *r, seen); !ok {
				return &DeniedError{Permission: missing, Scope: scope, Reason: fmt.Sprintf("the actor can't define %s, which %s lists, without the power to grant it on a %s", r.ID, id, t)}
			}
		}
	}
	return nil
}

// privileged reports whether a custom role gives a permission on a type that only privileged
// built-in roles give it on.
func (a *Authorizer) privileged(r RoleDefinition) bool {
	for _, p := range r.Permissions {
		for _, t := range r.ResourceTypes {
			if !a.unprivileged[permissionOn{p, t}] {
				return true
			}
		}
	}
	return false
}

// CustomRoles lists a tenant's custom roles, by id.
func (a *Authorizer) CustomRoles(ctx context.Context, tenant string) ([]RoleDefinition, error) {
	return a.customRoles(ctx, a.db, tenant)
}

func (a *Authorizer) customRoles(ctx context.Context, q DB, tenant string) ([]RoleDefinition, error) {
	rows, err := q.Query(ctx, `SELECT `+roleColumns+` FROM rbac_roles WHERE tenant = $1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	roles, err := collectRoles(rows)
	return a.current(roles), err
}

// current reads stored definitions as the catalog has them now, so a catalog change binds
// custom roles defined before it: they give only permissions and types the catalog still has,
// are public only while every permission they give is one an unprivileged role gives, and are
// privileged when they give or list what privileged roles do.
func (a *Authorizer) current(roles []RoleDefinition) []RoleDefinition {
	for i, r := range roles {
		r.Permissions = slices.DeleteFunc(r.Permissions, func(p Permission) bool { return !a.permissions[p] })
		r.ResourceTypes = slices.DeleteFunc(r.ResourceTypes, func(t string) bool { return !a.types[t] })
		r.Public = r.Public && !a.privileged(r) && !r.managesAccess()
		r.Privileged = r.Privileged || a.privileged(r) || a.listsPrivileged(r)
		roles[i] = r
	}
	return roles
}

// customGives reports whether a custom role can give p on a resource type: only a permission
// and a type the catalog has, so a search skips custom roles for any other.
func (a *Authorizer) customGives(p Permission, resourceType string) bool {
	return a.permissions[p] && a.types[resourceType]
}

// listsPrivileged reports whether r lists a privileged built-in role. A custom one it lists
// counts when r is defined.
func (a *Authorizer) listsPrivileged(r RoleDefinition) bool {
	return slices.ContainsFunc(r.GrantableRoles, func(id Role) bool { return a.roles[id].Privileged })
}

// RolesIn lists the roles that can be granted on a scope type in a tenant: the built-in ones in
// catalog order, then the tenant's custom ones by id.
func (a *Authorizer) RolesIn(ctx context.Context, tenant, scopeType string) ([]RoleDefinition, error) {
	custom, err := a.CustomRoles(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return a.rolesIn(scopeType, custom), nil
}

func (a *Authorizer) rolesIn(scopeType string, custom []RoleDefinition) []RoleDefinition {
	roles := a.Roles(scopeType)
	for _, r := range custom {
		if a.grantableOn(r, scopeType) {
			roles = append(roles, r)
		}
	}
	return roles
}
