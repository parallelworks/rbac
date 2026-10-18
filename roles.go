package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// CustomPrefix starts every custom role's id, so none can be a built-in role's.
const CustomPrefix = "custom."

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
// among them it reads nothing. A role it reads is privileged by what it gives and the built-in
// roles it lists, not the custom ones, so where the flag counts, read with tenantBook.
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

// tenantBook resolves ids with every custom role of the tenant when one is among them, so each
// is privileged when a role it lists is, directly or through others (handingOut).
func (a *Authorizer) tenantBook(ctx context.Context, q DB, tenant string, ids []Role) (book, error) {
	if !slices.ContainsFunc(ids, isCustom) {
		return book{builtin: a.roles}, nil
	}
	custom, err := a.customRoles(ctx, q, tenant)
	if err != nil {
		return book{}, err
	}
	return a.bookOf(custom), nil
}

// bookOf resolves the built-in roles and the custom ones given.
func (a *Authorizer) bookOf(custom []RoleDefinition) book {
	b := book{builtin: a.roles, custom: make(map[Role]RoleDefinition, len(custom))}
	for _, r := range custom {
		b.custom[r.ID] = r
	}
	return b
}

func (b Binding) role() Role { return b.Role }

// roleIDs are the roles of bindings, grants or holdings.
func roleIDs[T interface{ role() Role }](bindings []T) []Role {
	ids := make([]Role, len(bindings))
	for i, b := range bindings {
		ids[i] = b.role()
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

// publicSQL names the array arguments that Authorizer.publicArgs fills.
type publicSQL struct{ perms, types, pairs string }

// givingSQL is SQL for the ids of the roles that give perm on a resource type in a tenant: the
// built-in ones in the array argument builtin, and with custom the tenant's custom ones, read in
// the same statement. With public, only custom roles public as Authorizer.current reads them:
// marked Public, and of the permissions and types the catalog has, giving none that changes
// access and each only where a role that isn't privileged gives it, so a catalog change reaches
// searches as it reaches checks.
func givingSQL(builtin, tenant, perm, resourceType string, custom bool, public *publicSQL) string {
	only := ""
	if public != nil {
		only = fmt.Sprintf(` AND cr.public AND NOT EXISTS (SELECT FROM unnest(cr.permissions) cp, unnest(cr.resource_types) ct
		WHERE cp = ANY(%s::text[]) AND ct = ANY(%s::text[]) AND cp || ' ' || ct <> ALL(%s::text[]))`, public.perms, public.types, public.pairs)
	}
	// Without custom the subquery stays, constant false, so the statement's arguments are the
	// same and PostgreSQL plans it away.
	return fmt.Sprintf(`(%s::text[] || ARRAY(SELECT cr.id FROM rbac_roles cr WHERE %t AND cr.tenant = %s::text
		AND %s::text = ANY(cr.permissions) AND %s::text = ANY(cr.resource_types)%s))`, builtin, custom, tenant, perm, resourceType, only)
}

// publicArgs are the arguments of givingSQL's public check: the catalog's permissions, its types
// and the pairs of them a public role may give. They are NULL where the check can't matter, so a
// search doesn't send them: with no custom role in it, or where no grant to the public gives p,
// as Filter and Reachable then read none and Holders drops the public.
func (a *Authorizer) publicArgs(p Permission, resourceType string, custom bool) []any {
	if !custom || !a.publicGives(p, resourceType) {
		return []any{nil, nil, nil}
	}
	return []any{a.catalogPermissions, a.catalogTypes, a.publicPairs}
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
	if len(r.GrantableRoles) > MaxGrantableRoles {
		errs = append(errs, fmt.Errorf("lists more than %d grantable roles", MaxGrantableRoles))
	}
	if utf8.RuneCountInString(r.Name) > MaxName || utf8.RuneCountInString(r.Description) > MaxDescription {
		errs = append(errs, fmt.Errorf("a name is at most %d characters and a description %d", MaxName, MaxDescription))
	}
	// Each is checked alone: a character split between them is valid only once joined.
	if !validText(r.Name) || !validText(r.Description) {
		errs = append(errs, errors.New("a name and a description are UTF-8 text without NUL"))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: role %q: %w", ErrInvalid, r.ID, errors.Join(errs...))
	}
	return nil
}

// validText reports whether PostgreSQL stores s: it refuses text that isn't UTF-8 or holds a NUL,
// as an error that isn't ErrInvalid.
func validText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }

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

// SetRole creates a custom role in a tenant, or replaces one, as actor; grants of a replaced
// role give what it gives now. Its id starts with CustomPrefix, and it gives only permissions
// some built-in role gives, on types some built-in role is for. It is Privileged when it gives
// a permission on a type only privileged built-in roles give it on, or hands out a privileged
// role, directly or through the roles it lists, whatever r.Privileged says, so a role read and
// saved back keeps no flag it no longer earns.
//
// The actor needs DefineRoles on the tenant, not removed by a constraint (a condition on that
// right reads the tenant as a resource with no attributes), and every permission
// the role gives there, for each type it is for, as granting it on the tenant would need. Each
// of its GrantableRoles must be a role the actor may grant on the tenant. Replacing a role
// another custom role lists needs the power to grant it as defined wherever that one lists it.
// Replacing one so that its grants give something else changes them, so a constraint that stops
// changes to grants where it can be granted, or a deny that removes the actor's power to change
// them there, stops it, as it stops DeleteRole. A role another change redefined or created while
// this one waited for the tenant is refused, to be tried again: the constraints were asked about
// it as it was. One deleted meanwhile is created, as its grants went with it.
//
// Redefining a role so that its grants give more, or so that a role handing it out becomes
// privileged, changes what grants already made give: Config.ValidateGrant is asked about each of
// their grants and eligibilities in force that gives anything as the roles will be
// (ViaRedefinition), and refusing any refuses the redefinition, as granting the role so would be
// refused. Narrowing a role asks about none. One made while this waited for the tenant refuses it
// too, to be tried again, as the host wasn't asked about it.
func (a *Authorizer) SetRole(ctx context.Context, actor Subject, tenant string, r RoleDefinition) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	// Whether the actor may define roles at all, before the definition, so a refused actor
	// learns nothing of the catalog from what is invalid.
	if _, err := a.mayDefineRoles(ctx, actor, root); err != nil {
		return err
	}
	r = canonical(r)
	// Derived below, so what the definition says can't refuse a role it doesn't make privileged.
	r.Privileged = false
	if err := a.checkCustom(r); err != nil {
		return err
	}
	// Checked in full before the transaction too, so a refused actor never locks the tenant. The
	// constraints on defining roles ran above; those on what the role gives run here, once.
	cs := a.constrain(ctx, actor, root)
	au, err := a.mayDefine(ctx, a.db, actor, root, &r, cs)
	if err != nil {
		return err
	}
	checked, existed := au.roles.custom[r.ID]
	if existed && !sameAccess(checked, r) {
		// Its grants are on scopes of the types it is for, and on those it was for before and is
		// for again, whose grants it brings back.
		types := slices.Concat(checked.ResourceTypes, r.ResourceTypes)
		if err := a.changesStopped(ctx, actor, tenant, types, fmt.Sprintf("changing what %s's grants give", r.ID)); err != nil {
			return err
		}
		if err := a.changesDenied(au, tenant, types, fmt.Sprintf("changing what %s's grants give", r.ID)); err != nil {
			return err
		}
	}
	asked, err := a.revalidate(ctx, actor, tenant, au.roles.custom, r)
	if err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		// Alone in the tenant, so a change in progress checks and commits against one
		// definition of the role.
		if err := lockTenant(ctx, tx, tenant); err != nil {
			return ChangeEvent{}, err
		}
		cs.seal()
		au, err := a.mayDefine(ctx, tx, actor, root, &r, cs)
		if err != nil {
			return ChangeEvent{}, err
		}
		old, ok := au.roles.custom[r.ID]
		if ok && !sameAccess(old, r) && (!existed || !sameAccess(old, checked)) {
			return ChangeEvent{}, changedMeanwhile(r.ID)
		}
		// Again on the denies read under the lock, which a deny set meanwhile is among.
		if ok && !sameAccess(old, r) {
			if err := a.changesDenied(au, tenant, slices.Concat(old.ResourceTypes, r.ResourceTypes), fmt.Sprintf("changing what %s's grants give", r.ID)); err != nil {
				return ChangeEvent{}, err
			}
		}
		// Privileged as the roles that give its permissions on its types are, or as a role it
		// hands out is, so a host that confirms privileged grants asks about one that gives or
		// hands out root however it was defined. Derived as a read derives it, with r in place
		// of what it was, which is no part of what it is.
		after, widened := a.redefining(au.roles.custom, r)
		r.Privileged = after[r.ID].Privileged
		// The grants it widens are the ones the host was asked about, of the roles as it was asked
		// about them, or one was made or a role redefined meanwhile.
		need, err := a.revalidations(ctx, tx, tenant, widened)
		if err != nil {
			return ChangeEvent{}, err
		}
		for _, v := range need {
			if as, ok := asked[v.key()]; !ok || widens(as, v.role) {
				return ChangeEvent{}, fmt.Errorf("%w: grants %s's definition widens changed while it waited; try again", ErrConflict, r.ID)
			}
		}
		others := len(au.roles.custom)
		if ok {
			others--
		}
		if others >= MaxCustomRoles {
			return ChangeEvent{}, fmt.Errorf("%w: a tenant has at most %d custom roles", ErrInvalid, MaxCustomRoles)
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

// DeleteRole deletes a tenant's custom role and every grant and eligibility of it, as actor, who
// needs DefineRoles on the tenant. It refuses a role another custom role lists in
// GrantableRoles: redefine that one first, or a role later defined with the id would be handed
// out through it. Deleting a role that doesn't exist does nothing; one changed while the
// deletion waited for the tenant is refused, as in SetRole.
func (a *Authorizer) DeleteRole(ctx context.Context, actor Subject, tenant string, id Role) error {
	if tenant == "" || !isCustom(id) {
		return fmt.Errorf("%w: only a tenant's custom role can be deleted", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	au, err := a.mayDefineRoles(ctx, actor, root)
	if err != nil {
		return err
	}
	// Deleting it revokes its grants, so a constraint or deny that stops changes to grants where it
	// can be granted stops deleting it, as it would revoking one by one.
	roles, err := a.book(ctx, a.db, tenant, []Role{id})
	if err != nil {
		return err
	}
	checked, existed := roles.role(id)
	if existed {
		if err := a.changesStopped(ctx, actor, tenant, checked.ResourceTypes, "revoking "+string(id)); err != nil {
			return err
		}
		if err := a.changesDenied(au, tenant, checked.ResourceTypes, "revoking "+string(id)); err != nil {
			return err
		}
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockTenant(ctx, tx, tenant); err != nil {
			return ChangeEvent{}, err
		}
		au, err := a.mayDefine(ctx, tx, actor, root, nil, nil)
		if err != nil {
			return ChangeEvent{}, err
		}
		roles, err := a.book(ctx, tx, tenant, []Role{id})
		if err != nil {
			return ChangeEvent{}, err
		}
		if def, ok := roles.role(id); ok && (!existed || !sameAccess(def, checked)) {
			return ChangeEvent{}, changedMeanwhile(id)
		}
		if existed {
			if err := a.changesDenied(au, tenant, checked.ResourceTypes, "revoking "+string(id)); err != nil {
				return ChangeEvent{}, err
			}
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
		// The LIKE matches the partial indexes on custom roles' grants and eligibilities.
		const ofRole = "role = $2 AND role LIKE 'custom.%'"
		revoked, err := a.remove(ctx, tx, tenant, ofRole, id)
		if err != nil {
			return ChangeEvent{}, err
		}
		ended, err := a.removeEligible(ctx, tx, tenant, ofRole, id)
		if err != nil {
			return ChangeEvent{}, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM rbac_roles WHERE tenant = $1 AND id = $2`, tenant, id)
		if err != nil || tag.RowsAffected() == 0 {
			return ChangeEvent{Revoked: revoked, Ineligible: ended}, err
		}
		return ChangeEvent{Revoked: revoked, Ineligible: ended, DeletedRoles: []Role{id}}, nil
	})
}

// redefining returns the tenant's custom roles as they will be once r replaces its definition
// among custom, as read, and those whose grants give more then: r, when it gives more than it
// gave, and each role that hands it out and becomes privileged with it. Copies, as current trims
// them.
func (a *Authorizer) redefining(custom map[Role]RoleDefinition, r RoleDefinition) (after, widened map[Role]RoleDefinition) {
	roles := []RoleDefinition{r.clone()}
	for id, def := range custom {
		if id != r.ID {
			roles = append(roles, def.clone())
		}
	}
	after, widened = map[Role]RoleDefinition{}, map[Role]RoleDefinition{}
	for _, def := range handingOut(a.current(roles)) {
		after[def.ID] = def
		was := custom[def.ID]
		if def.Privileged && !was.Privileged || def.ID == r.ID && givesMore(was, def) {
			widened[def.ID] = def
		}
	}
	return after, widened
}

// givesMore reports whether grants of a role defined as now give anything they didn't as was, so
// that narrowing a role is never refused for grants it already has. An empty GrantableRoles lets
// holders grant any role they hold, and a listed role needn't be held, so only dropping roles from
// a list that stays non-empty gives no more.
func givesMore(was, now RoleDefinition) bool {
	return !subset(now.Permissions, was.Permissions) || !subset(now.ResourceTypes, was.ResourceTypes) ||
		now.Public && !was.Public ||
		len(now.GrantableRoles) == 0 && len(was.GrantableRoles) > 0 || !subset(now.GrantableRoles, was.GrantableRoles)
}

func subset[T comparable](xs, of []T) bool {
	return !slices.ContainsFunc(xs, func(x T) bool { return !slices.Contains(of, x) })
}

// redefinedSince refuses a change granting roles that, now, give more than the host was asked
// about before its transaction (asked), as a redefinition committed meanwhile, say to give root,
// makes them: the host was never asked about the grant as it gives now. One renamed or narrowed
// meanwhile gives no more, so is granted.
func redefinedSince(asked, now book, roles []Role) error {
	for _, id := range roles {
		was, _ := asked.role(id)
		if is, ok := now.role(id); ok && widens(was, is) {
			return changedMeanwhile(id)
		}
	}
	return nil
}

// widens reports whether grants of a role defined as now give more than the host was asked about
// as was: what it gives, or newly privileged, as through a role it lists.
func widens(was, now RoleDefinition) bool {
	return givesMore(was, now) || now.Privileged && !was.Privileged
}

// revalidation is a grant or eligibility of a role a redefinition widens, which the host is asked
// about again as the role will be.
type revalidation struct {
	scope   Scope
	binding Binding
	role    RoleDefinition
}

// revalidated is a revalidation as asked about: the same grant or eligibility, unchanged.
type revalidated struct {
	grantKey
	scope    Scope
	id, note string
}

func (v revalidation) key() revalidated {
	return revalidated{grantKey: keyOf(v.binding), scope: v.scope, id: v.binding.ID, note: v.binding.Note}
}

// revalidations reads, on q, the grants and eligibilities in force of the roles widened, leaving
// out those that give nothing as the roles will be, as checks read them: they widen nothing.
func (a *Authorizer) revalidations(ctx context.Context, q DB, tenant string, widened map[Role]RoleDefinition) ([]revalidation, error) {
	if len(widened) == 0 {
		return nil, nil
	}
	var ids []string
	for id := range widened {
		ids = append(ids, string(id))
	}
	// The LIKE matches the partial indexes on custom roles' grants and eligibilities.
	const ofRoles = `tenant = $1 AND role = ANY($2::text[]) AND role LIKE 'custom.%' AND (expires_at IS NULL OR expires_at > $3)`
	rows, err := q.Query(ctx, `SELECT `+grantColumns+` FROM rbac_grants WHERE `+ofRoles+` ORDER BY id`, tenant, ids, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	grants, err := collectGrants(rows)
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT `+eligibilityColumns+` FROM rbac_eligibilities WHERE `+ofRoles+` ORDER BY scope, principal, role`, tenant, ids, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	eligible, err := collectEligibilities(rows)
	if err != nil {
		return nil, err
	}
	need := make([]revalidation, 0, len(grants)+len(eligible))
	add := func(scope Scope, b Binding) {
		def := widened[b.Role]
		gives := slices.ContainsFunc(def.Permissions, func(p Permission) bool { return b.Principal.carries(def, p) })
		if gives && a.known(tenant, b.Principal) && a.grantableOn(def, scope.Type) {
			need = append(need, revalidation{scope: scope, binding: b, role: def})
		}
	}
	for _, g := range grants {
		add(g.Scope, g.Binding)
	}
	for _, e := range eligible {
		add(e.Scope, e.binding())
	}
	return need, nil
}

// revalidate asks Config.ValidateGrant, before SetRole's transaction, about each grant and
// eligibility of a role that redefining r as actor widens, and returns those it asked about, with
// the role as it asked. custom are the tenant's custom roles, as read.
func (a *Authorizer) revalidate(ctx context.Context, actor Subject, tenant string, custom map[Role]RoleDefinition, r RoleDefinition) (map[revalidated]RoleDefinition, error) {
	_, widened := a.redefining(custom, r)
	need, err := a.revalidations(ctx, a.db, tenant, widened)
	if err != nil {
		return nil, err
	}
	roles := book{builtin: a.roles, custom: widened}
	asked := make(map[revalidated]RoleDefinition, len(need))
	var refused []error
	for _, v := range need {
		bad, err := a.allowed(ctx, roles, actor, ViaRedefinition, tenant, v.scope, v.binding)
		if err != nil {
			return nil, err
		}
		// The binding names no scope, and an eligibility has no ID, so the reason says which.
		for _, e := range bad {
			var ie *InvalidError
			if errors.As(e, &ie) {
				ie.Reason = "on " + v.scope.Key() + ", " + ie.Reason
			}
		}
		refused = append(refused, bad...)
		asked[v.key()] = v.role
	}
	return asked, errors.Join(refused...)
}

// changesStopped returns why a constraint stops changing every grant of a custom role: one that
// stops changes to grants on scopes of one of the role's types, a container or the tenant.
func (a *Authorizer) changesStopped(ctx context.Context, actor Subject, tenant string, roleTypes []string, change string) error {
	for _, t := range a.grantedOn(roleTypes) {
		name, err := a.denied(ctx, ConstraintInput{Tenant: tenant, ResourceType: t, Permission: GrantPermission(t), Subject: &actor})
		if err != nil {
			return err
		}
		if name != "" {
			return &DeniedError{Permission: GrantPermission(t), Scope: TenantRoot(tenant), Reason: fmt.Sprintf("removed by %s, which stops %s", name, change)}
		}
	}
	return nil
}

// changesDenied returns why a deny stops the actor changing every grant of a custom role, as
// changesStopped does for a constraint: one that removes its power to change grants on scopes of
// one of the role's types, a container or the tenant.
func (a *Authorizer) changesDenied(au authority, tenant string, roleTypes []string, change string) error {
	for _, t := range a.grantedOn(roleTypes) {
		if au.handsOn(GrantPermission(t)) {
			return &DeniedError{Permission: GrantPermission(t), Scope: TenantRoot(tenant), Reason: "removed by a deny, which stops " + change}
		}
	}
	return nil
}

// grantedOn lists the scope types a custom role's grants can be on: its types, the containers
// and the tenant.
func (a *Authorizer) grantedOn(roleTypes []string) []string {
	types := slices.Concat(roleTypes, a.containerTypes, []string{TenantScope})
	slices.Sort(types)
	return slices.Compact(types)
}

// changedMeanwhile refuses a change to a role that another change redefined or created after
// the constraints, which run before the transaction, were asked about it.
func changedMeanwhile(id Role) error {
	return fmt.Errorf("%w: role %q changed while this change waited for it; try again", ErrConflict, id)
}

// sameAccess reports whether two definitions of a role give the same through its grants.
func sameAccess(x, y RoleDefinition) bool {
	return x.Public == y.Public && slices.Equal(x.Permissions, y.Permissions) &&
		slices.Equal(x.ResourceTypes, y.ResourceTypes) && slices.Equal(x.GrantableRoles, y.GrantableRoles)
}

// mayDefineRoles checks, before the transaction, that actor may define a tenant's roles. The
// constraints run here only, as in Apply: a hook that queries the pool while the transaction
// holds a connection can wait forever on a busy pool.
func (a *Authorizer) mayDefineRoles(ctx context.Context, actor Subject, root Resource) (authority, error) {
	scope := root.Scope()
	if actor.Principal == (Principal{}) {
		return authority{}, &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: root.Tenant, ResourceType: TenantScope, Permission: DefineRoles, Subject: &actor, Resource: &root})
	if err != nil {
		return authority{}, err
	}
	if name != "" {
		return authority{}, &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "removed by " + name}
	}
	return a.mayDefine(ctx, a.db, actor, root, nil, nil)
}

// mayDefine checks that actor holds DefineRoles on the tenant, and with r, that it may define r:
// that it holds everything r gives across the tenant, as granting r there would need, with no
// role it may merely hand out standing in, since defining r changes what its grants give, and
// none of it removed by a constraint (cs). It returns what it read; with r, every custom role of
// the tenant.
func (a *Authorizer) mayDefine(ctx context.Context, q DB, actor Subject, root Resource, r *RoleDefinition, cs *constrained) (authority, error) {
	scope := root.Scope()
	var ids []Role
	if r != nil {
		ids = append([]Role{r.ID}, r.GrantableRoles...)
	}
	au, err := a.authorityOn(ctx, q, actor, root, ids)
	if err != nil {
		return authority{}, err
	}
	au.constrained = cs
	if !au.may(DefineRoles, TenantScope) {
		return authority{}, &DeniedError{Permission: DefineRoles, Scope: scope, Reason: "the actor may not define roles here"}
	}
	if r == nil {
		return au, nil
	}
	// A role r lists is read as it will be, so one that lists itself is read as defined, while
	// the actor's own grants of r give what r gives now: holding r is no license to widen it.
	au.defining = r
	for _, id := range r.GrantableRoles {
		if _, known := au.named(id); !known {
			return authority{}, fmt.Errorf("%w: role %q: grantable role %q doesn't exist", ErrInvalid, r.ID, id)
		}
	}
	seen := map[string]bool{}
	if p, ok := a.holdsRole(au, *r, r.ResourceTypes, "", seen); !ok {
		reason := cs.refusal("define "+string(r.ID), p, fmt.Sprintf("the actor can't define %s without holding %s here", r.ID, p))
		return authority{}, cmp.Or(cs.failed(), error(&DeniedError{Permission: p, Scope: scope, Reason: reason}))
	}
	// A role that lists r lets its holders grant r as it will be wherever it can be granted, a
	// power its definer never had to have if r gave less or couldn't be granted there: the
	// actor must have it, unconditionally, as those holders may.
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
			if missing, ok := a.mayGrant(au, au.under(t, ""), t, *r, "", seen); !ok {
				reason := cs.refusal("define "+string(r.ID), missing, fmt.Sprintf("the actor can't define %s, which %s lists, without the power to grant it on a %s", r.ID, id, t))
				return authority{}, cmp.Or(cs.failed(), error(&DeniedError{Permission: missing, Scope: scope, Reason: reason}))
			}
		}
	}
	if err := cs.failed(); err != nil {
		return authority{}, err
	}
	return au, nil
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
	return handingOut(a.current(roles)), err
}

// handingOut marks privileged each role that lists a privileged one, directly or through others,
// however that one became so: redefined since the lister was, or by a catalog change.
func handingOut(roles []RoleDefinition) []RoleDefinition {
	listers := map[Role][]int{}
	var next []Role
	for i, r := range roles {
		for _, id := range r.GrantableRoles {
			listers[id] = append(listers[id], i)
		}
		if r.Privileged {
			next = append(next, r.ID)
		}
	}
	for len(next) > 0 {
		id := next[len(next)-1]
		next = next[:len(next)-1]
		for _, i := range listers[id] {
			if !roles[i].Privileged {
				roles[i].Privileged = true
				next = append(next, roles[i].ID)
			}
		}
	}
	return roles
}

// current reads stored definitions as the catalog has them now, so a catalog change binds
// custom roles defined before it: they give only permissions and types the catalog still has,
// are public only while every permission they give is one an unprivileged role gives, and are
// privileged when they give or list what privileged roles do. The stored flag counts for
// nothing: it can stand for what a role it lists was, or for a catalog since changed.
func (a *Authorizer) current(roles []RoleDefinition) []RoleDefinition {
	for i, r := range roles {
		r.Permissions = slices.DeleteFunc(r.Permissions, func(p Permission) bool { return !a.permissions[p] })
		r.ResourceTypes = slices.DeleteFunc(r.ResourceTypes, func(t string) bool { return !a.types[t] })
		r.Public = r.Public && !a.privileged(r) && !r.managesAccess()
		r.Privileged = a.privileged(r) || a.listsPrivileged(r)
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
// counts where every custom role of the tenant is read (handingOut).
func (a *Authorizer) listsPrivileged(r RoleDefinition) bool {
	return slices.ContainsFunc(r.GrantableRoles, func(id Role) bool { return a.roles[id].Privileged })
}

// Roles lists the roles that can be granted on a scope type in a tenant: the built-in ones in
// catalog order, then the tenant's custom ones by id.
func (a *Authorizer) Roles(ctx context.Context, tenant, scopeType string) ([]RoleDefinition, error) {
	custom, err := a.CustomRoles(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return a.rolesIn(scopeType, custom), nil
}

func (a *Authorizer) rolesIn(scopeType string, custom []RoleDefinition) []RoleDefinition {
	roles := a.BuiltinRoles(scopeType)
	for _, r := range custom {
		if a.grantableOn(r, scopeType) {
			roles = append(roles, r)
		}
	}
	return roles
}
