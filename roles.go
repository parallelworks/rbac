package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
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
	// sets are the built-in roles' permissions and types as sets, and customSets the custom ones'
	// gives has read, each made the first time it does, where a decision keeps them: a role can
	// give a thousand permissions, and a change asks of each it decides for each of its types.
	sets, customSets map[Role]roleSet
}

func (b book) role(id Role) (RoleDefinition, bool) {
	if r, ok := b.builtin[id]; ok {
		return r, true
	}
	r, ok := b.custom[id]
	return r, ok
}

// roleSet is a role's permissions and types as sets.
type roleSet struct {
	permissions map[Permission]bool
	types       map[string]bool
}

func setOf(r RoleDefinition) roleSet {
	readingEntries(len(r.Permissions) + len(r.ResourceTypes))
	s := roleSet{permissions: make(map[Permission]bool, len(r.Permissions)), types: make(map[string]bool, len(r.ResourceTypes))}
	for _, p := range r.Permissions {
		s.permissions[p] = true
	}
	for _, t := range r.ResourceTypes {
		s.types[t] = true
	}
	return s
}

func setsOf(roles map[Role]RoleDefinition) map[Role]roleSet {
	sets := make(map[Role]roleSet, len(roles))
	for id, r := range roles {
		sets[id] = setOf(r)
	}
	return sets
}

// gives reports whether role id, defined as def, gives p on a resource type.
func (b book) gives(id Role, def RoleDefinition, p Permission, resourceType string) bool {
	s, ok := b.sets[id]
	if _, builtin := b.builtin[id]; !builtin && b.customSets != nil {
		if s, ok = b.customSets[id]; !ok {
			s, ok = setOf(def), true
			b.customSets[id] = s
		}
	}
	if !ok {
		readingEntries(len(def.Permissions) + len(def.ResourceTypes))
		return def.GrantableOn(resourceType) && def.Gives(p)
	}
	readingEntries(1)
	return s.types[resourceType] && s.permissions[p]
}

// keepingSets is b keeping the custom roles' sets as gives makes them, for a decision that asks
// gives about them many times.
func (b book) keepingSets() book {
	if b.customSets == nil {
		b.customSets = map[Role]roleSet{}
	}
	return b
}

// readingEntries runs as a decision reads n entries: of a role's permissions and types, to make
// sets of them, which each later read takes one of, to look for one without them, or to compare two
// definitions, or one of what the constraints answered. A test counts the work deciding many roles
// takes.
var readingEntries = func(n int) {}

func isCustom(id Role) bool { return strings.HasPrefix(string(id), CustomPrefix) }

// book reads, on q, the definitions of the custom roles among ids in a tenant. Without one
// among them it reads nothing.
func (a *Authorizer) book(ctx context.Context, q DB, tenant string, ids []Role) (book, error) {
	b := a.builtinBook()
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

// tenantBook resolves ids with every custom role of the tenant when one is among them, as a
// role's GrantableRoles can name any.
func (a *Authorizer) tenantBook(ctx context.Context, q DB, tenant string, ids []Role) (book, error) {
	if !slices.ContainsFunc(ids, isCustom) {
		return a.builtinBook(), nil
	}
	custom, err := a.customRoles(ctx, q, tenant)
	if err != nil {
		return book{}, err
	}
	return a.bookOf(custom), nil
}

// builtinBook resolves the built-in roles.
func (a *Authorizer) builtinBook() book { return book{builtin: a.roles, sets: a.roleSets} }

// bookOf resolves the built-in roles and the custom ones given.
func (a *Authorizer) bookOf(custom []RoleDefinition) book {
	b := a.builtinBook()
	b.custom = make(map[Role]RoleDefinition, len(custom))
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
		var id, name, description string
		var perms, types, grantable []string
		var privileged, public bool
		err := row.Scan(&id, &name, &description, &perms, &types, &privileged, &public, &grantable)
		return roleFrom(id, name, description, perms, types, privileged, public, grantable), err
	})
}

// roleFrom is a custom role as its row holds it.
func roleFrom(id, name, description string, perms, types []string, privileged, public bool, grantable []string) RoleDefinition {
	r := RoleDefinition{ID: Role(id), Name: name, Description: description, ResourceTypes: types, Privileged: privileged, Public: public}
	for _, p := range perms {
		r.Permissions = append(r.Permissions, Permission(p))
	}
	for _, g := range grantable {
		r.GrantableRoles = append(r.GrantableRoles, Role(g))
	}
	return r
}

// catalogSQL names the array arguments that Authorizer.publicArgs and Authorizer.catalogArgs fill:
// the catalog's permissions, its types and the pairs of them a role that isn't privileged gives.
type catalogSQL struct{ perms, types, pairs string }

// givingSQL is SQL for the ids of the roles that give perm on a resource type in a tenant: the
// built-in ones in the array argument builtin, and with custom the tenant's custom ones, read in
// the same statement, of them only those only keeps, if any (publicOnly, privilegedOnly), so a
// catalog change reaches searches as it reaches checks.
func givingSQL(builtin, tenant, perm, resourceType string, custom bool, only string) string {
	// Without custom the subquery stays, constant false, so the statement's arguments are the
	// same and PostgreSQL plans it away.
	return fmt.Sprintf(`(%s::text[] || ARRAY(SELECT cr.id FROM rbac_roles cr WHERE %t AND cr.tenant = %s::text
		AND %s::text = ANY(cr.permissions) AND %s::text = ANY(cr.resource_types)%s))`, builtin, custom, tenant, perm, resourceType, only)
}

// publicOnly keeps the custom roles public as Authorizer.current reads them: marked Public, and of
// the permissions and types the catalog has, giving none that changes access and each only where
// a role that isn't privileged gives it.
func publicOnly(c catalogSQL) string {
	return fmt.Sprintf(` AND cr.public AND NOT EXISTS (SELECT FROM unnest(cr.permissions) cp, unnest(cr.resource_types) ct
		WHERE cp = ANY(%s::text[]) AND ct = ANY(%s::text[]) AND cp || ' ' || ct <> ALL(%s::text[]))`, c.perms, c.types, c.pairs)
}

// privilegedOnly keeps the custom roles privileged as Authorizer.current reads them: of the
// permissions and types the catalog has, giving one where only privileged roles give it, as every
// permission that changes access is.
func privilegedOnly(c catalogSQL) string {
	return fmt.Sprintf(` AND EXISTS (SELECT FROM unnest(cr.permissions) cp, unnest(cr.resource_types) ct
		WHERE cp = ANY(%s::text[]) AND ct = ANY(%s::text[]) AND cp || ' ' || ct <> ALL(%s::text[]))`, c.perms, c.types, c.pairs)
}

// publicArgs are the arguments of givingSQL's public check: the catalog's permissions, its types
// and the pairs of them a public role may give. They are NULL where the check can't matter, so a
// search doesn't send them: with no custom role in it, or where no grant to the public gives p,
// as Filter and Reachable then read none and Holders drops the public.
func (a *Authorizer) publicArgs(p Permission, resourceType string, custom bool) []any {
	if !a.publicGives(p, resourceType) {
		return []any{nil, nil, nil}
	}
	return a.catalogArgs(custom)
}

// catalogArgs are the arguments of privilegedOnly, NULL without custom, where it can't matter.
func (a *Authorizer) catalogArgs(custom bool) []any {
	if !custom {
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
	// Before the checks below, which read each permission against each type.
	if len(r.Permissions) > MaxRoleEntries || len(r.ResourceTypes) > MaxRoleEntries {
		return fmt.Errorf("%w: role %q gives more than %d permissions or is for more than %d resource types", ErrInvalid, r.ID, MaxRoleEntries, MaxRoleEntries)
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
	if p, q, two := twoExclusive(a.labels, r.Permissions); two {
		errs = append(errs, fmt.Errorf("permissions %q and %q are exclusive, so it would give neither", p, q))
	}
	// As for a built-in role (indexLabels): a value given on another scope would read as held
	// nowhere, or be mistaken for a permission on that scope.
	if a.givesLabels(r) && !slices.Equal(r.ResourceTypes, []string{TenantScope}) {
		errs = append(errs, errors.New("gives label values or a power to release, so it is for the tenant alone"))
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
// a permission on a type only privileged built-in roles give it on, or changes access, as one
// listing grantable roles does, whatever r.Privileged says, so a role read and saved back keeps
// no flag it no longer earns.
//
// The actor needs DefineRoles on the tenant, not removed by a constraint (a condition on that
// right reads the tenant as a resource with no attributes), and every permission
// the role gives there, for each type it is for, as granting it on the tenant for good would
// need: a definition never ends, so what the actor holds only until a time can't stand in. Each
// of its GrantableRoles must be a role the actor may grant on the tenant. Replacing a role
// another custom role lists needs the power to grant it as defined wherever that one lists it.
// Replacing one so that its grants give something else changes them, so a constraint that stops
// changes to grants where it can be granted, or a deny that removes the actor's power to change
// them there or on the path of a scope they are on, stops it, as it stops DeleteRole and Apply
// there; so does, where they will give more, a deny on that path that removes a permission the
// role gives, which the actor would hand on there. The scopes are as Config.ResourceOf gives them.
// A role another change redefined or created while this one waited for the tenant is refused, to
// be tried again: the constraints were asked about it as it was, as is one granted meanwhile on a
// scope the host wasn't asked about. One deleted meanwhile is created, as its grants went with it.
//
// Redefining a role so that its grants give more, or so that it becomes privileged, changes what
// grants already made give: Config.ValidateGrant is asked about each of its grants and
// eligibilities in force that gives anything as the role will be (ViaRedefinition), and refusing
// any refuses the redefinition, as granting the role so would be refused. Narrowing a role asks
// about none. One made while this waited for the tenant refuses it too, to be tried again, as the
// host wasn't asked about it. Redefining it to give more label values or powers to release is
// refused as invalid where a condition of its grants on the tenant that reads the action, which
// counts once for each (Condition), would leave theirs costing more than a check may spend, as
// granting it so would be refused.
func (a *Authorizer) SetRole(ctx context.Context, actor Subject, tenant string, r RoleDefinition) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "SetRole")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := tenantResource(tenant)
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
	change := fmt.Sprintf("changing what %s's grants give", r.ID)
	var reach roleReach
	if existed && !sameAccess(checked, r) {
		// Its grants are on scopes of the types it is for, and on those it was for before and is
		// for again, whose grants it brings back.
		types := slices.Concat(checked.ResourceTypes, r.ResourceTypes)
		if err := a.changesStopped(ctx, actor, tenant, types, change); err != nil {
			return err
		}
		if err := a.changesDenied(au, tenant, types, change); err != nil {
			return err
		}
		// Narrowed, it only takes access away, as deleting it does.
		var grows *RoleDefinition
		if givesMore(checked, r) {
			grows = &r
		}
		if reach, err = a.roleReachOf(ctx, actor, au, tenant, r.ID, grows, change); err != nil {
			return err
		}
	}
	asked, stand, err := a.revalidate(ctx, actor, tenant, au.roles.custom, r)
	if err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, "SetRole", func(tx pgx.Tx) (ChangeEvent, error) {
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
		// Again on the denies read under the lock, which a deny set meanwhile is among, and on the
		// scopes its grants are on now, which roleReachOf checked as they were.
		if ok && !sameAccess(old, r) {
			if err := a.changesDenied(au, tenant, slices.Concat(old.ResourceTypes, r.ResourceTypes), change); err != nil {
				return ChangeEvent{}, err
			}
			if err := a.stillReaches(ctx, tx, actor, au, tenant, r.ID, reach, change); err != nil {
				return ChangeEvent{}, err
			}
		}
		// Privileged as the roles that give its permissions on its types are, or as changing
		// access is, so a host that confirms privileged grants asks about one that gives root
		// however it was defined. Derived as a read derives it.
		after, widened := a.redefining(au.roles.custom, r)
		r.Privileged = after.Privileged
		if was := au.roles.custom[r.ID]; r.Privileged && !was.Privileged {
			if err := heldByMembers(ctx, tx, tenant, r.ID, a.cfg.Now()); err != nil {
				return ChangeEvent{}, err
			}
		}
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
		// The holders asked about, not need's: a grant revoked or ended meanwhile is no conflict.
		if err := a.stillStanding(ctx, tx, tenant, stand); err != nil {
			return ChangeEvent{}, err
		}
		others := len(au.roles.custom)
		if ok {
			others--
		}
		if others >= MaxCustomRoles {
			return ChangeEvent{}, fmt.Errorf("%w: a tenant has at most %d custom roles", ErrInvalid, MaxCustomRoles)
		}
		// A condition of its grants that reads the action counts once for each label value and power
		// to release they give (conditionsIn), so giving more can leave a bucket on the tenant past
		// what a check may spend, as no grant stored there could.
		var buckets []conditionBucket
		var before map[conditionBucket]map[string]int
		if a.givesMoreLabels(old, after) {
			if buckets, err = a.tenantBuckets(ctx, tx, tenant, r.ID); err != nil {
				return ChangeEvent{}, err
			}
			if before, err = a.conditionsIn(ctx, tx, tenant, buckets); err != nil {
				return ChangeEvent{}, err
			}
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
		if err := a.conditionsBounded(ctx, tx, tenant, buckets, before); err != nil {
			return ChangeEvent{}, err
		}
		return ChangeEvent{Roles: []RoleDefinition{r}}, nil
	})
}

// givesMoreLabels reports whether a role defined as now gives a label value or a power to release
// that it didn't as was.
func (a *Authorizer) givesMoreLabels(was, now RoleDefinition) bool {
	return slices.ContainsFunc(now.Permissions, func(p Permission) bool { return a.labelPermission(p) && !slices.Contains(was.Permissions, p) })
}

// tenantBuckets reads, on q, the buckets of a custom role's conditional grants in force on the
// tenant, where what they give of label values is held.
func (a *Authorizer) tenantBuckets(ctx context.Context, q DB, tenant string, id Role) ([]conditionBucket, error) {
	// The LIKE matches the partial index on custom roles' grants.
	rows, err := q.Query(ctx, `SELECT DISTINCT principal_kind, principal_id, source FROM rbac_grants
		WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%' AND scope = $3 AND conditional
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY 1, 2, 3`, tenant, string(id), TenantRoot(tenant).Key(), a.cfg.Now())
	if err != nil {
		return nil, err
	}
	seen := map[conditionBucket]bool{}
	var buckets []conditionBucket
	var p Principal
	var source string
	_, err = pgx.ForEachRow(rows, []any{&p.Kind, &p.ID, &source}, func() error {
		if b := a.bucketOf(TenantRoot(tenant), p, source); !seen[b] {
			seen[b] = true
			buckets = append(buckets, b)
		}
		return nil
	})
	return buckets, err
}

// DeleteRole deletes a tenant's custom role and every grant and eligibility of it, as actor, who
// needs DefineRoles on the tenant. It refuses a role another custom role lists in
// GrantableRoles: redefine that one first, or a role later defined with the id would be handed
// out through it. It refuses a role granted from a source the host owns (Config.Sources), whose
// grants only the host removes. Deleting it revokes its grants, so a constraint or deny that stops
// the actor changing grants where it can be granted, or a deny on the path of a scope it is
// granted on that removes the actor's power to change grants there, stops it, as in SetRole.
// Deleting a role that doesn't exist does nothing; one changed while the deletion waited for the
// tenant is refused, as in SetRole.
func (a *Authorizer) DeleteRole(ctx context.Context, actor Subject, tenant string, id Role) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "DeleteRole")
	if !validID(tenant) || !isCustom(id) || !validText(string(id)) {
		return fmt.Errorf("%w: only a tenant's custom role can be deleted", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := tenantResource(tenant)
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
	change := "revoking " + string(id)
	var reach roleReach
	if existed {
		if err := a.changesStopped(ctx, actor, tenant, checked.ResourceTypes, change); err != nil {
			return err
		}
		if err := a.changesDenied(au, tenant, checked.ResourceTypes, change); err != nil {
			return err
		}
		if reach, err = a.roleReachOf(ctx, actor, au, tenant, id, nil, change); err != nil {
			return err
		}
	}
	return a.inTx(ctx, tenant, actor.Principal, "DeleteRole", func(tx pgx.Tx) (ChangeEvent, error) {
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
			if err := a.changesDenied(au, tenant, checked.ResourceTypes, change); err != nil {
				return ChangeEvent{}, err
			}
			if err := a.stillReaches(ctx, tx, actor, au, tenant, id, reach, change); err != nil {
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
		// Deleting it would revoke the host's own grants of it, which only the host removes. Expired
		// ones give nothing and Grants doesn't list them, so the host has none to remove.
		if len(a.owned) > 0 {
			var source string
			err = tx.QueryRow(ctx, `SELECT source FROM rbac_grants WHERE tenant = $1 AND `+ofRole+` AND source = ANY($3::text[])
				AND (expires_at IS NULL OR expires_at > $4) LIMIT 1`,
				tenant, id, slices.Sorted(maps.Keys(a.owned)), a.cfg.Now()).Scan(&source)
			switch {
			case err == nil:
				return ChangeEvent{}, fmt.Errorf("%w: role %q is granted from %s, whose grants only the host removes (DeleteGrants)", ErrInvalid, id, source)
			case !errors.Is(err, pgx.ErrNoRows):
				return ChangeEvent{}, err
			}
		}
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

// redefining returns r as checks will read it once it replaces its definition among custom, as
// read, and, when its grants will give more than they gave, r as the one role that widens. A
// copy, as current trims it.
func (a *Authorizer) redefining(custom map[Role]RoleDefinition, r RoleDefinition) (after RoleDefinition, widened map[Role]RoleDefinition) {
	after = a.current([]RoleDefinition{r.clone()})[0]
	if widens(custom[r.ID], after) {
		return after, map[Role]RoleDefinition{r.ID: after}
	}
	return after, nil
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
	// Past a few, looked up in a set: a role can give a thousand permissions.
	if len(of) <= 16 {
		readingEntries(len(xs) * len(of))
		return !slices.ContainsFunc(xs, func(x T) bool { return !slices.Contains(of, x) })
	}
	readingEntries(len(xs) + len(of))
	in := make(map[T]bool, len(of))
	for _, x := range of {
		in[x] = true
	}
	return !slices.ContainsFunc(xs, func(x T) bool { return !in[x] })
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
// as was: what it gives, or newly privileged, as a catalog change can make it.
func widens(was, now RoleDefinition) bool {
	return givesMore(was, now) || now.Privileged && !was.Privileged
}

// revalidation is a grant or eligibility the host is asked about again: of a role a redefinition
// widens, as the role will be, or a group's that a member joining it, or a group in it, gains.
type revalidation struct {
	scope   Scope
	binding Binding
	role    RoleDefinition
	// eligibility is set on an eligibility's, which a change to members hands on as one.
	eligibility bool
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
		// A privileged role gives nothing through the tenant's members or the public.
		weak := def.Privileged && b.Principal.broad()
		if gives && !weak && a.known(tenant, b.Principal) && a.grantableOn(def, scope.Type) {
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
// the role as it asked, and the standing of their holders. custom are the tenant's custom roles,
// as read.
func (a *Authorizer) revalidate(ctx context.Context, actor Subject, tenant string, custom map[Role]RoleDefinition, r RoleDefinition) (map[revalidated]RoleDefinition, standing, error) {
	_, widened := a.redefining(custom, r)
	need, err := a.revalidations(ctx, a.db, tenant, widened)
	if err != nil {
		return nil, standing{}, err
	}
	holders := make([]Principal, len(need))
	for i, v := range need {
		holders[i] = v.binding.Principal
	}
	stand, err := a.stand(ctx, a.db, tenant, holders)
	if err != nil {
		return nil, standing{}, err
	}
	roles := a.builtinBook()
	roles.custom = widened
	asked := make(map[revalidated]RoleDefinition, len(need))
	var refused []error
	for _, v := range need {
		bad, err := a.allowed(ctx, roles, actor, ViaRedefinition, tenant, v.scope, v.binding)
		if err != nil {
			return nil, standing{}, err
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
	return asked, stand, errors.Join(refused...)
}

// roleReach is what a change to what a custom role's grants and eligibilities give, or deleting
// the role, checked of the scopes they are on before its transaction, which stillReaches checks
// again under the tenant's lock: each scope as Config.ResourceOf gives it, where a deny or a label
// needed it, the role as it will be where they will give more, and their labels.
type roleReach struct {
	on     map[Scope]Resource
	grows  *RoleDefinition
	labels labeling
}

// roleReachOf refuses changing what a custom role's grants and eligibilities give, or revoking
// them, where Apply would refuse the actor changing them: on a scope they are on, as
// Config.ResourceOf gives it, where a deny on its path removes the actor's power to change grants
// there or, with grows, the role as it will be when they will give more, a permission it gives
// (scopesDenied), or where its label refuses the actor (labelsHeld). Only a deny on a scope other
// than the tenant can remove more there than the tenant's, which mayDefine and changesDenied check,
// so only where one binds the actor, or a label could refuse it, is the host asked about the
// scopes. Without grows, as for deleting or narrowing the role, which only takes access away, a
// scope the host no longer has (ErrNotFound) is read as stored, with no containers or label. au is
// the actor's authority on the tenant, which mayDefine checked the role on.
func (a *Authorizer) roleReachOf(ctx context.Context, actor Subject, au authority, tenant string, id Role, grows *RoleDefinition, change string) (roleReach, error) {
	reach := roleReach{grows: grows}
	scopes, err := a.roleScopes(ctx, a.db, tenant, id)
	if err != nil {
		return roleReach{}, err
	}
	denied := false
	if len(scopes) > 0 {
		if denied, err = a.deniedBelow(ctx, a.db, tenant, actor); err != nil {
			return roleReach{}, err
		}
	}
	// Granted nowhere yet, it has no label to clear, so one granted while the change waits is
	// refused, to be tried again.
	removing := grows == nil
	if reach.labels, err = a.labelsAsked(ctx, actor, tenant, removing && len(scopes) > 0); err != nil {
		return roleReach{}, err
	}
	if !denied && !reach.labels.asks() {
		return reach, nil
	}
	reach.on = make(map[Scope]Resource, len(scopes))
	on := make([]Resource, 0, len(scopes))
	for _, s := range scopes {
		r, err := a.resourceOf(ctx, tenant, s)
		switch {
		case removing && errors.Is(err, ErrNotFound):
			r = Resource{Tenant: tenant, Type: s.Type, ID: s.ID}
		case err != nil:
			return roleReach{}, err
		}
		reach.on[s] = r
		on = append(on, r)
	}
	if denied {
		if err := a.scopesDenied(ctx, a.db, actor, au, tenant, id, on, grows, change); err != nil {
			return roleReach{}, err
		}
	}
	if reach.labels.asks() {
		for _, r := range on {
			if r.Labels.asks() {
				reach.labels.labeled = append(reach.labels.labeled, r)
			}
		}
	}
	return reach, a.labelsHeld(ctx, a.db, reach.labels)
}

// stillReaches checks again, under the tenant's lock, what roleReachOf checked, on the scopes a
// custom role's grants and eligibilities are on now: the denies on their paths and the actor's
// label values, read again, as one set or revoked meanwhile. Where a deny below the tenant now
// binds the actor, or a label asks, a scope roleReachOf didn't ask the host about, as one the role
// was granted on while the change waited, refuses the change, to be tried again.
func (a *Authorizer) stillReaches(ctx context.Context, tx pgx.Tx, actor Subject, au authority, tenant string, id Role, checked roleReach, change string) error {
	scopes, err := a.roleScopes(ctx, tx, tenant, id)
	if err != nil {
		return err
	}
	denied := false
	if len(scopes) > 0 {
		if denied, err = a.deniedBelow(ctx, tx, tenant, actor); err != nil {
			return err
		}
	}
	if denied || checked.labels.asks() {
		on := make([]Resource, 0, len(scopes))
		for _, s := range scopes {
			r, ok := checked.on[s]
			if !ok {
				return fmt.Errorf("%w: %s is granted on %s, which this change didn't check, as a grant or a deny made while it waited; try again", ErrConflict, id, s.Key())
			}
			on = append(on, r)
		}
		if denied {
			if err := a.scopesDenied(ctx, tx, actor, au, tenant, id, on, checked.grows, change); err != nil {
				return err
			}
		}
	}
	return a.stillLabeled(ctx, tx, checked.labels)
}

// deniedBelow reports, reading on q, whether a deny on a scope other than the tenant binds the
// actor, as heldOrDenied reads the denies on a path.
func (a *Authorizer) deniedBelow(ctx context.Context, q DB, tenant string, actor Subject) (bool, error) {
	var denied bool
	err := q.QueryRow(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$3")+`
		SELECT EXISTS (SELECT FROM rbac_denies WHERE tenant = $1 AND scope_type <> $4
		  AND principals && ARRAY(SELECT k FROM bound) AND NOT exempt && ARRAY(SELECT k FROM exempted))`,
		tenant, actor.identityKey(), a.cfg.Now(), TenantScope).Scan(&denied)
	return denied, err
}

// scopesDenied returns why a deny stops the actor changing a custom role's grants and eligibilities
// on scopes on, as it would stop Apply there: one on a scope's path that removes the actor's power
// to change grants there, or with grows, the role as it will be when they will give more, one that
// removes there a permission it gives, which the actor would hand on there. au is the actor's
// authority on the tenant, which mayDefine checked the role on.
func (a *Authorizer) scopesDenied(ctx context.Context, q DB, actor Subject, au authority, tenant string, id Role, on []Resource, grows *RoleDefinition, change string) error {
	if len(on) == 0 {
		return nil
	}
	aus, err := a.authorities(ctx, q, actor, on, []Role{id})
	if err != nil {
		return err
	}
	for i, at := range aus {
		if manage := GrantPermission(on[i].Type); at.handsOn(manage) {
			return &DeniedError{Permission: manage, Scope: on[i].Scope(), Reason: "removed by a deny, which stops " + change}
		}
	}
	if grows == nil {
		return nil
	}
	// Each scope that what the actor holds and the denies on its path can't tell apart from another
	// removes what that one does, so a role granted on thousands of resources is decided against a
	// few.
	var distinct []int
	seen := map[string]bool{}
	for i, at := range aus {
		if k := a.alike(at, on[i]); !seen[k] {
			seen[k] = true
			distinct = append(distinct, i)
		}
	}
	removedOn := func(p Permission) (Scope, bool) {
		for _, i := range distinct {
			if aus[i].handsOn(p) {
				return on[i].Scope(), true
			}
		}
		return Scope{}, false
	}
	// What the role gives, checked across the tenant as mayDefine did, under the denies on every
	// scope too: what one removes there, the actor can't hand on there.
	there := au
	there.handsOn = orDenied(au.handsOn, func(p Permission) bool { _, removed := removedOn(p); return removed })
	p, ok := a.holdsRole(there, *grows, grows.ResourceTypes, "", time.Time{}, newChecked())
	if ok {
		return au.constrained.failed()
	}
	scope, removed := removedOn(p)
	if !removed {
		scope = TenantRoot(tenant)
	}
	reason := fmt.Sprintf("removed by a deny there, which stops %s, as the actor can't hand %s on there", change, p)
	return cmp.Or(au.constrained.failed(), error(&DeniedError{Permission: p, Scope: scope, Reason: reason}))
}

// alike is the same for two scopes whose authorities, on and another, remove the same from what the
// actor hands on: the same grants it holds on their paths, and the same denies, and where one of
// those has a condition, which can read a resource, the same scope, but on containers, where what
// the actor hands on reaches resources the condition can't read.
func (a *Authorizer) alike(on authority, r Resource) string {
	var b strings.Builder
	for _, h := range on.held {
		b.WriteString(h.ID + " ")
	}
	b.WriteString("|")
	conditional := false
	for _, d := range on.denials {
		b.WriteString(d.scope + " " + d.id + " ")
		conditional = conditional || d.condition != ""
	}
	if conditional && !a.contains(r.Type) {
		b.WriteString("|" + r.Scope().Key())
	}
	return b.String()
}

// labeling is what roleReachOf checked of the labels of the scopes a custom role's grants and
// eligibilities are on: the resources whose label asks for values, and the constraints' answers
// about the actor's, which stillLabeled reads back; or that the actor's satisfy every label,
// cleared.
type labeling struct {
	labeled []Resource
	cs      *constrained
	cleared bool
}

// asks reports whether the labels of the scopes can refuse the change.
func (l labeling) asks() bool { return l.cs != nil && !l.cleared }

// labelsAsked is what a label of a scope a custom role's grants and eligibilities are on asks of a
// change to what they give, or revoking them, as Apply's label check asks of changing grants there:
// nothing without labels, and with removing, as for deleting or narrowing the role, nothing where
// the actor's label values satisfy every label, as ChangeMembers asks nothing about a scope a
// removal alone reaches, so the host isn't asked about the scopes. Labels are the host's, so they
// are read before the change's transaction, and the actor's values again in it (stillLabeled).
func (a *Authorizer) labelsAsked(ctx context.Context, actor Subject, tenant string, removing bool) (labeling, error) {
	if len(a.labels) == 0 {
		return labeling{}, nil
	}
	l := labeling{cs: a.constrain(ctx, actor, tenantResource(tenant))}
	if !removing {
		return l, nil
	}
	var err error
	l.cleared, err = a.clearsAll(ctx, a.db, l.cs)
	return l, err
}

// labelsHeld refuses, reading the actor's label values on q, a change to a role granted on a scope
// whose label they don't satisfy.
func (a *Authorizer) labelsHeld(ctx context.Context, q DB, l labeling) error {
	if !l.asks() {
		return nil
	}
	clearance := a.labelCheck(ctx, q, l.cs)
	for _, on := range l.labeled {
		if err := clearance(on, GrantPermission(on.Type)); err != nil {
			return err
		}
	}
	return nil
}

// stillLabeled refuses, under the tenant's lock, a change roleReachOf checked whose actor no longer
// holds the values a label asks for, as one revoked meanwhile, or, where they satisfied every
// label, no longer does.
func (a *Authorizer) stillLabeled(ctx context.Context, tx pgx.Tx, checked labeling) error {
	if checked.cs == nil {
		return nil
	}
	checked.cs.seal()
	if checked.cleared {
		return a.stillClearsAll(ctx, tx, checked.cs)
	}
	return a.labelsHeld(ctx, tx, checked)
}

// roleScopes reads, on q, the scopes a custom role's grants and eligibilities in force are on,
// sorted.
func (a *Authorizer) roleScopes(ctx context.Context, q DB, tenant string, id Role) ([]Scope, error) {
	// The LIKE matches the partial indexes on custom roles' grants and eligibilities. Those ended
	// give nothing, so changing what they give changes no access.
	rows, err := q.Query(ctx, `
		SELECT scope_type, scope_id FROM rbac_grants WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%'
		  AND (expires_at IS NULL OR expires_at > $3)
		UNION
		SELECT scope_type, scope_id FROM rbac_eligibilities WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%'
		  AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY 1, 2`, tenant, string(id), a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Scope])
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
	seen := newChecked()
	// A definition never ends, so what the actor holds only until a time can't stand in.
	if p, ok := a.holdsRole(au, *r, r.ResourceTypes, "", time.Time{}, seen); !ok {
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
			if missing, ok := a.mayGrant(au, au.under(t, "", time.Time{}), t, *r, "", time.Time{}, seen); !ok {
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
	if !validID(tenant) {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
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
// privileged when they give what only privileged roles do, or change access, as every role that
// lists grantable roles does. The stored flag counts for nothing: it can stand for a catalog
// since changed.
func (a *Authorizer) current(roles []RoleDefinition) []RoleDefinition {
	for i, r := range roles {
		r.Permissions = slices.DeleteFunc(r.Permissions, func(p Permission) bool { return !a.permissions[p] })
		r.ResourceTypes = slices.DeleteFunc(r.ResourceTypes, func(t string) bool { return !a.types[t] })
		r.Public = r.Public && !a.privileged(r) && !r.managesAccess()
		r.Privileged = a.privileged(r) || r.managesAccess()
		roles[i] = r
	}
	return roles
}

// customGives reports whether a custom role can give p on a resource type: only a permission
// and a type the catalog has, so a search skips custom roles for any other.
func (a *Authorizer) customGives(p Permission, resourceType string) bool {
	return a.permissions[p] && a.types[resourceType]
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
