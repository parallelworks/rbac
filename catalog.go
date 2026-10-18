package rbac

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RoleDefinition is a named set of permissions, grantable on certain resource types.
type RoleDefinition struct {
	ID          Role
	Name        string
	Description string
	Permissions []Permission
	// ResourceTypes are the types it can be granted on, besides containers and the tenant. A
	// grant on a container or the tenant applies to the resources of these types under it.
	ResourceTypes []string
	// Privileged marks administrative or root-level control, which a host may ask to confirm. A
	// role that changes access, granting, denying, defining roles or managing groups, is
	// privileged whatever this says, as account management is privileged (NIST SP 800-53 AC-2(7)).
	Privileged bool
	// Public lets the role be granted to the public, anyone signed in or not. A privileged role
	// or one that changes access can't be. A grant to the public gives nothing once its role
	// is no longer Public.
	Public bool
	// GrantableRoles, when set, are the only roles the role's `:grant` permissions let its
	// holders grant and revoke, and they need not hold those roles' permissions, so a role can
	// hand out narrower ones. When empty, its holders may grant any role whose permissions they
	// hold, and whose power to change grants they have too, and revoke any.
	GrantableRoles []Role
}

// Gives reports whether the role gives p.
func (r RoleDefinition) Gives(p Permission) bool { return slices.Contains(r.Permissions, p) }

// GrantableOn reports whether the role can be granted on resources of a type.
func (r RoleDefinition) GrantableOn(resourceType string) bool {
	return slices.Contains(r.ResourceTypes, resourceType)
}

func (r RoleDefinition) clone() RoleDefinition {
	r.Permissions = slices.Clone(r.Permissions)
	r.ResourceTypes = slices.Clone(r.ResourceTypes)
	r.GrantableRoles = slices.Clone(r.GrantableRoles)
	return r
}

// managesAccess reports whether the role gives any permission to change access.
func (r RoleDefinition) managesAccess() bool {
	return slices.ContainsFunc(r.Permissions, Permission.managesAccess)
}

var (
	typeName       = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	permissionName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}:[a-z][a-z0-9_-]{0,62}$`)
	roleID         = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

func validName(s string) bool { return typeName.MatchString(s) }

// Valid reports whether p is `type:verb` in lowercase letters, digits, hyphens and
// underscores.
func (p Permission) Valid() bool { return permissionName.MatchString(string(p)) }

// managesAccess reports whether p is a permission to change access: grants, the roles they
// give, the denies above them, or the groups they reach through.
func (p Permission) managesAccess() bool {
	_, verb := p.parts()
	return p.changesGrants() || p == DefineRoles || p == ManageGroups || p == ManagePrivilegedGroups || p == GroupMembers || verb == "deny"
}

// changesGrants reports whether p is `<type>:grant`, the only permission GrantableRoles limit.
func (p Permission) changesGrants() bool {
	_, verb := p.parts()
	return verb == "grant"
}

func (p Permission) parts() (resourceType, verb string) {
	resourceType, verb, _ = strings.Cut(string(p), ":")
	return resourceType, verb
}

// shape returns what is wrong with a role definition alone: its permissions, types and flags.
func shape(r RoleDefinition) []error {
	var errs []error
	if len(r.Permissions) == 0 {
		errs = append(errs, errors.New("gives no permissions"))
	}
	for _, p := range r.Permissions {
		if !p.Valid() {
			errs = append(errs, fmt.Errorf("permission %q is not `type:verb`", p))
		}
	}
	if len(r.ResourceTypes) == 0 {
		errs = append(errs, errors.New("can be granted on no resource type"))
	}
	for _, t := range r.ResourceTypes {
		if !validName(t) {
			errs = append(errs, fmt.Errorf("resource type %q is not valid", t))
		}
	}
	if r.Public && (r.Privileged || r.managesAccess()) {
		errs = append(errs, errors.New("a privileged role or one that changes access can't be public"))
	}
	if len(r.GrantableRoles) > 0 && !slices.ContainsFunc(r.Permissions, Permission.changesGrants) {
		errs = append(errs, errors.New("lists grantable roles but gives no `:grant` permission"))
	}
	return errs
}

// index checks a catalog and returns its roles by id, each its own copy.
func index(catalog []RoleDefinition) (map[Role]RoleDefinition, error) {
	var errs []error
	roles := make(map[Role]RoleDefinition, len(catalog))
	for _, r := range catalog {
		bad := func(err error) { errs = append(errs, fmt.Errorf("rbac: role %q: %w", r.ID, err)) }
		if !roleID.MatchString(string(r.ID)) || isCustom(r.ID) {
			bad(fmt.Errorf("id must be lowercase letters, digits, dots, hyphens and underscores, not starting %q", CustomPrefix))
		}
		if _, dup := roles[r.ID]; dup {
			bad(errors.New("listed twice"))
		}
		for _, err := range shape(r) {
			bad(err)
		}
		r = r.clone()
		r.Privileged = r.Privileged || r.managesAccess()
		roles[r.ID] = r
	}
	for _, r := range catalog {
		for _, g := range r.GrantableRoles {
			if _, ok := roles[g]; !ok {
				errs = append(errs, fmt.Errorf("rbac: role %q: grantable role %q is not in the catalog", r.ID, g))
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return roles, nil
}

// BuiltinRole returns a built-in role by id; Roles and CustomRoles read a tenant's own.
func (a *Authorizer) BuiltinRole(id Role) (RoleDefinition, bool) {
	r, ok := a.roles[id]
	if !ok {
		return RoleDefinition{}, false
	}
	return r.clone(), true
}

// BuiltinRoles lists the built-in roles that can be granted on a scope type, in catalog order: on
// a container type or the tenant, every role.
func (a *Authorizer) BuiltinRoles(scopeType string) []RoleDefinition {
	var roles []RoleDefinition
	for _, r := range a.cfg.Catalog {
		if a.grantableOn(r, scopeType) {
			roles = append(roles, r.clone())
		}
	}
	return roles
}

// reaching lists the scope types whose grants can reach a resource of a type: the tenant, the
// containers and the type itself. Searches keep to them, so a grant on another resource that a
// host's stored path lists above this one gives nothing, as it does in a check.
func (a *Authorizer) reaching(resourceType string) []string {
	types := append([]string{TenantScope, resourceType}, a.containerTypes...)
	slices.Sort(types)
	return slices.Compact(types)
}

// contains reports whether a scope type holds resources: a container type or the tenant.
func (a *Authorizer) contains(scopeType string) bool {
	return scopeType == TenantScope || a.containers[scopeType]
}

// grantableOn reports whether a role can be granted on a scope type: one of its own resource
// types, a container type, or the tenant.
func (a *Authorizer) grantableOn(r RoleDefinition, scopeType string) bool {
	return a.contains(scopeType) || r.GrantableOn(scopeType)
}

// giving lists the ids of the roles that give p on a resource type.
func (a *Authorizer) giving(p Permission, resourceType string) []string {
	var ids []string
	for _, r := range a.cfg.Catalog {
		if r.GrantableOn(resourceType) && r.Gives(p) {
			ids = append(ids, string(r.ID))
		}
	}
	return ids
}
