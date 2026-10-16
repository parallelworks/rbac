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
	// Privileged marks administrative or root-level control, which a host may ask to confirm.
	Privileged bool
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
	return r
}

// managesAccess reports whether the role gives any permission to change grants.
func (r RoleDefinition) managesAccess() bool {
	return slices.ContainsFunc(r.Permissions, func(p Permission) bool {
		_, verb := p.parts()
		return verb == "grant"
	})
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

func (p Permission) parts() (resourceType, verb string) {
	resourceType, verb, _ = strings.Cut(string(p), ":")
	return resourceType, verb
}

// index checks a catalog and returns its roles by id, each its own copy.
func index(catalog []RoleDefinition) (map[Role]RoleDefinition, error) {
	var errs []error
	roles := make(map[Role]RoleDefinition, len(catalog))
	for _, r := range catalog {
		bad := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("rbac: role %q: "+format, append([]any{r.ID}, args...)...))
		}
		if !roleID.MatchString(string(r.ID)) {
			bad("id must be lowercase letters, digits, dots, hyphens and underscores")
		}
		if _, dup := roles[r.ID]; dup {
			bad("listed twice")
		}
		if len(r.Permissions) == 0 {
			bad("gives no permissions")
		}
		for _, p := range r.Permissions {
			if !p.Valid() {
				bad("permission %q is not `type:verb`", p)
			}
		}
		if len(r.ResourceTypes) == 0 {
			bad("can be granted on no resource type")
		}
		for _, t := range r.ResourceTypes {
			if !validName(t) {
				bad("resource type %q is not valid", t)
			}
		}
		roles[r.ID] = r.clone()
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return roles, nil
}

// Role returns a built-in role by id.
func (a *Authorizer) Role(id Role) (RoleDefinition, bool) {
	r, ok := a.roles[id]
	if !ok {
		return RoleDefinition{}, false
	}
	return r.clone(), true
}

// Roles lists the roles that can be granted on a scope type, in catalog order: on a container
// type or the tenant, every role.
func (a *Authorizer) Roles(scopeType string) []RoleDefinition {
	var roles []RoleDefinition
	for _, r := range a.cfg.Catalog {
		if a.grantableOn(r, scopeType) {
			roles = append(roles, r.clone())
		}
	}
	return roles
}

// contains reports whether a scope type holds resources: a container type or the tenant.
func (a *Authorizer) contains(scopeType string) bool {
	return scopeType == TenantScope || a.containers[scopeType]
}

// ownerHolds reports whether owning a resource of a type gives p: every permission a role
// gives on the type, except changing the grants on a container or the tenant, which reach
// what its owner doesn't own.
func (a *Authorizer) ownerHolds(resourceType string, p Permission) bool {
	if a.contains(resourceType) && p == GrantPermission(resourceType) {
		return false
	}
	return slices.ContainsFunc(a.cfg.Catalog, func(r RoleDefinition) bool {
		return r.GrantableOn(resourceType) && r.Gives(p)
	})
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

// permissionsOn lists every permission some role gives on a resource type: what its owner
// holds.
func (a *Authorizer) permissionsOn(resourceType string) []Permission {
	var all []Permission
	for _, r := range a.cfg.Catalog {
		if !r.GrantableOn(resourceType) {
			continue
		}
		for _, p := range r.Permissions {
			if !slices.Contains(all, p) {
				all = append(all, p)
			}
		}
	}
	return all
}
