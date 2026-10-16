// Package rbac is role-based access control on PostgreSQL: Core RBAC with scoped role
// assignments. A role is a set of permissions; a grant gives one role to a user, a group or
// everyone in a tenant, on a resource, a container above resources or the whole tenant, and
// applies to everything under that scope.
//
// The host keeps users, groups, resources and their hierarchy and passes them in: a [Subject]
// is a user and every group they are in, and a [Resource] carries its owner and its
// ancestors. The package keeps the grants, decides ([Authorizer.Authorize]), lists
// ([Authorizer.Filter], [Authorizer.Reachable]) and changes grants with escalation checks
// ([Authorizer.Apply]).
//
// A check reads the grants as they are: there is no cache. Read a resource's ancestors and a
// subject's groups no earlier than the content they protect.
package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Permission is one thing that can be done to one type of resource, `type:verb`, such as
// `cluster:login`. `<type>:grant` is the permission to change grants on a scope of that type.
type Permission string

// GrantPermission is the permission to change grants on scopes of a type.
func GrantPermission(scopeType string) Permission { return Permission(scopeType + ":grant") }

// Role is a role definition's id. Grants store it, so never rename one.
type Role string

// TenantScope is the type of the scope that covers a whole tenant; its id is the tenant's.
const TenantScope = "tenant"

// Scope is what a grant applies to: a resource, a container above resources, or the tenant.
type Scope struct {
	Type string
	ID   string
}

// TenantRoot is the scope that covers every resource in a tenant.
func TenantRoot(tenant string) Scope { return Scope{Type: TenantScope, ID: tenant} }

// Key is the scope as `type:id`, the form grants store it in and a host's ancestor paths use.
func (s Scope) Key() string { return s.Type + ":" + s.ID }

func (s Scope) valid() bool { return validName(s.Type) && s.ID != "" }

// in reports whether the scope can hold grants in a tenant: a tenant scope only as its own.
func (s Scope) in(tenant string) bool {
	return s.valid() && (s.Type != TenantScope || s.ID == tenant)
}

// PrincipalKind is who a role can be granted to.
type PrincipalKind string

// The kinds of principal.
const (
	User  PrincipalKind = "user"
	Group PrincipalKind = "group"
	// Everyone is every user in the tenant, those who join later included; its id is empty.
	Everyone PrincipalKind = "everyone"
)

// Principal is who a role is granted to. Everyone's ID is empty.
type Principal struct {
	Kind PrincipalKind
	ID   string
}

func (p Principal) key() string { return string(p.Kind) + ":" + p.ID }

func (p Principal) valid() bool {
	switch p.Kind {
	case Everyone:
		return p.ID == ""
	case User, Group:
		return p.ID != ""
	}
	return false
}

// Subject is who is asking: a user in a tenant and every group they are in there, nested
// groups included. Build it from the authenticated session, never from request input.
type Subject struct {
	Tenant string
	User   string
	Groups []string
}

func (s Subject) principals() []string {
	keys := make([]string, 0, len(s.Groups)+2)
	if s.User != "" {
		keys = append(keys, Principal{User, s.User}.key())
	}
	for _, g := range s.Groups {
		if g != "" {
			keys = append(keys, Principal{Group, g}.key())
		}
	}
	// Everyone is every user in the tenant, so a subject with no user isn't one of them.
	if s.User != "" {
		keys = append(keys, Principal{Kind: Everyone}.key())
	}
	return keys
}

// Resource is what is asked about: its type and id, its owner, and every container above it,
// nearest first. The tenant is implied. For the tenant itself, Type is TenantScope and ID is
// the tenant.
type Resource struct {
	Tenant    string
	Type      string
	ID        string
	Owner     string
	Ancestors []Scope
}

// Scope is the scope the resource itself is.
func (r Resource) Scope() Scope { return Scope{Type: r.Type, ID: r.ID} }

func (r Resource) validate() error {
	if r.Tenant == "" {
		return fmt.Errorf("%w: resource has no tenant", ErrInvalid)
	}
	if !r.Scope().in(r.Tenant) {
		return fmt.Errorf("%w: resource %q is not a valid type and id", ErrInvalid, r.Scope().Key())
	}
	for _, a := range r.Ancestors {
		if !a.in(r.Tenant) {
			return fmt.Errorf("%w: ancestor %q is not a valid scope", ErrInvalid, a.Key())
		}
	}
	return nil
}

// Path is the keys of every scope whose grants apply to the resource: its own, every
// container's above it and the tenant's. Filter matches it against a host column holding the
// same keys, so store exactly this.
func (r Resource) Path() []string {
	keys := make([]string, 0, len(r.Ancestors)+2)
	for _, s := range append(append([]Scope{r.Scope()}, r.Ancestors...), TenantRoot(r.Tenant)) {
		if k := s.Key(); !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// Binding is one role for one principal, optionally until a time.
type Binding struct {
	Role      Role
	Principal Principal
	// ExpiresAt ends it; zero never does.
	ExpiresAt time.Time
}

// Grant is a binding on a scope, as stored.
type Grant struct {
	Scope Scope
	Binding
	// CreatedBy and CreatedAt are set on grants read back.
	CreatedBy string
	CreatedAt time.Time
}

// Change grants and revokes bindings on one scope. Revokes apply first, so a binding both
// revoked and granted ends up granted.
type Change struct {
	Grant  []Binding
	Revoke []Binding
}

// ChangeEvent is what a committed change did: only the grants that were added, updated or
// removed.
type ChangeEvent struct {
	Tenant  string
	Actor   string
	Granted []Grant
	Revoked []Grant
}

// Constraint removes a permission on a type of resource in a tenant, for everyone, owners
// included, such as a policy forbidding root access.
type Constraint struct {
	Name string
	Deny func(ctx context.Context, tenant, resourceType string, p Permission) (bool, error)
}

var (
	// ErrDenied is matched by every refusal: a check that doesn't allow, or a change the actor
	// may not make.
	ErrDenied = errors.New("rbac: denied")
	// ErrInvalid is matched by malformed input: an unknown role, a principal outside the
	// tenant, a scope a role can't be granted on.
	ErrInvalid = errors.New("rbac: invalid")
)

// DeniedError is a refusal, with why.
type DeniedError struct {
	Permission Permission
	Scope      Scope
	Reason     string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("rbac: %s on %s denied: %s", e.Permission, e.Scope.Key(), e.Reason)
}

// Is makes a DeniedError match ErrDenied.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// DB is what the package runs its queries on: a *pgxpool.Pool, a *pgx.Conn or a pgx.Tx.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Config is an Authorizer's roles, scopes and hooks.
type Config struct {
	// Catalog is the built-in roles.
	Catalog []RoleDefinition
	// ContainerTypes are scope types that hold resources, such as a workspace. Any role can
	// be granted on one, and applies to the resources under it.
	ContainerTypes []string
	// ValidatePrincipal returns an error matching ErrInvalid when the user or group doesn't
	// belong to the tenant; any other error fails the change. Required: a grant to a principal
	// outside the tenant must never be stored.
	ValidatePrincipal func(ctx context.Context, tenant string, p Principal) error
	Constraints       []Constraint
	// OnChange runs in the transaction of every change; an error rolls the change back.
	OnChange func(ctx context.Context, tx pgx.Tx, e ChangeEvent) error
	// Now is the clock that grant expiry is compared with; time.Now when nil.
	Now func() time.Time
}

// Authorizer decides and changes grants, on the tables Migrate creates.
type Authorizer struct {
	db         DB
	cfg        Config
	roles      map[Role]RoleDefinition
	containers map[string]bool
}

// New checks the configuration and returns an Authorizer that runs its queries on db.
func New(db DB, cfg Config) (*Authorizer, error) {
	if db == nil {
		return nil, errors.New("rbac: nil DB")
	}
	if cfg.ValidatePrincipal == nil {
		return nil, errors.New("rbac: Config.ValidatePrincipal is required")
	}
	roles, err := index(cfg.Catalog)
	if err != nil {
		return nil, err
	}
	// The listings read the catalog in order: from the copies, so that a caller changing its
	// slice after New can't make them disagree with checks.
	catalog := make([]RoleDefinition, len(cfg.Catalog))
	for i, r := range cfg.Catalog {
		catalog[i] = roles[r.ID]
	}
	cfg.Catalog = catalog
	containers := map[string]bool{}
	for _, t := range cfg.ContainerTypes {
		if !validName(t) || t == TenantScope {
			return nil, fmt.Errorf("rbac: container type %q is not valid", t)
		}
		containers[t] = true
	}
	for _, c := range cfg.Constraints {
		if c.Deny == nil {
			return nil, fmt.Errorf("rbac: constraint %q has no Deny", c.Name)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authorizer{db: db, cfg: cfg, roles: roles, containers: containers}, nil
}

// WithTx returns an Authorizer that runs on tx, so its changes commit or roll back with the
// host's own writes.
func (a *Authorizer) WithTx(tx pgx.Tx) *Authorizer {
	b := *a
	b.db = tx
	return &b
}

// denied returns the name of the first constraint that removes the permission, or "".
func (a *Authorizer) denied(ctx context.Context, tenant, resourceType string, p Permission) (string, error) {
	for _, c := range a.cfg.Constraints {
		deny, err := c.Deny(ctx, tenant, resourceType, p)
		if err != nil {
			return "", err
		}
		if deny {
			return c.Name, nil
		}
	}
	return "", nil
}

func parseScope(key string) Scope {
	t, id, _ := strings.Cut(key, ":")
	return Scope{Type: t, ID: id}
}
