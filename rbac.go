// Package rbac is role-based access control on PostgreSQL: Core RBAC with scoped role
// assignments. A role is a set of permissions; a grant gives one role to a principal (a user,
// another kind of identity such as a service account, a group, every member of a tenant, or
// the public) on a resource, a container above resources or the whole tenant, and applies to
// everything under that scope.
//
// The host keeps identities, groups, resources and their hierarchy and passes them in: a
// [Subject] is an identity and every group it is in, or no one, and a [Resource] carries its
// owner and its ancestors. The package keeps the grants, decides ([Authorizer.Authorize]), lists
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
	"maps"
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

// The kinds of principal every host has. A host declares its other kinds of identity, such as
// service accounts, in Config.PrincipalKinds.
const (
	User  PrincipalKind = "user"
	Group PrincipalKind = "group"
	// Tenant is every member of a tenant, of every kind, those who join later included; its id
	// is the tenant's (TenantMembers).
	Tenant PrincipalKind = "tenant"
	// Public is anyone, signed in or not, members of other tenants included; its id is empty.
	Public PrincipalKind = "public"
)

// Principal is who a role is granted to.
type Principal struct {
	Kind PrincipalKind
	ID   string
}

// TenantMembers is the principal that is every member of a tenant.
func TenantMembers(tenant string) Principal { return Principal{Kind: Tenant, ID: tenant} }

func (p Principal) key() string { return string(p.Kind) + ":" + p.ID }

// broad reports whether p is principals nobody named one by one: a tenant's members or the
// public.
func (p Principal) broad() bool { return p.Kind == Tenant || p.Kind == Public }

// wellFormed reports whether p could hold grants in a tenant, whether or not its kind is
// declared, as a revoke needs.
func (p Principal) wellFormed(tenant string) bool {
	switch p.Kind {
	case Public:
		return p.ID == ""
	case Tenant:
		return p.ID == tenant
	case User, Group:
		return p.ID != ""
	}
	return validName(string(p.Kind)) && p.ID != ""
}

// known reports whether p can be granted roles in a tenant: well formed, and of a kind every
// host has or the host declared.
func (a *Authorizer) known(tenant string, p Principal) bool {
	return p.wellFormed(tenant) && (p.Kind == Group || p.broad() || a.acts(p.Kind))
}

// acts reports whether a kind of principal can be a Subject: a user or a declared kind.
func (a *Authorizer) acts(k PrincipalKind) bool { return k == User || a.kinds[k] }

// carries reports whether a grant of a role to p can give perm, whatever the role gives now or
// later: a grant to a tenant's members or the public never gives a permission to change grants,
// and one to the public gives only while its role is marked Public.
func (a *Authorizer) carries(p Principal, role Role, perm Permission) bool {
	if p.broad() && perm.managesAccess() {
		return false
	}
	return p.Kind != Public || a.roles[role].Public
}

// publicRoles keeps the roles marked Public, the only ones a grant to the public gives.
func (a *Authorizer) publicRoles(roles []string) []string {
	var public []string
	for _, id := range roles {
		if a.roles[Role(id)].Public {
			public = append(public, id)
		}
	}
	return public
}

// Subject is who is asking: an identity in a tenant and every group it is in there, nested
// groups included. Build it from the authenticated session, never from request input.
//
// The zero Subject is anonymous, someone not signed in, and holds only what is granted to the
// public. So does a member of another tenant.
type Subject struct {
	Tenant string
	// Principal is a user, or a kind in Config.PrincipalKinds.
	Principal Principal
	Groups    []string
}

// subject checks that s is anonymous, or an identity of a kind that acts, in a tenant.
func (a *Authorizer) subject(s Subject) error {
	if s.Tenant == "" && s.Principal == (Principal{}) && len(s.Groups) == 0 {
		return nil
	}
	if s.Tenant == "" || !a.acts(s.Principal.Kind) || s.Principal.ID == "" {
		return fmt.Errorf("%w: a subject is anonymous or a user or declared kind in a tenant", ErrInvalid)
	}
	return nil
}

// member reports whether s is one of a tenant's members.
func (s Subject) member(tenant string) bool { return s.Tenant == tenant && s.Principal.ID != "" }

// user is the subject's id when it is a user in a tenant, the only kind that owns resources.
func (s Subject) user(tenant string) string {
	if s.member(tenant) && s.Principal.Kind == User {
		return s.Principal.ID
	}
	return ""
}

// owns reports whether s owns r.
func (s Subject) owns(r Resource) bool { return r.Owner != "" && s.user(r.Tenant) == r.Owner }

// principalsFor is the keys of the subject's principals whose grants in a tenant can give p: a
// grant to a tenant's members or the public never gives a permission to change grants,
// whatever its role gives now or later.
func (s Subject) principalsFor(tenant string, p Permission) []string {
	return s.keys(tenant, !p.managesAccess())
}

// principals is the keys of every principal the subject is in a tenant.
func (s Subject) principals(tenant string) []string { return s.keys(tenant, true) }

func (s Subject) keys(tenant string, broad bool) []string {
	var keys []string
	if broad {
		keys = append(keys, Principal{Kind: Public}.key())
	}
	if !s.member(tenant) {
		return keys
	}
	keys = append(keys, s.Principal.key())
	for _, g := range s.Groups {
		if g != "" {
			keys = append(keys, Principal{Group, g}.key())
		}
	}
	if broad {
		keys = append(keys, TenantMembers(tenant).key())
	}
	return keys
}

// Resource is what is asked about: its type and id, its owner, and every container above it,
// nearest first. The tenant is implied. For the tenant itself, Type is TenantScope and ID is
// the tenant.
type Resource struct {
	Tenant string
	Type   string
	ID     string
	// Owner is the id of the user who owns it; other kinds of identity own nothing.
	Owner     string
	Ancestors []Scope
}

// Scope is the scope the resource itself is.
func (r Resource) Scope() Scope { return Scope{Type: r.Type, ID: r.ID} }

// check validates a resource, and that every ancestor is a container: owning a resource lets
// its owner change its grants, so a resource that other resources sit under must be declared
// a container, whose owner can't.
func (a *Authorizer) check(r Resource) error {
	if err := r.validate(); err != nil {
		return err
	}
	for _, s := range r.Ancestors {
		if s.Type != TenantScope && !a.containers[s.Type] {
			return fmt.Errorf("%w: ancestor %q is not of a container type", ErrInvalid, s.Key())
		}
	}
	return nil
}

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
		// The tenant is above everything: a grant on a scope listed above it would reach it.
		if r.Type == TenantScope && a.Type != TenantScope {
			return fmt.Errorf("%w: the tenant has no ancestor %q", ErrInvalid, a.Key())
		}
	}
	return nil
}

// Path is the keys of every scope whose grants apply to the resource: its own, every
// container's above it and the tenant's. Filter matches it against a host column holding the
// same keys, so store exactly this, and keep it current when the resource moves.
func (a *Authorizer) Path(r Resource) ([]string, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	return r.path(), nil
}

func (r Resource) path() []string {
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
	// CreatedBy and CreatedAt are set on grants read back. CreatedBy is zero for a grant Import
	// stored.
	CreatedBy Principal
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
	Tenant string
	// Actor is who made the change through Apply; zero for Import and the deletes.
	Actor   Principal
	Granted []Grant
	Revoked []Grant
}

// Constraint removes a permission on a type of resource in a tenant, for everyone, owners
// included, such as a policy forbidding root access. On `<type>:grant` it stops changes,
// grants and revokes alike, on scopes of that type, not grants on a container that reach the
// type, as a deny on one type's grant permission does in cloud IAM. To keep anyone from having
// a permission, remove that permission itself. Deny is called for each permission a call
// considers, so keep it cheap.
type Constraint struct {
	Name string
	// Deny gets q, what the call runs on, to read the host's policy in the same transaction.
	Deny func(ctx context.Context, q DB, tenant, resourceType string, p Permission) (bool, error)
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

// DB is what the package runs its queries on, and hands to the hooks: a *pgxpool.Pool, a
// *pgx.Conn or a pgx.Tx.
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
	// PrincipalKinds are the kinds of identity besides users that act and are granted roles,
	// such as service accounts. Groups, a tenant's members and the public need no declaring.
	PrincipalKinds []PrincipalKind
	// ValidatePrincipal returns an error matching ErrInvalid when a principal can't be granted
	// roles in the tenant: an identity or group outside it, or the public where the host
	// doesn't allow public access. It is asked about every principal but the tenant's members;
	// any other error fails the change. q is what the change runs on, so under WithTx it sees a
	// member added earlier in the transaction. Required: a grant to a principal outside the
	// tenant must never be stored.
	ValidatePrincipal func(ctx context.Context, q DB, tenant string, p Principal) error
	Constraints       []Constraint
	// OnChange runs in the transaction of every change but DeleteExpired, whose grants already
	// gave nothing; an error rolls the change back.
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
	// containerTypes are the containers' types, sorted.
	containerTypes []string
	kinds          map[PrincipalKind]bool
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
	// slices after New can't make them disagree with checks or clear a Deny checked here.
	catalog := make([]RoleDefinition, len(cfg.Catalog))
	for i, r := range cfg.Catalog {
		catalog[i] = roles[r.ID]
	}
	cfg.Catalog = catalog
	cfg.Constraints = slices.Clone(cfg.Constraints)
	containers := map[string]bool{}
	for _, t := range cfg.ContainerTypes {
		if !validName(t) || t == TenantScope {
			return nil, fmt.Errorf("rbac: container type %q is not valid", t)
		}
		containers[t] = true
	}
	kinds := map[PrincipalKind]bool{}
	for _, k := range cfg.PrincipalKinds {
		if !validName(string(k)) || slices.Contains([]PrincipalKind{User, Group, Tenant, Public}, k) {
			return nil, fmt.Errorf("rbac: principal kind %q is not valid", k)
		}
		kinds[k] = true
	}
	for _, c := range cfg.Constraints {
		// denied reports a removal by the constraint's name, so one without a name would never deny.
		if c.Name == "" {
			return nil, errors.New("rbac: a constraint has no Name")
		}
		if c.Deny == nil {
			return nil, fmt.Errorf("rbac: constraint %q has no Deny", c.Name)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	types := slices.Sorted(maps.Keys(containers))
	return &Authorizer{db: db, cfg: cfg, roles: roles, containers: containers, containerTypes: types, kinds: kinds}, nil
}

// WithTx returns an Authorizer that runs on tx, so its changes commit or roll back with the
// host's own writes. Their locks last until tx ends, so two transactions that change the same
// scopes or principals in opposite orders can deadlock, as with any row locks: PostgreSQL fails
// one, to be retried. DeleteTenant locks the whole tenant.
func (a *Authorizer) WithTx(tx pgx.Tx) *Authorizer {
	b := *a
	b.db = tx
	return &b
}

// denied returns the name of the first constraint that removes the permission, or "".
func (a *Authorizer) denied(ctx context.Context, tenant, resourceType string, p Permission) (string, error) {
	for _, c := range a.cfg.Constraints {
		deny, err := c.Deny(ctx, a.db, tenant, resourceType, p)
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

func parsePrincipal(key string) Principal {
	k, id, _ := strings.Cut(key, ":")
	return Principal{Kind: PrincipalKind(k), ID: id}
}

// actorKey is who made a grant as created_by stores it: empty for no one, as Import.
func actorKey(p Principal) string {
	if p == (Principal{}) {
		return ""
	}
	return p.key()
}
