// Package rbac is role-based access control on PostgreSQL: Core RBAC with scoped role
// assignments. A role is a set of permissions, built into the host's catalog or defined by a
// tenant ([Authorizer.DefineRole]); a grant gives one role to a principal (a user, another kind
// of identity such as a service account, a group, every member of a tenant, or the public) on a
// resource, a container above resources or the whole tenant, and applies to everything under
// that scope.
//
// The host keeps identities, groups, resources and their hierarchy and passes them in: a
// [Subject] is an identity, the groups it is in and the tenants it is a member of, or no one,
// and a [Resource] carries its ancestors. The package keeps the grants, decides
// ([Authorizer.Authorize]), lists ([Authorizer.Filter], [Authorizer.Reachable]) and changes
// grants with escalation checks ([Authorizer.Apply]), under deny policies above every grant
// ([Authorizer.SetDeny]). Nothing is owned: a host gives whoever creates a resource a role on
// it ([Authorizer.Import]).
//
// A check reads the grants as they are: only compiled conditions are cached. Read a resource's
// ancestors and attributes and a subject's groups no earlier than the content they protect.
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
// `cluster:login`. `<type>:grant` is the permission to change grants on a scope of that type,
// and `<type>:deny` to set its deny policies (DenyPermission): every permission with either
// verb changes access, so a grant to a tenant's members or the public never gives it. No deny
// removes `<type>:deny`.
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
	// Public is anyone, signed in or not; its id is empty.
	Public PrincipalKind = "public"
)

// Principal is who a role is granted to. An identity's or a group's id names it in every
// tenant, so a tenant can grant a role to one from another, where Config.ValidateGrant allows
// it.
type Principal struct {
	Kind PrincipalKind
	ID   string
}

// TenantMembers is the principal that is every member of a tenant.
func TenantMembers(tenant string) Principal { return Principal{Kind: Tenant, ID: tenant} }

func (p Principal) key() string { return string(p.Kind) + ":" + p.ID }

var publicKey = Principal{Kind: Public}.key()

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
func (p Principal) carries(role RoleDefinition, perm Permission) bool {
	if p.broad() && perm.managesAccess() {
		return false
	}
	return p.Kind != Public || role.Public
}

// publicRoles keeps the built-in roles marked Public, the only built-in ones a grant to the
// public gives.
func (a *Authorizer) publicRoles(roles []string) []string {
	var public []string
	for _, id := range roles {
		if a.roles[Role(id)].Public {
			public = append(public, id)
		}
	}
	return public
}

// Subject is who is asking: an identity, every group it is in, nested groups included, and
// every tenant it is a member of. Build it from the authenticated session, never from request
// input.
//
// The zero Subject is anonymous, someone not signed in, and holds only what is granted to the
// public.
type Subject struct {
	// Principal is a user, or a kind in Config.PrincipalKinds.
	Principal Principal
	Groups    []string
	// Tenants are the tenants it is a member of, where grants to the tenant's members reach it.
	Tenants []string
	// Attributes are what conditions read as subject.attributes, such as a department.
	Attributes map[string]any
}

// subject checks that s is anonymous, or an identity of a kind that acts.
func (a *Authorizer) subject(s Subject) error {
	if s.Principal == (Principal{}) {
		if len(s.Groups)+len(s.Tenants) > 0 {
			return fmt.Errorf("%w: an anonymous subject is in no group or tenant", ErrInvalid)
		}
		return nil
	}
	if !a.acts(s.Principal.Kind) || s.Principal.ID == "" || slices.Contains(s.Tenants, "") {
		return fmt.Errorf("%w: a subject is anonymous, or a user or declared kind", ErrInvalid)
	}
	return nil
}

// principalsFor is the keys of the subject's principals whose grants in a tenant can give p: a
// grant to a tenant's members or the public never gives a permission to change grants,
// whatever its role gives now or later. public is whether a public role can give p
// (Authorizer.publicGives), so an anonymous subject reads no grants without one.
func (s Subject) principalsFor(tenant string, p Permission, public bool) []string {
	return s.keys(tenant, public && !p.managesAccess(), !p.managesAccess())
}

// publicGives reports whether a grant to the public can give p on a resource type: only a
// public role's can, built in or custom, and those give only what a role that isn't
// privileged gives there.
func (a *Authorizer) publicGives(p Permission, resourceType string) bool {
	return a.unprivileged[permissionOn{p, resourceType}]
}

// principals is the keys of every principal the subject is in a tenant.
func (s Subject) principals(tenant string) []string { return s.keys(tenant, true, true) }

func (s Subject) keys(tenant string, public, members bool) []string {
	var keys []string
	if public {
		keys = append(keys, publicKey)
	}
	if s.Principal.ID == "" {
		return keys
	}
	keys = append(keys, s.Principal.key())
	for _, g := range s.Groups {
		if g != "" {
			keys = append(keys, Principal{Group, g}.key())
		}
	}
	if members && slices.Contains(s.Tenants, tenant) {
		keys = append(keys, TenantMembers(tenant).key())
	}
	return keys
}

// Resource is what is asked about: its type and id, and every container above it, nearest
// first. The tenant is implied. For the tenant itself, Type is TenantScope and ID is the tenant.
type Resource struct {
	Tenant    string
	Type      string
	ID        string
	Ancestors []Scope
	// Attributes are what conditions read as resource.attributes, such as its labels: read them
	// from where the resource is stored, as its path, never from request input.
	Attributes map[string]any
}

// Scope is the scope the resource itself is.
func (r Resource) Scope() Scope { return Scope{Type: r.Type, ID: r.ID} }

// check validates a resource, and that every ancestor is a container: searches count only
// grants on containers, the tenant and the resource's own type, and checks must agree.
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

// Path is the keys of every scope whose grants apply to the resource: its own first, then every
// container's above it and the tenant's. Filter matches it against a host column holding the
// same keys, so store exactly this, in this order, and keep it current when the resource or a
// container above it moves.
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

// Binding is one role for one principal, optionally until a time or under a condition.
type Binding struct {
	// ID is a stored grant's, set on grants read back. In Change.Revoke it picks that one grant.
	ID        string
	Role      Role
	Principal Principal
	// Source is where a grant comes from: empty when made directly, SourceActivation when
	// activated from an eligibility, or a name the host gives the grants it manages, such as
	// those it syncs from a directory, so that it revokes only its own. A source is lowercase
	// letters, digits and . _ : / -, starting with a letter.
	Source string
	// ExpiresAt ends it; zero never does.
	ExpiresAt time.Time
	// Condition limits it to the requests its expression allows; the zero Condition is none.
	Condition Condition
	// Note says why it was made, such as the request or ticket behind it; an activated grant's
	// is its justification.
	Note string
}

// SourceActivation is the source of a grant activated from an eligibility (Authorizer.Activate).
const SourceActivation = "activation"

// Grant is a binding on a scope, as stored.
type Grant struct {
	Scope Scope
	Binding
	// ApprovedBy approved an activated grant whose eligibility needed approval; zero otherwise.
	ApprovedBy Principal
	// CreatedBy and CreatedAt are who made the grant and when, and UpdatedBy and UpdatedAt who last
	// changed its note or its condition's title or description; they are set on grants read back.
	// CreatedBy is zero for a grant Import stored.
	CreatedBy Principal
	CreatedAt time.Time
	UpdatedBy Principal
	UpdatedAt time.Time
}

// Change grants and revokes bindings on one scope.
//
// A grant is one role to one principal from one source, until one time, under one condition, as
// in cloud IAM: granting the same again changes only its note and its condition's title and
// description, and a grant that differs in any of these is another, beside it, so granting never
// narrows what a principal holds. A revoke removes every grant of its role to its principal from
// its source, whatever their expiry and condition, or with an ID that one grant. Revokes apply
// first, sparing grants the change makes again, so revoking and granting a role at once replaces
// its grants with those granted.
type Change struct {
	Grant  []Binding
	Revoke []Binding
}

// ChangeEvent is what a committed change did: only the grants that were added, whose note
// changed, or removed (an activation is a grant from SourceActivation), the custom roles defined
// or deleted, the deny policies set or deleted, and the eligibilities set or ended.
type ChangeEvent struct {
	Tenant string
	// Actor is who made the change: for Import and the deletes, the actor they name.
	Actor   Principal
	Granted []Grant
	Revoked []Grant
	// Roles are custom roles created or replaced, as they are now.
	Roles        []RoleDefinition
	DeletedRoles []Role
	// Denies are deny policies created or replaced, as they are now.
	Denies        []Deny
	DeletedDenies []Deny
	// Eligible are eligibilities set, as they are now; Ineligible, those ended.
	Eligible   []Eligibility
	Ineligible []Eligibility
}

func (e ChangeEvent) empty() bool {
	return len(e.Granted)+len(e.Revoked)+len(e.Roles)+len(e.DeletedRoles)+len(e.Denies)+len(e.DeletedDenies)+
		len(e.Eligible)+len(e.Ineligible) == 0
}

// Constraint removes permissions as the host's own policy, above anything a tenant grants or
// denies, such as forbidding root access, freezing changes under a container, or keeping
// service accounts from one. On `<type>:grant` it stops changes, grants and revokes alike, on
// scopes of that type, not grants on a container that reach the type, as a deny on one type's
// grant permission does in cloud IAM. To keep anyone from having a permission, remove that
// permission itself. Deny is called for each permission a call considers, so keep it cheap.
type Constraint struct {
	Name string
	// Deny reports whether the constraint removes in.Permission. q is what the call runs on, to
	// read the host's policy in the same transaction.
	Deny func(ctx context.Context, q DB, in ConstraintInput) (bool, error)
}

// ConstraintInput is what a constraint is asked about. Searches ask once for every resource of a
// type, and Holders once for every holder: where Resource or Subject is nil, answer true if the
// constraint removes the permission for any, so that a search never keeps what a check refuses.
type ConstraintInput struct {
	Tenant       string
	ResourceType string
	Permission   Permission
	// Subject is who asks, or who changes access; nil in Holders.
	Subject *Subject
	// Resource is what is asked about, with its ancestors and attributes; nil in Filter and
	// Reachable, and in DefineRole and DeleteRole, which change grants on every scope of a type.
	Resource *Resource
}

var (
	// ErrDenied is matched by every refusal: a check that doesn't allow, or a change the actor
	// may not make.
	ErrDenied = errors.New("rbac: denied")
	// ErrInvalid is matched by malformed input: an unknown role, a principal outside the
	// tenant, a scope a role can't be granted on.
	ErrInvalid = errors.New("rbac: invalid")
	// ErrConflict is matched by a change refused because another changed what it rests on while
	// it waited, or that PostgreSQL refused for a race, as a deadlock between host transactions:
	// try it again.
	ErrConflict = errors.New("rbac: conflict")
)

// conflicted makes PostgreSQL's refusals for a race match ErrConflict, keeping the error: a
// serialization failure, a deadlock, or a lock it couldn't take.
func conflicted(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && !errors.Is(err, ErrConflict) && (pg.Code == "40001" || pg.Code == "40P01" || pg.Code == "55P03") {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return err
}

// Limits on what is stored and what one call takes, so that what a check, a search or a change
// reads stays bounded. Input past one is refused as invalid; a host can check against them first.
// Lengths are in characters, but an expression's, in bytes.
const (
	// MaxBindings is how many bindings one Apply, grants and revokes together, or one Import takes.
	MaxBindings = 1000
	// MaxDenies is how many deny policies a scope holds, and MaxDenyEntries how many principals,
	// exemptions or permissions one names.
	MaxDenies      = 100
	MaxDenyEntries = 256
	// MaxCustomRoles is how many custom roles a tenant has, and MaxGrantableRoles how many roles one
	// role lists.
	MaxCustomRoles    = 300
	MaxGrantableRoles = 64
	// MaxApprovers is how many approvers an eligibility names.
	MaxApprovers = 16
	// MaxActivation is the longest an eligibility lets an activation last.
	MaxActivation = 366 * 24 * time.Hour
	// MaxName bounds names and titles; MaxDescription, descriptions; MaxNote, notes and
	// justifications; MaxExpression, a condition's or a requirement's expression.
	MaxName        = 128
	MaxDescription = 2048
	MaxNote        = 2048
	MaxExpression  = 2048
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
	// ValidateGrant returns an error matching ErrInvalid when a grant can't be made: to an
	// identity or group the tenant doesn't let in, such as one from another tenant; to the public
	// where the host doesn't allow public access; of a role a principal's kind may not hold, such
	// as a privileged one for a guest; or one this actor may not give this principal. It is asked
	// about every grant Apply, Import and Activate make, and every eligibility SetEligible sets,
	// once each is otherwise valid; any other error fails the change. q is what the change runs
	// on, so under WithTx it sees a member added earlier in the transaction. Required: a grant
	// to a principal the tenant doesn't let in must never be stored.
	ValidateGrant func(ctx context.Context, q DB, in GrantInput) error
	Constraints   []Constraint
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
	// permissions and types are what the built-in roles give and are for: all a custom role
	// may use. unprivileged are the permissions, each with a type, that a role that isn't
	// privileged gives there: all a public role may give.
	permissions  map[Permission]bool
	types        map[string]bool
	unprivileged map[permissionOn]bool
	// The same, sorted, as searches pass them to SQL. publicPairs are the unprivileged pairs, as
	// `permission type`, of permissions that don't change access: all a public role gives as
	// Authorizer.current reads it.
	catalogPermissions, catalogTypes, publicPairs []string
	conds                                         *conditions
}

// permissionOn is a permission on a type of resource.
type permissionOn struct {
	p Permission
	t string
}

// New checks the configuration and returns an Authorizer that runs its queries on db.
func New(db DB, cfg Config) (*Authorizer, error) {
	if db == nil {
		return nil, errors.New("rbac: nil DB")
	}
	if cfg.ValidateGrant == nil {
		return nil, errors.New("rbac: Config.ValidateGrant is required")
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
	perms, resourceTypes, unprivileged := map[Permission]bool{}, map[string]bool{}, map[permissionOn]bool{}
	for _, r := range catalog {
		for _, t := range r.ResourceTypes {
			resourceTypes[t] = true
			for _, p := range r.Permissions {
				perms[p] = true
				if !r.Privileged {
					unprivileged[permissionOn{p, t}] = true
				}
			}
		}
	}
	var permList, pairs []string
	for p := range perms {
		permList = append(permList, string(p))
	}
	for k := range unprivileged {
		if !k.p.managesAccess() {
			pairs = append(pairs, string(k.p)+" "+k.t)
		}
	}
	slices.Sort(permList)
	slices.Sort(pairs)
	conds, err := newConditions()
	if err != nil {
		return nil, err
	}
	return &Authorizer{
		db: db, cfg: cfg, roles: roles, containers: containers, containerTypes: slices.Sorted(maps.Keys(containers)),
		kinds: kinds, permissions: perms, types: resourceTypes, unprivileged: unprivileged,
		catalogPermissions: permList, catalogTypes: slices.Sorted(maps.Keys(resourceTypes)), publicPairs: pairs,
		conds: conds,
	}, nil
}

// WithTx returns an Authorizer that runs on tx, so its changes commit or roll back with the
// host's own writes. Changes need tx at READ COMMITTED, PostgreSQL's default, and fail in a
// stricter one, whose snapshot can predate the locks they wait for. Their locks last until tx
// ends, so two transactions that change the same scopes or principals in opposite orders can
// deadlock, as with any row locks: PostgreSQL fails one, to be retried. DeleteTenant,
// DefineRole and DeleteRole lock the whole tenant.
func (a *Authorizer) WithTx(tx pgx.Tx) *Authorizer {
	b := *a
	b.db = tx
	return &b
}

// GrantInput is a grant Config.ValidateGrant is asked about.
type GrantInput struct {
	Tenant  string
	Scope   Scope
	Binding Binding
	// Role is what the grant gives: the role as defined now.
	Role RoleDefinition
	// Actor is who makes it: the subject changing grants, setting an eligibility or activating, or
	// Import's actor.
	Actor Subject
	// Via is how it is made.
	Via Via
}

// Via is how a grant is made.
type Via string

// The ways a grant is made: by Apply, Import or Activate, or as an eligibility SetEligible
// sets, which is the grant activating it would make.
const (
	ViaApply       Via = "apply"
	ViaImport      Via = "import"
	ViaEligibility Via = "eligibility"
	ViaActivation  Via = "activation"
)

// denied returns the name of the first constraint that removes in.Permission, or "".
func (a *Authorizer) denied(ctx context.Context, in ConstraintInput) (string, error) {
	for _, c := range a.cfg.Constraints {
		deny, err := c.Deny(ctx, a.db, in)
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
