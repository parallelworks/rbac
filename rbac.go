// Package rbac is role-based access control on PostgreSQL: Core RBAC with scoped role
// assignments. A role is a set of permissions, built into the host's catalog or defined by a
// tenant ([Authorizer.SetRole]); a grant gives one role to a principal (a user, another kind
// of identity such as a service account, a group, every member of a tenant, or the public) on a
// resource, a container above resources or the whole tenant, and applies to everything under
// that scope.
//
// The host keeps identities, resources and their hierarchy and passes them in: a [Subject] is the
// identity asking, or no one, and a [Resource] carries its ancestors. The package keeps the
// identities that are members or guests of each tenant and in each of its groups
// ([Authorizer.SetMemberships], [Authorizer.ImportMembers]), and the grants, decides
// ([Authorizer.Authorize]), lists ([Authorizer.Filter], [Authorizer.Reachable]) and changes
// grants with escalation checks ([Authorizer.Apply]), under deny policies above every grant
// ([Authorizer.SetDeny]). Nothing is owned: a host gives whoever creates a resource a role on
// it ([Authorizer.Import]).
//
// A check reads the grants, memberships and groups as they are: only compiled conditions are
// cached. Read a resource's ancestors and attributes no earlier than the content they protect.
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

func (s Scope) valid() bool { return validName(s.Type) && validID(s.ID) }

// MaxID is the longest a tenant's, a scope's or a principal's id is, in bytes, so that keys of
// them fit the database's indexes.
const MaxID = 512

// validID reports whether s can be a tenant's, a scope's or a principal's id: text without NUL, of
// 1 to MaxID bytes, as the database stores it.
func validID(s string) bool { return s != "" && len(s) <= MaxID && validText(s) }

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
	// Members is every member of a tenant, of every kind, those who join later included, and none
	// of its guests; its id is the tenant's (TenantMembers).
	Members PrincipalKind = "members"
	// Public is anyone, signed in or not; its id is empty.
	Public PrincipalKind = "public"
)

// reservedKinds, and kinds starting rbac, are kinds of principal a later release may add, such as
// every signed-in identity, so a host can't declare one.
var reservedKinds = []PrincipalKind{"anonymous", "authenticated", "domain", "everyone", "role", "set"}

// Principal is who a role is granted to. An identity's id names it in every tenant, and it holds
// what a tenant grants it while it is a member or guest there; a group's names it only in its
// tenant.
type Principal struct {
	Kind PrincipalKind
	ID   string
}

// TenantMembers is the principal that is every member of a tenant.
func TenantMembers(tenant string) Principal { return Principal{Kind: Members, ID: tenant} }

func (p Principal) key() string { return string(p.Kind) + ":" + p.ID }

var publicKey = Principal{Kind: Public}.key()

// broad reports whether p is principals nobody named one by one: a tenant's members or the
// public.
func (p Principal) broad() bool { return p.Kind == Members || p.Kind == Public }

// broadKinds are the kinds of the broad principals, as a statement's argument, and broadKindsSQL
// as SQL.
var (
	broadKinds    = []string{string(Members), string(Public)}
	broadKindsSQL = fmt.Sprintf(`ARRAY['%s', '%s']::text[]`, Members, Public)
)

// wellFormed reports whether p could hold grants in a tenant, whether or not its kind is
// declared, as a revoke needs.
func (p Principal) wellFormed(tenant string) bool {
	switch p.Kind {
	case Public:
		return p.ID == ""
	case Members:
		return p.ID == tenant
	case User, Group:
		return validID(p.ID)
	}
	return validName(string(p.Kind)) && validID(p.ID)
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

// Subject is who is asking: an identity, built from the authenticated session, never from
// request input. The package knows the rest: whether it is a member or guest of the tenant asked
// about, and the groups it is in there (SetMemberships, ImportMembers). An identity holds nothing
// in a tenant it isn't a member or guest of, nor while its membership is suspended, but what is
// granted to the public.
//
// The zero Subject is anonymous, someone not signed in, and holds only what is granted to the
// public.
type Subject struct {
	// Principal is a user, or a kind in Config.PrincipalKinds.
	Principal Principal
	// Attributes are what conditions read as subject.attributes, such as a department.
	Attributes map[string]any
}

// subject checks that s is anonymous, or an identity of a kind that acts.
func (a *Authorizer) subject(s Subject) error {
	if s.Principal != (Principal{}) && (!a.acts(s.Principal.Kind) || !validID(s.Principal.ID)) {
		return fmt.Errorf("%w: a subject is anonymous, or a user or declared kind", ErrInvalid)
	}
	return nil
}

// copied is s with its attributes a deep copy, for a hook to be given.
func (s Subject) copied() Subject {
	s.Attributes = deepCopy(s.Attributes)
	return s
}

// identityKey is the subject's key, as membership is read by: empty for the anonymous, which no
// membership has.
func (s Subject) identityKey() string {
	if s.Principal == (Principal{}) {
		return ""
	}
	return s.Principal.key()
}

// broad is whose grants to broad principals a read counts: the public's, and the tenant's
// members'. A grant to either never gives a permission to change grants, whatever its role
// gives now or later, and one to the public gives only what a public role can (publicGives).
type broad struct{ public, members bool }

// counting is which broad grants can give p on a resource type.
func (a *Authorizer) counting(p Permission, resourceType string) broad {
	return broad{public: a.publicGives(p, resourceType) && !p.managesAccess(), members: !p.managesAccess()}
}

// all counts every broad grant, as a read of what a subject may do, whatever the permission,
// filters later.
var all = broad{public: true, members: true}

// keysSQL is SQL defining, in a WITH RECURSIVE, keys(k): the principal keys an identity is in a
// tenant at now, given as SQL for its key (empty for the anonymous), the tenant and the time. They
// are the public; and while the identity is a member or guest of the tenant, not suspended, the
// identity, the groups it is in, through those they are in, and unless it is a guest the tenant's
// members. A group is counted once, so membership nested in a cycle stops. It defines exempted(k)
// too, the keys a deny exempts it by: its keys, and its identity even where it isn't a member or
// guest, as a grant to the public still reaches it there; and bound(k), the keys a deny binds it
// by: those, and while its membership is suspended, the groups and the tenant's members it would
// be in, so suspending it, which gives it only the public's grants, lifts no deny from it. The
// groups a group is in are looked up by its key, each on its own: joined to the tenant's members, a
// generic plan, costing them by averages, can read every one to find a few. OFFSET 0 keeps the
// planner from flattening it into that join.
func keysSQL(tenant, identity, now string) string {
	return fmt.Sprintf(`membership AS (
		SELECT guest, suspended FROM rbac_memberships WHERE tenant = %[1]s AND principal = %[2]s
		  AND (expires_at IS NULL OR expires_at > %[3]s)
	), groups(id) AS (
		SELECT group_id FROM rbac_members WHERE tenant = %[1]s AND principal = %[2]s
		  AND (expires_at IS NULL OR expires_at > %[3]s) AND EXISTS (SELECT FROM membership)
		UNION
		SELECT m.group_id FROM groups g CROSS JOIN LATERAL (
		  SELECT group_id FROM rbac_members WHERE tenant = %[1]s AND principal = 'group:' || g.id
		    AND (expires_at IS NULL OR expires_at > %[3]s) OFFSET 0) m
	), keys(k) AS (
		SELECT 'public:' COLLATE "C"
		UNION ALL SELECT %[2]s COLLATE "C" FROM membership WHERE NOT suspended
		UNION ALL SELECT ('members:' || %[1]s) COLLATE "C" FROM membership WHERE NOT guest AND NOT suspended
		UNION ALL SELECT 'group:' || id FROM groups WHERE EXISTS (SELECT FROM membership WHERE NOT suspended)
	), exempted(k) AS (
		SELECT k FROM keys UNION SELECT %[2]s COLLATE "C" WHERE %[2]s <> ''
	), bound(k) AS (
		SELECT k FROM exempted
		UNION SELECT ('members:' || %[1]s) COLLATE "C" FROM membership WHERE NOT guest
		UNION SELECT 'group:' || id FROM groups
	)`, tenant, identity, now)
}

// exempting is the keys a deny exempts s by: its keys, and its identity even where it isn't a
// member or guest, as a grant to the public still reaches it there.
func exempting(keys []string, s Subject) []string {
	if k := s.identityKey(); k != "" && !slices.Contains(keys, k) {
		return append(slices.Clone(keys), k)
	}
	return keys
}

// countedKeys is SQL selecting, sorted, the keys keysSQL defines whose grants a read counts: the
// broad ones only where public and members, SQL for booleans, are true. Sorted, a lookup of them
// in the key index takes half as long.
func countedKeys(public, members string) string {
	return `SELECT k FROM keys WHERE ` + counted(public, members) + ` ORDER BY k`
}

// counted is SQL for whether keys' k is one whose grants a read counts, as countedKeys says.
func counted(public, members string) string {
	return fmt.Sprintf(`(k <> 'public:' OR %s) AND (k NOT LIKE 'members:%%' OR %s)`, public, members)
}

// keysOf reads the principal keys s is in a tenant, and those a deny binds it by, each sorted, as
// keysSQL defines them.
func (a *Authorizer) keysOf(ctx context.Context, q DB, tenant string, s Subject) (keys, binding []string, err error) {
	return a.keysAt(ctx, q, tenant, s, a.cfg.Now())
}

// keysAt is keysOf at a time.
func (a *Authorizer) keysAt(ctx context.Context, q DB, tenant string, s Subject, at time.Time) (keys, binding []string, err error) {
	rows, err := q.Query(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$3")+`
		SELECT k, k IN (SELECT k FROM keys) FROM bound ORDER BY k`, tenant, s.identityKey(), at)
	if err != nil {
		return nil, nil, err
	}
	var k string
	var in bool
	_, err = pgx.ForEachRow(rows, []any{&k, &in}, func() error {
		if in {
			keys = append(keys, k)
		}
		binding = append(binding, k)
		return nil
	})
	return keys, binding, err
}

// countedOf keeps the keys whose grants a read counts.
func countedOf(keys []string, b broad) []string {
	return slices.DeleteFunc(slices.Clone(keys), func(k string) bool {
		kind, _, _ := strings.Cut(k, ":")
		return kind == string(Public) && !b.public || kind == string(Members) && !b.members
	})
}

// publicGives reports whether a grant to the public can give p on a resource type: only a
// public role's can, built in or custom, and those give only what a role that isn't
// privileged gives there.
func (a *Authorizer) publicGives(p Permission, resourceType string) bool {
	return a.unprivileged[permissionOn{p, resourceType}]
}

// Resource is what is asked about: its type and id, and every container above it, nearest
// first. The tenant is implied. For the tenant itself, Type is TenantScope and ID is the tenant.
type Resource struct {
	Tenant    string
	Type      string
	ID        string
	Ancestors []Scope
	// Attributes are what conditions read as resource.attributes: read them from where the
	// resource is stored, as its path, never from request input.
	Attributes map[string]any
	// Labels is its label, which a subject's holding must satisfy, whatever its grants give, for
	// a check to allow anything (Config.Labels) but, on the tenant, a label value or a power to
	// release, which checks decide without it. Store it with the resource, as its path. A check
	// reads the resource's own, not its ancestors': label what a labeled container holds too.
	Labels Label
}

// Scope is the scope the resource itself is.
func (r Resource) Scope() Scope { return Scope{Type: r.Type, ID: r.ID} }

// check validates a resource, and that every ancestor is a container: searches count only
// grants on containers, the tenant and the resource's own type, and checks must agree.
func (a *Authorizer) check(r Resource) error {
	if err := r.validate(); err != nil {
		return err
	}
	if err := a.checkLabel(r.Labels); err != nil {
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
	if !validID(r.Tenant) {
		return fmt.Errorf("%w: resource has no tenant, or not one of text without NUL of at most %d bytes", ErrInvalid, MaxID)
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
	// ID is a stored grant's, set on grants read back. In Change.Revoke, with the grant's role and
	// principal, it picks that one grant.
	ID        string
	Role      Role
	Principal Principal
	// Source is where a grant comes from: empty when made directly, SourceActivation when
	// activated from an eligibility, or a name the host gives the grants it manages, such as
	// those it syncs from a directory, so that it revokes only its own. A source the host owns
	// (Config.Sources) only it changes, through Import and DeleteGrants. A source is lowercase
	// letters, digits and . _ : / -, starting with a letter, and one starting rbac is reserved for
	// the package.
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

// ChangeEvent is what a committed change did: only the grants that were added, whose note or
// condition's title or description changed, cut short or removed, the custom roles defined or
// deleted, the deny policies set or deleted, the eligibilities set or ended, the tenant memberships
// set or ended, the groups set or deleted, and the members who joined or left groups. An activation
// is a grant from SourceActivation: one that moves no end later changes nothing, so isn't reported.
type ChangeEvent struct {
	Tenant string
	// Actor is who made the change: for Import and the deletes, the actor they name.
	Actor   Principal
	Granted []Grant
	Revoked []Grant
	// Shortened are activations a change cut short, as they are now: one ending, sooner, a place in a
	// group or a membership an activation rested on.
	Shortened []Grant
	// Roles are custom roles created or replaced, as they are now.
	Roles        []RoleDefinition
	DeletedRoles []Role
	// Denies are deny policies created or replaced, as they are now.
	Denies        []Deny
	DeletedDenies []Deny
	// Eligible are eligibilities set, as they are now; Ineligible, those ended.
	Eligible   []Eligibility
	Ineligible []Eligibility
	// Memberships are tenant memberships set, as they are now; EndedMemberships, those ended.
	Memberships      []Membership
	EndedMemberships []Membership
	// Groups are groups created or replaced, as they are now; DeletedGroups, those deleted.
	Groups        []GroupDefinition
	DeletedGroups []GroupDefinition
	// Joined are members added to groups or changed, as they are now; Left, those removed.
	Joined []Member
	Left   []Member
}

func (e ChangeEvent) empty() bool {
	return len(e.Granted)+len(e.Revoked)+len(e.Shortened)+len(e.Roles)+len(e.DeletedRoles)+len(e.Denies)+len(e.DeletedDenies)+
		len(e.Eligible)+len(e.Ineligible)+len(e.Memberships)+len(e.EndedMemberships)+len(e.Groups)+len(e.DeletedGroups)+
		len(e.Joined)+len(e.Left) == 0
}

// Constraint removes permissions as the host's own policy, above anything a tenant grants or
// denies, such as forbidding root access, freezing changes under a container, or keeping
// service accounts from one. On `<type>:grant` it stops changes, grants and revokes alike, on
// scopes of that type, not grants on a container that reach the type, as a deny on one type's
// grant permission does in cloud IAM. To keep anyone from having a permission, remove that
// permission itself. What it removes from an actor the actor can't hand on either, as with a
// deny: a grant, an eligibility or a custom role giving it, or the power to grant it, but for a
// role a role it holds lists in GrantableRoles, which it grants without holding. Deny is called
// for each permission a call considers, so keep it cheap.
type Constraint struct {
	Name string
	// Deny reports whether the constraint removes in.Permission. q is what the call runs on, to
	// read the host's policy in the same transaction. A read asks before its own transaction, so
	// Deny may query the host's pool there too; but under AsOf, as under WithTx, q is a transaction
	// that holds one of the pool's connections while Deny runs, so query q: a query of the pool
	// waits for another connection, which on a busy pool may never come.
	Deny func(ctx context.Context, q DB, in ConstraintInput) (bool, error)
}

// ConstraintInput is what a constraint is asked about. Searches ask once for every resource of a
// type, and Holders first once for every holder: where Resource or Subject is nil, answer true if
// the constraint removes the permission for any, so that a search never keeps what a check
// refuses. Holders then asks again about each identity it lists, which it marks MaybeDenied where
// the constraint answers true. Each constraint is given copies of its own of the subject and the
// resource, their attributes, ancestors and label too, however deep, so one writing to them
// changes nothing decided. A host's struct among the attributes is copied by its exported fields
// and those an unexported struct it embeds promotes: the rest, a pointer it embeds unexported and
// the fields that promotes among them, reflection can't set, so they are shared. A map's keys are
// shared, and what a pointer among them reaches, as a copied key would be another key: key a map
// among the attributes by values, not pointers, or write through none.
type ConstraintInput struct {
	Tenant       string
	ResourceType string
	Permission   Permission
	// Subject is who asks, or who changes access; nil in Holders' first ask, and then each holder
	// without the attributes Holders doesn't know, as for the label values of a holder of a
	// labeled resource: answer true there if the constraint removes it from that principal with any.
	// Authorizer.GroupsOf reads the groups it is in, even while its membership is suspended.
	Subject *Subject
	// Resource is what is asked about, with its ancestors and attributes, but for a label value or a
	// power to release on the tenant, which every check decides, and a change hands on, on the tenant
	// with no attributes, ancestors or label, whatever it is passed, as Holding reads them, and whose
	// conditions can't read the tenant's attributes, any read making a grant's give nothing and a
	// deny's apply: read the tenant's state through q. For what else a change hands on, it is the
	// scope it is on, whose type is a container's or the tenant's where what it hands on reaches the
	// resources of ResourceType under it. There, answer true if the constraint removes the permission
	// on any of them: one that tells them apart by id or attributes sees only the scope, and would let
	// the actor hand on what it can't use on them. It is nil in Filter and Reachable, and in SetRole
	// and DeleteRole, which change grants on every scope of a type, but for what SetRole's role gives,
	// asked about the tenant.
	Resource *Resource
}

// copied is in with its subject and resource deep copies.
func (in ConstraintInput) copied() ConstraintInput {
	if in.Subject != nil {
		s := in.Subject.copied()
		in.Subject = &s
	}
	if in.Resource != nil {
		r := *in.Resource
		r.Ancestors, r.Attributes, r.Labels = deepCopy(r.Ancestors), deepCopy(r.Attributes), deepCopy(r.Labels)
		in.Resource = &r
	}
	return in
}

var (
	// ErrDenied is matched by every refusal: a check that doesn't allow, or a change the actor
	// may not make.
	ErrDenied = errors.New("rbac: denied")
	// ErrInvalid is matched by malformed input: an unknown role, a principal outside the
	// tenant, a scope a role can't be granted on, a check of a permission or resource type the
	// host doesn't have (Config.Permissions).
	ErrInvalid = errors.New("rbac: invalid")
	// ErrConflict is matched by a change refused because another changed what it rests on while
	// it waited, or that PostgreSQL refused for a race, as a deadlock between host transactions:
	// try it again.
	ErrConflict = errors.New("rbac: conflict")
	// ErrNotFound is what Config.ResourceOf returns, or wraps, for a scope the host no longer has,
	// as a resource deleted without DeleteScopes: a change that only takes access away there, as
	// removing a member of a group with access on it or deleting a role granted on it, reads it as
	// unlabeled. Any other error fails the change.
	ErrNotFound = errors.New("rbac: not found")
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
	// MaxBindings is how many bindings one Apply, grants and revokes together, or one Import takes,
	// and MaxGrantsPerRole how many grants in force of one role a principal holds on one scope,
	// differing by source, expiry or condition, as cloud IAM bounds bindings of one role: those from
	// each source the host owns (Config.Sources) counted apart.
	MaxBindings      = 1000
	MaxGrantsPerRole = 20
	// MaxDenies is how many deny policies a scope holds, and MaxDenyEntries how many principals,
	// exemptions or permissions one names.
	MaxDenies      = 100
	MaxDenyEntries = 256
	// MaxCustomRoles is how many custom roles a tenant has, MaxRoleEntries how many permissions one
	// gives and how many resource types it is for, and MaxGrantableRoles how many roles one role
	// lists.
	MaxCustomRoles    = 300
	MaxRoleEntries    = 1000
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
	// MaxConditionBytes is how many bytes of conditions, each counted once, one change carries:
	// compiling one takes up to ten milliseconds for each kilobyte, before the host is asked and
	// outside any check's budget, so a change of many distinct ones would otherwise spend seconds.
	MaxConditionBytes = 32 << 10
)

// DeniedError is a refusal, with why. Its message names only the permission, so a host that
// shows an error shows none of its policy; log Scope and Reason, or use Explain.
type DeniedError struct {
	Permission Permission
	Scope      Scope
	Reason     string
}

func (e *DeniedError) Error() string { return fmt.Sprintf("rbac: %s denied", e.Permission) }

// Is makes a DeniedError match ErrDenied.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// DB is what the package runs its queries on, and hands to the hooks: a *pgxpool.Pool, a
// *pgx.Conn or a pgx.Tx. A host's own DB, as one tracing its statements, that has no BeginTx begins
// with Begin, and its transaction's first statement sets the isolation a change or a read of one
// snapshot needs; one whose Begin gives a savepoint of a transaction under way runs them in that
// transaction, at its isolation, as under WithTx.
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
	// such as service accounts. Groups, a tenant's members and the public need no declaring, and
	// a few names are reserved for kinds a later release may add.
	PrincipalKinds []PrincipalKind
	// ValidateGrant returns an error matching ErrInvalid when a grant can't be made: to an
	// identity or group the tenant doesn't let in, such as one from another tenant; to the public
	// where the host doesn't allow public access; of a role a principal's kind may not hold, such
	// as a privileged one for a guest; or one this actor may not give this principal. It is asked
	// about every grant Apply, Import and Activate make, every eligibility SetEligibility sets,
	// every grant and eligibility that SetRole redefining a custom role makes give more, and every
	// one a member ChangeMembers or ImportMembers adds gains (ViaMembership), once each is
	// otherwise valid; the change's InvalidError for it wraps the error, so errors.Is and
	// errors.As find the host's own in it. Any other error fails the change as it is. q is what
	// the change runs on, so under WithTx it sees a member added earlier in the transaction. A
	// grant to a group reaches whoever is in it, now and later: it is asked about with the group,
	// and about each member as it joins, so a policy on who may hold a role, as none privileged for
	// a guest, refuses the group's grant too while the group holds one that may not.
	// Required: a grant to a principal the tenant doesn't let in must never be stored.
	ValidateGrant func(ctx context.Context, q DB, in GrantInput) error
	// Constraints are the host's policy above every grant and deny, asked about each permission a
	// call decides. A check asks about its permission, and for a labeled resource once about each
	// value its label asks for that the subject's grants give: in an Ordered dimension those as
	// high as the label's, and in another those it names, so a hook failing on another value fails
	// no check of it. Explain, Permissions, Grantable, Holders for each identity it lists, and a
	// change on a labeled scope ask the same. Holding, Filter and Reachable, which test any label,
	// ask about every value and power to release the subject's grants give, as do SetRole and
	// DeleteRole of a role granted somewhere, ChangeMembers where only a removal reaches a scope,
	// and Activate about an approver on a labeled scope.
	Constraints []Constraint
	// ResourceOf returns the resource a scope is, with its ancestors, attributes and label, as the
	// host passes it to a check. SetGroup and DeleteGroup check ManageGroups on the tenant, and,
	// where Labels are declared, the group's label, a group SetGroup creates included, and
	// ChangeMembers GroupMembers on each group it changes, on the resource it returns, and a change
	// to a group's members as the grants and denies it amounts to, and a removal by the label, on
	// each scope the group's access is on, the tenant's and groups' included, which the package knows
	// only by type and id, on the resource it returns for each. Without it, a scope is taken as
	// stored, its type and id directly under the tenant, with no attributes or label, as constraints
	// see it too. GroupMembers is checked on a group as group management checks its permissions; the
	// grants and denies a change amounts to only where that is all of the scope: for a host declaring
	// no Labels, and resource Attributes as none (an empty map, as nil lets conditions read any), and
	// on a scope other than the tenant or a group, no ContainerTypes. For any other, that change is
	// refused. SetRole changing what a custom role's grants give, and DeleteRole, check the label of
	// each scope the role is granted on, and where a deny on a scope other than the tenant binds the
	// actor, the denies on its path, and SetRole widening it the label of each scope a role listing it,
	// or listing one that does, is granted on, and the denies on its path, as it returns it, so with
	// Labels declared, or such a deny, they need it too. A removal reads a scope it reports as
	// ErrNotFound as stored and unlabeled, and ChangeMembers and DeleteRole ask nothing of the scopes
	// only a removal reaches where the actor's label values satisfy every label and, for DeleteRole,
	// no such deny binds it, as SetRole asks nothing of the scopes roles listing the role are granted
	// on then.
	ResourceOf func(ctx context.Context, tenant string, s Scope) (Resource, error)
	// Permissions are every permission the host checks, whether or not a role gives it, so that a
	// catalog leaving one out, as one an operator configures may, refuses it like any permission
	// no grant gives. A check or search of a permission not among them, or of a resource type none
	// of them nor any built-in role is for, is refused as invalid, as a typo, and New refuses a
	// built-in role giving one: they include what the package checks for the host that the
	// built-in roles give, `:grant` and `:deny` permissions, DefineRoles, ManageGroups and
	// GroupMembers. Empty, they are what the built-in roles give.
	Permissions []Permission
	// Sources are the sources the host owns, such as the one it syncs grants from a directory
	// from: Apply refuses to grant or revoke from one, by ID too, and DeleteRole to delete a role
	// granted from one, so a tenant's admins can neither forge the host's grants nor remove them
	// behind its back. The host makes and removes them with Import and DeleteGrants. A custom role
	// the host grants stays the tenant's to define: redefining it changes what the host's grants
	// give, as it does any grant of it, asking the host about those it widens. The conditions of
	// grants from each are bounded apart from the tenant's, as MaxGrantsPerRole counts them, so
	// neither can fill what the other stores in, and a check may spend as much again on each
	// (Condition).
	Sources []string
	// Attributes declares the attributes conditions read, so one misnamed or of another type is
	// refused when a condition is stored; undeclared, any is read.
	Attributes Attributes
	// Labels declares the dimensions of the labels on data (Resource.Labels): a mandatory layer
	// above every grant. A subject holds a dimension's values as permissions, `dimension:value`,
	// which roles for the tenant give, and a check allows anything of a labeled resource only
	// when what it holds satisfies the label. None, nothing is labeled. Checks, Permissions and
	// Grantable read the subject's values in the statement that reads its grants, Explain and
	// Reachable in the read's snapshot, and Holders every holder's at once, in its snapshot, so a
	// label is decided by values of the moment the grants are; but under WithTx at READ COMMITTED,
	// where each statement reads a snapshot of its own, Explain, Reachable and Holders can mix two
	// states, as WithTx says. Filter fixes the holding when it is called. A deny of an Ordered value
	// takes that value alone: to cap a level, deny it and every value above. Values are held on the
	// tenant, so they are denied there: SetDeny refuses a deny of one on any other scope, which would
	// bind no one. The conditions of a value's grants and denies read the tenant as their resource,
	// never the labeled one.
	Labels []LabelDimension
	// OnChange runs in the transaction of every change but DeleteExpired, whose grants already
	// gave nothing, once the change is written; an error rolls the change back. History records
	// what it writes as the host's, not as the change's. A delete's event holds every row it
	// removes, in memory at once: for a tenant of millions of rows, remove them a part at a time
	// first, its resources' grants with DeleteScopes, a batch of scopes at a time, and its
	// identities' memberships, places in groups and grants on the tenant with DeletePrincipal.
	OnChange func(ctx context.Context, tx pgx.Tx, e ChangeEvent) error
	// OnRefused is told of every change refused as ErrDenied or ErrInvalid, as an attempt that
	// failed, which history doesn't record, as nothing of it is written; but not of one on an
	// Authorizer AsOf gave, which refuses every change. It runs with the call's ctx before the
	// call returns, once the change's transaction has ended: under WithTx, its savepoint, in the
	// host's transaction, which is still open, with its locks. Record it on a connection of the
	// host's own, which the host's transaction rolling back leaves.
	OnRefused func(ctx context.Context, r Refusal)
	// Now is the clock that expiry is compared with and conditions read as request.time; time.Now
	// when nil. A call reads it once, where it first needs the time, so every statement it makes and
	// every condition it evaluates are of one moment: read apart, a grant or a membership ending as
	// the call runs could meet a deny, a condition or label values of a later moment. A change reads
	// it once more in its transaction, under its locks, where it decides again, the ends of what it
	// writes included. A call a hook makes, as a constraint's of GroupsOf, is a call of its own and
	// reads it apart, so what the hook decides by is of its own moment, not the asking call's.
	Now func() time.Time
}

// Authorizer decides and changes grants, on the tables Migrate creates.
type Authorizer struct {
	db  DB
	cfg Config
	// asOf is set on an Authorizer AsOf gave, which reads the past and changes nothing, and history
	// is then the table its views read, by its schema.
	asOf    bool
	history string
	roles   map[Role]RoleDefinition
	// roleSets are the built-in roles' permissions and types as sets.
	roleSets   map[Role]roleSet
	containers map[string]bool
	// containerTypes are the containers' types, sorted.
	containerTypes []string
	kinds          map[PrincipalKind]bool
	// owned are the sources the host owns (Config.Sources).
	owned map[string]bool
	// permissions and types are what the built-in roles give and are for: all a custom role
	// may use. unprivileged are the permissions, each with a type, that a role that isn't
	// privileged gives there: all a public role may give.
	permissions map[Permission]bool
	types       map[string]bool
	// permissionTypes are the types the built-in roles' permissions are for, which a deny's
	// `type:*` may name.
	permissionTypes map[string]bool
	unprivileged    map[permissionOn]bool
	// checked are the permissions the host checks (Config.Permissions), and checkedTypes the
	// resource types a check may name: those the built-in roles are for and those checked
	// permissions are for.
	checked      map[Permission]bool
	checkedTypes map[string]bool
	conds        *conditions
	// labels are the label dimensions (Config.Labels), by name.
	labels map[string]labelDimension
	// clock is the time the call under way decides at (still), nil outside one.
	clock *callClock
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
	labels, err := indexLabels(cfg.Labels, cfg.Catalog)
	if err != nil {
		return nil, err
	}
	// The listings read the catalog in order: from the copies, so that a caller changing its
	// slices after New can't make them disagree with checks or clear a Deny checked here.
	catalog := make([]RoleDefinition, len(cfg.Catalog))
	declared := make(map[Role]bool, len(cfg.Catalog))
	for i, r := range cfg.Catalog {
		catalog[i] = roles[r.ID]
		declared[r.ID] = r.Privileged
	}
	cfg.Catalog = catalog
	cfg.Constraints = slices.Clone(cfg.Constraints)
	// Checks read the declared types of attributes as storing a condition reads them, from copies.
	cfg.Attributes = Attributes{
		Subject: maps.Clone(cfg.Attributes.Subject), Resource: maps.Clone(cfg.Attributes.Resource), Request: maps.Clone(cfg.Attributes.Request),
	}
	containers := map[string]bool{}
	for _, t := range cfg.ContainerTypes {
		if !validName(t) || t == TenantScope || t == GroupScope {
			return nil, fmt.Errorf("rbac: container type %q is not valid", t)
		}
		// Its permissions would read as the dimension's values, so none could change its grants.
		if _, dimension := labels[t]; dimension {
			return nil, fmt.Errorf("rbac: container type %q is named as a label dimension", t)
		}
		containers[t] = true
	}
	kinds := map[PrincipalKind]bool{}
	for _, k := range cfg.PrincipalKinds {
		if !validName(string(k)) || slices.Contains([]PrincipalKind{User, Group, Members, Public}, k) ||
			slices.Contains(reservedKinds, k) || strings.HasPrefix(string(k), "rbac") {
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
	owned := map[string]bool{}
	for _, src := range cfg.Sources {
		if src == "" || src == SourceActivation || !validSource(src) || reservedSource(src) {
			return nil, fmt.Errorf("rbac: source %q is not one the host can own", src)
		}
		owned[src] = true
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
				// A role privileged only because it changes access leaves its other permissions as
				// they were.
				if !declared[r.ID] && !p.managesAccess() {
					unprivileged[permissionOn{p, t}] = true
				}
			}
		}
	}
	permissionTypes := map[string]bool{}
	for p := range perms {
		t, _ := p.parts()
		permissionTypes[t] = true
	}
	checked, checkedTypes, err := vocabulary(cfg.Permissions, perms, resourceTypes)
	if err != nil {
		return nil, err
	}
	conds, err := newConditions(cfg.Attributes)
	if err != nil {
		return nil, err
	}
	return &Authorizer{
		db: db, cfg: cfg, roles: roles, roleSets: setsOf(roles), containers: containers, containerTypes: slices.Sorted(maps.Keys(containers)),
		kinds: kinds, owned: owned, permissions: perms, types: resourceTypes, permissionTypes: permissionTypes, unprivileged: unprivileged,
		checked: checked, checkedTypes: checkedTypes, conds: conds, labels: labels,
	}, nil
}

// vocabulary returns the permissions a host checks, declared or else what the built-in roles
// give, and the resource types a check may name, given what the built-in roles give and are for.
// It refuses a built-in role giving a permission the host declares it never checks.
func vocabulary(declared []Permission, given map[Permission]bool, roleTypes map[string]bool) (map[Permission]bool, map[string]bool, error) {
	checked := maps.Clone(given)
	if len(declared) > 0 {
		checked = map[Permission]bool{}
		for _, p := range declared {
			if !p.Valid() {
				return nil, nil, fmt.Errorf("rbac: permission %q is not `type:verb`", p)
			}
			checked[p] = true
		}
		for _, p := range slices.Sorted(maps.Keys(given)) {
			if !checked[p] {
				return nil, nil, fmt.Errorf("rbac: a built-in role gives %q, which Config.Permissions doesn't list", p)
			}
		}
	}
	types := maps.Clone(roleTypes)
	for p := range checked {
		t, _ := p.parts()
		types[t] = true
	}
	return checked, types, nil
}

// WithTx returns an Authorizer that runs on tx, so its changes commit or roll back with the host's
// own writes. Changes need tx at READ COMMITTED, PostgreSQL's default, and fail in a stricter one,
// whose snapshot can predate the locks they wait for. Their locks last until tx ends, so two
// transactions that change the same scopes or principals in opposite orders can deadlock, as with
// any row locks: PostgreSQL fails one, to be retried. DeleteTenant, SetRole and DeleteRole lock the
// whole tenant, as does any other call that would lock more than 64 scopes and principals: a change
// by an actor, as Apply or ChangeMembers, and Import, DeleteGrants, DeleteScopes, SetMemberships,
// ImportGroups, ImportMembers and DeleteMembers, and so SetDeny from 64 groups named, DeleteGroups
// from 32 groups, which it locks as scopes and principals both, and DeleteGroup from 62 groups the
// group is in, through those they are in, whose locks it holds. Make such a call the first change
// in tx: after another, it waits for every change in the tenant while holding locks they may wait
// for, and PostgreSQL fails one as a deadlock. Where a label dimension is Exclusive, every change
// takes a lock of its tenant's first, which the tenant's other changes wait for, so two
// transactions changing two tenants in opposite orders can deadlock too. Explain, Reachable and
// Holders read in several statements, on tx at its isolation: at READ COMMITTED each reads a
// snapshot of its own, so a change committing between them can mix two states.
func (a *Authorizer) WithTx(tx pgx.Tx) *Authorizer {
	// One AsOf gave reads its own transaction, whose views are the past: on another, it would read
	// the tables as they are now.
	if a.asOf {
		return a
	}
	b := *a
	b.db = tx
	return &b
}

// still returns a for one call, deciding at one time (callClock); under a call already, a.
func (a *Authorizer) still() *Authorizer {
	if a.clock != nil {
		return a
	}
	b := *a
	b.clock = &callClock{host: a.cfg.Now}
	b.cfg.Now = b.clock.now
	return &b
}

// callClock is the time a call decides at: the host's clock read once, where the call first needs
// the time, so every statement it makes and the request.time of every condition it evaluates are
// of one moment. Read apart, a grant or a membership expiring between two readings could meet a
// condition, a deny or label values of a later moment in an answer no single moment gave. A change
// reads it again in its transaction (begin), which first needs it under its locks, where it decides
// again by what committed before them.
type callClock struct {
	host func() time.Time
	at   time.Time
	read bool
}

func (c *callClock) now() time.Time {
	if !c.read {
		c.at, c.read = c.host(), true
	}
	return c.at
}

// GrantInput is a grant Config.ValidateGrant is asked about.
type GrantInput struct {
	Tenant  string
	Scope   Scope
	Binding Binding
	// Role is what the grant gives: the role as defined now, or with ViaRedefinition, as it will be.
	Role RoleDefinition
	// Actor is who makes it: the subject changing grants, setting an eligibility, activating or
	// redefining the role, or Import's actor. Its attributes are a copy of the hook's own.
	Actor Subject
	// Via is how it is made.
	Via Via
}

// Via is how a grant is made.
type Via string

// The ways a grant is made: by Apply, Import or Activate, or as an eligibility SetEligibility
// sets, which is the grant activating it would make. ViaRedefinition is a grant or eligibility
// that exists, which SetRole redefining its custom role makes give more: an eligibility's binding
// is the grant activating it would make, as with ViaEligibility, and has no ID. ViaMembership is a
// grant or eligibility of a group, or of a group it is in, that a member ChangeMembers or
// ImportMembers adds to it gains, its binding naming the member, with no ID, and ending when the
// sooner of it and the membership does.
const (
	ViaApply        Via = "apply"
	ViaImport       Via = "import"
	ViaEligibility  Via = "eligibility"
	ViaActivation   Via = "activation"
	ViaRedefinition Via = "redefinition"
	ViaMembership   Via = "membership"
)

// denied returns the name of the first constraint that removes in.Permission, or "". Each hook is
// asked about copies of its own, so one that writes to what it is given changes neither what is
// decided, its input already validated, nor what a later hook is asked.
func (a *Authorizer) denied(ctx context.Context, in ConstraintInput) (string, error) {
	for _, c := range a.cfg.Constraints {
		deny, err := c.Deny(ctx, a.db, in.copied())
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

// snapshot runs read on an Authorizer that reads one snapshot of the database, as a read made of
// several statements needs, so a change committing between them can't leave it describing a state
// that never was: on a pool, a REPEATABLE READ, READ ONLY transaction of its own, as on a DB that
// wraps one, as isolated says; under WithTx, or on a DB whose Begin gives a savepoint, the host's
// transaction, at its isolation. Constraints run before it, as their hooks may query the pool while
// it holds a connection. A transaction that fails to commit answers nothing, as a failed read does.
func snapshot[T any](ctx context.Context, a *Authorizer, read func(*Authorizer) (T, error)) (T, error) {
	var v T
	in := func(tx pgx.Tx) error {
		var err error
		v, err = read(a.WithTx(tx))
		return err
	}
	var err error
	switch conn := a.db.(type) {
	case ownTx:
		err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, in)
	case pgx.Tx:
		return read(a)
	default:
		var nested bool
		if nested, err = isolated(ctx, conn, "REPEATABLE READ, READ ONLY", in); nested {
			return read(a)
		}
	}
	if err != nil {
		var none T
		return none, err
	}
	return v, nil
}
