package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// InvalidError is a binding a change can't make, with why.
type InvalidError struct {
	Binding Binding
	Reason  string
	// Err is the host's refusal, from Config.ValidateGrant, which the InvalidError wraps so that
	// errors.Is and errors.As find the host's own errors in it; nil for the package's own.
	Err error
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("rbac: %s for %s: %s", e.Binding.Role, e.Binding.Principal.key(), e.Reason)
}

// Is makes an InvalidError match ErrInvalid.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

func (e *InvalidError) Unwrap() error { return e.Err }

// Apply changes the grants on one scope, on, in one transaction, as actor:
//
//   - the actor needs `<on's type>:grant` there (through on, an ancestor or the tenant), and no
//     constraint, nor deny on the path, may remove it, nor on's label (Resource.Labels) refuse it;
//   - through a role with GrantableRoles, the actor may grant and revoke only those roles, and
//     needn't hold their permissions;
//   - through any other role, the actor may grant a role only by holding everything it gives
//     there, none of it removed by a deny on the path or a constraint, for every type the grant
//     reaches, and may revoke any. A role's power to change grants is part of what it gives: one
//     with GrantableRoles needs the power to grant each its holders could, and one without, the
//     unlimited power to change grants on its type;
//   - a conditional power to change grants holds only where its condition does, and what the
//     actor hands on, permissions and power alike, it holds unconditionally or under the
//     condition the grant has: a role a conditional grant lists is granted only under its
//     condition;
//   - a role that gives a `:grant` or `:deny` permission, DefineRoles, ManageGroups or
//     GroupMembers can't be granted to a tenant's members or the public, and only a role marked
//     Public can be granted to the public;
//   - a group granted a role, or one a role is granted on, is one of the tenant's: what a grant
//     naming one that doesn't exist gave would pass to a group made later with its id.
//
// Anonymous subjects change nothing. A grant outlives the actor's own access: revoking that
// access leaves the grants the actor made, as in cloud IAM, so a time-limited power to change
// grants can make lasting ones, to the actor too. Time-limit roles that can't change grants.
//
// Bindings are checked only once the actor may make the change, so a refused actor learns
// nothing about principals. Every invalid binding is reported at once, joined; an error from
// Config.ValidateGrant that isn't ErrInvalid fails the change as it is. Constraints and
// Config.ValidateGrant run before the transaction, on what the Authorizer runs on;
// Config.OnChange runs in it with the grants that changed.
func (a *Authorizer) Apply(ctx context.Context, actor Subject, on Resource, c Change) (err error) {
	defer a.refused(ctx, &err, on.Tenant, actor.Principal, "Apply")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	scope := on.Scope()
	grants, revokes := dedupe(c)
	if len(grants)+len(revokes) == 0 {
		return nil
	}
	if len(grants)+len(revokes) > MaxBindings {
		return fmt.Errorf("%w: a change grants and revokes at most %d bindings", ErrInvalid, MaxBindings)
	}
	for _, b := range grants {
		if b.Source == SourceActivation {
			return &InvalidError{Binding: b, Reason: "only Activate grants from " + SourceActivation}
		}
	}
	return a.change(ctx, actor, on, "Apply", ViaApply, grants, revokes, nil, nil, func(tx pgx.Tx) (ChangeEvent, error) {
		revoked, err := a.revoke(ctx, tx, on.Tenant, scope, revokes, grants)
		if err != nil {
			return ChangeEvent{}, err
		}
		// A revoke by ID removes a grant from any source: refusing one from a source the host owns
		// rolls the removal back.
		var owned []error
		for _, g := range revoked {
			if a.owned[g.Source] {
				owned = append(owned, ownedRevoke(g.Binding))
			}
		}
		if err := errors.Join(owned...); err != nil {
			return ChangeEvent{}, err
		}
		granted, err := a.upsert(ctx, tx, on.Tenant, actor.Principal, scopeGrants(scope, grants))
		return ChangeEvent{Granted: granted, Revoked: revoked}, err
	})
}

// ownedRevoke refuses revoking a grant from a source the host owns, which only DeleteGrants removes.
func ownedRevoke(b Binding) error {
	return &InvalidError{Binding: b, Reason: "only the host revokes from " + b.Source + ", through DeleteGrants"}
}

// change makes a change to the grants on one scope as actor, or to eligibilities, which are
// grants to come, with Apply's checks before its transaction and again under its locks, and
// then write. how is the call that makes it, named are the principals it names besides its
// bindings', such as an eligibility's approvers, and check is what else the change needs, run
// once the actor may make it.
func (a *Authorizer) change(ctx context.Context, actor Subject, on Resource, how string, via Via, grants, revokes []Binding,
	named []Principal, check func() error, write func(pgx.Tx) (ChangeEvent, error),
) error {
	scope := on.Scope()
	au, cs, err := a.mayChangeGrants(ctx, actor, on, grants, revokes)
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	stand, err := a.stand(ctx, a.db, on.Tenant, bindingPrincipals(grants))
	if err != nil {
		return err
	}
	if err := a.validate(ctx, au.roles, actor, via, on.Tenant, scope, grants, revokes); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, how, func(tx pgx.Tx) (ChangeEvent, error) {
		// One change to a scope at a time, so two changes can't deadlock on its rows.
		principals := map[string]bool{}
		for _, b := range slices.Concat(grants, revokes) {
			principals[b.Principal.key()] = true
		}
		groups := groupKeys(slices.Concat(bindingPrincipals(grants), named))
		for _, k := range groups {
			principals[k] = true
		}
		if err := lockAll(ctx, tx, on.Tenant, []string{scope.Key()}, slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		exist := groups
		if len(grants) > 0 {
			exist = slices.Concat(groups, groupScopes([]Scope{scope}))
		}
		if err := groupsExist(ctx, tx, on.Tenant, exist); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.stillStanding(ctx, tx, on.Tenant, stand); err != nil {
			return ChangeEvent{}, err
		}
		// Decided again in the transaction, so the actor's access and the roles are read as the
		// change is made: a custom role deleted or redefined since is granted only as it is now.
		// The constraints aren't asked again, as hooks run outside it.
		cs.seal()
		now, err := a.mayChange(ctx, tx, actor, on, grants, revokes, cs)
		if err != nil {
			return ChangeEvent{}, err
		}
		var bad []error
		for _, b := range grants {
			bad = append(bad, a.checkBinding(now.roles, on.Tenant, scope, b, a.cfg.Now())...)
		}
		if err := errors.Join(bad...); err != nil {
			return ChangeEvent{}, err
		}
		if err := redefinedSince(au.roles, now.roles, roleIDs(grants)); err != nil {
			return ChangeEvent{}, err
		}
		return write(tx)
	})
}

// standing is what a host's answer about grants to principals rests on, as the package keeps it:
// each identity's membership of the tenant, and the identities in each group with theirs. It is
// read before the host is asked, and again under the change's locks, which a change to it takes
// too, so a change made between them is tried again rather than made on an answer about another
// state: as a grant to an identity that has left the tenant, or to a group a guest joined
// meanwhile, of a role the host refuses guests. The memberships of a group's members are read
// with it, but their changes take the member's lock alone.
type standing struct {
	principals []Principal
	// by is, for each identity and group, its identities' memberships, each `principal=membership`:
	// an element, not a line, as an identity's id can hold a newline, and no membership an '='.
	by map[string][]string
}

// stand reads the standing of principals in a tenant on q.
func (a *Authorizer) stand(ctx context.Context, q DB, tenant string, principals []Principal) (standing, error) {
	s := standing{principals: principals}
	var identities, groups []string
	for _, p := range principals {
		switch {
		// Neither the broad nor one whose id is no id is anyone's member: a change refuses the
		// latter.
		case p.broad() || !validID(p.ID):
		case p.Kind == Group:
			groups = append(groups, p.ID)
		default:
			identities = append(identities, p.key())
		}
	}
	if len(identities)+len(groups) == 0 {
		return s, nil
	}
	// Joined in the statement, as a group can have many members; an end as seconds since the epoch,
	// which read the same whatever the session's time zone.
	rows, err := q.Query(ctx, `
		WITH RECURSIVE `+insideSQL("$3", "$4")+`, of(root, principal) AS (
		  SELECT 'group:' || root, principal FROM inside
		  UNION SELECT p, p FROM unnest($2::text[]) AS p
		)
		SELECT o.root, array_agg(o.principal || '=' || coalesce(m.guest::text || ' ' || m.suspended::text || ' ' ||
		  coalesce(extract(epoch FROM m.expires_at)::text, ''), '') ORDER BY o.principal)
		FROM of o LEFT JOIN rbac_memberships m ON m.tenant = $1 AND m.principal = o.principal
		GROUP BY o.root`, tenant, identities, groups, a.cfg.Now())
	if err != nil {
		return standing{}, err
	}
	s.by = map[string][]string{}
	var root string
	var members []string
	_, err = pgx.ForEachRow(rows, []any{&root, &members}, func() error {
		s.by[root] = members
		return nil
	})
	return s, err
}

// stillStanding refuses, under a change's locks, a change whose principals' standing has changed
// since the host was asked about it.
func (a *Authorizer) stillStanding(ctx context.Context, tx pgx.Tx, tenant string, was standing) error {
	now, err := a.stand(ctx, tx, tenant, was.principals)
	if err != nil {
		return err
	}
	if !maps.EqualFunc(now.by, was.by, slices.Equal) {
		return fmt.Errorf("%w: a membership the host was asked about changed while this change waited for it; try again", ErrConflict)
	}
	return nil
}

// mayChangeGrants checks, before a change's transaction, that actor may make grants and revokes on on: it
// holds the power to change grants there, which on's label takes too, not stopped by a constraint,
// and may hand each on. It returns that authority and the constraints it asked, which the
// transaction reads back rather than ask again.
func (a *Authorizer) mayChangeGrants(ctx context.Context, actor Subject, on Resource, grants, revokes []Binding) (authority, *constrained, error) {
	cs := a.constrain(ctx, actor, on)
	if err := a.changing(actor, on, cs); err != nil {
		return authority{}, nil, err
	}
	if dim, err := a.unsatisfied(ctx, actor, on); err != nil || dim != "" {
		return authority{}, nil, cmp.Or(err, error(&DeniedError{Permission: GrantPermission(on.Type), Scope: on.Scope(), Reason: labelRefusal(dim)}))
	}
	au, err := a.mayChange(ctx, a.db, actor, on, grants, revokes, cs)
	return au, cs, err
}

// changing refuses a change to grants on a scope of a type the host doesn't have, as a typo no
// actor could hold `<type>:grant` on, by an anonymous actor, or one a constraint on
// `<type>:grant` stops. The constraints run outside the transaction: one that queries the pool
// while the transaction holds a connection can wait forever on a busy pool. Asked through cs, so
// handing on that power on the same scope reads the answer rather than asking again.
func (a *Authorizer) changing(actor Subject, on Resource, cs *constrained) error {
	if err := a.scopeOf(on); err != nil {
		return err
	}
	manage := GrantPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: manage, Scope: on.Scope(), Reason: "an anonymous subject changes nothing"}
	}
	if cs.removes(manage, on.Type) {
		return cmp.Or(cs.failed(), error(&DeniedError{Permission: manage, Scope: on.Scope(), Reason: "removed by " + cs.removedBy(manage)}))
	}
	return nil
}

// A change takes its tenant's lock shared, then the lock of each scope and of each principal
// whose grants it changes, in order; deleting a tenant takes the tenant's lock alone. So two
// changes to the same rows run in turn. A change that also changes rows it doesn't lock, as
// deleting groups changes denies and eligibilities on other scopes and SetMemberships removes an
// ended membership's places in groups, can still deadlock with another change: PostgreSQL ends
// one, which matches ErrConflict. The locks last until the
// transaction ends. Advisory locks span the database, so the keys name the
// schema: another application's grants are in a schema of their own.
const lockKey = `hashtextextended(current_schema() || '/rbac/' || $1, 0)`

// maxLocks is how many scopes and principals a change locks one by one; a larger one locks the
// tenant, rather than fill PostgreSQL's lock table, which every session shares.
const maxLocks = 64

func lock(ctx context.Context, tx pgx.Tx, tenant string, scopes, principals []string) error {
	b := &pgx.Batch{}
	b.Queue(`SELECT current_setting('transaction_isolation')`)
	b.Queue(`SELECT pg_advisory_xact_lock_shared(`+lockKey+`)`, "tenant/"+tenant)
	for _, s := range slices.Compact(slices.Sorted(slices.Values(scopes))) {
		b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "scope/"+tenant+"/"+s)
	}
	for _, p := range slices.Compact(slices.Sorted(slices.Values(principals))) {
		b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "principal/"+tenant+"/"+p)
	}
	return locked(tx.SendBatch(ctx, b))
}

// lockAll locks scopes and principals one by one, or past maxLocks the tenant.
func lockAll(ctx context.Context, tx pgx.Tx, tenant string, scopes, principals []string) error {
	if len(scopes)+len(principals) > maxLocks {
		return lockTenant(ctx, tx, tenant)
	}
	return lock(ctx, tx, tenant, scopes, principals)
}

func lockTenant(ctx context.Context, tx pgx.Tx, tenant string) error {
	b := &pgx.Batch{}
	b.Queue(`SELECT current_setting('transaction_isolation')`)
	b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "tenant/"+tenant)
	return locked(tx.SendBatch(ctx, b))
}

// locked reads a lock batch, whose first query is the transaction's isolation, and refuses a
// change stricter than READ COMMITTED: its snapshot can predate the locks, so its checks could
// read grants as they were before a change the locks waited for.
func locked(br pgx.BatchResults) error {
	var level string
	if err := br.QueryRow().Scan(&level); err != nil {
		_ = br.Close()
		return err
	}
	if err := br.Close(); err != nil {
		return err
	}
	if level != "read committed" {
		return fmt.Errorf("rbac: a change runs at READ COMMITTED, not %s", strings.ToUpper(level))
	}
	return nil
}

// Import stores grants as actor without the checks Apply makes of an actor, for migrations,
// seeding, restores and the host's own grants: give whoever creates a resource or container a
// role on it, in the same transaction through WithTx. actor is who the grants are recorded as
// made by, such as the creator or the host's own service account. Each grant is still
// validated, and Config.ValidateGrant asked about it, via ViaImport. Grants from
// SourceActivation are refused, as only Activate makes them: a restore leaves them out.
func (a *Authorizer) Import(ctx context.Context, actor Principal, tenant string, grants []Grant) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "Import")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(grants) == 0 {
		return nil
	}
	if len(grants) > MaxBindings {
		return fmt.Errorf("%w: an import stores at most %d grants", ErrInvalid, MaxBindings)
	}
	grants = slices.Clone(grants)
	var conditions []error
	for i := range grants {
		grants[i].ExpiresAt = stored(grants[i].ExpiresAt)
		conditions = append(conditions, a.checkCondition(grants[i].Binding)...)
		if grants[i].Source == SourceActivation {
			conditions = append(conditions, &InvalidError{Binding: grants[i].Binding, Reason: "only Activate grants from " + SourceActivation})
		}
	}
	check := func(read func(context.Context, DB, string, []Role) (book, error), q DB, errs ...error) (book, error) {
		roles, err := read(ctx, q, tenant, roleIDs(grants))
		if err != nil {
			return book{}, err
		}
		for _, g := range grants {
			if !g.Scope.in(tenant) {
				errs = append(errs, &InvalidError{Binding: g.Binding, Reason: fmt.Sprintf("scope %q is not valid", g.Scope.Key())})
				continue
			}
			errs = append(errs, a.checkBinding(roles, tenant, g.Scope, g.Binding, a.cfg.Now())...)
		}
		return roles, errors.Join(errs...)
	}
	roles, err := check(a.tenantBook, a.db, conditions...)
	if err != nil {
		return err
	}
	named := make([]Principal, len(grants))
	for i, g := range grants {
		named[i] = g.Principal
	}
	stand, err := a.stand(ctx, a.db, tenant, named)
	if err != nil {
		return err
	}
	var refused []error
	for _, g := range grants {
		bad, err := a.allowed(ctx, roles, Subject{Principal: actor}, ViaImport, tenant, g.Scope, g.Binding)
		if err != nil {
			return err
		}
		refused = append(refused, bad...)
	}
	if err := errors.Join(refused...); err != nil {
		return err
	}
	scopes, principals := map[string]bool{}, map[string]bool{}
	on := make([]Scope, len(grants))
	for i, g := range grants {
		scopes[g.Scope.Key()] = true
		principals[g.Principal.key()] = true
		on[i] = g.Scope
	}
	return a.inTx(ctx, tenant, actor, "Import", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, slices.Collect(maps.Keys(scopes)), slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		if err := groupsExist(ctx, tx, tenant, slices.Concat(groupKeys(named), groupScopes(on))); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.stillStanding(ctx, tx, tenant, stand); err != nil {
			return ChangeEvent{}, err
		}
		// Again under the locks, so a custom role deleted since isn't granted, nor one redefined
		// since the host was asked about it.
		now, err := check(a.tenantBook, tx)
		if err != nil {
			return ChangeEvent{}, err
		}
		if err := redefinedSince(roles, now, roleIDs(grants)); err != nil {
			return ChangeEvent{}, err
		}
		granted, err := a.upsert(ctx, tx, tenant, actor, grants)
		return ChangeEvent{Granted: granted}, err
	})
}

// dedupe drops repeated bindings: of grants that are one grant, it keeps the last, whose note is
// the one stored. What is left keeps the order given, as errors report it.
func dedupe(c Change) (grants, revokes []Binding) {
	granted := map[grantKey]bool{}
	for _, b := range slices.Backward(c.Grant) {
		b.ExpiresAt = stored(b.ExpiresAt)
		if k := keyOf(b); !granted[k] {
			granted[k] = true
			grants = append(grants, b)
		}
	}
	slices.Reverse(grants)
	type revoke struct {
		role       Role
		p          Principal
		source, id string
	}
	revoked := map[revoke]bool{}
	for _, b := range c.Revoke {
		if k := (revoke{b.Role, b.Principal, b.Source, b.ID}); !revoked[k] {
			revoked[k] = true
			revokes = append(revokes, b)
		}
	}
	return grants, revokes
}

// grantKey is what makes a grant on a scope one grant: its role, principal, source, expiry and
// condition.
type grantKey struct {
	role      Role
	p         Principal
	source    string
	expires   int64
	condition string
}

func keyOf(b Binding) grantKey {
	var expires int64
	if !b.ExpiresAt.IsZero() {
		expires = b.ExpiresAt.UnixMicro()
	}
	return grantKey{b.Role, b.Principal, b.Source, expires, b.Condition.Expression}
}

// validate checks the bindings against the roles mayChange read, and asks the host about each
// grant otherwise valid.
func (a *Authorizer) validate(ctx context.Context, roles book, actor Subject, via Via, tenant string, scope Scope, grants, revokes []Binding) error {
	var errs []error
	now := a.cfg.Now()
	for _, b := range grants {
		bad := append(a.checkBinding(roles, tenant, scope, b, now), a.checkCondition(b)...)
		if a.owned[b.Source] {
			bad = append(bad, &InvalidError{Binding: b, Reason: "only the host grants from " + b.Source + ", through Import"})
		}
		if len(bad) == 0 {
			refused, err := a.allowed(ctx, roles, actor, via, tenant, scope, b)
			if err != nil {
				return err
			}
			bad = refused
		}
		errs = append(errs, bad...)
	}
	for _, b := range revokes {
		errs = append(errs, checkRevoke(tenant, b)...)
		// One by ID matches a grant from any source, so Apply checks the grant it removes instead.
		if b.ID == "" && a.owned[b.Source] {
			errs = append(errs, ownedRevoke(b))
		}
	}
	return errors.Join(errs...)
}

// checkRevoke returns why a revoke can't name a grant in a tenant. A role no longer in the
// catalog, or a kind no longer declared, can still be revoked.
func checkRevoke(tenant string, b Binding) []error {
	var errs []error
	if !b.Principal.wellFormed(tenant) {
		errs = append(errs, &InvalidError{Binding: b, Reason: "the principal is not valid"})
	}
	// No grant has no role, so a revoke without one, as by ID alone, would revoke nothing.
	if b.Role == "" {
		errs = append(errs, &InvalidError{Binding: b, Reason: "a revoke names its role, by ID too"})
	}
	if !validText(string(b.Role)) || !validText(b.Source) || !validText(b.ID) {
		errs = append(errs, &InvalidError{Binding: b, Reason: "a revoke's role, source and ID are text without NUL"})
	}
	return errs
}

// allowed asks Config.ValidateGrant about a grant, and returns why it refused, or the error that
// fails the change.
func (a *Authorizer) allowed(ctx context.Context, roles book, actor Subject, via Via, tenant string, scope Scope, b Binding) ([]error, error) {
	role, _ := roles.role(b.Role)
	err := a.cfg.ValidateGrant(ctx, a.db, GrantInput{Tenant: tenant, Scope: scope, Binding: b, Role: role.clone(), Actor: actor, Via: via})
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, ErrInvalid):
		return []error{&InvalidError{Binding: b, Reason: hostReason(err), Err: err}}, nil
	}
	return nil, err
}

// hostReason is the host's message for a grant it refused, less the ErrInvalid it wraps, which
// the InvalidError already says, whether before, after or joined; or the reason of an InvalidError
// of its own, which would otherwise name the binding twice.
func hostReason(err error) string {
	var own *InvalidError
	if errors.As(err, &own) {
		return cmp.Or(own.Reason, "refused by the host")
	}
	invalid := ErrInvalid.Error()
	msg := strings.TrimSuffix(strings.TrimSuffix(err.Error(), ": "+invalid), "\n"+invalid)
	if rest, ok := strings.CutPrefix(msg, invalid); ok && (rest == "" || rest[0] == ':' || rest[0] == '\n') {
		msg = strings.TrimLeft(rest, ": \n")
	}
	return cmp.Or(msg, "refused by the host")
}

// identity checks that an actor a call names is an identity: a user or a declared kind.
func (a *Authorizer) identity(actor Principal) error {
	if !a.acts(actor.Kind) || !validID(actor.ID) {
		return fmt.Errorf("%w: the actor is not a user or declared kind with an id of text without NUL of at most %d bytes", ErrInvalid, MaxID)
	}
	return nil
}

// checkBinding returns why a binding can't be granted on a scope in a tenant.
func (a *Authorizer) checkBinding(roles book, tenant string, scope Scope, b Binding, now time.Time) []error {
	var errs []error
	bad := func(reason string) { errs = append(errs, &InvalidError{Binding: b, Reason: reason}) }
	if !a.known(tenant, b.Principal) {
		bad("the principal is not valid")
	}
	def, ok := roles.role(b.Role)
	switch {
	case !ok:
		bad("no such role")
	case !a.grantableOn(def, scope.Type):
		bad(fmt.Sprintf("can't be granted on a %s", scope.Type))
	case b.Principal.broad() && def.managesAccess():
		bad("a role that changes access can't be granted to a tenant's members or the public")
	case b.Principal.Kind == Public && !def.Public:
		bad("the role can't be granted to the public")
	case b.Principal.Kind == Members && def.Privileged:
		bad("a privileged role is never granted to the tenant's members")
	}
	if reason := checkExpiry(b.ExpiresAt, now); reason != "" {
		bad(reason)
	}
	if !validNote(b.Note) {
		bad(fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	if reason := checkSource(b.Source); reason != "" {
		bad(reason)
	}
	return errs
}

var sourceName = regexp.MustCompile(`^([a-z][a-z0-9._:/-]{0,62})?$`)

func validSource(s string) bool { return sourceName.MatchString(s) }

// reservedSource reports whether a source is one a later release may name for grants of its own.
func reservedSource(s string) bool { return strings.HasPrefix(s, "rbac") }

func validNote(s string) bool { return utf8.RuneCountInString(s) <= MaxNote && validText(s) }

// checkCondition returns why a binding's condition can't be stored. It reads nothing stored, so a
// change checks it once, before its transaction: compiling a condition can take milliseconds,
// which a change of many shouldn't spend holding its locks.
func (a *Authorizer) checkCondition(b Binding) []error {
	var errs []error
	for _, reason := range a.conditionFaults(b.Condition) {
		errs = append(errs, &InvalidError{Binding: b, Reason: reason})
	}
	return errs
}

// conditionFaults returns why a condition, of a grant or a deny, can't be stored.
func (a *Authorizer) conditionFaults(c Condition) []string {
	var faults []string
	bad := func(reason string) { faults = append(faults, reason) }
	switch {
	// Each alone: a character split between two is valid only once they are joined.
	case !validText(c.Title) || !validText(c.Description) || !validText(c.Expression):
		bad("a condition is UTF-8 text without NUL")
	case c.Expression != "":
		if err := a.conds.check(c.Expression); err != nil {
			bad(err.Error())
		}
	case c != Condition{}:
		// Stored, it would read as a condition on a grant that has none.
		bad("a condition with a title or description has an expression")
	}
	if utf8.RuneCountInString(c.Title) > MaxName || utf8.RuneCountInString(c.Description) > MaxDescription {
		bad(fmt.Sprintf("a condition's title is at most %d characters and its description %d", MaxName, MaxDescription))
	}
	return faults
}

// authority is an actor's grants on a resource's path, and the roles to read them by.
type authority struct {
	held  []holding
	roles book
	// allows reports whether a grant's condition holds for the request, with an action.
	allows func(h holding, action Permission) bool
	// denied reports whether a deny on the path removes p from the actor in the request, on the
	// scope itself. handsOn is the same for what the actor hands on, which through a container or
	// the tenant reaches other resources: a deny whose condition reads the resource can't be
	// evaluated for them, so it denies. What a deny removes the actor can't use or hand on.
	denied, handsOn func(p Permission) bool
	// defining is a custom role SetRole checks: the roles a check names resolve to it, but the
	// actor's own grants of it give what it gives now.
	defining *RoleDefinition
	// constrained is what the constraints remove from the actor, which it can't hand on.
	constrained *constrained
}

// constrained is what the constraints remove from an actor handing permissions on through a
// change on a scope, as a deny removes them: the actor can't hand on what it can't use. Each is
// asked about once, before the change's transaction, and read back in it, as hooks run outside
// it. Asked about none, as for a call that hands nothing on, it removes everything.
type constrained struct {
	a     *Authorizer
	ctx   context.Context
	actor Subject
	on    Resource
	asked map[permissionOn]bool
	// by names the constraint that removed each permission, for a refusal to say.
	by  map[Permission]string
	err error
	// sealed is set in the transaction, where a permission not asked about before is one the change
	// came to need since, as for a role redefined meanwhile: missed refuses it, to be tried again.
	sealed, missed bool
}

func (a *Authorizer) constrain(ctx context.Context, actor Subject, on Resource) *constrained {
	return &constrained{a: a, ctx: ctx, actor: actor, on: on, asked: map[permissionOn]bool{}, by: map[Permission]string{}}
}

func (c *constrained) seal() { c.sealed = true }

// removes reports whether a constraint removes p on resources of a type from the actor, failing
// closed. The constraints are asked about the scope the change is on, a container or the tenant
// too, as a deny on that scope's path binds what the actor hands on there: a constraint that
// tells one container from another, as a freeze does, binds only where it removes p.
func (c *constrained) removes(p Permission, resourceType string) bool {
	if c == nil {
		return true
	}
	k := permissionOn{p, resourceType}
	if removed, ok := c.asked[k]; ok {
		return removed
	}
	if c.sealed {
		c.missed = true
		return true
	}
	// The call fails with the error anyway, so a slow or failing hook isn't asked again.
	if c.err != nil {
		return true
	}
	// Copies, so a hook that changes what it is asked about can't change what later ones are.
	actor, on := c.actor, c.on
	name, err := c.a.denied(c.ctx, ConstraintInput{Tenant: on.Tenant, ResourceType: resourceType, Permission: p, Subject: &actor, Resource: &on})
	if err != nil {
		c.err = err
	}
	if name != "" {
		c.by[p] = name
	}
	c.asked[k] = name != "" || err != nil
	return c.asked[k]
}

// removedBy names the constraint that removed p from the actor, or "".
func (c *constrained) removedBy(p Permission) string {
	if c == nil {
		return ""
	}
	return c.by[p]
}

// refusal is why the actor can't do what, lacking p: the constraint that removed p, or otherwise.
func (c *constrained) refusal(what string, p Permission, otherwise string) string {
	if name := c.removedBy(p); name != "" {
		return fmt.Sprintf("the actor can't %s while %s removes %s from it", what, name, p)
	}
	return otherwise
}

// failed returns what asking the constraints failed with, or a conflict where the transaction
// needed one not asked about: either outranks what the answers decided.
func (c *constrained) failed() error {
	switch {
	case c == nil:
		return nil
	case c.err != nil:
		return c.err
	case c.missed:
		return fmt.Errorf("%w: what this change hands on changed while it waited; try again", ErrConflict)
	}
	return nil
}

// named resolves a role a check names, as granted or listed rather than held.
func (au authority) named(id Role) (RoleDefinition, bool) {
	if au.defining != nil && au.defining.ID == id {
		return *au.defining, true
	}
	return au.roles.role(id)
}

// power is what an actor may change on scopes of a type: any role it holds everything of, and
// revoke any, or only the listed roles, without holding them.
type power struct {
	any bool
	// listed are the conditions of the grants that list each role, empty for none: a role listed
	// only by a conditional grant is the actor's to grant only under that condition, as a role
	// held only under one is, or a grant could drop it.
	listed map[Role][]string
}

func (p power) none() bool { return !p.any && len(p.listed) == 0 }

// lists reports whether the power lets the actor grant r with condition.
func (p power) lists(r Role, condition string) bool {
	return slices.ContainsFunc(p.listed[r], func(c string) bool { return c == "" || c == condition })
}

// authorityOn reads the actor's grants on a resource's path, and the roles they and the call
// name. With a custom role among them it reads all the tenant's, which a role's GrantableRoles
// can name.
func (a *Authorizer) authorityOn(ctx context.Context, q DB, actor Subject, on Resource, roles []Role) (authority, error) {
	held, ds, _, err := a.heldOrDenied(ctx, q, on.Tenant, actor, all, on.path(), "", noRoles)
	if err != nil {
		return authority{}, err
	}
	b, err := a.tenantBook(ctx, q, on.Tenant, append(roleIDs(held), roles...))
	if err != nil {
		return authority{}, err
	}
	return a.authorityOf(ctx, q, actor, on, held, ds, b)
}

// orDenied is a deny check that also denies what more does.
func orDenied(denied, more func(Permission) bool) func(Permission) bool {
	return func(p Permission) bool { return more(p) || denied(p) }
}

// authorityOf is the authority of held grants under the denies on the path, reading the
// grants' conditions.
func (a *Authorizer) authorityOf(ctx context.Context, q DB, actor Subject, on Resource, held []holding, ds []denial, b book) (authority, error) {
	if err := a.conditionsOf(ctx, q, on.Tenant, held); err != nil {
		return authority{}, err
	}
	vars, spend := a.vars(ctx, actor, "", on), newBudget()
	// The cheapest conditions first, as callers evaluate them in this order, so what a budget run
	// out decides doesn't rest on ids.
	held = slices.Clone(held)
	cheapestFirst(held, holding.expression)
	with := func(vars map[string]any, action Permission) map[string]any {
		v := maps.Clone(vars)
		v["action"] = string(action)
		return v
	}
	deny := func(vars map[string]any) func(Permission) bool {
		denied := map[Permission]bool{}
		return func(p Permission) bool {
			if d, ok := denied[p]; ok {
				return d
			}
			// On a budget of its own, as a check of p would be.
			_, d := a.deniedBy(ds, p, newDenyBudget(on.path()), with(vars, p))
			denied[p] = d
			return d
		}
	}
	// On a resource, what the actor hands on reaches only it, as what it does there does.
	denied := deny(vars)
	handsOn := denied
	if a.contains(on.Type) {
		reached := maps.Clone(vars)
		delete(reached, "resource")
		handsOn = deny(reached)
	}
	// The values of an exclusive dimension it holds none of, as its grants could give it two, it
	// can't use or hand on either, as checks refuse it them. Read from its grants on the path, which
	// hold its tenant's, so a change's recheck in its transaction asks no constraint.
	if excluded := a.excludedBy(b, held); len(excluded) > 0 {
		out := func(p Permission) bool { t, ok := a.exclusiveValue(p); return ok && excluded[t] }
		denied, handsOn = orDenied(denied, out), orDenied(handsOn, out)
	}
	return authority{
		held: held, roles: b,
		allows: func(h holding, action Permission) bool {
			return !h.conditional || a.conds.holds(spend, h.Condition.Expression, with(vars, action))
		},
		denied: denied, handsOn: handsOn,
	}, nil
}

// over is what the actor's grants let it change on scopes of a type in this request: a
// conditional grant gives its power only where its condition holds for the change.
func (au authority) over(scopeType string) power {
	manage := GrantPermission(scopeType)
	return au.power(scopeType, au.denied, func(g holding) bool { return au.allows(g, manage) })
}

// under is the power the actor may hand on with condition, as holds counts permissions: a power
// held under a condition can't be handed on without it, nor one a constraint removes.
func (au authority) under(scopeType, condition string) power {
	pw := au.power(scopeType, au.handsOn, func(g holding) bool { return g.under(condition) })
	// Asked only of a power the actor holds, as each ask calls the hooks.
	if !pw.none() && au.constrained.removes(GrantPermission(scopeType), scopeType) {
		return power{listed: map[Role][]string{}}
	}
	return pw
}

func (au authority) power(scopeType string, denied func(Permission) bool, counts func(holding) bool) power {
	pw := power{listed: map[Role][]string{}}
	manage := GrantPermission(scopeType)
	if denied(manage) {
		return pw
	}
	for _, g := range au.held {
		if !gives(au.roles, g, manage, scopeType) || !counts(g) {
			continue
		}
		def, _ := au.roles.role(g.Role)
		if len(def.GrantableRoles) == 0 {
			pw.any = true
		}
		for _, r := range def.GrantableRoles {
			pw.listed[r] = append(pw.listed[r], g.Condition.Expression)
		}
	}
	return pw
}

// under reports whether a grant gives what it gives under condition: unconditionally, or under
// the same condition, so a grant can't drop one its granter is bound by.
func (h holding) under(condition string) bool {
	return !h.conditional || sameFor(h.Condition.Expression, condition)
}

// sameFor reports whether holding under one condition is holding under another for whoever is
// granted it: the same condition, of the request and the resource. One that reads the subject
// decides for each holder, so the actor's holding under it says nothing of what it hands on.
func sameFor(held, condition string) bool {
	return held == condition && !readsSubject(condition)
}

// holds reports whether the actor holds p for resources of a type, to hand it on with condition:
// neither a deny nor a constraint removes it.
func (au authority) holds(p Permission, resourceType, condition string) bool {
	return !au.handsOn(p) && slices.ContainsFunc(au.held, func(g holding) bool {
		return gives(au.roles, g, p, resourceType) && g.under(condition)
	}) && !au.constrained.removes(p, resourceType)
}

// may reports whether the actor may do p, on resources of a type, in this request.
func (au authority) may(p Permission, resourceType string) bool {
	return !au.denied(p) && slices.ContainsFunc(au.held, func(g holding) bool {
		return gives(au.roles, g, p, resourceType) && au.allows(g, p)
	})
}

// mayGrant reports whether the actor may grant def on a scope of a type, with condition, and if
// not, a permission it lacks: its power there, pw, lists def, or lets it grant any role and it
// holds everything def gives. pw is over for a grant the actor makes, and under for one a grant
// it makes would let others make. seen is holdsRole's: fresh for each grant decided, or what
// grants already allowed proved.
func (a *Authorizer) mayGrant(au authority, pw power, scopeType string, def RoleDefinition, condition string, seen map[string]bool) (Permission, bool) {
	if pw.lists(def.ID, condition) {
		return "", true
	}
	if !pw.any {
		return GrantPermission(scopeType), false
	}
	// On a container or the tenant the grant reaches every type the role is for; on a resource,
	// its own type.
	types := []string{scopeType}
	if a.contains(scopeType) {
		types = def.ResourceTypes
	}
	return a.holdsRole(au, def, types, condition, seen)
}

// holdsRole reports whether the actor holds everything def gives for each of types, and if
// not, a permission it lacks. A permission to change grants on a type gives a power there: to
// grant any role, or the listed ones. The actor must have as much, or a grant could hand on
// more than it has: an unlimited one itself, or the power to grant each listed role that can
// be granted there.
//
// seen are the roles, with the types their grant reaches, already checked or being checked for
// this grant. Each is checked once: the grant needs every check to pass, so checking one again,
// as for a role that lists itself or one that lists it back, adds nothing. Without it, roles
// listing each other would be checked along every order they can be reached in.
func (a *Authorizer) holdsRole(au authority, def RoleDefinition, types []string, condition string, seen map[string]bool) (Permission, bool) {
	key := string(def.ID) + " " + strings.Join(types, ",") + " " + condition
	if seen[key] {
		return "", true
	}
	seen[key] = true
	for _, p := range def.Permissions {
		t, verb := p.parts()
		// Where the grant doesn't reach scopes of t, its t:grant changes no grants there: it is a
		// permission like any other.
		if verb != "grant" || !slices.Contains(types, t) {
			for _, rt := range types {
				if !au.holds(p, rt, condition) {
					return p, false
				}
			}
			continue
		}
		// The holders' power holds under the condition the grant has, so the actor's must too.
		pw := au.under(t, condition)
		if len(def.GrantableRoles) == 0 {
			if !pw.any {
				return p, false
			}
			continue
		}
		for _, id := range def.GrantableRoles {
			listed, known := au.named(id)
			if !known {
				return p, false
			}
			// Its holders can't grant a role on a scope that can't take it.
			if !a.grantableOn(listed, t) {
				continue
			}
			// Its holders may grant it under the grant's condition, or with any if it has none.
			if missing, ok := a.mayGrant(au, pw, t, listed, condition, seen); !ok {
				return missing, false
			}
		}
	}
	return "", true
}

// mayChange checks the actor's own access on the scope against the change, once Apply has
// checked the constraints on changing it, and returns what it read; cs are those on what the
// actor hands on.
func (a *Authorizer) mayChange(ctx context.Context, q DB, actor Subject, on Resource, grants, revokes []Binding, cs *constrained) (authority, error) {
	scope := on.Scope()
	manage := GrantPermission(scope.Type)
	au, err := a.authorityOn(ctx, q, actor, on, roleIDs(grants))
	if err != nil {
		return authority{}, err
	}
	au.constrained = cs
	pw := au.over(scope.Type)
	if pw.none() {
		return authority{}, &DeniedError{Permission: manage, Scope: scope, Reason: "the actor may not change access here"}
	}
	var errs []error
	for _, b := range revokes {
		if !pw.any && len(pw.listed[b.Role]) == 0 {
			errs = append(errs, &DeniedError{Permission: manage, Scope: scope, Reason: fmt.Sprintf("the actor may not revoke %s here", b.Role)})
		}
	}
	for _, b := range grants {
		def, known := au.roles.role(b.Role)
		if !known || !a.grantableOn(def, scope.Type) {
			// validate reports it as invalid rather than as an escalation.
			continue
		}
		if p, ok := a.mayGrant(au, pw, scope.Type, def, b.Condition.Expression, map[string]bool{}); !ok {
			reason := cs.refusal("grant "+string(b.Role), p, fmt.Sprintf("the actor can't grant %s without holding %s here", b.Role, p))
			switch {
			case !pw.any && len(pw.listed[b.Role]) > 0:
				reason = fmt.Sprintf("the actor may grant %s here only under the condition of a grant that lists it", b.Role)
			case !pw.any:
				reason = fmt.Sprintf("the actor may not grant %s here", b.Role)
			}
			errs = append(errs, &DeniedError{Permission: p, Scope: scope, Reason: reason})
		}
	}
	if err := cs.failed(); err != nil {
		return authority{}, err
	}
	return au, errors.Join(errs...)
}

// Grantable lists the roles the subject may grant on r, built-in ones in catalog order and then
// the tenant's custom ones, for an access screen to offer.
func (a *Authorizer) Grantable(ctx context.Context, s Subject, r Resource) ([]RoleDefinition, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if err := a.scopeOf(r); err != nil {
		return nil, err
	}
	if err := a.subject(s); err != nil {
		return nil, err
	}
	if dim, err := a.unsatisfied(ctx, s, r); err != nil || dim != "" {
		return nil, err
	}
	cs := a.constrain(ctx, s, r)
	if cs.removes(GrantPermission(r.Type), r.Type) {
		return nil, cs.failed()
	}
	// Every custom role, read once: the candidates, and those their GrantableRoles name. In the
	// statement that reads the grants, as a check reads them: read apart, a grant revoked and its
	// role widened meanwhile could offer what no moment would.
	held, ds, b, err := a.heldOrDenied(ctx, a.db, r.Tenant, s, all, r.path(), "", tenantRoles)
	if err != nil || len(held) == 0 {
		return nil, err
	}
	readingRoles()
	au, err := a.authorityOf(ctx, a.db, s, r, held, ds, b)
	if err != nil {
		return nil, err
	}
	custom := slices.SortedFunc(maps.Values(b.custom), func(x, y RoleDefinition) int { return strings.Compare(string(x.ID), string(y.ID)) })
	au.constrained = cs
	pw := au.over(r.Type)
	if pw.none() {
		return nil, nil
	}
	var roles []RoleDefinition
	// Everything checked for a role the actor may grant holds, so later roles needn't check it
	// again. A refused role's checks are dropped: some passed only while it was in progress.
	proven := map[string]bool{}
	for _, def := range a.rolesIn(r.Type, custom) {
		seen := maps.Clone(proven)
		if _, ok := a.mayGrant(au, pw, r.Type, def, "", seen); ok {
			proven = seen
			roles = append(roles, def)
		}
	}
	if err := cs.failed(); err != nil {
		return nil, err
	}
	return roles, nil
}

// stored is an expiry as PostgreSQL keeps it, to the microsecond, so a change reports the
// expiry it stored.
func stored(t time.Time) time.Time { return t.Truncate(time.Microsecond) }

func scopeGrants(scope Scope, bindings []Binding) []Grant {
	grants := make([]Grant, len(bindings))
	for i, b := range bindings {
		grants[i] = Grant{Scope: scope, Binding: b}
	}
	return grants
}

// removals are the calls that only remove grants, eligibilities, denies, memberships, groups or
// roles, which can't leave anyone able to hold two exclusive values, as denies don't count, so
// aren't checked for it: one that rewrites approvers or denies, as DeleteGroups does, would
// otherwise be refused for a conflict it left as it found.
var removals = map[string]bool{
	"Deactivate": true, "DeleteDeny": true, "DeleteGrants": true, "DeleteGroup": true, "DeleteGroups": true,
	"DeleteEligibility": true, "DeleteMembers": true, "DeletePrincipal": true, "DeleteRole": true, "DeleteScope": true,
	"DeleteScopes": true, "DeleteTenant": true,
}

// inTx runs fn in a transaction, recording what it writes in history as actor's change made by
// how, the call that makes it, and hands what it changed to Config.OnChange there. Where a
// dimension is Exclusive, it refuses a change that lets an identity hold two of its values.
func (a *Authorizer) inTx(ctx context.Context, tenant string, actor Principal, how string, fn func(pgx.Tx) (ChangeEvent, error)) error {
	return a.begin(ctx, func(tx pgx.Tx) error {
		// Taken by every change, removals too, so changes in one host transaction take their locks in
		// one order.
		exclusive := a.exclusive()
		if exclusive {
			if err := lockExclusive(ctx, tx, tenant); err != nil {
				return err
			}
		}
		done, err := a.recording(ctx, tx, actor, how, "")
		if err != nil {
			return err
		}
		e, err := fn(tx)
		if err != nil {
			return err
		}
		if exclusive && !removals[how] {
			if err := a.excludes(ctx, tx, tenant, e); err != nil {
				return err
			}
		}
		if err := done(); err != nil {
			return err
		}
		e.Tenant, e.Actor = tenant, actor
		return a.report(ctx, tx, e)
	})
}

func (a *Authorizer) begin(ctx context.Context, fn func(pgx.Tx) error) error {
	if err := a.writable(); err != nil {
		return err
	}
	return begin(ctx, a.db, fn)
}

// begin runs fn in a transaction of its own at READ COMMITTED, whatever the database's default,
// as a change's checks must read what committed before it took its locks; on any other DB, as a
// pgx.Tx under WithTx, in a savepoint of that DB's transaction, whose isolation the locks check.
// PostgreSQL refusing it for a race matches ErrConflict.
func begin(ctx context.Context, db DB, fn func(pgx.Tx) error) error {
	var err error
	if conn, ok := db.(ownTx); ok {
		err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, fn)
	} else {
		err = savepoint(ctx, db, fn)
	}
	return conflicted(err)
}

// ownTx is a DB that begin runs fn in a transaction of its own on, as a pool or a connection.
type ownTx interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// savepointEnd is how long a savepoint's release or rollback may take once its ctx is done.
var savepointEnd = 10 * time.Second

// savepoint runs fn in a savepoint, which it releases or rolls back even once ctx is done: pgx
// sends nothing on a done ctx, which would leave the savepoint open, and the host's transaction
// holding what a failed change wrote and its context for history, to commit with its own writes.
func savepoint(ctx context.Context, db DB, fn func(pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	// Bounded, as a done ctx's deadline no longer is, so a dead connection can't hold it for good;
	// from when fn returns, or a change that took as long would leave it open.
	end := func(f func(context.Context) error) error {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), savepointEnd)
		defer cancel()
		return f(c)
	}
	// After the release, a no-op.
	defer func() { _ = end(tx.Rollback) }()
	if err := fn(tx); err != nil {
		return err
	}
	return end(tx.Commit)
}

// report hands a change to Config.OnChange in its transaction, unless it changed nothing.
func (a *Authorizer) report(ctx context.Context, tx pgx.Tx, e ChangeEvent) error {
	if a.cfg.OnChange == nil || e.empty() {
		return nil
	}
	return a.cfg.OnChange(ctx, tx, e)
}

// upsert stores grants in one statement, sorted so concurrent changes lock rows in the same
// order, and returns those it added or whose note it changed. Of grants that are one grant it
// stores the last, since one statement can't change a row twice.
func (a *Authorizer) upsert(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, grants []Grant) ([]Grant, error) {
	if len(grants) == 0 {
		return nil, nil
	}
	byKey := func(x, y Grant) int {
		return cmp.Or(cmp.Compare(x.Principal.key(), y.Principal.key()), cmp.Compare(x.Scope.Key(), y.Scope.Key()),
			cmp.Compare(x.Role, y.Role), cmp.Compare(x.Source, y.Source), x.ExpiresAt.Compare(y.ExpiresAt),
			cmp.Compare(x.Condition.Expression, y.Condition.Expression))
	}
	grants = slices.Clone(grants)
	slices.Reverse(grants)
	slices.SortStableFunc(grants, byKey)
	grants = slices.CompactFunc(grants, func(x, y Grant) bool { return byKey(x, y) == 0 })
	n := len(grants)
	scopeTypes, scopeIDs, kinds, ids, roles := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	sources, expires := make([]string, n), make([]pgtype.Timestamptz, n)
	titles, descriptions, conditions, notes := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, g := range grants {
		scopeTypes[i], scopeIDs[i] = g.Scope.Type, g.Scope.ID
		kinds[i], ids[i], roles[i] = string(g.Principal.Kind), g.Principal.ID, string(g.Role)
		sources[i], expires[i] = g.Source, pgtype.Timestamptz{Time: g.ExpiresAt, Valid: !g.ExpiresAt.IsZero()}
		titles[i], descriptions[i], conditions[i] = g.Condition.Title, g.Condition.Description, g.Condition.Expression
		notes[i] = g.Note
	}
	// The same grant again changes only its note and its condition's title and description. The
	// condition's length and hash pick it, and its text must match, so a hash shared by two
	// conditions changes neither.
	rows, err := tx.Query(ctx, `
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at,
		  condition_title, condition_description, condition, note, created_by, updated_by)
		SELECT $1, st, si, pk, pi, r, src, e, ct, cd, c, n, $9, $9
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::timestamptz[],
		  $10::text[], $11::text[], $12::text[], $13::text[])
		  AS t(st, si, pk, pi, r, src, e, ct, cd, c, n)
		ON CONFLICT (tenant, principal, scope, role, source, coalesce(expires_at, 'infinity'), length(condition), hashtextextended(condition, 0))
		DO UPDATE SET condition_title = EXCLUDED.condition_title, condition_description = EXCLUDED.condition_description,
		  note = EXCLUDED.note, updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE rbac_grants.condition = EXCLUDED.condition
		  AND (rbac_grants.condition_title, rbac_grants.condition_description, rbac_grants.note)
		  IS DISTINCT FROM (EXCLUDED.condition_title, EXCLUDED.condition_description, EXCLUDED.note)
		RETURNING `+grantColumns,
		tenant, scopeTypes, scopeIDs, kinds, ids, roles, sources, expires, actorKey(actor), titles, descriptions, conditions, notes)
	if err != nil {
		return nil, err
	}
	granted, err := collectGrants(rows)
	if err != nil {
		return nil, err
	}
	if err := a.bounded(ctx, tx, tenant, granted); err != nil {
		return nil, err
	}
	return granted, nil
}

// bounded refuses grants just stored that leave a principal holding their role on their scope
// more than MaxGrantsPerRole times. It counts under the change's locks, once they are stored, the
// grants in force the change didn't touch included, activations too: so no write passes the
// bound, and one that adds nothing never finds it passed.
func (a *Authorizer) bounded(ctx context.Context, tx pgx.Tx, tenant string, stored []Grant) error {
	if len(stored) == 0 {
		return nil
	}
	n := len(stored)
	scopes, principals, roles, buckets := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, g := range stored {
		scopes[i], principals[i], roles[i] = g.Scope.Key(), g.Principal.key(), string(g.Role)
		if a.owned[g.Source] {
			buckets[i] = g.Source
		}
	}
	// Grants from each source the host owns count apart from the rest, so a tenant's admins can't
	// fill the bound to keep the host's own from being made, nor the host fill theirs.
	rows, err := tx.Query(ctx, `
		SELECT scope, principal, role FROM (
		  SELECT scope, principal, role, CASE WHEN source = ANY($7::text[]) THEN source ELSE '' END AS bucket FROM rbac_grants
		  WHERE tenant = $1 AND (scope, principal, role) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))
		    AND (expires_at IS NULL OR expires_at > $5)) g
		WHERE (scope, principal, role, bucket) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[], $8::text[]))
		GROUP BY scope, principal, role, bucket HAVING count(*) > $6
		ORDER BY scope, principal, role`,
		tenant, scopes, principals, roles, a.cfg.Now(), MaxGrantsPerRole, slices.Sorted(maps.Keys(a.owned)), buckets)
	if err != nil {
		return err
	}
	over, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (error, error) {
		var scope, principal, role string
		if err := row.Scan(&scope, &principal, &role); err != nil {
			return nil, err
		}
		return fmt.Errorf("%w: %s holds %s on %s at most %d times, by source, expiry and condition",
			ErrInvalid, principal, role, scope, MaxGrantsPerRole), nil
	})
	if err != nil {
		return err
	}
	return errors.Join(over...)
}

// revoke deletes from a scope the grants bindings name, each by its role, principal and source,
// or by its id, sparing those kept, which the change grants again, and returns those it removed.
func (a *Authorizer) revoke(ctx context.Context, tx pgx.Tx, tenant string, scope Scope, bindings, kept []Binding) ([]Grant, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, revoking, revokeArgs(tenant, scope, bindings, kept)...)
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

const revoking = `
	DELETE FROM rbac_grants g
	WHERE tenant = $1 AND scope = $2
	  AND EXISTS (SELECT FROM unnest($3::text[], $4::text[], $5::text[], $6::text[]) AS r(principal, role, source, id)
	    WHERE r.principal = g.principal AND r.role = g.role AND (r.id = '' AND r.source = g.source OR r.id = g.id::text))
	  AND NOT EXISTS (SELECT FROM unnest($7::text[], $8::text[], $9::text[], $10::timestamptz[], $11::text[])
	    AS k(principal, role, source, expires_at, condition)
	    WHERE k.principal = g.principal AND k.role = g.role AND k.source = g.source
	      AND k.expires_at IS NOT DISTINCT FROM g.expires_at AND k.condition = g.condition)
	RETURNING ` + grantColumns

// revokeArgs are revoking's arguments.
func revokeArgs(tenant string, scope Scope, bindings, kept []Binding) []any {
	n := len(bindings)
	principals, roles, sources, ids := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, b := range bindings {
		principals[i], roles[i], sources[i], ids[i] = b.Principal.key(), string(b.Role), b.Source, b.ID
	}
	m := len(kept)
	keptPrincipals, keptRoles, keptSources, keptConditions := make([]string, m), make([]string, m), make([]string, m), make([]string, m)
	keptExpires := make([]pgtype.Timestamptz, m)
	for i, b := range kept {
		keptPrincipals[i], keptRoles[i], keptSources[i] = b.Principal.key(), string(b.Role), b.Source
		keptExpires[i], keptConditions[i] = pgtype.Timestamptz{Time: b.ExpiresAt, Valid: !b.ExpiresAt.IsZero()}, b.Condition.Expression
	}
	return []any{tenant, scope.Key(), principals, roles, sources, ids, keptPrincipals, keptRoles, keptSources, keptExpires, keptConditions}
}

// GrantFilter picks grants or eligibilities by scope, by principal, or both; at least one is
// required.
type GrantFilter struct {
	Scopes     []Scope
	Principals []Principal
}

// valid reports whether the filter picks something, by scopes and principals that could be
// stored in a tenant.
func (f GrantFilter) valid(tenant string) bool {
	return len(f.Scopes)+len(f.Principals) > 0 &&
		!slices.ContainsFunc(f.Scopes, func(s Scope) bool { return !s.valid() }) &&
		!slices.ContainsFunc(f.Principals, func(p Principal) bool { return !p.wellFormed(tenant) })
}

// sql is the condition picking what the filter matches, on $2 and $3, and their arguments: a
// statement of its own for each shape, so each plans for the index it can use.
func (f GrantFilter) sql() (where string, scopes, principals []string) {
	scopes = make([]string, len(f.Scopes))
	for i, s := range f.Scopes {
		scopes[i] = s.Key()
	}
	principals = keysOf(f.Principals)
	switch {
	case len(principals) == 0:
		return "scope = ANY($2::text[]) AND $3::text[] IS NULL", scopes, nil
	case len(scopes) == 0:
		return "$2::text[] IS NULL AND principal = ANY($3::text[])", nil, principals
	}
	return "scope = ANY($2::text[]) AND principal = ANY($3::text[])", scopes, principals
}

// Grants lists the grants in force that match the filter: who has access to a resource and
// through which ancestor, or what a principal holds (RBAC's assigned roles). It lists them as
// stored, so they can be revoked, even those that give less than their role or nothing: one to
// a tenant's members or the public gives no `:grant` permission, and one of a role no longer in
// the catalog, to a kind no longer declared, or to the public of a role no longer Public gives
// nothing.
func (a *Authorizer) Grants(ctx context.Context, tenant string, f GrantFilter) ([]Grant, error) {
	if !validID(tenant) || !f.valid(tenant) {
		return nil, fmt.Errorf("%w: Grants needs a tenant and valid scopes or principals", ErrInvalid)
	}
	where, scopes, principals := f.sql()
	rows, err := a.db.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND `+where+` AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY scope, principal, role, source, expires_at NULLS FIRST, condition, id`,
		tenant, scopes, principals, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

// DeleteGrants revokes grants in a tenant as actor without the checks Apply makes of an actor: the
// host's own counterpart of Import, for the grants it manages, such as those from a source it owns
// (Config.Sources), which Apply can't change. Each names its scope and, as Change.Revoke does, its
// role, principal and source, every grant of the role to the principal from the source there, or
// with an ID that one grant. actor is who they are recorded as revoked by. It locks their scopes
// and principals until the transaction ends, or past 64 the tenant, as Import does.
func (a *Authorizer) DeleteGrants(ctx context.Context, actor Principal, tenant string, grants []Grant) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteGrants")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(grants) == 0 {
		return nil
	}
	if len(grants) > MaxBindings {
		return fmt.Errorf("%w: a deletion names at most %d grants", ErrInvalid, MaxBindings)
	}
	byScope, principals := map[Scope][]Binding{}, map[string]bool{}
	var errs []error
	for _, g := range grants {
		if !g.Scope.in(tenant) {
			errs = append(errs, &InvalidError{Binding: g.Binding, Reason: fmt.Sprintf("scope %q is not valid", g.Scope.Key())})
			continue
		}
		errs = append(errs, checkRevoke(tenant, g.Binding)...)
		byScope[g.Scope] = append(byScope[g.Scope], g.Binding)
		principals[g.Principal.key()] = true
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	scopes := slices.SortedFunc(maps.Keys(byScope), func(x, y Scope) int { return strings.Compare(x.Key(), y.Key()) })
	keys := make([]string, len(scopes))
	for i, s := range scopes {
		keys[i] = s.Key()
	}
	return a.inTx(ctx, tenant, actor, "DeleteGrants", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, keys, slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		// One round trip for every scope, rather than one each while the locks are held.
		b := &pgx.Batch{}
		for _, s := range scopes {
			b.Queue(revoking, revokeArgs(tenant, s, byScope[s], nil)...)
		}
		br := tx.SendBatch(ctx, b)
		var e ChangeEvent
		for range scopes {
			rows, err := br.Query()
			if err == nil {
				var revoked []Grant
				revoked, err = collectGrants(rows)
				e.Revoked = append(e.Revoked, revoked...)
			}
			if err != nil {
				_ = br.Close()
				return ChangeEvent{}, err
			}
		}
		return e, br.Close()
	})
}

// DeleteScope removes every grant, eligibility and deny on a scope, as DeleteScopes does.
func (a *Authorizer) DeleteScope(ctx context.Context, actor Principal, tenant string, s Scope) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteScope")
	return a.deleteScopes(ctx, actor, tenant, "DeleteScope", []Scope{s})
}

// DeleteScopes removes every grant, eligibility and deny on scopes, as actor, as when resources
// or containers are deleted: call it in the transaction that deletes them, through WithTx, once
// with every scope the deletion removes, a container's and those under it. It waits for changes
// to the scopes in progress, so a grant one makes is removed too.
//
// It locks each scope until the transaction ends, or past 64 scopes the tenant, so one call
// holds a bounded number of locks however many scopes it removes. A call for each scope in one
// transaction would hold a lock for each, which PostgreSQL keeps in one table every session
// shares: a few thousand can fill it.
func (a *Authorizer) DeleteScopes(ctx context.Context, actor Principal, tenant string, scopes []Scope) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteScopes")
	return a.deleteScopes(ctx, actor, tenant, "DeleteScopes", scopes)
}

func (a *Authorizer) deleteScopes(ctx context.Context, actor Principal, tenant, how string, scopes []Scope) error {
	keys := make([]string, len(scopes))
	for i, s := range scopes {
		if !s.in(tenant) {
			return fmt.Errorf("%w: scope %q is not valid", ErrInvalid, s.Key())
		}
		keys[i] = s.Key()
	}
	// A scope listed twice, as on the paths of resources under one container, counts toward
	// maxLocks once, or a few scopes would lock the whole tenant.
	slices.Sort(keys)
	keys = slices.Compact(keys)
	return a.delete(ctx, actor, tenant, how, func(tx pgx.Tx) error { return lockAll(ctx, tx, tenant, keys, nil) },
		deletion{denies: "scope = ANY($2::text[])", where: "scope = ANY($2::text[])"}, keys)
}

// DeletePrincipal removes every grant and eligibility of a principal in a tenant, as actor, with
// its places in groups and an identity's membership, as when it leaves the tenant; or every grant
// to the public, as when a tenant stops allowing public access.
func (a *Authorizer) DeletePrincipal(ctx context.Context, actor Principal, tenant string, p Principal) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeletePrincipal")
	if !p.wellFormed(tenant) {
		return fmt.Errorf("%w: principal %q is not valid", ErrInvalid, p.key())
	}
	return a.delete(ctx, actor, tenant, "DeletePrincipal", func(tx pgx.Tx) error { return lock(ctx, tx, tenant, nil, []string{p.key()}) },
		deletion{where: "principal = $2", members: "principal = $2"}, p.key())
}

// DeletePrincipalEverywhere removes every grant and eligibility of an identity in every tenant,
// with its memberships and places in groups, as actor, as when it is deleted. A group is its
// tenant's alone: DeleteGroups removes one. Delete it from the host first, so
// Config.ValidateGrant refuses new grants to it. Each tenant's removals reach Config.OnChange as a
// change of their own.
//
// Each tenant's removal takes two locks, so it removes a batch of tenants per transaction, to
// keep a principal in many tenants from filling PostgreSQL's lock table: on an error, the
// batches before it stay removed, and calling it again removes the rest. Under WithTx every
// batch is in the host's transaction, and its locks last until that ends.
func (a *Authorizer) DeletePrincipalEverywhere(ctx context.Context, actor, p Principal) (err error) {
	defer a.refused(ctx, &err, "", actor, "DeletePrincipalEverywhere")
	// A group is its tenant's alone: one with its id elsewhere is another.
	if p.broad() || p.Kind == Group || !p.wellFormed("") {
		return fmt.Errorf("%w: principal %q is not an identity", ErrInvalid, p.key())
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	const batch = maxLocks / 2
	for {
		var n int
		err := a.begin(ctx, func(tx pgx.Tx) error {
			done, err := a.recording(ctx, tx, actor, "DeletePrincipalEverywhere", "")
			if err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `SELECT tenant FROM rbac_grants WHERE principal = $1
				UNION SELECT tenant FROM rbac_eligibilities WHERE principal = $1
				UNION SELECT tenant FROM rbac_memberships WHERE principal = $1
				UNION SELECT tenant FROM rbac_members WHERE principal = $1 ORDER BY tenant LIMIT $2`, p.key(), batch)
			if err != nil {
				return err
			}
			tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			n = len(tenants)
			events := make([]ChangeEvent, 0, n)
			// In tenant order, so two of these for one principal never deadlock.
			for _, t := range tenants {
				if err := lock(ctx, tx, t, nil, []string{p.key()}); err != nil {
					return err
				}
				revoked, err := a.remove(ctx, tx, t, "principal = $2", p.key())
				if err != nil {
					return err
				}
				ended, err := a.removeEligible(ctx, tx, t, "principal = $2", p.key())
				if err != nil {
					return err
				}
				// The membership before the groups it reaches, as delete removes them.
				memberships, err := removed(ctx, a, tx, "rbac_memberships", membershipColumns, collectMemberships, t, "principal = $2", p.key())
				if err != nil {
					return err
				}
				left, err := removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, t, "principal = $2", p.key())
				if err != nil {
					return err
				}
				events = append(events, ChangeEvent{
					Tenant: t, Actor: actor, Revoked: revoked, Ineligible: ended,
					Left: left, EndedMemberships: memberships,
				})
			}
			if err := done(); err != nil {
				return err
			}
			for _, e := range events {
				if err := a.report(ctx, tx, e); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil || n < batch {
			return err
		}
	}
}

// DeleteTenant removes every grant, eligibility, custom role, deny, membership and group in a
// tenant, as actor, so a tenant created later with its id starts with none.
func (a *Authorizer) DeleteTenant(ctx context.Context, actor Principal, tenant string) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteTenant")
	return a.delete(ctx, actor, tenant, "DeleteTenant", func(tx pgx.Tx) error { return lockTenant(ctx, tx, tenant) },
		deletion{roles: true, groups: true, denies: "TRUE", where: "TRUE", members: "TRUE"})
}

// deletion is what a delete removes in a tenant: grants and eligibilities where picks, denies
// where denies does, and memberships of the tenant and of its groups where members does (none
// where either is empty); with roles its custom roles, and with groups its groups. Each reads args
// from $2.
type deletion struct {
	roles, groups          bool
	denies, where, members string
}

// delete removes what del picks in a tenant as actor, by how, once lock holds.
func (a *Authorizer) delete(ctx context.Context, actor Principal, tenant, how string, lock func(pgx.Tx) error, del deletion, args ...any) error {
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor, how, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(tx); err != nil {
			return ChangeEvent{}, err
		}
		var e ChangeEvent
		var err error
		if e.Ineligible, err = a.removeEligible(ctx, tx, tenant, del.where, args...); err != nil {
			return ChangeEvent{}, err
		}
		if del.roles {
			rows, err := tx.Query(ctx, `DELETE FROM rbac_roles WHERE tenant = $1 RETURNING id`, tenant)
			if err != nil {
				return ChangeEvent{}, err
			}
			if e.DeletedRoles, err = pgx.CollectRows(rows, pgx.RowTo[Role]); err != nil {
				return ChangeEvent{}, err
			}
		}
		if del.denies != "" {
			if e.DeletedDenies, err = removed(ctx, a, tx, "rbac_denies", denyColumns, collectDenies, tenant, del.denies, args...); err != nil {
				return ChangeEvent{}, err
			}
		}
		if del.members != "" {
			// Memberships before the members they reach, as DeleteExpired takes them, so the two never
			// deadlock.
			if e.EndedMemberships, err = removed(ctx, a, tx, "rbac_memberships", membershipColumns, collectMemberships, tenant, del.members, args...); err != nil {
				return ChangeEvent{}, err
			}
			if e.Left, err = removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant, del.members, args...); err != nil {
				return ChangeEvent{}, err
			}
		}
		if del.groups {
			if e.DeletedGroups, err = removed(ctx, a, tx, "rbac_groups", groupColumns, collectGroups, tenant, "TRUE"); err != nil {
				return ChangeEvent{}, err
			}
		}
		e.Revoked, err = a.remove(ctx, tx, tenant, del.where, args...)
		return e, err
	})
}

// removeEligible deletes the eligibilities in a tenant that where picks, and returns them for
// OnChange.
func (a *Authorizer) removeEligible(ctx context.Context, tx pgx.Tx, tenant, where string, args ...any) ([]Eligibility, error) {
	return removed(ctx, a, tx, "rbac_eligibilities", eligibilityColumns, collectEligibilities, tenant, where, args...)
}

// remove deletes the grants in a tenant that where picks, and returns them for OnChange.
func (a *Authorizer) remove(ctx context.Context, tx pgx.Tx, tenant, where string, args ...any) ([]Grant, error) {
	return removed(ctx, a, tx, "rbac_grants", grantColumns, collectGrants, tenant, where, args...)
}

func removed[T any](ctx context.Context, a *Authorizer, tx pgx.Tx, table, columns string, collect func(pgx.Rows) ([]T, error),
	tenant, where string, args ...any,
) ([]T, error) {
	query := `DELETE FROM ` + table + ` WHERE tenant = $1 AND ` + where
	args = append([]any{tenant}, args...)
	// Only OnChange reads what was removed, which for a whole tenant can be every row it has.
	if a.cfg.OnChange == nil {
		_, err := tx.Exec(ctx, query, args...)
		return nil, err
	}
	rows, err := tx.Query(ctx, query+` RETURNING `+columns, args...)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// DeleteExpired removes grants, eligibilities, group members and tenant memberships that have
// expired, which no longer give or allow anything, and returns how many: those expired by
// Config.Now and by the database's clock both, so history records each as an expiry. It passes
// over those a change is holding, rather than wait on it, so the next run removes them. It
// removes a batch at a time, on a pool each in a transaction of its own, so none holds many
// locks, and on an error those it removed before stay removed. A race PostgreSQL refuses matches
// ErrConflict.
func (a *Authorizer) DeleteExpired(ctx context.Context) (n int64, err error) {
	defer a.refused(ctx, &err, "", Principal{}, "DeleteExpired")
	if err := a.writable(); err != nil {
		return 0, err
	}
	n, err = a.deleteExpired(ctx)
	return n, conflicted(err)
}

// expiryBatch is the most rows of a table one of DeleteExpired's transactions picks, so none
// holds the locks of, or records, an unbounded number; but for the places in groups of the
// identities whose memberships it ends, which go with them, however many groups each is in.
var expiryBatch = 1000

func (a *Authorizer) deleteExpired(ctx context.Context) (int64, error) {
	// As of one time, so rows expiring meanwhile can't keep it deleting.
	now := a.cfg.Now()
	// Each batch in a transaction of its own, which history records as expiries no one made. A
	// statement returns how many of its table's rows it deleted, and how many in all.
	expire := func(sql string) (n, all int64, err error) {
		err = a.begin(ctx, func(tx pgx.Tx) error {
			// It takes no lock, but as a change it reads what committed before it, which only
			// READ COMMITTED reads: an older snapshot would leave an ended member's newer places.
			b := &pgx.Batch{}
			b.Queue(`SELECT current_setting('transaction_isolation')`)
			if err := locked(tx.SendBatch(ctx, b)); err != nil {
				return err
			}
			done, err := a.recording(ctx, tx, Principal{}, "DeleteExpired", "expire")
			if err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, sql, now, expiryBatch).Scan(&n, &all); err != nil {
				return err
			}
			return done()
		})
		return n, all, err
	}
	var total int64
	// By the database's clock too, which history records an expiry by: a row expired by Config.Now
	// alone, which can run ahead of it, would be recorded as deleted.
	for _, sql := range []string{
		`WITH d AS (DELETE FROM rbac_grants WHERE id IN (
			SELECT id FROM rbac_grants WHERE expires_at <= least($1, statement_timestamp()) LIMIT $2 FOR UPDATE SKIP LOCKED) RETURNING 1)
		SELECT count(*), count(*) FROM d`,
		`WITH d AS (DELETE FROM rbac_eligibilities WHERE id IN (
			SELECT id FROM rbac_eligibilities WHERE expires_at <= least($1, statement_timestamp()) LIMIT $2 FOR UPDATE SKIP LOCKED) RETURNING 1)
		SELECT count(*), count(*) FROM d`,
		`WITH d AS (DELETE FROM rbac_members WHERE (tenant, group_id, principal, source) IN (
			SELECT tenant, group_id, principal, source FROM rbac_members WHERE expires_at <= least($1, statement_timestamp()) LIMIT $2 FOR UPDATE SKIP LOCKED) RETURNING 1)
		SELECT count(*), count(*) FROM d`,
		// An identity whose membership ended leaves the tenant's groups with it, as one that leaves
		// the tenant does, so joining again gives back none of the groups it was in. Its own grants
		// and eligibilities stay, as they do for an identity granted roles in a tenant it isn't in.
		`WITH ended AS (
		  DELETE FROM rbac_memberships WHERE (tenant, principal) IN (
		    SELECT tenant, principal FROM rbac_memberships WHERE expires_at <= least($1, statement_timestamp()) LIMIT $2 FOR UPDATE SKIP LOCKED)
		  RETURNING tenant, principal
		), left_groups AS (
		  DELETE FROM rbac_members m USING ended e WHERE m.tenant = e.tenant AND m.principal = e.principal RETURNING 1
		)
		SELECT (SELECT count(*) FROM ended), (SELECT count(*) FROM ended) + (SELECT count(*) FROM left_groups)`,
	} {
		for {
			// A batch that failed, even once its statement ran, removed nothing.
			n, all, err := expire(sql)
			if err != nil {
				return total, err
			}
			total += all
			if n < int64(expiryBatch) {
				break
			}
		}
	}
	return total, nil
}
