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
//     constraint, nor deny on the path, may remove it;
//   - through a role with GrantableRoles, the actor may grant and revoke only those roles, and
//     needn't hold their permissions;
//   - through any other role, the actor may grant a role only by holding everything it gives
//     there, none of it removed by a deny on the path, for every type the grant reaches, and
//     may revoke any. A role's power to change grants is part of what it gives: one with
//     GrantableRoles needs the power to grant each its holders could, and one without, the
//     unlimited power to change grants on its type;
//   - a conditional power to change grants holds only where its condition does, and what the
//     actor hands on, permissions and power alike, it holds unconditionally or under the
//     condition the grant has: a role a conditional grant lists is granted only under its
//     condition;
//   - a role that gives a `:grant` or `:deny` permission or DefineRoles can't be granted to a
//     tenant's members or the public, and only a role marked Public can be granted to the public.
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
func (a *Authorizer) Apply(ctx context.Context, actor Subject, on Resource, c Change) error {
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
	return a.change(ctx, actor, on, ViaApply, grants, revokes, nil, func(tx pgx.Tx) (ChangeEvent, error) {
		revoked, err := a.revoke(ctx, tx, on.Tenant, scope, revokes, grants)
		if err != nil {
			return ChangeEvent{}, err
		}
		granted, err := a.upsert(ctx, tx, on.Tenant, actor.Principal, scopeGrants(scope, grants))
		return ChangeEvent{Granted: granted, Revoked: revoked}, err
	})
}

// change makes a change to the grants on one scope as actor, or to eligibilities, which are
// grants to come, with Apply's checks before its transaction and again under its locks, and
// then write. check is what else the change needs, run once the actor may make it.
func (a *Authorizer) change(ctx context.Context, actor Subject, on Resource, via Via, grants, revokes []Binding,
	check func() error, write func(pgx.Tx) (ChangeEvent, error),
) error {
	scope := on.Scope()
	if err := a.changing(ctx, actor, on); err != nil {
		return err
	}
	au, err := a.mayChange(ctx, a.db, actor, on, grants, revokes)
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := a.validate(ctx, au.roles, actor, via, on.Tenant, scope, grants, revokes); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		// One change to a scope at a time, so two changes can't deadlock on its rows.
		principals := map[string]bool{}
		for _, b := range slices.Concat(grants, revokes) {
			principals[b.Principal.key()] = true
		}
		if err := lockAll(ctx, tx, on.Tenant, []string{scope.Key()}, slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		// Decided again in the transaction, so the actor's access and the roles are read as the
		// change is made: a custom role deleted or redefined since is granted only as it is now.
		au, err := a.mayChange(ctx, tx, actor, on, grants, revokes)
		if err != nil {
			return ChangeEvent{}, err
		}
		var bad []error
		for _, b := range grants {
			bad = append(bad, a.checkBinding(au.roles, on.Tenant, scope, b, a.cfg.Now())...)
		}
		if err := errors.Join(bad...); err != nil {
			return ChangeEvent{}, err
		}
		return write(tx)
	})
}

// changing refuses a change to grants on a scope by an anonymous actor, or one a constraint on
// `<type>:grant` stops. The constraints run outside the transaction: one that queries the pool
// while the transaction holds a connection can wait forever on a busy pool.
func (a *Authorizer) changing(ctx context.Context, actor Subject, on Resource) error {
	manage := GrantPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: manage, Scope: on.Scope(), Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: on.Tenant, ResourceType: on.Type, Permission: manage, Subject: &actor, Resource: &on})
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: manage, Scope: on.Scope(), Reason: "removed by " + name}
	}
	return nil
}

// A change takes its tenant's lock shared, then the lock of each scope and of each principal
// whose grants it changes, in order; deleting a tenant takes the tenant's lock alone. So two
// changes to the same rows run in turn, and one call never deadlocks with another. The locks
// last until the transaction ends. Advisory locks span the database, so the keys name the
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
func (a *Authorizer) Import(ctx context.Context, actor Principal, tenant string, grants []Grant) error {
	if tenant == "" {
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
	for _, g := range grants {
		scopes[g.Scope.Key()] = true
		principals[g.Principal.key()] = true
	}
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, slices.Collect(maps.Keys(scopes)), slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		// Again under the locks, so a custom role deleted since isn't granted. Only ValidateGrant,
		// asked above, reads the flag, so the roles named are enough.
		if _, err := check(a.book, tx); err != nil {
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
		// A role no longer in the catalog, or a kind no longer declared, can still be revoked.
		if !b.Principal.wellFormed(tenant) {
			errs = append(errs, &InvalidError{Binding: b, Reason: "the principal is not valid"})
		}
		// No grant has no role, so a revoke without one, as by ID alone, would revoke nothing.
		if b.Role == "" {
			errs = append(errs, &InvalidError{Binding: b, Reason: "a revoke names its role, by ID too"})
		}
	}
	return errors.Join(errs...)
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
	if !a.acts(actor.Kind) || actor.ID == "" {
		return fmt.Errorf("%w: the actor %q is not a user or declared kind", ErrInvalid, actor.key())
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
	}
	if !b.ExpiresAt.IsZero() && !b.ExpiresAt.After(now) {
		bad("already expired")
	}
	if !validNote(b.Note) {
		bad(fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	if !validSource(b.Source) {
		bad("a source is lowercase letters, digits and . _ : / -, starting with a letter, of at most 63")
	}
	return errs
}

var sourceName = regexp.MustCompile(`^([a-z][a-z0-9._:/-]{0,62})?$`)

func validSource(s string) bool { return sourceName.MatchString(s) }

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
	keys := actor.principals(on.Tenant)
	held, ds, err := a.heldOrDenied(ctx, q, on.Tenant, keys, keys, on.path(), "")
	if err != nil {
		return authority{}, err
	}
	b, err := a.tenantBook(ctx, q, on.Tenant, append(roleIDs(held), roles...))
	if err != nil {
		return authority{}, err
	}
	return a.authorityOf(ctx, q, actor, on, held, ds, b)
}

// authorityOf is the authority of held grants under the denies on the path, reading the
// grants' conditions.
func (a *Authorizer) authorityOf(ctx context.Context, q DB, actor Subject, on Resource, held []holding, ds []denial, b book) (authority, error) {
	if err := a.conditionsOf(ctx, q, on.Tenant, held); err != nil {
		return authority{}, err
	}
	vars, spend := a.vars(ctx, actor, "", on), newBudget()
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
			_, d := a.deniedBy(ds, p, spend, with(vars, p))
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
// held under a condition can't be handed on without it.
func (au authority) under(scopeType, condition string) power {
	return au.power(scopeType, au.handsOn, func(g holding) bool { return g.under(condition) })
}

func (au authority) power(scopeType string, denied func(Permission) bool, counts func(holding) bool) power {
	pw := power{listed: map[Role][]string{}}
	manage := GrantPermission(scopeType)
	if denied(manage) {
		return pw
	}
	for _, g := range au.held {
		if !gives(au.roles, g.Principal, g.Role, manage, scopeType) || !counts(g) {
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
	return !h.conditional || h.Condition.Expression == condition
}

// holds reports whether the actor holds p for resources of a type, to hand it on with condition.
func (au authority) holds(p Permission, resourceType, condition string) bool {
	return !au.handsOn(p) && slices.ContainsFunc(au.held, func(g holding) bool {
		return gives(au.roles, g.Principal, g.Role, p, resourceType) && g.under(condition)
	})
}

// may reports whether the actor may do p, on resources of a type, in this request.
func (au authority) may(p Permission, resourceType string) bool {
	return !au.denied(p) && slices.ContainsFunc(au.held, func(g holding) bool {
		return gives(au.roles, g.Principal, g.Role, p, resourceType) && au.allows(g, p)
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
// checked the constraints, and returns what it read.
func (a *Authorizer) mayChange(ctx context.Context, q DB, actor Subject, on Resource, grants, revokes []Binding) (authority, error) {
	scope := on.Scope()
	manage := GrantPermission(scope.Type)
	au, err := a.authorityOn(ctx, q, actor, on, roleIDs(grants))
	if err != nil {
		return authority{}, err
	}
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
			reason := fmt.Sprintf("the actor can't grant %s without holding %s here", b.Role, p)
			switch {
			case !pw.any && len(pw.listed[b.Role]) > 0:
				reason = fmt.Sprintf("the actor may grant %s here only under the condition of a grant that lists it", b.Role)
			case !pw.any:
				reason = fmt.Sprintf("the actor may not grant %s here", b.Role)
			}
			errs = append(errs, &DeniedError{Permission: p, Scope: scope, Reason: reason})
		}
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
	name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: GrantPermission(r.Type), Subject: &s, Resource: &r})
	if err != nil || name != "" {
		return nil, err
	}
	keys := s.principals(r.Tenant)
	held, ds, err := a.heldOrDenied(ctx, a.db, r.Tenant, keys, keys, r.path(), "")
	if err != nil || len(held) == 0 {
		return nil, err
	}
	// Every custom role, read once: the candidates, and those their GrantableRoles name.
	custom, err := a.customRoles(ctx, a.db, r.Tenant)
	if err != nil {
		return nil, err
	}
	au, err := a.authorityOf(ctx, a.db, s, r, held, ds, a.bookOf(custom))
	if err != nil {
		return nil, err
	}
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

// inTx runs fn in a transaction and hands what it changed to Config.OnChange there.
func (a *Authorizer) inTx(ctx context.Context, tenant string, actor Principal, fn func(pgx.Tx) (ChangeEvent, error)) error {
	return a.begin(ctx, func(tx pgx.Tx) error {
		e, err := fn(tx)
		if err != nil {
			return err
		}
		e.Tenant, e.Actor = tenant, actor
		return a.report(ctx, tx, e)
	})
}

func (a *Authorizer) begin(ctx context.Context, fn func(pgx.Tx) error) error {
	return begin(ctx, a.db, fn)
}

// begin runs fn in a transaction of its own at READ COMMITTED, whatever the database's default,
// as a change's checks must read what committed before it took its locks; on a pgx.Tx, as under
// WithTx, in a savepoint of that transaction, whose isolation the locks check. PostgreSQL
// refusing it for a race matches ErrConflict.
func begin(ctx context.Context, db DB, fn func(pgx.Tx) error) error {
	var err error
	if conn, ok := db.(interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	}); ok {
		err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, fn)
	} else {
		err = pgx.BeginFunc(ctx, db, fn)
	}
	return conflicted(err)
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
	scopes, principals, roles := make([]string, n), make([]string, n), make([]string, n)
	for i, g := range stored {
		scopes[i], principals[i], roles[i] = g.Scope.Key(), g.Principal.key(), string(g.Role)
	}
	rows, err := tx.Query(ctx, `
		SELECT scope, principal, role FROM rbac_grants
		WHERE tenant = $1 AND (scope, principal, role) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))
		  AND (expires_at IS NULL OR expires_at > $5)
		GROUP BY scope, principal, role HAVING count(*) > $6
		ORDER BY scope, principal, role`,
		tenant, scopes, principals, roles, a.cfg.Now(), MaxGrantsPerRole)
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
	rows, err := tx.Query(ctx, `
		DELETE FROM rbac_grants g
		WHERE tenant = $1 AND scope = $2
		  AND EXISTS (SELECT FROM unnest($3::text[], $4::text[], $5::text[], $6::text[]) AS r(principal, role, source, id)
		    WHERE r.principal = g.principal AND r.role = g.role AND (r.id = '' AND r.source = g.source OR r.id = g.id::text))
		  AND NOT EXISTS (SELECT FROM unnest($7::text[], $8::text[], $9::text[], $10::timestamptz[], $11::text[])
		    AS k(principal, role, source, expires_at, condition)
		    WHERE k.principal = g.principal AND k.role = g.role AND k.source = g.source
		      AND k.expires_at IS NOT DISTINCT FROM g.expires_at AND k.condition = g.condition)
		RETURNING `+grantColumns,
		tenant, scope.Key(), principals, roles, sources, ids, keptPrincipals, keptRoles, keptSources, keptExpires, keptConditions)
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

// GrantFilter picks grants or eligibilities by scope, by principal, or both; at least one is
// required.
type GrantFilter struct {
	Scopes     []Scope
	Principals []Principal
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
	if tenant == "" || len(f.Scopes)+len(f.Principals) == 0 {
		return nil, fmt.Errorf("%w: Grants needs a tenant and scopes or principals", ErrInvalid)
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

// DeleteScope removes every grant, eligibility and deny on a scope, as actor, as when the
// resource or container is deleted: call it in the transaction that deletes it, through WithTx,
// and for each scope under it. It waits for a change to the scope in progress, so a grant that
// change makes is removed too.
func (a *Authorizer) DeleteScope(ctx context.Context, actor Principal, tenant string, s Scope) error {
	return a.delete(ctx, actor, tenant, func(tx pgx.Tx) error { return lock(ctx, tx, tenant, []string{s.Key()}, nil) },
		deletion{denies: "scope = $2", where: "scope = $2"}, s.Key())
}

// DeletePrincipal removes every grant and eligibility of a principal in a tenant, as actor, as
// when an identity or group leaves it, or every grant to the public, as when a tenant stops
// allowing public access.
func (a *Authorizer) DeletePrincipal(ctx context.Context, actor Principal, tenant string, p Principal) error {
	if !p.wellFormed(tenant) {
		return fmt.Errorf("%w: principal %q is not valid", ErrInvalid, p.key())
	}
	return a.delete(ctx, actor, tenant, func(tx pgx.Tx) error { return lock(ctx, tx, tenant, nil, []string{p.key()}) },
		deletion{where: "principal = $2"}, p.key())
}

// DeletePrincipalEverywhere removes every grant and eligibility of an identity or group in every
// tenant, as actor, as when it is deleted. Delete it from the host first, so Config.ValidateGrant
// refuses new grants to it. Each tenant's removals reach Config.OnChange as a change of their own.
//
// Each tenant's removal takes two locks, so it removes a batch of tenants per transaction, to
// keep a principal in many tenants from filling PostgreSQL's lock table: on an error, the
// batches before it stay removed, and calling it again removes the rest. Under WithTx every
// batch is in the host's transaction, and its locks last until that ends.
func (a *Authorizer) DeletePrincipalEverywhere(ctx context.Context, actor, p Principal) error {
	if p.broad() || !p.wellFormed("") {
		return fmt.Errorf("%w: principal %q is not an identity or group", ErrInvalid, p.key())
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	const batch = maxLocks / 2
	for {
		var n int
		err := a.begin(ctx, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT tenant FROM rbac_grants WHERE principal = $1
				UNION SELECT tenant FROM rbac_eligibilities WHERE principal = $1 ORDER BY tenant LIMIT $2`, p.key(), batch)
			if err != nil {
				return err
			}
			tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			n = len(tenants)
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
				if err := a.report(ctx, tx, ChangeEvent{Tenant: t, Actor: actor, Revoked: revoked, Ineligible: ended}); err != nil {
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

// DeleteTenant removes every grant, eligibility, custom role and deny in a tenant, as actor, so a
// tenant created later with its id starts with none.
func (a *Authorizer) DeleteTenant(ctx context.Context, actor Principal, tenant string) error {
	return a.delete(ctx, actor, tenant, func(tx pgx.Tx) error { return lockTenant(ctx, tx, tenant) },
		deletion{roles: true, denies: "TRUE", where: "TRUE"})
}

// deletion is what a delete removes in a tenant: grants and eligibilities where picks, denies
// where denies does (none when it is empty), and with roles its custom roles. Both read args
// from $2.
type deletion struct {
	roles         bool
	denies, where string
}

// delete removes what del picks in a tenant as actor, once lock holds.
func (a *Authorizer) delete(ctx context.Context, actor Principal, tenant string, lock func(pgx.Tx) error, del deletion, args ...any) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
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

// DeleteExpired removes grants and eligibilities that have expired, which no longer give or
// allow anything, and returns how many. It passes over those a change is holding, rather than
// wait on it, so the next run removes them.
func (a *Authorizer) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := a.db.Exec(ctx, `
		DELETE FROM rbac_grants WHERE id IN (
			SELECT id FROM rbac_grants WHERE expires_at <= $1 FOR UPDATE SKIP LOCKED)`, a.cfg.Now())
	if err != nil {
		return 0, err
	}
	ended, err := a.db.Exec(ctx, `
		DELETE FROM rbac_eligibilities WHERE id IN (
			SELECT id FROM rbac_eligibilities WHERE expires_at <= $1 FOR UPDATE SKIP LOCKED)`, a.cfg.Now())
	return tag.RowsAffected() + ended.RowsAffected(), err
}
