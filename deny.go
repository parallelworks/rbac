package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Deny is a deny policy: on its scope and everything under it, it removes permissions from
// principals, whatever their grants give, as a guardrail above roles. A principal it names is
// an identity, a user or of a kind the host declares, a group, a tenant's members or the public
// (everyone, signed in or not); those Exempt names, identities or groups, keep their access. One
// of a kind the host doesn't declare, which no subject can be, is refused, as a grant to it is. A
// deny naming the public may exempt the tenant's members, to bind only those who aren't; the
// public itself is never exempt, as that would exempt everyone, nor is a principal it names.
// Permissions are `type:verb`, or `type:*` for every permission on a type. With a Condition it
// denies only where the expression holds, or can't be evaluated.
type Deny struct {
	// ID names it on its scope, in lowercase letters, digits, dots, hyphens and underscores.
	ID          string
	Scope       Scope
	Name        string
	Principals  []Principal
	Exempt      []Principal
	Permissions []Permission
	Condition   Condition
	// CreatedBy, CreatedAt, UpdatedBy and UpdatedAt are set on denies read back.
	CreatedBy Principal
	CreatedAt time.Time
	UpdatedBy Principal
	UpdatedAt time.Time
}

// DenyPermission is the permission to set and delete the deny policies on scopes of a type.
func DenyPermission(scopeType string) Permission { return Permission(scopeType + ":deny") }

var denyID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// undeniable reports whether no deny can remove p: the permission to set and delete denies,
// so a guard on a scope above can always lift one set below, however wide.
func undeniable(p Permission) bool {
	_, verb := p.parts()
	return verb == "deny"
}

// matchable is what deny queries match for p: p and the `type:*` that covers it; for a
// permission none can remove, ok is false, and nothing is read, so no row stored around the
// package can remove it either.
func matchable(p Permission) (perm, wildcard string, ok bool) {
	if undeniable(p) {
		return "", "", false
	}
	t, _ := p.parts()
	return string(p), t + ":*", true
}

// denies reports whether a permission a deny lists covers p.
func denies(listed []Permission, p Permission) bool {
	perm, wildcard, ok := matchable(p)
	return ok && (slices.Contains(listed, Permission(perm)) || slices.Contains(listed, Permission(wildcard)))
}

// denial is a deny as a check reads it.
type denial struct {
	id, scope          string
	permissions        []Permission
	principals, exempt []string
	condition          string
	// unevaluated is set on a deny that removed a permission because its condition couldn't be
	// evaluated, failing closed, and spent where that was because the check's budget ran out.
	unevaluated, spent bool
}

// deniesOn reads the denies on scopes that name one of binding and exempt none of exempt, the
// keys keysOf and exempting give, or name anyone when binding is nil, listing p.
func (a *Authorizer) deniesOn(ctx context.Context, q DB, tenant string, binding, exempt, scopes []string, p Permission) ([]denial, error) {
	perm, wildcard, ok := matchable(p)
	if binding != nil && len(binding) == 0 || !ok {
		return nil, nil
	}
	// In the order a check reads them, so Explain names the deny Authorize does.
	rows, err := q.Query(ctx, byKey("$2", "rbac_denies", "scope", "id, scope, permissions, principals, exempt, condition", `tenant = $1
		  AND ($3::text[] IS NULL OR principals && $3::text[] AND NOT exempt && $6::text[])
		  AND ($4 = ANY(permissions) OR $5 = ANY(permissions))`)+`
		ORDER BY id, scope`,
		tenant, scopes, binding, perm, wildcard, exempt)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (denial, error) {
		var d denial
		var perms []string
		err := row.Scan(&d.id, &d.scope, &perms, &d.principals, &d.exempt, &d.condition)
		for _, x := range perms {
			d.permissions = append(d.permissions, Permission(x))
		}
		return d, err
	})
}

// deniedBy returns the first deny that removes p for this request: an unconditional one, or one
// whose condition holds or can't be evaluated, failing closed, the cheapest first.
func (a *Authorizer) deniedBy(ds []denial, p Permission, spend *budget, vars map[string]any) (denial, bool) {
	var conditional []denial
	for _, d := range ds {
		switch {
		case !denies(d.permissions, p):
		case d.condition == "":
			return d, true
		default:
			conditional = append(conditional, d)
		}
	}
	cheapestFirst(conditional, denial.expression)
	for _, d := range conditional {
		held, evaluated := a.conds.decide(spend, d.condition, vars)
		if held || !evaluated {
			d.unevaluated, d.spent = !evaluated, !evaluated && spend.exhausted
			return d, true
		}
	}
	return denial{}, false
}

func (d denial) expression() string { return d.condition }

func (d denial) String() string { return "deny " + d.id + " on " + d.scope }

// removal is why d removed a permission, for Decision.Reason.
func (d denial) removal() string {
	switch {
	case d.spent:
		return "removed by " + d.String() + ", whose condition couldn't be evaluated within the check's budget"
	case d.unevaluated:
		return "removed by " + d.String() + ", whose condition couldn't be evaluated"
	}
	return "removed by " + d.String()
}

// checkDeny returns why a deny is malformed.
func (a *Authorizer) checkDeny(tenant string, d Deny) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if !denyID.MatchString(d.ID) {
		bad("id %q is lowercase letters, digits, dots, hyphens and underscores", d.ID)
	}
	if utf8.RuneCountInString(d.Name) > MaxName || !validText(d.Name) {
		bad("a name is valid text of at most %d characters", MaxName)
	}
	if len(d.Principals) == 0 || len(d.Principals) > MaxDenyEntries || len(d.Exempt) > MaxDenyEntries {
		bad("it names 1 to %d principals and exempts at most %d", MaxDenyEntries, MaxDenyEntries)
	}
	// Of a kind the host declares, as a grant's principal is: one of another, such as a misspelled
	// kind, no subject can be, so a deny naming it would bind no one, and one exempting it would
	// leave bound whom it meant to exempt.
	for _, p := range slices.Concat(d.Principals, d.Exempt) {
		if !a.known(tenant, p) {
			bad("principal %q is not valid", p.key())
		}
	}
	// A set, so lists past the limit cost no more than one pass each.
	named := make(map[Principal]bool, len(d.Principals))
	for _, p := range d.Principals {
		named[p] = true
	}
	// Every subject is the public, and every member a tenant's members, so exempting either where
	// it doesn't narrow the deny would exempt everyone it names, and it would bind no one.
	for _, p := range d.Exempt {
		switch {
		case p.Kind == Public:
			bad("exempting the public exempts everyone")
		case p.Kind == Members && !named[Principal{Kind: Public}]:
			bad("only a deny naming the public may exempt the tenant's members")
		case named[p]:
			bad("principal %q is both named and exempt", p.key())
		}
	}
	if len(d.Permissions) == 0 || len(d.Permissions) > MaxDenyEntries {
		bad("it denies 1 to %d permissions", MaxDenyEntries)
	}
	for _, p := range d.Permissions {
		t, verb := p.parts()
		switch {
		case !p.Valid() && (verb != "*" || !validName(t)):
			bad("permission %q is not `type:verb` or `type:*`", p)
		case undeniable(p):
			bad("permission %q sets denies, which no deny removes, so a guard above can always lift one", p)
		case verb == "*" && !a.permissionTypes[t]:
			bad("permission %q is for a type no built-in role's permissions are", p)
		case verb != "*" && !a.permissions[p]:
			bad("permission %q is not one any built-in role gives", p)
		}
		// Checks read a subject's label values on the tenant, so a deny of one on a scope under it
		// would be stored and bind no one.
		if _, value := a.labels[t]; value && d.Scope.Type != TenantScope {
			bad("permission %q is a label value or a power to release, which is held on the tenant, so it is denied there alone", p)
		}
	}
	for _, fault := range a.conditionFaults(nil, d.Condition) {
		bad("%s", fault)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: deny %q: %w", ErrInvalid, d.ID, errors.Join(errs...))
	}
	return nil
}

// SetDeny creates or replaces a deny policy on a scope, on, as actor, who needs
// DenyPermission(on's type) there (through on, an ancestor or the tenant), not removed by a
// constraint. A deny only takes access away, so setting one needs no more than that; one can
// deny its setter too. A scope's conditional denies are bounded together by what a check may spend
// on conditions, so that one always evaluates them: about seven short distinct conditions, or
// three of the longest, however many denies share them. Whoever holds that permission on the
// scope, those the deny names included, can replace or delete it, so to bind one who holds it
// there, set the deny on a scope above where it doesn't. The groups it names or exempts, and a
// group it is on, are the tenant's.
func (a *Authorizer) SetDeny(ctx context.Context, actor Subject, on Resource, d Deny) (err error) {
	defer a.refused(ctx, &err, on.Tenant, actor.Principal, "SetDeny")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	d.Scope = on.Scope()
	cs, err := a.mayDeny(ctx, actor, on)
	if err != nil {
		return err
	}
	if err := a.checkDeny(on.Tenant, d); err != nil {
		return err
	}
	d = canonicalDeny(d)
	groups := groupKeys(slices.Concat(d.Principals, d.Exempt))
	return a.inTx(ctx, on.Tenant, actor.Principal, "SetDeny", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, on.Tenant, []string{d.Scope.Key()}, groups); err != nil {
			return ChangeEvent{}, err
		}
		if err := groupsExist(ctx, tx, on.Tenant, slices.Concat(groups, groupScopes([]Scope{d.Scope}))); err != nil {
			return ChangeEvent{}, err
		}
		cs.seal()
		if err := a.denyAllowed(ctx, tx, actor, on, cs, nil, nil); err != nil {
			return ChangeEvent{}, err
		}
		var others int
		var conditions []string
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(array_agg(condition) FILTER (WHERE condition <> ''), '{}')
			FROM rbac_denies WHERE tenant = $1 AND scope = $2 AND id <> $3`,
			on.Tenant, d.Scope.Key(), d.ID).Scan(&others, &conditions); err != nil {
			return ChangeEvent{}, err
		}
		if others >= MaxDenies {
			return ChangeEvent{}, fmt.Errorf("%w: a scope has at most %d denies", ErrInvalid, MaxDenies)
		}
		// Past this, a check's budget could run out before it evaluated them, and the rest would
		// deny everyone they name, whatever their conditions say.
		if d.Condition.Expression != "" && !affordable(append(conditions, d.Condition.Expression)) {
			return ChangeEvent{}, fmt.Errorf("%w: a scope's conditional denies cost more together than a check may spend evaluating them", ErrInvalid)
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, name, principals, exempt, permissions,
			  condition_title, condition_description, condition, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)
			ON CONFLICT (tenant, scope_type, scope_id, id) DO UPDATE SET name = EXCLUDED.name,
			  principals = EXCLUDED.principals, exempt = EXCLUDED.exempt, permissions = EXCLUDED.permissions,
			  condition_title = EXCLUDED.condition_title, condition_description = EXCLUDED.condition_description,
			  condition = EXCLUDED.condition, updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE (rbac_denies.name, rbac_denies.principals, rbac_denies.exempt, rbac_denies.permissions,
			  rbac_denies.condition_title, rbac_denies.condition_description, rbac_denies.condition)
			  IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.principals, EXCLUDED.exempt, EXCLUDED.permissions,
			  EXCLUDED.condition_title, EXCLUDED.condition_description, EXCLUDED.condition)
			RETURNING `+denyColumns,
			on.Tenant, d.Scope.Type, d.Scope.ID, d.ID, d.Name, keysOf(d.Principals), keysOf(d.Exempt), permissionStrings(d.Permissions),
			d.Condition.Title, d.Condition.Description, d.Condition.Expression, actorKey(actor.Principal))
		if err != nil {
			return ChangeEvent{}, err
		}
		set, err := collectDenies(rows)
		return ChangeEvent{Denies: set}, err
	})
}

// DeleteDeny deletes a deny policy from a scope, as actor, who needs DenyPermission(on's type)
// there. Deleting one that doesn't exist does nothing.
func (a *Authorizer) DeleteDeny(ctx context.Context, actor Subject, on Resource, id string) (err error) {
	defer a.refused(ctx, &err, on.Tenant, actor.Principal, "DeleteDeny")
	if err := a.check(on); err != nil {
		return err
	}
	if !validText(id) {
		return fmt.Errorf("%w: deny %q is not text without NUL", ErrInvalid, id)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	cs, err := a.mayDeny(ctx, actor, on)
	if err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, "DeleteDeny", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{on.Scope().Key()}, nil); err != nil {
			return ChangeEvent{}, err
		}
		cs.seal()
		if err := a.denyAllowed(ctx, tx, actor, on, cs, nil, nil); err != nil {
			return ChangeEvent{}, err
		}
		rows, err := tx.Query(ctx, `DELETE FROM rbac_denies WHERE tenant = $1 AND scope = $2 AND id = $3 RETURNING `+denyColumns,
			on.Tenant, on.Scope().Key(), id)
		if err != nil {
			return ChangeEvent{}, err
		}
		deleted, err := collectDenies(rows)
		return ChangeEvent{DeletedDenies: deleted}, err
	})
}

// mayDeny checks, before the transaction, that actor may set and delete the denies on a scope,
// one of a type the host has, as changing does for grants, and returns the constraints' answers,
// which the transaction reads back to check the actor's label values again under its locks. The
// constraints run here only, as in Apply: a hook that queries the pool while the transaction holds
// a connection can wait forever on a busy pool.
func (a *Authorizer) mayDeny(ctx context.Context, actor Subject, on Resource) (*constrained, error) {
	cs := a.constrain(ctx, actor, on)
	return cs, a.denyAllowed(ctx, a.db, actor, on, cs, nil, nil)
}

// denyAllowed is what setting or deleting a deny on on checks, and a change to members lifting one
// there: before the change's transaction, the constraints on it, asked through cs, then on's label
// and that the actor holds DenyPermission(on's type) there; and once cs is sealed, under its locks,
// what it holds and the label again. The actor's label values are read through labels, or where
// nil, cs on the tenant, and what it holds on q, or is au, where read already.
func (a *Authorizer) denyAllowed(ctx context.Context, q DB, actor Subject, on Resource, cs, labels *constrained, au *authority) error {
	checkLabel := func() error { return a.labelAllows(ctx, q, on, cs, labels, DenyPermission(on.Type)) }
	if !cs.sealed {
		if err := a.denying(actor, on, cs); err != nil {
			return err
		}
		// Who can't see a labeled scope sets no deny on it, nor lifts one, which would widen access.
		if err := checkLabel(); err != nil {
			return err
		}
	}
	held, err := a.authorityOr(ctx, q, actor, on, nil, au)
	if err != nil {
		return err
	}
	if err := held.setsDenies(on); err != nil {
		return err
	}
	if cs.sealed {
		return checkLabel()
	}
	return nil
}

// denying refuses setting or deleting the denies on a scope of a type the host doesn't have, by an
// anonymous actor, or one a constraint on DenyPermission(on's type) stops, asked through cs.
func (a *Authorizer) denying(actor Subject, on Resource, cs *constrained) error {
	if err := a.scopeOf(on); err != nil {
		return err
	}
	perm := DenyPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: perm, Scope: on.Scope(), Reason: "an anonymous subject changes nothing"}
	}
	if cs.removes(perm, on.Type) {
		return cmp.Or(cs.failed(), error(&DeniedError{Permission: perm, Scope: on.Scope(), Reason: "removed by " + cs.removedBy(perm)}))
	}
	return nil
}

// setsDenies refuses an actor whose authority on on, au, doesn't give DenyPermission(on's type).
func (au authority) setsDenies(on Resource) error {
	perm := DenyPermission(on.Type)
	if !au.may(perm, on.Type) {
		return &DeniedError{Permission: perm, Scope: on.Scope(), Reason: "the actor may not set denies here"}
	}
	return nil
}

// Denies lists the deny policies on scopes in a tenant, as stored.
func (a *Authorizer) Denies(ctx context.Context, tenant string, scopes []Scope) ([]Deny, error) {
	if !validID(tenant) || len(scopes) == 0 || slices.ContainsFunc(scopes, func(s Scope) bool { return !s.valid() }) {
		return nil, fmt.Errorf("%w: Denies needs a tenant and valid scopes", ErrInvalid)
	}
	keys := make([]string, len(scopes))
	for i, s := range scopes {
		keys[i] = s.Key()
	}
	slices.Sort(keys)
	rows, err := a.db.Query(ctx, `SELECT `+denyColumns+` FROM (`+byKey("$2", "rbac_denies", "scope", denyColumns+", scope", "tenant = $1")+`) d
		ORDER BY scope, id`, tenant, slices.Compact(keys))
	if err != nil {
		return nil, err
	}
	return collectDenies(rows)
}

const denyColumns = `scope_type, scope_id, id, name, principals, exempt, permissions,
	condition_title, condition_description, condition, created_by, created_at, updated_by, updated_at`

func collectDenies(rows pgx.Rows) ([]Deny, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Deny, error) {
		var d Deny
		var principals, exempt, perms []string
		var createdBy, updatedBy string
		err := row.Scan(&d.Scope.Type, &d.Scope.ID, &d.ID, &d.Name, &principals, &exempt, &perms,
			&d.Condition.Title, &d.Condition.Description, &d.Condition.Expression, &createdBy, &d.CreatedAt, &updatedBy, &d.UpdatedAt)
		for _, k := range principals {
			d.Principals = append(d.Principals, parsePrincipal(k))
		}
		for _, k := range exempt {
			d.Exempt = append(d.Exempt, parsePrincipal(k))
		}
		for _, p := range perms {
			d.Permissions = append(d.Permissions, Permission(p))
		}
		d.CreatedBy, d.UpdatedBy = parsePrincipal(createdBy), parsePrincipal(updatedBy)
		return d, err
	})
}

// canonicalDeny is a copy of d with its lists sorted and without repeats, so a deny reordered is
// the same one.
func canonicalDeny(d Deny) Deny {
	d.Principals, d.Exempt = canonicalPrincipals(d.Principals), canonicalPrincipals(d.Exempt)
	d.Permissions = slices.Compact(slices.Sorted(slices.Values(d.Permissions)))
	return d
}

// canonicalPrincipals is a copy of ps sorted by key and without repeats.
func canonicalPrincipals(ps []Principal) []Principal {
	byKey := func(x, y Principal) int { return strings.Compare(x.key(), y.key()) }
	return slices.CompactFunc(slices.SortedFunc(slices.Values(ps), byKey), func(x, y Principal) bool { return x == y })
}

func keysOf(ps []Principal) []string {
	keys := make([]string, len(ps))
	for i, p := range ps {
		keys[i] = p.key()
	}
	return keys
}

func permissionStrings(ps []Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	return out
}
