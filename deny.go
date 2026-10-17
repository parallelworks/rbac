package rbac

import (
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
// an identity, a group, a tenant's members or the public (everyone, signed in or not); those
// Exempt names keep their access. Permissions are `type:verb`, or `type:*` for every permission
// on a type. With a Condition it denies only where the expression holds, or can't be evaluated.
type Deny struct {
	// ID names it on its scope, in lowercase letters, digits, dots, hyphens and underscores.
	ID          string
	Scope       Scope
	Name        string
	Principals  []Principal
	Exempt      []Principal
	Permissions []Permission
	Condition   Condition
	// CreatedBy and CreatedAt are set on denies read back.
	CreatedBy Principal
	CreatedAt time.Time
}

// DenyPermission is the permission to set and delete the deny policies on scopes of a type.
func DenyPermission(scopeType string) Permission { return Permission(scopeType + ":deny") }

// A scope holds at most maxDenies, each naming at most maxDenied principals and permissions,
// so the denies a check reads stay bounded.
const (
	maxDenies = 100
	maxDenied = 256
)

var denyID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// wildcard is the `type:*` a deny lists to cover every permission on p's type.
func wildcard(p Permission) string {
	t, _ := p.parts()
	return t + ":*"
}

// denies reports whether a permission a deny lists covers p.
func denies(listed []Permission, p Permission) bool {
	return slices.Contains(listed, p) || slices.Contains(listed, Permission(wildcard(p)))
}

// denial is a deny as a check reads it.
type denial struct {
	id, name, scope    string
	permissions        []Permission
	principals, exempt []string
	condition          string
}

// names reports whether d removes access from a holder Holders lists: one it names, or every
// one when it names the public, every member when it names a tenant's members, and none it
// exempts. A group's members aren't known here.
func (d denial) names(tenant string, h Principal) bool {
	if slices.Contains(d.exempt, h.key()) {
		return false
	}
	return slices.Contains(d.principals, h.key()) || slices.Contains(d.principals, publicKey) ||
		h.Kind != Public && slices.Contains(d.principals, TenantMembers(tenant).key())
}

// applies reports whether a deny removes p for this request: always, or where its condition
// holds or can't be evaluated, failing closed.
func (a *Authorizer) applies(d denial, spend *budget, vars map[string]any) bool {
	if d.condition == "" {
		return true
	}
	held, evaluated := a.conds.decide(spend, d.condition, vars)
	return held || !evaluated
}

// deniesOn reads the denies on scopes that name one of keys, and none it exempts, or name
// anyone when keys is nil, listing p, or any permission when p is empty.
func (a *Authorizer) deniesOn(ctx context.Context, q DB, tenant string, keys, scopes []string, p Permission) ([]denial, error) {
	if keys != nil && len(keys) == 0 {
		return nil, nil
	}
	// In the order a check reads them, so Explain names the deny Authorize does.
	rows, err := q.Query(ctx, `
		SELECT id, name, scope, permissions, principals, exempt, condition FROM rbac_denies
		WHERE tenant = $1 AND scope = ANY($2::text[])
		  AND ($3::text[] IS NULL OR principals && $3::text[] AND NOT exempt && $3::text[])
		  AND ($4 = '' OR $4 = ANY(permissions) OR $5 = ANY(permissions))
		ORDER BY id, scope`,
		tenant, scopes, keys, string(p), wildcard(p))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (denial, error) {
		var d denial
		var perms []string
		err := row.Scan(&d.id, &d.name, &d.scope, &perms, &d.principals, &d.exempt, &d.condition)
		for _, x := range perms {
			d.permissions = append(d.permissions, Permission(x))
		}
		return d, err
	})
}

// deniedBy returns the first deny that removes p for this request, unconditional ones first.
func (a *Authorizer) deniedBy(ds []denial, p Permission, spend *budget, vars map[string]any) (denial, bool) {
	for _, conditional := range []bool{false, true} {
		for _, d := range ds {
			if (d.condition != "") == conditional && denies(d.permissions, p) && a.applies(d, spend, vars) {
				return d, true
			}
		}
	}
	return denial{}, false
}

func (d denial) String() string { return "deny " + d.id + " on " + d.scope }

// checkDeny returns why a deny is malformed.
func (a *Authorizer) checkDeny(tenant string, d Deny) error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if !denyID.MatchString(d.ID) {
		bad("id %q is lowercase letters, digits, dots, hyphens and underscores", d.ID)
	}
	if utf8.RuneCountInString(d.Name) > maxName || !validText(d.Name) {
		bad("a name is valid text of at most %d characters", maxName)
	}
	if len(d.Principals) == 0 || len(d.Principals) > maxDenied || len(d.Exempt) > maxDenied {
		bad("it names 1 to %d principals and exempts at most %d", maxDenied, maxDenied)
	}
	for _, p := range slices.Concat(d.Principals, d.Exempt) {
		if !p.wellFormed(tenant) {
			bad("principal %q is not valid", p.key())
		}
	}
	if len(d.Permissions) == 0 || len(d.Permissions) > maxDenied {
		bad("it denies 1 to %d permissions", maxDenied)
	}
	for _, p := range d.Permissions {
		t, verb := p.parts()
		if !p.Valid() && (verb != "*" || !validName(t)) {
			bad("permission %q is not `type:verb` or `type:*`", p)
		}
	}
	for _, fault := range a.conditionFaults(d.Condition) {
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
// deny its setter too.
func (a *Authorizer) SetDeny(ctx context.Context, actor Subject, on Resource, d Deny) error {
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	d.Scope = on.Scope()
	if err := a.mayDeny(ctx, actor, on); err != nil {
		return err
	}
	if err := a.checkDeny(on.Tenant, d); err != nil {
		return err
	}
	d = canonicalDeny(d)
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{d.Scope.Key()}, nil); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.holdsDeny(ctx, tx, actor, on); err != nil {
			return ChangeEvent{}, err
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM rbac_denies WHERE tenant = $1 AND scope = $2 AND id <> $3`,
			on.Tenant, d.Scope.Key(), d.ID).Scan(&others); err != nil {
			return ChangeEvent{}, err
		}
		if others >= maxDenies {
			return ChangeEvent{}, fmt.Errorf("%w: a scope has at most %d denies", ErrInvalid, maxDenies)
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, name, principals, exempt, permissions,
			  condition_title, condition_description, condition, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (tenant, scope_type, scope_id, id) DO UPDATE SET name = EXCLUDED.name,
			  principals = EXCLUDED.principals, exempt = EXCLUDED.exempt, permissions = EXCLUDED.permissions,
			  condition_title = EXCLUDED.condition_title, condition_description = EXCLUDED.condition_description,
			  condition = EXCLUDED.condition
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
func (a *Authorizer) DeleteDeny(ctx context.Context, actor Subject, on Resource, id string) error {
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	if err := a.mayDeny(ctx, actor, on); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{on.Scope().Key()}, nil); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.holdsDeny(ctx, tx, actor, on); err != nil {
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

// mayDeny checks, before the transaction, that actor may set and delete the denies on a scope.
// The constraints run here only, as in Apply: a hook that queries the pool while the
// transaction holds a connection can wait forever on a busy pool.
func (a *Authorizer) mayDeny(ctx context.Context, actor Subject, on Resource) error {
	perm := DenyPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: perm, Scope: on.Scope(), Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, on.Tenant, on.Type, perm)
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: perm, Scope: on.Scope(), Reason: "removed by " + name}
	}
	return a.holdsDeny(ctx, a.db, actor, on)
}

// holdsDeny checks, on q, that actor holds DenyPermission(on's type) on a scope. A deny can
// remove that permission too, from the actor among others.
func (a *Authorizer) holdsDeny(ctx context.Context, q DB, actor Subject, on Resource) error {
	perm := DenyPermission(on.Type)
	au, err := a.authorityOn(ctx, q, actor, on, nil)
	if err != nil {
		return err
	}
	if !au.may(perm, on.Type) {
		return &DeniedError{Permission: perm, Scope: on.Scope(), Reason: "the actor may not set denies here"}
	}
	return nil
}

// Denies lists the deny policies on scopes in a tenant, as stored.
func (a *Authorizer) Denies(ctx context.Context, tenant string, scopes []Scope) ([]Deny, error) {
	if tenant == "" || len(scopes) == 0 {
		return nil, fmt.Errorf("%w: Denies needs a tenant and scopes", ErrInvalid)
	}
	keys := make([]string, len(scopes))
	for i, s := range scopes {
		keys[i] = s.Key()
	}
	rows, err := a.db.Query(ctx, `SELECT `+denyColumns+` FROM rbac_denies WHERE tenant = $1 AND scope = ANY($2::text[]) ORDER BY scope, id`, tenant, keys)
	if err != nil {
		return nil, err
	}
	return collectDenies(rows)
}

const denyColumns = `scope_type, scope_id, id, name, principals, exempt, permissions,
	condition_title, condition_description, condition, created_by, created_at`

func collectDenies(rows pgx.Rows) ([]Deny, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Deny, error) {
		var d Deny
		var principals, exempt, perms []string
		var createdBy string
		err := row.Scan(&d.Scope.Type, &d.Scope.ID, &d.ID, &d.Name, &principals, &exempt, &perms,
			&d.Condition.Title, &d.Condition.Description, &d.Condition.Expression, &createdBy, &d.CreatedAt)
		for _, k := range principals {
			d.Principals = append(d.Principals, parsePrincipal(k))
		}
		for _, k := range exempt {
			d.Exempt = append(d.Exempt, parsePrincipal(k))
		}
		for _, p := range perms {
			d.Permissions = append(d.Permissions, Permission(p))
		}
		d.CreatedBy = parsePrincipal(createdBy)
		return d, err
	})
}

// canonicalDeny is a copy of d with its lists sorted and without repeats, so a deny reordered is
// the same one.
func canonicalDeny(d Deny) Deny {
	byKey := func(x, y Principal) int { return strings.Compare(x.key(), y.key()) }
	for _, ps := range []*[]Principal{&d.Principals, &d.Exempt} {
		*ps = slices.CompactFunc(slices.SortedFunc(slices.Values(*ps), byKey), func(x, y Principal) bool { return x == y })
	}
	d.Permissions = slices.Compact(slices.Sorted(slices.Values(d.Permissions)))
	return d
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
