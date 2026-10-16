package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// InvalidError is a binding a change can't make, with why.
type InvalidError struct {
	Binding Binding
	Reason  string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("rbac: %s for %s: %s", e.Binding.Role, e.Binding.Principal.key(), e.Reason)
}

// Is makes an InvalidError match ErrInvalid.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

// Apply changes the grants on one scope, on, in one transaction, as actor:
//
//   - the actor needs `<on's type>:grant` there (through on, an ancestor or the tenant), or
//     owns it;
//   - to grant a role, the actor must hold every permission it gives there, or own it;
//   - a grant the actor makes expires no later than the actor's own access it rests on;
//   - a role that gives a `:grant` permission can't be granted to everyone;
//   - revoking needs only `<on's type>:grant`.
//
// Every invalid binding is reported at once, joined. Config.OnChange runs in the transaction
// with the grants that changed.
func (a *Authorizer) Apply(ctx context.Context, actor Subject, on Resource, c Change) error {
	if err := on.validate(); err != nil {
		return err
	}
	scope := on.Scope()
	grants, revokes := dedupe(c)
	if len(grants)+len(revokes) == 0 {
		return nil
	}
	if actor.Tenant != on.Tenant {
		return &DeniedError{Permission: GrantPermission(scope.Type), Scope: scope, Reason: "the scope is in another tenant"}
	}
	if err := a.validate(ctx, on.Tenant, scope, grants, revokes); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.User, func(tx pgx.Tx) (granted, revoked []Grant, err error) {
		// Decided in the transaction, so the actor's access is read as the change is made.
		if err := a.mayChange(ctx, tx, actor, on, grants); err != nil {
			return nil, nil, err
		}
		if revoked, err = a.revoke(ctx, tx, on.Tenant, scope, revokes); err != nil {
			return nil, nil, err
		}
		granted, err = a.upsert(ctx, tx, on.Tenant, actor.User, scopeGrants(scope, grants))
		return granted, revoked, err
	})
}

// Import stores grants without the actor checks Apply makes, for migrations and seeding. Each
// grant is still validated, except that principals aren't asked about.
func (a *Authorizer) Import(ctx context.Context, tenant string, grants []Grant) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	var errs []error
	for _, g := range grants {
		if !g.Scope.in(tenant) {
			errs = append(errs, &InvalidError{Binding: g.Binding, Reason: fmt.Sprintf("scope %q is not valid", g.Scope.Key())})
			continue
		}
		errs = append(errs, a.checkBinding(g.Scope, g.Binding, a.cfg.Now())...)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, "", func(tx pgx.Tx) ([]Grant, []Grant, error) {
		granted, err := a.upsert(ctx, tx, tenant, "", grants)
		return granted, nil, err
	})
}

// dedupe drops repeated bindings and bindings revoked and granted at once (granted wins).
func dedupe(c Change) (grants, revokes []Binding) {
	type id struct {
		role Role
		p    Principal
	}
	granted := map[id]bool{}
	for _, b := range slices.Backward(c.Grant) {
		k := id{b.Role, b.Principal}
		if !granted[k] {
			granted[k] = true
			grants = append(grants, b)
		}
	}
	revoked := map[id]bool{}
	for _, b := range c.Revoke {
		k := id{b.Role, b.Principal}
		if !granted[k] && !revoked[k] {
			revoked[k] = true
			revokes = append(revokes, b)
		}
	}
	return grants, revokes
}

func (a *Authorizer) validate(ctx context.Context, tenant string, scope Scope, grants, revokes []Binding) error {
	var errs []error
	now := a.cfg.Now()
	for _, b := range grants {
		bad := a.checkBinding(scope, b, now)
		if len(bad) == 0 && b.Principal.Kind != Everyone {
			if err := a.cfg.ValidatePrincipal(ctx, tenant, b.Principal); err != nil {
				bad = append(bad, &InvalidError{Binding: b, Reason: "not in the tenant: " + err.Error()})
			}
		}
		errs = append(errs, bad...)
	}
	for _, b := range revokes {
		// A role no longer in the catalog can still be revoked.
		if !b.Principal.valid() {
			errs = append(errs, &InvalidError{Binding: b, Reason: "the principal is not valid"})
		}
	}
	return errors.Join(errs...)
}

// checkBinding returns why a binding can't be granted on a scope.
func (a *Authorizer) checkBinding(scope Scope, b Binding, now time.Time) []error {
	var errs []error
	bad := func(reason string) { errs = append(errs, &InvalidError{Binding: b, Reason: reason}) }
	if !b.Principal.valid() {
		bad("the principal is not valid")
	}
	def, ok := a.roles[b.Role]
	switch {
	case !ok:
		bad("no such role")
	case !a.grantableOn(def, scope.Type):
		bad(fmt.Sprintf("can't be granted on a %s", scope.Type))
	case b.Principal.Kind == Everyone && def.managesAccess():
		bad("a role that changes access can't be granted to everyone")
	}
	if !b.ExpiresAt.IsZero() && !b.ExpiresAt.After(now) {
		bad("already expired")
	}
	return errs
}

// mayChange checks the actor's own access on the scope against the change.
func (a *Authorizer) mayChange(ctx context.Context, q DB, actor Subject, on Resource, grants []Binding) error {
	scope := on.Scope()
	if actor.User != "" && actor.User == on.Owner {
		return nil
	}
	held, err := a.heldGrants(ctx, q, on.Tenant, actor.principals(), on.Path())
	if err != nil {
		return err
	}
	// holds reports whether the actor holds p for one of types, and until when (zero: always).
	holds := func(p Permission, types []string) (bool, time.Time) {
		ok, forever := false, false
		var until time.Time
		for _, g := range held {
			def, known := a.roles[g.Role]
			if !known || !def.Gives(p) || !slices.ContainsFunc(types, def.GrantableOn) {
				continue
			}
			ok = true
			if g.ExpiresAt.IsZero() {
				forever = true
			} else if g.ExpiresAt.After(until) {
				until = g.ExpiresAt
			}
		}
		if forever {
			until = time.Time{}
		}
		return ok, until
	}

	manage := GrantPermission(scope.Type)
	ok, limit := holds(manage, []string{scope.Type})
	if !ok {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "the actor may not change access here"}
	}
	var errs []error
	for _, b := range grants {
		def := a.roles[b.Role]
		until := limit
		for _, p := range def.Permissions {
			ok, held := holds(p, def.ResourceTypes)
			if !ok {
				errs = append(errs, &DeniedError{
					Permission: p, Scope: scope,
					Reason: fmt.Sprintf("the actor can't grant %s without holding %s here", b.Role, p),
				})
				break
			}
			until = earliest(until, held)
		}
		if !until.IsZero() && (b.ExpiresAt.IsZero() || b.ExpiresAt.After(until)) {
			errs = append(errs, &DeniedError{
				Permission: manage, Scope: scope,
				Reason: fmt.Sprintf("a grant of %s must expire by %s, when the actor's own access does", b.Role, until.UTC().Format(time.RFC3339)),
			})
		}
	}
	return errors.Join(errs...)
}

// earliest is the earlier of two ends, where zero is never.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}

func scopeGrants(scope Scope, bindings []Binding) []Grant {
	grants := make([]Grant, len(bindings))
	for i, b := range bindings {
		grants[i] = Grant{Scope: scope, Binding: b}
	}
	return grants
}

// inTx runs fn in a transaction and hands what it changed to Config.OnChange there.
func (a *Authorizer) inTx(ctx context.Context, tenant, actor string, fn func(pgx.Tx) (granted, revoked []Grant, err error)) error {
	return pgx.BeginFunc(ctx, a.db, func(tx pgx.Tx) error {
		granted, revoked, err := fn(tx)
		if err != nil {
			return err
		}
		if a.cfg.OnChange == nil || len(granted)+len(revoked) == 0 {
			return nil
		}
		return a.cfg.OnChange(ctx, tx, ChangeEvent{Tenant: tenant, Actor: actor, Granted: granted, Revoked: revoked})
	})
}

// upsert stores grants in one statement, sorted so concurrent changes lock rows in the same
// order, and returns those it added or whose expiry it changed.
func (a *Authorizer) upsert(ctx context.Context, tx pgx.Tx, tenant, actor string, grants []Grant) ([]Grant, error) {
	if len(grants) == 0 {
		return nil, nil
	}
	grants = slices.Clone(grants)
	slices.SortFunc(grants, func(x, y Grant) int {
		return cmp.Or(cmp.Compare(x.Principal.key(), y.Principal.key()),
			cmp.Compare(x.Scope.Key(), y.Scope.Key()), cmp.Compare(x.Role, y.Role))
	})
	n := len(grants)
	scopeTypes, scopeIDs, kinds, ids, roles := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	expires := make([]pgtype.Timestamptz, n)
	for i, g := range grants {
		scopeTypes[i], scopeIDs[i] = g.Scope.Type, g.Scope.ID
		kinds[i], ids[i], roles[i] = string(g.Principal.Kind), g.Principal.ID, string(g.Role)
		expires[i] = pgtype.Timestamptz{Time: g.ExpiresAt, Valid: !g.ExpiresAt.IsZero()}
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at, created_by)
		SELECT $1, st, si, pk, pi, r, e, $8
		FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[]) AS t(st, si, pk, pi, r, e)
		ON CONFLICT ON CONSTRAINT rbac_grants_key DO UPDATE SET expires_at = EXCLUDED.expires_at
		WHERE rbac_grants.expires_at IS DISTINCT FROM EXCLUDED.expires_at
		RETURNING `+grantColumns,
		tenant, scopeTypes, scopeIDs, kinds, ids, roles, expires, actor)
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

// revoke deletes bindings from a scope and returns the grants it removed.
func (a *Authorizer) revoke(ctx context.Context, tx pgx.Tx, tenant string, scope Scope, bindings []Binding) ([]Grant, error) {
	if len(bindings) == 0 {
		return nil, nil
	}
	principals, roles := make([]string, len(bindings)), make([]string, len(bindings))
	for i, b := range bindings {
		principals[i], roles[i] = b.Principal.key(), string(b.Role)
	}
	rows, err := tx.Query(ctx, `
		DELETE FROM rbac_grants
		WHERE tenant = $1 AND scope = $2
		  AND (principal, role) IN (SELECT * FROM unnest($3::text[], $4::text[]))
		RETURNING `+grantColumns,
		tenant, scope.Key(), principals, roles)
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

// GrantFilter picks grants by scope, by principal, or both; at least one is required.
type GrantFilter struct {
	Scopes     []Scope
	Principals []Principal
}

// Grants lists the grants in force that match the filter: who has access to a resource and
// through which ancestor, or what a user or group holds (RBAC's assigned roles).
func (a *Authorizer) Grants(ctx context.Context, tenant string, f GrantFilter) ([]Grant, error) {
	if tenant == "" || len(f.Scopes)+len(f.Principals) == 0 {
		return nil, fmt.Errorf("%w: Grants needs a tenant and scopes or principals", ErrInvalid)
	}
	scopes := make([]string, len(f.Scopes))
	for i, s := range f.Scopes {
		scopes[i] = s.Key()
	}
	principals := make([]string, len(f.Principals))
	for i, p := range f.Principals {
		principals[i] = p.key()
	}
	where := "scope = ANY($2::text[]) AND principal = ANY($3::text[])"
	switch {
	case len(principals) == 0:
		where = "scope = ANY($2::text[]) AND $3::text[] IS NULL"
		principals = nil
	case len(scopes) == 0:
		where = "$2::text[] IS NULL AND principal = ANY($3::text[])"
		scopes = nil
	}
	rows, err := a.db.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND `+where+` AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY scope, principal, role`,
		tenant, scopes, principals, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

// DeleteScope removes every grant on a scope, as when the resource or container is deleted.
func (a *Authorizer) DeleteScope(ctx context.Context, tenant string, s Scope) error {
	return a.delete(ctx, tenant, "scope = $2", s.Key())
}

// DeletePrincipal removes every grant to a user or group, as when it is deleted.
func (a *Authorizer) DeletePrincipal(ctx context.Context, tenant string, p Principal) error {
	return a.delete(ctx, tenant, "principal = $2", p.key())
}

// DeleteTenant removes every grant in a tenant.
func (a *Authorizer) DeleteTenant(ctx context.Context, tenant string) error {
	return a.delete(ctx, tenant, "$2::text IS NOT NULL", "")
}

func (a *Authorizer) delete(ctx context.Context, tenant, where string, arg string) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	return a.inTx(ctx, tenant, "", func(tx pgx.Tx) ([]Grant, []Grant, error) {
		rows, err := tx.Query(ctx, `DELETE FROM rbac_grants WHERE tenant = $1 AND `+where+` RETURNING `+grantColumns, tenant, arg)
		if err != nil {
			return nil, nil, err
		}
		revoked, err := collectGrants(rows)
		return nil, revoked, err
	})
}

// DeleteExpired removes grants that have expired, which no longer give anything, and returns
// how many.
func (a *Authorizer) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := a.db.Exec(ctx, `DELETE FROM rbac_grants WHERE expires_at <= $1`, a.cfg.Now())
	return tag.RowsAffected(), err
}
