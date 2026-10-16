package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
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
//   - the actor needs `<on's type>:grant` there (through on, an ancestor or the tenant), and no
//     constraint may remove it. The owner of a resource needs no grant, but the owner of a
//     container doesn't count: a grant there reaches resources they don't own;
//   - to grant a role, the actor must hold every permission it gives there, or own the
//     resource;
//   - a grant the actor makes expires no later than the actor's own access it rests on;
//   - a role that gives a `:grant` permission can't be granted to a tenant's members or the
//     public, and only a role marked Public can be granted to the public;
//   - revoking needs only `<on's type>:grant`.
//
// The actor is a member of the scope's tenant: anonymous subjects and other tenants' members
// change nothing.
//
// Bindings are checked only once the actor may make the change, so a refused actor learns
// nothing about principals. Every invalid binding is reported at once, joined; an error from
// Config.ValidatePrincipal that isn't ErrInvalid fails the change as it is. Constraints and
// Config.ValidatePrincipal run before the transaction, on what the Authorizer runs on;
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
	manage := GrantPermission(scope.Type)
	if !actor.member(on.Tenant) {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "the actor isn't a member of the scope's tenant"}
	}
	// The hooks run outside the transaction: one that queries the pool while the transaction
	// holds a connection can wait forever on a busy pool.
	name, err := a.denied(ctx, on.Tenant, scope.Type, manage)
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "removed by " + name}
	}
	if err := a.mayChange(ctx, a.db, actor, on, grants); err != nil {
		return err
	}
	if err := a.validate(ctx, on.Tenant, scope, grants, revokes); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (granted, revoked []Grant, err error) {
		// One change to a scope at a time, so two changes can't deadlock on its rows.
		var principals []string
		for _, b := range slices.Concat(grants, revokes) {
			principals = append(principals, b.Principal.key())
		}
		if err := lock(ctx, tx, on.Tenant, []string{scope.Key()}, principals); err != nil {
			return nil, nil, err
		}
		// Decided again in the transaction, so the actor's access is read as the change is made.
		if err := a.mayChange(ctx, tx, actor, on, grants); err != nil {
			return nil, nil, err
		}
		if revoked, err = a.revoke(ctx, tx, on.Tenant, scope, revokes); err != nil {
			return nil, nil, err
		}
		granted, err = a.upsert(ctx, tx, on.Tenant, actor.Principal, scopeGrants(scope, grants))
		return granted, revoked, err
	})
}

// A change takes its tenant's lock shared, then the lock of each scope and of each principal
// whose grants it changes, in order; deleting a tenant takes the tenant's lock alone. So two
// changes to the same rows run in turn, and one call never deadlocks with another. The locks
// last until the transaction ends. Advisory locks span the database, so the keys name the
// schema: another application's grants are in a schema of their own.
const lockKey = `hashtextextended(current_schema() || '/rbac/' || $1, 0)`

// maxLocks is how many scopes and principals an Import locks one by one; a larger one locks
// the tenant, rather than fill PostgreSQL's lock table.
const maxLocks = 64

func lock(ctx context.Context, tx pgx.Tx, tenant string, scopes, principals []string) error {
	b := &pgx.Batch{}
	b.Queue(`SELECT pg_advisory_xact_lock_shared(`+lockKey+`)`, "tenant/"+tenant)
	for _, s := range slices.Compact(slices.Sorted(slices.Values(scopes))) {
		b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "scope/"+tenant+"/"+s)
	}
	for _, p := range slices.Compact(slices.Sorted(slices.Values(principals))) {
		b.Queue(`SELECT pg_advisory_xact_lock(`+lockKey+`)`, "principal/"+tenant+"/"+p)
	}
	return tx.SendBatch(ctx, b).Close()
}

func lockTenant(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+lockKey+`)`, "tenant/"+tenant)
	return err
}

// Import stores grants without the actor checks Apply makes, for migrations, seeding and the
// host's own grants, such as a role for whoever creates a container. Each grant is still
// validated, except that principals aren't asked about.
func (a *Authorizer) Import(ctx context.Context, tenant string, grants []Grant) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if len(grants) == 0 {
		return nil
	}
	grants = slices.Clone(grants)
	for i := range grants {
		grants[i].ExpiresAt = stored(grants[i].ExpiresAt)
	}
	var errs []error
	for _, g := range grants {
		if !g.Scope.in(tenant) {
			errs = append(errs, &InvalidError{Binding: g.Binding, Reason: fmt.Sprintf("scope %q is not valid", g.Scope.Key())})
			continue
		}
		errs = append(errs, a.checkBinding(tenant, g.Scope, g.Binding, a.cfg.Now())...)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	scopes, principals := map[string]bool{}, map[string]bool{}
	for _, g := range grants {
		scopes[g.Scope.Key()] = true
		principals[g.Principal.key()] = true
	}
	return a.inTx(ctx, tenant, Principal{}, func(tx pgx.Tx) ([]Grant, []Grant, error) {
		var err error
		if len(scopes)+len(principals) > maxLocks {
			err = lockTenant(ctx, tx, tenant)
		} else {
			err = lock(ctx, tx, tenant, slices.Collect(maps.Keys(scopes)), slices.Collect(maps.Keys(principals)))
		}
		if err != nil {
			return nil, nil, err
		}
		granted, err := a.upsert(ctx, tx, tenant, Principal{}, grants)
		return granted, nil, err
	})
}

// dedupe drops repeated bindings, keeping the last of each grant, and bindings revoked and
// granted at once (granted wins). What is left keeps the order given, as errors report it.
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
			b.ExpiresAt = stored(b.ExpiresAt)
			grants = append(grants, b)
		}
	}
	slices.Reverse(grants)
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
	// A change often gives one principal several roles; the host is asked about each once.
	member := map[Principal]bool{}
	inTenant := func(p Principal) (bool, error) {
		if ok, asked := member[p]; asked {
			return ok, nil
		}
		err := a.cfg.ValidatePrincipal(ctx, a.db, tenant, p)
		if err != nil && !errors.Is(err, ErrInvalid) {
			return false, err
		}
		member[p] = err == nil
		return err == nil, nil
	}
	for _, b := range grants {
		bad := a.checkBinding(tenant, scope, b, now)
		// The public is asked about too, so a host can refuse public access.
		if len(bad) == 0 && b.Principal.Kind != Tenant {
			ok, err := inTenant(b.Principal)
			if err != nil {
				return err
			}
			if !ok {
				reason := "not in the tenant"
				if b.Principal.Kind == Public {
					reason = "the tenant doesn't allow public access"
				}
				bad = append(bad, &InvalidError{Binding: b, Reason: reason})
			}
		}
		errs = append(errs, bad...)
	}
	for _, b := range revokes {
		// A role no longer in the catalog, or a kind no longer declared, can still be revoked.
		if !b.Principal.wellFormed(tenant) {
			errs = append(errs, &InvalidError{Binding: b, Reason: "the principal is not valid"})
		}
	}
	return errors.Join(errs...)
}

// checkBinding returns why a binding can't be granted on a scope in a tenant.
func (a *Authorizer) checkBinding(tenant string, scope Scope, b Binding, now time.Time) []error {
	var errs []error
	bad := func(reason string) { errs = append(errs, &InvalidError{Binding: b, Reason: reason}) }
	if !a.known(tenant, b.Principal) {
		bad("the principal is not valid")
	}
	def, ok := a.roles[b.Role]
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
	return errs
}

// mayChange checks the actor's own access on the scope against the change, once Apply has
// checked the constraints.
func (a *Authorizer) mayChange(ctx context.Context, q DB, actor Subject, on Resource, grants []Binding) error {
	scope := on.Scope()
	manage := GrantPermission(scope.Type)
	if actor.owns(on) && a.ownerHolds(scope.Type, manage) {
		return nil
	}
	held, err := a.heldBindings(ctx, q, on.Tenant, actor.principals(on.Tenant), on.path())
	if err != nil {
		return err
	}
	// holds reports whether the actor holds p for one of types, and until when (zero: always).
	holds := func(p Permission, types []string) (bool, time.Time) {
		ok, forever := false, false
		var until time.Time
		for _, g := range held {
			def, known := a.roles[g.Role]
			if !known || !def.Gives(p) || !slices.ContainsFunc(types, def.GrantableOn) || !a.carries(g.Principal, g.Role, p) {
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

	ok, limit := holds(manage, []string{scope.Type})
	if !ok {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "the actor may not change access here"}
	}
	var errs []error
bindings:
	for _, b := range grants {
		def, known := a.roles[b.Role]
		if !known || !a.grantableOn(def, scope.Type) {
			// validate reports it as invalid rather than as an escalation.
			continue
		}
		until := limit
		for _, p := range def.Permissions {
			// On a container or the tenant the grant reaches every type the role is for, so the
			// actor must hold p for each of them; on a resource, for its own type.
			types := []string{scope.Type}
			if a.contains(scope.Type) {
				types = def.ResourceTypes
			}
			ok, end := holdsEach(holds, p, types)
			if !ok {
				errs = append(errs, &DeniedError{
					Permission: p, Scope: scope,
					Reason: fmt.Sprintf("the actor can't grant %s without holding %s here", b.Role, p),
				})
				continue bindings
			}
			until = earliest(until, end)
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

// holdsEach reports whether holds is true for p on every one of types, and until the earliest
// of their ends.
func holdsEach(holds func(Permission, []string) (bool, time.Time), p Permission, types []string) (bool, time.Time) {
	var until time.Time
	for _, t := range types {
		ok, end := holds(p, []string{t})
		if !ok {
			return false, time.Time{}
		}
		until = earliest(until, end)
	}
	return len(types) > 0, until
}

// stored is an expiry as PostgreSQL keeps it, to the microsecond, so a grant ending when the
// actor's own access does compares equal to it rather than nanoseconds later.
func stored(t time.Time) time.Time { return t.Truncate(time.Microsecond) }

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
func (a *Authorizer) inTx(ctx context.Context, tenant string, actor Principal, fn func(pgx.Tx) (granted, revoked []Grant, err error)) error {
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
// order, and returns those it added or whose expiry it changed. Of repeated grants it stores
// the last, since one statement can't change a row twice. An expired grant that is still
// stored gave nothing, so granting it again records the new actor and time.
func (a *Authorizer) upsert(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, grants []Grant) ([]Grant, error) {
	if len(grants) == 0 {
		return nil, nil
	}
	byKey := func(x, y Grant) int {
		return cmp.Or(cmp.Compare(x.Principal.key(), y.Principal.key()),
			cmp.Compare(x.Scope.Key(), y.Scope.Key()), cmp.Compare(x.Role, y.Role))
	}
	grants = slices.Clone(grants)
	slices.Reverse(grants)
	slices.SortStableFunc(grants, byKey)
	grants = slices.CompactFunc(grants, func(x, y Grant) bool { return byKey(x, y) == 0 })
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
		ON CONFLICT ON CONSTRAINT rbac_grants_key DO UPDATE SET expires_at = EXCLUDED.expires_at,
		  created_by = CASE WHEN rbac_grants.expires_at <= $9 THEN EXCLUDED.created_by ELSE rbac_grants.created_by END,
		  created_at = CASE WHEN rbac_grants.expires_at <= $9 THEN EXCLUDED.created_at ELSE rbac_grants.created_at END
		WHERE rbac_grants.expires_at IS DISTINCT FROM EXCLUDED.expires_at
		RETURNING `+grantColumns,
		tenant, scopeTypes, scopeIDs, kinds, ids, roles, expires, actorKey(actor), a.cfg.Now())
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
// through which ancestor, or what a principal holds (RBAC's assigned roles).
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

// DeleteScope removes every grant on a scope, as when the resource or container is deleted. It
// waits for a change to the scope in progress, so a grant that change makes is removed too.
func (a *Authorizer) DeleteScope(ctx context.Context, tenant string, s Scope) error {
	return a.delete(ctx, tenant, func(tx pgx.Tx) error { return lock(ctx, tx, tenant, []string{s.Key()}, nil) }, "scope = $2", s.Key())
}

// DeletePrincipal removes every grant to a principal, as when an identity or group is deleted,
// or every grant to the public, as when a tenant stops allowing public access.
func (a *Authorizer) DeletePrincipal(ctx context.Context, tenant string, p Principal) error {
	if !p.wellFormed(tenant) {
		return fmt.Errorf("%w: principal %q is not valid", ErrInvalid, p.key())
	}
	return a.delete(ctx, tenant, func(tx pgx.Tx) error { return lock(ctx, tx, tenant, nil, []string{p.key()}) }, "principal = $2", p.key())
}

// DeleteTenant removes every grant in a tenant.
func (a *Authorizer) DeleteTenant(ctx context.Context, tenant string) error {
	return a.delete(ctx, tenant, func(tx pgx.Tx) error { return lockTenant(ctx, tx, tenant) }, "TRUE")
}

func (a *Authorizer) delete(ctx context.Context, tenant string, lock func(pgx.Tx) error, where string, args ...any) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	query := `DELETE FROM rbac_grants WHERE tenant = $1 AND ` + where
	args = append([]any{tenant}, args...)
	return a.inTx(ctx, tenant, Principal{}, func(tx pgx.Tx) ([]Grant, []Grant, error) {
		if err := lock(tx); err != nil {
			return nil, nil, err
		}
		// Only OnChange reads what was removed, which for a whole tenant can be every grant it has.
		if a.cfg.OnChange == nil {
			_, err := tx.Exec(ctx, query, args...)
			return nil, nil, err
		}
		rows, err := tx.Query(ctx, query+` RETURNING `+grantColumns, args...)
		if err != nil {
			return nil, nil, err
		}
		revoked, err := collectGrants(rows)
		return nil, revoked, err
	})
}

// DeleteExpired removes grants that have expired, which no longer give anything, and returns
// how many. It passes over grants a change is holding, rather than wait on it, so the next run
// removes those.
func (a *Authorizer) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := a.db.Exec(ctx, `
		DELETE FROM rbac_grants WHERE id IN (
			SELECT id FROM rbac_grants WHERE expires_at <= $1 FOR UPDATE SKIP LOCKED)`, a.cfg.Now())
	return tag.RowsAffected(), err
}
