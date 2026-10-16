package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Eligibility lets a principal activate a role on a scope when it needs it, for a while, rather
// than hold it standing: just-in-time access. Activating gives the identity that activates a
// grant until MaxDuration from then at most, with its justification as the grant's note; one
// eligible through a group activates for itself. An approval before activating is the host's:
// on approval, it can grant with Import.
type Eligibility struct {
	Scope     Scope
	Role      Role
	Principal Principal
	// MaxDuration is the longest an activation lasts, at most a year.
	MaxDuration time.Duration
	// ExpiresAt ends the eligibility; zero never does. A grant activated from it keeps its own end.
	ExpiresAt time.Time
	// Requires is what activating needs, as a condition's expression, such as a second factor
	// (`request.attributes.mfa == true`); empty for nothing more.
	Requires string
	Note     string
	// CreatedBy and CreatedAt are set on eligibilities read back.
	CreatedBy Principal
	CreatedAt time.Time
}

const maxActivation = 366 * 24 * time.Hour

func (e Eligibility) binding() Binding {
	return Binding{Role: e.Role, Principal: e.Principal, ExpiresAt: e.ExpiresAt, Note: e.Note}
}

// checkEligibility returns why an eligibility is malformed beyond what checkBinding finds.
func (a *Authorizer) checkEligibility(e Eligibility) error {
	var errs []error
	if e.Principal.broad() {
		errs = append(errs, errors.New("a tenant's members and the public activate nothing"))
	}
	if e.MaxDuration < time.Second || e.MaxDuration > maxActivation {
		errs = append(errs, fmt.Errorf("an activation lasts a second or more and at most %s", maxActivation))
	}
	if e.Requires != "" {
		if _, err := a.conds.compile(e.Requires); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &InvalidError{Binding: e.binding(), Reason: errors.Join(errs...).Error()}
	}
	return nil
}

// SetEligible makes a principal eligible to activate a role on a scope, on, or changes how, as
// actor, who needs what granting the role there unconditionally would: an eligibility is a grant
// to come.
func (a *Authorizer) SetEligible(ctx context.Context, actor Subject, on Resource, e Eligibility) error {
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	e.Scope, e.ExpiresAt = on.Scope(), stored(e.ExpiresAt)
	b := e.binding()
	manage := GrantPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: manage, Scope: e.Scope, Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, on.Tenant, on.Type, manage)
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: manage, Scope: e.Scope, Reason: "removed by " + name}
	}
	au, err := a.mayChange(ctx, a.db, actor, on, []Binding{b}, nil)
	if err != nil {
		return err
	}
	if err := a.checkEligibility(e); err != nil {
		return err
	}
	if err := a.validate(ctx, au.roles, on.Tenant, e.Scope, []Binding{b}, nil); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{e.Scope.Key()}, []string{e.Principal.key()}); err != nil {
			return ChangeEvent{}, err
		}
		au, err := a.mayChange(ctx, tx, actor, on, []Binding{b}, nil)
		if err != nil {
			return ChangeEvent{}, err
		}
		if err := errors.Join(a.checkBinding(au.roles, on.Tenant, e.Scope, b, a.cfg.Now())...); err != nil {
			return ChangeEvent{}, err
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds,
			  expires_at, requires, note, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT ON CONSTRAINT rbac_eligibilities_key DO UPDATE SET max_seconds = EXCLUDED.max_seconds,
			  expires_at = EXCLUDED.expires_at, requires = EXCLUDED.requires, note = EXCLUDED.note
			WHERE (rbac_eligibilities.max_seconds, rbac_eligibilities.expires_at, rbac_eligibilities.requires, rbac_eligibilities.note)
			  IS DISTINCT FROM (EXCLUDED.max_seconds, EXCLUDED.expires_at, EXCLUDED.requires, EXCLUDED.note)
			RETURNING `+eligibilityColumns,
			on.Tenant, e.Scope.Type, e.Scope.ID, e.Principal.Kind, e.Principal.ID, e.Role, int64(e.MaxDuration/time.Second),
			pgtype.Timestamptz{Time: e.ExpiresAt, Valid: !e.ExpiresAt.IsZero()}, e.Requires, e.Note, actorKey(actor.Principal))
		if err != nil {
			return ChangeEvent{}, err
		}
		set, err := collectEligibilities(rows)
		return ChangeEvent{Eligible: set}, err
	})
}

// RevokeEligible ends a principal's eligibility to activate a role on a scope, as actor, who
// needs what revoking the role there would. Grants activated from it keep their own ends.
func (a *Authorizer) RevokeEligible(ctx context.Context, actor Subject, on Resource, role Role, p Principal) error {
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	scope, manage := on.Scope(), GrantPermission(on.Type)
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "an anonymous subject changes nothing"}
	}
	name, err := a.denied(ctx, on.Tenant, on.Type, manage)
	if err != nil {
		return err
	}
	if name != "" {
		return &DeniedError{Permission: manage, Scope: scope, Reason: "removed by " + name}
	}
	revoke := []Binding{{Role: role, Principal: p}}
	if _, err := a.mayChange(ctx, a.db, actor, on, nil, revoke); err != nil {
		return err
	}
	return a.inTx(ctx, on.Tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{scope.Key()}, []string{p.key()}); err != nil {
			return ChangeEvent{}, err
		}
		if _, err := a.mayChange(ctx, tx, actor, on, nil, revoke); err != nil {
			return ChangeEvent{}, err
		}
		rows, err := tx.Query(ctx, `DELETE FROM rbac_eligibilities WHERE tenant = $1 AND scope = $2 AND principal = $3 AND role = $4
			RETURNING `+eligibilityColumns, on.Tenant, scope.Key(), p.key(), role)
		if err != nil {
			return ChangeEvent{}, err
		}
		gone, err := collectEligibilities(rows)
		return ChangeEvent{Ineligible: gone}, err
	})
}

// Activate gives s a role on a scope, on, for d, as an eligibility of s's or of a group of s's
// there allows, with justification as the grant's note. It needs no permission to change grants:
// the eligibility is the authority. A constraint that stops changes to grants on the scope's
// type stops activating. A grant of the role s already holds there is kept when it lasts as long
// or longer; one under a condition is never replaced, so activating refuses.
func (a *Authorizer) Activate(ctx context.Context, s Subject, on Resource, role Role, d time.Duration, justification string) (Grant, error) {
	if err := a.check(on); err != nil {
		return Grant{}, err
	}
	if err := a.subject(s); err != nil {
		return Grant{}, err
	}
	scope, manage := on.Scope(), GrantPermission(on.Type)
	b := Binding{Role: role, Principal: s.Principal, Note: justification}
	switch {
	case s.Principal == (Principal{}):
		return Grant{}, &DeniedError{Permission: manage, Scope: scope, Reason: "an anonymous subject activates nothing"}
	case d <= 0 || justification == "" || utf8.RuneCountInString(justification) > maxNote || !validText(justification):
		return Grant{}, &InvalidError{Binding: b, Reason: fmt.Sprintf("an activation lasts more than nothing and has a justification of at most %d characters", maxNote)}
	}
	name, err := a.denied(ctx, on.Tenant, on.Type, manage)
	if err != nil {
		return Grant{}, err
	}
	if name != "" {
		return Grant{}, &DeniedError{Permission: manage, Scope: scope, Reason: "removed by " + name}
	}
	if _, err := a.eligible(ctx, a.db, s, on, role, d); err != nil {
		return Grant{}, err
	}
	var activated Grant
	err = a.inTx(ctx, on.Tenant, s.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{scope.Key()}, []string{s.Principal.key()}); err != nil {
			return ChangeEvent{}, err
		}
		// Again under the locks, so an eligibility revoked meanwhile activates nothing.
		roles, err := a.eligible(ctx, tx, s, on, role, d)
		if err != nil {
			return ChangeEvent{}, err
		}
		b.ExpiresAt = stored(a.cfg.Now().Add(d))
		if err := errors.Join(a.checkBinding(roles, on.Tenant, scope, b, a.cfg.Now())...); err != nil {
			return ChangeEvent{}, err
		}
		held, err := a.WithTx(tx).Grants(ctx, on.Tenant, GrantFilter{Scopes: []Scope{scope}, Principals: []Principal{s.Principal}})
		if err != nil {
			return ChangeEvent{}, err
		}
		for _, g := range held {
			if g.Role != role {
				continue
			}
			if g.Condition.Expression != "" {
				return ChangeEvent{}, &InvalidError{Binding: b, Reason: "the role is held here under a condition, which activating would drop"}
			}
			if g.ExpiresAt.IsZero() || !g.ExpiresAt.Before(b.ExpiresAt) {
				activated = g
				return ChangeEvent{}, nil
			}
		}
		granted, err := a.upsert(ctx, tx, on.Tenant, s.Principal, scopeGrants(scope, []Binding{b}))
		if err != nil || len(granted) == 0 {
			return ChangeEvent{}, err
		}
		activated = granted[0]
		return ChangeEvent{Activated: granted}, nil
	})
	return activated, err
}

// eligible checks that s may activate role on on for d, and returns the roles it read: an
// eligibility of s's identity or of one of its groups there, unexpired, lasting d or longer,
// whose requirement holds in the request, failing closed.
func (a *Authorizer) eligible(ctx context.Context, q DB, s Subject, on Resource, role Role, d time.Duration) (book, error) {
	scope, manage := on.Scope(), GrantPermission(on.Type)
	keys := []string{s.Principal.key()}
	for _, g := range s.Groups {
		if g != "" {
			keys = append(keys, Principal{Group, g}.key())
		}
	}
	rows, err := q.Query(ctx, `
		SELECT requires FROM rbac_eligibilities
		WHERE tenant = $1 AND scope = $2 AND role = $3 AND principal = ANY($4::text[]) AND max_seconds >= $5
		  AND (expires_at IS NULL OR expires_at > $6)
		ORDER BY requires`,
		on.Tenant, scope.Key(), role, keys, int64((d+time.Second-1)/time.Second), a.cfg.Now())
	if err != nil {
		return book{}, err
	}
	requires, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return book{}, err
	}
	vars, spend := a.vars(ctx, s, manage, on), newBudget()
	for _, r := range requires {
		if r == "" || a.conds.holds(spend, r, vars) {
			return a.book(ctx, q, on.Tenant, []Role{role})
		}
	}
	return book{}, &DeniedError{Permission: manage, Scope: scope, Reason: fmt.Sprintf("not eligible to activate %s here for %s", role, d)}
}

// Eligibilities lists the eligibilities that match the filter, as stored, expired ones aside.
func (a *Authorizer) Eligibilities(ctx context.Context, tenant string, f GrantFilter) ([]Eligibility, error) {
	if tenant == "" || len(f.Scopes)+len(f.Principals) == 0 {
		return nil, fmt.Errorf("%w: Eligibilities needs a tenant and scopes or principals", ErrInvalid)
	}
	scopes := make([]string, len(f.Scopes))
	for i, s := range f.Scopes {
		scopes[i] = s.Key()
	}
	rows, err := a.db.Query(ctx, `
		SELECT `+eligibilityColumns+` FROM rbac_eligibilities
		WHERE tenant = $1 AND (cardinality($2::text[]) = 0 OR scope = ANY($2::text[]))
		  AND (cardinality($3::text[]) = 0 OR principal = ANY($3::text[])) AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY scope, principal, role`,
		tenant, scopes, keysOf(f.Principals), a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectEligibilities(rows)
}

const eligibilityColumns = `scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at, requires, note,
	created_by, created_at`

func collectEligibilities(rows pgx.Rows) ([]Eligibility, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Eligibility, error) {
		var e Eligibility
		var seconds int64
		var expires *time.Time
		var createdBy string
		err := row.Scan(&e.Scope.Type, &e.Scope.ID, &e.Principal.Kind, &e.Principal.ID, &e.Role, &seconds, &expires,
			&e.Requires, &e.Note, &createdBy, &e.CreatedAt)
		e.MaxDuration = time.Duration(seconds) * time.Second
		if expires != nil {
			e.ExpiresAt = *expires
		}
		e.CreatedBy = parsePrincipal(createdBy)
		return e, err
	})
}
