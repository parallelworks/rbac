package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Eligibility lets a principal activate a role on a scope when it needs it, for a while, rather
// than hold it standing: just-in-time access. Activating gives the identity that activates a
// grant of its own, from SourceActivation, until MaxDuration from then at most and no later than
// the eligibility ends, with its justification as the grant's note; one eligible through a group
// activates for itself. With Approvers, each activation needs one of them to approve it. An
// activated role that changes grants lets its holder make lasting grants, to itself too, as any
// time-limited one does: make eligible roles that can't change grants.
type Eligibility struct {
	Scope     Scope
	Role      Role
	Principal Principal
	// MaxDuration is the longest an activation lasts, in whole seconds, rounded down, and at most
	// a year.
	MaxDuration time.Duration
	// ExpiresAt ends the eligibility, which no activation outlasts; zero never does. Revoking it
	// leaves the grants activated from it to their own ends.
	ExpiresAt time.Time
	// Requires is what activating needs, as a condition's expression read with the action
	// `<type>:grant`, such as a second factor (`request.attributes.mfa == true`); empty for
	// nothing more.
	Requires string
	// Approvers are who approves each activation, identities or groups, at most MaxApprovers; none
	// when empty. One of them other than the one activating is Activation.Approver.
	Approvers []Principal
	Note      string
	// CreatedBy and CreatedAt are set on eligibilities read back.
	CreatedBy Principal
	CreatedAt time.Time
}

func (e Eligibility) binding() Binding {
	return Binding{Role: e.Role, Principal: e.Principal, ExpiresAt: e.ExpiresAt, Note: e.Note}
}

// checkEligibility returns why an eligibility is malformed beyond what checkBinding finds.
func (a *Authorizer) checkEligibility(e Eligibility) error {
	var errs []error
	if e.Principal.broad() {
		errs = append(errs, errors.New("a tenant's members and the public activate nothing"))
	}
	if e.MaxDuration < time.Second || e.MaxDuration > MaxActivation {
		errs = append(errs, fmt.Errorf("an activation lasts a second or more and at most %s", MaxActivation))
	}
	if len(e.Approvers) > MaxApprovers {
		errs = append(errs, fmt.Errorf("an eligibility has at most %d approvers", MaxApprovers))
	}
	for _, p := range e.Approvers {
		// Of a kind that acts, or no Subject could ever approve as it.
		if p.broad() || !a.known("", p) {
			errs = append(errs, fmt.Errorf("approver %q is not an identity or group", p.key()))
		}
	}
	switch {
	case !validText(e.Requires):
		errs = append(errs, errors.New("a requirement is UTF-8 text without NUL"))
	case e.Requires != "":
		if err := a.conds.check(e.Requires); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return &InvalidError{Binding: e.binding(), Reason: errors.Join(errs...).Error()}
	}
	return nil
}

// SetEligibility makes a principal eligible to activate a role on a scope, on, or changes how, as
// actor, who needs what granting the role there unconditionally would: an eligibility is a grant
// to come. The groups it names, eligible or approving, and a group it is on, are the tenant's.
func (a *Authorizer) SetEligibility(ctx context.Context, actor Subject, on Resource, e Eligibility) (err error) {
	defer a.refused(ctx, &err, on.Tenant, actor.Principal, "SetEligibility")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	e.Scope, e.ExpiresAt = on.Scope(), stored(e.ExpiresAt)
	e.Approvers = canonicalPrincipals(e.Approvers)
	check := func() error { return a.checkEligibility(e) }
	return a.change(ctx, actor, on, "SetEligibility", ViaEligibility, []Binding{e.binding()}, nil, e.Approvers, check, func(tx pgx.Tx) (ChangeEvent, error) {
		// An expired eligibility that is still stored allowed nothing, so setting it again records
		// the new actor and time.
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds,
			  expires_at, requires, approvers, note, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT ON CONSTRAINT rbac_eligibilities_key DO UPDATE SET max_seconds = EXCLUDED.max_seconds,
			  expires_at = EXCLUDED.expires_at, requires = EXCLUDED.requires, approvers = EXCLUDED.approvers, note = EXCLUDED.note,
			  created_by = CASE WHEN rbac_eligibilities.expires_at <= $13 THEN EXCLUDED.created_by ELSE rbac_eligibilities.created_by END,
			  created_at = CASE WHEN rbac_eligibilities.expires_at <= $13 THEN EXCLUDED.created_at ELSE rbac_eligibilities.created_at END
			WHERE (rbac_eligibilities.max_seconds, rbac_eligibilities.expires_at, rbac_eligibilities.requires,
			  rbac_eligibilities.approvers, rbac_eligibilities.note)
			  IS DISTINCT FROM (EXCLUDED.max_seconds, EXCLUDED.expires_at, EXCLUDED.requires, EXCLUDED.approvers, EXCLUDED.note)
			RETURNING `+eligibilityColumns,
			on.Tenant, e.Scope.Type, e.Scope.ID, e.Principal.Kind, e.Principal.ID, e.Role, int64(e.MaxDuration/time.Second),
			pgtype.Timestamptz{Time: e.ExpiresAt, Valid: !e.ExpiresAt.IsZero()}, e.Requires, keysOf(e.Approvers), e.Note,
			actorKey(actor.Principal), a.cfg.Now())
		if err != nil {
			return ChangeEvent{}, err
		}
		set, err := collectEligibilities(rows)
		return ChangeEvent{Eligible: set}, err
	})
}

// DeleteEligibility ends a principal's eligibility to activate a role on a scope, as actor, who
// needs what revoking the role there would. Grants activated from it keep their own ends.
func (a *Authorizer) DeleteEligibility(ctx context.Context, actor Subject, on Resource, role Role, p Principal) (err error) {
	defer a.refused(ctx, &err, on.Tenant, actor.Principal, "DeleteEligibility")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	scope := on.Scope()
	return a.change(ctx, actor, on, "DeleteEligibility", ViaEligibility, nil, []Binding{{Role: role, Principal: p}}, nil, nil, func(tx pgx.Tx) (ChangeEvent, error) {
		rows, err := tx.Query(ctx, `DELETE FROM rbac_eligibilities WHERE tenant = $1 AND scope = $2 AND principal = $3 AND role = $4
			RETURNING `+eligibilityColumns, on.Tenant, scope.Key(), p.key(), role)
		if err != nil {
			return ChangeEvent{}, err
		}
		gone, err := collectEligibilities(rows)
		return ChangeEvent{Ineligible: gone}, err
	})
}

// Activation is what activating a role asks for (Authorizer.Activate).
type Activation struct {
	Role Role
	// Duration is how long it lasts: at most the eligibility's MaxDuration, ending no later than the
	// eligibility does.
	Duration time.Duration
	// Justification says why; it is the grant's note.
	Justification string
	// Approver approved it, where the eligibility names Approvers: one of them other than the one
	// activating, as the host's approval flow has them when they approve. Zero when there are none.
	Approver Subject
}

// Activate gives s a role on a scope, on, as an eligibility of s's or of a group of s's there
// allows: a grant of its own from SourceActivation, beside any grant s holds, lasting
// act.Duration, with act.Justification as its note. s holds one activation of a role on a scope,
// which records the request its end rests on: activating again until later replaces it with this
// request, its justification and approver; one that would end no later changes nothing and
// returns the activation as it is, reporting nothing; and once it has ended, activating again
// makes a new grant, with a new ID. It needs no permission to change grants, the
// eligibility being the authority, but a constraint that stops changes to grants on the scope's
// type stops it, and Config.ValidateGrant is asked about it, as about any grant. Where the
// eligibility names approvers, the host's approval flow activates for s once one approves,
// passing act.Approver and, in ctx, the request s made (WithRequest), which Requires reads.
func (a *Authorizer) Activate(ctx context.Context, s Subject, on Resource, act Activation) (g Grant, err error) {
	defer a.refused(ctx, &err, on.Tenant, s.Principal, "Activate")
	if err := a.check(on); err != nil {
		return Grant{}, err
	}
	if err := a.subject(s); err != nil {
		return Grant{}, err
	}
	if err := a.subject(act.Approver); err != nil {
		return Grant{}, err
	}
	scope := on.Scope()
	b := Binding{Role: act.Role, Principal: s.Principal, Source: SourceActivation, Note: act.Justification}
	if !validText(string(act.Role)) {
		return Grant{}, &InvalidError{Binding: b, Reason: "the role is not text without NUL"}
	}
	if err := a.changing(s, on, a.constrain(ctx, s, on)); err != nil {
		return Grant{}, err
	}
	// Bounded before eligible rounds it up to seconds, which near the largest Duration overflows.
	if d := act.Duration; d <= 0 || d > MaxActivation || act.Justification == "" || !validNote(act.Justification) {
		return Grant{}, &InvalidError{Binding: b, Reason: fmt.Sprintf("an activation lasts more than nothing and at most %s, and has a justification of at most %d characters", MaxActivation, MaxNote)}
	}
	b.ExpiresAt = stored(a.cfg.Now().Add(act.Duration))
	if _, err := a.eligible(ctx, a.db, s, on, act, b.ExpiresAt); err != nil {
		return Grant{}, err
	}
	roles, err := a.tenantBook(ctx, a.db, on.Tenant, []Role{act.Role})
	if err != nil {
		return Grant{}, err
	}
	stand, err := a.stand(ctx, a.db, on.Tenant, []Principal{s.Principal})
	if err != nil {
		return Grant{}, err
	}
	if err := a.validate(ctx, roles, s, ViaActivation, on.Tenant, scope, []Binding{b}, nil); err != nil {
		return Grant{}, err
	}
	var activated Grant
	err = a.inTx(ctx, on.Tenant, s.Principal, "Activate", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{scope.Key()}, []string{s.Principal.key()}); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.stillStanding(ctx, tx, on.Tenant, stand); err != nil {
			return ChangeEvent{}, err
		}
		// Again under the locks, so an eligibility revoked meanwhile activates nothing.
		b.ExpiresAt = stored(a.cfg.Now().Add(act.Duration))
		approver, err := a.eligible(ctx, tx, s, on, act, b.ExpiresAt)
		if err != nil {
			return ChangeEvent{}, err
		}
		now, err := a.tenantBook(ctx, tx, on.Tenant, []Role{act.Role})
		if err != nil {
			return ChangeEvent{}, err
		}
		if err := errors.Join(a.checkBinding(now, on.Tenant, scope, b, a.cfg.Now())...); err != nil {
			return ChangeEvent{}, err
		}
		if err := redefinedSince(roles, now, []Role{act.Role}); err != nil {
			return ChangeEvent{}, err
		}
		// The table keeps one activation of a role on a scope, which always records the request its
		// end rests on: activating again until later replaces it with this request, its justification
		// and its approver; set anew once it has ended, it is a new grant, with a new id; and one that
		// ends no later changes nothing, so is reported as nothing. Ended is by the database's clock
		// too, which history dates the old one's expiry by: by Config.Now alone, which can run ahead
		// of it, the old one would be recorded as revoked by s.
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_grants AS g (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at,
			  note, approved_by, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
			ON CONFLICT (tenant, principal, scope, role) WHERE source = 'activation' DO UPDATE SET
			  id = CASE WHEN g.expires_at > least($12, statement_timestamp()) THEN g.id ELSE gen_random_uuid() END,
			  created_at = CASE WHEN g.expires_at > least($12, statement_timestamp()) THEN g.created_at ELSE now() END,
			  expires_at = EXCLUDED.expires_at, note = EXCLUDED.note, approved_by = EXCLUDED.approved_by,
			  updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE g.expires_at <= $12 OR g.expires_at < EXCLUDED.expires_at
			RETURNING `+grantColumns,
			on.Tenant, scope.Type, scope.ID, s.Principal.Kind, s.Principal.ID, act.Role, SourceActivation, b.ExpiresAt,
			b.Note, actorKey(approver), s.Principal.key(), a.cfg.Now())
		if err != nil {
			return ChangeEvent{}, err
		}
		granted, err := collectGrants(rows)
		if err != nil {
			return ChangeEvent{}, err
		}
		if len(granted) == 0 {
			// By its key, not through Grants, which reads the clock again and could find it ended since.
			rows, err := tx.Query(ctx, `SELECT `+grantColumns+` FROM rbac_grants
				WHERE tenant = $1 AND principal = $2 AND scope = $3 AND role = $4 AND source = $5`,
				on.Tenant, s.Principal.key(), scope.Key(), act.Role, SourceActivation)
			if err != nil {
				return ChangeEvent{}, err
			}
			activated, err = pgx.CollectExactlyOneRow(rows, scanGrant)
			return ChangeEvent{}, err
		}
		if err := a.bounded(ctx, tx, on.Tenant, granted); err != nil {
			return ChangeEvent{}, err
		}
		activated = granted[0]
		return ChangeEvent{Granted: granted}, nil
	})
	if err != nil {
		return Grant{}, err
	}
	return activated, nil
}

// Deactivate ends s's activations of a role on a scope, on, early, as when the work is done. It
// needs no permission, and no constraint stops it: s gives up only access it activated.
func (a *Authorizer) Deactivate(ctx context.Context, s Subject, on Resource, role Role) (err error) {
	defer a.refused(ctx, &err, on.Tenant, s.Principal, "Deactivate")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.subject(s); err != nil {
		return err
	}
	if !validText(string(role)) {
		return fmt.Errorf("%w: role %q is not text without NUL", ErrInvalid, role)
	}
	if s.Principal == (Principal{}) {
		return nil
	}
	scope := on.Scope()
	return a.inTx(ctx, on.Tenant, s.Principal, "Deactivate", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, on.Tenant, []string{scope.Key()}, []string{s.Principal.key()}); err != nil {
			return ChangeEvent{}, err
		}
		ended, err := a.remove(ctx, tx, on.Tenant, "scope = $2 AND principal = $3 AND role = $4 AND source = $5",
			scope.Key(), s.Principal.key(), role, SourceActivation)
		return ChangeEvent{Revoked: ended}, err
	})
}

// eligible checks that s may activate act.Role on on until until, and returns who approved: an
// eligibility of s's identity or of one of its groups there, lasting act.Duration or longer and
// in force until then, whose requirement holds in the request, failing closed, and whose
// approvers, if it names any, include act.Approver, who isn't s. approved is zero when the
// eligibility allowing it names none. A privileged role's counts only through s's identity or its
// groups, as its grants do, never through the tenant's members.
func (a *Authorizer) eligible(ctx context.Context, q DB, s Subject, on Resource, act Activation, until time.Time) (approved Principal, err error) {
	scope, manage := on.Scope(), GrantPermission(on.Type)
	// As s will be when the activation ends, so none outlasts the place in a group, or the
	// membership, that makes s eligible.
	keys, _, err := a.keysAt(ctx, q, on.Tenant, s, until)
	if err != nil {
		return Principal{}, err
	}
	approvers, _, err := a.keysOf(ctx, q, on.Tenant, act.Approver)
	if err != nil {
		return Principal{}, err
	}
	// Those needing no approval first, so an approver passed where none is needed isn't recorded,
	// and of each the cheapest requirement first, as cheapestFirst orders conditions, so which
	// allows doesn't rest on the database's collation, nor on how many approvers one names.
	rows, err := q.Query(ctx, `
		SELECT requires, approvers FROM rbac_eligibilities
		WHERE tenant = $1 AND scope = $2 AND role = $3 AND principal = ANY($4::text[]) AND max_seconds >= $5
		  AND (expires_at IS NULL OR expires_at > $6 AND expires_at >= $7)
		ORDER BY cardinality(approvers) > 0, octet_length(requires), requires COLLATE "C"`,
		on.Tenant, scope.Key(), act.Role, countedOf(keys, broad{}), seconds(act.Duration), a.cfg.Now(), until)
	if err != nil {
		return Principal{}, err
	}
	type eligibility struct {
		requires  string
		approvers []string
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eligibility, error) {
		var e eligibility
		return e, row.Scan(&e.requires, &e.approvers)
	})
	if err != nil {
		return Principal{}, err
	}
	reason := fmt.Sprintf("not eligible to activate %s here for %s", act.Role, act.Duration)
	vars, spend := a.vars(ctx, s, manage, on), newBudget()
	for _, e := range found {
		if len(e.approvers) > 0 && !approves(act.Approver, s, countedOf(approvers, broad{}), e.approvers) {
			reason = fmt.Sprintf("activating %s here needs one of its approvers to approve", act.Role)
			continue
		}
		if e.requires == "" || a.conds.holds(spend, e.requires, vars) {
			if len(e.approvers) > 0 {
				return act.Approver.Principal, nil
			}
			return Principal{}, nil
		}
	}
	return Principal{}, &DeniedError{Permission: manage, Scope: scope, Reason: reason}
}

// approves reports whether approver, by one of its keys in the tenant, its identity or a group it
// is in there, is among an eligibility's approvers, and isn't s, who can't approve its own
// activation.
func approves(approver, s Subject, keys, approvers []string) bool {
	if approver.Principal == (Principal{}) || approver.Principal == s.Principal {
		return false
	}
	return slices.ContainsFunc(keys, func(k string) bool { return slices.Contains(approvers, k) })
}

// seconds is d in whole seconds, rounded up.
func seconds(d time.Duration) int64 {
	s := int64(d / time.Second)
	if d%time.Second > 0 {
		s++
	}
	return s
}

// Eligibilities lists the eligibilities that match the filter, as stored, expired ones aside.
func (a *Authorizer) Eligibilities(ctx context.Context, tenant string, f GrantFilter) ([]Eligibility, error) {
	if !validID(tenant) || !f.valid(tenant) {
		return nil, fmt.Errorf("%w: Eligibilities needs a tenant and valid scopes or principals", ErrInvalid)
	}
	where, scopes, principals := f.sql()
	rows, err := a.db.Query(ctx, `
		SELECT `+eligibilityColumns+` FROM rbac_eligibilities
		WHERE tenant = $1 AND `+where+` AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY scope, principal, role`,
		tenant, scopes, principals, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectEligibilities(rows)
}

const eligibilityColumns = `scope_type, scope_id, principal_kind, principal_id, role, max_seconds, expires_at, requires, approvers,
	note, created_by, created_at`

func collectEligibilities(rows pgx.Rows) ([]Eligibility, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Eligibility, error) {
		var e Eligibility
		var seconds int64
		var expires *time.Time
		var createdBy string
		var approvers []string
		err := row.Scan(&e.Scope.Type, &e.Scope.ID, &e.Principal.Kind, &e.Principal.ID, &e.Role, &seconds, &expires,
			&e.Requires, &approvers, &e.Note, &createdBy, &e.CreatedAt)
		for _, k := range approvers {
			e.Approvers = append(e.Approvers, parsePrincipal(k))
		}
		e.MaxDuration = time.Duration(seconds) * time.Second
		if expires != nil {
			e.ExpiresAt = *expires
		}
		e.CreatedBy = parsePrincipal(createdBy)
		return e, err
	})
}
