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

// Eligibility lets a principal activate a role on a scope when it needs it, for a while, rather
// than hold it standing: just-in-time access. Activating gives the identity that activates a
// grant of its own, from SourceActivation, until MaxDuration from then at most and no later than
// the eligibility, its membership of the tenant or its place in the group that makes it eligible
// ends, with its justification as the grant's note; one eligible through a group activates for
// itself. The activation records the eligibility it was made through, and rests on its holder
// being that one's principal, or in its group, through those it is in: a change ending the
// membership or a place on the way sooner, or removing it, cuts the activation short to the latest
// end of the paths left, or ends it if none is left, whatever another eligibility would allow.
// With Approvers, each activation needs one of them to approve it. What an activation gives, its
// holder can't hand on past its end, nor as an eligibility; but an activated power to change grants
// grants for good what its holder holds for good, and the roles a role it activated lists, as any
// power held for a while does (Authorizer.Apply): make eligible roles that list none.
type Eligibility struct {
	Scope     Scope
	Role      Role
	Principal Principal
	// MaxDuration is the longest an activation lasts, in whole seconds, rounded down, and at most
	// a year.
	MaxDuration time.Duration
	// ExpiresAt ends the eligibility, which no activation made from it outlasts; zero never does.
	// Setting it sooner, or revoking the eligibility, leaves the grants activated from it to their
	// own ends, or to their holders leaving its principal's group sooner.
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

// handedOn is an eligibility's binding as an actor setting it, or making it a member's, hands it
// on: the grant for good activating it can become, on terms the actor sets, so what the actor
// holds only until a time, as an activation, makes no one eligible for it.
func handedOn(b Binding) Binding {
	b.ExpiresAt = time.Time{}
	return b
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
// actor, who needs what granting the role there unconditionally and for good would: an
// eligibility is a grant to come, on terms the actor sets, so what the actor holds only until a
// time, as an activation, it can't make anyone eligible for. The groups it names, eligible or
// approving, and a group it is on, are the tenant's. The requirements of groups' eligibilities for
// a role on a scope are bounded together, as activating evaluates those of each group it is in
// (Condition): a group's past that is refused as invalid.
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
		was, err := a.requirementOf(ctx, tx, on.Tenant, e)
		if err != nil {
			return ChangeEvent{}, err
		}
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
		if err != nil {
			return ChangeEvent{}, err
		}
		// Set again as it is, it adds nothing activating reads, as a grant granted again doesn't.
		if len(set) == 0 {
			return ChangeEvent{}, nil
		}
		return ChangeEvent{Eligible: set}, a.requirementsBounded(ctx, tx, on.Tenant, e, was)
	})
}

// requirementOf is what an eligibility of a group in force requires, as stored, "" for none.
func (a *Authorizer) requirementOf(ctx context.Context, tx pgx.Tx, tenant string, e Eligibility) (string, error) {
	if e.Principal.Kind != Group {
		return "", nil
	}
	var requires string
	err := tx.QueryRow(ctx, `SELECT coalesce(max(requires), '') FROM rbac_eligibilities
		WHERE tenant = $1 AND principal = $2 AND scope = $3 AND role = $4 AND (expires_at IS NULL OR expires_at > $5)`,
		tenant, e.Principal.key(), e.Scope.Key(), e.Role, a.cfg.Now()).Scan(&requires)
	return requires, err
}

// requirementsBounded refuses an eligibility of a group just stored, which required was before,
// that leaves the requirements of groups' eligibilities for its role on its scope costing more
// together than activating may spend on them, and more than they did: one activating evaluates
// those of each group it is in, and a subject holds one eligibility of its own there. Activating
// evaluates them whole, so an eligibility set beside another, as by an actor who can't delete it,
// never changes what that one allows.
func (a *Authorizer) requirementsBounded(ctx context.Context, tx pgx.Tx, tenant string, e Eligibility, was string) error {
	if e.Requires == "" || e.Principal.Kind != Group {
		return nil
	}
	var others []string
	if err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT requires), '{}') FROM rbac_eligibilities
		WHERE tenant = $1 AND scope = $2 AND role = $3 AND principal >= 'group:' AND principal < 'group;' AND principal <> $4
		  AND requires <> '' AND (expires_at IS NULL OR expires_at > $5)`,
		tenant, e.Scope.Key(), e.Role, e.Principal.key(), a.cfg.Now()).Scan(&others); err != nil {
		return err
	}
	if !a.conds.within(once(append(others, was)), once(append(others, e.Requires))) {
		return fmt.Errorf("%w: the requirements of groups' eligibilities for %s on %s cost more together than activating may spend evaluating them",
			ErrInvalid, e.Role, e.Scope.Key())
	}
	return nil
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
// request, its justification, approver and eligibility; one that would end no later changes
// nothing and returns the activation as it is, reporting nothing; and once it has ended,
// activating again makes a new grant, with a new ID. It needs no permission to change grants, the
// eligibility being the authority, but a constraint that stops changes to grants on the scope's
// type stops it, and Config.ValidateGrant is asked about it, as about any grant. Where the
// eligibility names approvers, the host's approval flow activates for s once one approves,
// passing act.Approver and, in ctx, the request s made (WithRequest), which Requires reads. Of the
// eligibilities that allow it, the activation is made through one needing no approval over one
// that does, and of those through the one whose requirement is cheapest, and records it: it rests
// on s being that one's principal or in its group (Eligibility). It holds the places in groups s
// is in until it commits, and finds s eligible through those alone, so a change ending one of them
// sooner waits for it, and cuts the activation short if it rests on that place.
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
	keys, _, err := a.keysAt(ctx, a.db, on.Tenant, s, b.ExpiresAt)
	if err != nil {
		return Grant{}, err
	}
	if _, _, err := a.eligible(ctx, a.db, s, on, act, b.ExpiresAt, keys); err != nil {
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
		// Again under the locks, so an eligibility revoked meanwhile activates nothing, and through
		// the places in groups it holds alone.
		b.ExpiresAt = stored(a.cfg.Now().Add(act.Duration))
		held := holdingPlaces()
		keys, err := holdPlaces(ctx, tx, on.Tenant, s, a.cfg.Now(), b.ExpiresAt)
		if err != nil {
			return ChangeEvent{}, err
		}
		held()
		through, approver, err := a.eligible(ctx, tx, s, on, act, b.ExpiresAt, keys)
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
			  note, approved_by, created_by, updated_by, activated_through, eligibility_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11, $13, $14)
			ON CONFLICT (tenant, principal, scope, role) WHERE source = 'activation' DO UPDATE SET
			  id = CASE WHEN g.expires_at > least($12, statement_timestamp()) THEN g.id ELSE gen_random_uuid() END,
			  created_at = CASE WHEN g.expires_at > least($12, statement_timestamp()) THEN g.created_at ELSE now() END,
			  expires_at = EXCLUDED.expires_at, note = EXCLUDED.note, approved_by = EXCLUDED.approved_by,
			  activated_through = EXCLUDED.activated_through, eligibility_id = EXCLUDED.eligibility_id,
			  updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE g.expires_at <= $12 OR g.expires_at < EXCLUDED.expires_at
			RETURNING `+grantColumns,
			on.Tenant, scope.Type, scope.ID, s.Principal.Kind, s.Principal.ID, act.Role, SourceActivation, b.ExpiresAt,
			b.Note, actorKey(approver), s.Principal.key(), a.cfg.Now(), through.principal, through.id)
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
// needs no permission, and no constraint stops it: s gives up only access it activated. A scope of
// a type the host doesn't have is refused as invalid, as a typo, as Activate refuses it.
func (a *Authorizer) Deactivate(ctx context.Context, s Subject, on Resource, role Role) (err error) {
	defer a.refused(ctx, &err, on.Tenant, s.Principal, "Deactivate")
	if err := a.check(on); err != nil {
		return err
	}
	if err := a.scopeOf(on); err != nil {
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

// holdingPlaces runs as Activate begins holding the places in groups it can rest on, and what it
// returns once it holds them, as a test changes them meanwhile.
var holdingPlaces = func() func() { return func() {} }

// holdPlaces holds, in tx, until it commits, the places in groups s can rest an activation on in the
// tenant at now, its identity's and its groups', through those they are in, each key's found on its
// own (byKey) and each held by its key, in the order changes hold them: a change ending one sooner
// holds it before reading the activations resting on it, so it waits for the activation and finds
// it. In the same statement it returns the keys s holds at until through the places it held alone,
// and its identity's while its membership is in force then and not suspended: a later statement
// would read a place nested meanwhile, which no change removing it would wait for. Each is held as
// it is when held, a place updated meanwhile in its new version. Walking up from s reads every place
// held, so each is held before the keys are returned; where s isn't standing it reads none, and
// activates nothing.
func holdPlaces(ctx context.Context, tx pgx.Tx, tenant string, s Subject, now, until time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$3")+`, held AS MATERIALIZED (
		  SELECT m.* FROM (SELECT * FROM (`+byKey("ARRAY(SELECT k FROM keys)", "rbac_members", "principal", "group_id, principal, source",
		"tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`) p ORDER BY `+placeOrder+`) p CROSS JOIN LATERAL (
		    SELECT group_id, principal, expires_at FROM rbac_members WHERE tenant = $1 AND group_id = p.group_id AND principal = p.principal
		      AND source = p.source AND (expires_at IS NULL OR expires_at > $3) FOR SHARE) m
		), standing AS (
		  SELECT FROM rbac_memberships WHERE tenant = $1 AND principal = $2 AND NOT suspended AND (expires_at IS NULL OR expires_at > $4)
		), up(id) AS (
		  SELECT group_id FROM held WHERE principal = $2 AND (expires_at IS NULL OR expires_at > $4) AND EXISTS (SELECT FROM standing)
		  UNION
		  SELECT h.group_id FROM up u JOIN held h ON h.principal = 'group:' || u.id AND (h.expires_at IS NULL OR h.expires_at > $4)
		)
		SELECT $2 COLLATE "C" FROM standing UNION ALL SELECT 'group:' || id FROM up ORDER BY 1`, tenant, s.identityKey(), now, until)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// resting is the activations, by id, a change ending places in groups or memberships sooner may cut
// short: those of the identities it ends them for.
type resting struct {
	ids []string
}

// reachingSQL is SQL defining, in a WITH RECURSIVE, reaching(holder, k, ends): the keys of the
// identities holders, SQL for an array of their keys, hold in the tenant $1 at now, with when the
// latest of the paths to each ends, null for never: its own while its membership is in force,
// suspended too, as lifting it holds them again, and its groups', through those they are in, while
// its places in them are. Each key's are looked up on its own (byKey, groupsAbove).
func reachingSQL(holders, now string) string {
	return fmt.Sprintf(`tenure(holder, ends) AS (
		%[1]s
	), placed(holder, id, ends) AS (
		SELECT t.holder, m.group_id, least(t.ends, m.expires_at) FROM tenure t CROSS JOIN LATERAL (
		  SELECT group_id, expires_at FROM rbac_members WHERE tenant = $1 AND principal = t.holder
		    AND (expires_at IS NULL OR expires_at > %[2]s) OFFSET 0) m
		UNION
		SELECT p.holder, m.group_id, least(p.ends, m.expires_at) FROM placed p %[3]s
	), reaching(holder, k, ends) AS (
		SELECT holder, holder, ends FROM tenure
		UNION ALL SELECT holder, 'group:' || id, ends FROM placed
	)`, byKey(holders, "rbac_memberships", "principal", "principal, expires_at", "tenant = $1 AND (expires_at IS NULL OR expires_at > "+now+")"),
		now, groupsAbove("p.id", now, "group_id, expires_at"))
}

// restingOn reads, in tx, at now, the activations of identities, by key, and of the identities in
// groups, by id, in a tenant, that a change ending their places in groups or memberships sooner may
// cut short. The change holds the rows it ends first, as Activate holds those an activation rests
// on, so none is made meanwhile through what the change ends; and reads them before it ends any, as
// it may end the places that put the identities in the groups.
func (a *Authorizer) restingOn(ctx context.Context, tx pgx.Tx, tenant string, identities, groups []string, now time.Time) (resting, error) {
	if len(identities)+len(groups) == 0 {
		return resting{}, nil
	}
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE `+insideSQL("$3", "$4", "NULL", false)+`, holders(k) AS (
		  SELECT unnest($2::text[]) COLLATE "C" UNION SELECT principal FROM inside
		)
		SELECT id::text FROM (`+byKey("ARRAY(SELECT k FROM holders)", "rbac_grants", "principal", "id",
		"tenant = $1 AND source = 'activation' AND expires_at > $4")+`) a ORDER BY id`, tenant, identities, groups, now)
	if err != nil {
		return resting{}, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return resting{ids: ids}, err
}

// unrest cuts short, in tx, as actor, the activations r found resting, once the change has ended
// places or memberships, whose holders reach the principals they were made through until sooner
// than they last: each to the latest end of the paths left, or ended if none is left past now,
// whatever another eligibility would allow. One that records no principal, stored before Activate
// recorded them and that migrating couldn't tie to one eligibility, ends, as which of its holder's
// paths it rested on can't be told. It returns those it cut short and those it ended.
func (a *Authorizer) unrest(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, r resting, now time.Time) (short, ended []Grant, err error) {
	if len(r.ids) == 0 {
		return nil, nil, nil
	}
	// Each by its id alone, kept to the tenant's activations in force outside the lookup: beside
	// tenant = $1 and the source, a generic plan reads every activation in the tenant by the index
	// on them, which it costs as an average tenant's few. Each joined to its paths, not a subquery
	// per activation, which scans every holder's paths for each, once for each use of until.
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE act AS (
		  SELECT g.id, g.principal, g.expires_at, g.activated_through FROM unnest($2::text[]) AS w(i) CROSS JOIN LATERAL (
		    SELECT id, tenant, source, principal, expires_at, activated_through FROM rbac_grants WHERE id = w.i::uuid OFFSET 0) g
		  WHERE g.tenant = $1 AND g.source = 'activation' AND g.expires_at > $3
		), `+reachingSQL("ARRAY(SELECT DISTINCT principal FROM act)", "$3")+`, rests(id, expires_at, until) AS (
		  SELECT a.id, a.expires_at, max(coalesce(r.ends, 'infinity')) FILTER (WHERE r.k IS NOT NULL)
		  FROM act a LEFT JOIN reaching r ON r.holder = a.principal AND r.k = a.activated_through
		  GROUP BY a.id, a.expires_at
		)
		SELECT id::text, until FROM rests WHERE until IS NULL OR until < expires_at ORDER BY id`,
		tenant, r.ids, now)
	if err != nil {
		return nil, nil, err
	}
	var gone, cut []string
	var to []time.Time
	var id string
	var until *time.Time
	if _, err := pgx.ForEachRow(rows, []any{&id, &until}, func() error {
		if until == nil || !until.After(now) {
			gone = append(gone, id)
		} else {
			cut, to = append(cut, id), append(to, *until)
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	if len(gone)+len(cut) == 0 {
		return nil, nil, nil
	}
	// In the order the grants a change removes are locked in (inOrder), as two changes ending places
	// can each cut short the other's. By id alone, which act found in the tenant: beside tenant = $1,
	// a generic plan could read the tenant's grants by it (byKey).
	if _, err := tx.Exec(ctx, lockedInOrder("rbac_grants", "", bindingOrder, "id = ANY($1::text[]::uuid[])"), slices.Concat(gone, cut)); err != nil {
		return nil, nil, err
	}
	if len(gone) > 0 {
		if ended, err = removedWhere(ctx, a, tx, "rbac_grants", grantColumns, collectGrants, "id = ANY($1::text[]::uuid[])", gone); err != nil {
			return nil, nil, err
		}
	}
	if len(cut) > 0 {
		rows, err := tx.Query(ctx, `UPDATE rbac_grants SET expires_at = c.x, updated_by = $3, updated_at = now()
			FROM unnest($1::text[], $2::timestamptz[]) AS c(i, x)
			WHERE id = c.i::uuid
			RETURNING `+grantColumns, cut, to, actorKey(actor))
		if err != nil {
			return nil, nil, err
		}
		if short, err = collectGrants(rows); err != nil {
			return nil, nil, err
		}
	}
	return short, ended, nil
}

// madeThrough is the eligibility an activation is made through: its id, and its principal's key.
type madeThrough struct {
	id        int64
	principal string
}

// eligible checks that s may activate act.Role on on until until through keys, the principal keys
// s holds then, so none outlasts the place in a group, or the membership, that makes s eligible. It
// returns the eligibility that allows it and who approved: one of s's identity or of one of its
// groups there, lasting act.Duration or longer and in force until then, whose requirement holds in
// the request, failing closed, and whose approvers, if it names any, include act.Approver, who isn't
// s. approved is zero when the eligibility allowing it names none. A privileged role's counts only
// through s's identity or its groups, as its grants do, never through the tenant's members.
func (a *Authorizer) eligible(ctx context.Context, q DB, s Subject, on Resource, act Activation, until time.Time, keys []string) (through madeThrough, approved Principal, err error) {
	scope, manage := on.Scope(), GrantPermission(on.Type)
	approvers, _, err := a.keysOf(ctx, q, on.Tenant, act.Approver)
	if err != nil {
		return madeThrough{}, Principal{}, err
	}
	rows, err := q.Query(ctx, byKey("$4", "rbac_eligibilities", "principal", "id, principal, requires, approvers", `tenant = $1 AND scope = $2 AND role = $3
		  AND max_seconds >= $5 AND (expires_at IS NULL OR expires_at > $6 AND expires_at >= $7)`),
		on.Tenant, scope.Key(), act.Role, countedOf(keys, broad{}), seconds(act.Duration), a.cfg.Now(), until)
	if err != nil {
		return madeThrough{}, Principal{}, err
	}
	type eligibility struct {
		madeThrough
		requires  string
		approvers []string
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (eligibility, error) {
		var e eligibility
		return e, row.Scan(&e.id, &e.principal, &e.requires, &e.approvers)
	})
	if err != nil {
		return madeThrough{}, Principal{}, err
	}
	// Those needing no approval first, so an approver passed where none is needed isn't recorded,
	// and of each the cheapest requirement first, as checks order conditions, so which allows
	// doesn't rest on how many approvers one names.
	cheapestFirst(found, func(e eligibility) string { return e.requires })
	slices.SortStableFunc(found, func(x, y eligibility) int {
		return cmp.Compare(min(len(x.approvers), 1), min(len(y.approvers), 1))
	})
	reason := fmt.Sprintf("not eligible to activate %s here for %s", act.Role, act.Duration)
	// The subject holds one eligibility for a role there, and its groups' requirements are bounded
	// together (SetEligibility).
	vars, spend := a.vars(ctx, s, manage, on), budgetOf(2*maxCheckCost)
	for _, e := range found {
		if len(e.approvers) > 0 && !approves(act.Approver, s, countedOf(approvers, broad{}), e.approvers) {
			reason = fmt.Sprintf("activating %s here needs one of its approvers to approve", act.Role)
			continue
		}
		if e.requires == "" || a.conds.holds(spend, e.requires, vars) {
			if len(e.approvers) > 0 {
				return e.madeThrough, act.Approver.Principal, nil
			}
			return e.madeThrough, Principal{}, nil
		}
	}
	return madeThrough{}, Principal{}, &DeniedError{Permission: manage, Scope: scope, Reason: reason}
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

// Eligibilities lists the eligibilities that match the filter, as stored, expired ones aside. It
// has no limit or cursor, so what it returns grows with what matches, as every eligibility on the
// tenant's scope.
func (a *Authorizer) Eligibilities(ctx context.Context, tenant string, f GrantFilter) ([]Eligibility, error) {
	if !validID(tenant) || !f.valid(tenant) {
		return nil, fmt.Errorf("%w: Eligibilities needs a tenant and valid scopes or principals", ErrInvalid)
	}
	query, scopes, principals := f.sql("rbac_eligibilities", eligibilityColumns, eligibilityColumns+", scope, principal", "scope, principal, role")
	rows, err := a.db.Query(ctx, query, tenant, scopes, principals, a.cfg.Now())
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
