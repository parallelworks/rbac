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
// itself, and a change ending that membership or place sooner cuts the activation short with it.
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
	// own ends.
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
		return ChangeEvent{Eligible: set}, a.requirementsBounded(ctx, tx, on.Tenant, e)
	})
}

// requirementsBounded refuses an eligibility of a group just stored that leaves the requirements
// of groups' eligibilities for its role on its scope costing more together than activating may
// spend on them: one activating evaluates those of each group it is in, and a subject holds one
// eligibility of its own there. Activating evaluates them whole, so an eligibility set beside
// another, as by an actor who can't delete it, never changes what that one allows.
func (a *Authorizer) requirementsBounded(ctx context.Context, tx pgx.Tx, tenant string, e Eligibility) error {
	if e.Requires == "" || e.Principal.Kind != Group {
		return nil
	}
	var requires []string
	if err := tx.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT requires), '{}') FROM rbac_eligibilities
		WHERE tenant = $1 AND scope = $2 AND role = $3 AND principal >= 'group:' AND principal < 'group;' AND requires <> ''
		  AND (expires_at IS NULL OR expires_at > $4)`,
		tenant, e.Scope.Key(), e.Role, a.cfg.Now()).Scan(&requires); err != nil {
		return err
	}
	if !affordable(once(requires)) {
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
// request, its justification and approver; one that would end no later changes nothing and
// returns the activation as it is, reporting nothing; and once it has ended, activating again
// makes a new grant, with a new ID. It needs no permission to change grants, the
// eligibility being the authority, but a constraint that stops changes to grants on the scope's
// type stops it, and Config.ValidateGrant is asked about it, as about any grant. Where the
// eligibility names approvers, the host's approval flow activates for s once one approves,
// passing act.Approver and, in ctx, the request s made (WithRequest), which Requires reads. It
// holds the places in groups s is in until it commits, so a change ending one of them sooner waits
// for it, and cuts the activation short if it rests on that place.
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
		// The places in groups it can rest on, held until it commits: a change ending one sooner holds
		// it before reading the activations resting on it, so it waits for this one and finds it. Each
		// key's are found on its own (byKey), then each held by its key in the order changes hold them.
		if _, err := tx.Exec(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$3")+`
			SELECT FROM (SELECT * FROM (`+byKey("ARRAY(SELECT k FROM keys)", "rbac_members", "principal", "group_id, principal, source",
			"tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`) p ORDER BY `+placeOrder+`) p CROSS JOIN LATERAL (
			  SELECT FROM rbac_members WHERE tenant = $1 AND group_id = p.group_id AND principal = p.principal AND source = p.source
			    AND (expires_at IS NULL OR expires_at > $3) FOR SHARE) m`, on.Tenant, s.identityKey(), a.cfg.Now()); err != nil {
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

// resting is the activations a change ending places in groups or memberships sooner may cut short:
// of the identities it ends them for, those the eligibilities allowed through their keys before the
// change, each with when the latest they allowed ends. gone are the eligibilities the change
// deletes besides, which still count, as deleting one leaves its activations to their own ends.
type resting struct {
	ids     []string
	allowed []pgtype.Timestamptz
	gone    []Eligibility
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

// allowingSQL is SQL defining, after act(id, principal, scope, role, expires_at), activations, and
// reachingSQL for their holders, elig(scope, role, principal, ends) and allowing(id, expires_at,
// until): the eligibilities in force at now, SQL for it, on the activations' scopes for their roles,
// and those as arrays at gone, SQL for the first of five parameters, a change deletes, each ending
// when it does or when an activation made from it now would, at its MaxDuration; and until when the
// eligibilities allow each activation through its holder's keys, by the latest of them, each until
// it or the holding of the key it names ends, null for none.
func allowingSQL(now string, gone int) string {
	return fmt.Sprintf(`elig(scope, role, principal, ends) AS (
		SELECT e.scope, e.role, e.principal, least(e.expires_at, %[1]s + e.max_seconds * interval '1 second')
		FROM (SELECT DISTINCT scope, role FROM act) a CROSS JOIN LATERAL (
		  SELECT scope, role, principal, expires_at, max_seconds FROM rbac_eligibilities WHERE tenant = $1 AND scope = a.scope AND role = a.role
		    AND (expires_at IS NULL OR expires_at > %[1]s) OFFSET 0) e
		UNION ALL
		SELECT s COLLATE "C", r COLLATE "C", p COLLATE "C", least(x, %[1]s + m * interval '1 second')
		FROM unnest($%[2]d::text[], $%[3]d::text[], $%[4]d::text[], $%[5]d::timestamptz[], $%[6]d::bigint[]) AS g(s, r, p, x, m)
	), allowing(id, expires_at, until) AS (
		SELECT a.id, a.expires_at, (SELECT max(least(e.ends, r.ends)) FROM elig e JOIN reaching r ON r.k = e.principal
		  WHERE e.scope = a.scope AND e.role = a.role AND r.holder = a.principal)
		FROM act a
	)`, now, gone, gone+1, gone+2, gone+3, gone+4)
}

// goneArgs are the arguments allowingSQL reads gone from.
func goneArgs(gone []Eligibility) []any {
	n := len(gone)
	scopes, roles, principals, ends := make([]string, n), make([]string, n), make([]string, n), make([]pgtype.Timestamptz, n)
	seconds := make([]int64, n)
	for i, e := range gone {
		scopes[i], roles[i], principals[i] = e.Scope.Key(), string(e.Role), e.Principal.key()
		ends[i] = pgtype.Timestamptz{Time: e.ExpiresAt, Valid: !e.ExpiresAt.IsZero()}
		seconds[i] = int64(e.MaxDuration / time.Second)
	}
	return []any{scopes, roles, principals, ends, seconds}
}

// doomed reads, in tx, the eligibilities in force at now that deleting those of principals, by key,
// deletes: theirs, and those only they approve, which unapprove deletes. They still count for the
// activations resting on what the change ends (resting.gone).
func doomed(ctx context.Context, tx pgx.Tx, tenant string, principals []string, now time.Time) ([]Eligibility, error) {
	// Theirs a principal at a time, and those they approve by the keys named (naming), each once.
	rows, err := tx.Query(ctx, `SELECT `+eligibilityColumns+` FROM (
		  `+byKey("$2", "rbac_eligibilities", "principal", eligibilityColumns, "tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`
		  UNION ALL
		  SELECT `+eligibilityColumns+` FROM rbac_eligibilities
		  WHERE `+naming("approvers", "$2")+` AND approvers <@ $2::text[] AND principal <> ALL($2::text[])
		    AND (expires_at IS NULL OR expires_at > $3)) e`, tenant, principals, now)
	if err != nil {
		return nil, err
	}
	return collectEligibilities(rows)
}

// restingOn reads, in tx, at now, the activations resting of identities, by key, and of the
// identities in groups, by id, in a tenant, that a change ending their places in groups or
// memberships sooner may cut short, with gone, the eligibilities it deletes besides. The change
// holds the rows it ends first, as Activate holds those an activation rests on, so none is made
// meanwhile through what the change ends.
func (a *Authorizer) restingOn(ctx context.Context, tx pgx.Tx, tenant string, identities, groups []string, gone []Eligibility, now time.Time) (resting, error) {
	if len(identities)+len(groups) == 0 {
		return resting{}, nil
	}
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE `+insideSQL("$3", "$4", "NULL", false)+`, holders(k) AS (
		  SELECT unnest($2::text[]) COLLATE "C" UNION SELECT principal FROM inside
		), act AS (
		  `+byKey("ARRAY(SELECT k FROM holders)", "rbac_grants", "principal", "id, principal, scope, role, expires_at",
		"tenant = $1 AND source = 'activation' AND expires_at > $4")+`
		), `+reachingSQL("ARRAY(SELECT DISTINCT principal FROM act)", "$4")+`, `+allowingSQL("$4", 5)+`
		SELECT id::text, until FROM allowing WHERE until IS NOT NULL ORDER BY id`,
		append([]any{tenant, identities, groups, now}, goneArgs(gone)...)...)
	if err != nil {
		return resting{}, err
	}
	r := resting{gone: gone}
	var id string
	var until pgtype.Timestamptz
	_, err = pgx.ForEachRow(rows, []any{&id, &until}, func() error {
		r.ids, r.allowed = append(r.ids, id), append(r.allowed, until)
		return nil
	})
	return r, err
}

// unrest cuts short, in tx, as actor, the activations r found resting that the eligibilities now
// allow, through the keys their holders hold once the change has ended places or memberships, less
// long than before it and than they last: each to when they still allow it, or ended if they don't
// past now, as an activation made now would last no longer. It returns those it cut short and
// those it ended.
func (a *Authorizer) unrest(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, r resting, now time.Time) (short, ended []Grant, err error) {
	if len(r.ids) == 0 {
		return nil, nil, nil
	}
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE was(id, allowed) AS (
		  SELECT i::uuid, x FROM unnest($2::text[], $3::timestamptz[]) AS t(i, x)
		), act AS (
		  SELECT g.id, g.principal, g.scope, g.role, g.expires_at FROM was w CROSS JOIN LATERAL (
		    SELECT id, principal, scope, role, expires_at FROM rbac_grants WHERE id = w.id AND tenant = $1
		      AND source = 'activation' AND expires_at > $4 OFFSET 0) g
		), `+reachingSQL("ARRAY(SELECT DISTINCT principal FROM act)", "$4")+`, `+allowingSQL("$4", 5)+`
		SELECT a.id::text, a.until FROM allowing a JOIN was w ON w.id = a.id
		WHERE a.until IS NULL OR a.until < w.allowed AND a.until < a.expires_at
		ORDER BY a.id`,
		append([]any{tenant, r.ids, r.allowed, now}, goneArgs(r.gone)...)...)
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
	rows, err := q.Query(ctx, byKey("$4", "rbac_eligibilities", "principal", "requires, approvers", `tenant = $1 AND scope = $2 AND role = $3
		  AND max_seconds >= $5 AND (expires_at IS NULL OR expires_at > $6 AND expires_at >= $7)`),
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
	// Those needing no approval first, so an approver passed where none is needed isn't recorded,
	// and of each the cheapest requirement first, as checks order conditions, so which allows
	// doesn't rest on how many approvers one names.
	cheapestFirst(found, func(e eligibility) string { return e.requires })
	slices.SortStableFunc(found, func(x, y eligibility) int {
		return cmp.Compare(min(len(x.approvers), 1), min(len(y.approvers), 1))
	})
	reason := fmt.Sprintf("not eligible to activate %s here for %s", act.Role, act.Duration)
	// On the budget of a check of the scope: the subject holds one eligibility for a role there,
	// and its groups' requirements are bounded together (SetEligibility).
	vars, spend := a.vars(ctx, s, manage, on), newGrantBudget([]string{scope.Key()})
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
