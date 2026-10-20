package rbac

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ManageGroups is the permission to create, replace and delete a tenant's groups, held on the
// tenant. GroupMembers is the permission to change a group's members, held on its scope or the
// tenant; adding one gives it what the group holds, so that takes the power to grant it too
// (ChangeMembers). Both change access.
const (
	ManageGroups Permission = "tenant:groups"
	GroupMembers Permission = "group:members"
)

// GroupScope is the type of the scope a group is, which a host's catalog gives roles on, as on any
// scope: groups are directly under the tenant.
const GroupScope = "group"

// MaxGroupDepth is how many groups a chain of groups, each in the next, holds at most.
const MaxGroupDepth = 8

// MaxPlacesInGroup is how many places in force a principal has in one group, each from a source of
// its own, as MaxGrantsPerRole bounds a role's grants: those from each source the host owns
// (Config.Sources) counted apart.
const MaxPlacesInGroup = 20

// MaxGroupsOfPrincipal is how many groups a principal, an identity or a group, is in directly, by
// places in force, as every check reads each group its subject is in: those it is in from each
// source the host owns (Config.Sources) counted apart, as for MaxPlacesInGroup.
const MaxGroupsOfPrincipal = 1000

// Membership is an identity's membership of a tenant. A member holds what it is granted there and
// what is granted to the tenant's members; a guest only what it is granted; and a suspended one
// keeps its grants and groups but holds only what the public does until the suspension is lifted,
// still bound by the denies that name its groups or the tenant's members. The host keeps
// memberships with SetMemberships and ends them with DeletePrincipal.
type Membership struct {
	// Tenant is set on memberships read back.
	Tenant    string
	Principal Principal
	Guest     bool
	Suspended bool
	// Source is who keeps it, as Binding.Source is for grants: empty, or the host's, such as a
	// directory it syncs from.
	Source string
	// ExpiresAt ends it; zero never does. Ending it sooner, or removing it, cuts short the
	// identity's activations to it, as each rests on it, whichever eligibility it was made through
	// (Eligibility).
	ExpiresAt time.Time
	Note      string
	// CreatedBy, CreatedAt, UpdatedBy and UpdatedAt are set on memberships read back.
	CreatedBy Principal
	CreatedAt time.Time
	UpdatedBy Principal
	UpdatedAt time.Time
}

// GroupDefinition is a tenant's group of identities and other groups. `group:<id>` in a grant, a
// deny or an eligibility names it only in its tenant.
type GroupDefinition struct {
	// ID names it in its tenant: any text without NUL, of at most MaxName characters. Never reuse
	// one: grants to a group are by its id.
	ID          string
	Name        string
	Description string
	// Source is who keeps it: empty, or the host's (Config.Sources), whose groups only the host
	// changes.
	Source string
	// CreatedBy, CreatedAt, UpdatedBy and UpdatedAt are set on groups read back.
	CreatedBy Principal
	CreatedAt time.Time
	UpdatedBy Principal
	UpdatedAt time.Time
}

// Member is one principal in a group, from a source: an identity that is a member or guest of the
// tenant, or another of the tenant's groups, whose members are then the group's too, at most
// MaxGroupDepth groups deep.
type Member struct {
	Group     string
	Principal Principal
	Source    string
	// ExpiresAt ends it; zero never does. Ending it sooner, or removing it, cuts short the
	// activations made through an eligibility of the group, or of a group it is in, by the
	// identities it puts there, to the latest end of the paths they have left to that group, or
	// ends them (Eligibility).
	ExpiresAt time.Time
	Note      string
	// CreatedBy, CreatedAt, UpdatedBy and UpdatedAt are set on members read back.
	CreatedBy Principal
	CreatedAt time.Time
	UpdatedBy Principal
	UpdatedAt time.Time
}

func validGroupID(id string) bool {
	return id != "" && utf8.RuneCountInString(id) <= MaxName && validText(id)
}

// checkSource returns why a source can't be stored.
func checkSource(s string) string {
	switch {
	case !validSource(s):
		return "a source is lowercase letters, digits and . _ : / -, starting with a letter, of at most 63"
	case reservedSource(s):
		return "a source starting rbac is reserved for the package"
	}
	return ""
}

// checkExpiry returns why an expiry can't be stored at now, or "" if it can: none, or one to come
// by the end of 9999-12-30, which is in 9999 in every time zone, the last year JSON and RFC 3339
// write, so the expiry, and history, can be written as text wherever it is read.
func checkExpiry(expires, now time.Time) string {
	switch {
	case expires.IsZero():
		return ""
	case !expires.After(now):
		return "already expired"
	case expires.After(time.Date(9999, time.December, 30, 23, 59, 59, 999999000, time.UTC)):
		return "expires after 9999-12-30"
	}
	return ""
}

// checkKept returns why a membership's or member's source, expiry and note can't be stored at now.
func checkKept(source string, expires time.Time, note string, now time.Time) []string {
	var errs []string
	if reason := checkSource(source); reason != "" {
		errs = append(errs, reason)
	}
	if reason := checkExpiry(expires, now); reason != "" {
		errs = append(errs, reason)
	}
	if !validNote(note) {
		errs = append(errs, fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	return errs
}

// checkMembership returns why a membership can't be stored at now.
func (a *Authorizer) checkMembership(m Membership, now time.Time) error {
	var errs []string
	if !a.acts(m.Principal.Kind) || !validID(m.Principal.ID) {
		errs = append(errs, "only an identity, a user or a declared kind, is a member of a tenant")
	}
	errs = append(errs, checkKept(m.Source, m.ExpiresAt, m.Note, now)...)
	if len(errs) > 0 {
		return fmt.Errorf("%w: membership of %s: %s", ErrInvalid, m.Principal.key(), strings.Join(errs, "; "))
	}
	return nil
}

// SetMemberships makes identities members or guests of a tenant, or changes how, as actor: the
// host's own write, without the checks a change by a tenant's admins has, as Import is for grants.
// It reports the memberships it set or changed. An identity whose membership had ended joins again
// in none of the groups it was in, whether or not DeleteExpired has run since, as a membership
// made by actor now. Config.ValidateGrant is asked about none of what an identity holds: a host
// whose policy decides by membership, as none privileged for a guest, checks what one holds when
// it makes it a guest or lifts its suspension.
func (a *Authorizer) SetMemberships(ctx context.Context, actor Principal, tenant string, ms []Membership) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "SetMemberships")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(ms) == 0 {
		return nil
	}
	if len(ms) > MaxBindings {
		return fmt.Errorf("%w: a change sets at most %d memberships", ErrInvalid, MaxBindings)
	}
	now := a.cfg.Now()
	// The last of one principal's, as a change can't set a row twice.
	byPrincipal := map[Principal]Membership{}
	var errs []error
	for _, m := range ms {
		m.ExpiresAt = stored(m.ExpiresAt)
		errs = append(errs, a.checkMembership(m, now))
		byPrincipal[m.Principal] = m
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	set := slices.SortedFunc(maps.Values(byPrincipal), func(x, y Membership) int { return strings.Compare(x.Principal.key(), y.Principal.key()) })
	n := len(set)
	kinds, ids, sources, notes := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	guests, suspended, expires := make([]bool, n), make([]bool, n), make([]pgtype.Timestamptz, n)
	keys := make([]string, n)
	var ending []string
	for i, m := range set {
		kinds[i], ids[i], sources[i], notes[i] = string(m.Principal.Kind), m.Principal.ID, m.Source, m.Note
		guests[i], suspended[i] = m.Guest, m.Suspended
		expires[i] = pgtype.Timestamptz{Time: m.ExpiresAt, Valid: !m.ExpiresAt.IsZero()}
		keys[i] = m.Principal.key()
		if !m.ExpiresAt.IsZero() {
			ending = append(ending, keys[i])
		}
	}
	return a.inTxReaching(ctx, tenant, actor, "SetMemberships", func(tx pgx.Tx) (ChangeEvent, []string, error) {
		if err := lockAll(ctx, tx, tenant, nil, keys); err != nil {
			return ChangeEvent{}, nil, err
		}
		// One time for both statements, under the locks: a membership ending between two reads
		// would be made anew yet keep its groups. An ended membership's groups go, as DeleteExpired
		// would remove them, each membership held before its members as there, so the two never
		// deadlock; and any places of an identity with no membership, which joins in none.
		at := a.cfg.Now()
		var widened []string
		if a.exclusive() {
			if widened, err = widening(ctx, tx, tenant, set, keys, at); err != nil {
				return ChangeEvent{}, nil, err
			}
		}
		// A membership with an end may end one in force sooner, which the activations resting on it
		// end with.
		r, err := a.restingOn(ctx, tx, tenant, ending, nil, at)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		// The places of each key leaving are found on its own and locked in order, as removeGroups
		// finds and locks its own.
		left, err := removedWhere(ctx, a, tx, "rbac_members", memberColumns, collectMembers, lockedAnyOf("rbac_members", "ctid", placeOrder,
			byKeys("rbac_members", "ctid", "principal", `(
			  ARRAY(SELECT principal FROM rbac_memberships WHERE tenant = $1 AND principal = ANY($2::text[]) AND expires_at <= $3 FOR UPDATE)
			  || ARRAY(SELECT k FROM unnest($2::text[]) AS k WHERE NOT EXISTS (SELECT FROM rbac_memberships WHERE tenant = $1 AND principal = k OFFSET 0)))`)),
			tenant, keys, at)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_memberships AS m (tenant, principal_kind, principal_id, guest, suspended, source, expires_at, note,
			  created_by, updated_by)
			SELECT $1, k, i, g, s, src, e, n, $9, $9
			FROM unnest($2::text[], $3::text[], $4::bool[], $5::bool[], $6::text[], $7::timestamptz[], $8::text[]) AS t(k, i, g, s, src, e, n)
			ON CONFLICT (tenant, principal) DO UPDATE SET guest = EXCLUDED.guest, suspended = EXCLUDED.suspended,
			  source = EXCLUDED.source, expires_at = EXCLUDED.expires_at, note = EXCLUDED.note,
			  created_by = CASE WHEN m.expires_at <= $10 THEN EXCLUDED.created_by ELSE m.created_by END,
			  created_at = CASE WHEN m.expires_at <= $10 THEN EXCLUDED.created_at ELSE m.created_at END,
			  updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE (m.guest, m.suspended, m.source, m.expires_at, m.note)
			  IS DISTINCT FROM (EXCLUDED.guest, EXCLUDED.suspended, EXCLUDED.source, EXCLUDED.expires_at, EXCLUDED.note)
			RETURNING `+membershipColumns,
			tenant, kinds, ids, guests, suspended, sources, expires, notes, actorKey(actor), at)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		changed, err := collectMemberships(rows)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		e := ChangeEvent{Memberships: changed, Left: left}
		e.Shortened, e.Revoked, err = a.unrest(ctx, tx, tenant, actor, r, at)
		return e, widened, err
	})
}

// widening reads, on tx before set is stored, the memberships in force of its identities, by keys,
// and returns the keys of those whose memberships set widens what they hold, or will hold once a
// suspension is lifted, which their exclusive values are checked for. A suspended membership holds
// only what the public does, so suspending one never widens what it holds, nor does a suspended
// guest's, as the exclusive values count an identity's own grants before it joins; but a member's
// made, renewed or lifted from a guest's while suspended will hold more once lifted, which lifting
// it would then be refused for. One that only ends sooner, or changes its note, is a removal or no
// change, never refused.
func widening(ctx context.Context, tx pgx.Tx, tenant string, set []Membership, keys []string, at time.Time) ([]string, error) {
	// Each key's membership is looked up on its own: as a join, a generic plan, costing the tenant's
	// memberships by averages, reads every one. OFFSET 0 keeps the planner from making it one.
	rows, err := tx.Query(ctx, `SELECT m.principal, m.guest, m.suspended, m.source, m.expires_at FROM unnest($2::text[]) AS k
		CROSS JOIN LATERAL (SELECT principal, guest, suspended, source, expires_at FROM rbac_memberships
		  WHERE tenant = $1 AND principal = k AND (expires_at IS NULL OR expires_at > $3) OFFSET 0) m`, tenant, keys, at)
	if err != nil {
		return nil, err
	}
	was := map[string]Membership{}
	var key string
	var row Membership
	var expires *time.Time
	if _, err := pgx.ForEachRow(rows, []any{&key, &row.Guest, &row.Suspended, &row.Source, &expires}, func() error {
		row.ExpiresAt = time.Time{}
		if expires != nil {
			row.ExpiresAt = *expires
		}
		was[key] = row
		return nil
	}); err != nil {
		return nil, err
	}
	var widened []string
	for i, m := range set {
		old, ok := was[keys[i]]
		switch {
		case m.Suspended && (m.Guest || ok && !old.Guest):
		case m.Suspended:
			widened = append(widened, keys[i])
		case !ok || old.Guest != m.Guest || old.Suspended || old.Source != m.Source || outlasts(m.ExpiresAt, old.ExpiresAt):
			widened = append(widened, keys[i])
		}
	}
	return widened, nil
}

// outlasts reports whether what ends at end, zero for never, lasts past was.
func outlasts(end, was time.Time) bool {
	return !was.IsZero() && (end.IsZero() || end.After(was))
}

// Memberships lists a tenant's memberships in force, by principal: of those principals, or with
// none, all. It has no limit or cursor, so with none, what it returns grows with the tenant's
// members and guests.
func (a *Authorizer) Memberships(ctx context.Context, tenant string, principals []Principal) ([]Membership, error) {
	// The zero principal, the anonymous subject's, which a constraint may ask about, has none.
	if !validID(tenant) || slices.ContainsFunc(principals, func(p Principal) bool { return p != (Principal{}) && !p.wellFormed(tenant) }) {
		return nil, fmt.Errorf("%w: Memberships needs a tenant and valid principals", ErrInvalid)
	}
	// A statement of its own for each shape, as GrantFilter's: one plan for both, cached generic
	// once a connection has listed the tenant, reads every membership to find the principals'.
	which, keys := "$2::text[] IS NULL", []string(nil)
	if len(principals) > 0 {
		which, keys = "principal = ANY($2::text[])", keysOf(principals)
	}
	rows, err := a.db.Query(ctx, `SELECT `+membershipColumns+` FROM rbac_memberships
		WHERE tenant = $1 AND `+which+` AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY principal`, tenant, keys, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectMemberships(rows)
}

// MembershipsOf lists an identity's memberships in force in every tenant, by tenant.
func (a *Authorizer) MembershipsOf(ctx context.Context, p Principal) ([]Membership, error) {
	// The zero principal, the anonymous subject's, which a constraint may ask about, has none.
	if p == (Principal{}) {
		return nil, nil
	}
	if !validName(string(p.Kind)) || !validID(p.ID) {
		return nil, fmt.Errorf("%w: MembershipsOf needs a kind and an id of text without NUL of at most %d bytes", ErrInvalid, MaxID)
	}
	rows, err := a.db.Query(ctx, `SELECT `+membershipColumns+` FROM rbac_memberships
		WHERE principal = $1 AND (expires_at IS NULL OR expires_at > $2) ORDER BY tenant`, p.key(), a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectMemberships(rows)
}

const membershipColumns = `tenant, principal_kind, principal_id, guest, suspended, source, expires_at, note,
	created_by, created_at, updated_by, updated_at`

func collectMemberships(rows pgx.Rows) ([]Membership, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Membership, error) {
		var m Membership
		var expires *time.Time
		var createdBy, updatedBy string
		err := row.Scan(&m.Tenant, &m.Principal.Kind, &m.Principal.ID, &m.Guest, &m.Suspended, &m.Source, &expires, &m.Note,
			&createdBy, &m.CreatedAt, &updatedBy, &m.UpdatedAt)
		if expires != nil {
			m.ExpiresAt = *expires
		}
		m.CreatedBy, m.UpdatedBy = parsePrincipal(createdBy), parsePrincipal(updatedBy)
		return m, err
	})
}

// checkGroup returns why a group can't be stored.
func checkGroup(g GroupDefinition) error {
	var errs []string
	if !validGroupID(g.ID) {
		errs = append(errs, fmt.Sprintf("an id is text without NUL of 1 to %d characters", MaxName))
	}
	if utf8.RuneCountInString(g.Name) > MaxName || utf8.RuneCountInString(g.Description) > MaxDescription ||
		!validText(g.Name) || !validText(g.Description) {
		errs = append(errs, fmt.Sprintf("a name is text of at most %d characters and a description %d", MaxName, MaxDescription))
	}
	if reason := checkSource(g.Source); reason != "" {
		errs = append(errs, reason)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: group %q: %s", ErrInvalid, g.ID, strings.Join(errs, "; "))
	}
	return nil
}

// SetGroup creates a group in a tenant, or renames or redescribes one, as actor, who needs
// ManageGroups on the tenant as Config.ResourceOf gives it, not removed by a constraint nor refused
// by its label, nor by the group's, as Config.ResourceOf gives the group. A group from a source the
// host owns (Config.Sources) only the host changes, with ImportGroups.
func (a *Authorizer) SetGroup(ctx context.Context, actor Subject, tenant string, g GroupDefinition) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "SetGroup")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root, err := a.groupsTenant(ctx, tenant)
	if err != nil {
		return err
	}
	labels := a.tenantLabels(ctx, actor, tenant)
	if err := a.mayManageGroups(ctx, a.db, actor, ManageGroups, root, labels); err != nil {
		return err
	}
	if err := checkGroup(g); err != nil {
		return err
	}
	if a.owned[g.Source] {
		return fmt.Errorf("%w: group %q: only the host makes groups from %s, through ImportGroups", ErrInvalid, g.ID, g.Source)
	}
	group, err := a.groupLabeled(ctx, tenant, g.ID, labels, false)
	if err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, "SetGroup", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, tenant, []string{groupKey(g.ID)}, nil); err != nil {
			return ChangeEvent{}, err
		}
		labels.seal()
		if err := a.mayManageGroups(ctx, tx, actor, ManageGroups, root, labels); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.labelCheck(ctx, tx, labels)(group, ManageGroups); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.notOwnedGroups(ctx, tx, tenant, []string{g.ID}); err != nil {
			return ChangeEvent{}, err
		}
		set, err := upsertGroups(ctx, tx, tenant, actor.Principal, []GroupDefinition{g})
		return ChangeEvent{Groups: set}, err
	})
}

// ImportGroups creates groups in a tenant or replaces them, as actor: the host's own write, as for
// a directory it syncs from, without the checks SetGroup makes of an actor. Taking over a group
// the tenant made, from one of Config.Sources, removes the members it has from no source of the
// host's, which ChangeEvent.Left reports.
func (a *Authorizer) ImportGroups(ctx context.Context, actor Principal, tenant string, groups []GroupDefinition) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "ImportGroups")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil
	}
	if len(groups) > MaxBindings {
		return fmt.Errorf("%w: an import stores at most %d groups", ErrInvalid, MaxBindings)
	}
	byID := map[string]GroupDefinition{}
	var errs []error
	for _, g := range groups {
		errs = append(errs, checkGroup(g))
		byID[g.ID] = g
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	set := slices.SortedFunc(maps.Values(byID), func(x, y GroupDefinition) int { return strings.Compare(x.ID, y.ID) })
	keys := make([]string, len(set))
	for i, g := range set {
		keys[i] = groupKey(g.ID)
	}
	return a.inTx(ctx, tenant, actor, "ImportGroups", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, keys, nil); err != nil {
			return ChangeEvent{}, err
		}
		taken, err := a.takenOver(ctx, tx, tenant, set)
		if err != nil {
			return ChangeEvent{}, err
		}
		changed, err := upsertGroups(ctx, tx, tenant, actor, set)
		if err != nil || len(taken) == 0 {
			return ChangeEvent{Groups: changed}, err
		}
		// Those a tenant put in a group it made were checked as granting what it held then, not
		// what the host grants its own, as it may once it holds the group.
		const tenants = "tenant = $1 AND source <> ALL($3::text[])"
		owned := slices.Sorted(maps.Keys(a.owned))
		now := a.cfg.Now()
		identities, groups, err := endingPlaces(ctx, tx, `
			SELECT m.principal FROM unnest($2::text[]) AS k(g) CROSS JOIN LATERAL (
			  SELECT principal FROM rbac_members WHERE `+tenants+` AND group_id = k.g
			  ORDER BY principal, source FOR UPDATE) m`, tenant, taken, owned)
		if err != nil {
			return ChangeEvent{}, err
		}
		r, err := a.restingOn(ctx, tx, tenant, identities, groups, now)
		if err != nil {
			return ChangeEvent{}, err
		}
		e := ChangeEvent{Groups: changed}
		// Each group's found on its own, as removeGroups finds them.
		if e.Left, err = removedWhere(ctx, a, tx, "rbac_members", memberColumns, collectMembers,
			lockedAnyOf("rbac_members", "ctid", placeOrder, byKey("$2", "rbac_members", "group_id", "ctid", tenants)), tenant, taken, owned); err != nil {
			return ChangeEvent{}, err
		}
		e.Shortened, e.Revoked, err = a.unrest(ctx, tx, tenant, actor, r, now)
		return e, err
	})
}

// takenOver returns, of the groups an import sets, those it takes from the tenant: that exist, from
// a source the host doesn't own, and that it sets from one it does.
func (a *Authorizer) takenOver(ctx context.Context, tx pgx.Tx, tenant string, set []GroupDefinition) ([]string, error) {
	var ids []string
	for _, g := range set {
		if a.owned[g.Source] {
			ids = append(ids, g.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT id FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[]) AND source <> ALL($3::text[]) ORDER BY id`,
		tenant, ids, slices.Sorted(maps.Keys(a.owned)))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// upsertGroups stores groups, sorted by id, and returns those it created or changed.
func upsertGroups(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, groups []GroupDefinition) ([]GroupDefinition, error) {
	n := len(groups)
	ids, names, descriptions, sources := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, g := range groups {
		ids[i], names[i], descriptions[i], sources[i] = g.ID, g.Name, g.Description, g.Source
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO rbac_groups AS g (tenant, id, name, description, source, created_by, updated_by)
		SELECT $1, i, n, d, s, $6, $6 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS t(i, n, d, s)
		ON CONFLICT (tenant, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
		  source = EXCLUDED.source, updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE (g.name, g.description, g.source) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.source)
		RETURNING `+groupColumns,
		tenant, ids, names, descriptions, sources, actorKey(actor))
	if err != nil {
		return nil, err
	}
	return collectGroups(rows)
}

// DeleteGroup deletes a tenant's group, as actor, who needs ManageGroups on the tenant, and the
// group's label, as SetGroup does, and with it its members and its place in other groups. Its
// members hold what it and the groups it is in hold, so it refuses a group that, or a group it is
// in, holds grants or eligibilities in force, which revoking first shows, that a deny names or
// exempts, or that approves an eligibility's activations: deleting one never changes access as a
// side effect. It holds the locks of the groups it is in, as a change to their members does, so a
// grant, eligibility or deny naming one waits for it, or it reads that one. It refuses one from a
// source the host owns, in a group from one, or with members, a place in a group or grants on it
// from one. Deleting a group that doesn't exist does nothing, and asks Config.ResourceOf nothing of
// it; one the host no longer has (ErrNotFound) it reads as unlabeled, as a removal reads any scope.
func (a *Authorizer) DeleteGroup(ctx context.Context, actor Subject, tenant, id string) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "DeleteGroup")
	if !validID(tenant) || !validGroupID(id) {
		return fmt.Errorf("%w: DeleteGroup needs a tenant and a valid group", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root, err := a.groupsTenant(ctx, tenant)
	if err != nil {
		return err
	}
	labels := a.tenantLabels(ctx, actor, tenant)
	if err := a.mayManageGroups(ctx, a.db, actor, ManageGroups, root, labels); err != nil {
		return err
	}
	// The groups it is in, whose locks a grant, eligibility or deny naming one takes, so one made
	// meanwhile waits for the deletion, or deletable reads it. Read before the transaction, so it
	// takes every lock at once, in order: under nestingKey none is nested above it meanwhile, so one
	// read there and not here was nested in between, and the deletion is tried again.
	scopes := []string{groupKey(id), nestingKey}
	above, err := upOf(ctx, a.db, tenant, id, a.cfg.Now())
	if err != nil {
		return err
	}
	// A group that doesn't exist has no label to ask the host for, and deleting it does nothing.
	// Without declared labels none is asked for, so one made meanwhile needs no new check.
	existed, group := true, Resource{Tenant: tenant, Type: GroupScope, ID: id}
	if len(a.labels) > 0 {
		if existed, err = groupExists(ctx, a.db, tenant, id); err != nil {
			return err
		}
		if existed {
			if group, err = a.groupLabeled(ctx, tenant, id, labels, true); err != nil {
				return err
			}
		}
	}
	return a.inTx(ctx, tenant, actor.Principal, "DeleteGroup", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, above); err != nil {
			return ChangeEvent{}, err
		}
		exists, err := groupExists(ctx, tx, tenant, id)
		if err != nil {
			return ChangeEvent{}, err
		}
		labels.seal()
		if err := a.mayManageGroups(ctx, tx, actor, ManageGroups, root, labels); err != nil {
			return ChangeEvent{}, err
		}
		// Without a group, the grants and denies on its scope are no group's to remove.
		if !exists {
			return ChangeEvent{}, nil
		}
		if !existed {
			return ChangeEvent{}, fmt.Errorf("%w: group %q was made while this change waited; try again", ErrConflict, id)
		}
		if err := a.labelCheck(ctx, tx, labels)(group, ManageGroups); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.notOwnedGroups(ctx, tx, tenant, []string{id}); err != nil {
			return ChangeEvent{}, err
		}
		reached, err := upOf(ctx, tx, tenant, id, a.cfg.Now())
		if err != nil {
			return ChangeEvent{}, err
		}
		if len(scopes)+len(above) <= maxLocks {
			for _, k := range reached {
				if _, ok := slices.BinarySearch(above, k); !ok {
					return ChangeEvent{}, fmt.Errorf("%w: group %q is now in %s, which this deletion doesn't lock; try again", ErrConflict, id, k)
				}
			}
		}
		if err := a.deletable(ctx, tx, tenant, id, reached); err != nil {
			return ChangeEvent{}, err
		}
		return a.removeGroups(ctx, tx, tenant, actor.Principal, []string{id})
	})
}

// upOf reads, on q, the keys of a group and the groups it is in, through those they are in, at now,
// sorted. Each group's are looked up by its key (groupsAbove), so a generic plan can't join them to
// every member of the tenant.
func upOf(ctx context.Context, q DB, tenant, id string, now time.Time) ([]string, error) {
	rows, err := q.Query(ctx, `
		WITH RECURSIVE up(id) AS (
		  SELECT $2::text COLLATE "C"
		  UNION
		  SELECT m.group_id FROM up u `+groupsAbove("u.id", "$3", "group_id")+`
		)
		SELECT 'group:' || id FROM up ORDER BY 1`, tenant, id, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// groupExists reports, on q, whether a tenant has a group.
func groupExists(ctx context.Context, q DB, tenant, id string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = $2)`, tenant, id).Scan(&exists)
	return exists, err
}

// deletable refuses deleting a group an actor asks to delete when that would change access, its
// members' through the groups it is in too, above, as upOf reads them, or what the host
// keeps. Expired grants, eligibilities and places in groups give nothing, and Grants doesn't list
// them to revoke, so they go with it.
func (a *Authorizer) deletable(ctx context.Context, tx pgx.Tx, tenant, id string, above []string) error {
	var held, denied, approves, owned bool
	if err := tx.QueryRow(ctx, `
		SELECT
		  EXISTS (`+byKey("$7", "rbac_grants", "principal", "1", "tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`)
		    OR EXISTS (`+byKey("$7", "rbac_eligibilities", "principal", "1", "tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`),
		  EXISTS (SELECT FROM rbac_denies WHERE `+naming("principals", "$7")+` OR `+naming("exempt", "$7")+`),
		  EXISTS (SELECT FROM rbac_eligibilities WHERE `+naming("approvers", "$7")+` AND (expires_at IS NULL OR expires_at > $3)),
		  EXISTS (SELECT FROM rbac_members WHERE tenant = $1 AND (group_id = $4 OR principal = $2) AND source = ANY($5::text[]))
		    OR EXISTS (SELECT FROM rbac_members m JOIN rbac_groups g ON g.tenant = m.tenant AND g.id = m.group_id
		      WHERE m.tenant = $1 AND m.principal = $2 AND g.source = ANY($5::text[]))
		    OR EXISTS (SELECT FROM rbac_grants WHERE tenant = $1 AND scope = $6 AND source = ANY($5::text[])
		      AND (expires_at IS NULL OR expires_at > $3))`,
		tenant, groupPrincipal(id).key(), a.cfg.Now(), id, slices.Sorted(maps.Keys(a.owned)), groupKey(id), above).Scan(&held, &denied, &approves, &owned); err != nil {
		return err
	}
	switch {
	case held:
		return fmt.Errorf("%w: group %q, or a group it is in, holds grants or eligibilities: revoke them first", ErrInvalid, id)
	case denied:
		return fmt.Errorf("%w: a deny names or exempts group %q, or a group it is in: change it first", ErrInvalid, id)
	case approves:
		return fmt.Errorf("%w: an eligibility names group %q, or a group it is in, as an approver: change it first", ErrInvalid, id)
	case owned:
		return fmt.Errorf("%w: group %q is in a group of the host's, or has members, a place in a group or grants on it from a source only the host changes", ErrInvalid, id)
	}
	return nil
}

// DeleteGroups deletes a tenant's groups, as actor: the host's own write, as for a directory it
// syncs from. With each go its members, its place in other groups, its grants and eligibilities,
// and its place in denies and among approvers: an eligibility only the groups approve goes too,
// rather than activate without approval.
func (a *Authorizer) DeleteGroups(ctx context.Context, actor Principal, tenant string, ids []string) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteGroups")
	if len(ids) > MaxBindings {
		return fmt.Errorf("%w: a deletion names at most %d groups", ErrInvalid, MaxBindings)
	}
	if !validID(tenant) || slices.ContainsFunc(ids, func(id string) bool { return !validGroupID(id) }) {
		return fmt.Errorf("%w: DeleteGroups needs a tenant and valid groups", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	if len(ids) == 0 {
		return nil
	}
	// nestingKey too, as DeleteGroup takes it: two removals at once would each take their groups out
	// of the denies and approvers the other left, and an eligibility both approve could keep none.
	scopes, principals := []string{nestingKey}, make([]string, len(ids))
	for i, id := range ids {
		scopes = append(scopes, groupKey(id))
		principals[i] = groupPrincipal(id).key()
	}
	return a.inTx(ctx, tenant, actor, "DeleteGroups", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		return a.removeGroups(ctx, tx, tenant, actor, ids)
	})
}

// removeGroups deletes groups with their grants and eligibilities, the members they have, their
// places in other groups, in denies and among approvers, and returns what it changed for OnChange.
func (a *Authorizer) removeGroups(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, ids []string) (ChangeEvent, error) {
	var e ChangeEvent
	principals, scopes := make([]string, len(ids)), make([]string, len(ids))
	for i, id := range ids {
		principals[i], scopes[i] = groupPrincipal(id).key(), groupKey(id)
	}
	// DeleteScopes and DeletePrincipal hold other scopes' and principals' locks and change some of
	// these rows too, so each table is changed in the order delete changes them, grants last, and
	// the rows changed in it are locked in order first: otherwise they would deadlock. Each is found
	// by key on its own (byKeys), or by the keys it names (naming), and deleted by key: ORed, the
	// conditions are none an index seeks, and beside tenant = $1 a generic plan, costing the tenant
	// as an average tenant's few rows, finds them by reading every row in the tenant. The
	// eligibilities of the groups and on them, as their managers', which would pass to a group made
	// later with an id of theirs, and those they approve.
	if err := lockByKeys(ctx, tx, "rbac_eligibilities", "id", bindingOrder, []string{"principal", "scope"},
		[]string{"SELECT id FROM rbac_eligibilities WHERE " + naming("approvers", "$2")}, tenant, principals, scopes); err != nil {
		return ChangeEvent{}, err
	}
	now := a.cfg.Now()
	var err error
	if e.Ineligible, err = removedWhere(ctx, a, tx, "rbac_eligibilities", eligibilityColumns, collectEligibilities,
		lockedByKeys("rbac_eligibilities", "id", bindingOrder, "principal", "scope"), tenant, principals, scopes); err != nil {
		return ChangeEvent{}, err
	}
	unapproved, changed, err := a.unapprove(ctx, tx, tenant, principals)
	if err != nil {
		return ChangeEvent{}, err
	}
	e.Ineligible, e.Eligible = append(e.Ineligible, unapproved...), changed
	// The denies on the groups, and those that name or exempt them.
	if err := lockDenies(ctx, tx, []string{
		byKeys("rbac_denies", denyKey, "scope", "$2"),
		"SELECT " + denyKey + " FROM rbac_denies WHERE " + naming("principals", "$3"),
		"SELECT " + denyKey + " FROM rbac_denies WHERE " + naming("exempt", "$3"),
	}, tenant, scopes, principals); err != nil {
		return ChangeEvent{}, err
	}
	if e.DeletedDenies, err = removedWhere(ctx, a, tx, "rbac_denies", denyColumns, collectDenies,
		anyOf("ctid", byKeys("rbac_denies", "ctid", "scope", "$2")), tenant, scopes); err != nil {
		return ChangeEvent{}, err
	}
	// A deny that names or exempts the groups would name or exempt a group made later with one's
	// id: one naming only them denies no one, and goes. Each found by the keys it names, so it names
	// one of them: none of them is empty.
	unnamed, err := removedWhere(ctx, a, tx, "rbac_denies", denyColumns, collectDenies,
		naming("principals", "$2")+" AND principals <@ $2::text[]", tenant, principals)
	if err != nil {
		return ChangeEvent{}, err
	}
	e.DeletedDenies = append(e.DeletedDenies, unnamed...)
	if e.Denies, err = unexempt(ctx, tx, tenant, actor, principals, true); err != nil {
		return ChangeEvent{}, err
	}
	// The places in the groups and of them, and the grants of the groups and on them, so too. Places
	// in groups have no id, so a ctid keys them: no change moves one meanwhile, as each takes its
	// group's lock or its principal's, which this change holds. The places are held before the
	// activations resting on them are read.
	if err := lockByKeys(ctx, tx, "rbac_members", "ctid", placeOrder, []string{"group_id", "principal"}, nil, tenant, ids, principals); err != nil {
		return ChangeEvent{}, err
	}
	r, err := a.restingOn(ctx, tx, tenant, nil, ids, now)
	if err != nil {
		return ChangeEvent{}, err
	}
	if e.Left, err = removedWhere(ctx, a, tx, "rbac_members", memberColumns, collectMembers,
		lockedByKeys("rbac_members", "ctid", placeOrder, "group_id", "principal"), tenant, ids, principals); err != nil {
		return ChangeEvent{}, err
	}
	if e.DeletedGroups, err = removed(ctx, a, tx, "rbac_groups", groupColumns, collectGroups, tenant, "id = ANY($2::text[])", ids); err != nil {
		return ChangeEvent{}, err
	}
	if len(r.ids) > 0 {
		// With the activations it may cut short, in one order.
		if err := lockByKeys(ctx, tx, "rbac_grants", "id", bindingOrder, []string{"principal", "scope"}, []string{"SELECT unnest($4::text[]::uuid[])"},
			tenant, principals, scopes, r.ids); err != nil {
			return ChangeEvent{}, err
		}
	}
	if e.Revoked, err = removedWhere(ctx, a, tx, "rbac_grants", grantColumns, collectGrants,
		lockedByKeys("rbac_grants", "id", bindingOrder, "principal", "scope"), tenant, principals, scopes); err != nil {
		return ChangeEvent{}, err
	}
	short, ended, err := a.unrest(ctx, tx, tenant, actor, r, now)
	e.Shortened, e.Revoked = short, append(e.Revoked, ended...)
	return e, err
}

// lockedByKeys is SQL picking, by key, the rows of table in tenant $1 whose cols are each one of
// the text array's keys from $2 on, the first col's from $2, once they are locked in order.
func lockedByKeys(table, key, order string, cols ...string) string {
	return lockedAnyOf(table, key, order, keyedBy(table, key, cols)...)
}

// lockByKeys locks, in tx, in order, the rows lockedByKeys picks and those more selects by key, for
// a change that changes them in later statements.
func lockByKeys(ctx context.Context, tx pgx.Tx, table, key, order string, cols, more []string, args ...any) error {
	_, err := tx.Exec(ctx, lockedInOrder(table, "", order, anyOf(key, append(keyedBy(table, key, cols), more...)...)), args...)
	return err
}

// lockedAnyOf is SQL picking, by key, the rows of table any of selects picks, once they are locked
// in order.
func lockedAnyOf(table, key, order string, selects ...string) string {
	return anyOf(key, lockedInOrder(table, key, order, anyOf(key, selects...)))
}

// keyedBy is, for each of cols, byKeys of its rows by the text array's keys from $2 on, the first
// col's from $2.
func keyedBy(table, key string, cols []string) []string {
	selects := make([]string, len(cols))
	for i, col := range cols {
		selects[i] = byKeys(table, key, col, fmt.Sprintf("$%d", i+2))
	}
	return selects
}

// byKeys is SQL selecting key of the rows of table in tenant $1 whose col is one of the text array
// keys, each looked up on its own, as byKey looks them up.
func byKeys(table, key, col, keys string) string {
	return byKey(keys, table, col, key, "tenant = $1")
}

// anyOf is SQL picking, by key, the rows any of selects picks.
func anyOf(key string, selects ...string) string {
	return key + " = ANY(ARRAY(" + strings.Join(selects, " UNION ALL ") + "))"
}

// lockDenies locks, in tx, in order, the denies any of selects picks by denyKey, each looked up by
// its primary key on its own, for a change that changes them in later statements, which can then
// find them by a ctid. A deny has no column of its own that keys it, and its ctid moves as a change
// takes a principal out of its exemptions, which takes no lock of its scope's: a lock by ctid that
// waited for that change would pass over it. Matched to the denies in a semi-join instead, a plan
// can read the table whole.
func lockDenies(ctx context.Context, tx pgx.Tx, selects []string, args ...any) error {
	_, err := tx.Exec(ctx, `SELECT FROM (SELECT DISTINCT `+denyKey+` FROM (`+strings.Join(selects, " UNION ALL ")+`) u ORDER BY `+denyOrder+`) k
		CROSS JOIN LATERAL (SELECT FROM rbac_denies d
		  WHERE d.tenant = k.tenant AND d.scope_type = k.scope_type AND d.scope_id = k.scope_id AND d.id = k.id FOR UPDATE) d`, args...)
	return err
}

// denyKey is what keys a deny, its primary key, with its scope, which denyOrder sorts by: types sort
// apart from their scopes, as a type can hold '-', which sorts before ':'.
const denyKey = "tenant, scope_type, scope_id, id, scope"

// notOwnedGroups refuses, on q, changing groups from a source the host owns, which only it changes.
func (a *Authorizer) notOwnedGroups(ctx context.Context, q DB, tenant string, ids []string) error {
	if len(a.owned) == 0 {
		return nil
	}
	var id, source string
	err := q.QueryRow(ctx, `SELECT id, source FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[]) AND source = ANY($3::text[])
		ORDER BY id LIMIT 1`, tenant, ids, slices.Sorted(maps.Keys(a.owned))).Scan(&id, &source)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: group %q is from %s, which only the host changes", ErrInvalid, id, source)
}

// groupsTenant is the tenant ManageGroups is checked on, as Config.ResourceOf gives it, as
// ChangeMembers reads the groups it changes.
func (a *Authorizer) groupsTenant(ctx context.Context, tenant string) ([]Resource, error) {
	r, _, err := a.hostResource(ctx, tenant, TenantRoot(tenant))
	return []Resource{r}, err
}

// mayManageGroups checks that actor holds perm, to manage groups or their members, on each of on,
// as hostResource gives them, so a constraint, a deny or a label reading one sees what the host's
// own check of perm would: before the change's transaction, with the constraints, and again in it,
// on q, once labels is sealed. labels is what the constraints remove of the actor's label values,
// asked about on the tenant before the transaction and read back in it.
func (a *Authorizer) mayManageGroups(ctx context.Context, q DB, actor Subject, perm Permission, on []Resource, labels *constrained) error {
	if actor.Principal == (Principal{}) && len(on) > 0 {
		return &DeniedError{Permission: perm, Scope: on[0].Scope(), Reason: "an anonymous subject changes nothing"}
	}
	// On all of them in one read, as a change to the members of many groups checks each.
	aus, err := a.authorities(ctx, q, actor, on, nil)
	if err != nil {
		return err
	}
	clearance := a.labelCheck(ctx, q, labels)
	for i, r := range on {
		scope := r.Scope()
		if !labels.sealed {
			name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: perm, Subject: &actor, Resource: &r})
			if err != nil {
				return err
			}
			if name != "" {
				return &DeniedError{Permission: perm, Scope: scope, Reason: "removed by " + name}
			}
		}
		if !aus[i].may(perm, r.Type) {
			return &DeniedError{Permission: perm, Scope: scope, Reason: "the actor may not manage these groups here"}
		}
		// As a check of perm on it refuses who can't see it, read again under the change's locks, so a
		// value revoked meanwhile changes nothing.
		if err := clearance(r, perm); err != nil {
			return err
		}
	}
	return nil
}

// groupLabeled returns a group as groupOf gives it, as ChangeMembers reads the groups it changes,
// before a change's transaction, refusing an actor its label refuses, as a change to its members
// does: ManageGroups is the tenant's, but who can't see a group doesn't rename or delete it. labels
// is what mayManageGroups reads the actor's label values through, and the transaction checks the
// label again with it. Without declared labels the host isn't asked: nothing it returns is checked,
// and a host that knows no group it hasn't made yet would refuse making one.
func (a *Authorizer) groupLabeled(ctx context.Context, tenant, id string, labels *constrained, removing bool) (Resource, error) {
	if len(a.labels) == 0 {
		return Resource{Tenant: tenant, Type: GroupScope, ID: id}, nil
	}
	group, err := a.groupOf(ctx, tenant, id, removing)
	if err != nil {
		return Resource{}, err
	}
	return group, a.labelCheck(ctx, a.db, labels)(group, ManageGroups)
}

// groupOf returns a group as Config.ResourceOf gives it: with removing, as for a change that only
// takes access away from its members, one the host no longer has (ErrNotFound) as unlabeled, as a
// removal reads any scope.
func (a *Authorizer) groupOf(ctx context.Context, tenant, id string, removing bool) (Resource, error) {
	group, _, err := a.hostResource(ctx, tenant, Scope{Type: GroupScope, ID: id})
	if removing && errors.Is(err, ErrNotFound) {
		return Resource{Tenant: tenant, Type: GroupScope, ID: id}, nil
	}
	return group, err
}

// tenantLabels is what the constraints remove of actor's label values in a tenant, for
// mayManageGroups to ask before a change's transaction and read back in it.
func (a *Authorizer) tenantLabels(ctx context.Context, actor Subject, tenant string) *constrained {
	return a.constrain(ctx, actor, tenantResource(tenant))
}

// Groups lists a tenant's groups, by id. It has no limit or cursor, so what it returns grows with
// them.
func (a *Authorizer) Groups(ctx context.Context, tenant string) ([]GroupDefinition, error) {
	if !validID(tenant) {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	rows, err := a.db.Query(ctx, `SELECT `+groupColumns+` FROM rbac_groups WHERE tenant = $1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	return collectGroups(rows)
}

const groupColumns = `id, name, description, source, created_by, created_at, updated_by, updated_at`

func collectGroups(rows pgx.Rows) ([]GroupDefinition, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (GroupDefinition, error) {
		var g GroupDefinition
		var createdBy, updatedBy string
		err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Source, &createdBy, &g.CreatedAt, &updatedBy, &g.UpdatedAt)
		g.CreatedBy, g.UpdatedBy = parsePrincipal(createdBy), parsePrincipal(updatedBy)
		return g, err
	})
}

// clearsAll reports whether the actor's label values, read on q through labels, satisfy every label
// a resource can have.
func (a *Authorizer) clearsAll(ctx context.Context, q DB, labels *constrained) (bool, error) {
	h, err := labels.holding(ctx, q)
	return err == nil && h.clearsAll(), err
}

// stillClearsAll refuses, read on q in a change's transaction, a change that found the actor's
// label values satisfying every label before it, which no longer do.
func (a *Authorizer) stillClearsAll(ctx context.Context, q DB, labels *constrained) error {
	all, err := a.clearsAll(ctx, q, labels)
	if err != nil {
		return err
	}
	if !all {
		return fmt.Errorf("%w: the actor's label values changed while this change waited; try again", ErrConflict)
	}
	return nil
}

// groupKey is the scope key of a group, which changes to it lock.
func groupKey(id string) string { return Scope{Type: GroupScope, ID: id}.Key() }

func groupPrincipal(id string) Principal { return Principal{Kind: Group, ID: id} }

// nestingKey is a lock a change taking it holds alone among those changing which groups are in
// which in a tenant, so two can't make a cycle between them, nor a chain too deep. It is no
// scope's key, as those all have a ':'.
const nestingKey = "nesting"

// checkMember returns why a member can't be stored at now, beyond what is stored already.
func (a *Authorizer) checkMember(m Member, now time.Time) error {
	var errs []string
	if !validGroupID(m.Group) {
		errs = append(errs, "the group is not valid")
	}
	switch p := m.Principal; {
	case p.Kind == Group && !validGroupID(p.ID):
		errs = append(errs, "the member group is not valid")
	case p.Kind == Group && p.ID == m.Group:
		errs = append(errs, "a group can't be in itself")
	case p.Kind != Group && (!a.acts(p.Kind) || !validID(p.ID)):
		errs = append(errs, "a member is an identity, a user or a declared kind, or a group")
	}
	errs = append(errs, checkKept(m.Source, m.ExpiresAt, m.Note, now)...)
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s in group %q: %s", ErrInvalid, m.Principal.key(), m.Group, strings.Join(errs, "; "))
	}
	return nil
}

// keyed reports whether m names a member as one could be stored, by its group, principal and
// source, as a removal names it: of any kind, as one the host no longer declares is still removed.
func (m Member) keyed() bool {
	if !validGroupID(m.Group) || !validSource(m.Source) {
		return false
	}
	if m.Principal.Kind == Group {
		return validGroupID(m.Principal.ID)
	}
	return validName(string(m.Principal.Kind)) && validID(m.Principal.ID)
}

// keyedAll returns why not every member is keyed.
func keyedAll(members []Member) error {
	if i := slices.IndexFunc(members, func(m Member) bool { return !m.keyed() }); i >= 0 {
		return fmt.Errorf("%w: %q in group %q is not a valid member", ErrInvalid, members[i].Principal.key(), members[i].Group)
	}
	return nil
}

// ImportMembers adds members to a tenant's groups, from their sources, or changes their expiry or
// note, as actor: the host's own write, as for a directory it syncs from. A member identity is a
// member or guest of the tenant, and a member group exists; nesting a group can't make one contain
// itself, nor a chain of more than MaxGroupDepth groups; and a principal is in a group at most
// MaxPlacesInGroup times, and in at most MaxGroupsOfPrincipal groups. Config.ValidateGrant is asked
// about each grant and eligibility a member gains, as with ChangeMembers, so about none of a place
// made to end sooner.
func (a *Authorizer) ImportMembers(ctx context.Context, actor Principal, tenant string, members []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "ImportMembers")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	if len(members) > MaxBindings {
		return fmt.Errorf("%w: an import stores at most %d members", ErrInvalid, MaxBindings)
	}
	set, err := a.memberSet(members)
	if err != nil {
		return err
	}
	rc, err := a.reachOf(ctx, a.db, tenant, set, nil)
	if err != nil {
		return err
	}
	stand, err := a.askMemberships(ctx, Subject{Principal: actor}, tenant, set, rc)
	if err != nil {
		return err
	}
	scopes, principals := memberLocks(set)
	principals = append(principals, rc.locks()...)
	return a.inTxReaching(ctx, tenant, actor, "ImportMembers", func(tx pgx.Tx) (ChangeEvent, []string, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, nil, err
		}
		locked, err := a.stillReached(ctx, tx, tenant, set, nil, rc, true)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		if err := a.stillStanding(ctx, tx, tenant, stand); err != nil {
			return ChangeEvent{}, nil, err
		}
		now := a.cfg.Now()
		r, err := a.restingIn(ctx, tx, tenant, set, expiring(set), now)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		e := ChangeEvent{}
		if e.Joined, err = a.join(ctx, tx, tenant, actor, set); err != nil {
			return ChangeEvent{}, nil, err
		}
		e.Shortened, e.Revoked, err = a.unrest(ctx, tx, tenant, actor, r, now)
		return e, locked.joining(e.Joined), err
	})
}

// memberGroups returns the groups members join, sorted, each once.
func memberGroups(members []Member) []string {
	ids := map[string]bool{}
	for _, m := range members {
		ids[m.Group] = true
	}
	return slices.Sorted(maps.Keys(ids))
}

// memberSet checks members to add and returns them sorted, each group, principal and source once,
// the last given.
func (a *Authorizer) memberSet(members []Member) ([]Member, error) {
	now := a.cfg.Now()
	byKey := map[string]Member{}
	var errs []error
	for _, m := range members {
		m.ExpiresAt = stored(m.ExpiresAt)
		errs = append(errs, a.checkMember(m, now))
		byKey[memberKey(m)] = m
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return slices.SortedFunc(maps.Values(byKey), func(x, y Member) int { return strings.Compare(memberKey(x), memberKey(y)) }), nil
}

// memberLocks returns the scope and principal locks a change to members takes: each group's, the
// nesting lock when one nests groups, and each member's.
func memberLocks(members []Member) (scopes, principals []string) {
	ss, ps := map[string]bool{}, map[string]bool{}
	for _, m := range members {
		ss[groupKey(m.Group)] = true
		ps[m.Principal.key()] = true
		if m.Principal.Kind == Group {
			ss[nestingKey] = true
		}
	}
	return slices.Sorted(maps.Keys(ss)), slices.Sorted(maps.Keys(ps))
}

// join stores members memberSet checked, under the change's locks, and returns those it added or
// changed: refusing an identity that isn't a member or guest of the tenant, a group that doesn't
// exist, and nesting that makes a cycle or too long a chain.
func (a *Authorizer) join(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, set []Member) ([]Member, error) {
	groups, identities := map[string]bool{}, map[string]bool{}
	var nested []Member
	for _, m := range set {
		groups[m.Group] = true
		if m.Principal.Kind == Group {
			groups[m.Principal.ID] = true
			nested = append(nested, m)
		} else {
			identities[m.Principal.key()] = true
		}
	}
	if err := a.membersCanJoin(ctx, tx, tenant, slices.Sorted(maps.Keys(groups)), slices.Sorted(maps.Keys(identities))); err != nil {
		return nil, err
	}
	n := len(set)
	ids, kinds, pids, sources, notes := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	expires := make([]pgtype.Timestamptz, n)
	for i, m := range set {
		ids[i], kinds[i], pids[i], sources[i], notes[i] = m.Group, string(m.Principal.Kind), m.Principal.ID, m.Source, m.Note
		expires[i] = pgtype.Timestamptz{Time: m.ExpiresAt, Valid: !m.ExpiresAt.IsZero()}
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO rbac_members AS m (tenant, group_id, principal_kind, principal_id, source, expires_at, note, created_by, updated_by)
		SELECT $1, g, k, i, s, e, n, $8, $8 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::text[])
		  AS t(g, k, i, s, e, n)
		ON CONFLICT (tenant, group_id, principal, source) DO UPDATE SET expires_at = EXCLUDED.expires_at, note = EXCLUDED.note,
		  updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE (m.expires_at, m.note) IS DISTINCT FROM (EXCLUDED.expires_at, EXCLUDED.note)
		RETURNING `+memberColumns,
		tenant, ids, kinds, pids, sources, expires, notes, actorKey(actor))
	if err != nil {
		return nil, err
	}
	joined, err := collectMembers(rows)
	if err != nil {
		return nil, err
	}
	if err := a.placesBounded(ctx, tx, tenant, joined); err != nil {
		return nil, err
	}
	if err := a.groupsBounded(ctx, tx, tenant, joined); err != nil {
		return nil, err
	}
	return joined, a.nestable(ctx, tx, tenant, nested)
}

// groupsBounded refuses places just stored that leave a principal in more than MaxGroupsOfPrincipal
// groups: under the change's locks, which every change to the principal's places takes, once they
// are stored, those in force the change didn't touch included. Those from each source the host
// owns count apart, as placesBounded counts, so neither the tenant's admins nor the host can fill
// the bound to keep the other's from being made.
func (a *Authorizer) groupsBounded(ctx context.Context, tx pgx.Tx, tenant string, stored []Member) error {
	if len(stored) == 0 {
		return nil
	}
	principals, sources := make([]string, len(stored)), make([]string, len(stored))
	for i, m := range stored {
		principals[i], sources[i] = m.Principal.key(), m.Source
	}
	// Each principal's places by source, the others' together, counted on its own, as byKey reads
	// its rows.
	rows, err := tx.Query(ctx, `
		SELECT t.p, t.s FROM (SELECT DISTINCT p, CASE WHEN s = ANY($4::text[]) THEN s ELSE '' END
		  FROM unnest($2::text[], $3::text[]) AS u(p, s)) AS t(p, s) CROSS JOIN LATERAL (
		  SELECT count(DISTINCT group_id) AS n FROM rbac_members WHERE tenant = $1 AND principal = t.p
		    AND (expires_at IS NULL OR expires_at > $5)
		    AND CASE WHEN t.s = '' THEN (source = ANY($4::text[])) IS NOT TRUE ELSE source = t.s END) m
		WHERE m.n > $6
		ORDER BY t.p COLLATE "C", t.s COLLATE "C"`,
		tenant, principals, sources, slices.Sorted(maps.Keys(a.owned)), a.cfg.Now(), MaxGroupsOfPrincipal)
	if err != nil {
		return err
	}
	over, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (error, error) {
		var principal, source string
		if err := row.Scan(&principal, &source); err != nil {
			return nil, err
		}
		if source != "" {
			return fmt.Errorf("%w: %s is in at most %d groups from %s", ErrInvalid, principal, MaxGroupsOfPrincipal, source), nil
		}
		return fmt.Errorf("%w: %s is in at most %d groups", ErrInvalid, principal, MaxGroupsOfPrincipal), nil
	})
	if err != nil {
		return err
	}
	return errors.Join(over...)
}

// placesBounded refuses places just stored that leave a principal in their group more than
// MaxPlacesInGroup times, counting as bounded counts grants: under the change's locks, once they
// are stored, those in force the change didn't touch included. A source the host owns gives one
// place at most, so only the others' count, and neither the tenant's admins nor the host can fill
// the bound to keep the other's from being made.
func (a *Authorizer) placesBounded(ctx context.Context, tx pgx.Tx, tenant string, stored []Member) error {
	var groups, principals []string
	for _, m := range stored {
		if !a.owned[m.Source] {
			groups, principals = append(groups, m.Group), append(principals, m.Principal.key())
		}
	}
	if len(groups) == 0 {
		return nil
	}
	// Each counted on its own, as byKey reads its rows.
	rows, err := tx.Query(ctx, `
		SELECT t.g, t.p FROM (SELECT DISTINCT * FROM unnest($2::text[], $3::text[])) AS t(g, p) CROSS JOIN LATERAL (
		  SELECT count(*) AS n FROM rbac_members WHERE tenant = $1 AND group_id = t.g AND principal = t.p
		    AND (source = ANY($4::text[])) IS NOT TRUE AND (expires_at IS NULL OR expires_at > $5)) m
		WHERE m.n > $6
		ORDER BY t.g COLLATE "C", t.p COLLATE "C"`,
		tenant, groups, principals, slices.Sorted(maps.Keys(a.owned)), a.cfg.Now(), MaxPlacesInGroup)
	if err != nil {
		return err
	}
	over, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (error, error) {
		var group, principal string
		if err := row.Scan(&group, &principal); err != nil {
			return nil, err
		}
		return fmt.Errorf("%w: %s is in group %q at most %d times, by source", ErrInvalid, principal, group, MaxPlacesInGroup), nil
	})
	if err != nil {
		return err
	}
	return errors.Join(over...)
}

// ChangeMembers adds members to a tenant's groups, or changes their expiry or note, and removes
// others, each by its group, principal and source, as actor, in one transaction, with GroupMembers
// on each group's scope, not removed by a constraint. A group's members hold what it holds, so a
// change to them is checked as the changes to access it makes, each on its scope as Apply and
// SetDeny check one there. An added member gains the grants and eligibilities of the group and the
// groups it is in, those the same change nests it in too, which the actor must be able to grant to
// it, a grant until the member's place or the grant ends and an eligibility for good, and
// Config.ValidateGrant is asked about each as the member's (ViaMembership); it approves the
// activations of the eligibilities those approve, which the actor must be able to set; and it is
// exempt from the denies those are exempt from, as a removed member is from the denies those name,
// which the actor must be able to set. A removed member loses the rest, which only the label of
// each scope it is on refuses the actor, as Apply refuses a revoke there; a place made to end
// sooner gains nothing: it is a removal then, checked as one now. Each group changed, and each
// scope reached, is checked as Config.ResourceOf returns it. Members from a source the host owns,
// and the members of a group from one, only the host changes, and what ImportMembers refuses, this
// does.
func (a *Authorizer) ChangeMembers(ctx context.Context, actor Subject, tenant string, add, remove []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "ChangeMembers")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	if len(add)+len(remove) == 0 {
		return nil
	}
	if len(add)+len(remove) > MaxBindings {
		return fmt.Errorf("%w: a change names at most %d members", ErrInvalid, MaxBindings)
	}
	if err := keyedAll(remove); err != nil {
		return err
	}
	set, err := a.memberSet(add)
	if err != nil {
		return err
	}
	var owned []error
	for _, m := range slices.Concat(set, remove) {
		if a.owned[m.Source] {
			owned = append(owned, fmt.Errorf("%w: %s in group %q is from %s, which only the host changes", ErrInvalid, m.Principal.key(), m.Group, m.Source))
		}
	}
	if err := errors.Join(owned...); err != nil {
		return err
	}
	groups, adding := memberGroups(slices.Concat(set, remove)), memberGroups(set)
	// As Config.ResourceOf gives them, so a constraint or deny reading a group's attributes sees
	// what the host's own check of GroupMembers would; a group the change only removes members from,
	// as a removal reads it.
	targets := make([]Resource, len(groups))
	for i, g := range groups {
		_, adds := slices.BinarySearch(adding, g)
		if targets[i], err = a.groupOf(ctx, tenant, g, !adds); err != nil {
			return err
		}
	}
	labels := a.tenantLabels(ctx, actor, tenant)
	if err := a.mayManageGroups(ctx, a.db, actor, GroupMembers, targets, labels); err != nil {
		return err
	}
	// Refused before the host is asked about what the members would gain, and again under the locks.
	if err := a.notOwnedGroups(ctx, a.db, tenant, groups); err != nil {
		return err
	}
	rc, err := a.reachOf(ctx, a.db, tenant, set, remove)
	if err != nil {
		return err
	}
	checks, err := a.mayReach(ctx, actor, tenant, set, remove, rc, labels)
	if err != nil {
		return err
	}
	stand, err := a.askMemberships(ctx, actor, tenant, set, rc)
	if err != nil {
		return err
	}
	scopes, principals := memberLocks(slices.Concat(set, remove))
	principals = append(principals, rc.locks()...)
	return a.inTxReaching(ctx, tenant, actor.Principal, "ChangeMembers", func(tx pgx.Tx) (ChangeEvent, []string, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, nil, err
		}
		locked, err := a.stillReached(ctx, tx, tenant, set, remove, rc, false)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		if err := a.stillStanding(ctx, tx, tenant, stand); err != nil {
			return ChangeEvent{}, nil, err
		}
		// The host's groups only the host changes, members and all.
		if err := a.notOwnedGroups(ctx, tx, tenant, groups); err != nil {
			return ChangeEvent{}, nil, err
		}
		labels.seal()
		if err := a.mayManageGroups(ctx, tx, actor, GroupMembers, targets, labels); err != nil {
			return ChangeEvent{}, nil, err
		}
		if err := a.mayReachAgain(ctx, tx, actor, checks, labels); err != nil {
			return ChangeEvent{}, nil, err
		}
		now := a.cfg.Now()
		r, err := a.restingIn(ctx, tx, tenant, slices.Concat(remove, set), slices.Concat(remove, expiring(set)), now)
		if err != nil {
			return ChangeEvent{}, nil, err
		}
		var e ChangeEvent
		if len(remove) > 0 {
			if e.Left, err = a.leave(ctx, tx, tenant, remove); err != nil {
				return ChangeEvent{}, nil, err
			}
		}
		if len(set) > 0 {
			if e.Joined, err = a.join(ctx, tx, tenant, actor.Principal, set); err != nil {
				return ChangeEvent{}, nil, err
			}
		}
		e.Shortened, e.Revoked, err = a.unrest(ctx, tx, tenant, actor.Principal, r, now)
		return e, locked.joining(e.Joined), err
	})
}

// expiring is the members of set with an end, which may end a place in force sooner.
func expiring(set []Member) []Member {
	return slices.DeleteFunc(slices.Clone(set), func(m Member) bool { return m.ExpiresAt.IsZero() })
}

// reach is what a change to the members of groups changes for them beyond being in them: what
// the groups and those they are in, up, hold, which an added member gains; the eligibilities they
// approve, whose activations it then approves; and the denies that name or exempt them.
type reach struct {
	// up is each group's key and those of the groups it is in, by group, as the change will store
	// them: so with the nestings it adds too. stored is as they are stored, which a member leaving
	// a group leaves: not those the change nests the group in, which it was never in.
	up, stored map[string]map[string]bool
	held       []revalidation
	approving  []approving
	denies     []Deny
	// ending is the members added, by memberKey, that end a membership in force sooner than it
	// would: they leave the group then, as removing them does now.
	ending map[string]bool
	// leaves is those of them and of the members removed, by memberKey, that leave their group: a
	// place in force ends, and no other of theirs there, from another source, keeps them in it as
	// long as it would have.
	leaves map[string]bool
	// labeled is whether the host declares labels, which alone check what a member leaving loses:
	// without them, a grant made to its group meanwhile changes nothing the change checked.
	labeled bool
}

// memberKey is what makes a member one member: its group, principal and source.
func memberKey(m Member) string { return m.Group + "\x00" + m.Principal.key() + "\x00" + m.Source }

// approving is an eligibility a group approves the activations of.
type approving struct {
	revalidation
	approvers []Principal
}

// reachOf reads, on q, what adding add and removing remove reaches, in force at now, which of add
// end a membership sooner and which members leave their groups: of what the groups hold, approve
// and are named or exempt in, all a change checks.
func (a *Authorizer) reachOf(ctx context.Context, q DB, tenant string, add, remove []Member) (reach, error) {
	r := reach{up: map[string]map[string]bool{}, labeled: len(a.labels) > 0}
	groups := memberGroups(slices.Concat(add, remove))
	if len(groups) == 0 {
		return r, nil
	}
	now := a.cfg.Now()
	rows, err := q.Query(ctx, `
		WITH RECURSIVE up(root, id) AS (
		  SELECT g, g COLLATE "C" FROM unnest($2::text[]) AS g
		  UNION
		  SELECT u.root, m.group_id FROM up u `+groupsAbove("u.id", "$3", "group_id")+`
		)
		SELECT root, id FROM up`, tenant, groups, now)
	if err != nil {
		return reach{}, err
	}
	var root, id string
	reached := map[string]bool{}
	if _, err := pgx.ForEachRow(rows, []any{&root, &id}, func() error {
		k := groupPrincipal(id).key()
		if r.up[root] == nil {
			r.up[root] = map[string]bool{}
		}
		r.up[root][k], reached[k] = true, true
		return nil
	}); err != nil {
		return reach{}, err
	}
	r.stored, r.up = r.up, r.nested(add)
	keys := slices.Sorted(maps.Keys(reached))
	if r.ending, r.leaves, err = a.placesLeft(ctx, q, tenant, add, remove); err != nil {
		return reach{}, err
	}
	// Without declared labels, a member leaving loses nothing a change checks but the denies naming
	// its groups, which then no longer bind it: where none gains, as none is added but to end a place
	// sooner, those alone are read, not what the groups hold.
	if !r.labeled && len(r.gaining(add)) == 0 {
		rows, err = q.Query(ctx, `SELECT `+denyColumns+` FROM rbac_denies WHERE `+naming("principals", "$2")+` ORDER BY scope, id`, tenant, keys)
		if err != nil {
			return reach{}, err
		}
		if r.denies, err = collectDenies(rows); err != nil {
			return reach{}, err
		}
		return r, nil
	}
	rows, err = q.Query(ctx, `SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3) ORDER BY id`, tenant, keys, now)
	if err != nil {
		return reach{}, err
	}
	grants, err := collectGrants(rows)
	if err != nil {
		return reach{}, err
	}
	// The groups' eligibilities by principal, a group at a time, and those they approve, each once.
	rows, err = q.Query(ctx, `SELECT `+eligibilityColumns+` FROM (
		  `+byKey("$2", "rbac_eligibilities", "principal", eligibilityColumns+", scope, principal",
		"tenant = $1 AND (expires_at IS NULL OR expires_at > $3)")+`
		  UNION ALL
		  SELECT `+eligibilityColumns+`, scope, principal FROM rbac_eligibilities
		  WHERE `+naming("approvers", "$2")+` AND principal <> ALL($2::text[]) AND (expires_at IS NULL OR expires_at > $3)) e
		ORDER BY scope, principal, role`, tenant, keys, now)
	if err != nil {
		return reach{}, err
	}
	eligible, err := collectEligibilities(rows)
	if err != nil {
		return reach{}, err
	}
	rows, err = q.Query(ctx, `SELECT `+denyColumns+` FROM rbac_denies
		WHERE `+naming("principals", "$2")+` OR `+naming("exempt", "$2")+` ORDER BY scope, id`, tenant, keys)
	if err != nil {
		return reach{}, err
	}
	if r.denies, err = collectDenies(rows); err != nil {
		return reach{}, err
	}
	var ids []Role
	for _, g := range grants {
		ids = append(ids, g.Role)
	}
	for _, e := range eligible {
		ids = append(ids, e.Role)
	}
	roles, err := a.book(ctx, q, tenant, ids)
	if err != nil {
		return reach{}, err
	}
	// A role no longer in the catalog gives nothing.
	for _, g := range grants {
		if def, ok := roles.role(g.Role); ok {
			r.held = append(r.held, revalidation{scope: g.Scope, binding: g.Binding, role: def})
		}
	}
	for _, e := range eligible {
		def, ok := roles.role(e.Role)
		if !ok {
			continue
		}
		v := revalidation{scope: e.Scope, binding: e.binding(), role: def, eligibility: true}
		if reached[e.Principal.key()] {
			r.held = append(r.held, v)
		}
		if slices.ContainsFunc(e.Approvers, func(p Principal) bool { return reached[p.key()] }) {
			r.approving = append(r.approving, approving{v, e.Approvers})
		}
	}
	return r, nil
}

// naming is SQL for whether the array of keys col of a row holds one of the keys in the array keys
// in the tenant $1: as the GIN indexes on rbac_tenant_keys find them, with no other condition on
// the tenant, which a generic plan, costing it as an average tenant's few rows, would read every row
// of the tenant by.
func naming(col, keys string) string { return namingIn("$1", col, keys) }

// namingIn is naming in the tenant SQL gives, as text.
func namingIn(tenant, col, keys string) string {
	return fmt.Sprintf("rbac_tenant_keys(tenant, %s) && rbac_tenant_keys(%s, %s::text[])", col, tenant, keys)
}

// nested is each group's up extended over the groups add nests in others, as the change will store
// them: a member it adds below one reaches what the group it nests that one in holds, which as
// stored it doesn't yet, and the host would be asked about it only for the nested group, without
// the member. Each group a nesting is in, its outer group's up, is read already, as it is a group
// the change changes.
func (r reach) nested(add []Member) map[string]map[string]bool {
	outer := map[string][]string{}
	for _, m := range add {
		if m.Principal.Kind == Group {
			outer[m.Principal.key()] = append(outer[m.Principal.key()], m.Group)
		}
	}
	if len(outer) == 0 {
		return r.up
	}
	nested := make(map[string]map[string]bool, len(r.up))
	for group, stored := range r.up {
		up := maps.Clone(stored)
		nested[group] = up
		next := slices.Collect(maps.Keys(up))
		for len(next) > 0 {
			k := next[len(next)-1]
			next = next[:len(next)-1]
			for _, g := range outer[k] {
				for o := range r.up[g] {
					if !up[o] {
						up[o] = true
						next = append(next, o)
					}
				}
			}
		}
	}
	return nested
}

// placesLeft reads, on q, the places in force in their groups of the principals add and remove
// name, and returns, by memberKey, those of add that end a place sooner than it would end
// (reach.ending), and those of them and of remove that leave their group (reach.leaves): whose
// place in force ends, and that keep no other there, from another source, as long as that place
// would have lasted, as the change leaves the others.
func (a *Authorizer) placesLeft(ctx context.Context, q DB, tenant string, add, remove []Member) (ending, leaves map[string]bool, err error) {
	type pair struct{ group, principal string }
	pairOf := func(m Member) pair { return pair{m.Group, m.Principal.key()} }
	pairs := map[pair]bool{}
	for _, m := range add {
		if !m.ExpiresAt.IsZero() {
			pairs[pairOf(m)] = true
		}
	}
	for _, m := range remove {
		pairs[pairOf(m)] = true
	}
	if len(pairs) == 0 {
		return nil, nil, nil
	}
	var groups, principals []string
	for p := range pairs {
		groups, principals = append(groups, p.group), append(principals, p.principal)
	}
	now := a.cfg.Now()
	// Each pair's found on its own, as leave finds its rows.
	rows, err := q.Query(ctx, `
		SELECT m.group_id, m.principal, m.source, m.expires_at FROM unnest($2::text[], $3::text[]) AS t(g, p) CROSS JOIN LATERAL (
		  SELECT group_id, principal, source, expires_at FROM rbac_members WHERE tenant = $1 AND group_id = t.g AND principal = t.p
		    AND (expires_at IS NULL OR expires_at > $4) OFFSET 0) m`,
		tenant, groups, principals, now)
	if err != nil {
		return nil, nil, err
	}
	// Each pair's places, by source, as the change leaves them: until when, zero for never.
	places := map[pair]map[string]time.Time{}
	var group, principal, source string
	var expires *time.Time
	if _, err := pgx.ForEachRow(rows, []any{&group, &principal, &source, &expires}, func() error {
		p := pair{group, principal}
		if places[p] == nil {
			places[p] = map[string]time.Time{}
		}
		places[p][source] = time.Time{}
		if expires != nil {
			places[p][source] = *expires
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	stored := maps.Clone(places)
	for p, ps := range stored {
		stored[p] = maps.Clone(ps)
	}
	for _, m := range add {
		if places[pairOf(m)] == nil {
			places[pairOf(m)] = map[string]time.Time{}
		}
		places[pairOf(m)][m.Source] = m.ExpiresAt
	}
	for _, m := range remove {
		delete(places[pairOf(m)], m.Source)
	}
	// keeps reports whether another of m's places keeps it in its group until until, zero for never:
	// as long as the place the change ends sooner would have, so its member's time there is as it was.
	keeps := func(m Member, until time.Time) bool {
		for source, end := range places[pairOf(m)] {
			if source != m.Source && (end.IsZero() || !until.IsZero() && !end.Before(until)) {
				return true
			}
		}
		return false
	}
	ending, leaves = map[string]bool{}, map[string]bool{}
	for _, m := range add {
		was, ok := stored[pairOf(m)][m.Source]
		if m.ExpiresAt.IsZero() || !ok || !was.IsZero() && !was.After(m.ExpiresAt) {
			continue
		}
		ending[memberKey(m)] = true
		if !keeps(m, was) {
			leaves[memberKey(m)] = true
		}
	}
	for _, m := range remove {
		if was, ok := stored[pairOf(m)][m.Source]; ok && !keeps(m, was) {
			leaves[memberKey(m)] = true
		}
	}
	return ending, leaves, nil
}

// gaining is the members added that gain what their groups hold: all but those added to end sooner,
// which gain nothing.
func (r reach) gaining(add []Member) []Member {
	if len(r.ending) == 0 {
		return add
	}
	var out []Member
	for _, m := range add {
		if !r.ending[memberKey(m)] {
			out = append(out, m)
		}
	}
	return out
}

// joining is the keys of the principals of joined, the members a change stored, whose places
// widen what they hold, which their exclusive values are checked for: all but those that only end
// a place in force sooner, a removal then.
func (r reach) joining(joined []Member) []string {
	var keys []string
	for _, m := range joined {
		if !r.ending[memberKey(m)] {
			keys = append(keys, m.Principal.key())
		}
	}
	return keys
}

// leaving is the members that leave their groups: those removed, and those added to end sooner,
// that no other place there keeps in it.
func (r reach) leaving(add, remove []Member) []Member {
	var out []Member
	for _, m := range slices.Concat(remove, add) {
		if r.leaves[memberKey(m)] {
			out = append(out, m)
		}
	}
	return out
}

// in reports whether ps names group or a group it is in, by up.
func in(up map[string]map[string]bool, group string, ps ...Principal) bool {
	return slices.ContainsFunc(ps, func(p Principal) bool { return up[group][p.key()] })
}

// heldBy is what a member of group gains: the grants and eligibilities of it and those it is in.
func (r reach) heldBy(group string) []revalidation {
	var vs []revalidation
	for _, v := range r.held {
		if in(r.up, group, v.binding.Principal) {
			vs = append(vs, v)
		}
	}
	return vs
}

// approvedBy is the eligibilities whose activations a member of group approves.
func (r reach) approvedBy(group string) []revalidation {
	var vs []revalidation
	for _, v := range r.approving {
		if in(r.up, group, v.approvers...) {
			vs = append(vs, v.revalidation)
		}
	}
	return vs
}

// lifted is the denies that no longer bind a member that joins group, exempting it or one it will
// be in, or with leaving, that leaves it, naming it or one it is in.
func (r reach) lifted(group string, leaving bool) []Deny {
	var ds []Deny
	for _, d := range r.denies {
		if !leaving && in(r.up, group, d.Exempt...) || leaving && in(r.stored, group, d.Principals...) {
			ds = append(ds, d)
		}
	}
	return ds
}

// leftBy is the scopes a member leaving group loses access on, as stored: those of the grants and
// eligibilities of it and those it is in, of the eligibilities they approve, and of the denies that
// exempt them; none where no label checks them.
func (r reach) leftBy(group string) []Scope {
	if !r.labeled {
		return nil
	}
	var ss []Scope
	for _, v := range r.held {
		if in(r.stored, group, v.binding.Principal) {
			ss = append(ss, v.scope)
		}
	}
	for _, v := range r.approving {
		if in(r.stored, group, v.approvers...) {
			ss = append(ss, v.scope)
		}
	}
	for _, d := range r.denies {
		if in(r.stored, group, d.Exempt...) {
			ss = append(ss, d.Scope)
		}
	}
	return ss
}

// locks are the principal locks of every group the change reaches: a grant, an eligibility or a
// deny naming one takes its lock, and so does nesting it in another group.
func (r reach) locks() []string {
	keys := map[string]bool{}
	for _, up := range r.up {
		for k := range up {
			keys[k] = true
		}
	}
	return slices.Sorted(maps.Keys(keys))
}

// reachKey is one change to access a change to members makes for a member of group: a grant or
// eligibility gained, or one whose activations it approves, a deny on a scope lifted, or access on
// a scope left.
type reachKey struct {
	group    string
	approves bool
	gained   revalidated
	deny     Scope
	left     Scope
}

// footprint is the changes to access adding add and removing remove make, with the role of each
// grant or eligibility; with gains, only the grants and eligibilities added members gain.
func (r reach) footprint(add, remove []Member, gains bool) map[reachKey]RoleDefinition {
	f := map[reachKey]RoleDefinition{}
	for _, m := range r.gaining(add) {
		for _, v := range r.heldBy(m.Group) {
			f[reachKey{group: m.Group, gained: v.key()}] = v.role
		}
		if gains {
			continue
		}
		for _, v := range r.approvedBy(m.Group) {
			f[reachKey{group: m.Group, approves: true, gained: v.key()}] = v.role
		}
		for _, d := range r.lifted(m.Group, false) {
			f[reachKey{group: m.Group, deny: d.Scope}] = RoleDefinition{}
		}
	}
	if gains {
		return f
	}
	for _, m := range r.leaving(add, remove) {
		for _, d := range r.lifted(m.Group, true) {
			f[reachKey{group: m.Group, deny: d.Scope}] = RoleDefinition{}
		}
		for _, s := range r.leftBy(m.Group) {
			f[reachKey{group: m.Group, left: s}] = RoleDefinition{}
		}
	}
	return f
}

// stillReached refuses, under a change's locks, a change to members that now makes a change to
// access it didn't when it was checked and the host asked about it before the transaction, or one
// of a role widened since, or that reaches a group it didn't then. With gains, as for the host's
// write, which is checked only as the host is asked about what members gain, it compares only
// those. It returns what the change reaches under the locks.
func (a *Authorizer) stillReached(ctx context.Context, tx pgx.Tx, tenant string, add, remove []Member, was reach, gains bool) (reach, error) {
	now, err := a.reachOf(ctx, tx, tenant, add, remove)
	if err != nil {
		return reach{}, err
	}
	// A group nested meanwhile above one the change reaches is one whose lock it doesn't hold, so
	// a grant to it could commit without the host asked about what the members gain.
	locked := was.locks()
	for _, k := range now.locks() {
		if _, ok := slices.BinarySearch(locked, k); !ok {
			return reach{}, fmt.Errorf("%w: the groups changed are now in %s, which this change doesn't lock; try again", ErrConflict, k)
		}
	}
	before := was.footprint(add, remove, gains)
	for k, role := range now.footprint(add, remove, gains) {
		if old, ok := before[k]; !ok || widens(old, role) {
			return reach{}, fmt.Errorf("%w: what group %q holds changed while this change waited for it; try again", ErrConflict, k.group)
		}
	}
	return now, nil
}

// as is v, a group's grant or eligibility, as the one m gains by joining it or a group in it, as
// the host is asked about it: until the sooner of its end and m's.
func (v revalidation) as(m Member) Binding {
	b := v.binding
	b.ID, b.Principal = "", m.Principal
	if !m.ExpiresAt.IsZero() && (b.ExpiresAt.IsZero() || m.ExpiresAt.Before(b.ExpiresAt)) {
		b.ExpiresAt = m.ExpiresAt
	}
	return b
}

// askMemberships asks Config.ValidateGrant, before a change's transaction, about each grant and
// eligibility each member set adds gains, as the member's, and returns the standing of the members
// it asked about, which the answers rest on.
func (a *Authorizer) askMemberships(ctx context.Context, actor Subject, tenant string, set []Member, rc reach) (standing, error) {
	gaining := rc.gaining(set)
	var asked []Principal
	for _, m := range gaining {
		if len(rc.heldBy(m.Group)) > 0 {
			asked = append(asked, m.Principal)
		}
	}
	stand, err := a.stand(ctx, a.db, tenant, asked)
	if err != nil {
		return standing{}, err
	}
	var refused []error
	for _, m := range gaining {
		for _, v := range rc.heldBy(m.Group) {
			roles := book{builtin: a.roles, custom: map[Role]RoleDefinition{v.role.ID: v.role}}
			bad, err := a.allowed(ctx, roles, actor, ViaMembership, tenant, v.scope, v.as(m))
			if err != nil {
				return standing{}, err
			}
			refused = append(refused, bad...)
		}
	}
	return stand, errors.Join(refused...)
}

// reachCheck is what a change to members is checked as on one scope it reaches: the grants it
// amounts to there, whether it lifts a deny there, and whether a member leaving loses access there,
// with what the transaction checks again.
type reachCheck struct {
	on     Resource
	grants []Binding
	denies bool
	leaves bool
	// cleared is set where only a member leaving is checked, by the label alone, and the actor's
	// label values satisfied every label, so the host wasn't asked: they must still.
	cleared bool
	// cs and ds are the constraints' answers on granting and on lifting denies there.
	cs, ds *constrained
}

// mayReach checks, before ChangeMembers' transaction, that actor may make each change to access a
// change to members makes, by scope: grant each grant and eligibility an added member gains, as
// Apply would; set each eligibility it would approve; set each deny lifted for a member; and take
// away what a member leaving loses, which only a scope's label refuses, as Apply refuses a revoke
// there. The actor's label values are read through labels.
func (a *Authorizer) mayReach(ctx context.Context, actor Subject, tenant string, add, remove []Member, rc reach, labels *constrained) ([]*reachCheck, error) {
	byScope := map[Scope]*reachCheck{}
	at := func(s Scope) *reachCheck {
		if byScope[s] == nil {
			byScope[s] = &reachCheck{}
		}
		return byScope[s]
	}
	// One no one could make there now, as a catalog change can leave, Apply would refuse rather
	// than check, so it is refused here too.
	stale := func(v revalidation) error {
		if a.grantableOn(v.role, v.scope.Type) {
			return nil
		}
		return fmt.Errorf("%w: %s holds %s on %s, which can't be granted there now: revoke it first", ErrInvalid, v.binding.Principal.key(), v.role.ID, v.scope.Key())
	}
	for _, m := range rc.gaining(add) {
		for _, v := range rc.heldBy(m.Group) {
			if err := stale(v); err != nil {
				return nil, err
			}
			b := v.as(m)
			if v.eligibility {
				b = handedOn(b)
			}
			c := at(v.scope)
			c.grants = append(c.grants, b)
		}
		for _, v := range rc.approvedBy(m.Group) {
			if err := stale(v); err != nil {
				return nil, err
			}
			c := at(v.scope)
			c.grants = append(c.grants, handedOn(v.binding))
		}
		for _, d := range rc.lifted(m.Group, false) {
			at(d.Scope).denies = true
		}
	}
	for _, m := range rc.leaving(add, remove) {
		for _, d := range rc.lifted(m.Group, true) {
			at(d.Scope).denies = true
		}
		for _, s := range rc.leftBy(m.Group) {
			at(s).leaves = true
		}
	}
	// Each as Config.ResourceOf gives it, and then the actor's authority on all of them in one read,
	// so a group with access on many scopes doesn't cost a read on each. Where only its label checks
	// a scope, the host is asked about it only if a label could refuse the actor, and one it no
	// longer has, as for a revoke there, has none.
	var cleared *bool
	var checks []*reachCheck
	for _, s := range slices.SortedFunc(maps.Keys(byScope), func(x, y Scope) int { return strings.Compare(x.Key(), y.Key()) }) {
		c := byScope[s]
		leaving := len(c.grants) == 0 && !c.denies
		if leaving && cleared == nil {
			all, err := a.clearsAll(ctx, a.db, labels)
			if err != nil {
				return nil, err
			}
			cleared = &all
		}
		if leaving && *cleared {
			c.cleared = true
			checks = append(checks, c)
			continue
		}
		var err error
		c.on, err = a.resourceOf(ctx, tenant, s)
		switch {
		case leaving && errors.Is(err, ErrNotFound):
			continue
		case err != nil:
			return nil, err
		}
		checks = append(checks, c)
	}
	granting, denying, err := a.reachAuthority(ctx, a.db, actor, checks)
	if err != nil {
		return nil, err
	}
	clearance := a.labelCheck(ctx, a.db, labels)
	for i, c := range checks {
		// As Apply checks grants there, and SetDeny a deny.
		if len(c.grants) > 0 {
			c.cs = a.constrain(ctx, actor, c.on)
			if _, err := a.grantsAllowed(ctx, a.db, actor, c.on, c.grants, nil, c.cs, labels, &granting[i]); err != nil {
				return nil, err
			}
		}
		if c.denies {
			c.ds = a.constrain(ctx, actor, c.on)
			if err := a.denyAllowed(ctx, a.db, actor, c.on, c.ds, labels, &denying[i]); err != nil {
				return nil, err
			}
		}
		if c.leaves && !c.cleared {
			if err := clearance(c.on, GrantPermission(c.on.Type)); err != nil {
				return nil, err
			}
		}
	}
	return checks, nil
}

// mayReachAgain checks what mayReach checked again, in a change's transaction, reading the
// constraints' answers from before it rather than ask them again, the actor's label values too.
func (a *Authorizer) mayReachAgain(ctx context.Context, tx pgx.Tx, actor Subject, checks []*reachCheck, labels *constrained) error {
	granting, denying, err := a.reachAuthority(ctx, tx, actor, checks)
	if err != nil {
		return err
	}
	clearance := a.labelCheck(ctx, tx, labels)
	if slices.ContainsFunc(checks, func(c *reachCheck) bool { return c.cleared }) {
		if err := a.stillClearsAll(ctx, tx, labels); err != nil {
			return err
		}
	}
	for i, c := range checks {
		if len(c.grants) > 0 {
			c.cs.seal()
			if _, err := a.grantsAllowed(ctx, tx, actor, c.on, c.grants, nil, c.cs, labels, &granting[i]); err != nil {
				return err
			}
		}
		if c.denies {
			c.ds.seal()
			if err := a.denyAllowed(ctx, tx, actor, c.on, c.ds, labels, &denying[i]); err != nil {
				return err
			}
		}
		if c.leaves && !c.cleared {
			if err := clearance(c.on, GrantPermission(c.on.Type)); err != nil {
				return err
			}
		}
	}
	return nil
}

// reachAuthority reads, on q, the actor's authority on each scope checks reach, in one read: for
// the grants a change to members amounts to there, and apart for the denies it lifts, as Apply and
// SetDeny each read their own, the conditions of the grants it holds spending a budget of its own.
func (a *Authorizer) reachAuthority(ctx context.Context, q DB, actor Subject, checks []*reachCheck) (granting, denying []authority, err error) {
	var on []Resource
	var roles []Role
	for _, c := range checks {
		if len(c.grants) > 0 {
			on, roles = append(on, c.on), append(roles, roleIDs(c.grants)...)
		}
		if c.denies {
			on = append(on, c.on)
		}
	}
	aus, err := a.authorities(ctx, q, actor, on, roles)
	if err != nil {
		return nil, nil, err
	}
	granting, denying = make([]authority, len(checks)), make([]authority, len(checks))
	for i, c := range checks {
		if len(c.grants) > 0 {
			granting[i], aus = aus[0], aus[1:]
		}
		if c.denies {
			denying[i], aus = aus[0], aus[1:]
		}
	}
	return granting, denying, nil
}

// hostResource is a scope as Config.ResourceOf returns it, and true, or without it, as stored: its
// type and id, directly under the tenant.
func (a *Authorizer) hostResource(ctx context.Context, tenant string, s Scope) (Resource, bool, error) {
	if a.cfg.ResourceOf == nil {
		return Resource{Tenant: tenant, Type: s.Type, ID: s.ID}, false, nil
	}
	r, err := a.cfg.ResourceOf(ctx, tenant, s)
	if err != nil {
		return Resource{}, false, err
	}
	if r.Tenant != tenant || r.Scope() != s {
		return Resource{}, false, fmt.Errorf("rbac: Config.ResourceOf gave %s of tenant %q for %s", r.Scope().Key(), r.Tenant, s.Key())
	}
	return r, true, a.check(r)
}

// resourceOf is the resource a scope a change to members reaches is, to check the grants and denies
// the change amounts to there as Apply and SetDeny check them, on the resource the host passes: as
// Config.ResourceOf returns it, or as stored only where that is all of it, as where the host
// declares no labels and that resources have no attributes, and for a scope other than the tenant
// or a group, no containers. Undeclared, a condition reads any attribute, as
// `has(resource.attributes.frozen)` does.
func (a *Authorizer) resourceOf(ctx context.Context, tenant string, s Scope) (Resource, error) {
	r, given, err := a.hostResource(ctx, tenant, s)
	switch {
	case err != nil || given:
		return r, err
	case len(a.labels) > 0 || a.cfg.Attributes.Resource == nil || len(a.cfg.Attributes.Resource) > 0,
		s.Type != TenantScope && s.Type != GroupScope && len(a.containers) > 0:
		return Resource{}, fmt.Errorf("%w: the change reaches %s, whose containers, label and attributes only Config.ResourceOf gives", ErrInvalid, s.Key())
	}
	return r, nil
}

// membersCanJoin refuses members of groups that don't exist, or identities that aren't members or
// guests of the tenant, read under the change's locks, each on its own, as groupsExist reads them.
// It holds the memberships until the change ends, so DeleteExpired passes over one expiring
// meanwhile, rather than end it without seeing the groups this change joins.
func (a *Authorizer) membersCanJoin(ctx context.Context, tx pgx.Tx, tenant string, groups, identities []string) error {
	rows, err := tx.Query(ctx, `
		SELECT 'group ' || g FROM unnest($2::text[]) AS g WHERE NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = g OFFSET 0)
		UNION ALL
		SELECT 'identity ' || p FROM unnest($3::text[]) AS p WHERE NOT EXISTS (
		  SELECT FROM rbac_memberships WHERE tenant = $1 AND principal = p AND (expires_at IS NULL OR expires_at > $4) FOR KEY SHARE)
		ORDER BY 1`, tenant, groups, identities, a.cfg.Now())
	if err != nil {
		return err
	}
	missing, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range missing {
		kind, id, _ := strings.Cut(m, " ")
		if kind == "group" {
			errs = append(errs, fmt.Errorf("%w: group %q doesn't exist", ErrInvalid, id))
		} else {
			errs = append(errs, fmt.Errorf("%w: %s is not a member or guest of the tenant", ErrInvalid, id))
		}
	}
	return errors.Join(errs...)
}

// nestable refuses each group nested in another, as stored, that makes a group contain itself, or a
// chain of more than MaxGroupDepth groups: the groups under the inner one, it and the outer, and
// those the outer is in. It reads at most MaxGroupDepth levels each way, which a chain that long or
// a cycle passes, for every nesting in one round trip.
func (a *Authorizer) nestable(ctx context.Context, tx pgx.Tx, tenant string, nested []Member) error {
	if len(nested) == 0 {
		return nil
	}
	now := a.cfg.Now()
	b := &pgx.Batch{}
	for _, m := range nested {
		b.Queue(nestingDepths, tenant, m.Group, m.Principal.ID, now, MaxGroupDepth)
	}
	br := tx.SendBatch(ctx, b)
	for _, m := range nested {
		var below, above int
		var cycle bool
		err := br.QueryRow().Scan(&below, &above, &cycle)
		outer, inner := m.Group, m.Principal.ID
		switch {
		case err != nil:
		case cycle:
			err = fmt.Errorf("%w: group %q in %q would make a group contain itself", ErrInvalid, inner, outer)
		case below+above+2 > MaxGroupDepth:
			err = fmt.Errorf("%w: group %q in %q would make a chain of more than %d groups", ErrInvalid, inner, outer, MaxGroupDepth)
		}
		if err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}

// nestingDepths walks down from a group, $3, to the groups in it (groupsIn), and up from another,
// $2, to those it is in, a group at a time, as keysSQL walks up: so it reads only those groups'
// places, rather than every member of each group, or of the tenant.
var nestingDepths = `
	WITH RECURSIVE down(id, depth) AS (
	  SELECT $3::text COLLATE "C", 0
	  UNION
	  SELECT m.principal_id, d.depth + 1 FROM down d CROSS JOIN LATERAL (
	    SELECT principal_id FROM rbac_members WHERE tenant = $1 AND ` + groupsIn("d.id") + `
	      AND (expires_at IS NULL OR expires_at > $4) OFFSET 0) m
	  WHERE d.depth <= $5
	), up(id, depth) AS (
	  SELECT $2::text COLLATE "C", 0
	  UNION
	  SELECT m.group_id, u.depth + 1 FROM up u ` + groupsAbove("u.id", "$4", "group_id") + `
	  WHERE u.depth <= $5
	)
	SELECT (SELECT max(depth) FROM down), (SELECT max(depth) FROM up), EXISTS (SELECT FROM down WHERE id = $2)`

// DeleteMembers removes members from a tenant's groups, each by its group, principal and source,
// as actor: the host's own write, as for a directory it syncs from.
func (a *Authorizer) DeleteMembers(ctx context.Context, actor Principal, tenant string, members []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteMembers")
	if !validID(tenant) {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.identity(actor); err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	if len(members) > MaxBindings {
		return fmt.Errorf("%w: a deletion names at most %d members", ErrInvalid, MaxBindings)
	}
	if err := keyedAll(members); err != nil {
		return err
	}
	scopes, principals := memberLocks(members)
	return a.inTx(ctx, tenant, actor, "DeleteMembers", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		now := a.cfg.Now()
		r, err := a.restingIn(ctx, tx, tenant, members, members, now)
		if err != nil {
			return ChangeEvent{}, err
		}
		e := ChangeEvent{}
		if e.Left, err = a.leave(ctx, tx, tenant, members); err != nil {
			return ChangeEvent{}, err
		}
		e.Shortened, e.Revoked, err = a.unrest(ctx, tx, tenant, actor, r, now)
		return e, err
	})
}

// placeArgs are members' groups, principals and sources, as arrays.
func placeArgs(members []Member) []any {
	n := len(members)
	groups, principals, sources := make([]string, n), make([]string, n), make([]string, n)
	for i, m := range members {
		groups[i], principals[i], sources[i] = m.Group, m.Principal.key(), m.Source
	}
	return []any{groups, principals, sources}
}

// leave removes members, each by its group, principal and source, under the change's locks.
func (a *Authorizer) leave(ctx context.Context, tx pgx.Tx, tenant string, members []Member) ([]Member, error) {
	// Each found on its own, as byKey finds its rows.
	return removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant, `(group_id, principal, source) IN (
		  SELECT m.group_id, m.principal, m.source FROM unnest($2::text[], $3::text[], $4::text[]) AS t(g, p, s) CROSS JOIN LATERAL (
		    SELECT group_id, principal, source FROM rbac_members WHERE tenant = $1 AND group_id = t.g AND principal = t.p AND source = t.s
		    OFFSET 0) m)`, placeArgs(members)...)
}

// restingIn holds, in tx, in order, the places members name, by group, principal and source: every
// one the change writes, as an upsert of one it doesn't end, once those it ends are held, would wait
// out of order on an Activate holding both. It reads at now the activations resting (restingOn) of
// the identities among ending, the places the change ends or may end sooner, and in the groups among
// them.
func (a *Authorizer) restingIn(ctx context.Context, tx pgx.Tx, tenant string, members, ending []Member, now time.Time) (resting, error) {
	if len(ending) == 0 {
		return resting{}, nil
	}
	members = slices.SortedFunc(slices.Values(members), func(x, y Member) int { return strings.Compare(memberKey(x), memberKey(y)) })
	members = slices.CompactFunc(members, func(x, y Member) bool { return memberKey(x) == memberKey(y) })
	identities, groups, err := endingPlaces(ctx, tx, `
		SELECT m.principal FROM unnest($2::text[], $3::text[], $4::text[]) AS k(g, p, s) CROSS JOIN LATERAL (
		  SELECT principal FROM rbac_members WHERE tenant = $1 AND group_id = k.g AND principal = k.p AND source = k.s FOR UPDATE) m`,
		slices.Concat([]any{tenant}, placeArgs(members))...)
	if err != nil {
		return resting{}, err
	}
	ends := map[string]bool{}
	for _, m := range ending {
		ends[m.Principal.key()] = true
	}
	identities = slices.DeleteFunc(identities, func(k string) bool { return !ends[k] })
	groups = slices.DeleteFunc(groups, func(id string) bool { return !ends[groupPrincipal(id).key()] })
	return a.restingOn(ctx, tx, tenant, identities, groups, now)
}

// endingPlaces holds, in tx, the places in groups query picks, in the order of their groups,
// principals and sources, by each one's key, as a generic plan joining the arguments to the
// tenant's places would read every one; it returns the keys of the identities among them and the
// ids of the groups.
func endingPlaces(ctx context.Context, tx pgx.Tx, query string, args ...any) (identities, groups []string, err error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, err
	}
	for _, k := range slices.Compact(slices.Sorted(slices.Values(keys))) {
		if id, ok := strings.CutPrefix(k, string(Group)+":"); ok {
			groups = append(groups, id)
		} else {
			identities = append(identities, k)
		}
	}
	return identities, groups, nil
}

// Members lists a group's members in force, as stored: identities and groups, not the members of
// the groups in it. An identity whose membership of the tenant ended is in none of its groups. It
// has no limit or cursor, so what it returns grows with the group.
func (a *Authorizer) Members(ctx context.Context, tenant, group string) ([]Member, error) {
	if !validID(tenant) || !validGroupID(group) {
		return nil, fmt.Errorf("%w: Members needs a tenant and a valid group", ErrInvalid)
	}
	rows, err := a.db.Query(ctx, `SELECT `+memberColumns+` FROM rbac_members m
		WHERE tenant = $1 AND group_id = $2 AND (expires_at IS NULL OR expires_at > $3)
		  AND (principal_kind = 'group' OR `+inTenant("m.principal", "$1", "$3")+`)
		ORDER BY principal, source`, tenant, group, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectMembers(rows)
}

// GroupsOf lists the groups a principal is in in a tenant, by id: those it is a member of, and
// those they are in, to the top, as memberships are in force now. An identity whose membership of
// the tenant ended is in none. One whose membership is suspended is listed in its groups, which a
// check counts then only to bind it to denies, never to give it their grants: a constraint that
// lets a group's members through should check the membership too (Memberships).
func (a *Authorizer) GroupsOf(ctx context.Context, tenant string, p Principal) ([]string, error) {
	// The zero principal, the anonymous subject's, which a constraint may ask about, is in none.
	if !validID(tenant) || p != (Principal{}) && !p.wellFormed(tenant) {
		return nil, fmt.Errorf("%w: GroupsOf needs a tenant and a valid principal", ErrInvalid)
	}
	rows, err := a.db.Query(ctx, `
		WITH RECURSIVE g(id) AS (
		  SELECT group_id FROM rbac_members WHERE tenant = $1 AND principal = $2 AND (expires_at IS NULL OR expires_at > $3)
		    AND ($4 OR `+inTenant("$2", "$1", "$3")+`)
		  UNION
		  SELECT m.group_id FROM g `+groupsAbove("g.id", "$3", "group_id")+`
		)
		SELECT id FROM g ORDER BY id`, tenant, p.key(), a.cfg.Now(), p.Kind == Group)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// heldByMembers refuses making a custom role privileged while the tenant's members are granted it,
// through whom it would then give nothing; no eligibility names them.
func heldByMembers(ctx context.Context, q DB, tenant string, role Role, now time.Time) error {
	var held bool
	// The LIKE matches the partial index on custom roles' grants.
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%'
		AND principal_kind = 'members' AND (expires_at IS NULL OR expires_at > $3))`, tenant, string(role), now).Scan(&held)
	if err != nil || !held {
		return err
	}
	return fmt.Errorf("%w: %s would be privileged, and the tenant's members hold it: a privileged role is never theirs, so revoke it first", ErrInvalid, role)
}

// groupKeys returns the keys of the groups among principals, sorted, each once.
func groupKeys(principals []Principal) []string {
	var keys []string
	for _, p := range principals {
		if p.Kind == Group {
			keys = append(keys, p.key())
		}
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

func bindingPrincipals(bs []Binding) []Principal {
	ps := make([]Principal, len(bs))
	for i, b := range bs {
		ps[i] = b.Principal
	}
	return ps
}

// groupScopes returns the keys of the group scopes among scopes, which are the groups' keys as
// principals too.
func groupScopes(scopes []Scope) []string {
	var keys []string
	for _, s := range scopes {
		if s.Type == GroupScope {
			keys = append(keys, s.Key())
		}
	}
	return keys
}

// groupsExist refuses a change naming, by key, a group the tenant doesn't have, read under the
// change's locks on them: what it names, or makes on one's scope, would pass to a group made later
// with that id. Each is looked up on its own: OFFSET 0 keeps the planner from flattening the test
// into an anti-join, which a generic plan, costing the tenant's groups as an average tenant's few,
// runs by reading every one.
func groupsExist(ctx context.Context, q DB, tenant string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	var missing string
	err := q.QueryRow(ctx, `SELECT k FROM unnest($2::text[]) AS k
		WHERE NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = substr(k, length('group:') + 1) OFFSET 0)
		ORDER BY k LIMIT 1`, tenant, keys).Scan(&missing)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: tenant %q has no %s", ErrInvalid, tenant, missing)
}

// inTenant is SQL for whether an identity, by the SQL for its key, is a member or guest of a tenant
// at now: until DeleteExpired removes them, an ended membership's groups are still stored.
func inTenant(principal, tenant, now string) string {
	return `EXISTS (SELECT FROM rbac_memberships ms WHERE ms.tenant = ` + tenant + ` AND ms.principal = ` + principal +
		` AND (ms.expires_at IS NULL OR ms.expires_at > ` + now + `))`
}

const memberColumns = `group_id, principal_kind, principal_id, source, expires_at, note, created_by, created_at, updated_by, updated_at`

func collectMembers(rows pgx.Rows) ([]Member, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Member, error) {
		var m Member
		var expires *time.Time
		var createdBy, updatedBy string
		err := row.Scan(&m.Group, &m.Principal.Kind, &m.Principal.ID, &m.Source, &expires, &m.Note,
			&createdBy, &m.CreatedAt, &updatedBy, &m.UpdatedAt)
		if expires != nil {
			m.ExpiresAt = *expires
		}
		m.CreatedBy, m.UpdatedBy = parsePrincipal(createdBy), parsePrincipal(updatedBy)
		return m, err
	})
}
