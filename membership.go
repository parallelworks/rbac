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
// tenant; ManagePrivilegedGroups the same for its privileged groups (GroupDefinition.Privileged),
// and to change their members. GroupMembers is the permission to change the members of a group
// that isn't privileged, held on its scope or the tenant. All change access, as the members of a
// group hold what it is granted.
const (
	ManageGroups           Permission = "tenant:groups"
	ManagePrivilegedGroups Permission = "tenant:privileged-groups"
	GroupMembers           Permission = "group:members"
)

// GroupScope is the type of the scope a group is, which a host's catalog gives roles on, as on any
// scope: groups are directly under the tenant.
const GroupScope = "group"

// MaxGroupDepth is how many groups a chain of groups, each in the next, holds at most.
const MaxGroupDepth = 8

// Membership is an identity's membership of a tenant. A member holds what it is granted there and
// what is granted to the tenant's members; a guest only what it is granted; and a suspended one
// keeps its grants and groups but holds nothing until the suspension is lifted. The host keeps
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
	// ExpiresAt ends it; zero never does.
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
	// Privileged marks a group that may hold privileged roles, which no other group may. It is set
	// when the group is created and never after, needs ManagePrivilegedGroups, and its members are
	// identities, never groups, so privileged access reaches no one through nesting: a group
	// made privileged later would make its members privileged unreviewed.
	Privileged bool
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
	// ExpiresAt ends it; zero never does.
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

// checkKept returns why a membership's or member's source, expiry and note can't be stored at now.
func checkKept(source string, expires time.Time, note string, now time.Time) []string {
	var errs []string
	if reason := checkSource(source); reason != "" {
		errs = append(errs, reason)
	}
	if !expires.IsZero() && !expires.After(now) {
		errs = append(errs, "already expired")
	}
	if !validNote(note) {
		errs = append(errs, fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	return errs
}

// checkMembership returns why a membership can't be stored at now.
func (a *Authorizer) checkMembership(m Membership, now time.Time) error {
	var errs []string
	if !a.acts(m.Principal.Kind) || m.Principal.ID == "" {
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
// made by actor now.
func (a *Authorizer) SetMemberships(ctx context.Context, actor Principal, tenant string, ms []Membership) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "SetMemberships")
	if tenant == "" {
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
	for i, m := range set {
		kinds[i], ids[i], sources[i], notes[i] = string(m.Principal.Kind), m.Principal.ID, m.Source, m.Note
		guests[i], suspended[i] = m.Guest, m.Suspended
		expires[i] = pgtype.Timestamptz{Time: m.ExpiresAt, Valid: !m.ExpiresAt.IsZero()}
		keys[i] = m.Principal.key()
	}
	return a.inTx(ctx, tenant, actor, "SetMemberships", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, nil, keys); err != nil {
			return ChangeEvent{}, err
		}
		// An ended membership's groups go, as DeleteExpired would remove them, each membership held
		// before its members as there, so the two never deadlock.
		left, err := removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant, `principal IN (
			SELECT principal FROM rbac_memberships WHERE tenant = $1 AND principal = ANY($2::text[]) AND expires_at <= $3 FOR UPDATE)`,
			keys, a.cfg.Now())
		if err != nil {
			return ChangeEvent{}, err
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
			tenant, kinds, ids, guests, suspended, sources, expires, notes, actorKey(actor), a.cfg.Now())
		if err != nil {
			return ChangeEvent{}, err
		}
		changed, err := collectMemberships(rows)
		return ChangeEvent{Memberships: changed, Left: left}, err
	})
}

// Memberships lists a tenant's memberships in force, by principal: of those principals, or with
// none, all.
func (a *Authorizer) Memberships(ctx context.Context, tenant string, principals []Principal) ([]Membership, error) {
	if tenant == "" {
		return nil, fmt.Errorf("%w: Memberships needs a tenant", ErrInvalid)
	}
	var keys []string
	if len(principals) > 0 {
		keys = keysOf(principals)
	}
	rows, err := a.db.Query(ctx, `SELECT `+membershipColumns+` FROM rbac_memberships
		WHERE tenant = $1 AND ($2::text[] IS NULL OR principal = ANY($2::text[])) AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY principal`, tenant, keys, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectMemberships(rows)
}

// MembershipsOf lists an identity's memberships in force in every tenant, by tenant.
func (a *Authorizer) MembershipsOf(ctx context.Context, p Principal) ([]Membership, error) {
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
// ManageGroups on the tenant, not removed by a constraint. A group from a source the host owns
// (Config.Sources) only the host changes, with ImportGroups.
func (a *Authorizer) SetGroup(ctx context.Context, actor Subject, tenant string, g GroupDefinition) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "SetGroup")
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	perm := managing(g.Privileged)
	if err := a.mayManageGroups(ctx, a.db, actor, root, perm, true); err != nil {
		return err
	}
	if err := checkGroup(g); err != nil {
		return err
	}
	if a.owned[g.Source] {
		return fmt.Errorf("%w: group %q: only the host makes groups from %s, through ImportGroups", ErrInvalid, g.ID, g.Source)
	}
	return a.inTx(ctx, tenant, actor.Principal, "SetGroup", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, tenant, []string{groupKey(g.ID)}, nil); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayManageGroups(ctx, tx, actor, root, perm, false); err != nil {
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
// a directory it syncs from, without the checks SetGroup makes of an actor.
func (a *Authorizer) ImportGroups(ctx context.Context, actor Principal, tenant string, groups []GroupDefinition) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "ImportGroups")
	if tenant == "" {
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
		changed, err := upsertGroups(ctx, tx, tenant, actor, set)
		return ChangeEvent{Groups: changed}, err
	})
}

// upsertGroups stores groups, sorted by id, and returns those it created or changed.
func upsertGroups(ctx context.Context, tx pgx.Tx, tenant string, actor Principal, groups []GroupDefinition) ([]GroupDefinition, error) {
	n := len(groups)
	ids, names, descriptions, sources := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	privileged := make([]bool, n)
	for i, g := range groups {
		ids[i], names[i], descriptions[i], sources[i], privileged[i] = g.ID, g.Name, g.Description, g.Source, g.Privileged
	}
	rows, err := tx.Query(ctx, `SELECT g.id FROM rbac_groups g JOIN unnest($2::text[], $3::bool[]) AS t(i, p) ON g.id = t.i
		WHERE g.tenant = $1 AND g.privileged <> t.p ORDER BY g.id`, tenant, ids, privileged)
	if err != nil {
		return nil, err
	}
	flipped, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(flipped) > 0 {
		return nil, fmt.Errorf("%w: group %q: whether a group is privileged is set when it is created", ErrInvalid, flipped[0])
	}
	rows, err = tx.Query(ctx, `
		INSERT INTO rbac_groups AS g (tenant, id, name, description, source, privileged, created_by, updated_by)
		SELECT $1, i, n, d, s, p, $7, $7 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::bool[]) AS t(i, n, d, s, p)
		ON CONFLICT (tenant, id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
		  source = EXCLUDED.source, updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE (g.name, g.description, g.source) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.source)
		RETURNING `+groupColumns,
		tenant, ids, names, descriptions, sources, privileged, actorKey(actor))
	if err != nil {
		return nil, err
	}
	return collectGroups(rows)
}

// managing is the permission that manages a group, privileged or not.
func managing(privileged bool) Permission {
	if privileged {
		return ManagePrivilegedGroups
	}
	return ManageGroups
}

// privilegedGroup reads, on q, whether a tenant's group exists and whether it is privileged.
func privilegedGroup(ctx context.Context, q DB, tenant, id string) (exists, privileged bool, err error) {
	err = q.QueryRow(ctx, `SELECT privileged FROM rbac_groups WHERE tenant = $1 AND id = $2`, tenant, id).Scan(&privileged)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	return err == nil, privileged, err
}

// DeleteGroup deletes a tenant's group, as actor, who needs ManageGroups on the tenant, and with it
// its members and its place in other groups. Its members hold what it and the groups it is in
// hold, so it refuses a group that, or a group it is in, holds grants or eligibilities in force,
// which revoking first shows, that a deny names or exempts, or that approves an eligibility's
// activations: deleting one never changes access as a side effect. It refuses one from a source
// the host owns, in a group from one, or with members, a place in a group or grants on it from
// one. Deleting a group that doesn't exist does nothing.
func (a *Authorizer) DeleteGroup(ctx context.Context, actor Subject, tenant, id string) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "DeleteGroup")
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	_, privileged, err := privilegedGroup(ctx, a.db, tenant, id)
	if err != nil {
		return err
	}
	if err := a.mayManageGroups(ctx, a.db, actor, root, managing(privileged), true); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, "DeleteGroup", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, tenant, []string{groupKey(id), nestingKey}, []string{groupPrincipal(id).key()}); err != nil {
			return ChangeEvent{}, err
		}
		exists, now, err := privilegedGroup(ctx, tx, tenant, id)
		switch {
		case err != nil:
			return ChangeEvent{}, err
		// Deleted and made again otherwise meanwhile, it isn't the group the constraints were asked about.
		case exists && now != privileged:
			return ChangeEvent{}, fmt.Errorf("%w: group %q changed while this change waited for it; try again", ErrConflict, id)
		}
		if err := a.mayManageGroups(ctx, tx, actor, root, managing(privileged), false); err != nil {
			return ChangeEvent{}, err
		}
		// Without a group, the grants and denies on its scope are no group's to remove.
		if !exists {
			return ChangeEvent{}, nil
		}
		if err := a.notOwnedGroups(ctx, tx, tenant, []string{id}); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.deletable(ctx, tx, tenant, id); err != nil {
			return ChangeEvent{}, err
		}
		return a.removeGroups(ctx, tx, tenant, actor.Principal, []string{id})
	})
}

// deletable refuses deleting a group an actor asks to delete when that would change access, its
// members' through the groups it is in too, or what the host keeps. Expired grants, eligibilities
// and places in groups give nothing, and Grants doesn't list them to revoke, so they go with it.
func (a *Authorizer) deletable(ctx context.Context, tx pgx.Tx, tenant, id string) error {
	var held, denied, approves, owned bool
	if err := tx.QueryRow(ctx, `
		WITH RECURSIVE up(id) AS (
		  SELECT $4::text COLLATE "C"
		  UNION
		  SELECT m.group_id FROM rbac_members m JOIN up u ON m.principal = 'group:' || u.id
		  WHERE m.tenant = $1 AND (m.expires_at IS NULL OR m.expires_at > $3)
		), reached AS (SELECT array_agg('group:' || id) AS keys FROM up)
		SELECT
		  EXISTS (SELECT FROM rbac_grants, reached WHERE tenant = $1 AND principal = ANY(keys) AND (expires_at IS NULL OR expires_at > $3))
		    OR EXISTS (SELECT FROM rbac_eligibilities, reached WHERE tenant = $1 AND principal = ANY(keys) AND (expires_at IS NULL OR expires_at > $3)),
		  EXISTS (SELECT FROM rbac_denies, reached WHERE tenant = $1 AND (principals && keys OR exempt && keys)),
		  EXISTS (SELECT FROM rbac_eligibilities, reached WHERE tenant = $1 AND approvers && keys AND (expires_at IS NULL OR expires_at > $3)),
		  EXISTS (SELECT FROM rbac_members WHERE tenant = $1 AND (group_id = $4 OR principal = $2) AND source = ANY($5::text[]))
		    OR EXISTS (SELECT FROM rbac_members m JOIN rbac_groups g ON g.tenant = m.tenant AND g.id = m.group_id
		      WHERE m.tenant = $1 AND m.principal = $2 AND g.source = ANY($5::text[]))
		    OR EXISTS (SELECT FROM rbac_grants WHERE tenant = $1 AND scope = $6 AND source = ANY($5::text[])
		      AND (expires_at IS NULL OR expires_at > $3))`,
		tenant, groupPrincipal(id).key(), a.cfg.Now(), id, slices.Sorted(maps.Keys(a.owned)), groupKey(id)).Scan(&held, &denied, &approves, &owned); err != nil {
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
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
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
	// The group's grants, and those on the group, as its managers', which would pass to a group
	// made later with its id.
	const ofGroups = "(principal = ANY($2::text[]) OR scope = ANY($3::text[]))"
	var err error
	if e.Revoked, err = a.remove(ctx, tx, tenant, ofGroups, principals, scopes); err != nil {
		return ChangeEvent{}, err
	}
	if e.Ineligible, err = a.removeEligible(ctx, tx, tenant, ofGroups, principals, scopes); err != nil {
		return ChangeEvent{}, err
	}
	if e.DeletedDenies, err = removed(ctx, a, tx, "rbac_denies", denyColumns, collectDenies, tenant, "scope = ANY($2::text[])", scopes); err != nil {
		return ChangeEvent{}, err
	}
	// A deny that names or exempts the groups would name or exempt a group made later with one's
	// id: one naming only them denies no one, and goes.
	unnamed, err := removed(ctx, a, tx, "rbac_denies", denyColumns, collectDenies, tenant, "principals <@ $2::text[]", principals)
	if err != nil {
		return ChangeEvent{}, err
	}
	e.DeletedDenies = append(e.DeletedDenies, unnamed...)
	rows, err := tx.Query(ctx, `UPDATE rbac_denies SET
		  principals = array(SELECT k FROM unnest(principals) WITH ORDINALITY AS t(k, i) WHERE k <> ALL($2::text[]) ORDER BY i),
		  exempt = array(SELECT k FROM unnest(exempt) WITH ORDINALITY AS t(k, i) WHERE k <> ALL($2::text[]) ORDER BY i),
		  updated_by = $3, updated_at = now()
		WHERE tenant = $1 AND (principals && $2::text[] OR exempt && $2::text[])
		RETURNING `+denyColumns, tenant, principals, actorKey(actor))
	if err != nil {
		return ChangeEvent{}, err
	}
	if e.Denies, err = collectDenies(rows); err != nil {
		return ChangeEvent{}, err
	}
	// An eligibility only the groups approve would need no approval without them, so it goes; the
	// others no longer name them.
	unapproved, err := removed(ctx, a, tx, "rbac_eligibilities", eligibilityColumns, collectEligibilities, tenant,
		"approvers <> '{}' AND approvers <@ $2::text[]", principals)
	if err != nil {
		return ChangeEvent{}, err
	}
	e.Ineligible = append(e.Ineligible, unapproved...)
	rows, err = tx.Query(ctx, `UPDATE rbac_eligibilities SET
		  approvers = array(SELECT k FROM unnest(approvers) WITH ORDINALITY AS t(k, i) WHERE k <> ALL($2::text[]) ORDER BY i)
		WHERE tenant = $1 AND approvers && $2::text[]
		RETURNING `+eligibilityColumns, tenant, principals)
	if err != nil {
		return ChangeEvent{}, err
	}
	if e.Eligible, err = collectEligibilities(rows); err != nil {
		return ChangeEvent{}, err
	}
	if e.Left, err = removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant,
		"(group_id = ANY($2::text[]) OR principal = ANY($3::text[]))", ids, principals); err != nil {
		return ChangeEvent{}, err
	}
	e.DeletedGroups, err = removed(ctx, a, tx, "rbac_groups", groupColumns, collectGroups, tenant, "id = ANY($2::text[])", ids)
	return e, err
}

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

// mayManageGroups checks that actor may create and delete a tenant's groups: before the change's
// transaction, with the constraints, and again in it, on q.
func (a *Authorizer) mayManageGroups(ctx context.Context, q DB, actor Subject, root Resource, perm Permission, constraints bool) error {
	scope := root.Scope()
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: perm, Scope: scope, Reason: "an anonymous subject changes nothing"}
	}
	if constraints {
		name, err := a.denied(ctx, ConstraintInput{Tenant: root.Tenant, ResourceType: root.Type, Permission: perm, Subject: &actor, Resource: &root})
		if err != nil {
			return err
		}
		if name != "" {
			return &DeniedError{Permission: perm, Scope: scope, Reason: "removed by " + name}
		}
	}
	au, err := a.authorityOn(ctx, q, actor, root, nil)
	if err != nil {
		return err
	}
	if !au.may(perm, root.Type) {
		return &DeniedError{Permission: perm, Scope: scope, Reason: "the actor may not manage these groups here"}
	}
	return nil
}

// Groups lists a tenant's groups, by id.
func (a *Authorizer) Groups(ctx context.Context, tenant string) ([]GroupDefinition, error) {
	rows, err := a.db.Query(ctx, `SELECT `+groupColumns+` FROM rbac_groups WHERE tenant = $1 ORDER BY id`, tenant)
	if err != nil {
		return nil, err
	}
	return collectGroups(rows)
}

const groupColumns = `id, name, description, source, privileged, created_by, created_at, updated_by, updated_at`

func collectGroups(rows pgx.Rows) ([]GroupDefinition, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (GroupDefinition, error) {
		var g GroupDefinition
		var createdBy, updatedBy string
		err := row.Scan(&g.ID, &g.Name, &g.Description, &g.Source, &g.Privileged, &createdBy, &g.CreatedAt, &updatedBy, &g.UpdatedAt)
		g.CreatedBy, g.UpdatedBy = parsePrincipal(createdBy), parsePrincipal(updatedBy)
		return g, err
	})
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
	case p.Kind != Group && (!a.acts(p.Kind) || p.ID == ""):
		errs = append(errs, "a member is an identity, a user or a declared kind, or a group")
	}
	errs = append(errs, checkKept(m.Source, m.ExpiresAt, m.Note, now)...)
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s in group %q: %s", ErrInvalid, m.Principal.key(), m.Group, strings.Join(errs, "; "))
	}
	return nil
}

// ImportMembers adds members to a tenant's groups, from their sources, or changes their expiry or
// note, as actor: the host's own write, as for a directory it syncs from. A member identity is a
// member or guest of the tenant, and a member group exists; nesting a group can't make one contain
// itself, nor a chain of more than MaxGroupDepth groups. Config.ValidateGrant is asked about each
// privileged grant and eligibility of a privileged group for each identity added to it, as with
// ChangeMembers.
func (a *Authorizer) ImportMembers(ctx context.Context, actor Principal, tenant string, members []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "ImportMembers")
	if tenant == "" {
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
	groups := memberGroups(set)
	privileged, err := privilegedGroups(ctx, a.db, tenant, groups)
	if err != nil {
		return err
	}
	joined := joining(set, privileged)
	asked, err := a.askMemberships(ctx, Subject{Principal: actor}, tenant, set, joined)
	if err != nil {
		return err
	}
	scopes, principals := memberLocks(set)
	principals = append(principals, joinedLocks(joined)...)
	return a.inTx(ctx, tenant, actor, "ImportMembers", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.stillAsked(ctx, tx, tenant, groups, privileged, joined, asked); err != nil {
			return ChangeEvent{}, err
		}
		joined, err := a.join(ctx, tx, tenant, actor, set)
		return ChangeEvent{Joined: joined}, err
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

// joining returns the privileged groups an identity in set joins, whose privileged holdings it
// gains, sorted.
func joining(set []Member, privileged map[string]bool) []string {
	ids := map[string]bool{}
	for _, m := range set {
		if privileged[m.Group] && m.Principal.Kind != Group {
			ids[m.Group] = true
		}
	}
	return slices.Sorted(maps.Keys(ids))
}

// joinedLocks are the principal locks of the privileged groups joined: a grant to one takes its
// lock, so none is made while the members it gains are.
func joinedLocks(joined []string) []string {
	keys := make([]string, len(joined))
	for i, g := range joined {
		keys[i] = groupPrincipal(g).key()
	}
	return keys
}

// stillAsked refuses, under a change's locks, a change to members whose groups, or the privileged
// holdings of the privileged groups identities join, changed since the host was asked about them
// before its transaction.
func (a *Authorizer) stillAsked(ctx context.Context, tx pgx.Tx, tenant string, groups []string, privileged map[string]bool, joined []string, asked map[revalidated]RoleDefinition) error {
	now, err := privilegedGroups(ctx, tx, tenant, groups)
	if err != nil {
		return err
	}
	if !maps.Equal(now, privileged) {
		return fmt.Errorf("%w: a group changed while this change waited for it; try again", ErrConflict)
	}
	gains, err := a.privilegedHeld(ctx, tx, tenant, joined)
	if err != nil {
		return err
	}
	for _, g := range gains {
		if was, ok := asked[g.key()]; !ok || widens(was, g.role) {
			return fmt.Errorf("%w: what group %q holds changed while this change waited for it; try again", ErrConflict, g.binding.Principal.ID)
		}
	}
	return nil
}

// memberSet checks members to add and returns them sorted, each group, principal and source once,
// the last given.
func (a *Authorizer) memberSet(members []Member) ([]Member, error) {
	now := a.cfg.Now()
	type key struct {
		group, principal, source string
	}
	byKey := map[key]Member{}
	var errs []error
	for _, m := range members {
		m.ExpiresAt = stored(m.ExpiresAt)
		errs = append(errs, a.checkMember(m, now))
		byKey[key{m.Group, m.Principal.key(), m.Source}] = m
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return slices.SortedFunc(maps.Values(byKey), func(x, y Member) int {
		return strings.Compare(x.Group+"\x00"+x.Principal.key()+"\x00"+x.Source, y.Group+"\x00"+y.Principal.key()+"\x00"+y.Source)
	}), nil
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
// exist, a group in a privileged one, and nesting that makes a cycle or too long a chain.
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
	if err := privilegedTakeNoGroups(ctx, tx, tenant, nested); err != nil {
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
	return joined, a.nestable(ctx, tx, tenant, nested)
}

// ChangeMembers adds members to a tenant's groups, or changes their expiry or note, and removes
// others, each by its group, principal and source, as actor, in one transaction. Whoever is in a
// group holds what it holds and is bound by the denies naming it, so the members of one that isn't
// privileged change with GroupMembers on its scope, and a privileged one's only with
// ManagePrivilegedGroups on the tenant, removals included, and never to add the actor itself; a
// constraint on either stops them. Config.ValidateGrant is asked about each grant and eligibility
// of a privileged role a privileged group holds, for each identity added to it (ViaMembership), as
// that identity's. Removing someone from a group a deny names, or adding them to one it exempts,
// lifts that deny for them, whatever it removes. Members from a source the host owns, and the
// members of a group from one, only the host changes, and what ImportMembers refuses, this does.
func (a *Authorizer) ChangeMembers(ctx context.Context, actor Subject, tenant string, add, remove []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor.Principal, "ChangeMembers")
	if tenant == "" {
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
	groups := memberGroups(slices.Concat(set, remove))
	privileged, err := privilegedGroups(ctx, a.db, tenant, groups)
	if err != nil {
		return err
	}
	if err := a.mayChangeMembers(ctx, a.db, actor, tenant, groups, privileged, true); err != nil {
		return err
	}
	// Refused before the host is asked about what the members would gain, and again under the locks.
	if err := a.notOwnedGroups(ctx, a.db, tenant, groups); err != nil {
		return err
	}
	for _, m := range set {
		if privileged[m.Group] && m.Principal == actor.Principal {
			return &DeniedError{Permission: ManagePrivilegedGroups, Scope: TenantRoot(tenant), Reason: "no one adds themselves to a privileged group"}
		}
	}
	joined := joining(set, privileged)
	asked, err := a.askMemberships(ctx, actor, tenant, set, joined)
	if err != nil {
		return err
	}
	scopes, principals := memberLocks(slices.Concat(set, remove))
	principals = append(principals, joinedLocks(joined)...)
	return a.inTx(ctx, tenant, actor.Principal, "ChangeMembers", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.stillAsked(ctx, tx, tenant, groups, privileged, joined, asked); err != nil {
			return ChangeEvent{}, err
		}
		// The host's groups only the host changes, members and all.
		if err := a.notOwnedGroups(ctx, tx, tenant, groups); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayChangeMembers(ctx, tx, actor, tenant, groups, privileged, false); err != nil {
			return ChangeEvent{}, err
		}
		var e ChangeEvent
		if len(remove) > 0 {
			if e.Left, err = a.leave(ctx, tx, tenant, remove); err != nil {
				return ChangeEvent{}, err
			}
		}
		if len(set) > 0 {
			if e.Joined, err = a.join(ctx, tx, tenant, actor.Principal, set); err != nil {
				return ChangeEvent{}, err
			}
		}
		return e, nil
	})
}

// privilegedGroups reads, on q, which of a tenant's groups exist, and whether each is privileged.
func privilegedGroups(ctx context.Context, q DB, tenant string, ids []string) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT id, privileged FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[])`, tenant, ids)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	var id string
	var privileged bool
	_, err = pgx.ForEachRow(rows, []any{&id, &privileged}, func() error {
		found[id] = privileged
		return nil
	})
	return found, err
}

// mayChangeMembers checks, on q, that actor may change the members of groups: ManagePrivilegedGroups
// on the tenant for a privileged one, GroupMembers on its scope for any other, or one that doesn't
// exist, which has none to change. Constraints are asked only with constraints, before the
// transaction.
func (a *Authorizer) mayChangeMembers(ctx context.Context, q DB, actor Subject, tenant string, groups []string, privileged map[string]bool, constraints bool) error {
	checked := false
	for _, g := range groups {
		if privileged[g] {
			if !checked {
				if err := a.mayManageGroups(ctx, q, actor, Resource{Tenant: tenant, Type: TenantScope, ID: tenant}, ManagePrivilegedGroups, constraints); err != nil {
					return err
				}
				checked = true
			}
			continue
		}
		if err := a.mayManageGroups(ctx, q, actor, Resource{Tenant: tenant, Type: GroupScope, ID: g}, GroupMembers, constraints); err != nil {
			return err
		}
	}
	return nil
}

// gainedBy reports whether an identity m adds gains v, a privileged group's grant or eligibility.
func (v revalidation) gainedBy(m Member) bool {
	return m.Group == v.binding.Principal.ID && m.Principal.Kind != Group
}

// as is v as the grant or eligibility of m, as the host is asked about it: until the sooner of its
// end and m's.
func (v revalidation) as(m Member) Binding {
	b := v.binding
	b.ID, b.Principal = "", m.Principal
	if !m.ExpiresAt.IsZero() && (b.ExpiresAt.IsZero() || m.ExpiresAt.Before(b.ExpiresAt)) {
		b.ExpiresAt = m.ExpiresAt
	}
	return b
}

// privilegedHeld reads, on q, the grants and eligibilities in force of a privileged role that the
// privileged groups joined hold, which an identity joining one gains.
func (a *Authorizer) privilegedHeld(ctx context.Context, q DB, tenant string, joined []string) ([]revalidation, error) {
	if len(joined) == 0 {
		return nil, nil
	}
	keys := make([]string, len(joined))
	for i, g := range joined {
		keys[i] = groupPrincipal(g).key()
	}
	now := a.cfg.Now()
	rows, err := q.Query(ctx, `SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3) ORDER BY id`, tenant, keys, now)
	if err != nil {
		return nil, err
	}
	grants, err := collectGrants(rows)
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT `+eligibilityColumns+` FROM rbac_eligibilities
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND (expires_at IS NULL OR expires_at > $3) ORDER BY scope, principal, role`,
		tenant, keys, now)
	if err != nil {
		return nil, err
	}
	eligible, err := collectEligibilities(rows)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	var gains []revalidation
	add := func(scope Scope, b Binding) {
		if def, ok := roles.role(b.Role); ok && def.Privileged {
			gains = append(gains, revalidation{scope: scope, binding: b, role: def})
		}
	}
	for _, g := range grants {
		add(g.Scope, g.Binding)
	}
	for _, e := range eligible {
		add(e.Scope, e.binding())
	}
	return gains, nil
}

// askMemberships asks Config.ValidateGrant, before ChangeMembers' transaction, about each
// privileged grant and eligibility each identity set adds to a privileged group gains, and returns
// those it asked about, with the role as it asked: by what the host was asked, so one changed in
// place meanwhile, as an eligibility extended, is asked about again.
func (a *Authorizer) askMemberships(ctx context.Context, actor Subject, tenant string, set []Member, joined []string) (map[revalidated]RoleDefinition, error) {
	gains, err := a.privilegedHeld(ctx, a.db, tenant, joined)
	if err != nil {
		return nil, err
	}
	asked := map[revalidated]RoleDefinition{}
	var refused []error
	for _, g := range gains {
		roles := book{builtin: a.roles, custom: map[Role]RoleDefinition{g.role.ID: g.role}}
		for _, m := range set {
			if !g.gainedBy(m) {
				continue
			}
			bad, err := a.allowed(ctx, roles, actor, ViaMembership, tenant, g.scope, g.as(m))
			if err != nil {
				return nil, err
			}
			refused = append(refused, bad...)
		}
		asked[g.key()] = g.role
	}
	return asked, errors.Join(refused...)
}

// privilegedTakeNoGroups refuses nesting a group in a privileged one, whose members are identities
// only, so privileged access reaches no one through a group's members.
func privilegedTakeNoGroups(ctx context.Context, tx pgx.Tx, tenant string, nested []Member) error {
	if len(nested) == 0 {
		return nil
	}
	outer := make([]string, len(nested))
	for i, m := range nested {
		outer[i] = m.Group
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[]) AND privileged ORDER BY id LIMIT 1`,
		tenant, outer).Scan(&id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: group %q is privileged, so its members are identities, not groups", ErrInvalid, id)
}

// membersCanJoin refuses members of groups that don't exist, or identities that aren't members or
// guests of the tenant, read under the change's locks. It holds the memberships until the change
// ends, so DeleteExpired passes over one expiring meanwhile, rather than end it without seeing
// the groups this change joins.
func (a *Authorizer) membersCanJoin(ctx context.Context, tx pgx.Tx, tenant string, groups, identities []string) error {
	rows, err := tx.Query(ctx, `
		SELECT 'group ' || g FROM unnest($2::text[]) AS g WHERE NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = g)
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

// nestingDepths walks down from a group, $3, by the principal of its members, so the walk reads only
// the tenant's nested groups from rbac_members_principal rather than every member of each group.
const nestingDepths = `
	WITH RECURSIVE down(id, depth) AS (
	  SELECT $3::text COLLATE "C", 0
	  UNION
	  SELECT substr(m.principal, length('group:') + 1), d.depth + 1 FROM rbac_members m JOIN down d ON m.group_id = d.id
	  WHERE m.tenant = $1 AND m.principal LIKE 'group:%' AND (m.expires_at IS NULL OR m.expires_at > $4) AND d.depth <= $5
	), up(id, depth) AS (
	  SELECT $2::text COLLATE "C", 0
	  UNION
	  SELECT m.group_id, u.depth + 1 FROM rbac_members m JOIN up u ON m.principal = 'group:' || u.id
	  WHERE m.tenant = $1 AND (m.expires_at IS NULL OR m.expires_at > $4) AND u.depth <= $5
	)
	SELECT (SELECT max(depth) FROM down), (SELECT max(depth) FROM up), EXISTS (SELECT FROM down WHERE id = $2)`

// DeleteMembers removes members from a tenant's groups, each by its group, principal and source,
// as actor: the host's own write, as for a directory it syncs from.
func (a *Authorizer) DeleteMembers(ctx context.Context, actor Principal, tenant string, members []Member) (err error) {
	defer a.refused(ctx, &err, tenant, actor, "DeleteMembers")
	if tenant == "" {
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
	scopes, principals := memberLocks(members)
	return a.inTx(ctx, tenant, actor, "DeleteMembers", func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		left, err := a.leave(ctx, tx, tenant, members)
		return ChangeEvent{Left: left}, err
	})
}

// leave removes members, each by its group, principal and source, under the change's locks.
func (a *Authorizer) leave(ctx context.Context, tx pgx.Tx, tenant string, members []Member) ([]Member, error) {
	n := len(members)
	groups, principals, sources := make([]string, n), make([]string, n), make([]string, n)
	for i, m := range members {
		groups[i], principals[i], sources[i] = m.Group, m.Principal.key(), m.Source
	}
	return removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant,
		"(group_id, principal, source) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))", groups, principals, sources)
}

// Members lists a group's members in force, as stored: identities and groups, not the members of
// the groups in it. An identity whose membership of the tenant ended is in none of its groups.
func (a *Authorizer) Members(ctx context.Context, tenant, group string) ([]Member, error) {
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
// the tenant ended is in none.
func (a *Authorizer) GroupsOf(ctx context.Context, tenant string, p Principal) ([]string, error) {
	rows, err := a.db.Query(ctx, `
		WITH RECURSIVE g(id) AS (
		  SELECT group_id FROM rbac_members WHERE tenant = $1 AND principal = $2 AND (expires_at IS NULL OR expires_at > $3)
		    AND ($4 OR `+inTenant("$2", "$1", "$3")+`)
		  UNION
		  SELECT m.group_id FROM rbac_members m JOIN g ON m.principal = 'group:' || g.id
		  WHERE m.tenant = $1 AND (m.expires_at IS NULL OR m.expires_at > $3)
		)
		SELECT id FROM g ORDER BY id`, tenant, p.key(), a.cfg.Now(), p.Kind == Group)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// strongHold refuses granting, or making eligible, a privileged role to the tenant's members or a
// group that isn't privileged, through which it gives nothing: read under the change's locks on
// the groups, whose mark never changes.
func strongHold(ctx context.Context, q DB, tenant string, roles book, bs []Binding) error {
	refuse := func(b Binding) error {
		return &InvalidError{Binding: b, Reason: fmt.Sprintf("%s is privileged, and a privileged role is held only by identities and privileged groups", b.Role)}
	}
	var errs []error
	byGroup := map[string][]Binding{}
	for _, b := range bs {
		def, ok := roles.role(b.Role)
		switch {
		case !ok || !def.Privileged:
		case b.Principal.broad():
			errs = append(errs, refuse(b))
		case b.Principal.Kind == Group:
			byGroup[b.Principal.ID] = append(byGroup[b.Principal.ID], b)
		}
	}
	if len(byGroup) > 0 {
		ids := slices.Sorted(maps.Keys(byGroup))
		privileged, err := privilegedGroups(ctx, q, tenant, ids)
		if err != nil {
			return err
		}
		for _, g := range ids {
			if privileged[g] {
				continue
			}
			for _, b := range byGroup[g] {
				errs = append(errs, refuse(b))
			}
		}
	}
	return errors.Join(errs...)
}

// heldStrongly refuses making a custom role privileged while the tenant's members or a group that
// isn't privileged hold it, granted or eligible, through which it would then give nothing.
func heldStrongly(ctx context.Context, q DB, tenant string, role Role, now time.Time) error {
	var who string
	// The LIKE matches the partial indexes on custom roles' grants and eligibilities.
	err := q.QueryRow(ctx, `
		SELECT principal FROM (
		  SELECT principal, principal_kind, principal_id FROM rbac_grants
		  WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%' AND (expires_at IS NULL OR expires_at > $3)
		  UNION ALL
		  SELECT principal, principal_kind, principal_id FROM rbac_eligibilities
		  WHERE tenant = $1 AND role = $2 AND role LIKE 'custom.%' AND (expires_at IS NULL OR expires_at > $3)
		) h
		WHERE principal_kind = 'members' OR principal_kind = 'group'
		  AND NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = h.principal_id AND privileged)
		ORDER BY principal LIMIT 1`, tenant, string(role), now).Scan(&who)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%w: %s would be privileged, and %s holds it: a privileged role is held only by identities and privileged groups, so revoke it first", ErrInvalid, role, who)
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
// with that id.
func groupsExist(ctx context.Context, q DB, tenant string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	var missing string
	err := q.QueryRow(ctx, `SELECT k FROM unnest($2::text[]) AS k
		WHERE NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = substr(k, length('group:') + 1))
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
