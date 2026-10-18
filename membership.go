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
// tenant.
const ManageGroups Permission = "tenant:groups"

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

// checkMembership returns why a membership can't be stored at now.
func (a *Authorizer) checkMembership(m Membership, now time.Time) error {
	var errs []string
	if !a.acts(m.Principal.Kind) || m.Principal.ID == "" {
		errs = append(errs, "only an identity, a user or a declared kind, is a member of a tenant")
	}
	if reason := checkSource(m.Source); reason != "" {
		errs = append(errs, reason)
	}
	if !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(now) {
		errs = append(errs, "already expired")
	}
	if !validNote(m.Note) {
		errs = append(errs, fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: membership of %s: %s", ErrInvalid, m.Principal.key(), strings.Join(errs, "; "))
	}
	return nil
}

// SetMemberships makes identities members or guests of a tenant, or changes how, as actor: the
// host's own write, without the checks a change by a tenant's admins has, as Import is for grants.
// It reports the memberships it set or changed.
func (a *Authorizer) SetMemberships(ctx context.Context, actor Principal, tenant string, ms []Membership) error {
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
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, nil, keys); err != nil {
			return ChangeEvent{}, err
		}
		rows, err := tx.Query(ctx, `
			INSERT INTO rbac_memberships AS m (tenant, principal_kind, principal_id, guest, suspended, source, expires_at, note,
			  created_by, updated_by)
			SELECT $1, k, i, g, s, src, e, n, $9, $9
			FROM unnest($2::text[], $3::text[], $4::bool[], $5::bool[], $6::text[], $7::timestamptz[], $8::text[]) AS t(k, i, g, s, src, e, n)
			ON CONFLICT (tenant, principal) DO UPDATE SET guest = EXCLUDED.guest, suspended = EXCLUDED.suspended,
			  source = EXCLUDED.source, expires_at = EXCLUDED.expires_at, note = EXCLUDED.note,
			  updated_by = EXCLUDED.updated_by, updated_at = now()
			WHERE (m.guest, m.suspended, m.source, m.expires_at, m.note)
			  IS DISTINCT FROM (EXCLUDED.guest, EXCLUDED.suspended, EXCLUDED.source, EXCLUDED.expires_at, EXCLUDED.note)
			RETURNING `+membershipColumns,
			tenant, kinds, ids, guests, suspended, sources, expires, notes, actorKey(actor))
		if err != nil {
			return ChangeEvent{}, err
		}
		changed, err := collectMemberships(rows)
		return ChangeEvent{Memberships: changed}, err
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
func (a *Authorizer) SetGroup(ctx context.Context, actor Subject, tenant string, g GroupDefinition) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	if err := a.mayManageGroups(ctx, a.db, actor, root, true); err != nil {
		return err
	}
	if err := checkGroup(g); err != nil {
		return err
	}
	if a.owned[g.Source] {
		return fmt.Errorf("%w: group %q: only the host makes groups from %s, through ImportGroups", ErrInvalid, g.ID, g.Source)
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, tenant, []string{groupKey(g.ID)}, nil); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayManageGroups(ctx, tx, actor, root, false); err != nil {
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
func (a *Authorizer) ImportGroups(ctx context.Context, actor Principal, tenant string, groups []GroupDefinition) error {
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
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
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

// DeleteGroup deletes a tenant's group, as actor, who needs ManageGroups on the tenant, and with it
// its members and its place in other groups. It refuses a group that holds grants or
// eligibilities, which revoking first shows, and one from a source the host owns. Deleting a group
// that doesn't exist does nothing.
func (a *Authorizer) DeleteGroup(ctx context.Context, actor Subject, tenant, id string) error {
	if tenant == "" {
		return fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(actor); err != nil {
		return err
	}
	root := Resource{Tenant: tenant, Type: TenantScope, ID: tenant}
	if err := a.mayManageGroups(ctx, a.db, actor, root, true); err != nil {
		return err
	}
	return a.inTx(ctx, tenant, actor.Principal, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lock(ctx, tx, tenant, []string{groupKey(id), nestingKey}, []string{groupPrincipal(id).key()}); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.mayManageGroups(ctx, tx, actor, root, false); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.notOwnedGroups(ctx, tx, tenant, []string{id}); err != nil {
			return ChangeEvent{}, err
		}
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE tenant = $1 AND principal = $2)
			OR EXISTS (SELECT FROM rbac_eligibilities WHERE tenant = $1 AND principal = $2)`,
			tenant, groupPrincipal(id).key()).Scan(&held); err != nil {
			return ChangeEvent{}, err
		}
		if held {
			return ChangeEvent{}, fmt.Errorf("%w: group %q holds grants or eligibilities: revoke them first", ErrInvalid, id)
		}
		return a.removeGroups(ctx, tx, tenant, []string{id})
	})
}

// DeleteGroups deletes a tenant's groups, as actor: the host's own write, as for a directory it
// syncs from. With each go its members, its place in other groups, and its grants and
// eligibilities.
func (a *Authorizer) DeleteGroups(ctx context.Context, actor Principal, tenant string, ids []string) error {
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
	scopes, principals := []string{nestingKey}, make([]string, len(ids))
	for i, id := range ids {
		scopes = append(scopes, groupKey(id))
		principals[i] = groupPrincipal(id).key()
	}
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, scopes, principals); err != nil {
			return ChangeEvent{}, err
		}
		revoked, err := a.remove(ctx, tx, tenant, "principal = ANY($2::text[])", principals)
		if err != nil {
			return ChangeEvent{}, err
		}
		ended, err := a.removeEligible(ctx, tx, tenant, "principal = ANY($2::text[])", principals)
		if err != nil {
			return ChangeEvent{}, err
		}
		e, err := a.removeGroups(ctx, tx, tenant, ids)
		e.Revoked, e.Ineligible = revoked, ended
		return e, err
	})
}

// removeGroups deletes groups with the members they have and their places in other groups, and
// returns what it removed for OnChange.
func (a *Authorizer) removeGroups(ctx context.Context, tx pgx.Tx, tenant string, ids []string) (ChangeEvent, error) {
	var e ChangeEvent
	principals := make([]string, len(ids))
	for i, id := range ids {
		principals[i] = groupPrincipal(id).key()
	}
	var err error
	if e.Left, err = removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant,
		"(group_id = ANY($2::text[]) OR principal = ANY($3::text[]))", ids, principals); err != nil {
		return ChangeEvent{}, err
	}
	rows, err := tx.Query(ctx, `DELETE FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[]) RETURNING `+groupColumns, tenant, ids)
	if err != nil {
		return ChangeEvent{}, err
	}
	e.DeletedGroups, err = collectGroups(rows)
	return e, err
}

// notOwnedGroups refuses changing groups from a source the host owns, which only it changes.
func (a *Authorizer) notOwnedGroups(ctx context.Context, tx pgx.Tx, tenant string, ids []string) error {
	if len(a.owned) == 0 {
		return nil
	}
	var id, source string
	err := tx.QueryRow(ctx, `SELECT id, source FROM rbac_groups WHERE tenant = $1 AND id = ANY($2::text[]) AND source = ANY($3::text[])
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
func (a *Authorizer) mayManageGroups(ctx context.Context, q DB, actor Subject, root Resource, constraints bool) error {
	scope := root.Scope()
	if actor.Principal == (Principal{}) {
		return &DeniedError{Permission: ManageGroups, Scope: scope, Reason: "an anonymous subject changes nothing"}
	}
	if constraints {
		name, err := a.denied(ctx, ConstraintInput{Tenant: root.Tenant, ResourceType: TenantScope, Permission: ManageGroups, Subject: &actor, Resource: &root})
		if err != nil {
			return err
		}
		if name != "" {
			return &DeniedError{Permission: ManageGroups, Scope: scope, Reason: "removed by " + name}
		}
	}
	au, err := a.authorityOn(ctx, q, actor, root, nil)
	if err != nil {
		return err
	}
	if !au.may(ManageGroups, TenantScope) {
		return &DeniedError{Permission: ManageGroups, Scope: scope, Reason: "the actor may not manage groups here"}
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
	if reason := checkSource(m.Source); reason != "" {
		errs = append(errs, reason)
	}
	if !m.ExpiresAt.IsZero() && !m.ExpiresAt.After(now) {
		errs = append(errs, "already expired")
	}
	if !validNote(m.Note) {
		errs = append(errs, fmt.Sprintf("a note is text of at most %d characters", MaxNote))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s in group %q: %s", ErrInvalid, m.Principal.key(), m.Group, strings.Join(errs, "; "))
	}
	return nil
}

// ImportMembers adds members to a tenant's groups, from their sources, or changes their expiry or
// note, as actor: the host's own write, as for a directory it syncs from. A member identity is a
// member or guest of the tenant, and a member group exists; nesting a group can't make one contain
// itself, nor a chain of more than MaxGroupDepth groups.
func (a *Authorizer) ImportMembers(ctx context.Context, actor Principal, tenant string, members []Member) error {
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
		return err
	}
	set := slices.SortedFunc(maps.Values(byKey), func(x, y Member) int {
		return strings.Compare(x.Group+"\x00"+x.Principal.key()+"\x00"+x.Source, y.Group+"\x00"+y.Principal.key()+"\x00"+y.Source)
	})
	groups, identities, nested := map[string]bool{}, map[string]bool{}, false
	scopes, principals := map[string]bool{}, map[string]bool{}
	for _, m := range set {
		groups[m.Group] = true
		scopes[groupKey(m.Group)] = true
		principals[m.Principal.key()] = true
		if m.Principal.Kind == Group {
			groups[m.Principal.ID], nested = true, true
		} else {
			identities[m.Principal.key()] = true
		}
	}
	if nested {
		scopes[nestingKey] = true
	}
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, slices.Collect(maps.Keys(scopes)), slices.Collect(maps.Keys(principals))); err != nil {
			return ChangeEvent{}, err
		}
		if err := a.membersCanJoin(ctx, tx, tenant, slices.Sorted(maps.Keys(groups)), slices.Sorted(maps.Keys(identities))); err != nil {
			return ChangeEvent{}, err
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
			return ChangeEvent{}, err
		}
		joined, err := collectMembers(rows)
		if err != nil {
			return ChangeEvent{}, err
		}
		if nested {
			for _, m := range set {
				if m.Principal.Kind == Group {
					if err := a.nestable(ctx, tx, tenant, m.Group, m.Principal.ID); err != nil {
						return ChangeEvent{}, err
					}
				}
			}
		}
		return ChangeEvent{Joined: joined}, nil
	})
}

// membersCanJoin refuses members of groups that don't exist, or identities that aren't members or
// guests of the tenant, read under the change's locks.
func (a *Authorizer) membersCanJoin(ctx context.Context, tx pgx.Tx, tenant string, groups, identities []string) error {
	rows, err := tx.Query(ctx, `
		SELECT 'group ' || g FROM unnest($2::text[]) AS g WHERE NOT EXISTS (SELECT FROM rbac_groups WHERE tenant = $1 AND id = g)
		UNION ALL
		SELECT 'identity ' || p FROM unnest($3::text[]) AS p WHERE NOT EXISTS (
		  SELECT FROM rbac_memberships WHERE tenant = $1 AND principal = p AND (expires_at IS NULL OR expires_at > $4))
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

// nestable refuses group inner in group outer, as stored, when it makes a group contain itself, or
// a chain of more than MaxGroupDepth groups: the groups under inner, inner and outer, and those
// outer is in. It reads at most MaxGroupDepth levels each way, which a chain that long or a cycle
// passes.
func (a *Authorizer) nestable(ctx context.Context, tx pgx.Tx, tenant, outer, inner string) error {
	var below, above int
	var cycle bool
	err := tx.QueryRow(ctx, `
		WITH RECURSIVE down(id, depth) AS (
		  SELECT $3::text COLLATE "C", 0
		  UNION
		  SELECT m.principal_id, d.depth + 1 FROM rbac_members m JOIN down d ON m.group_id = d.id
		  WHERE m.tenant = $1 AND m.principal_kind = 'group' AND (m.expires_at IS NULL OR m.expires_at > $4) AND d.depth <= $5
		), up(id, depth) AS (
		  SELECT $2::text COLLATE "C", 0
		  UNION
		  SELECT m.group_id, u.depth + 1 FROM rbac_members m JOIN up u ON m.principal = 'group:' || u.id
		  WHERE m.tenant = $1 AND (m.expires_at IS NULL OR m.expires_at > $4) AND u.depth <= $5
		)
		SELECT (SELECT max(depth) FROM down), (SELECT max(depth) FROM up), EXISTS (SELECT FROM down WHERE id = $2)`,
		tenant, outer, inner, a.cfg.Now(), MaxGroupDepth).Scan(&below, &above, &cycle)
	switch {
	case err != nil:
		return err
	case cycle:
		return fmt.Errorf("%w: group %q in %q would make a group contain itself", ErrInvalid, inner, outer)
	case below+above+2 > MaxGroupDepth:
		return fmt.Errorf("%w: group %q in %q would make a chain of more than %d groups", ErrInvalid, inner, outer, MaxGroupDepth)
	}
	return nil
}

// DeleteMembers removes members from a tenant's groups, each by its group, principal and source,
// as actor: the host's own write, as for a directory it syncs from.
func (a *Authorizer) DeleteMembers(ctx context.Context, actor Principal, tenant string, members []Member) error {
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
	n := len(members)
	groups, principals, sources := make([]string, n), make([]string, n), make([]string, n)
	scopes, keys := map[string]bool{}, map[string]bool{}
	for i, m := range members {
		groups[i], principals[i], sources[i] = m.Group, m.Principal.key(), m.Source
		scopes[groupKey(m.Group)] = true
		keys[m.Principal.key()] = true
	}
	return a.inTx(ctx, tenant, actor, func(tx pgx.Tx) (ChangeEvent, error) {
		if err := lockAll(ctx, tx, tenant, slices.Collect(maps.Keys(scopes)), slices.Collect(maps.Keys(keys))); err != nil {
			return ChangeEvent{}, err
		}
		left, err := removed(ctx, a, tx, "rbac_members", memberColumns, collectMembers, tenant,
			"(group_id, principal, source) IN (SELECT * FROM unnest($2::text[], $3::text[], $4::text[]))", groups, principals, sources)
		return ChangeEvent{Left: left}, err
	})
}

// Members lists a group's members in force, as stored: identities and groups, not the members of
// the groups in it.
func (a *Authorizer) Members(ctx context.Context, tenant, group string) ([]Member, error) {
	rows, err := a.db.Query(ctx, `SELECT `+memberColumns+` FROM rbac_members
		WHERE tenant = $1 AND group_id = $2 AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY principal, source`, tenant, group, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectMembers(rows)
}

// GroupsOf lists the groups a principal is in in a tenant, by id: those it is a member of, and
// those they are in, to the top, as memberships are in force now.
func (a *Authorizer) GroupsOf(ctx context.Context, tenant string, p Principal) ([]string, error) {
	rows, err := a.db.Query(ctx, `
		WITH RECURSIVE g(id) AS (
		  SELECT group_id FROM rbac_members WHERE tenant = $1 AND principal = $2 AND (expires_at IS NULL OR expires_at > $3)
		  UNION
		  SELECT m.group_id FROM rbac_members m JOIN g ON m.principal = 'group:' || g.id
		  WHERE m.tenant = $1 AND (m.expires_at IS NULL OR m.expires_at > $3)
		)
		SELECT id FROM g ORDER BY id`, tenant, p.key(), a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
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
