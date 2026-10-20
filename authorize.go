package rbac

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Decision is why a check came out as it did.
type Decision struct {
	Allowed bool
	// Grants are the subject's grants that give the permission.
	Grants []Grant
	// DeniedBy names the constraint or deny policy that removed the permission.
	DeniedBy string
	// Label is the dimension of the resource's label the subject's holding doesn't satisfy, which
	// denied what its grants allowed.
	Label string
	// Reason says why it was denied, in English, for logs.
	Reason string
}

// Authorize returns nil when the subject may do p to r, and otherwise an error matching
// ErrDenied, or ErrInvalid for malformed input, such as a permission or resource type the host
// doesn't check (Config.Permissions), which can only be a mistake. Any error means no.
func (a *Authorizer) Authorize(ctx context.Context, s Subject, p Permission, r Resource) error {
	d, err := a.decide(ctx, s, p, r, false)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return &DeniedError{Permission: p, Scope: r.Scope(), Reason: d.Reason}
	}
	return nil
}

// Explain decides as Authorize does and says why: the grants that give the permission, or what
// denied it.
func (a *Authorizer) Explain(ctx context.Context, s Subject, p Permission, r Resource) (Decision, error) {
	return a.decide(ctx, s, p, r, true)
}

// decide decides as Authorize does, and with explain, says why: the grants, and then the
// resource's label, which allows nothing its holding doesn't satisfy.
func (a *Authorizer) decide(ctx context.Context, s Subject, p Permission, r Resource, explain bool) (Decision, error) {
	d, err := a.decideGrants(ctx, s, p, r, explain)
	if err != nil || !d.Allowed {
		return d, err
	}
	value, exclusive := a.exclusiveValue(p)
	if !exclusive && !r.Labels.asks() {
		return d, nil
	}
	h, _, err := a.holding(ctx, r.Tenant, s)
	if err != nil {
		return Decision{}, err
	}
	if h.excludes(p) {
		return Decision{Reason: exclusiveRefusal(value)}, nil
	}
	if dim := h.Unsatisfied(r.Labels); dim != "" {
		return Decision{Label: dim, Reason: labelRefusal(dim)}, nil
	}
	return d, nil
}

// exclusiveRefusal is why a check refuses a value of dim, an exclusive dimension.
func exclusiveRefusal(dim string) string {
	return "its grants could give it two values of " + dim + ", whose values are exclusive, so it holds none"
}

func (a *Authorizer) decideGrants(ctx context.Context, s Subject, p Permission, r Resource, explain bool) (Decision, error) {
	if err := a.check(r); err != nil {
		return Decision{}, err
	}
	if err := a.askable(p, r.Type); err != nil {
		return Decision{}, err
	}
	if err := a.subject(s); err != nil {
		return Decision{}, err
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Subject: &s, Resource: &r})
	if err != nil {
		return Decision{}, err
	}
	if name != "" {
		return Decision{DeniedBy: name, Reason: "removed by " + name}, nil
	}

	counts := a.counting(p, r.Type)
	if !explain {
		return a.decideHeld(ctx, s, p, r, counts)
	}

	// Explain reads the subject's groups apart from its grants and denies, so in one snapshot, as
	// Authorize reads them in one statement.
	return snapshot(ctx, a, func(a *Authorizer) (Decision, error) { return a.explain(ctx, s, p, r, counts) })
}

// readingRoles runs once a read has read grants and the custom roles with them, as a
// test's change that commits there.
var readingRoles = func() {}

// decideHeld is Authorize's decision once no constraint removes p, from s's grants and denies and
// the custom roles they name, read in one statement.
func (a *Authorizer) decideHeld(ctx context.Context, s Subject, p Permission, r Resource, counts broad) (Decision, error) {
	held, ds, roles, err := a.heldOrDenied(ctx, a.db, r.Tenant, s, counts, r.path(), p, namedRoles, false)
	if err != nil {
		return Decision{}, err
	}
	readingRoles()
	// What conditions read is built only for a check that reads one, so one a grant decides
	// builds none of it.
	var vars map[string]any
	if len(ds) > 0 {
		vars = a.vars(ctx, s, p, r)
		// A deny decides first, as it binds every grant.
		if d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()), vars); ok {
			return Decision{DeniedBy: d.String(), Reason: d.removal()}, nil
		}
	}
	var conditional []holding
	for _, h := range held {
		if !gives(roles, h, p, r.Type) {
			continue
		}
		if !h.conditional {
			return Decision{Allowed: true}, nil
		}
		conditional = append(conditional, h)
	}
	if len(conditional) == 0 {
		return Decision{Reason: "no grant gives it"}, nil
	}
	// Only now, with no unconditional grant to allow, are conditions read and evaluated.
	if err := a.conditionsOf(ctx, a.db, r.Tenant, conditional); err != nil {
		return Decision{}, err
	}
	if vars == nil {
		vars = a.vars(ctx, s, p, r)
	}
	spend := newGrantBudget(r.path())
	cheapestFirst(conditional, holding.expression)
	for _, h := range conditional {
		if a.conds.holds(spend, h.Condition.Expression, vars) {
			return Decision{Allowed: true}, nil
		}
	}
	return Decision{Reason: unmet(spend)}, nil
}

// explain is Explain's decision once no constraint removes p: every grant that allows it, or why
// none does.
func (a *Authorizer) explain(ctx context.Context, s Subject, p Permission, r Resource, counts broad) (Decision, error) {
	vars, spend := a.vars(ctx, s, p, r), newGrantBudget(r.path())
	keys, binding, err := a.keysOf(ctx, a.db, r.Tenant, s)
	if err != nil {
		return Decision{}, err
	}
	principals := countedOf(keys, counts)
	// As Authorize, which reads no deny for a subject none of whose grants can give p.
	if len(principals) > 0 {
		ds, err := a.deniesOn(ctx, a.db, r.Tenant, binding, exempting(keys, s), r.path(), p)
		if err != nil {
			return Decision{}, err
		}
		if d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()), vars); ok {
			return Decision{DeniedBy: d.String(), Reason: d.removal()}, nil
		}
	}
	grants, err := a.heldGrants(ctx, a.db, r.Tenant, principals, r.path())
	if err != nil {
		return Decision{}, err
	}
	roles, err := a.book(ctx, a.db, r.Tenant, roleIDs(grants))
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Reason: "no grant gives it"}
	grants = slices.DeleteFunc(grants, func(g Grant) bool {
		return !gives(roles, holding{Binding: g.Binding}, p, r.Type)
	})
	// Evaluated in the order Authorize evaluates them, so a budget runs out where it does for it.
	byCost := slices.Clone(grants)
	cheapestFirst(byCost, Grant.expression)
	held := map[string]bool{}
	for _, g := range byCost {
		held[g.ID] = g.Condition.Expression == "" || a.conds.holds(spend, g.Condition.Expression, vars)
	}
	for _, g := range grants {
		if !held[g.ID] {
			d.Reason = unmet(spend)
			continue
		}
		d.Grants = append(d.Grants, g)
	}
	if len(d.Grants) > 0 {
		d.Allowed, d.Reason = true, ""
	}
	return d, nil
}

// askable returns why p on a resource type isn't something the host checks (Config.Permissions):
// p is malformed or not a permission it has, or the type isn't one a built-in role or one of its
// permissions is for. Such a question is a typo, not a refusal, so it is invalid, as SetRole and
// SetDeny find one in a role or a deny.
func (a *Authorizer) askable(p Permission, resourceType string) error {
	switch {
	case !p.Valid():
		return fmt.Errorf("%w: permission %q is not `type:verb`", ErrInvalid, p)
	case !a.checked[p]:
		return fmt.Errorf("%w: permission %q is not one the host checks", ErrInvalid, p)
	case !a.checkedTypes[resourceType]:
		return fmt.Errorf("%w: resource type %q is not one the host checks", ErrInvalid, resourceType)
	}
	return nil
}

// scopeOf returns why r's type is no scope the host has: not a resource type a check may name, a
// container's or the tenant's, so nothing could be done to it or granted on it.
func (a *Authorizer) scopeOf(r Resource) error { return a.scopeType(r.Type) }

// scopeType is scopeOf for a scope's type. A type the catalog no longer has stays one while
// Config.Permissions lists a permission of it, so what is stored on it can still be removed.
func (a *Authorizer) scopeType(t string) error {
	if !a.checkedTypes[t] && !a.contains(t) {
		return fmt.Errorf("%w: resource type %q is not one the host checks", ErrInvalid, t)
	}
	return nil
}

// unmet is why no conditional grant allowed, given what is left of the check's budget.
func unmet(spend *budget) string {
	if spend.exhausted {
		return "the conditions of the grants that give it cost more than a check may spend"
	}
	return "no condition of a grant that gives it holds"
}

// gives reports whether a grant held as h gives p on a resource type. A role that no longer
// exists gives nothing.
func gives(roles book, h holding, p Permission, resourceType string) bool {
	def, ok := roles.role(h.Role)
	return ok && def.GrantableOn(resourceType) && def.Gives(p) && h.carries(def, p)
}

// carries reports whether a grant held as h gives p, which def gives: as its principal carries
// it, and for a privileged role never through the tenant's members or the public, so a catalog
// change that makes a role privileged reaches what they hold.
func (h holding) carries(def RoleDefinition, p Permission) bool {
	return h.Principal.carries(def, p) && (!h.Principal.broad() || !def.Privileged)
}

// Permissions lists what the subject may do to r, sorted: the AuthZEN action search.
func (a *Authorizer) Permissions(ctx context.Context, s Subject, r Resource) ([]Permission, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if err := a.scopeOf(r); err != nil {
		return nil, err
	}
	if err := a.subject(s); err != nil {
		return nil, err
	}
	// A label the subject doesn't satisfy leaves it nothing, whatever its grants give.
	if dim, err := a.unsatisfied(ctx, s, r); err != nil || dim != "" {
		return nil, err
	}
	perms, _, excluded, err := a.permissionsOf(ctx, a.db, s, r, nil, a.constrain(ctx, s, r))
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(perms, func(p Permission) bool { t, ok := a.exclusiveValue(p); return ok && excluded[t] }), nil
}

// permissionsOf is what Permissions lists, once its input is checked, of the permissions only
// keeps, or all where it is nil; and of them, those a condition decided, a grant's or a deny's,
// or a constraint asked without the request's attributes, which a read without the request can't
// settle; and the exclusive dimensions s holds none of, as its grants on the tenant could give it
// two (excludedBy). It reads on q, and asks the constraints through cs, which is on r, so a change
// reads them back in its transaction.
func (a *Authorizer) permissionsOf(ctx context.Context, q DB, s Subject, r Resource, only func(Permission) bool, cs *constrained,
) ([]Permission, map[Permission]bool, map[string]bool, error) {
	kept := func(p Permission) bool { return only == nil || only(p) }
	byCondition := map[Permission]bool{}
	held, ds, roles, err := a.heldOrDenied(ctx, q, r.Tenant, s, all, r.path(), "", namedRoles, false)
	if err != nil {
		return nil, nil, nil, err
	}
	readingRoles()
	given := map[Permission]bool{}
	var conditional []holding
	for _, h := range held {
		def, ok := roles.role(h.Role)
		switch {
		case !ok || !def.GrantableOn(r.Type):
		case h.conditional:
			if slices.ContainsFunc(def.Permissions, kept) {
				conditional = append(conditional, h)
			}
		default:
			for _, p := range def.Permissions {
				if kept(p) {
					given[p] = given[p] || h.carries(def, p)
				}
			}
		}
	}
	// What a constraint removes is settled first, so no budget is spent on conditions for it.
	removed := map[Permission]bool{}
	isRemoved := func(p Permission) (bool, error) {
		removed[p] = cs.removes(p, r.Type)
		return removed[p], cs.failed()
	}
	// Each permission is decided as Authorize would decide it, on budgets of its own, which share
	// what conditions came to: one that doesn't read the action runs once for them all.
	vars, spends, ran := a.vars(ctx, s, "", r), map[Permission]*budget{}, map[string]run{}
	spendOn := func(p Permission) *budget {
		if spends[p] == nil {
			spends[p] = newGrantBudget(r.path()).sharing(ran)
		}
		return spends[p]
	}
	// A deny is settled before a grant's condition, as checks settle it. always are those a deny
	// without a condition takes, whatever the request.
	denied, always := map[Permission]bool{}, map[Permission]bool{}
	isDenied := func(p Permission) bool {
		if d, ok := denied[p]; ok {
			return d
		}
		vars["action"] = string(p)
		d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()).sharing(ran), vars)
		denied[p], always[p] = ok, ok && d.condition == ""
		return ok
	}
	// Holders asks a constraint about s without the request's attributes, where it answers true if
	// it removes p with any: what it removes another request may keep, unless a deny takes it
	// whatever the request.
	byConstraint := func(p Permission) {
		if !isDenied(p) || !always[p] {
			byCondition[p] = true
		}
	}
	// Conditions are evaluated only for what no unconditional grant gives, as checks do, the
	// cheapest first.
	if err := a.conditionsOf(ctx, q, r.Tenant, conditional); err != nil {
		return nil, nil, nil, err
	}
	cheapestFirst(conditional, holding.expression)
	for _, h := range conditional {
		def, _ := roles.role(h.Role)
		for _, p := range def.Permissions {
			if given[p] || !kept(p) || !h.carries(def, p) {
				continue
			}
			if gone, err := isRemoved(p); err != nil || gone {
				if err != nil {
					return nil, nil, nil, err
				}
				byConstraint(p)
				continue
			}
			// The grant's condition decides it, or a deny's that takes it first here, which another
			// request may not meet.
			if isDenied(p) {
				if !always[p] {
					byCondition[p] = true
				}
				continue
			}
			byCondition[p] = true
			// A condition reads the action, so it is evaluated for each permission.
			vars["action"] = string(p)
			given[p] = a.conds.holds(spendOn(p), h.Condition.Expression, vars)
		}
	}
	var perms []Permission
	for _, p := range slices.Sorted(maps.Keys(given)) {
		if !given[p] {
			continue
		}
		gone, err := isRemoved(p)
		switch {
		case err != nil:
			return nil, nil, nil, err
		case gone:
			byConstraint(p)
		case !isDenied(p):
			perms = append(perms, p)
		}
	}
	// What is given here, a conditional deny may take under another request, or give back.
	for _, d := range ds {
		if d.condition == "" {
			continue
		}
		for p, ok := range given {
			if ok && !removed[p] && !always[p] && denies(d.permissions, p) {
				byCondition[p] = true
			}
		}
	}
	return perms, byCondition, a.excludedBy(roles, held), nil
}

// Holder is one who may do p to r, as Holders finds it.
type Holder struct {
	// Principal is an identity that is a member or guest of the tenant, or the tenant's members or
	// the public, each as one holder rather than every one of them.
	Principal Principal
	// Grants are the ids of the grants that give it p: an identity's own and its groups', and the
	// members' or the public's theirs.
	Grants []string
	// Groups are the groups whose grants give an identity p, by id: those granted, which it is in
	// directly or through others.
	Groups []string
	// Conditional is set when every grant giving it p has a condition, so whether it may depends on
	// the request.
	Conditional bool
	// MaybeDenied is set when a deny on the path may bind it: one whose condition depends on the
	// request, or for the members or the public one that may bind some of them; and when a
	// constraint may remove the permission from it. It is set too when the resource's label may
	// refuse it: where a condition, or a constraint as Holders asks it, decides its label values,
	// and for the members or the public, who hold values each their own; as it is for them where p
	// is a value of an exclusive dimension, which some of them may hold none of.
	MaybeDenied bool
}

// Holders lists who may do p to r, the AuthZEN subject search, for an access review: every
// identity a member or guest of the tenant, not suspended, that a grant on r's path gives p, its own
// or through its groups', and the tenant's members and the public where grants to them give it. It
// counts conditional grants and marks them, and leaves out a holder a deny on the path binds,
// marking one that a deny may bind: it reads the groups a deny names, and whom it exempts, as
// checks do. Where a constraint may remove p, it marks each holder it may remove p from, asked
// about as ConstraintInput says. An identity's record counts its own grants and its groups', not
// the members' or the public's, which are records of their own. It has no limit or cursor, so what
// it returns grows with the holders, as every identity in a group granted on the tenant; and it
// reads every grant on the path, of any role, so it takes longer with those that don't give p too,
// as many to other members on the tenant.
func (a *Authorizer) Holders(ctx context.Context, p Permission, r Resource) ([]Holder, error) {
	if err := a.check(r); err != nil {
		return nil, err
	}
	if err := a.askable(p, r.Type); err != nil {
		return nil, err
	}
	removed, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Resource: &r})
	if err != nil {
		return nil, err
	}
	roles, custom := a.giving(p, r.Type), a.customGives(p, r.Type)
	if len(roles) == 0 && !custom {
		return nil, nil
	}
	holders, err := snapshot(ctx, a, func(a *Authorizer) ([]Holder, error) { return a.holders(ctx, p, r, roles, custom) })
	if err == nil && removed != "" {
		holders, err = a.constrained(ctx, p, r, holders)
	}
	if _, exclusive := a.exclusiveValue(p); err != nil || !r.Labels.asks() && !exclusive {
		return holders, err
	}
	return a.labeled(ctx, p, r, holders)
}

// constrained marks MaybeDenied the holders a constraint may remove p from, where one may remove
// it from some: each identity as the constraint answers about it, as itself without the attributes
// Holders doesn't know, true if it removes p with any, and the tenant's members and the public,
// whose people a constraint tells apart. As for a deny whose condition reads the request, Holders
// can't tell whom a check would refuse, so it lists them all.
func (a *Authorizer) constrained(ctx context.Context, p Permission, r Resource, holders []Holder) ([]Holder, error) {
	for i, h := range holders {
		// One a deny already marks, the hooks needn't be asked about.
		if h.Principal.broad() || h.MaybeDenied {
			holders[i].MaybeDenied = true
			continue
		}
		name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Subject: &Subject{Principal: h.Principal}, Resource: &r})
		if err != nil {
			return nil, err
		}
		holders[i].MaybeDenied = name != ""
	}
	return holders, nil
}

// labeled keeps of holders those whose holding satisfies r's label whatever the request, and
// where p is a value of an exclusive dimension, holds it: one that satisfies it only with the
// values a condition or a constraint decided, which a read without the request can't settle, is
// marked MaybeDenied, as the members and the public are, whose people hold apart, unless their own
// grants leave none of them able to (broadExcludes); and one that doesn't even then, or holds none
// of p's dimension, is left out. Each identity's holding is read after the list, as its
// constraints run as for any read.
func (a *Authorizer) labeled(ctx context.Context, p Permission, r Resource, holders []Holder) ([]Holder, error) {
	kept := holders[:0]
	for _, h := range holders {
		if h.Principal.broad() {
			out, err := a.broadExcludes(ctx, r.Tenant, h.Principal, p, r.Labels)
			if err != nil {
				return nil, err
			}
			if !out {
				h.MaybeDenied = true
				kept = append(kept, h)
			}
			continue
		}
		holding, byCondition, err := a.holding(ctx, r.Tenant, Subject{Principal: h.Principal})
		if err != nil {
			return nil, err
		}
		switch {
		case holding.excludes(p):
		case holding.changed(byCondition, false).Satisfies(r.Labels):
			kept = append(kept, h)
		case holding.changed(byCondition, true).Satisfies(r.Labels):
			h.MaybeDenied = true
			kept = append(kept, h)
		}
	}
	return kept, nil
}

// holders is Holders' list once no constraint removes p, for the built-in roles that give it, and
// custom ones too where custom.
func (a *Authorizer) holders(ctx context.Context, p Permission, r Resource, roles []string, custom bool) ([]Holder, error) {
	// One time for every statement, as one snapshot, so a grant, a membership or a group's member
	// ending between them can't leave a holder that no single moment had.
	now := a.cfg.Now()
	args := append(append([]any{
		r.Tenant, r.path(), roles, now, p.managesAccess(),
		broadKinds,
		string(p), r.Type, a.publicRoles(roles), string(Public),
	}, a.publicArgs(p, r.Type, custom)...), append([]any{a.privilegedRoles(roles)}, a.catalogArgs(custom)...)...)
	// A privileged role gives nothing through the tenant's members or the public.
	rows, err := a.db.Query(ctx, byKey("$2", "rbac_grants", "scope", "id::text, principal_kind, principal_id, conditional", `
		  tenant = $1 AND role = ANY(`+givingSQL("$3", "$1", "$7", "$8", custom, "")+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND (NOT $5 OR principal_kind <> ALL($6::text[]))
		  AND (principal_kind <> $10 OR role = ANY(`+givingSQL("$9", "$1", "$7", "$8", custom, publicOnly(catalogSQL{"$11", "$12", "$13"}))+`))
		  AND (principal_kind <> ALL($6::text[])
		    OR role <> ALL(`+givingSQL("$14", "$1", "$7", "$8", custom, privilegedOnly(catalogSQL{"$15", "$16", "$17"}))+`))`)+`
		ORDER BY principal_kind, principal_id, id`, args...)
	if err != nil {
		return nil, err
	}
	type held struct {
		id          string
		p           Principal
		conditional bool
	}
	grants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (held, error) {
		var g held
		err := row.Scan(&g.id, &g.p.Kind, &g.p.ID, &g.conditional)
		return g, err
	})
	if err != nil {
		return nil, err
	}
	// A grant to the public gives nothing where no public role can give p, as checks read it.
	public := a.publicGives(p, r.Type)
	byPrincipal := map[string]*Holder{}
	holder := func(p Principal) *Holder {
		if byPrincipal[p.key()] == nil {
			byPrincipal[p.key()] = &Holder{Principal: p, Conditional: true}
		}
		return byPrincipal[p.key()]
	}
	add := func(h *Holder, g held) {
		if !slices.Contains(h.Grants, g.id) {
			h.Grants = append(h.Grants, g.id)
		}
		h.Conditional = h.Conditional && g.conditional
	}
	var groups []string
	byGroup, direct := map[string][]held{}, map[string][]held{}
	for _, g := range grants {
		switch {
		case g.p.Kind == Public && !public:
		case g.p.Kind == Group:
			if byGroup[g.p.ID] == nil {
				groups = append(groups, g.p.ID)
			}
			byGroup[g.p.ID] = append(byGroup[g.p.ID], g)
		case g.p.broad():
			add(holder(g.p), g)
		default:
			direct[g.p.key()] = append(direct[g.p.key()], g)
		}
	}
	identities := slices.Sorted(maps.Keys(direct))
	// The identities in the groups granted, through those nested in them, and those granted
	// directly, that are members or guests of the tenant now.
	rows, err = a.db.Query(ctx, `
		WITH RECURSIVE `+insideSQL("$2", "$3", "NULL", true)+`
		SELECT root, principal, guest FROM inside
		UNION
		SELECT '', principal, guest FROM rbac_memberships WHERE tenant = $1 AND principal = ANY($4::text[])
		  AND NOT suspended AND (expires_at IS NULL OR expires_at > $3)
		ORDER BY principal, root`, r.Tenant, groups, now, identities)
	if err != nil {
		return nil, err
	}
	guests := map[string]bool{}
	var root, key string
	var guest bool
	if _, err := pgx.ForEachRow(rows, []any{&root, &key, &guest}, func() error {
		who := parsePrincipal(key)
		// A kind the host no longer declares can't act, as checks refuse it as a subject, so
		// neither its grants nor its groups' give it anything.
		if !a.acts(who.Kind) {
			return nil
		}
		h := holder(who)
		guests[key] = guest
		if root == "" {
			for _, g := range direct[key] {
				add(h, g)
			}
			return nil
		}
		if !slices.Contains(h.Groups, root) {
			h.Groups = append(h.Groups, root)
		}
		for _, g := range byGroup[root] {
			add(h, g)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := a.boundByDenies(ctx, p, r, now, byPrincipal, guests); err != nil {
		return nil, err
	}
	found := slices.SortedFunc(maps.Values(byPrincipal), func(x, y *Holder) int { return strings.Compare(x.Principal.key(), y.Principal.key()) })
	holders := make([]Holder, 0, len(found))
	for _, h := range found {
		slices.Sort(h.Groups)
		holders = append(holders, *h)
	}
	return holders, nil
}

// boundByDenies drops from holders those a deny on r's path binds whatever the request, and marks
// those one may bind. It reads the groups a deny names or exempts an identity is in, as checks
// read its groups; guests are the identities that are no tenant member.
func (a *Authorizer) boundByDenies(ctx context.Context, p Permission, r Resource, now time.Time, holders map[string]*Holder, guests map[string]bool) error {
	if len(holders) == 0 {
		return nil
	}
	ds, err := a.deniesOn(ctx, a.db, r.Tenant, nil, nil, r.path(), p)
	if err != nil || len(ds) == 0 {
		return err
	}
	members := TenantMembers(r.Tenant).key()
	keys := map[string][]string{}
	var identities []string
	for k, h := range holders {
		if h.Principal.broad() {
			continue
		}
		identities = append(identities, k)
		keys[k] = []string{k, publicKey}
		if !guests[k] {
			keys[k] = append(keys[k], members)
		}
	}
	// Of an identity's groups only those a deny names or exempts matter, so they are read from
	// those groups down: walking up from every holder reads each one's every group, which on a
	// large tenant costs far more than the list. Of their members only the holders are read, as a
	// deny can name a group far larger than the list.
	seen := map[string]bool{}
	var groups []string
	for _, d := range ds {
		for _, k := range slices.Concat(d.principals, d.exempt) {
			if id, ok := strings.CutPrefix(k, string(Group)+":"); ok && !seen[id] {
				seen[id] = true
				groups = append(groups, id)
			}
		}
	}
	if len(identities) > 0 && len(groups) > 0 {
		rows, err := a.db.Query(ctx, `
			WITH RECURSIVE `+insideSQL("$2", "$3", "$4", false)+`
			SELECT DISTINCT principal, 'group:' || root FROM inside`,
			r.Tenant, groups, now, identities)
		if err != nil {
			return err
		}
		var principal, group string
		if _, err := pgx.ForEachRow(rows, []any{&principal, &group}, func() error {
			keys[principal] = append(keys[principal], group)
			return nil
		}); err != nil {
			return err
		}
	}
	in := func(set map[string]bool, ks []string) bool {
		return slices.ContainsFunc(ks, func(k string) bool { return set[k] })
	}
	for _, d := range ds {
		named, exempt := map[string]bool{}, map[string]bool{}
		for _, k := range d.principals {
			named[k] = true
		}
		for _, k := range d.exempt {
			exempt[k] = true
		}
		for k, h := range holders {
			var binds, whole bool
			switch k {
			case members, publicKey:
				// All of them where the deny names them, or the public, and exempts none; none where
				// it exempts them; otherwise perhaps some.
				binds = !exempt[k]
				whole = (named[k] || named[publicKey]) && len(d.exempt) == 0
			default:
				binds = in(named, keys[k]) && !in(exempt, keys[k])
				whole = binds
			}
			switch {
			case whole && d.condition == "":
				delete(holders, k)
			case binds:
				h.MaybeDenied = true
			}
		}
	}
	return nil
}

// insideSQL is SQL defining, in a WITH RECURSIVE, inside(root, principal, guest): the identities in
// each of the groups, given as SQL for an array of their ids, directly or through groups in it, at
// now, by the same memberships keysSQL reads up from an identity, in the tenant $1; of principals
// alone, SQL for an array of keys or NULL for every one, and with standing, only those that are
// members or guests of the tenant at now, not suspended, with whether each is a guest. The groups
// in groups are few, and each group's are read on its own, as keysSQL reads up; but their
// identities can be many, so they are read by rbac_group_members, which plans for the groups
// reached, as it does what is read with them: planned here, it would be for the thousand rows the
// planner counts a function as.
func insideSQL(groups, now, principals string, standing bool) string {
	return fmt.Sprintf(`down(root, id) AS (
		  SELECT g, g COLLATE "C" FROM unnest(%[1]s::text[]) AS g
		  UNION
		  SELECT d.root, m.principal_id FROM down d CROSS JOIN LATERAL (
		    SELECT principal_id FROM rbac_members WHERE tenant = $1 AND `+groupsIn("d.id")+`
		      AND (expires_at IS NULL OR expires_at > %[2]s) OFFSET 0) m
		), inside(root, principal, guest) AS (
		  SELECT d.root, m.principal COLLATE "C", m.guest FROM down d
		  JOIN rbac_group_members($1, ARRAY(SELECT DISTINCT id FROM down), %[2]s, %[3]s::text[], %[4]t) m ON m.group_id COLLATE "C" = d.id
		)`, groups, now, principals, standing)
}

// groupsIn is SQL for whether a place in a group is a group's in the group g: a range of the key
// index, by group and then principal, written as a row comparison, which no other index seeks. The
// index by principal holds the tenant's places of groups too, and a generic plan, costing both as
// an average tenant's few rows, can read them all by it to find one group's. The range of the
// principal alone lets a plan count the places by its statistics, as few, not as many as the
// average group's members, which in a tenant of a few large groups costs a walk past JIT's
// thresholds.
func groupsIn(g string) string {
	return fmt.Sprintf(`group_id = %[1]s AND principal >= 'group:' AND principal < 'group;'
		AND (group_id, principal) >= (%[1]s, 'group:') AND (group_id, principal) < (%[1]s, 'group;')`, g)
}

// groupsAbove is SQL joining, as m, cols of the places in tenant $1 in force at now of the group
// whose id is g, a group at a time, as keysSQL reads them.
func groupsAbove(g, now, cols string) string {
	return fmt.Sprintf(`CROSS JOIN LATERAL (
		SELECT %[3]s FROM rbac_members WHERE tenant = $1 AND principal = 'group:' || %[1]s
		  AND (expires_at IS NULL OR expires_at > %[2]s) OFFSET 0) m`, g, now, cols)
}

// Reach is where a subject may do something. A resource, by its path (Authorizer.Path), is
// reachable when its path holds none of Except; All is set or its path holds one of Scopes or
// Conditional; Labels satisfies its label (Resource.Labels); and, if its path holds one of
// Conditional or ConditionalExcept, Authorize allows it.
type Reach struct {
	All    bool
	Scopes []Scope
	// Conditional are the scopes only conditional grants reach, which a search can't evaluate:
	// check the resources under them one by one.
	Conditional []Scope
	// Except are the scopes a deny covers: nothing under them is reachable.
	Except []Scope
	// ConditionalExcept are the scopes a conditional deny covers: a resource under one that is
	// otherwise reachable is checked on its own.
	ConditionalExcept []Scope
	// Labels is the subject's holding (Config.Labels): of what the scopes reach, it may do p only
	// to resources whose label the holding satisfies.
	Labels Holding
}

// Reachable says where the subject may do p to resources of a type in a tenant, for hosts that
// list from a store other than this PostgreSQL. Hosts on the same database use Filter. It has no
// limit or cursor, so Reach.Scopes grows with the scopes the subject's grants are on, as one on
// each resource it created.
func (a *Authorizer) Reachable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (Reach, error) {
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil || removed {
		return Reach{}, err
	}
	custom := a.customGives(p, resourceType)
	if len(roles) == 0 && !custom {
		return Reach{}, nil
	}
	reach, err := snapshot(ctx, a, func(a *Authorizer) (Reach, error) {
		return a.reachable(ctx, s, p, tenant, resourceType, roles, custom)
	})
	if err != nil || !reach.All && len(reach.Scopes)+len(reach.Conditional) == 0 {
		return reach, err
	}
	// Outside the snapshot, as its constraints run as for any read.
	reach.Labels, _, err = a.holding(ctx, tenant, s)
	if err != nil || reach.Labels.excludes(p) {
		return Reach{}, err
	}
	return reach, nil
}

// reachable is Reachable's answer once no constraint removes p, for the built-in roles that give
// it, and custom ones too where custom.
func (a *Authorizer) reachable(ctx context.Context, s Subject, p Permission, tenant, resourceType string, roles []string, custom bool) (Reach, error) {
	keys, binding, err := a.keysOf(ctx, a.db, tenant, s)
	if err != nil {
		return Reach{}, err
	}
	principals := countedOf(keys, a.counting(p, resourceType))
	if len(principals) == 0 {
		return Reach{}, nil
	}
	reaching := a.reaching(resourceType)
	args := append(append([]any{
		tenant, principals, roles, a.cfg.Now(), reaching, publicKey, a.publicRoles(roles),
		string(p), resourceType,
	}, a.publicArgs(p, resourceType, custom)...), append([]any{broadKinds, a.privilegedRoles(roles)}, a.catalogArgs(custom)...)...)
	rows, err := a.db.Query(ctx, `
		SELECT scope, bool_and(conditional) FROM (`+byType("$5", "g.scope, g.conditional", `
		  g.tenant = $1 AND g.principal = ANY($2::text[]) AND g.role = ANY(`+givingSQL("$3", "$1", "$8", "$9", custom, "")+`)
		  AND (g.expires_at IS NULL OR g.expires_at > $4)
		  AND (g.principal <> $6 OR g.role = ANY(`+givingSQL("$7", "$1", "$8", "$9", custom, publicOnly(catalogSQL{"$10", "$11", "$12"}))+`))
		  AND (g.principal_kind <> ALL($13::text[]) OR g.role <> ALL(`+givingSQL("$14", "$1", "$8", "$9", custom, privilegedOnly(catalogSQL{"$15", "$16", "$17"}))+`))`)+`) g
		GROUP BY scope ORDER BY scope`, args...)
	if err != nil {
		return Reach{}, err
	}
	var reach Reach
	var key string
	var conditional bool
	if _, err := pgx.ForEachRow(rows, []any{&key, &conditional}, func() error {
		switch {
		case conditional:
			reach.Conditional = append(reach.Conditional, parseScope(key))
		case key == TenantRoot(tenant).Key():
			reach.All = true
		default:
			reach.Scopes = append(reach.Scopes, parseScope(key))
		}
		return nil
	}); err != nil {
		return Reach{}, err
	}
	// A deny only takes away: where no grant reaches, there is nothing to take.
	if !reach.All && len(reach.Scopes)+len(reach.Conditional) == 0 {
		return Reach{}, nil
	}
	// Denies on scopes a resource of the type can have on its path: those of the type, the
	// containers and the tenant.
	if perm, wildcard, deniable := matchable(p); deniable {
		rows, err = a.db.Query(ctx, `
			SELECT scope, bool_or(condition = '') FROM rbac_denies
			WHERE tenant = $1 AND scope_type = ANY($2::text[])
			  AND principals && $3::text[] AND NOT exempt && $6::text[] AND ($4 = ANY(permissions) OR $5 = ANY(permissions))
			GROUP BY scope ORDER BY scope`,
			tenant, reaching, binding, perm, wildcard, exempting(keys, s))
		if err != nil {
			return Reach{}, err
		}
		var always bool
		if _, err := pgx.ForEachRow(rows, []any{&key, &always}, func() error {
			if always {
				reach.Except = append(reach.Except, parseScope(key))
			} else {
				reach.ConditionalExcept = append(reach.ConditionalExcept, parseScope(key))
			}
			return nil
		}); err != nil {
			return Reach{}, err
		}
		if slices.Contains(reach.Except, TenantRoot(tenant)) {
			return Reach{}, nil
		}
	}
	if reach.All {
		reach.Scopes, reach.Conditional = nil, nil
	}
	return reach, nil
}

// searchable returns the built-in roles that give p on a resource type, and whether a
// constraint removes p there.
func (a *Authorizer) searchable(ctx context.Context, s Subject, p Permission, tenant, resourceType string) (roles []string, removed bool, err error) {
	if !validID(tenant) || !validName(resourceType) {
		return nil, false, fmt.Errorf("%w: a search needs a tenant and a resource type", ErrInvalid)
	}
	if err := a.askable(p, resourceType); err != nil {
		return nil, false, err
	}
	if err := a.subject(s); err != nil {
		return nil, false, err
	}
	name, err := a.denied(ctx, ConstraintInput{Tenant: tenant, ResourceType: resourceType, Permission: p, Subject: &s})
	if err != nil || name != "" {
		return nil, name != "", err
	}
	return a.giving(p, resourceType), false, nil
}

// Columns names the host's columns that Filter reads.
type Columns struct {
	// Tenant is the resource's tenant, compared as text, byte for byte, as Authorize compares it:
	// a column of another type, such as uuid, matches the tenant its text names.
	Tenant string
	// Path is a text[] holding the resource's Authorizer.Path, with a GIN index. Its keys are
	// compared byte for byte, whatever its collation, which the index serves in.
	Path string
	// Labels is a text[] holding the resource's label as `dimension:value` values, never NULL: '{}'
	// for none. The label's test, which keeps only the rows the subject's holding satisfies,
	// compares them in the default collation and needs no index: an index on the column could serve
	// it only by reading every row it holds, so the path's index drives the query. With labels
	// declared the column is needed, so Filter refuses a call without it as invalid: pass
	// '{}'::text[] for a type whose resources carry no label.
	Labels string
}

// Predicate is a SQL condition and its arguments, numbered from the first argument the host
// asked for.
type Predicate struct {
	SQL  string
	Args []any
}

// Filter returns a condition for the host's own query that keeps the resources of a type in a
// tenant the subject may do p to. It reads the grants in the same statement as the rows, so
// sorting and pagination work and nothing changes between deciding and reading. A condition holds
// for the query it was built for: it fixes the time (Config.Now), the subject's label holding and
// what the constraints answered when Filter was called, so a later query keeps rows Authorize then
// refuses, as once a grant it counted has expired. Build one for each query. The host's
// query must reach this package's tables (they are in the pool's schema), and column names are
// trusted host code; every value is an argument. It counts only unconditional grants, and leaves
// out every resource a deny covers, conditional ones included, so it never keeps one Authorize
// refuses: Reachable's Conditional and ConditionalExcept name the scopes where that may be too
// strict.
func (a *Authorizer) Filter(ctx context.Context, s Subject, p Permission, tenant, resourceType string, cols Columns, firstArg int) (Predicate, error) {
	if cols.Tenant == "" || cols.Path == "" || firstArg < 1 {
		return Predicate{}, fmt.Errorf("%w: Filter needs the tenant and path columns and a first argument", ErrInvalid)
	}
	// Without the column, labeled rows would be kept that Authorize refuses.
	if len(a.labels) > 0 && cols.Labels == "" {
		return Predicate{}, fmt.Errorf("%w: with labels declared, Filter needs the label column: '{}'::text[] for resources that carry none", ErrInvalid)
	}
	roles, removed, err := a.searchable(ctx, s, p, tenant, resourceType)
	if err != nil {
		return Predicate{}, err
	}
	counts := a.counting(p, resourceType)
	custom := a.customGives(p, resourceType)
	if removed || s.Principal == (Principal{}) && !counts.public || len(roles) == 0 && !custom {
		return Predicate{SQL: "FALSE"}, nil
	}
	arg := func(i int) string { return fmt.Sprintf("$%d", firstArg+i) }
	// Null for a permission no deny removes, which no deny's permissions then match.
	var perm, wildcard any
	if listed, covering, ok := matchable(p); ok {
		perm, wildcard = listed, covering
	}
	// The subject's principals, read in the statement as its grants and denies are, so a list
	// reads its membership, its groups and what they hold in one snapshot.
	keys := func(of string) string {
		return "ARRAY(WITH RECURSIVE " + keysSQL(arg(1)+"::text", arg(2)+"::text", arg(4)) + " " + of + ")"
	}
	// The subject's grants on the scopes of the types in the array types, in the default collation,
	// which a column's own collation overrides where a comparison doesn't name one.
	grants := func(types string) string {
		return byType(types, `g.scope COLLATE "default"`, fmt.Sprintf(`g.tenant = %s::text AND g.principal = ANY(%s) AND g.role = ANY(%s)
			  AND (g.expires_at IS NULL OR g.expires_at > %s) AND NOT g.conditional
			  AND (g.principal <> %s::text OR g.role = ANY(%s))
			  AND (g.principal_kind <> ALL(%s) OR g.role <> ALL(%s))`,
			arg(1), keys(countedKeys(arg(13), arg(17))), givingSQL(arg(3), arg(1), arg(8), arg(9), custom, ""), arg(4), arg(6),
			givingSQL(arg(7), arg(1), arg(8), arg(9), custom, publicOnly(catalogSQL{arg(10), arg(11), arg(12)})),
			broadKindsSQL, givingSQL(arg(18), arg(1), arg(8), arg(9), custom, privilegedOnly(catalogSQL{arg(19), arg(20), arg(21)}))))
	}
	// The denies on the scopes `of` keeps that bind the subject, by the primary key, which leads to
	// a scope's type.
	denies := func(of string) string {
		return fmt.Sprintf(`SELECT d.scope FROM rbac_denies d
			WHERE d.tenant = %s::text AND %s AND d.principals && %s AND NOT d.exempt && %s
			  AND (%s::text = ANY(d.permissions) OR %s::text = ANY(d.permissions))`,
			arg(1), of, keys("SELECT k FROM bound"), keys("SELECT k FROM exempted"), arg(14), arg(15))
	}
	// The grants' tenant is an argument of its own: the host's tenant column needn't be text,
	// and one argument can't take two types. The grants overlap the path, which the host's GIN
	// index serves. A subject can hold thousands, such as one on each resource or workspace it
	// created, where an overlap would compare each with every key of every row, and the index merge
	// what each finds for every row it finds. So past a few on resources of the type, each of which
	// reaches only its resource, whose key is its path's first, they are looked up in a hash of
	// them, and past more on containers and the tenant (maxContainerOverlap), each of a row's keys
	// is looked up in one object of them all (keyed). Neither can use an index, so a subject with
	// few keeps the overlap: a test an index on the first key could serve, as `= ANY` of an array,
	// compares each row with every grant wherever a plan reads rows without that index, and a
	// host's sorted, limited query can.
	// Denies are looked up so whatever their number, as a tenant's admins can put one on each of
	// thousands of resources or workspaces, and no index serves a test that a row has none.
	//
	// The host's columns can have a collation of their own, which would compare keys and tenants
	// that differ, such as in case, as equal. A collation inside a subquery doesn't carry out of
	// it, so each comparison that decides names the default one, the tenant's as text, as the
	// column needn't be, or compares keys as an object does, byte for byte. The tenant and the path
	// are compared in the column's own collation too, which its indexes are in, so they serve
	// whatever it is.
	overlap := "ARRAY(" + grants(arg(5)) + ")"
	reached := fmt.Sprintf(`(%[1]s && %[2]s AND %[1]s && (%[2]s COLLATE "default"))`, cols.Path, overlap)
	above, denied := a.reaching(resourceType), a.reaching(resourceType)
	var deniedByKey string
	if !a.contains(resourceType) {
		denied = slices.DeleteFunc(denied, func(t string) bool { return t == resourceType })
		deniedByKey = fmt.Sprintf(`NOT (%s)[1] COLLATE "default" IN (%s) AND `, cols.Path, denies("d.scope_type = "+arg(9)+"::text"))
	}
	resources, containers, err := a.grantCounts(ctx, tenant, s, p, roles, custom, counts, resourceType)
	if err != nil {
		return Predicate{}, err
	}
	switch {
	// Past a few on resources of the type no index serves the condition, so the overlap would
	// compare every row of the tenant with each grant on containers: past a few of those too, each
	// key is looked up.
	case containers > maxContainerOverlap || resources > maxOverlap && containers > maxOverlap:
		reached = keyed(cols.Path, grants(arg(5)))
	case resources > maxOverlap:
		above = denied
		reached = fmt.Sprintf(`((%[1]s)[1] COLLATE "default" IN (%[3]s) OR %[1]s && %[2]s AND %[1]s && (%[2]s COLLATE "default"))`,
			cols.Path, overlap, grants("ARRAY["+arg(9)+"::text]"))
	}
	pred := Predicate{
		SQL: fmt.Sprintf(`(%[1]s = %[2]s AND (%[1]s)::text = %[5]s::text COLLATE "default" AND %[3]s
			AND %[7]sNOT %[6]s)`,
			cols.Tenant, arg(0), reached, cols.Path, arg(1), keyed(cols.Path, denies("d.scope_type = ANY("+arg(16)+"::text[])")), deniedByKey),
		Args: append(append([]any{
			tenant, tenant, s.identityKey(), roles, a.cfg.Now(), above, publicKey, a.publicRoles(roles),
			string(p), resourceType,
		}, a.publicArgs(p, resourceType, custom)...), append([]any{
			counts.public, perm, wildcard, denied, counts.members, a.privilegedRoles(roles),
		}, a.catalogArgs(custom)...)...),
	}
	// With no dimension declared too, as then any label is invalid, and Authorize refuses it.
	if cols.Labels == "" {
		return pred, nil
	}
	// The label, against the holding read now, as conditions of label grants can be evaluated only
	// here, not in the statement.
	h, _, err := a.holding(ctx, tenant, s)
	if err != nil {
		return Predicate{}, err
	}
	if h.excludes(p) {
		return Predicate{SQL: "FALSE"}, nil
	}
	labels, args := h.labelColumn(cols.Labels, arg, len(pred.Args))
	pred.SQL = "(" + pred.SQL + " AND " + labels + ")"
	pred.Args = append(pred.Args, args...)
	return pred, nil
}

// byType is SQL selecting cols of the grants g for which where holds whose scope is of one of the
// types in the array types, a type at a time: each one range of scopes, which the indexes leading
// to a principal seek for each of its principals. Ranges ORed are none an index can seek, so a plan
// reads every grant of the principals in the tenant, as a group's on thousands of resources of
// another type. OFFSET 0 keeps the planner from flattening it into a join it could run the other
// way round.
func byType(types, cols, where string) string {
	return fmt.Sprintf(`SELECT %[2]s FROM unnest(%[1]s::text[]) AS t(t) CROSS JOIN LATERAL (
		SELECT %[2]s FROM rbac_grants g WHERE %[3]s AND %[4]s OFFSET 0) g`, types, cols, where, ofType("g.scope", "t.t"))
}

// byKey is SQL selecting cols of the rows of table for which where holds whose col is one of the
// distinct keys in the array keys, a key at a time: each an equality the indexes leading to col, or
// to the tenant and col, seek. A generic plan costs col = ANY(keys) as ten seeks, and a read of the
// tenant by an index leading to it alone, which it costs as an average tenant's few rows, as
// cheaper, so it reads every row of a large tenant. OFFSET 0 keeps the planner from flattening it
// into a join it could run the other way round.
func byKey(keys, table, col, cols, where string) string {
	return fmt.Sprintf(`SELECT r.* FROM unnest(%[1]s::text[]) AS keyed(k) CROSS JOIN LATERAL (
		SELECT %[4]s FROM %[2]s WHERE (%[5]s) AND %[3]s = keyed.k OFFSET 0) r`, keys, table, col, cols, where)
}

// ofType is SQL keeping the rows whose scope, col, is of the type t. A scope is `type:id`, and in
// the C collation the scopes of a type sort from `type:` to just before `type;`, so a btree on the
// scope reads only them, as one on split_part couldn't.
func ofType(col, t string) string {
	return fmt.Sprintf("(%s >= (%s || ':') AND %s < (%s || ';'))", col, t, col, t)
}

// keyed is SQL for whether one of the keys of a path, col, is a scope scopes selects: each is
// looked up in one object of them, built once for the statement, so a key costs a few comparisons
// however many there are, and compares byte for byte. A hashed subquery for each key would need one
// for each depth a path can have, which has no bound, and one inside a subquery over a row's keys
// is built again for every row. jsonb_exists_any is the operator `?|`, which a host's query builder
// could read as a placeholder.
func keyed(col, scopes string) string {
	return fmt.Sprintf(`jsonb_exists_any((SELECT coalesce(jsonb_object_agg(s, true), '{}') FROM (%s) AS k(s)), %s)`, scopes, col)
}

// maxOverlap is how many grants on resources of a type Filter overlaps with each row's path:
// about where comparing each with every key of a row costs as much as a lookup in a hash.
const maxOverlap = 8

// maxContainerOverlap is how many grants on containers and the tenant Filter overlaps with each
// row's path where the host's index serves the overlap; where none does, it is maxOverlap. The
// index finds the rows under them, merging what each finds, which costs each row it finds a
// comparison for every one: about where that costs as much as reading a row and looking up its
// keys. A test lowers it.
var maxContainerOverlap = 128

// grantCounts counts s's principals' unconditional grants in force on resources of a type, and on
// the containers, a container type's own among them, and the tenant, of the roles that give p on
// the type, the built-in ones in roles and with custom the tenant's, counting broad ones as counts
// says, of each type only until they pass maxContainerOverlap: it only picks the form of Filter's
// condition. Grants of other roles aren't in the condition, and counted they would trade an index
// that finds the few rows its grants reach for a read of every row of the tenant.
func (a *Authorizer) grantCounts(ctx context.Context, tenant string, s Subject, p Permission, roles []string, custom bool, counts broad, resourceType string) (resources, containers int, err error) {
	err = a.db.QueryRow(ctx, `WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$5")+`
		SELECT coalesce(sum(n) FILTER (WHERE t = $3 AND NOT $4), 0)::int, coalesce(sum(n) FILTER (WHERE t <> $3 OR $4), 0)::int
		FROM unnest($6::text[]) AS t(t) CROSS JOIN LATERAL (SELECT count(*) AS n FROM (SELECT FROM rbac_grants
		  WHERE tenant = $1 AND principal = ANY(ARRAY(`+countedKeys("$8", "$9")+`)) AND `+ofType("scope", "t.t")+` AND NOT conditional
		    AND (expires_at IS NULL OR expires_at > $5) AND role = ANY(`+givingSQL("$10", "$1", "$11", "$3", custom, "")+`) LIMIT $7) g) g`,
		tenant, s.identityKey(), resourceType, a.contains(resourceType), a.cfg.Now(), a.reaching(resourceType), maxContainerOverlap+1,
		counts.public, counts.members, roles, string(p)).Scan(&resources, &containers)
	return resources, containers, err
}

// holding is a grant as a check reads it from the key index: whether it has a condition, not
// the condition, which conditionsOf reads when a check needs it.
type holding struct {
	Binding
	scope       string
	conditional bool
	// ends is when the subject holds it until, zero for never: the sooner of its expiry and the end
	// of the subject's membership of the tenant or its place in the group it is granted to, read for
	// a change alone.
	ends time.Time
}

// sooner is the earlier of two ends, zero for never.
func sooner(x, y time.Time) time.Time {
	if x.IsZero() || !y.IsZero() && y.Before(x) {
		return y
	}
	return x
}

// rolesRead is which of a tenant's custom roles heldOrDenied reads with the grants.
type rolesRead int

const (
	// namedRoles are those the grants name.
	namedRoles rolesRead = iota
	// tenantRoles are all of them, as a role's GrantableRoles can name any.
	tenantRoles
	// heldTenantRoles are all of them where a grant names one.
	heldTenantRoles
)

// heldOrDenied returns the grants on any of scopes, not expired, held by s's principals in a
// tenant, counting broad ones as counts says, and the denies deniesOn reads for all its principals
// and p, or any permission when p is empty, in one statement that reads its membership and groups
// too, so a check is one round trip. The grants' part reads only what the key index holds, and the
// other indexes it could use lead to the principals and scopes too and hold the same, so whichever
// a plan picks, a generic one too, it is an index-only scan of no more grants. Like Explain, it
// reads no deny for a subject none of whose grants count, such as one that isn't a member or guest
// of the tenant. It reads the custom roles roles says in the statement too, as SetRole changes one
// in place: read apart, a grant revoked and its role widened meanwhile could give what no moment
// did. With ending, it reads when each grant's holding ends too, as a change hands on nothing past
// it.
func (a *Authorizer) heldOrDenied(ctx context.Context, q DB, tenant string, s Subject, counts broad, scopes []string, p Permission,
	roles rolesRead, ending bool,
) ([]holding, []denial, book, error) {
	b := book{builtin: a.roles}
	// The anonymous are the public alone.
	if s.Principal == (Principal{}) && !counts.public {
		return nil, nil, b, nil
	}
	var perm, wildcard string
	deniable := true
	if p != "" {
		perm, wildcard, deniable = matchable(p)
	}
	// No deny is read for a permission none removes, so no row stored around the package can
	// remove it: in the statement's text, which then plans no read of them.
	read := "TRUE"
	if !deniable {
		read = "FALSE"
	}
	// The latest end of the subject's place in each group, by any path to it, and of its
	// membership, which every key but the public's rests on; null for never. In the statement,
	// so they are of the moment its grants are.
	var places, ends string
	if ending {
		places = `, placed(id, ends) AS (
		  SELECT group_id, expires_at FROM rbac_members WHERE tenant = $1 AND principal = $2::text
		    AND (expires_at IS NULL OR expires_at > $4) AND EXISTS (SELECT FROM membership)
		  UNION
		  SELECT m.group_id, least(p.ends, m.expires_at) FROM placed p ` + groupsAbove("p.id", "$4", "group_id, expires_at") + `
		), ends(k, e) AS (
		  SELECT 'group:' || id, CASE WHEN bool_or(ends IS NULL) THEN NULL ELSE max(ends) END FROM placed GROUP BY id
		  UNION ALL
		  SELECT principal, expires_at FROM rbac_memberships WHERE tenant = $1 AND principal = $2::text
		    AND (expires_at IS NULL OR expires_at > $4)
		)`
		ends = `
		UNION ALL
		SELECT 3, k, '', '', '', e, false, NULL, '', NULL, false, false, NULL, '', '' FROM ends`
	}
	// In the statement's text rather than an argument: a generic plan can't tell from one whether
	// to read every role of the tenant or look up those the grants name.
	var which string
	switch roles {
	case namedRoles:
		which = "id IN (SELECT role FROM held WHERE role LIKE '" + CustomPrefix + "%')"
	case tenantRoles:
		which = "TRUE"
	case heldTenantRoles:
		which = "EXISTS (SELECT FROM held WHERE role LIKE '" + CustomPrefix + "%')"
	}
	// Grants, denies and roles in that order; grants by principal, scope, role and id, denies by id
	// and scope, as deniesOn.
	const deny, role, end = 1, 2, 3
	rows, err := q.Query(ctx, `
		WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$4")+`, held AS (
		  SELECT id::text, principal, scope, role, expires_at, conditional FROM rbac_grants
		  WHERE tenant = $1 AND principal = ANY(ARRAY(`+countedKeys("$7", "$8")+`)) AND scope = ANY($3::text[])
		    AND (expires_at IS NULL OR expires_at > $4)
		)`+places+`
		SELECT 0, id, principal, scope, role, expires_at, conditional, NULL::text[], '', NULL::text[], false, false, NULL::text[], '', ''
		FROM held
		UNION ALL
		SELECT 1, id, id, scope, '', NULL, condition <> '', permissions, condition, NULL, false, false, NULL, '', ''
		FROM (`+byKey("$3", "rbac_denies", "scope", "id, scope, permissions, condition", read+` AND tenant = $1
		  AND principals && ARRAY(SELECT k FROM bound) AND NOT exempt && ARRAY(SELECT k FROM exempted)
		  AND ($5 = '' OR $5 = ANY(permissions) OR $6 = ANY(permissions)) AND EXISTS (SELECT FROM keys WHERE `+counted("$7", "$8")+`)`)+`) d
		UNION ALL
		SELECT 2, id, '', '', id, NULL, false, permissions, '', resource_types, privileged, public, grantable_roles, name, description
		FROM rbac_roles
		WHERE tenant = $1 AND `+which+ends+`
		ORDER BY 1, 3, 4, 5, 2`,
		tenant, s.identityKey(), scopes, a.cfg.Now(), perm, wildcard, counts.public, counts.members)
	if err != nil {
		return nil, nil, book{}, err
	}
	var held []holding
	var ds []denial
	var custom []RoleDefinition
	placeEnds := map[string]time.Time{}
	var kind int
	var id, principal, scope, roleID, condition, name, description string
	var expires *time.Time
	var conditional, privileged, public bool
	var perms, types, grantable []string
	_, err = pgx.ForEachRow(rows, []any{&kind, &id, &principal, &scope, &roleID, &expires, &conditional, &perms, &condition, &types, &privileged, &public, &grantable, &name, &description}, func() error {
		switch kind {
		case deny:
			d := denial{id: id, scope: scope, condition: condition}
			for _, x := range perms {
				d.permissions = append(d.permissions, Permission(x))
			}
			ds = append(ds, d)
		case role:
			custom = append(custom, roleFrom(id, name, description, perms, types, privileged, public, grantable))
		case end:
			if expires == nil {
				placeEnds[id] = time.Time{}
			} else {
				placeEnds[id] = *expires
			}
		default:
			h := holding{Binding: Binding{ID: id, Principal: parsePrincipal(principal), Role: Role(roleID)}, scope: scope, conditional: conditional}
			if expires != nil {
				h.ExpiresAt = *expires
			}
			held = append(held, h)
		}
		return nil
	})
	if err != nil {
		return nil, nil, book{}, err
	}
	if ending {
		tenure := placeEnds[s.identityKey()]
		for i, h := range held {
			held[i].ends = h.ExpiresAt
			// A grant to the public reaches the subject whatever it is a member of.
			if h.Principal.Kind != Public {
				held[i].ends = sooner(held[i].ends, tenure)
			}
			if h.Principal.Kind == Group {
				held[i].ends = sooner(held[i].ends, placeEnds[h.Principal.key()])
			}
		}
	}
	if len(custom) > 0 {
		b = a.bookOf(a.current(custom))
	}
	return held, ds, b, nil
}

// conditionsOf reads the conditions of the conditional grants among held, in place.
func (a *Authorizer) conditionsOf(ctx context.Context, q DB, tenant string, held []holding) error {
	var ids, principals, scopes []string
	for _, h := range held {
		if h.conditional {
			ids = append(ids, h.ID)
			principals = append(principals, h.Principal.key())
			scopes = append(scopes, h.scope)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// Only the expression: a check reads nothing else of a condition. By principal too: as of a
	// time, history finds a grant's versions by its principal, not by its id. And by scope, so every
	// index a generic plan can pick seeks those grants: by the principals alone, it would read every
	// grant of a group granted on thousands of resources.
	rows, err := q.Query(ctx, `SELECT id::text, condition FROM rbac_grants
		WHERE id = ANY($1::uuid[]) AND tenant = $2 AND principal = ANY($3::text[]) AND scope = ANY($4::text[])`,
		ids, tenant, principals, scopes)
	if err != nil {
		return err
	}
	found := map[string]string{}
	var id, expr string
	_, err = pgx.ForEachRow(rows, []any{&id, &expr}, func() error {
		found[id] = expr
		return nil
	})
	if err != nil {
		return err
	}
	for i, h := range held {
		if h.conditional {
			// One gone since is read as a condition nothing meets.
			held[i].Condition.Expression = cmp.Or(found[h.ID], "false")
		}
	}
	return nil
}

// heldGrants returns the grants held by any of principals on any of scopes, not expired, in the
// order heldOrDenied reads them, so Explain lists them in a stable order: it spends on their
// conditions cheapest first, as Authorize does.
func (a *Authorizer) heldGrants(ctx context.Context, q DB, tenant string, principals, scopes []string) ([]Grant, error) {
	if len(principals) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT `+grantColumns+` FROM rbac_grants
		WHERE tenant = $1 AND principal = ANY($2::text[]) AND scope = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > $4)
		ORDER BY principal, scope, role, id`,
		tenant, principals, scopes, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	return collectGrants(rows)
}

const grantColumns = `id::text, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at,
	condition_title, condition_description, condition, note, approved_by, created_by, created_at, updated_by, updated_at`

func collectGrants(rows pgx.Rows) ([]Grant, error) {
	return pgx.CollectRows(rows, scanGrant)
}

func scanGrant(row pgx.CollectableRow) (Grant, error) {
	var g Grant
	var expires *time.Time
	var approvedBy, createdBy, updatedBy string
	err := row.Scan(&g.ID, &g.Scope.Type, &g.Scope.ID, &g.Principal.Kind, &g.Principal.ID, &g.Role, &g.Source, &expires,
		&g.Condition.Title, &g.Condition.Description, &g.Condition.Expression, &g.Note,
		&approvedBy, &createdBy, &g.CreatedAt, &updatedBy, &g.UpdatedAt)
	if expires != nil {
		g.ExpiresAt = *expires
	}
	g.ApprovedBy, g.CreatedBy, g.UpdatedBy = parsePrincipal(approvedBy), parsePrincipal(createdBy), parsePrincipal(updatedBy)
	return g, err
}
