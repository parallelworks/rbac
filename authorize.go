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
	// denied what its grants allowed; or for a value of an exclusive dimension, that dimension, of
	// which the subject holds none, as its grants could give it two.
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
// resource's label, which allows nothing its holding doesn't satisfy, decided by the label values
// read with the grants, so a check allows only what one moment did.
func (a *Authorizer) decide(ctx context.Context, s Subject, p Permission, r Resource, explain bool) (Decision, error) {
	d, values, err := a.decideGrants(ctx, s, p, r, explain)
	if err != nil || !d.Allowed || values == nil {
		return d, err
	}
	r = a.decidedOn(p, r)
	h, _, err := a.holdingOf(ctx, r.Tenant, s, values)
	if err != nil {
		return Decision{}, err
	}
	if value, _ := a.exclusiveValue(p); h.excludes(p) {
		return Decision{Label: value, Reason: exclusiveRefusal(value)}, nil
	}
	if dim := h.Unsatisfied(r.Labels); dim != "" {
		return Decision{Label: dim, Reason: labelRefusal(dim)}, nil
	}
	return d, nil
}

// asksValues reports whether a check of p on r, as decidedOn gives it, reads the subject's label
// values: r's label asks for some, or p is a value of an exclusive dimension.
func (a *Authorizer) asksValues(p Permission, r Resource) bool {
	_, exclusive := a.exclusiveValue(p)
	return exclusive || r.Labels.asks()
}

// exclusiveRefusal is why a check refuses a value of dim, an exclusive dimension.
func exclusiveRefusal(dim string) string {
	return "its grants could give it two values of " + dim + ", whose values are exclusive, so it holds none"
}

// decideGrants is decide's decision by s's grants and denies, and where the check reads label
// values (asksValues), what they are decided by, read with the grants.
func (a *Authorizer) decideGrants(ctx context.Context, s Subject, p Permission, r Resource, explain bool) (Decision, *valuesRead, error) {
	if err := a.check(r); err != nil {
		return Decision{}, nil, err
	}
	if err := a.askable(p, r.Type); err != nil {
		return Decision{}, nil, err
	}
	if err := a.subject(s); err != nil {
		return Decision{}, nil, err
	}
	// Checked as passed, and decided as a labeled check decides it.
	r = a.decidedOn(p, r)
	name, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Subject: &s, Resource: &r})
	if err != nil {
		return Decision{}, nil, err
	}
	if name != "" {
		return Decision{DeniedBy: name, Reason: "removed by " + name}, nil, nil
	}

	counts, values := a.counting(p, r.Type), a.asksValues(p, r)
	if !explain {
		return a.decideHeld(ctx, s, p, r, counts, values)
	}

	// Explain reads the subject's groups apart from its grants and denies, so in one snapshot, as
	// Authorize reads them in one statement; and its label values in it too.
	type explained struct {
		d      Decision
		values *valuesRead
	}
	got, err := snapshot(ctx, a, func(a *Authorizer) (explained, error) {
		d, err := a.explain(ctx, s, p, r, counts)
		if err != nil || !d.Allowed || !values {
			return explained{d: d}, err
		}
		v, err := a.valuesOn(ctx, a.db, r.Tenant, s)
		return explained{d, v}, err
	})
	return got.d, got.values, err
}

// readingRoles runs once a read has read grants and the custom roles with them, as a
// test's change that commits there.
var readingRoles = func() {}

// decideHeld is Authorize's decision once no constraint removes p, from s's grants and denies and
// the custom roles they name, read in one statement; with values, what its label values are decided
// by, read in it too.
func (a *Authorizer) decideHeld(ctx context.Context, s Subject, p Permission, r Resource, counts broad, values bool) (Decision, *valuesRead, error) {
	got, err := a.readHeld(ctx, a.db, r.Tenant, s, counts, r.path(), p, namedRoles, alsoRead{values: values})
	if err != nil {
		return Decision{}, nil, err
	}
	readingRoles()
	d, err := a.decideBy(ctx, s, p, r, got.held, got.ds, got.roles)
	return d, got.values, err
}

// decideBy is decideHeld's decision by what it read.
func (a *Authorizer) decideBy(ctx context.Context, s Subject, p Permission, r Resource, held []holding, ds []denial, roles book) (Decision, error) {
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
	spend := a.grantBudget(r.path())
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
	vars, spend := a.vars(ctx, s, p, r), a.grantBudget(r.path())
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
	readingRoles()
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
	return ok && roles.gives(h.Role, def, p, resourceType) && h.carries(def, p)
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
	// Its label values are those its grants on the tenant give, read with these, so a label is
	// decided by what it held as it held them.
	held, ds, roles, err := a.heldOrDenied(ctx, a.db, r.Tenant, s, all, r.path(), namedRoles, false)
	if err != nil {
		return nil, err
	}
	readingRoles()
	// A label the subject doesn't satisfy leaves it nothing, whatever its grants give, but on the
	// tenant the label values and powers to release it holds, which no label of the tenant's decides
	// (decidedOn).
	var only func(Permission) bool
	if r.Labels.asks() {
		h, _, err := a.holdingOf(ctx, r.Tenant, s, onTenant(r.Tenant, held, ds, roles))
		switch {
		case err != nil:
			return nil, err
		case h.Unsatisfied(r.Labels) == "":
		case r.Type != TenantScope:
			return nil, nil
		default:
			only = a.labelPermission
		}
	}
	perms, _, excluded, err := a.permissionsOf(ctx, a.db, s, r, only, a.constrain(ctx, s, r), held, ds, roles)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(perms, func(p Permission) bool { t, ok := a.exclusiveValue(p); return ok && excluded[t] }), nil
}

// permissionsOf is what Permissions lists, once its input is checked, of the permissions only
// keeps, or all where it is nil, decided by held and ds, s's grants and denies on r's path, and the
// roles they name, read together; and of them, those a condition decided, a grant's or a deny's,
// or a constraint asked without the request's attributes, which a read without the request can't
// settle; and the exclusive dimensions s holds none of, as its grants on the tenant could give it
// two (excludedBy). It reads on q the conditions not read with the grants, and asks the
// constraints through cs, which is on r, so a change reads them back in its transaction.
func (a *Authorizer) permissionsOf(ctx context.Context, q DB, s Subject, r Resource, only func(Permission) bool, cs *constrained,
	held []holding, ds []denial, roles book,
) ([]Permission, map[Permission]bool, map[string]bool, error) {
	kept := func(p Permission) bool { return only == nil || only(p) }
	byCondition := map[Permission]bool{}
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
	// Each permission is decided as Authorize would decide it, a label value or a power to release
	// on the tenant as valueResource, on budgets of its own, which share what conditions came to on
	// the same resource: one that doesn't read the action runs once for them all.
	type deciding struct {
		vars map[string]any
		ran  map[string]run
	}
	resource := &deciding{a.vars(ctx, s, "", r), map[string]run{}}
	values := resource
	if r.Type == TenantScope && len(a.labels) > 0 {
		vars := a.vars(ctx, s, "", r)
		vars["resource"] = valueResource(r.Tenant)
		values = &deciding{vars, map[string]run{}}
	}
	on := func(p Permission) *deciding {
		if a.labelPermission(p) {
			return values
		}
		return resource
	}
	// What a constraint removes is settled first, so no budget is spent on conditions for it.
	removed := map[Permission]bool{}
	isRemoved := func(p Permission) (bool, error) {
		removed[p] = cs.removes(p, r.Type)
		return removed[p], cs.failed()
	}
	spends := map[Permission]*budget{}
	spendOn := func(p Permission) *budget {
		if spends[p] == nil {
			spends[p] = a.grantBudget(r.path()).sharing(on(p).ran)
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
		vars := on(p).vars
		vars["action"] = string(p)
		d, ok := a.deniedBy(ds, p, newDenyBudget(r.path()).sharing(on(p).ran), vars)
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
			vars := on(p).vars
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
	r = a.decidedOn(p, r)
	removed, err := a.denied(ctx, ConstraintInput{Tenant: r.Tenant, ResourceType: r.Type, Permission: p, Resource: &r})
	if err != nil {
		return nil, err
	}
	roles, custom := a.giving(p, r.Type), a.customGives(p, r.Type)
	if len(roles) == 0 && !custom {
		return nil, nil
	}
	// What the holders' label values are decided by is read in the list's snapshot, so each is of
	// the moment its grants are.
	type listed struct {
		holders []Holder
		values  map[string]*valuesRead
	}
	asks := a.asksValues(p, r)
	got, err := snapshot(ctx, a, func(a *Authorizer) (listed, error) {
		holders, err := a.holders(ctx, p, r, roles, custom)
		if err != nil || !asks {
			return listed{holders: holders}, err
		}
		if holders, err = a.broadLabeled(ctx, p, r, holders); err != nil {
			return listed{}, err
		}
		values, err := a.valuesOfEach(ctx, a.db, r.Tenant, holders)
		return listed{holders, values}, err
	})
	holders := got.holders
	if err == nil && removed != "" {
		holders, err = a.constrained(ctx, p, r, holders)
	}
	if err != nil || !asks {
		return holders, err
	}
	return a.labeled(ctx, p, r, holders, got.values)
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

// broadLabeled leaves out of holders the tenant's members and the public where their own grants
// leave none of them able to do p to r (broadExcludes), and otherwise marks them MaybeDenied, as
// their people hold values each their own.
func (a *Authorizer) broadLabeled(ctx context.Context, p Permission, r Resource, holders []Holder) ([]Holder, error) {
	kept := holders[:0]
	for _, h := range holders {
		if h.Principal.broad() {
			out, err := a.broadExcludes(ctx, r.Tenant, h.Principal, p, r.Labels)
			if err != nil {
				return nil, err
			}
			if out {
				continue
			}
			h.MaybeDenied = true
		}
		kept = append(kept, h)
	}
	return kept, nil
}

// labeled keeps of holders the identities whose holding, decided by values, read with the list,
// satisfies r's label whatever the request, and where p is a value of an exclusive dimension, holds
// it: one that satisfies it only with the values a condition or a constraint decided, which a read
// without the request can't settle, is marked MaybeDenied; and one that doesn't even then, or holds
// none of p's dimension, is left out. The members and the public broadLabeled kept stay. Each
// identity's holding is decided after the list's snapshot, as its constraints run as for any read.
func (a *Authorizer) labeled(ctx context.Context, p Permission, r Resource, holders []Holder, values map[string]*valuesRead) ([]Holder, error) {
	kept := holders[:0]
	for _, h := range holders {
		if h.Principal.broad() {
			kept = append(kept, h)
			continue
		}
		s := Subject{Principal: h.Principal}
		holding, byCondition, err := a.holdingOf(ctx, r.Tenant, s, values[h.Principal.key()])
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

// valuesOfEach reads on q, in one statement, what the label values in a tenant of each identity
// among holders are decided by (valuesRead), by its key, with their conditions: each one's keys
// apart, as conflicts reads them, and the grants on the tenant and the denies there binding any of
// them once, as many share a group.
func (a *Authorizer) valuesOfEach(ctx context.Context, q DB, tenant string, holders []Holder) (map[string]*valuesRead, error) {
	var identities []string
	for _, h := range holders {
		if !h.Principal.broad() {
			identities = append(identities, h.Principal.key())
		}
	}
	if len(identities) == 0 {
		return nil, nil
	}
	// Each identity's keys cost the planner as a walk of many groups, which across many identities is
	// past JIT's thresholds.
	return withoutJIT(ctx, q, func() (map[string]*valuesRead, error) { return a.valuesOfAll(ctx, q, tenant, identities) })
}

// valuesOfAll is valuesOfEach's read of identities, by key.
func (a *Authorizer) valuesOfAll(ctx context.Context, q DB, tenant string, identities []string) (map[string]*valuesRead, error) {
	rows, err := q.Query(ctx, `
		WITH idents AS MATERIALIZED (
		  SELECT t.identity, ks.keys, ks.bound, ks.exempted FROM (SELECT unnest($2::text[]) COLLATE "C" AS identity) t
		  CROSS JOIN LATERAL (WITH RECURSIVE `+keysSQL("$1::text", "t.identity", "$3")+`
		    SELECT ARRAY(SELECT k FROM keys) AS keys, ARRAY(SELECT k FROM bound) AS bound, ARRAY(SELECT k FROM exempted) AS exempted) ks
		), held AS (
		  SELECT g.* FROM (SELECT DISTINCT unnest(keys) AS k FROM idents) k CROSS JOIN LATERAL (
		    SELECT id::text, principal, role, expires_at, condition FROM rbac_grants
		    WHERE tenant = $1 AND principal = k.k AND scope = 'tenant:' || $1 AND (expires_at IS NULL OR expires_at > $3) OFFSET 0) g
		)
		SELECT 0, identity, '', '', NULL::timestamptz, '', keys, bound, exempted, false, false, '', '' FROM idents
		UNION ALL
		SELECT 1, id, principal, role, expires_at, condition, NULL, NULL, NULL, false, false, '', '' FROM held
		UNION ALL
		SELECT 2, id, '', '', NULL, condition, permissions, principals, exempt, false, false, '', '' FROM rbac_denies
		WHERE tenant = $1 AND scope = 'tenant:' || $1 AND principals && ARRAY(SELECT DISTINCT unnest(bound) FROM idents)
		UNION ALL
		SELECT 3, id, '', '', NULL, '', permissions, resource_types, grantable_roles, privileged, public, name, description
		FROM rbac_roles WHERE tenant = $1 AND id IN (SELECT role FROM held WHERE role LIKE '`+CustomPrefix+`%')
		ORDER BY 1, 3, 4, 2`, tenant, identities, a.cfg.Now())
	if err != nil {
		return nil, err
	}
	// Grants by principal, role and id, and denies by id, as a read of one identity's orders them.
	type keyed struct{ keys, bound, exempted []string }
	byIdentity := map[string]keyed{}
	var grants []holding
	at := map[string][]int{}
	var ds []denial
	var custom []RoleDefinition
	scope := TenantRoot(tenant).Key()
	var kind int
	var id, principal, role, condition, name, description string
	var expires *time.Time
	var first, second, third []string
	var privileged, public bool
	if _, err := pgx.ForEachRow(rows, []any{&kind, &id, &principal, &role, &expires, &condition, &first, &second, &third, &privileged, &public, &name, &description}, func() error {
		switch kind {
		case 0:
			byIdentity[id] = keyed{first, second, third}
		case 1:
			h := holding{
				Binding: Binding{ID: id, Principal: parsePrincipal(principal), Role: Role(role), Condition: Condition{Expression: condition}},
				scope:   scope, conditional: condition != "",
			}
			if expires != nil {
				h.ExpiresAt = *expires
			}
			at[principal] = append(at[principal], len(grants))
			grants = append(grants, h)
		case 2:
			d := denial{id: id, scope: scope, condition: condition, principals: second, exempt: third}
			for _, x := range first {
				d.permissions = append(d.permissions, Permission(x))
			}
			ds = append(ds, d)
		default:
			custom = append(custom, roleFrom(id, name, description, first, second, privileged, public, third))
		}
		return nil
	}); err != nil {
		return nil, err
	}
	readingRoles()
	roles := a.builtinBook()
	if len(custom) > 0 {
		roles = a.bookOf(a.current(custom))
	}
	overlaps := func(xs, ys []string) bool {
		return slices.ContainsFunc(xs, func(x string) bool { return slices.Contains(ys, x) })
	}
	values := make(map[string]*valuesRead, len(byIdentity))
	for identity, k := range byIdentity {
		v := &valuesRead{roles: roles}
		var is []int
		for _, key := range slices.Compact(slices.Sorted(slices.Values(k.keys))) {
			is = append(is, at[key]...)
		}
		slices.Sort(is)
		for _, i := range is {
			v.held = append(v.held, grants[i])
		}
		for _, d := range ds {
			if overlaps(d.principals, k.bound) && !overlaps(d.exempt, k.exempted) {
				v.ds = append(v.ds, d)
			}
		}
		values[identity] = v
	}
	return values, nil
}

// holders is Holders' list once no constraint removes p, for the built-in roles that give it, and
// custom ones too where custom.
func (a *Authorizer) holders(ctx context.Context, p Permission, r Resource, roles []string, custom bool) ([]Holder, error) {
	// One time for every statement, as one snapshot, so a grant, a membership or a group's member
	// ending between them can't leave a holder that no single moment had.
	now := a.cfg.Now()
	through, err := a.broadArgs(ctx, a.db, r.Tenant, p, r.Type, roles, custom,
		byKey("$4", "rbac_grants", "scope", "role", `tenant = $1 AND principal = ANY($5::text[]) AND role LIKE 'custom.%'`),
		r.path(), broadKeys(r.Tenant))
	if err != nil {
		return nil, err
	}
	args := append([]any{
		r.Tenant, r.path(), roles, now, p.managesAccess(),
		broadKinds,
		string(p), r.Type, a.publicRoles(roles), string(Public),
	}, through...)
	// A privileged role gives nothing through the tenant's members or the public.
	rows, err := a.db.Query(ctx, byKey("$2", "rbac_grants", "scope", "id::text, principal_kind, principal_id, conditional", `
		  tenant = $1 AND role = ANY(`+givingSQL("$3", "$1", "$7", "$8", custom, "")+`)
		  AND (expires_at IS NULL OR expires_at > $4) AND (NOT $5 OR principal_kind <> ALL($6::text[]))
		  AND (principal_kind <> $10 OR role = ANY(`+givingSQL("$9", "$1", "$7", "$8", custom, publicOnly("$11"))+`))
		  AND (principal_kind <> ALL($6::text[])
		    OR role = ANY(`+givingSQL("$12", "$1", "$7", "$8", custom, listedOnly("$13"))+`))`)+`
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
	readingRoles()
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
	// to resources whose label the holding satisfies. For a label value or a power to release on the
	// tenant, which a check decides on the tenant without its label, it holds every value, so it
	// satisfies any label whose values are declared.
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
	// With what its label values are decided by, in the snapshot, so they are of the moment its
	// grants are.
	type reached struct {
		reach  Reach
		values *valuesRead
	}
	got, err := snapshot(ctx, a, func(a *Authorizer) (reached, error) {
		reach, err := a.reachable(ctx, s, p, tenant, resourceType, roles, custom)
		if err != nil || !reach.All && len(reach.Scopes)+len(reach.Conditional) == 0 {
			return reached{reach: reach}, err
		}
		v, err := a.valuesOn(ctx, a.db, tenant, s)
		return reached{reach, v}, err
	})
	reach := got.reach
	if err != nil || got.values == nil {
		return reach, err
	}
	// Decided outside the snapshot, as its constraints run as for any read.
	h, _, err := a.holdingOf(ctx, tenant, s, got.values)
	if err != nil || h.excludes(p) {
		return Reach{}, err
	}
	reach.Labels = a.listedBy(h, p, resourceType)
	return reach, nil
}

// listedBy is the holding a list of resources of a type by p keeps those by whose label it
// satisfies: h, but for a label value or a power to release on the tenant, which a check decides
// on the tenant without its label (decidedOn), every value, which satisfies any label whose values
// are declared, as a check refuses one whose values aren't.
func (a *Authorizer) listedBy(h Holding, p Permission, resourceType string) Holding {
	if resourceType != TenantScope || !a.labelPermission(p) {
		return h
	}
	every := Holding{tenant: h.tenant, dims: h.dims, values: map[string]map[string]bool{}, releases: map[string]bool{}, excluded: map[string]bool{}}
	for dim, ld := range h.dims {
		every.values[dim] = map[string]bool{}
		for v := range ld.rank {
			every.values[dim][v] = true
		}
	}
	return every
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
	through, err := a.broadArgs(ctx, a.db, tenant, p, resourceType, roles, custom, broadOn("$4", "$5"), reaching, broadKeys(tenant))
	if err != nil {
		return Reach{}, err
	}
	args := append(append([]any{
		tenant, principals, roles, a.cfg.Now(), reaching, publicKey, a.publicRoles(roles),
		string(p), resourceType,
	}, through...), broadKinds)
	rows, err := a.db.Query(ctx, `
		SELECT scope, bool_and(conditional) FROM (`+byType("$5", "g.scope, g.conditional", `
		  g.tenant = $1 AND g.principal = ANY($2::text[]) AND g.role = ANY(`+givingSQL("$3", "$1", "$8", "$9", custom, "")+`)
		  AND (g.expires_at IS NULL OR g.expires_at > $4)
		  AND (g.principal <> $6 OR g.role = ANY(`+givingSQL("$7", "$1", "$8", "$9", custom, publicOnly("$10"))+`))
		  AND (g.principal_kind <> ALL($13::text[]) OR g.role = ANY(`+givingSQL("$11", "$1", "$8", "$9", custom, listedOnly("$12"))+`))`)+`) g
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
	readingRoles()
	// A deny only takes away: where no grant reaches, there is nothing to take.
	if !reach.All && len(reach.Scopes)+len(reach.Conditional) == 0 {
		return Reach{}, nil
	}
	// Denies on scopes a resource of the type can have on its path: those of the type, the
	// containers and the tenant, that bind the subject (bindingDenies), as Filter finds them.
	if perm, wildcard, deniable := matchable(p); deniable {
		narrow := countedOf(binding, broad{})
		wide := slices.DeleteFunc(slices.Clone(binding), func(k string) bool { return slices.Contains(narrow, k) })
		rows, err = a.db.Query(ctx, `
			SELECT scope, bool_or(condition = '') FROM (`+bindingDenies("$1", "$2", "$3", "$7", "scope, condition, exempt, permissions")+`) d
			WHERE NOT exempt && $6::text[] AND ($4 = ANY(permissions) OR $5 = ANY(permissions))
			GROUP BY scope ORDER BY scope`,
			tenant, reaching, narrow, perm, wildcard, exempting(keys, s), wide)
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
	// compared byte for byte, whatever its collation, which the index serves in. Its first element,
	// at whatever subscript the array starts from, is the resource's own key.
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
// for the query it was built for: it fixes the time (Config.Now), the subject's label holding, what
// the constraints answered, and which custom roles granted to the public or the tenant's members
// give through them, when Filter was called, so a later query keeps rows Authorize then refuses, as
// once a grant it counted has expired, and leaves out what a custom role first granted to them
// since gives. Build one for each query. The host's query must reach this package's tables and call
// its function rbac_tenant_keys (they are in the pool's schema), and column names are trusted host
// code; every value is an argument. It counts only unconditional grants, and leaves out every
// resource a deny covers, conditional ones included, so it never keeps one Authorize refuses:
// Reachable's Conditional and ConditionalExcept name the scopes where that may be too strict.
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
	keys := func(of string) string { return filterKeys(arg, of) }
	grants := func(types string) string { return filterGrants(arg, custom, types) }
	// The denies on scopes of the types in the array types that bind the subject (bindingDenies).
	narrow := counted("FALSE", "FALSE")
	denies := func(types string) string {
		return fmt.Sprintf(`SELECT d.scope FROM (%s) d
			WHERE NOT d.exempt && %s AND (%s::text = ANY(d.permissions) OR %s::text = ANY(d.permissions))`,
			bindingDenies(arg(1)+"::text", types, keys("SELECT k FROM bound WHERE "+narrow), keys("SELECT k FROM bound WHERE NOT ("+narrow+")"),
				"scope, exempt, permissions"),
			keys("SELECT k FROM exempted"), arg(14), arg(15))
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
	// A row's own key is its path's first, at the array's lower bound: an array can start from any
	// subscript, and one stored from 0 holds its second key, a container's, at 1, which no deny or
	// grant on a resource of the type names.
	own := fmt.Sprintf(`(%[1]s)[array_lower(%[1]s, 1)] COLLATE "default"`, cols.Path)
	var deniedByKey string
	if !a.contains(resourceType) {
		denied = slices.DeleteFunc(denied, func(t string) bool { return t == resourceType })
		deniedByKey = fmt.Sprintf(`NOT %s IN (%s) AND `, own, denies("ARRAY["+arg(9)+"::text]"))
	}
	now := a.cfg.Now()
	// Which custom roles give p through the public and the tenant's members is read now, and the
	// statement keeps of them those that still give it, and through the public those still public:
	// one first granted to them later gives nothing through them.
	through, err := a.broadArgs(ctx, a.db, tenant, p, resourceType, roles, custom, broadOn("$4", "$5"), a.reaching(resourceType), broadKeys(tenant))
	if err != nil {
		return Predicate{}, err
	}
	filterArgs := func(above []string) []any {
		return append(append([]any{
			tenant, tenant, s.identityKey(), roles, now, above, publicKey, a.publicRoles(roles),
			string(p), resourceType,
		}, through...), counts.public, perm, wildcard, denied, counts.members)
	}
	resources, containers, err := a.grantCounts(ctx, custom, a.contains(resourceType), filterArgs(above))
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
		reached = fmt.Sprintf(`(%[4]s IN (%[3]s) OR %[1]s && %[2]s AND %[1]s && (%[2]s COLLATE "default"))`,
			cols.Path, overlap, grants("ARRAY["+arg(9)+"::text]"), own)
	}
	pred := Predicate{
		SQL: fmt.Sprintf(`(%[1]s = %[2]s AND (%[1]s)::text = %[5]s::text COLLATE "default" AND %[3]s
			AND %[7]sNOT %[6]s)`,
			cols.Tenant, arg(0), reached, cols.Path, arg(1), keyed(cols.Path, denies(arg(16))), deniedByKey),
		Args: filterArgs(above),
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
	labels, args := a.listedBy(h, p, resourceType).labelColumn(cols.Labels, arg, len(pred.Args))
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

// broadOn is SQL selecting the custom roles of the grants in force to the principals whose keys
// are in the array keys on scopes of the types in the array types, in the tenant $1.
func broadOn(types, keys string) string {
	return byType(types, "g.role", `g.tenant = $1 AND g.principal = ANY(`+keys+`::text[]) AND g.role LIKE 'custom.%'`)
}

// byKey is SQL selecting cols of the rows of table for which where holds whose col is one of the
// keys in the array keys, a key at a time: each an equality the indexes leading to col, or to the
// tenant and col, seek. A generic plan costs col = ANY(keys) as ten seeks, and a read of the tenant
// by an index leading to it alone, which it costs as an average tenant's few rows, as cheaper, so
// it reads every row of a large tenant. OFFSET 0 keeps the planner from flattening it into a join
// it could run the other way round. A key listed twice selects its rows twice, so each caller lists
// a key once, as a path and a sorted, compacted list do, or reads them through = ANY, EXISTS or
// DISTINCT, which a repeat changes nothing in.
func byKey(keys, table, col, cols, where string) string {
	return fmt.Sprintf(`SELECT r.* FROM unnest(%[1]s::text[]) AS keyed(k) CROSS JOIN LATERAL (
		SELECT %[4]s FROM %[2]s WHERE (%[5]s) AND %[3]s = keyed.k OFFSET 0) r`, keys, table, col, cols, where)
}

// bindingDenies is SQL selecting cols of the denies in a tenant, SQL for its text, on scopes of the
// types in the array types, that name one of the keys in the array narrow, an identity's or a
// group's, or in the array broad, the public's or the tenant's members'. Those naming narrow are
// found by those keys (naming). Any number of the tenant's denies can name broad, on scopes of any
// type, and no index finds those of a type alone: so while fewer than manyTypedDenies of the
// tenant's denies are on scopes of the types, they are read a type at a time, each a range of the
// scopes (ofType), and past that they are found by those keys too. Each way reads every deny the
// other passes over, so with many of both a list reads every deny in the tenant naming broad. The
// count reads at most manyTypedDenies entries of the scopes' index, once for the statement, in its
// snapshot. A deny naming both narrow and broad is selected twice.
func bindingDenies(tenant, types, narrow, broad, cols string) string {
	ofTypes := func(cols, where string) string {
		return `SELECT d.* FROM unnest(` + types + `::text[]) AS t(t) CROSS JOIN LATERAL (SELECT ` + cols + ` FROM rbac_denies
			WHERE tenant = ` + tenant + ` AND ` + where + ofType("scope", "t.t") + ` OFFSET 0) d`
	}
	return fmt.Sprintf(`WITH typed(few) AS MATERIALIZED (SELECT count(*) < %[5]d FROM (%[6]s LIMIT %[5]d) c)
		SELECT %[4]s FROM rbac_denies WHERE %[2]s AND scope_type = ANY(%[1]s::text[])
		UNION ALL
		SELECT %[4]s FROM rbac_denies WHERE %[3]s AND scope_type = ANY(%[1]s::text[]) AND NOT (SELECT few FROM typed)
		UNION ALL
		SELECT * FROM (%[7]s) d WHERE (SELECT few FROM typed)`,
		types, namingIn(tenant, "principals", narrow), namingIn(tenant, "principals", broad), cols, manyTypedDenies,
		ofTypes("1", ""), ofTypes(cols, "principals && "+broad+"::text[] AND "))
}

// manyTypedDenies is how many denies on scopes of the types a list reads bindingDenies reads by type
// to find those naming the public or the tenant's members, before it finds them by those keys.
const manyTypedDenies = 16

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

// filterKeys is SQL for the array of Filter's subject's keys of selects, as keysSQL defines them,
// read in the statement, as its grants and denies are, so a list reads its membership, its groups
// and what they hold in one snapshot. arg numbers Filter's arguments.
func filterKeys(arg func(int) string, of string) string {
	return "ARRAY(WITH RECURSIVE " + keysSQL(arg(1)+"::text", arg(2)+"::text", arg(4)) + " " + of + ")"
}

// filterGrants is SQL selecting the scopes of the grants Filter's condition counts for its subject
// on scopes of the types in the array types, in the default collation, which a column's own
// collation overrides where a comparison doesn't name one: unconditional, in force, of the roles
// that give the permission, the public's only of public ones and the broad principals' of none
// privileged. arg numbers Filter's arguments.
func filterGrants(arg func(int) string, custom bool, types string) string {
	return byType(types, `g.scope COLLATE "default"`, fmt.Sprintf(`g.tenant = %s::text AND g.principal = ANY(%s) AND g.role = ANY(%s)
		  AND (g.expires_at IS NULL OR g.expires_at > %s) AND NOT g.conditional
		  AND (g.principal <> %s::text OR g.role = ANY(%s))
		  AND (g.principal_kind <> ALL(%s) OR g.role = ANY(%s))`,
		arg(1), filterKeys(arg, countedKeys(arg(13), arg(17))), givingSQL(arg(3), arg(1), arg(8), arg(9), custom, ""), arg(4), arg(6),
		givingSQL(arg(7), arg(1), arg(8), arg(9), custom, publicOnly(arg(10))),
		broadKindsSQL, givingSQL(arg(11), arg(1), arg(8), arg(9), custom, listedOnly(arg(12)))))
}

// grantCounts counts, with Filter's arguments args, the grants its condition counts (filterGrants)
// on resources of the type, none for a container type, and on the containers, a container type's
// own among them, and the tenant, each only past where Filter's form compares them: it only picks
// the form. Grants the condition doesn't count, as of roles that don't give the permission, or a
// broad principal's that give nothing, counted would trade an index that finds the few rows its
// grants reach for a read of every row of the tenant.
func (a *Authorizer) grantCounts(ctx context.Context, custom, container bool, args []any) (resources, containers int, err error) {
	// The arguments the count reads, numbered from $1 as it first reads each.
	var read []any
	at := map[int]int{}
	arg := func(i int) string {
		if at[i] == 0 {
			read = append(read, args[i])
			at[i] = len(read)
		}
		return fmt.Sprintf("$%d", at[i])
	}
	onResources := "0"
	if !container {
		onResources = fmt.Sprintf(`(SELECT count(*) FROM (%s LIMIT %d) g)`, filterGrants(arg, custom, "ARRAY["+arg(9)+"::text]"), maxOverlap+1)
	}
	// The containers' and the tenant's are of the types Filter reads denies on by each key (16).
	query := fmt.Sprintf(`SELECT %s, (SELECT count(*) FROM (%s LIMIT %d) g)`,
		onResources, filterGrants(arg, custom, arg(16)), max(maxOverlap, maxContainerOverlap)+1)
	err = a.db.QueryRow(ctx, query, read...).Scan(&resources, &containers)
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

// heldOrDenied is readHeld of the grants, the denies of any permission and the roles alone, and
// with ending, when each grant's holding ends.
func (a *Authorizer) heldOrDenied(ctx context.Context, q DB, tenant string, s Subject, counts broad, scopes []string, roles rolesRead,
	ending bool,
) ([]holding, []denial, book, error) {
	got, err := a.readHeld(ctx, q, tenant, s, counts, scopes, "", roles, alsoRead{ending: ending})
	return got.held, got.ds, got.roles, err
}

// alsoRead is what else readHeld reads in its statement.
type alsoRead struct {
	// ending is when each grant's holding ends, as a change hands on nothing past it.
	ending bool
	// values is what the subject's label values are decided by (valuesRead), whatever counts and p
	// are, so they are of the moment its other grants are. The scopes hold the tenant's.
	values bool
	// keys are the subject's keys in the tenant, as keysOf reads them.
	keys bool
}

// grantsRead is what readHeld reads.
type grantsRead struct {
	held  []holding
	ds    []denial
	roles book
	// values is set with alsoRead.values, and keys read with alsoRead.keys.
	values *valuesRead
	keys   []string
}

// valuesRead is what a subject's label values are decided by: its grants on its tenant, and the
// denies binding it there, of any permission, with the custom roles they name; read with its other
// grants, in one statement or one snapshot, so a check of a label decides by what it held as it
// held them. The grants' conditions are read with them, or later where a decision needs them.
type valuesRead struct {
	held  []holding
	ds    []denial
	roles book
	// decided is the holding decided by it through each constrained, so a change's checks decide it
	// once for each read.
	decided map[*constrained]Holding
}

// onTenant is what of grants and denies read on scopes holding the tenant's, with roles, a subject's
// label values are decided by: those on the tenant's own scope. The others' denies don't bind its
// values, and their grants give none.
func onTenant(tenant string, held []holding, ds []denial, roles book) *valuesRead {
	key := TenantRoot(tenant).Key()
	v := &valuesRead{roles: roles}
	for _, h := range held {
		if h.scope == key {
			v.held = append(v.held, h)
		}
	}
	for _, d := range ds {
		if d.scope == key {
			v.ds = append(v.ds, d)
		}
	}
	return v
}

// readHeld returns the grants on any of scopes, not expired, held by s's principals in a tenant,
// counting broad ones as counts says, and the denies deniesOn reads for all its principals and p, or
// any permission when p is empty, in one statement that reads its membership and groups too, so a
// check is one round trip. The grants' part reads only what the key index holds, and the other
// indexes it could use lead to the principals and scopes too and hold the same, so whichever a plan
// picks, a generic one too, it is an index-only scan of no more grants. Like Explain, it reads no
// deny for a subject none of whose grants count, such as one that isn't a member or guest of the
// tenant. It reads the custom roles roles says in the statement too, as SetRole changes one in
// place: read apart, a grant revoked and its role widened meanwhile could give what no moment did.
// It reads what with says too.
func (a *Authorizer) readHeld(ctx context.Context, q DB, tenant string, s Subject, counts broad, scopes []string, p Permission,
	roles rolesRead, with alsoRead,
) (grantsRead, error) {
	got := grantsRead{roles: a.builtinBook()}
	if with.values {
		got.values = &valuesRead{roles: got.roles}
	}
	// The anonymous are the public alone: where it doesn't count, nothing gives the anonymous p, so
	// no label of it is decided either.
	if s.Principal == (Principal{}) && !counts.public {
		return got, nil
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
	// With values, the grants on the tenant of the broad principals counts leaves out, and every
	// deny binding the subject there: in the statement's text, which otherwise plans no read of them.
	// Each grant and deny says whether it is one for p.
	values, keyed := "FALSE", "FALSE"
	if with.values {
		values = "TRUE"
	}
	if with.keys {
		keyed = "TRUE"
	}
	forP := read + ` AND ($5 = '' OR $5 = ANY(permissions) OR $6 = ANY(permissions)) AND EXISTS (SELECT FROM keys WHERE ` + counted("$7", "$8") + `)`
	// In the statement, so they are of the moment its grants are.
	var places, ends string
	if with.ending {
		places = `, ` + endsSQL("$2::text", "$4")
		ends = `
		UNION ALL
		SELECT 3, k, '', '', '', e, false, NULL, '', NULL, false, false, NULL, '', '', false FROM ends`
	}
	// In the statement's text rather than an argument: a generic plan can't tell from one whether
	// to read every role of the tenant or look up those the grants name. Those are looked up a key at
	// a time (byKey): matched to the grants, a plan counting the tenant's roles as a few reads them
	// all, and as of a time each one's every version, again for each version.
	customRoles := "rbac_roles WHERE tenant = $1"
	switch roles {
	case namedRoles:
		customRoles = "(" + byKey("ARRAY(SELECT DISTINCT role FROM held WHERE role LIKE '"+CustomPrefix+"%')", "rbac_roles", "id", roleColumns, "tenant = $1") + ") r"
	case tenantRoles:
	case heldTenantRoles:
		customRoles += " AND EXISTS (SELECT FROM held WHERE role LIKE '" + CustomPrefix + "%')"
	}
	// Grants, denies, roles and keys in that order; grants by principal, scope, role and id, denies
	// by id and scope, as deniesOn.
	const deny, role, end, key = 1, 2, 3, 4
	rows, err := q.Query(ctx, `
		WITH RECURSIVE `+keysSQL("$1::text", "$2::text", "$4")+`, held AS (
		  SELECT id::text, principal, scope, role, expires_at, conditional, true AS counts FROM rbac_grants
		  WHERE tenant = $1 AND principal = ANY(ARRAY(`+countedKeys("$7", "$8")+`)) AND scope = ANY($3::text[])
		    AND (expires_at IS NULL OR expires_at > $4)
		  UNION ALL
		  SELECT id::text, principal, scope, role, expires_at, conditional, false FROM rbac_grants
		  WHERE `+values+` AND tenant = $1 AND principal = ANY(ARRAY(SELECT k FROM keys WHERE NOT (`+counted("$7", "$8")+`) ORDER BY k))
		    AND scope = 'tenant:' || $1 AND (expires_at IS NULL OR expires_at > $4)
		)`+places+`
		SELECT 0, id, principal, scope, role, expires_at, conditional, NULL::text[], '', NULL::text[], false, false, NULL::text[], '', '', counts
		FROM held
		UNION ALL
		SELECT 1, id, id, scope, '', NULL, condition <> '', permissions, condition, NULL, false, false, NULL, '', '', counts
		FROM (`+byKey("$3", "rbac_denies", "scope", "id, scope, permissions, condition, "+forP+" AS counts", `tenant = $1
		  AND principals && ARRAY(SELECT k FROM bound) AND NOT exempt && ARRAY(SELECT k FROM exempted)
		  AND (`+forP+` OR `+values+` AND scope = 'tenant:' || $1)`)+`) d
		UNION ALL
		SELECT 2, id, '', '', id, NULL, false, permissions, '', resource_types, privileged, public, grantable_roles, name, description, false
		FROM `+customRoles+ends+`
		UNION ALL
		SELECT 4, k, '', '', '', NULL, false, NULL, '', NULL, false, false, NULL, '', '', false FROM keys WHERE `+keyed+`
		ORDER BY 1, 3, 4, 5, 2`,
		tenant, s.identityKey(), scopes, a.cfg.Now(), perm, wildcard, counts.public, counts.members)
	if err != nil {
		return grantsRead{}, err
	}
	var custom []RoleDefinition
	placeEnds := map[string]time.Time{}
	tenantKey := TenantRoot(tenant).Key()
	var kind int
	var id, principal, scope, roleID, condition, name, description string
	var expires *time.Time
	var conditional, privileged, public, ofP bool
	var perms, types, grantable []string
	_, err = pgx.ForEachRow(rows, []any{&kind, &id, &principal, &scope, &roleID, &expires, &conditional, &perms, &condition, &types, &privileged, &public, &grantable, &name, &description, &ofP}, func() error {
		switch kind {
		case deny:
			d := denial{id: id, scope: scope, condition: condition}
			for _, x := range perms {
				d.permissions = append(d.permissions, Permission(x))
			}
			if ofP {
				got.ds = append(got.ds, d)
			}
			if with.values && scope == tenantKey {
				got.values.ds = append(got.values.ds, d)
			}
		case role:
			custom = append(custom, roleFrom(id, name, description, perms, types, privileged, public, grantable))
		case end:
			if expires == nil {
				placeEnds[id] = time.Time{}
			} else {
				placeEnds[id] = *expires
			}
		case key:
			got.keys = append(got.keys, id)
		default:
			h := holding{Binding: Binding{ID: id, Principal: parsePrincipal(principal), Role: Role(roleID)}, scope: scope, conditional: conditional}
			if expires != nil {
				h.ExpiresAt = *expires
			}
			if ofP {
				got.held = append(got.held, h)
			}
			if with.values && scope == tenantKey {
				got.values.held = append(got.values.held, h)
			}
		}
		return nil
	})
	if err != nil {
		return grantsRead{}, err
	}
	if with.ending {
		tenure := placeEnds[s.identityKey()]
		for i, h := range got.held {
			got.held[i].ends = h.ExpiresAt
			// A grant to the public reaches the subject whatever it is a member of.
			if h.Principal.Kind != Public {
				got.held[i].ends = sooner(got.held[i].ends, tenure)
			}
			if h.Principal.Kind == Group {
				got.held[i].ends = sooner(got.held[i].ends, placeEnds[h.Principal.key()])
			}
		}
	}
	if len(custom) > 0 {
		got.roles = a.bookOf(a.current(custom))
		if with.values {
			got.values.roles = got.roles
		}
	}
	return got, nil
}

// conditionsOf reads the conditions of the conditional grants among held not read already, in
// place.
func (a *Authorizer) conditionsOf(ctx context.Context, q DB, tenant string, held []holding) error {
	var ids, principals, scopes []string
	for _, h := range held {
		if h.conditional && h.Condition.Expression == "" {
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
		if h.conditional && h.Condition.Expression == "" {
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

func scanGrant(row pgx.CollectableRow) (Grant, error) { return scanGrantWith(row) }

// scanGrantWith scans a row of grantColumns, and after them, more.
func scanGrantWith(row pgx.CollectableRow, more ...any) (Grant, error) {
	var g Grant
	var expires *time.Time
	var approvedBy, createdBy, updatedBy string
	err := row.Scan(append([]any{
		&g.ID, &g.Scope.Type, &g.Scope.ID, &g.Principal.Kind, &g.Principal.ID, &g.Role, &g.Source, &expires,
		&g.Condition.Title, &g.Condition.Description, &g.Condition.Expression, &g.Note,
		&approvedBy, &createdBy, &g.CreatedAt, &updatedBy, &g.UpdatedAt,
	}, more...)...)
	if expires != nil {
		g.ExpiresAt = *expires
	}
	g.ApprovedBy, g.CreatedBy, g.UpdatedBy = parsePrincipal(approvedBy), parsePrincipal(createdBy), parsePrincipal(updatedBy)
	return g, err
}
