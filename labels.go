package rbac

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// LabelRule is how the values a subject holds in a dimension satisfy a label's values in it.
type LabelRule int

const (
	// Ordered is satisfied by a value at least as high as the label's highest, in the order the
	// dimension declares, lowest first: a higher value includes every lower one.
	Ordered LabelRule = iota + 1
	// AllOf is satisfied by holding every value the label has.
	AllOf
	// AnyOf is satisfied by holding one of the values the label has, or by any holding where it
	// has none.
	AnyOf
)

// LabelDimension is a kind of label a host declares: its name, which is the type of the
// permissions that are its values, as `rel:gbr` is the value gbr of the dimension rel; how
// values satisfy a label's; and its values, lowest first for Ordered.
type LabelDimension struct {
	Name   string
	Rule   LabelRule
	Values []string
}

// Label is a resource's label, or a data point's: by dimension, its values. A dimension it has no
// values in asks nothing of a subject.
type Label map[string][]string

// asks reports whether the label has a value in any dimension.
func (l Label) asks() bool {
	for _, vs := range l {
		if len(vs) > 0 {
			return true
		}
	}
	return false
}

// labelRefusal is why a check refuses what a label asks for in dim, which names no value.
func labelRefusal(dim string) string {
	return "the resource's label asks for values in " + dim + " the subject doesn't hold"
}

// unsatisfied returns the dimension of r's label that s's holding doesn't satisfy, or "".
func (a *Authorizer) unsatisfied(ctx context.Context, s Subject, r Resource) (string, error) {
	if !r.Labels.asks() {
		return "", nil
	}
	h, _, err := a.holding(ctx, r.Tenant, s)
	if err != nil {
		return "", err
	}
	return h.Unsatisfied(r.Labels), nil
}

// labelDimension is a dimension as checks read it: each value's rank, lowest 0.
type labelDimension struct {
	rule LabelRule
	rank map[string]int
}

// indexLabels checks the dimensions a host declares, and the catalog's roles that give their
// values, which a subject holds on the tenant alone.
func indexLabels(dims []LabelDimension, catalog []RoleDefinition) (map[string]labelDimension, error) {
	index := map[string]labelDimension{}
	for _, d := range dims {
		switch {
		case !validName(d.Name) || d.Name == TenantScope || d.Name == GroupScope:
			return nil, fmt.Errorf("rbac: label dimension %q is not a permission type", d.Name)
		case d.Rule < Ordered || d.Rule > AnyOf:
			return nil, fmt.Errorf("rbac: label dimension %q has no rule", d.Name)
		case len(d.Values) == 0:
			return nil, fmt.Errorf("rbac: label dimension %q has no values", d.Name)
		}
		if _, dup := index[d.Name]; dup {
			return nil, fmt.Errorf("rbac: label dimension %q is declared twice", d.Name)
		}
		ld := labelDimension{rule: d.Rule, rank: map[string]int{}}
		for i, v := range d.Values {
			p := Permission(d.Name + ":" + v)
			if !p.Valid() {
				return nil, fmt.Errorf("rbac: label dimension %q: value %q is not a permission's verb", d.Name, v)
			}
			// No deny takes a `:deny` permission, and a `:grant` one is a power over grants.
			if p.managesAccess() {
				return nil, fmt.Errorf("rbac: label dimension %q: value %q is a verb that changes access", d.Name, v)
			}
			if _, dup := ld.rank[v]; dup {
				return nil, fmt.Errorf("rbac: label dimension %q: value %q is declared twice", d.Name, v)
			}
			ld.rank[v] = i
		}
		index[d.Name] = ld
	}
	for _, r := range catalog {
		gives := false
		for _, p := range r.Permissions {
			t, v := p.parts()
			ld, ok := index[t]
			if !ok {
				continue
			}
			if _, ok := ld.rank[v]; !ok {
				return nil, fmt.Errorf("rbac: role %q gives %q, which isn't a value label dimension %q declares", r.ID, p, t)
			}
			gives = true
		}
		// A subject holds a value on the tenant: given on any other scope, it would read as held
		// nowhere, or be mistaken for a permission on that scope.
		if gives && !slices.Equal(r.ResourceTypes, []string{TenantScope}) {
			return nil, fmt.Errorf("rbac: role %q gives label values, so it is for the tenant alone", r.ID)
		}
		for _, t := range r.ResourceTypes {
			if _, ok := index[t]; ok {
				return nil, fmt.Errorf("rbac: role %q is for %q, a label dimension, not a resource type", r.ID, t)
			}
		}
	}
	return index, nil
}

// checkLabel returns why a label names a dimension or a value the host doesn't declare, which a
// check refuses as invalid rather than read as asking nothing.
func (a *Authorizer) checkLabel(l Label) error {
	for _, dim := range slices.Sorted(maps.Keys(l)) {
		ld, ok := a.labels[dim]
		if !ok {
			return fmt.Errorf("%w: the label's dimension %q isn't one the host declares (Config.Labels)", ErrInvalid, dim)
		}
		for _, v := range l[dim] {
			if _, ok := ld.rank[v]; !ok {
				return fmt.Errorf("%w: the label's value %q isn't one dimension %q declares", ErrInvalid, v, dim)
			}
		}
	}
	return nil
}

// Holding is the label values a subject holds in a tenant, by dimension, which its Satisfies
// checks a label against without reading the database: a feed checks each data point with it.
// It is what was held as it was read, in that request: a value also ends with no change to
// report, as a grant, a membership or a place in a group expires or a condition stops holding, so
// a feed reads it again as often as it may lag behind access ending, not only on changes.
type Holding struct {
	tenant string
	dims   map[string]labelDimension
	values map[string]map[string]bool
}

// Tenant is the tenant whose values these are: check only its data points with the holding.
func (h Holding) Tenant() string { return h.tenant }

// Values lists the label values held, as permissions, sorted.
func (h Holding) Values() []Permission {
	var ps []Permission
	for dim, vs := range h.values {
		for v := range vs {
			ps = append(ps, Permission(dim+":"+v))
		}
	}
	slices.Sort(ps)
	return ps
}

// Satisfies reports whether the values held satisfy a label in every dimension it has values in.
// A dimension or a value the holding's Authorizer doesn't declare is never satisfied.
func (h Holding) Satisfies(l Label) bool { return h.Unsatisfied(l) == "" }

// Unsatisfied returns the first dimension, in order of name, whose values in a label the holding
// doesn't satisfy, or "" where it satisfies them all.
func (h Holding) Unsatisfied(l Label) string {
	for _, dim := range slices.Sorted(maps.Keys(l)) {
		if !h.satisfies(dim, l[dim]) {
			return dim
		}
	}
	return ""
}

func (h Holding) satisfies(dim string, want []string) bool {
	ld, ok := h.dims[dim]
	if !ok {
		return false
	}
	// As Filter keeps no row whose label holds one, whatever else it holds.
	if slices.ContainsFunc(want, func(v string) bool { _, ok := ld.rank[v]; return !ok }) {
		return false
	}
	if len(want) == 0 {
		return true
	}
	held := h.values[dim]
	switch ld.rule {
	case Ordered:
		top := -1
		for v := range held {
			top = max(top, ld.rank[v])
		}
		return !slices.ContainsFunc(want, func(v string) bool { return ld.rank[v] > top })
	case AllOf:
		return !slices.ContainsFunc(want, func(v string) bool { return !held[v] })
	case AnyOf:
		return slices.ContainsFunc(want, func(v string) bool { return held[v] })
	}
	return false
}

// changed is a copy of the holding with ps held too, or with held false, without them.
func (h Holding) changed(ps map[Permission]bool, held bool) Holding {
	c := Holding{dims: h.dims, values: map[string]map[string]bool{}}
	for dim, vs := range h.values {
		c.values[dim] = maps.Clone(vs)
	}
	for p := range ps {
		dim, v := p.parts()
		switch {
		case !held:
			delete(c.values[dim], v)
		case c.values[dim] == nil:
			c.values[dim] = map[string]bool{v: true}
		default:
			c.values[dim][v] = true
		}
	}
	return c
}

// Holding returns the label values s holds in a tenant: those its grants give it on the tenant,
// decided as Permissions decides them, with ctx's request for their conditions.
func (a *Authorizer) Holding(ctx context.Context, tenant string, s Subject) (Holding, error) {
	if tenant == "" {
		return Holding{}, fmt.Errorf("%w: no tenant", ErrInvalid)
	}
	if err := a.subject(s); err != nil {
		return Holding{}, err
	}
	h, _, err := a.holding(ctx, tenant, s)
	return h, err
}

// holding is Holding, and the values a condition decided, a grant's or a deny's, which a read
// without the request, as Holders, can't settle.
func (a *Authorizer) holding(ctx context.Context, tenant string, s Subject) (Holding, map[Permission]bool, error) {
	h := Holding{tenant: tenant, dims: a.labels, values: map[string]map[string]bool{}}
	if len(a.labels) == 0 {
		return h, nil, nil
	}
	// Only the values, so neither the constraints nor the conditions of the tenant's other
	// permissions are asked about.
	value := func(p Permission) bool { t, _ := p.parts(); _, ok := a.labels[t]; return ok }
	perms, byCondition, err := a.permissionsOf(ctx, s, Resource{Tenant: tenant, Type: TenantScope, ID: tenant}, value)
	if err != nil {
		return Holding{}, nil, err
	}
	for _, p := range perms {
		t, v := p.parts()
		if h.values[t] == nil {
			h.values[t] = map[string]bool{}
		}
		h.values[t][v] = true
	}
	return h, byCondition, nil
}

// labelColumn is SQL keeping the rows whose label column, col, of `dimension:value` values, the
// holding satisfies, with its arguments numbered from arg: every value declared, none the holding
// doesn't satisfy alone, as an AllOf or Ordered one, and in each AnyOf dimension none or one held.
// Each test is an array operator, which a GIN index on col serves.
func (h Holding) labelColumn(col string, arg func(int) string, first int) (string, []any) {
	// In the default collation, which compares values as Satisfies does: in one that isn't
	// deterministic, col's own could find a value equal to another it holds that differs only in
	// case or punctuation.
	array := func(i int) string { return arg(i) + `::text[] COLLATE "default"` }
	// Empty, never nil, which pgx would send as NULL, and an array test of NULL keeps no row.
	declared, refused := []string{}, []string{}
	clauses := []string{col + " <@ " + array(first), "NOT " + col + " && " + array(first+1)}
	args := []any{nil, nil}
	for _, dim := range slices.Sorted(maps.Keys(h.dims)) {
		ld := h.dims[dim]
		all, held := []string{}, []string{}
		top := -1
		for v := range h.values[dim] {
			top = max(top, ld.rank[v])
		}
		for v, r := range ld.rank {
			key := dim + ":" + v
			all = append(all, key)
			switch ld.rule {
			case Ordered:
				if r > top {
					refused = append(refused, key)
				}
			case AllOf:
				if !h.values[dim][v] {
					refused = append(refused, key)
				}
			case AnyOf:
				if h.values[dim][v] {
					held = append(held, key)
				}
			}
		}
		slices.Sort(all)
		declared = append(declared, all...)
		if ld.rule == AnyOf {
			slices.Sort(held)
			n := first + len(args)
			clauses = append(clauses, fmt.Sprintf("(NOT %s && %s OR %s && %s)", col, array(n), col, array(n+1)))
			args = append(args, all, held)
		}
	}
	slices.Sort(declared)
	slices.Sort(refused)
	args[0], args[1] = declared, refused
	return "(" + strings.Join(clauses, " AND ") + ")", args
}
