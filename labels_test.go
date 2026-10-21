package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/parallelworks/rbac"
)

// labelDimensions are a level, compartments a subject must hold all of, and partners a label is
// releasable to.
var labelDimensions = []rbac.LabelDimension{
	{Name: "level", Rule: rbac.Ordered, Values: []string{"low", "mid", "high"}},
	{Name: "comp", Rule: rbac.AllOf, Values: []string{"alpha", "bravo"}},
	{Name: "rel", Rule: rbac.AnyOf, Values: []string{"usa", "gbr", "fra"}},
}

// labeled is setup with the label dimensions, and a role for the tenant giving each value.
func labeled(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return setup(t, append([]func(*rbac.Config){func(c *rbac.Config) {
		c.Labels = labelDimensions
		c.Catalog = slices.Clone(c.Catalog)
		for _, d := range labelDimensions {
			for _, v := range d.Values {
				c.Catalog = append(c.Catalog, rbac.RoleDefinition{
					ID: rbac.Role(d.Name + "." + v), Permissions: []rbac.Permission{rbac.Permission(d.Name + ":" + v)}, ResourceTypes: []string{rbac.TenantScope},
				})
			}
		}
	}}, mutate...)...)
}

// hold grants id roles giving label values on the tenant.
func (h *harness) hold(t *testing.T, id string, values ...string) {
	t.Helper()
	var grants []rbac.Grant
	for _, v := range values {
		grants = append(grants, grant(rbac.TenantRoot("t1"), rbac.Role(strings.Replace(v, ":", ".", 1)), rbac.User, id))
	}
	h.seed(t, grants...)
}

// compartments declares sixty compartments a subject must hold all of, a role for the tenant
// giving every one, and another giving one.
func compartments(c *rbac.Config) {
	var values []string
	var perms []rbac.Permission
	for i := range 60 {
		values = append(values, fmt.Sprintf("c%02d", i))
		perms = append(perms, rbac.Permission(fmt.Sprintf("comp:c%02d", i)))
	}
	c.Labels = []rbac.LabelDimension{{Name: "comp", Rule: rbac.AllOf, Values: values}}
	c.Catalog = append(slices.Clone(c.Catalog),
		rbac.RoleDefinition{ID: "compartments", Permissions: perms, ResourceTypes: []string{rbac.TenantScope}},
		rbac.RoleDefinition{ID: "compartment", Permissions: perms[:1], ResourceTypes: []string{rbac.TenantScope}},
		rbac.RoleDefinition{ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission(rbac.TenantScope)}, ResourceTypes: []string{rbac.TenantScope}},
	)
}

// A labeled check reads the subject's label values, each decided as a check of it would be: a
// condition that doesn't read the action decides the same for every value, so it is evaluated once
// for them all, a grant's or a deny's, however many values the grants carrying it give.
func TestALabeledCheckEvaluatesAConditionOnceForEveryValue(t *testing.T) {
	h := setup(t, compartments)
	ctx := t.Context()
	l := "[1,2,3,4,5,6,7,8]"
	costly := func(i int) string {
		return fmt.Sprintf(`%s.all(a,%s.all(b,%s.all(c,%s.all(d,a>%d))))`, l, l, l, l, -1-i)
	}
	tenant := rbac.TenantRoot("t1")
	// As many costly conditions as the subject's grants on the tenant and those to its members may
	// carry, and, costliest to compile, the one that holds.
	grants := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(tenant, "guard", rbac.User, "guardian")}
	holds := grant(tenant, "compartments", rbac.User, "u")
	holds.Condition = rbac.Condition{Expression: `request.attributes.mfa == true && "` + strings.Repeat("x", 200) + `" != ""`}
	grants = append(grants, holds)
	for i := range 13 {
		g := grant(tenant, "compartments", rbac.User, "u")
		if i >= 6 {
			g.Principal = rbac.TenantMembers("t1")
		}
		g.Condition = rbac.Condition{Expression: costly(i)}
		grants = append(grants, g)
	}
	h.seed(t, grants...)
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, rbac.Deny{
		ID: "mfa", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{"comp:*"},
		Condition: rbac.Condition{Expression: `request.attributes.mfa != true`},
	}); err != nil {
		t.Fatal(err)
	}
	u := h.as(t, "u")
	r := cluster
	r.Labels = rbac.Label{"comp": {"c00", "c59"}}
	n := rbac.CountEvaluations(t)
	if err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"mfa": true}), u, login, r); err != nil {
		t.Fatalf("with the condition that holds: %v", err)
	}
	if *n != 15 {
		t.Errorf("a labeled check evaluated %d conditions, of 15", *n)
	}
	if allowed(t, h, u, login, r) {
		t.Error("without it")
	}
}

// A condition that reads the action is evaluated apart for each label value a read of the subject's
// decides, so where it is stored it counts once for each value its grants give, or its denies deny:
// a cheap one fits for sixty values, and one that may cost all a condition may doesn't.
func TestAConditionReadingTheActionCountsOnceForEachLabelValue(t *testing.T) {
	h := setup(t, compartments)
	ctx := t.Context()
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	h.seed(t, grant(tenant.Scope(), "guard", rbac.User, "guardian"), grant(tenant.Scope(), "tenant.admin", rbac.User, "admin"))
	under := func(role rbac.Role, expr string) error {
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{{Scope: tenant.Scope(), Binding: rbac.Binding{
			Role: role, Principal: identity("u"), Condition: rbac.Condition{Expression: expr},
		}}})
	}
	deny := func(id string, p rbac.Permission, expr string) error {
		return h.authz.SetDeny(ctx, h.as(t, "guardian"), tenant, rbac.Deny{
			ID: id, Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{p},
			Condition: rbac.Condition{Expression: expr},
		})
	}
	reading := `action != "comp:c07" && request.attributes.groups.exists(g, g == "ops")`
	if err := under("compartments", reading); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a costly condition reading the action on a grant of sixty values: %v", err)
	}
	if err := deny("reading", "comp:*", reading); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("a costly condition reading the action on a deny of sixty values: %v", err)
	}
	// A cheap one, one that doesn't read it, or a grant or a deny of one value, fits.
	cheap := `action != "comp:c07" && request.attributes.mfa == true`
	for name, err := range map[string]error{
		"a cheap grant reading it": under("compartments", cheap),
		"a cheap deny reading it":  deny("cheap", "comp:*", cheap),
		"a grant not reading it":   under("compartments", `request.attributes.groups.exists(g, g == "sre")`),
		"a grant of one value":     under("compartment", reading),
		"a deny not reading it":    deny("not-reading", "comp:*", `request.attributes.groups.exists(g, g == "dev")`),
		"a deny of one value":      deny("one", "comp:c00", reading),
		"a grant of other powers":  under("tenant.admin", reading),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Redefining a role to give more label values counts a condition of its grants on the tenant that
// reads the action once for each, as granting it so would: one the role's grants carry where it
// gave one value can't stay where it gives sixty, and a cheap one can.
func TestRedefiningARoleToGiveMoreLabelValuesIsBoundedAsGrantingItSo(t *testing.T) {
	h := setup(t, compartments)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "definer"), grant(tenant, "compartments", rbac.User, "definer"))
	definer := h.as(t, "definer")
	all, _ := h.authz.BuiltinRole("compartments")
	reading := `action != "comp:c07" && request.attributes.groups.exists(g, g == "ops")`
	cheap := `action != "comp:c07" && request.attributes.mfa == true`
	for id, expr := range map[rbac.Role]string{"custom.costly": reading, "custom.cheap": cheap} {
		role := rbac.RoleDefinition{ID: id, Permissions: []rbac.Permission{"comp:c00"}, ResourceTypes: []string{rbac.TenantScope}}
		if err := h.authz.SetRole(ctx, definer, "t1", role); err != nil {
			t.Fatal(err)
		}
		// Each to a holder of its own, so neither's conditions count in the other's bucket.
		g := grant(tenant, id, rbac.User, string(id))
		g.Condition = rbac.Condition{Expression: expr}
		h.seed(t, g)
		role.Permissions = all.Permissions
		err := h.authz.SetRole(ctx, definer, "t1", role)
		if expr == reading && !errors.Is(err, rbac.ErrInvalid) || expr == cheap && err != nil {
			t.Errorf("%s widened to sixty values: %v", id, err)
		}
	}
	roles, err := h.authz.CustomRoles(ctx, "t1")
	if err != nil || len(roles) != 2 || len(roles[0].Permissions) != 60 || len(roles[1].Permissions) != 1 {
		t.Fatalf("the cheap role gives sixty values and the costly one still one: %d roles, %v", len(roles), err)
	}
}

func TestAHoldingSatisfiesALabelByItsDimensionsRules(t *testing.T) {
	h := labeled(t)
	pilot := h.as(t, "pilot")
	h.hold(t, "pilot", "level:mid", "comp:alpha", "rel:gbr")
	holding, err := h.authz.Holding(t.Context(), "t1", pilot)
	if err != nil {
		t.Fatal(err)
	}
	if got := holding.Values(); !slices.Equal(got, []rbac.Permission{"comp:alpha", "level:mid", "rel:gbr"}) {
		t.Fatalf("Values = %v", got)
	}
	for _, c := range []struct {
		label rbac.Label
		want  string
	}{
		{rbac.Label{}, ""},
		{rbac.Label{"level": {"low"}}, ""},
		{rbac.Label{"level": {"mid"}}, ""},
		{rbac.Label{"level": {"high"}}, "level"},
		{rbac.Label{"level": {"low", "high"}}, "level"},
		{rbac.Label{"comp": {"alpha"}}, ""},
		{rbac.Label{"comp": {"alpha", "bravo"}}, "comp"},
		{rbac.Label{"rel": {"usa", "gbr"}}, ""},
		{rbac.Label{"rel": {"usa"}}, "rel"},
		{rbac.Label{"rel": {}}, ""},
		{rbac.Label{"level": {"low"}, "comp": {"alpha"}, "rel": {"gbr", "fra"}}, ""},
		{rbac.Label{"comp": {"bravo"}, "rel": {"usa"}}, "comp"},
		{rbac.Label{"zone": {"red"}}, "zone"},
		{rbac.Label{"level": {"top"}}, "level"},
		{rbac.Label{"rel": {"mars", "gbr"}}, "rel"},
	} {
		if got := holding.Unsatisfied(c.label); got != c.want || holding.Satisfies(c.label) != (c.want == "") {
			t.Errorf("%v: Unsatisfied = %q, want %q", c.label, got, c.want)
		}
	}
	// One with none satisfies only what asks nothing.
	none, err := h.authz.Holding(t.Context(), "t1", h.as(t, "none"))
	if err != nil || none.Satisfies(rbac.Label{"level": {"low"}}) || none.Satisfies(rbac.Label{"rel": {"usa"}}) || !none.Satisfies(rbac.Label{"comp": {}}) {
		t.Fatalf("none = %v, %v", none.Values(), err)
	}
	// As checks refuse them, a holding is of a tenant, for a subject that can act.
	for name, s := range map[string]rbac.Subject{
		"an undeclared kind": {Principal: rbac.Principal{Kind: "robot", ID: "r1"}},
		"a group":            {Principal: rbac.Principal{Kind: rbac.Group, ID: "g1"}},
	} {
		if _, err := h.authz.Holding(t.Context(), "t1", s); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Holding of %s: %v", name, err)
		}
	}
	if _, err := h.authz.Holding(t.Context(), "", pilot); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("Holding of no tenant: %v", err)
	}
}

func TestALabelIsCheckedAboveEveryGrant(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}, "rel": {"gbr", "usa"}}
	// The owner's admin role gives everything, but its holding nothing.
	if allowed(t, h, owner, view, secret) {
		t.Fatal("a grant reached past the label")
	}
	if d, err := h.authz.Explain(ctx, owner, view, secret); err != nil || d.Allowed || d.Label != "level" || d.Reason == "" {
		t.Fatalf("Explain = %+v, %v", d, err)
	}
	if perms, err := h.authz.Permissions(ctx, owner, secret); err != nil || len(perms) != 0 {
		t.Fatalf("Permissions = %v, %v", perms, err)
	}
	if holders, err := h.authz.Holders(ctx, view, secret); err != nil || slices.Contains(holderPrincipals(holders), owner.Principal) {
		t.Fatalf("Holders = %+v, %v", holders, err)
	}
	h.hold(t, "owner", "level:high")
	if d, err := h.authz.Explain(ctx, owner, view, secret); err != nil || d.Allowed || d.Label != "rel" {
		t.Fatalf("Explain with the level but no partner = %+v, %v", d, err)
	}
	h.hold(t, "owner", "rel:usa")
	if !allowed(t, h, owner, view, secret) {
		t.Fatal("the label is satisfied, and the grant gives it")
	}
	if holders, err := h.authz.Holders(ctx, view, secret); err != nil || !slices.Contains(holderPrincipals(holders), owner.Principal) {
		t.Fatalf("Holders = %+v, %v", holders, err)
	}
	reach, err := h.authz.Reachable(ctx, owner, view, "t1", "cluster")
	if err != nil || !reach.Labels.Satisfies(secret.Labels) {
		t.Fatalf("Reachable's holding = %v, %v", reach.Labels.Values(), err)
	}
	// Values hold nothing without a grant: the label only takes away.
	stranger := h.as(t, "stranger")
	h.hold(t, "stranger", "level:high", "rel:usa")
	if allowed(t, h, stranger, view, secret) {
		t.Fatal("label values gave what no grant does")
	}
}

func TestALabelIsCheckedAboveThePowerToChangeGrants(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.as(t, "pilot")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	pilot := rbac.Binding{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "pilot"}}
	// The owner's admin role gives cluster:grant, which the label takes as it takes the rest.
	if roles, err := h.authz.Grantable(ctx, owner, secret); err != nil || len(roles) != 0 {
		t.Fatalf("Grantable = %v, %v", roles, err)
	}
	if err := h.authz.Apply(ctx, owner, secret, rbac.Change{Grant: []rbac.Binding{pilot}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("Apply = %v", err)
	}
	if err := h.authz.SetEligibility(ctx, owner, secret, rbac.Eligibility{Role: pilot.Role, Principal: pilot.Principal, MaxDuration: time.Hour}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("SetEligibility = %v", err)
	}
	h.hold(t, "owner", "level:high")
	if roles, err := h.authz.Grantable(ctx, owner, secret); err != nil || len(roles) == 0 {
		t.Fatalf("Grantable once the label is satisfied = %v, %v", roles, err)
	}
	if err := h.authz.Apply(ctx, owner, secret, rbac.Change{Grant: []rbac.Binding{pilot}}); err != nil {
		t.Fatalf("Apply once the label is satisfied: %v", err)
	}
}

func TestALabelValueHeldUnderAConditionHoldsWhereItHolds(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	g := grant(rbac.TenantRoot("t1"), "rel.gbr", rbac.User, "owner")
	g.Condition = rbac.Condition{Expression: `request.attributes.mission == true`}
	h.seed(t, g)
	partner := cluster
	partner.Labels = rbac.Label{"rel": {"gbr"}}
	if err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"mission": true}), owner, view, partner); err != nil {
		t.Fatalf("during the mission: %v", err)
	}
	if allowed(t, h, owner, view, partner) {
		t.Fatal("outside the mission")
	}
	// An access review can't tell, so it marks the holder, whatever the request it is made in.
	for _, ctx := range []context.Context{ctx, rbac.WithRequest(ctx, map[string]any{"mission": true})} {
		holders, err := h.authz.Holders(ctx, view, partner)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(holders, func(x rbac.Holder) bool { return x.Principal == owner.Principal })
		if i < 0 || !holders[i].MaybeDenied {
			t.Fatalf("Holders = %+v", holders)
		}
	}
}

func TestALabelValueAConditionalDenyTakesIsMarked(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), tenantGuard) })
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.hold(t, "owner", "rel:gbr")
	// The pilot holds the value only under a condition, which the deny's, where it holds, comes
	// before.
	pilot := h.as(t, "pilot")
	mission := rbac.Condition{Expression: `request.attributes.mission == true`}
	g := grant(rbac.TenantRoot("t1"), "rel.gbr", rbac.User, "pilot")
	g.Condition = mission
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "pilot"))
	// Those a deny without a condition takes the value from hold it under no request, as the
	// owner and the pilot do theirs.
	grounded, groundedPilot := h.as(t, "grounded"), h.as(t, "grounded-pilot")
	h.hold(t, "grounded", "rel:gbr")
	g = grant(rbac.TenantRoot("t1"), "rel.gbr", rbac.User, "grounded-pilot")
	g.Condition = mission
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "grounded"), grant(cluster.Scope(), "cluster.login", rbac.User, "grounded-pilot"))
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	for _, d := range []rbac.Deny{{
		ID: "off-mission", Principals: []rbac.Principal{owner.Principal, pilot.Principal, grounded.Principal, groundedPilot.Principal},
		Permissions: []rbac.Permission{"rel:gbr"}, Condition: rbac.Condition{Expression: `request.attributes.mission != true`},
	}, {
		ID: "grounded", Principals: []rbac.Principal{grounded.Principal, groundedPilot.Principal}, Permissions: []rbac.Permission{"rel:gbr"},
	}} {
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), tenant, d); err != nil {
			t.Fatal(err)
		}
	}
	partner := cluster
	partner.Labels = rbac.Label{"rel": {"gbr"}}
	if err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"mission": true}), pilot, view, partner); err != nil {
		t.Fatalf("the pilot during the mission: %v", err)
	}
	holders, err := h.authz.Holders(ctx, view, partner)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []rbac.Subject{owner, pilot} {
		i := slices.IndexFunc(holders, func(x rbac.Holder) bool { return x.Principal == s.Principal })
		if i < 0 || !holders[i].MaybeDenied {
			t.Errorf("%s: Holders = %+v", s.Principal.ID, holders)
		}
	}
	for _, s := range []rbac.Subject{grounded, groundedPilot} {
		if slices.Contains(holderPrincipals(holders), s.Principal) {
			t.Errorf("%s: Holders = %+v", s.Principal.ID, holders)
		}
	}
}

// tenantGuard sets denies on the tenant, as on label values.
var tenantGuard = rbac.RoleDefinition{ID: "tenant.guard", Permissions: []rbac.Permission{rbac.DenyPermission(rbac.TenantScope)}, ResourceTypes: []string{rbac.TenantScope}}

// Checks read a subject's label values on the tenant, so a deny of one under it would bind no one.
func TestALabelValueIsDeniedOnTheTenantAlone(t *testing.T) {
	workspaceGuard := rbac.RoleDefinition{ID: "workspace.guard", Permissions: []rbac.Permission{rbac.DenyPermission("workspace")}, ResourceTypes: []string{"workspace"}}
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), tenantGuard, workspaceGuard) })
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.hold(t, "owner", "level:high")
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"), grant(rbac.TenantRoot("t1"), "workspace.guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	for _, p := range []rbac.Permission{"level:high", "level:*"} {
		d := rbac.Deny{ID: "cap", Principals: []rbac.Principal{owner.Principal}, Permissions: []rbac.Permission{p}}
		if err := h.authz.SetDeny(ctx, guardian, workspace, d); !errors.Is(err, rbac.ErrInvalid) {
			t.Fatalf("a deny of %s on the workspace above the cluster: %v", p, err)
		}
	}
	if !allowed(t, h, owner, view, secret) {
		t.Fatal("the owner holds the level")
	}
	tenant := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}
	if err := h.authz.SetDeny(ctx, guardian, tenant, rbac.Deny{ID: "cap", Principals: []rbac.Principal{owner.Principal}, Permissions: []rbac.Permission{"level:high"}}); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, owner, view, secret) {
		t.Fatal("a deny of the value on the tenant binds")
	}
}

func TestFilterKeepsWhatTheLabelAllows(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE points (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `CREATE INDEX ON points USING gin (labels)`); err != nil {
		t.Fatal(err)
	}
	labels := []rbac.Label{
		{},
		{"level": {"low"}},
		{"level": {"high"}},
		{"comp": {"alpha"}},
		{"comp": {"alpha", "bravo"}},
		{"rel": {"gbr"}},
		{"rel": {"usa", "fra"}},
		{"level": {"mid"}, "rel": {"gbr"}},
		{"rel": {}},
	}
	var points []rbac.Resource
	for i, l := range labels {
		r := cluster
		r.ID, r.Labels = fmt.Sprintf("p%d", i), l
		var column []string
		for _, dim := range slices.Sorted(maps.Keys(l)) {
			for _, v := range l[dim] {
				column = append(column, dim+":"+v)
			}
		}
		if column == nil {
			column = []string{}
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO points VALUES ($1, $2, $3, $4)`, r.Tenant, r.ID, h.path(t, r), column); err != nil {
			t.Fatal(err)
		}
		points = append(points, r)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"))
	for _, c := range []struct {
		id   string
		hold []string
	}{
		{"nobody", nil},
		{"low", []string{"level:low"}},
		{"mid-gbr", []string{"level:mid", "rel:gbr"}},
		{"alpha", []string{"comp:alpha"}},
		{"all", []string{"level:high", "comp:alpha", "comp:bravo", "rel:fra"}},
	} {
		s := h.as(t, c.id)
		h.hold(t, c.id, c.hold...)
		// After an argument of the host's, so the label's are numbered after Filter's others.
		pred, err := h.authz.Filter(ctx, s, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 2)
		if err != nil {
			t.Fatal(err)
		}
		listed := listPoints(t, h, `id <> $1 AND `+pred.SQL, append([]any{"none"}, pred.Args...)...)
		var want []string
		for _, r := range points {
			if allowed(t, h, s, view, r) {
				want = append(want, r.ID)
			}
		}
		slices.Sort(want)
		if !slices.Equal(listed, want) {
			t.Errorf("%s: Filter %v, Authorize %v", c.id, listed, want)
		}
	}
}

// listPoints lists the ids of the rows of points where holds, in order.
func listPoints(t *testing.T, h *harness, where string, args ...any) []string {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), `SELECT id FROM points WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// A label column in a collation that isn't deterministic compares values the package tells apart
// as equal: Filter compares them as Satisfies does, byte for byte.
func TestFilterTellsLabelValuesApartInAnyCollation(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		c.Labels = append(slices.Clone(c.Labels), rbac.LabelDimension{Name: "team", Rule: rbac.AnyOf, Values: []string{"ab", "a-b"}})
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "team.ab", Permissions: []rbac.Permission{"team:ab"}, ResourceTypes: []string{rbac.TenantScope}},
			rbac.RoleDefinition{ID: "team.a-b", Permissions: []rbac.Permission{"team:a-b"}, ResourceTypes: []string{rbac.TenantScope}})
	})
	ctx := t.Context()
	for _, q := range []string{
		// Punctuation ignored, and case.
		`CREATE COLLATION loose (provider = icu, locale = 'und-u-ka-shifted-ks-level2', deterministic = false)`,
		`CREATE TABLE points (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] COLLATE loose NOT NULL)`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.Members, "t1"))
	s := h.as(t, "pilot")
	h.hold(t, "pilot", "team:ab", "rel:gbr")
	points := map[string]rbac.Label{"p0": {"team": {"a-b"}}, "p1": {"team": {"ab"}}, "p2": {"rel": {"GBR"}}}
	for id, l := range points {
		var column []string
		for dim, vs := range l {
			for _, v := range vs {
				column = append(column, dim+":"+v)
			}
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO points VALUES ('t1', $1, $2, $3)`, id, h.path(t, cluster), column); err != nil {
			t.Fatal(err)
		}
	}
	pred, err := h.authz.Filter(ctx, s, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := listPoints(t, h, pred.SQL, pred.Args...); !slices.Equal(got, []string{"p1"}) {
		t.Errorf("Filter = %v, want p1", got)
	}
	// p0's label is one the pilot doesn't satisfy, and p2's an undeclared value.
	r := cluster
	r.Labels = points["p0"]
	if allowed(t, h, s, view, r) {
		t.Error("Authorize allowed p0")
	}
	r.Labels = points["p2"]
	if err := h.authz.Authorize(ctx, s, view, r); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("Authorize of p2: %v", err)
	}
}

// Where the host names a label column, Filter tests it, so with no dimension declared it keeps
// only what has no label, as Authorize refuses any.
func TestFilterTestsALabelColumnWithNoDimensions(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `CREATE TABLE points (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for id, column := range map[string][]string{"p0": {}, "p1": {"zone:red"}} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO points VALUES ('t1', $1, $2, $3)`, id, h.path(t, cluster), column); err != nil {
			t.Fatal(err)
		}
	}
	owner := h.as(t, "owner")
	pred, err := h.authz.Filter(ctx, owner, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := listPoints(t, h, pred.SQL, pred.Args...); !slices.Equal(got, []string{"p0"}) {
		t.Errorf("Filter = %v, want p0", got)
	}
	r := cluster
	r.Labels = rbac.Label{"zone": {"red"}}
	if err := h.authz.Authorize(ctx, owner, view, r); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("Authorize: %v", err)
	}
}

func TestLabelsAreDeclared(t *testing.T) {
	h := labeled(t)
	owner := h.as(t, "owner")
	for name, l := range map[string]rbac.Label{
		"an undeclared dimension": {"zone": {"red"}},
		"an undeclared value":     {"level": {"top"}},
	} {
		r := cluster
		r.Labels = l
		if err := h.authz.Authorize(t.Context(), owner, view, r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*rbac.Config){
		"a role giving a value on a cluster": func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bad", Permissions: []rbac.Permission{"rel:gbr"}, ResourceTypes: []string{"cluster"}})
		},
		"a role giving an undeclared value": func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bad", Permissions: []rbac.Permission{"rel:mars"}, ResourceTypes: []string{rbac.TenantScope}})
		},
		"a dimension declared twice": func(c *rbac.Config) { c.Labels = append(slices.Clone(c.Labels), c.Labels[0]) },
		"a dimension with no rule": func(c *rbac.Config) {
			c.Labels = append(slices.Clone(c.Labels), rbac.LabelDimension{Name: "zone", Values: []string{"red"}})
		},
		// `zone:deny` would be a permission no deny takes, and `zone:grant` a power to change grants.
		"a value no deny could take": func(c *rbac.Config) {
			c.Labels = append(slices.Clone(c.Labels), rbac.LabelDimension{Name: "zone", Rule: rbac.AnyOf, Values: []string{"red", "deny"}})
		},
		"a value that is a power to change grants": func(c *rbac.Config) {
			c.Labels = append(slices.Clone(c.Labels), rbac.LabelDimension{Name: "zone", Rule: rbac.AllOf, Values: []string{"grant"}})
		},
		"a value named for the power to release": func(c *rbac.Config) {
			c.Labels = append(slices.Clone(c.Labels), rbac.LabelDimension{Name: "zone", Rule: rbac.Ordered, Values: []string{"release"}})
		},
		"an unprivileged role giving the power to release": func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bad", Permissions: []rbac.Permission{rbac.ReleasePermission("rel")}, ResourceTypes: []string{rbac.TenantScope}})
		},
		"a role giving the power to release on a cluster": func(c *rbac.Config) {
			c.Catalog = append(slices.Clone(c.Catalog), rbac.RoleDefinition{ID: "bad", Permissions: []rbac.Permission{rbac.ReleasePermission("rel")}, ResourceTypes: []string{"cluster"}, Privileged: true})
		},
	} {
		cfg := h.cfg
		mutate(&cfg)
		if _, err := rbac.New(h.pool, cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

func TestWhoCantSeeALabeledScopeSetsNoDenyOnIt(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guardRole) })
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{login}}
	if err := h.authz.SetDeny(ctx, guardian, secret, d); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("a deny on a scope its setter can't see: %v", err)
	}
	h.hold(t, "guardian", "level:high")
	if err := h.authz.SetDeny(ctx, guardian, secret, d); err != nil {
		t.Fatal(err)
	}
	// Lifting one widens access, which no one who can't see the scope may do either.
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "other"))
	if err := h.authz.DeleteDeny(ctx, h.as(t, "other"), secret, "d"); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("lifting a deny on a scope its lifter can't see: %v", err)
	}
	if err := h.authz.DeleteDeny(ctx, guardian, secret, "d"); err != nil {
		t.Fatal(err)
	}
}

func TestALabelValueRevokedWhileAChangeWaitsRefusesIt(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	viewer := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	// Of root, which no change here hands on, so that binding the actor too it refuses none of them.
	d := rbac.Deny{ID: "d", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Permissions: []rbac.Permission{root}}
	pilot := rbac.Binding{Role: "cluster.login", Principal: identity("pilot")}
	for name, change := range map[string]func(ctx context.Context, h *harness, admin rbac.Subject) error{
		"Apply": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.Apply(ctx, admin, secret, rbac.Change{Grant: []rbac.Binding{pilot}})
		},
		"SetEligibility": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.SetEligibility(ctx, admin, secret, rbac.Eligibility{Role: pilot.Role, Principal: pilot.Principal, MaxDuration: time.Minute})
		},
		"DeleteEligibility": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.DeleteEligibility(ctx, admin, secret, pilot.Role, pilot.Principal)
		},
		"SetDeny": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.SetDeny(ctx, admin, secret, rbac.Deny{ID: "e", Principals: d.Principals, Permissions: d.Permissions})
		},
		"DeleteDeny": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.DeleteDeny(ctx, admin, secret, d.ID)
		},
		"SetRole": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			widened := viewer
			widened.Permissions = []rbac.Permission{view, login}
			return h.authz.SetRole(ctx, admin, "t1", widened)
		},
		"DeleteRole": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.DeleteRole(ctx, admin, "t1", viewer.ID)
		},
		"SetGroup": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "new"})
		},
		"DeleteGroup": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.DeleteGroup(ctx, admin, "t1", "old")
		},
		"ChangeMembers of a labeled group": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "vault", Principal: pilot.Principal}}, nil)
		},
		"ChangeMembers granting on a labeled scope": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "ops", Principal: pilot.Principal}}, nil)
		},
		"ChangeMembers lifting a deny on a labeled scope": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "exempt", Principal: pilot.Principal}}, nil)
		},
		"ChangeMembers taking away access on a labeled scope": func(ctx context.Context, h *harness, admin rbac.Subject) error {
			return h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "ops", Principal: identity("crew")}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h := labeled(t, func(c *rbac.Config) {
				c.Catalog = append(c.Catalog, guardRole, groupMembers,
					rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
				resourceOf := c.ResourceOf
				// The cluster, a group and the tenant, as the host stores them, labeled.
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					switch s {
					case secret.Scope():
						return secret, nil
					case rbac.Scope{Type: rbac.GroupScope, ID: "vault"}, rbac.TenantRoot("t1"):
						return rbac.Resource{Tenant: tenant, Type: s.Type, ID: s.ID, Labels: secret.Labels}, nil
					}
					return resourceOf(ctx, tenant, s)
				}
				// Asked about the actor's clearance, before the change's transaction, the host revokes it.
				c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if do := meanwhile; do != nil && in.Permission == "level:high" {
						meanwhile = nil
						return false, do(ctx)
					}
					return false, nil
				}}}
			})
			ctx := t.Context()
			admin := roleAdmin(t, h)
			h.as(t, "pilot")
			h.hold(t, "admin", "level:high")
			h.seed(t, grant(rbac.TenantRoot("t1"), "guard", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"),
				grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
			// Groups the change to members names: one labeled, one holding a role on the labeled
			// cluster, with a member, and one a deny there exempts.
			h.groups(t, "vault", "ops", "exempt", "old")
			h.seed(t, grant(secret.Scope(), "cluster.login", rbac.Group, "ops"))
			h.as(t, "crew", "ops")
			if err := h.authz.SetDeny(ctx, admin, secret, rbac.Deny{ID: "x", Principals: d.Principals, Exempt: []rbac.Principal{groupOf("exempt")}, Permissions: d.Permissions}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.SetRole(ctx, admin, "t1", viewer); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(secret.Scope(), viewer.ID, rbac.User, "pilot"))
			if err := h.authz.SetEligibility(ctx, admin, secret, rbac.Eligibility{Role: pilot.Role, Principal: pilot.Principal, MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.SetDeny(ctx, admin, secret, d); err != nil {
				t.Fatal(err)
			}
			meanwhile = func(ctx context.Context) error {
				return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "admin")})
			}
			h.events = nil
			if err := change(ctx, h, admin); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("a change made once the actor lost the label value its scope's label asks for: %v", err)
			}
			if meanwhile != nil || len(h.events) != 1 || len(h.events[0].Revoked) != 1 {
				t.Fatalf("the clearance should have been revoked meanwhile, and nothing else changed: %+v", h.events)
			}
		})
	}
}

// Approving an activation decides access on its scope, as changing the grants there does, so on a
// labeled scope only an approver holding what the label asks for approves one: by its own values,
// which the constraints may remove, read again under the activation's locks, and decided without
// the request, which is the activating subject's, so every read of its attributes fails.
func TestApprovingAnActivationOnALabeledScopeNeedsItsLabel(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	var meanwhile func(context.Context) error
	validated := 0
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog, tenantGuard)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
		c.Constraints = []rbac.Constraint{{Name: "clearance", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Permission != "level:high" || in.Subject == nil {
				return false, nil
			}
			switch in.Subject.Principal.ID {
			case "barred":
				return true, nil
			case "revoked":
				// Asked before the activation's transaction, the host revokes the value.
				if do := meanwhile; do != nil {
					meanwhile = nil
					return false, do(ctx)
				}
			}
			return false, nil
		}}}
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, db rbac.DB, in rbac.GrantInput) error {
			if in.Via == rbac.ViaActivation {
				validated++
			}
			return validate(ctx, db, in)
		}
	})
	ctx := t.Context()
	h.hold(t, "owner", "level:high")
	u := h.as(t, "u")
	h.hold(t, "u", "level:high")
	h.groups(t, "approvers")
	approvers := []rbac.Principal{groupOf("approvers")}
	for _, id := range []string{"cleared", "uncleared", "lower", "conditional", "guarded", "flagged", "barred", "revoked"} {
		approvers = append(approvers, h.as(t, id).Principal)
	}
	h.as(t, "lead", "approvers")
	h.as(t, "member", "approvers")
	h.hold(t, "cleared", "level:high")
	h.hold(t, "lower", "level:mid")
	h.hold(t, "barred", "level:high")
	h.hold(t, "revoked", "level:high")
	h.hold(t, "lead", "level:high")
	// Its value under a condition on the request, which u's request in ctx meets.
	mfa := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "conditional")
	mfa.Condition = rbac.Condition{Expression: `request.attributes.mfa == true`}
	// Its value unless a request carries a risk, and a deny of another's where one does: u's
	// carries none, and with none, or an empty one, the value would hold and the deny lift.
	unflagged := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "guarded")
	unflagged.Condition = rbac.Condition{Expression: `!has(request.attributes.risk)`}
	h.seed(t, mfa, unflagged, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	h.hold(t, "flagged", "level:high")
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, rbac.Deny{
		ID: "risky", Principals: []rbac.Principal{identity("flagged")}, Permissions: []rbac.Permission{"level:high"},
		Condition: rbac.Condition{Expression: `has(request.attributes.risk)`},
	}); err != nil {
		t.Fatal(err)
	}
	ctx = rbac.WithRequest(ctx, map[string]any{"mfa": true})
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), secret, rbac.Eligibility{
		Role: "cluster.login", Principal: u.Principal, MaxDuration: time.Hour, Approvers: approvers,
	}); err != nil {
		t.Fatal(err)
	}
	activate := func(approver string) error {
		_, err := h.authz.Activate(ctx, u, secret, rbac.Activation{
			Role: "cluster.login", Duration: time.Minute, Justification: "on call", Approver: rbac.Subject{Principal: identity(approver)},
		})
		return err
	}
	for _, id := range []string{"uncleared", "lower", "member", "conditional", "guarded", "flagged", "barred"} {
		validated = 0
		if err := activate(id); !errors.Is(err, rbac.ErrDenied) || validated != 0 {
			t.Errorf("approved by %s, without the label's values: %v, the host asked %d times", id, err, validated)
		}
		if allowed(t, h, u, view, secret) {
			t.Fatalf("approved by %s, u can see the cluster", id)
		}
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "revoked")})
	}
	if err := activate("revoked"); !errors.Is(err, rbac.ErrDenied) || meanwhile != nil {
		t.Errorf("approved by one whose value was revoked while it activated: %v", err)
	}
	for _, id := range []string{"cleared", "lead"} {
		if err := activate(id); err != nil {
			t.Fatalf("approved by %s, holding the label's values: %v", id, err)
		}
		if !allowed(t, h, u, view, secret) {
			t.Fatalf("approved by %s, u can't see the cluster", id)
		}
		if err := h.authz.Deactivate(ctx, u, secret, "cluster.login"); err != nil {
			t.Fatal(err)
		}
	}
}

// The approver's values are read before the transaction wherever an eligibility it approves is
// found, not only where it outranks the one chosen as found then: under the locks, the paths'
// ends can rank an eligibility needing approval above one that doesn't, and its values, never
// asked about, would refuse every activation as a conflict.
func TestAnApprovalTheLocksRankFirstIsReadBeforeThem(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t)
	ctx := t.Context()
	h.hold(t, "owner", "level:high")
	h.groups(t, "a")
	u := h.as(t, "u", "a")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: u.Principal, ExpiresAt: h.now.Add(3 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	cleared := h.as(t, "cleared")
	h.hold(t, "cleared", "level:high")
	owner := h.as(t, "owner")
	// Through a, found first, needing no approval; through u's own, lasting longer, needing it.
	for _, e := range []rbac.Eligibility{
		{Role: "cluster.login", Principal: groupOf("a"), MaxDuration: time.Hour},
		{Role: "cluster.login", Principal: u.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{cleared.Principal}},
	} {
		if err := h.authz.SetEligibility(ctx, owner, secret, e); err != nil {
			t.Fatal(err)
		}
	}
	g, err := h.authz.Activate(ctx, u, secret, rbac.Activation{
		Role: "cluster.login", Duration: time.Minute, Justification: "on call", Approver: cleared,
	})
	if err != nil {
		t.Fatalf("approved by %s, holding the label's values: %v", cleared.Principal.ID, err)
	}
	if g.ApprovedBy != cleared.Principal {
		t.Errorf("approved by %v, not through u's own eligibility", g.ApprovedBy)
	}
}

func TestFilterNeedsTheLabelColumnWhereLabelsAreDeclared(t *testing.T) {
	h := labeled(t)
	s := h.as(t, "u")
	if _, err := h.authz.Filter(t.Context(), s, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("Filter without the label column: %v", err)
	}
	holding, err := h.authz.Holding(t.Context(), "t1", s)
	if err != nil || holding.Tenant() != "t1" {
		t.Fatalf("Holding = %+v, %v", holding, err)
	}
}

func TestALabelValueIsGrantedOnTheTenantAlone(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "workspace.admin", rbac.User, "admin"),
		grant(rbac.TenantRoot("t1"), "rel.gbr", rbac.User, "admin"))
	admin := h.as(t, "admin")
	// Granted on a workspace, a value would give nothing, so it isn't offered or taken there.
	if err := h.authz.Apply(ctx, admin, workspace, rbac.Change{Grant: []rbac.Binding{{Role: "rel.gbr", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a value granted on a workspace: %v", err)
	}
	roles, err := h.authz.Roles(ctx, "t1", "workspace")
	if err != nil || slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "rel.gbr" }) {
		t.Fatalf("Roles on a workspace = %v, %v", roles, err)
	}
	if err := h.authz.Apply(ctx, admin, rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1"}, rbac.Change{Grant: []rbac.Binding{{Role: "rel.gbr", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); err != nil {
		t.Fatalf("a value granted on the tenant: %v", err)
	}
}

func TestMayWriteKeepsDataUnderALabelAsRestrictive(t *testing.T) {
	h := labeled(t)
	pilot := h.as(t, "pilot")
	h.hold(t, "pilot", "level:mid", "comp:alpha", "rel:gbr")
	holding, err := h.authz.Holding(t.Context(), "t1", pilot)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		from, to rbac.Label
		want     bool
	}{
		{rbac.Label{}, rbac.Label{}, true},
		{rbac.Label{}, rbac.Label{"level": {}}, true},
		{rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"mid"}}, true},
		{rbac.Label{"level": {"low", "mid"}}, rbac.Label{"level": {"mid"}}, true},
		{rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"high"}}, true},
		{rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"low"}}, false},
		{rbac.Label{"level": {"mid"}}, rbac.Label{}, false},
		{rbac.Label{"level": {"high"}}, rbac.Label{"level": {"high"}}, false},
		{rbac.Label{"comp": {"alpha"}}, rbac.Label{"comp": {"alpha", "bravo"}}, true},
		{rbac.Label{"comp": {"alpha"}}, rbac.Label{"comp": {"bravo"}}, false},
		{rbac.Label{"comp": {"alpha"}}, rbac.Label{"level": {"high"}}, false},
		{rbac.Label{"rel": {"gbr", "usa"}}, rbac.Label{"rel": {"gbr"}}, true},
		{rbac.Label{}, rbac.Label{"rel": {"usa"}}, true},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {"gbr", "fra"}}, false},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {"fra"}}, false},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {}}, false},
		{rbac.Label{}, rbac.Label{"level": {"top"}}, false},
		{rbac.Label{}, rbac.Label{"zone": {"red"}}, false},
		{rbac.Label{}, rbac.Label{"zone": {}}, false},
	} {
		if got := holding.MayWrite(c.from, c.to); got != c.want {
			t.Errorf("MayWrite(%v, %v) = %v", c.from, c.to, got)
		}
	}
}

// releasing has a privileged role for the tenant giving each dimension's power to release.
func releasing(c *rbac.Config) {
	for _, d := range labelDimensions {
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{
			ID: rbac.Role(d.Name + ".release"), Permissions: []rbac.Permission{rbac.ReleasePermission(d.Name)}, ResourceTypes: []string{rbac.TenantScope}, Privileged: true,
		})
	}
}

func TestMayReleaseNeedsTheDimensionsPowerToRelease(t *testing.T) {
	h := labeled(t, releasing)
	ctx := t.Context()
	officer := h.as(t, "officer")
	h.hold(t, "officer", "level:mid", "comp:alpha", "rel:gbr", "level:release")
	holding, err := h.authz.Holding(ctx, "t1", officer)
	if err != nil {
		t.Fatal(err)
	}
	if got := holding.Values(); !slices.Equal(got, []rbac.Permission{"comp:alpha", "level:mid", "rel:gbr"}) {
		t.Fatalf("Values = %v", got)
	}
	for _, c := range []struct {
		from, to rbac.Label
		want     bool
	}{
		{rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"low"}}, true},
		{rbac.Label{"level": {"mid"}}, rbac.Label{}, true},
		{rbac.Label{"level": {"low"}}, rbac.Label{"level": {"mid"}}, true},
		{rbac.Label{"level": {"high"}}, rbac.Label{"level": {"low"}}, false},
		{rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"top"}}, false},
		{rbac.Label{"level": {"mid"}, "rel": {"gbr"}}, rbac.Label{"level": {"low"}, "rel": {"gbr"}}, true},
		{rbac.Label{"level": {"mid"}, "rel": {"gbr"}}, rbac.Label{"level": {"low"}}, false},
		{rbac.Label{"comp": {"alpha"}}, rbac.Label{}, false},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {"gbr", "fra"}}, false},
	} {
		if got := holding.MayRelease(c.from, c.to); got != c.want {
			t.Errorf("MayRelease(%v, %v) = %v", c.from, c.to, got)
		}
		// Writing never releases.
		if holding.MayWrite(c.from, c.to) && !c.want {
			t.Errorf("MayWrite(%v, %v)", c.from, c.to)
		}
	}
	if holding.MayWrite(rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"low"}}) {
		t.Error("MayWrite released")
	}

	h.hold(t, "officer", "rel:release", "comp:release")
	if holding, err = h.authz.Holding(ctx, "t1", officer); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ from, to rbac.Label }{
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {"gbr", "fra"}}},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{"rel": {"usa"}}},
		{rbac.Label{"rel": {"gbr"}}, rbac.Label{}},
		{rbac.Label{"comp": {"alpha"}}, rbac.Label{}},
		{rbac.Label{"level": {"mid"}, "comp": {"alpha"}, "rel": {"gbr"}}, rbac.Label{"comp": {"bravo"}}},
	} {
		if !holding.MayRelease(c.from, c.to) {
			t.Errorf("MayRelease(%v, %v)", c.from, c.to)
		}
	}
	if holding.MayRelease(rbac.Label{"comp": {"bravo"}}, rbac.Label{}) {
		t.Error("released data it can't read")
	}
}

func TestAPowerToReleaseHeldUnderAConditionIsNoValue(t *testing.T) {
	h := labeled(t, releasing)
	owner := h.as(t, "owner")
	g := grant(rbac.TenantRoot("t1"), "level.release", rbac.User, "owner")
	g.Condition = rbac.Condition{Expression: `request.attributes.mission == true`}
	h.seed(t, g)
	low := cluster
	low.Labels = rbac.Label{"level": {"low"}}
	holders, err := h.authz.Holders(t.Context(), view, low)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(holders, func(x rbac.Holder) bool { return x.Principal == owner.Principal }) {
		t.Fatalf("Holders = %+v", holders)
	}

	// With a level, the label is what decides, and the condition the power to release.
	h.hold(t, "owner", "level:mid")
	if holders, err = h.authz.Holders(t.Context(), view, low); err != nil || !slices.Contains(holderPrincipals(holders), owner.Principal) {
		t.Fatalf("Holders with a level = %+v, %v", holders, err)
	}
	for mission, want := range map[bool]bool{false: false, true: true} {
		holding, err := h.authz.Holding(rbac.WithRequest(t.Context(), map[string]any{"mission": mission}), "t1", owner)
		if err != nil {
			t.Fatal(err)
		}
		if got := holding.MayRelease(rbac.Label{"level": {"mid"}}, rbac.Label{"level": {"low"}}); got != want {
			t.Errorf("MayRelease on a mission %v = %v", mission, got)
		}
	}
}

func TestACustomRoleGivingALabelValueIsForTheTenantAlone(t *testing.T) {
	h := labeled(t, releasing)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.hold(t, "admin", "rel:gbr", "rel:release")
	for _, r := range []rbac.RoleDefinition{
		{ID: "custom.liaison", Permissions: []rbac.Permission{"rel:gbr"}, ResourceTypes: []string{"cluster"}},
		{ID: "custom.liaison", Permissions: []rbac.Permission{"rel:gbr"}, ResourceTypes: []string{rbac.TenantScope, "cluster"}},
		{ID: "custom.officer", Permissions: []rbac.Permission{rbac.ReleasePermission("rel")}, ResourceTypes: []string{"cluster"}},
	} {
		if err := h.authz.SetRole(ctx, admin, "t1", r); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s for %v: %v", r.ID, r.ResourceTypes, err)
		}
	}
	if err := h.authz.SetRole(ctx, admin, "t1", rbac.RoleDefinition{ID: "custom.liaison", Permissions: []rbac.Permission{"rel:gbr"}, ResourceTypes: []string{rbac.TenantScope}}); err != nil {
		t.Fatalf("for the tenant: %v", err)
	}
}

// A label value a custom role gives is read with the grant of the role, as of one moment, as a
// check reads what its grants give.
func TestALabelValueIsReadWithItsCustomRoleAsOfOneMoment(t *testing.T) {
	h := labeled(t)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.hold(t, "admin", "comp:alpha", "comp:bravo")
	cleared := rbac.RoleDefinition{ID: "custom.cleared", Permissions: []rbac.Permission{"comp:alpha"}, ResourceTypes: []string{rbac.TenantScope}}
	if err := h.authz.SetRole(ctx, admin, "t1", cleared); err != nil {
		t.Fatal(err)
	}
	held := grant(rbac.TenantRoot("t1"), cleared.ID, rbac.User, "op")
	h.seed(t, held)
	operator := h.as(t, "op")
	// Once the values are read, its grant is revoked and then its role widened.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{held}); err != nil {
			t.Error(err)
		}
		widened := cleared
		widened.Permissions = []rbac.Permission{"comp:alpha", "comp:bravo"}
		if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
			t.Error(err)
		}
	})
	values, err := h.authz.Permissions(ctx, operator, tenantT1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(values, []rbac.Permission{"comp:alpha"}) {
		t.Fatalf("held %v: a revoked grant gave a value its role was widened to after", values)
	}
}

// A constraint asked about a holder without the request's attributes answers for any, so Holders
// marks one whose label value it may remove, as it marks one it may remove the permission from.
func TestHoldersMarksAHolderAConstraintMayRemoveALabelValueFrom(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "high with a second factor", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			return in.Permission == "level:high" && (in.Subject == nil || in.Subject.Attributes["mfa"] != true), nil
		}}}
	})
	owner := h.as(t, "owner")
	h.hold(t, "owner", "level:high")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	if !allowed(t, h, rbac.Subject{Principal: owner.Principal, Attributes: map[string]any{"mfa": true}}, view, secret) || allowed(t, h, owner, view, secret) {
		t.Fatal("the constraint decides the value by the subject's second factor")
	}
	holders, err := h.authz.Holders(t.Context(), view, secret)
	if err != nil || len(holders) != 1 || holders[0].Principal != owner.Principal || !holders[0].MaybeDenied {
		t.Fatalf("Holders = %+v, %v", holders, err)
	}
}

// A subject's label values are decided on the tenant as Holding reads them for every labeled check,
// without the attributes or label a check passes with the tenant, for conditions and constraints
// alike: so a check of a value, Explain, Permissions and Holders agree with a check of a label.
func TestALabelValueIsDecidedOnTheTenantAsALabeledCheckReadsIt(t *testing.T) {
	var asked []rbac.Resource
	h := labeled(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "lockdown", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Permission != "level:high" || in.Resource == nil {
				return false, nil
			}
			asked = append(asked, *in.Resource)
			// Clearances frozen while the tenant is locked down.
			return in.Resource.Attributes["lockdown"] == true, nil
		}}}
	})
	ctx := t.Context()
	h.hold(t, "ann", "level:high")
	cleared := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "bob")
	cleared.Condition = rbac.Condition{Expression: `resource.attributes.cleared == true`}
	h.seed(t, cleared, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "ann"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "ann"), grant(cluster.Scope(), "cluster.login", rbac.User, "bob"))
	ann, bob := h.as(t, "ann"), h.as(t, "bob")
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	tenants := map[string]rbac.Resource{
		"locked down": {Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"lockdown": true}},
		"cleared":     {Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"cleared": true}},
		"labeled":     {Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Labels: rbac.Label{"comp": {"alpha"}}},
	}
	for name, tenant := range tenants {
		for _, s := range []rbac.Subject{ann, bob} {
			holding, err := h.authz.Holding(ctx, "t1", s)
			if err != nil {
				t.Fatal(err)
			}
			held := slices.Contains(holding.Values(), "level:high")
			if held != (s.Principal == ann.Principal) || allowed(t, h, s, view, secret) != held {
				t.Fatalf("%s: Holding %v, and a check of the label disagrees", s.Principal.ID, holding.Values())
			}
			if allowed(t, h, s, "level:high", tenant) != held {
				t.Errorf("%s, %s: Authorize of the value allows it: %v, though Holding holds it: %v", name, s.Principal.ID, !held, held)
			}
			d, err := h.authz.Explain(ctx, s, "level:high", tenant)
			if err != nil || d.Allowed != held {
				t.Errorf("%s, %s: Explain = %+v, %v", name, s.Principal.ID, d, err)
			}
			perms, err := h.authz.Permissions(ctx, s, tenant)
			if err != nil || slices.Contains(perms, "level:high") != held {
				t.Errorf("%s, %s: Permissions = %v, %v", name, s.Principal.ID, perms, err)
			}
		}
		holders, err := h.authz.Holders(ctx, "level:high", tenant)
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.IndexFunc(holders, func(x rbac.Holder) bool { return x.Principal == ann.Principal }); i < 0 || holders[i].MaybeDenied {
			t.Errorf("%s: Holders = %+v", name, holders)
		}
	}
	if i := slices.IndexFunc(asked, func(r rbac.Resource) bool { return len(r.Attributes) > 0 || len(r.Labels) > 0 }); i >= 0 {
		t.Errorf("a constraint was asked about a label value on the tenant as passed: %+v", asked[i])
	}
	// The tenant's other permissions are decided on it as passed.
	if allowed(t, h, ann, "tenant:view", tenants["labeled"]) {
		t.Error("the tenant's label no longer binds its other permissions")
	}
	perms, err := h.authz.Permissions(ctx, ann, tenants["labeled"])
	if err != nil || !slices.Equal(perms, []rbac.Permission{"level:high"}) {
		t.Errorf("Permissions on the labeled tenant = %v, %v", perms, err)
	}
}

// An actor hands on a label value only as it holds it: a change on the tenant passed with
// attributes asks a constraint about the value on the tenant as every check decides it, so one the
// actor can't use there it can't grant, nor offer.
func TestALabelValueIsHandedOnAsChecksDecideIt(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "probation", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			// Lifted only on a tenant passed as approved.
			approved := in.Resource != nil && in.Resource.Attributes["approved"] == true
			return in.Permission == "level:high" && in.Subject != nil && in.Subject.Principal.ID == "ann" && !approved, nil
		}}}
	})
	ctx := t.Context()
	h.hold(t, "ann", "level:high")
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "ann"))
	ann, bob := h.as(t, "ann"), h.as(t, "bob")
	approved := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"approved": true}}
	if allowed(t, h, ann, "level:high", approved) {
		t.Fatal("the constraint should remove level:high from ann on the tenant as checks decide it")
	}
	roles, err := h.authz.Grantable(ctx, ann, approved)
	if err != nil || slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "level.high" }) {
		t.Errorf("Grantable offers level.high, which ann can't use: %v", err)
	}
	err = h.authz.Apply(ctx, ann, approved, rbac.Change{Grant: []rbac.Binding{{Role: "level.high", Principal: bob.Principal}}})
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("ann granted level.high, which it can't use: %v", err)
	}
	if allowed(t, h, bob, "level:high", tenantT1) {
		t.Error("bob holds level:high")
	}
}

// A label value's conditions can't read the tenant's attributes: it is decided on the bare tenant,
// where any read of them fails, a test of one's presence, in, size(), a macro and a comparison
// too, so a deny guarded by one applies and a grant guarded by one's absence gives nothing,
// whatever tenant a check passes, rather than lift or hold for what the bare tenant lacks. The
// tenant's type and id read as ever.
func TestALabelValuesConditionsCantReadTheTenantsAttributes(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), tenantGuard) })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	// Each false where the attributes are empty, so a deny under it would lift there, and a grant
	// under its negation give.
	frozen := []string{
		`has(resource.attributes.frozen) && resource.attributes.frozen == true`,
		`"frozen" in resource.attributes`,
		`size(resource.attributes) > 0`,
		`resource.attributes.exists(k, k == "frozen")`,
		`resource.attributes != {}`,
	}
	type held struct {
		s    rbac.Subject
		held bool
	}
	var subjects []held
	for i, expr := range frozen {
		denied, granted := h.as(t, fmt.Sprint("denied", i)), h.as(t, fmt.Sprint("granted", i))
		g := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, granted.Principal.ID)
		g.Condition = rbac.Condition{Expression: "!(" + expr + ")"}
		h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, denied.Principal.ID), grant(cluster.Scope(), "cluster.login", rbac.User, granted.Principal.ID))
		h.hold(t, denied.Principal.ID, "level:high")
		if err := h.authz.SetDeny(ctx, guardian, tenantT1, rbac.Deny{
			ID: fmt.Sprint("frozen", i), Principals: []rbac.Principal{denied.Principal}, Permissions: []rbac.Permission{"level:high"},
			Condition: rbac.Condition{Expression: expr},
		}); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, held{denied, false}, held{granted, false})
	}
	// One reading only the tenant's type and id holds.
	ours := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "ours")
	ours.Condition = rbac.Condition{Expression: `resource.type == "tenant" && resource.id == "t1" && resource.tenant == "t1"`}
	h.seed(t, ours, grant(cluster.Scope(), "cluster.login", rbac.User, "ours"))
	subjects = append(subjects, held{h.as(t, "ours"), true})
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	tenants := []rbac.Resource{tenantT1, {Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"frozen": true}}}
	for _, c := range subjects {
		holding, err := h.authz.Holding(ctx, "t1", c.s)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(holding.Values(), "level:high") != c.held {
			t.Errorf("%s: Holding = %v", c.s.Principal.ID, holding.Values())
		}
		for _, tenant := range tenants {
			if allowed(t, h, c.s, "level:high", tenant) != c.held {
				t.Errorf("%s: Authorize of the value on %v allows it: %v", c.s.Principal.ID, tenant.Attributes, !c.held)
			}
			perms, err := h.authz.Permissions(ctx, c.s, tenant)
			if err != nil || slices.Contains(perms, "level:high") != c.held {
				t.Errorf("%s: Permissions on %v = %v, %v", c.s.Principal.ID, tenant.Attributes, perms, err)
			}
		}
		if allowed(t, h, c.s, view, secret) != c.held {
			t.Errorf("%s: a check of the labeled cluster allows it: %v", c.s.Principal.ID, !c.held)
		}
	}
	// What a deny takes from one it can't hand on either.
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "denied0"))
	err := h.authz.Apply(ctx, subjects[0].s, tenantT1, rbac.Change{Grant: []rbac.Binding{{Role: "level.high", Principal: identity("ours")}}})
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("handing on level:high, which a deny takes: %v", err)
	}
}

// A read decides a resource's label by the label values the subject held as it held its grants:
// one moved, in one statement, between the group granted on a labeled cluster and the group
// holding the label's value never held both, so no read made while it moves lets it see the
// cluster, whichever way it moves, whatever a read reads first.
func TestReadsDecideALabelByTheValuesHeldWithTheGrants(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	reads := map[string]func(t *testing.T, h *harness, x rbac.Subject) bool{
		"Authorize": func(t *testing.T, h *harness, x rbac.Subject) bool { t.Helper(); return allowed(t, h, x, view, secret) },
		"Explain": func(t *testing.T, h *harness, x rbac.Subject) bool {
			t.Helper()
			d, err := h.authz.Explain(t.Context(), x, view, secret)
			if err != nil {
				t.Fatal(err)
			}
			return d.Allowed
		},
		"Permissions": func(t *testing.T, h *harness, x rbac.Subject) bool {
			t.Helper()
			perms, err := h.authz.Permissions(t.Context(), x, secret)
			if err != nil {
				t.Fatal(err)
			}
			return slices.Contains(perms, view)
		},
		"Grantable": func(t *testing.T, h *harness, x rbac.Subject) bool {
			t.Helper()
			roles, err := h.authz.Grantable(t.Context(), x, secret)
			if err != nil {
				t.Fatal(err)
			}
			return len(roles) > 0
		},
		"Reachable": func(t *testing.T, h *harness, x rbac.Subject) bool {
			t.Helper()
			reach, err := h.authz.Reachable(t.Context(), x, view, "t1", "cluster")
			if err != nil {
				t.Fatal(err)
			}
			return (reach.All || slices.Contains(reach.Scopes, cluster.Scope())) && reach.Labels.Satisfies(secret.Labels)
		},
		"Holders": func(t *testing.T, h *harness, x rbac.Subject) bool {
			t.Helper()
			holders, err := h.authz.Holders(t.Context(), view, secret)
			if err != nil {
				t.Fatal(err)
			}
			return slices.ContainsFunc(holders, func(hd rbac.Holder) bool { return hd.Principal == x.Principal })
		},
	}
	world := func(t *testing.T, groups ...string) (*harness, rbac.Subject) {
		t.Helper()
		h := labeled(t)
		h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.Group, "readers"), grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"))
		return h, h.as(t, "x", groups...)
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			if h, x := world(t, "readers", "cleared"); !read(t, h, x) {
				t.Fatal("in both groups, x may see the cluster")
			}
			for from, to := range map[string]string{"readers": "cleared", "cleared": "readers"} {
				h, x := world(t, from)
				moved := false
				rbac.SetReadingRoles(t, func() {
					if moved {
						return
					}
					moved = true
					if _, err := h.pool.Exec(h.ctx, `WITH gone AS (DELETE FROM rbac_members WHERE tenant = 't1' AND group_id = $1 AND principal_kind = 'user' AND principal_id = 'x')
						INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', $2, 'user', 'x')`, from, to); err != nil {
						t.Error(err)
					}
				})
				if read(t, h, x) {
					t.Errorf("moved from %s to %s as it read, x may see the labeled cluster, though it never held both its grant and its value", from, to)
				}
				if !moved {
					t.Fatal("the read reached no hook")
				}
			}
		})
	}
}

// Under its locks a change checks its actor's power on a labeled scope and the label's values as
// of one moment. Here the actor's own value is revoked before the change's transaction, and once
// the transaction has read its power, it moves from the group giving that power to the group
// holding the value: at no moment there did it hold both, so the change is refused.
func TestAChangeChecksALabelByTheValuesHeldWithItsPower(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	guard := rbac.RoleDefinition{ID: "cluster.guard", Permissions: []rbac.Permission{rbac.DenyPermission("cluster")}, ResourceTypes: []string{"cluster"}}
	for name, change := range map[string]func(h *harness, x rbac.Subject, to string) error{
		"Apply": func(h *harness, x rbac.Subject, to string) error {
			return h.authz.Apply(h.ctx, x, secret, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity(to)}}})
		},
		"SetDeny": func(h *harness, x rbac.Subject, to string) error {
			return h.authz.SetDeny(h.ctx, x, secret, rbac.Deny{ID: to, Principals: []rbac.Principal{identity(to)}, Permissions: []rbac.Permission{root}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), guard) })
			h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.Group, "leads"), grant(cluster.Scope(), guard.ID, rbac.Group, "leads"),
				grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"))
			x := h.as(t, "x", "leads")
			h.hold(t, "x", "level:high")
			h.as(t, "u")
			h.as(t, "v")
			if err := change(h, x, "v"); err != nil {
				t.Fatalf("x holds the power and the value: %v", err)
			}
			moved := false
			rbac.SetReadingRoles(t, func() {
				// The change's transaction holds a connection of the test's pool; its reads before it
				// hold none once read.
				if h.pool.Stat().AcquiredConns() == 0 {
					if _, err := h.pool.Exec(h.ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:x' AND role = 'level.high'`); err != nil {
						t.Error(err)
					}
					return
				}
				if moved {
					return
				}
				moved = true
				if _, err := h.pool.Exec(h.ctx, `WITH gone AS (DELETE FROM rbac_members WHERE tenant = 't1' AND group_id = 'leads' AND principal = 'user:x')
					INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'cleared', 'user', 'x')`); err != nil {
					t.Error(err)
				}
			})
			err := change(h, x, "u")
			if !moved {
				t.Fatal("the change read its power in its transaction without reaching the hook")
			}
			if !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("the change was made, by an actor that held its power and the label's value at no moment: %v", err)
			}
		})
	}
}

// Under the activation's locks an approver is checked as one of the approvers and as holding the
// label's values as of one moment. Here its own value is revoked before the transaction, and once
// the transaction has read its groups, it moves from the approving group to the group holding the
// value: it never was both, so it approves nothing.
func TestAnApproverIsCheckedAsOneOfTheApproversHoldingTheValuesAtOnce(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.hold(t, "owner", "level:high")
	u := h.as(t, "u")
	h.hold(t, "u", "level:high")
	h.seed(t, grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"))
	approver := h.as(t, "approver", "approvers")
	h.hold(t, "approver", "level:high")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), secret, rbac.Eligibility{
		Role: "cluster.login", Principal: u.Principal, MaxDuration: time.Hour, Approvers: []rbac.Principal{groupOf("approvers")},
	}); err != nil {
		t.Fatal(err)
	}
	activate := func() error {
		_, err := h.authz.Activate(ctx, u, secret, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "on call", Approver: approver})
		return err
	}
	if err := activate(); err != nil {
		t.Fatalf("approved by one of the approvers holding the value: %v", err)
	}
	if err := h.authz.Deactivate(ctx, u, secret, "cluster.login"); err != nil {
		t.Fatal(err)
	}
	inTx := func() bool { return h.pool.Stat().AcquiredConns() > 0 }
	rbac.SetReadingRoles(t, func() {
		if !inTx() {
			if _, err := h.pool.Exec(h.ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:approver' AND role = 'level.high'`); err != nil {
				t.Error(err)
			}
		}
	})
	moved := false
	rbac.SetReadingKeys(t, func() {
		if !inTx() || moved {
			return
		}
		moved = true
		if _, err := h.pool.Exec(h.ctx, `WITH gone AS (DELETE FROM rbac_members WHERE tenant = 't1' AND group_id = 'approvers' AND principal = 'user:approver')
			INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'cleared', 'user', 'approver')`); err != nil {
			t.Error(err)
		}
	})
	err := activate()
	if !moved {
		t.Fatal("the activation read its approver's groups in its transaction without reaching the hook")
	}
	if !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("approved by one that never was an approver holding the label's value: %v", err)
	}
}

// Under its locks a change to a labeled group, or to its members, checks its actor's power over
// groups and the group's label values as of one moment. Here the actor's own value is revoked once
// the change has checked it before its transaction, and once the transaction has read its power,
// it moves from the group giving that power to the group holding the value: at no moment did it
// hold both, so the change is refused.
func TestAChangeToALabeledGroupChecksItsLabelByTheValuesHeldWithThePower(t *testing.T) {
	vault := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "vault", Labels: rbac.Label{"level": {"high"}}}
	for name, change := range map[string]func(h *harness, x rbac.Subject) error{
		"ChangeMembers": func(h *harness, x rbac.Subject) error {
			return h.authz.ChangeMembers(h.ctx, x, "t1", []rbac.Member{{Group: "vault", Principal: identity("u")}}, nil)
		},
		"SetGroup": func(h *harness, x rbac.Subject) error {
			return h.authz.SetGroup(h.ctx, x, "t1", rbac.GroupDefinition{ID: "vault", Name: "Vault"})
		},
		"DeleteGroup": func(h *harness, x rbac.Subject) error { return h.authz.DeleteGroup(h.ctx, x, "t1", "vault") },
	} {
		t.Run(name, func(t *testing.T) {
			var revoke func()
			h := labeled(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), groupMembers,
					rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s == vault.Scope() {
						return vault, nil
					}
					return resourceOf(ctx, tenant, s)
				}
				// Asked about x's value before the transaction alone, once the change has read it.
				c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if do := revoke; do != nil && in.Permission == "level:high" {
						do()
					}
					return false, nil
				}}}
			})
			h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.Group, "leads"), grant(rbac.TenantRoot("t1"), "group.members", rbac.Group, "leads"),
				grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"))
			h.groups(t, "vault")
			x := h.as(t, "x", "leads")
			h.hold(t, "x", "level:high")
			h.as(t, "u")
			revoke = func() {
				if _, err := h.pool.Exec(h.ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:x' AND role = 'level.high'`); err != nil {
					t.Error(err)
				}
			}
			moved := false
			rbac.SetReadingRoles(t, func() {
				// The change's transaction holds a connection of the test's pool; its reads before it
				// hold none once read.
				if h.pool.Stat().AcquiredConns() == 0 || moved {
					return
				}
				moved = true
				if _, err := h.pool.Exec(h.ctx, `WITH gone AS (DELETE FROM rbac_members WHERE tenant = 't1' AND group_id = 'leads' AND principal = 'user:x')
					INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'cleared', 'user', 'x')`); err != nil {
					t.Error(err)
				}
			})
			err := change(h, x)
			if !moved {
				t.Fatal("the change read its power in its transaction without reaching the hook")
			}
			if !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("the change was made, by an actor that held its power and the group's label value at no moment: %v", err)
			}
		})
	}
}

// Under its locks a removal from a group granted on a labeled scope checks the scope's label by the
// actor's values as it held its power over the group's members. Here the actor's own value is
// revoked once the removal has checked it before its transaction, and once the transaction has read
// its power, it moves from the group giving that power to the group holding the value: at no moment
// did it hold both, so the removal is refused.
func TestARemovalChecksTheLabelItReachesByTheValuesHeldWithThePower(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	var revoke func()
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
		// Asked about x's value before the transaction alone, once the removal has read it.
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := revoke; do != nil && in.Permission == "level:high" {
				do()
			}
			return false, nil
		}}}
	})
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.Group, "leads"), grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"),
		grant(cluster.Scope(), "cluster.login", rbac.Group, "readers"))
	x := h.as(t, "x", "leads")
	h.hold(t, "x", "level:high")
	h.as(t, "u", "readers")
	revoke = func() {
		if _, err := h.pool.Exec(h.ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:x' AND role = 'level.high'`); err != nil {
			t.Error(err)
		}
	}
	moved := false
	rbac.SetReadingRoles(t, func() {
		// The removal's transaction holds a connection of the test's pool; its reads before it hold
		// none once read.
		if h.pool.Stat().AcquiredConns() == 0 || moved {
			return
		}
		moved = true
		if _, err := h.pool.Exec(h.ctx, `WITH gone AS (DELETE FROM rbac_members WHERE tenant = 't1' AND group_id = 'leads' AND principal = 'user:x')
			INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'cleared', 'user', 'x')`); err != nil {
			t.Error(err)
		}
	})
	err := h.authz.ChangeMembers(h.ctx, x, "t1", nil, []rbac.Member{{Group: "readers", Principal: identity("u")}})
	if !moved {
		t.Fatal("the removal read its power in its transaction without reaching the hook")
	}
	if !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("the removal was made, by an actor that held its power and the scope's label value at no moment: %v", err)
	}
}

// A deny of a label value reads the tenant as checks decide the value, its type, id and tenant
// included, when the actor hands the value on as when it uses it: one whose condition is false
// there takes nothing the actor hands on, as it takes nothing it uses, and one that holds there, or
// reads the tenant's attributes, takes both, whatever tenant a change passes.
func TestALabelValuesDenyReadsTheTenantAsChecksDoWhenTheValueIsHandedOn(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), tenantGuard) })
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"))
	guardian, bob := h.as(t, "guardian"), h.as(t, "bob")
	passed := rbac.Resource{Tenant: "t1", Type: rbac.TenantScope, ID: "t1", Attributes: map[string]any{"region": "eu"}}
	for i, c := range []struct {
		expr string
		held bool
	}{
		{`resource.id == "t2"`, true},
		{`resource.tenant != "t1"`, true},
		{`resource.type != "tenant"`, true},
		{`resource.id == "t1"`, false},
		{`resource.attributes.region == "eu"`, false},
	} {
		actor := h.as(t, fmt.Sprint("actor", i))
		h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, actor.Principal.ID))
		h.hold(t, actor.Principal.ID, "level:high")
		if err := h.authz.SetDeny(ctx, guardian, tenantT1, rbac.Deny{
			ID: fmt.Sprint("deny", i), Principals: []rbac.Principal{actor.Principal}, Permissions: []rbac.Permission{"level:high"},
			Condition: rbac.Condition{Expression: c.expr},
		}); err != nil {
			t.Fatal(err)
		}
		for _, tenant := range []rbac.Resource{tenantT1, passed} {
			if allowed(t, h, actor, "level:high", tenant) != c.held {
				t.Fatalf("%s: a check of the value allows it: %v", c.expr, !c.held)
			}
			roles, err := h.authz.Grantable(ctx, actor, tenant)
			if err != nil {
				t.Fatal(err)
			}
			if slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "level.high" }) != c.held {
				t.Errorf("%s, on %v: Grantable offers level.high: %v, though the actor holds it: %v", c.expr, tenant.Attributes, !c.held, c.held)
			}
			err = h.authz.Apply(ctx, actor, tenant, rbac.Change{Grant: []rbac.Binding{{Role: "level.high", Principal: bob.Principal}}})
			if (err == nil) != c.held || err != nil && !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("%s, on %v: handing on level:high, which the actor holds: %v: %v", c.expr, tenant.Attributes, c.held, err)
			}
		}
	}
}

// Holders of a labeled resource reads the label values of every identity it lists in one
// statement, however many they are, and decides each as a read of one decides it: by its grants
// on the tenant and its groups', through those they are in, under the denies binding it there,
// marking one a condition decides.
func TestHoldersOfALabeledResourceReadEveryHoldersValuesAtOnce(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	list := func(t *testing.T, others int) (map[string]bool, int) {
		t.Helper()
		h := labeled(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), tenantGuard) })
		ctx := t.Context()
		h.groups(t, "big", "cleared", "inner")
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'cleared', 'group', 'inner')`); err != nil {
			t.Fatal(err)
		}
		conditional := grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "conditional")
		conditional.Condition = rbac.Condition{Expression: `request.attributes.mfa == true`}
		h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "big"), grant(rbac.TenantRoot("t1"), "level.high", rbac.Group, "cleared"),
			grant(rbac.TenantRoot("t1"), "tenant.guard", rbac.User, "guardian"), conditional)
		for id, groups := range map[string][]string{
			"direct": {"big"}, "nested": {"big", "inner"}, "lower": {"big"}, "none": {"big"}, "conditional": {"big"},
			"denied": {"big", "cleared"}, "exempt": {"big", "cleared"},
		} {
			h.as(t, id, groups...)
		}
		h.hold(t, "direct", "level:high")
		h.hold(t, "lower", "level:mid")
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), tenantT1, rbac.Deny{
			ID: "cleared", Principals: []rbac.Principal{groupOf("cleared")}, Exempt: []rbac.Principal{identity("exempt"), groupOf("inner")},
			Permissions: []rbac.Permission{"level:*"},
		}); err != nil {
			t.Fatal(err)
		}
		manyMembers(t, h, others, `, places AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) SELECT 't1', 'big', 'user', id FROM others)
			SELECT 1`, "rbac_members")
		reads := 0
		rbac.SetReadingRoles(t, func() { reads++ })
		holders, err := h.authz.Holders(ctx, view, secret)
		if err != nil {
			t.Fatal(err)
		}
		listed := map[string]bool{}
		for _, hd := range holders {
			listed[hd.Principal.ID] = hd.MaybeDenied
		}
		return listed, reads
	}
	want := map[string]bool{"direct": false, "nested": false, "exempt": false, "conditional": true}
	few, n := list(t, 0)
	if !maps.Equal(few, want) {
		t.Errorf("Holders = %v, by MaybeDenied, of %v", few, want)
	}
	many, m := list(t, 200)
	if !maps.Equal(many, want) {
		t.Errorf("among 200 more members: Holders = %v, by MaybeDenied, of %v", many, want)
	}
	if m != n {
		t.Errorf("Holders read grants %d times among 7 members, and %d among 207", n, m)
	}
}
