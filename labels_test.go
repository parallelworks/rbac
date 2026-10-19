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
