package rbac_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/parallelworks/rbac"
)

func TestADeclaredAttributePassedAsAnotherTypeFailsItsConditions(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"env": rbac.AttrString}}
	})
	ctx := t.Context()
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `resource.attributes.env != "prod"`}
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	u, v := h.as(t, "u"), h.as(t, "v")
	d := rbac.Deny{
		ID: "prod", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `resource.attributes.env == "prod"`},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	at := func(env any) rbac.Resource {
		r := cluster
		r.Attributes = map[string]any{"env": env}
		return r
	}
	if !allowed(t, h, u, login, at("dev")) || !allowed(t, h, v, login, at("dev")) {
		t.Fatal("a string the conditions take")
	}
	// CEL compares values of different types as unequal: as one not passed, it fails both the
	// grant's condition and the deny's, which then applies.
	for _, env := range []any{nil, 7, []string{"prod"}, []byte("prod")} {
		if allowed(t, h, u, login, at(env)) {
			t.Errorf("a grant's condition held for env %#v", env)
		}
		if allowed(t, h, v, login, at(env)) {
			t.Errorf("a deny's condition was lifted for env %#v", env)
		}
	}
}

func TestADeclaredAttributePassedAsAnotherTypeFailsAComparisonOfWhatHoldsIt(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"env": rbac.AttrString}}
	})
	ctx := t.Context()
	// Each holds for env "dev": CEL's own comparison of maps and lists counts a value that fails
	// as equal to anything.
	grants := map[string]string{
		"maps":        `dyn(resource.attributes) == {"env": "dev"}`,
		"lists":       `[dyn(resource.attributes)] == [{"env": "dev"}]`,
		"in a list":   `dyn(resource.attributes) in [{"env": "dev"}]`,
		"maps unlike": `{"env": "prod"} != dyn(resource.attributes)`,
	}
	gs := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian")}
	for id, expr := range grants {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, id)
		g.Condition = rbac.Condition{Expression: expr}
		gs = append(gs, g)
	}
	h.seed(t, gs...)
	v := h.as(t, "v")
	d := rbac.Deny{
		ID: "prod", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `{"env": "prod"} == dyn(resource.attributes)`},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	at := func(env any) rbac.Resource {
		r := cluster
		r.Attributes = map[string]any{"env": env}
		return r
	}
	for id := range grants {
		if !allowed(t, h, h.as(t, id), login, at("dev")) {
			t.Errorf("%s: a string the condition takes", id)
		}
	}
	if !allowed(t, h, v, login, at("dev")) {
		t.Error("a deny's condition held for env dev")
	}
	for _, env := range []any{nil, 7, []string{"prod"}} {
		for id := range grants {
			if allowed(t, h, h.as(t, id), login, at(env)) {
				t.Errorf("%s: a grant's condition held for env %#v", id, env)
			}
		}
		if allowed(t, h, v, login, at(env)) {
			t.Errorf("a deny's condition was lifted for env %#v", env)
		}
	}
}

func TestDeclaredAttributesChangedAfterNewAreReadAsDeclaredAtNew(t *testing.T) {
	declared := map[string]rbac.AttributeType{"env": rbac.AttrString}
	h := setup(t, func(c *rbac.Config) { c.Attributes = rbac.Attributes{Resource: declared} })
	declared["env"] = rbac.AttrInt
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `resource.attributes.env == "dev"`}
	h.seed(t, g)
	r := cluster
	r.Attributes = map[string]any{"env": "dev"}
	if !allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("an attribute checked as stored conditions read it")
	}
}

// named is a Go type a host may pass an attribute as, which CEL reads as a string.
type named string

func TestADeclaredAttributeIsReadAsWhatCELReadsItAs(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{
			"env": rbac.AttrString, "size": rbac.AttrInt, "tags": rbac.AttrStrings, "labels": rbac.AttrStringMap,
			"at": rbac.AttrTimestamp, "age": rbac.AttrDuration,
		}}
	})
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `resource.attributes.env == "dev" && resource.attributes.size == 3 &&
		"gpu" in resource.attributes.tags && resource.attributes.labels["team"] == "core" &&
		resource.attributes.at < request.time && resource.attributes.age > duration("1m")`}
	h.seed(t, g)
	env := "dev"
	r := cluster
	// As decoded from JSON, or passed as pointers and protobuf values.
	r.Attributes = map[string]any{
		"env": named(env), "size": int32(3), "tags": []any{"gpu"}, "labels": map[string]any{"team": "core"},
		"at": timestamppb.New(time.Unix(0, 0)), "age": durationpb.New(time.Hour),
	}
	if !allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("attributes CEL reads as their declared types")
	}
	r.Attributes["env"] = &env
	if !allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("a pointer to a string")
	}
	// A list or map holding another type is another type.
	r.Attributes["env"], r.Attributes["tags"] = "dev", []any{"gpu", 7}
	if allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("a list holding an int read as a list of strings")
	}
	r.Attributes["tags"], r.Attributes["labels"] = []any{"gpu"}, map[string]any{"team": "core", "n": 7}
	if allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("a map holding an int read as a map of strings")
	}
}

func TestADeclaredAttributePassedAsANilPointerOrAPointerToAListFailsItsConditions(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{
			"at": rbac.AttrTimestamp, "age": rbac.AttrDuration, "tags": rbac.AttrStrings,
		}}
	})
	ctx := t.Context()
	// Each grant's condition holds, and each deny's doesn't, for a value read as zero or empty.
	conditions := map[string][2]string{
		"at":   {`resource.attributes.at < timestamp("2020-01-01T00:00:00Z")`, `resource.attributes.at >= timestamp("2020-01-01T00:00:00Z")`},
		"age":  {`resource.attributes.age < duration("1h")`, `resource.attributes.age >= duration("1h")`},
		"tags": {`!("blocked" in resource.attributes.tags)`, `"blocked" in resource.attributes.tags`},
	}
	gs := []rbac.Grant{grant(cluster.Scope(), "guard", rbac.User, "guardian")}
	for name, c := range conditions {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, "granted-"+name)
		g.Condition = rbac.Condition{Expression: c[0]}
		gs = append(gs, g, grant(cluster.Scope(), "cluster.login", rbac.User, "denied-"+name))
	}
	h.seed(t, gs...)
	for name, c := range conditions {
		d := rbac.Deny{
			ID: name, Principals: []rbac.Principal{h.as(t, "denied-"+name).Principal}, Permissions: []rbac.Permission{login},
			Condition: rbac.Condition{Expression: c[1]},
		}
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	at := func(name string, v any) rbac.Resource {
		r := cluster
		r.Attributes = map[string]any{name: v}
		return r
	}
	for name, v := range map[string]any{"at": timestamppb.New(time.Unix(0, 0)), "age": durationpb.New(time.Minute), "tags": []string{}} {
		if !allowed(t, h, h.as(t, "granted-"+name), login, at(name, v)) || !allowed(t, h, h.as(t, "denied-"+name), login, at(name, v)) {
			t.Fatalf("%s: a value the conditions take", name)
		}
	}
	// CEL reads a nil timestamp or duration message as zero and a nil list message as empty, and
	// converting a pointer to a slice panics.
	for name, vs := range map[string][]any{
		"at":   {(*timestamppb.Timestamp)(nil)},
		"age":  {(*durationpb.Duration)(nil)},
		"tags": {(*structpb.ListValue)(nil), &[]string{}, []any{&[]string{}}},
	} {
		for _, v := range vs {
			if allowed(t, h, h.as(t, "granted-"+name), login, at(name, v)) {
				t.Errorf("%s: a grant's condition held for %#v", name, v)
			}
			if allowed(t, h, h.as(t, "denied-"+name), login, at(name, v)) {
				t.Errorf("%s: a deny's condition was lifted for %#v", name, v)
			}
		}
	}
}

// doubling is a condition that nests a list in itself k times, so it holds 2^k values, at little
// cost, and then compares it with itself, which reads them all in one call.
func doubling(k int, compare string) string {
	return "[[1]]" + strings.Repeat(".map(x, [x, x])", k) + ".map(x, " + compare + ")[0]"
}

func TestAConditionComparingMoreThanItsCostIsRefusedBeforeItRuns(t *testing.T) {
	h := setup(t)
	for id, compare := range map[string]string{"equal": "x == x", "unequal": "!(x != x)", "in": "x in [x]"} {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, id)
		g.Condition = rbac.Condition{Expression: doubling(24, compare)}
		h.seed(t, g)
		start := time.Now()
		if allowed(t, h, h.as(t, id), login, cluster) {
			t.Errorf("%s: a condition past its cost held", id)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s: a check took %s", id, took)
		}
	}
}

func TestAConditionNestedTooDeeplyIsRefused(t *testing.T) {
	h := setup(t)
	for name, expr := range map[string]string{
		"lists":          strings.Repeat("[", 40) + strings.Repeat("]", 40) + " == []",
		"parentheses":    strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40),
		"a chain of map": doubling(40, "x == x"),
	} {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
		g.Condition = rbac.Condition{Expression: expr}
		if err := h.authz.Import(t.Context(), host, "t1", []rbac.Grant{g}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAConditionPastItsCostSpendsNoMoreThanItsOwnBound(t *testing.T) {
	h := setup(t)
	// Evaluated first, as it is the shorter: it reads a list it can't afford to.
	wasteful := grant(cluster.Scope(), "cluster.login", rbac.User, "alice")
	wasteful.Condition = rbac.Condition{Expression: `resource.attributes.l == resource.attributes.l`}
	held := grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "alice")
	held.Condition = rbac.Condition{Expression: `request.attributes.mfa == true && request.attributes.site != "outside"`}
	h.seed(t, wasteful, held)
	r := cluster
	r.Attributes = map[string]any{"l": make([]int, 200000)}
	ctx := rbac.WithRequest(t.Context(), map[string]any{"mfa": true, "site": "hq"})
	if err := h.authz.Authorize(ctx, h.as(t, "alice"), login, r); err != nil {
		t.Fatalf("a condition that holds, after one past its cost: %v", err)
	}
}

func TestAnAttributeADeclaredKindDoesntDeclareFailsItsConditions(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"env": rbac.AttrString}}
	})
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	// dyn() reads past the declaration, which checks no type for team when stored.
	g.Condition = rbac.Condition{Expression: `dyn(resource.attributes).team != "x"`}
	h.seed(t, g)
	r := cluster
	r.Attributes = map[string]any{"env": "dev", "team": nil}
	if allowed(t, h, h.as(t, "u"), login, r) {
		t.Fatal("a condition held on an attribute its kind doesn't declare")
	}
}
