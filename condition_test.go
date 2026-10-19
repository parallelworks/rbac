package rbac_test

import (
	"errors"
	"strings"
	"testing"
	"time"

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

// doubling is a condition that nests a list in itself k times, so it holds 2^k values, at little
// cost, and then compares it with itself, which reads them all in one call.
func doubling(k int) string {
	return "[[1]]" + strings.Repeat(".map(x, [x, x])", k) + ".map(x, x == x)[0]"
}

func TestAConditionComparingMoreThanItsCostIsRefusedBeforeItRuns(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: doubling(24)}
	h.seed(t, g)
	start := time.Now()
	if allowed(t, h, h.as(t, "u"), login, cluster) {
		t.Fatal("a condition past its cost held")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("a check took %s", took)
	}
}

func TestAConditionNestedTooDeeplyIsRefused(t *testing.T) {
	h := setup(t)
	for name, expr := range map[string]string{
		"lists":          strings.Repeat("[", 40) + strings.Repeat("]", 40) + " == []",
		"parentheses":    strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40),
		"a chain of map": doubling(40),
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
