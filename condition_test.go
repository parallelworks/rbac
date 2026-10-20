package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
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

// NaN compares as false with anything, and an infinity is NaN once taken from another, so either
// would lift a deny ordering a declared double and hold a grant ordering it the other way.
func TestADeclaredDoubleThatIsntFiniteFailsItsConditions(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Request: map[string]rbac.AttributeType{"risk": rbac.AttrDouble}}
	})
	ctx := t.Context()
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `request.attributes.risk < 0.5`}
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	u, v := h.as(t, "u"), h.as(t, "v")
	d := rbac.Deny{
		ID: "risky", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `request.attributes.risk >= 0.5`},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	is := func(s rbac.Subject, risk float64) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"risk": risk}), s, login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	if !is(u, 0.1) || !is(v, 0.1) || is(u, 0.9) || is(v, 0.9) {
		t.Fatal("finite risks the conditions order")
	}
	for _, risk := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if is(u, risk) {
			t.Errorf("a grant's condition held for risk %v", risk)
		}
		if is(v, risk) {
			t.Errorf("a deny's condition was lifted for risk %v", risk)
		}
	}
}

// A condition can make a double that isn't finite of finite ones, dividing by zero or converting
// "NaN", which CEL orders and equates as false with anything: so comparing one fails too.
func TestADoubleAConditionMakesThatIsntFiniteFailsWhatComparesIt(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Request: map[string]rbac.AttributeType{
			"failed": rbac.AttrDouble, "total": rbac.AttrDouble, "score": rbac.AttrString,
		}}
	})
	ctx := t.Context()
	const ratio = `request.attributes.failed / request.attributes.total`
	grants := []string{ratio + ` < 0.5`, `!(` + ratio + ` >= 0.5)`, ratio + ` != 1.0`}
	denies := []string{ratio + ` >= 0.5`, ratio + ` == 1.0`, `double(request.attributes.score) >= 0.5`}
	seeded := []rbac.Grant{grant(cluster.Scope(), "guard", rbac.User, "guardian")}
	for i, expr := range grants {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, fmt.Sprint("u", i))
		g.Condition = rbac.Condition{Expression: expr}
		seeded = append(seeded, g, grant(cluster.Scope(), "cluster.login", rbac.User, fmt.Sprint("v", i)))
	}
	h.seed(t, seeded...)
	for i, expr := range denies {
		d := rbac.Deny{
			ID: fmt.Sprint("d", i), Principals: []rbac.Principal{identity(fmt.Sprint("v", i))}, Permissions: []rbac.Permission{login},
			Condition: rbac.Condition{Expression: expr},
		}
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	is := func(who string, request map[string]any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, request), h.as(t, who), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	finite := map[string]any{"failed": 0.0, "total": 1.0, "score": "0.1"}
	for i := range 3 {
		if !is(fmt.Sprint("u", i), finite) || !is(fmt.Sprint("v", i), finite) {
			t.Fatalf("finite doubles: %s, %s", grants[i], denies[i])
		}
	}
	for name, request := range map[string]map[string]any{
		"NaN":       {"failed": 0.0, "total": 0.0, "score": "NaN"},
		"infinity":  {"failed": 1.0, "total": 0.0, "score": "inf"},
		"-infinity": {"failed": -1.0, "total": 0.0, "score": "-inf"},
	} {
		for i := range 3 {
			if is(fmt.Sprint("u", i), request) {
				t.Errorf("a grant's condition %s held for %s", grants[i], name)
			}
			if is(fmt.Sprint("v", i), request) {
				t.Errorf("a deny's condition %s was lifted for %s", denies[i], name)
			}
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

// A declared attribute passed as nil, as a nil pointer or as another type fails a test of its
// presence, and whatever reads the attributes as a whole, as it fails what reads it: otherwise a
// deny that applies while one is missing would lift, and a grant given while one is present hold.
// The attributes it doesn't refuse read as they are.
func TestADeclaredAttributePassedAsAnotherTypeFailsAPresenceTest(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Request: map[string]rbac.AttributeType{"mfa_at": rbac.AttrTimestamp, "team": rbac.AttrString}}
	})
	ctx := t.Context()
	grants := map[string]string{
		"present":  `has(request.attributes.mfa_at)`,
		"listed":   `"mfa_at" in dyn(request.attributes)`,
		"counted":  `size(dyn(request.attributes)) == 2`,
		"iterated": `dyn(request.attributes).exists(k, k == "mfa_at")`,
		// By its size alone, the map would compare as one holding mfa_at.
		"compared": `dyn(request.attributes) != {"team": "sre"}`,
	}
	gs := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian")}
	sibling := grant(cluster.Scope(), "cluster.login", rbac.User, "sibling")
	sibling.Condition = rbac.Condition{Expression: `request.attributes.team == "sre"`}
	gs = append(gs, sibling)
	for id, expr := range grants {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, id)
		g.Condition = rbac.Condition{Expression: expr}
		gs = append(gs, g)
	}
	h.seed(t, gs...)
	v := h.as(t, "v")
	d := rbac.Deny{
		ID: "mfa", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `!has(request.attributes.mfa_at)`},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	with := func(mfa any) context.Context {
		return rbac.WithRequest(ctx, map[string]any{"mfa_at": mfa, "team": "sre"})
	}
	is := func(c context.Context, id string) bool {
		t.Helper()
		err := h.authz.Authorize(c, h.as(t, id), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	ok := with(time.Now())
	for id := range grants {
		if !is(ok, id) {
			t.Errorf("%s: a timestamp the condition takes", id)
		}
	}
	if !is(ok, "v") {
		t.Error("a deny's condition held with mfa_at present")
	}
	var none *time.Time
	for _, mfa := range []any{nil, none, "not a time", 7} {
		c := with(mfa)
		for id := range grants {
			if is(c, id) {
				t.Errorf("%s: a grant's condition held for mfa_at %#v", id, mfa)
			}
		}
		if is(c, "v") {
			t.Errorf("a deny's condition was lifted for mfa_at %#v", mfa)
		}
		if !is(c, "sibling") {
			t.Errorf("an attribute beside one refused was refused too, for mfa_at %#v", mfa)
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

// A grant's condition, a deny's and a requirement, stored while env and level were declared strings,
// read once the host declares them lists of strings: none passes the declarations now, so each
// fails, rather than run as if they hadn't changed, where a list is unequal to any string.
func TestAConditionStoredUnderOtherDeclarationsFailsWhereItNoLongerPassesThem(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{
			Resource: map[string]rbac.AttributeType{"env": rbac.AttrString},
			Request:  map[string]rbac.AttributeType{"level": rbac.AttrString},
		}
	})
	ctx := t.Context()
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `resource.attributes.env != "prod"`}
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	u, v, w := h.as(t, "u"), h.as(t, "v"), h.as(t, "w")
	d := rbac.Deny{
		ID: "prod", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `resource.attributes.env == "prod"`},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	e := rbac.Eligibility{Role: "cluster.login", Principal: w.Principal, MaxDuration: time.Hour, Requires: `request.attributes.level != "low"`}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfg
	cfg.Attributes = rbac.Attributes{
		Resource: map[string]rbac.AttributeType{"env": rbac.AttrStrings},
		Request:  map[string]rbac.AttributeType{"level": rbac.AttrStrings},
	}
	later, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := later.SetDeny(ctx, h.as(t, "guardian"), cluster, d); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("storing the deny under the declarations now: %v", err)
	}
	r := cluster
	r.Attributes = map[string]any{"env": []string{"prod"}}
	if dec, err := later.Explain(ctx, v, login, r); err != nil || dec.Allowed || !strings.Contains(dec.Reason, "couldn't be evaluated") {
		t.Errorf("a deny of prod, for a resource in prod: %+v, %v", dec, err)
	}
	if err := later.Authorize(ctx, u, login, r); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("a grant for anything but prod, for a resource in prod: %v", err)
	}
	act := rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "INC-1"}
	if _, err := later.Activate(rbac.WithRequest(ctx, map[string]any{"level": []string{"low"}}), w, cluster, act); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("a requirement of a level other than low, at level low: %v", err)
	}
	// Under the declarations they were stored under, they decide as ever.
	r.Attributes = map[string]any{"env": "prod"}
	if allowed(t, h, u, login, r) || allowed(t, h, v, login, r) {
		t.Error("the conditions under the declarations they were stored under")
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

// doubling is a condition that nests a list of leaf in itself k times, so it holds 2^k leaves, at
// little cost, and then compares it with itself, which reads them all in one call.
func doubling(leaf string, k int, compare string) string {
	return "[[" + leaf + "]]" + strings.Repeat(".map(x, [x, x])", k) + ".map(x, " + compare + ")[0]"
}

// compared is a value a condition reads that counts each comparison of it, so a test sees whether
// a comparison ran.
type compared struct{ n *int }

var comparedType = types.NewOpaqueType("rbac_test.Compared")

func (c compared) ConvertToNative(reflect.Type) (any, error) {
	return nil, errors.New("compared converts to nothing")
}

func (c compared) ConvertToType(ref.Type) ref.Val {
	return types.NewErr("compared converts to nothing")
}

func (c compared) Equal(other ref.Val) ref.Val {
	*c.n++
	return types.Bool(other == ref.Val(c))
}

func (c compared) Type() ref.Type { return comparedType }

func (c compared) Value() any { return c }

// A comparison of more values than a condition may spend reading is refused before it reads any:
// a call's cost is counted only once it has run, and the values a condition doubles cheaply would
// hold a check for as long as reading them takes.
func TestAConditionComparingMoreThanItsCostIsRefusedBeforeItRuns(t *testing.T) {
	h := setup(t)
	for id, compare := range map[string]string{"equal": "x == x", "unequal": "!(x != x)", "in": "x in [x]"} {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, id)
		g.Condition = rbac.Condition{Expression: doubling("resource.attributes.leaf", 16, compare)}
		h.seed(t, g)
		n := 0
		r := cluster
		r.Attributes = map[string]any{"leaf": compared{&n}}
		if allowed(t, h, h.as(t, id), login, r) {
			t.Errorf("%s: a condition past its cost held", id)
		}
		if n > 0 {
			t.Errorf("%s: a check compared %d of the values of a comparison past its cost", id, n)
		}
		// Within its cost the comparison reads the leaf, so a count of none above is one refused.
		few := grant(cluster.Scope(), "cluster.login", rbac.User, id+"-few")
		few.Condition = rbac.Condition{Expression: doubling("resource.attributes.leaf", 1, compare)}
		h.seed(t, few)
		if !allowed(t, h, h.as(t, id+"-few"), login, r) || n == 0 {
			t.Errorf("%s: a comparison within its cost compared %d values", id, n)
		}
	}
}

func TestAConditionNestedTooDeeplyIsRefused(t *testing.T) {
	h := setup(t)
	for name, expr := range map[string]string{
		"lists":          strings.Repeat("[", 40) + strings.Repeat("]", 40) + " == []",
		"parentheses":    strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40),
		"a chain of map": doubling("1", 40, "x == x"),
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

// A change's conditions are bounded together, each counted once: compiling one takes milliseconds,
// before the host is asked, so a change of a thousand distinct ones would spend seconds.
func TestAChangeCarriesBoundedConditions(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	pad := strings.Repeat("x", 180)
	distinct := func(n int, same bool) []rbac.Binding {
		bs := make([]rbac.Binding, n)
		for i := range bs {
			c := i
			if same {
				c = 0
			}
			bs[i] = rbac.Binding{
				Role: "cluster.login", Principal: identity(fmt.Sprintf("u%d", i)),
				Condition: rbac.Condition{Expression: fmt.Sprintf(`"%d%s" != ""`, c, pad)},
			}
		}
		return bs
	}
	many := distinct(rbac.MaxBindings, false)
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: many}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("Apply of %d distinct conditions: %v", len(many), err)
	}
	grants := make([]rbac.Grant, len(many))
	for i, b := range many {
		grants[i] = rbac.Grant{Scope: cluster.Scope(), Binding: b}
	}
	if err := h.authz.Import(ctx, host, "t1", grants); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("Import of %d distinct conditions: %v", len(grants), err)
	}
	// One condition carried by every binding counts once.
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: distinct(rbac.MaxBindings, true)}); err != nil {
		t.Errorf("Apply of one condition on every binding: %v", err)
	}
	// And is compiled once, though one that doesn't compile isn't cached, whatever titles it has.
	broken := distinct(rbac.MaxBindings, true)
	for i := range broken {
		broken[i].Condition = rbac.Condition{Title: fmt.Sprintf("t%d", i), Expression: strings.Repeat(`"x" != "" && `, 150) + "1"}
	}
	imported := make([]rbac.Grant, len(broken))
	for i, b := range broken {
		imported[i] = rbac.Grant{Scope: cluster.Scope(), Binding: b}
	}
	checks := 0
	rbac.SetCheckingCondition(t, func() { checks++ })
	for how, change := range map[string]func() error{
		"Apply":  func() error { return h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: broken}) },
		"Import": func() error { return h.authz.Import(ctx, host, "t1", imported) },
	} {
		checks = 0
		if err := change(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s of one condition that doesn't compile on every binding: %v", how, err)
		}
		if checks != 1 {
			t.Errorf("%s of one condition that doesn't compile on %d bindings checked it %d times", how, len(broken), checks)
		}
	}
}

// What evaluating a condition can cost is bounded by what it reads, which a check runs it within:
// little for one comparing what a request passes with literals, whatever it passes, and all a
// condition may for one reading the size of, or looping over, what the request decides. None costs
// more than its bound, however large what it reads.
func TestAConditionCostsNoMoreThanItsBound(t *testing.T) {
	big := strings.Repeat("x", 20000)
	many := make([]any, 5000)
	for i := range many {
		many[i] = big[:i%40]
	}
	requests := []map[string]any{
		{},
		{
			"mfa": true, "ip": "10.0.0.1", "team": "sre", "env": "dev", "n": 3, "f": 1.0, "g": 2.0, "d": time.Minute,
			"at": time.Now(), "tags": []any{"gpu"}, "m": map[string]any{"k": "v"}, "x": 1,
		},
		{
			"mfa": big, "ip": big, "team": many, "env": map[string]any{"a": many}, "n": big, "f": 1.0, "g": 0.0, "d": big,
			"at": big, "tags": many, "m": map[string]any{"k": many}, "x": many,
		},
	}
	for _, c := range []struct {
		expr  string
		cheap bool
	}{
		{`request.attributes.mfa == true`, true},
		{`request.attributes.ip == "10.0.0.1" || request.attributes.ip == "10.0.0.2"`, true},
		{`resource.attributes.env != "prod" && subject.id in ["a", "b", "c"]`, true},
		{`request.time < timestamp("2027-01-01T00:00:00Z") && request.time.getHours("America/New_York") >= 9`, true},
		{`request.attributes.ip.startsWith("10.") && "abc".contains("b")`, true},
		{`has(request.attributes.mfa) && !has(request.attributes.at) && request.attributes.x != null`, true},
		{`dyn(request.attributes)["team"] == "sre" && request.attributes.m["k"] == "v"`, true},
		{`request.attributes.d < duration("1h") && request.attributes.f / request.attributes.g >= 0.5`, true},
		{`(request.attributes.mfa ? request.attributes.team : "none") == "sre"`, true},
		{`[1, 2, 3].all(i, i > 0) && [request.attributes.x] == [1] && {"a": request.attributes.x} == {"a": 1}`, true},
		{`[1, 2] + [3] == [1, 2, 3] && "a" + "b" == "ab" && size("abc") == 3 && action == "cluster:login"`, true},
		// What map() and filter() make of literals is bounded by them, so looping over it is cheap too.
		{`[1, 2].map(x, "ab").all(s, s.contains("a"))`, true},
		{`[1, 2, 3].map(x, [x, x]).all(l, l.all(y, y > 0))`, true},
		{`["abc"].map(s, s + s + s).all(s, s.matches("c$")) && [[1], []].map(l, l + l).all(l, 1 in l)`, true},
		{`["10.0.0.1", "10.0.0.2"].filter(ip, ip.startsWith("10.")).exists(ip, request.attributes.ip == ip)`, true},
		{`[1, 2, 3].filter(x, x > 1).map(x, [x]) == [2, 3].map(x, [x]) && [[], ["ab"]].all(l, l.all(s, s.contains("a")))`, true},
		// What a literal holds is bounded by it, wherever a condition reads it from.
		{`[["10.0.0.1"], ["10.0.0.2"]].exists(g, request.attributes.ip in g) && "time" in request`, true},
		{`{"dev": 1, "prod": 2}[resource.attributes.env] <= request.attributes.n && [{"n": 2}].exists(r, r.n == request.attributes.n)`, true},
		{`[[1, 2], [3]][0][1] == request.attributes.x && [1].map(x, {"a": request.attributes.tags}).exists(m, "zz" in m)`, true},
		{"[[" + strings.Repeat("0, ", 499) + "0]].all(l, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].all(i, \"a\".startsWith(dyn(l))))", true},
		{`"gpu" in request.attributes.tags`, false},
		{`request.attributes.team in {"sre": true}`, false},
		{`size(request.attributes.tags) > 0`, false},
		{`request.attributes.ip.matches("^10[.]0[.]")`, false},
		{`request.attributes.tags.exists(t, t == "gpu")`, false},
		{`request.attributes.x == request.attributes.team`, false},
		{`string(request.attributes.n) == "3" || int(request.attributes.n) > 2`, false},
		{`request.attributes.ip + request.attributes.team == "ab"`, false},
		{`[1,2,3,4,5,6,7,8].all(a, [1,2,3,4,5,6,7,8].all(b, [1,2,3,4,5,6,7,8].all(c, [1,2,3,4,5,6,7,8].all(d, a > 0))))`, false},
		{`request.attributes.tags.map(t, "gpu").exists(t, t == "gpu")`, false},
		{`["a", "b"].map(x, request.attributes.team).exists(t, t.contains("s"))`, false},
		{`request.attributes.tags.filter(t, t != "").exists(t, t == "gpu")`, false},
		// CEL checks a dyn() value that meets another as of the other's type, which it needn't have.
		{`(dyn([{"a": 1}]) + [[]]).exists(m, request.attributes.n in m)`, false},
		{`(dyn([request.attributes.tags]) + [1])[0] == request.attributes.tags`, false},
		{`(dyn([{"a": request.attributes.tags}]) + [{"a": 1}]).exists(m, m.a == request.attributes.tags)`, false},
		{`(dyn([[request.attributes.tags]]) + [""]).exists(s, s + s == request.attributes.tags)`, false},
		{"[[" + strings.Repeat("0, ", 499) + "0]].all(l, dyn(l).contains(dyn(l)))", false},
		// A map's keys don't bound what they index, and what may be a map or a list finds a key by it.
		{`{"a": request.attributes.tags}["a"] == request.attributes.tags`, false},
		{`[[1], {"a": 1}].exists(v, request.attributes.ip in v)`, false},
	} {
		for i, attributes := range requests {
			limit, actual := rbac.ConditionCost(t, c.expr, attributes)
			if actual > limit && limit < 10000 {
				t.Errorf("%s on request %d cost %d, past its bound, %d", c.expr, i, actual, limit)
			}
			if c.cheap != (limit < 1000) {
				t.Errorf("%s is bounded at %d", c.expr, limit)
			}
		}
	}
}

// Another version of CEL may expand macros otherwise: name the list map() makes so a condition can
// read it and grow it by more each loop, or give a loop a second variable, which CEL checks as a
// type it needn't have. A condition still costs no more than its bound.
func TestAConditionCostsNoMoreThanItsBoundWhereCELExpandsMacrosOtherwise(t *testing.T) {
	ones := strings.Repeat("1, ", 11) + "1"
	for _, c := range []struct {
		expr string
		opt  cel.EnvOption
	}{
		{"[" + ones + "].map(x, dyn(__result__.map(y, y))) == [" + ones + "].map(x, dyn(__result__.map(y, y)))", cel.EnableHiddenAccumulatorName(false)},
		{"(dyn([[" + strings.Repeat("0, ", 499) + "0]]) + [1]).all(i, v, v == v)", ext.TwoVarComprehensions()},
	} {
		if limit, actual := rbac.ConditionCost(t, c.expr, nil, c.opt); actual > limit {
			t.Errorf("%s cost %d, past its bound, %d", c.expr, actual, limit)
		}
	}
}

// A stored condition's bound is computed again in each process, from what the CEL it is built with
// makes of it, so another version of CEL can move the bounds of conditions already stored and leave
// what a check reads together past one. These pin the bounds of conditions of common shapes, so an
// upgrade that moves one shows.
func TestStoredConditionsKeepTheirBounds(t *testing.T) {
	for _, c := range []struct {
		expr  string
		bound uint64
	}{
		{`request.attributes.mfa == true`, 8},
		{`request.attributes.ip == "10.0.0.1" || request.attributes.ip == "10.0.0.2"`, 16},
		{`resource.attributes.env != "prod" && subject.id in ["a", "b", "c"]`, 27},
		{`request.time < timestamp("2027-01-01T00:00:00Z") && request.time.getHours("America/New_York") >= 9`, 116},
		{`request.attributes.ip.startsWith("10.") && "abcdefghijk".contains("bc")`, 9},
		{`"abc".matches("^a(b|c){2}$")`, 11},
		{`has(request.attributes.mfa) && request.attributes.x != null`, 14},
		{`dyn(request.attributes)["team"] == "sre" && [1, 2, 3][1] == 2`, 23},
		{`(request.attributes.mfa ? request.attributes.team : "none") == "sre"`, 14},
		{`[request.attributes.x] == [1] && {"a": request.attributes.x} == {"a": 1}`, 99},
		{`[1, 2] + [3] == [1, 2, 3] && "a" + "b" == "ab" && size("abc") == 3 && action == "cluster:login"`, 52},
		{`int("12") == 12 && string(1) == "1" && duration("1h") > duration("1m")`, 14},
		{`google.protobuf.Struct{fields: {"a": 1.0}} == {"a": 1.0}`, 104},
		{`[1, 2, 3].all(i, i > 0) && [1, 2, 3].exists_one(i, i == 2) && {"a": 1}.exists(k, k == "a")`, 128},
		{`[[1, 2], [3]].all(l, l.all(i, i > 0))`, 86},
		{`[1, 2, 3].map(x, x > 1, x * 2) == [4, 6]`, 108},
		{`[1, 2].map(x, "ab").all(s, s.contains("a"))`, 70},
		{`["10.0.0.1", "10.0.0.2"].filter(ip, ip.startsWith("10.")).exists(ip, request.attributes.ip == ip)`, 100},
		{`[["10.0.0.1"], ["10.0.0.2"]].exists(g, request.attributes.ip in g) && "time" in request`, 70},
		{`{"dev": 1, "prod": 2}[resource.attributes.env] <= request.attributes.n`, 50},
		{`[{"level": 2}, {"level": 3}].exists(r, r.level == request.attributes.n)`, 112},
		{`"gpu" in request.attributes.tags`, 10000},
		{`request.attributes.tags.exists(t, t == "gpu")`, 10000},
	} {
		if limit, _ := rbac.ConditionCost(t, c.expr, nil); limit != c.bound {
			t.Errorf("%s is bounded at %d, not %d", c.expr, limit, c.bound)
		}
	}
}

// Conditions that compare what a request passes with literals cost little, so the grants a check
// reads together on a scope may carry hundreds, as one for each group's addresses: what bounds them
// is what compiling and evaluating each costs.
func TestCheapConditionsFitAScopeByTheHundreds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var groups []string
	var grants []rbac.Grant
	for i := range 300 {
		g := fmt.Sprintf("g%03d", i)
		groups = append(groups, g)
		b := rbac.Binding{Role: "cluster.login", Principal: groupOf(g), Condition: rbac.Condition{Expression: fmt.Sprintf(`request.attributes.ip == "10.0.%d.1"`, i)}}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: b})
	}
	h.groups(t, groups...)
	if err := h.authz.Import(ctx, host, "t1", grants[:250]); err != nil {
		t.Fatalf("250 cheap conditions: %v", err)
	}
	if err := h.authz.Import(ctx, host, "t1", grants[250:]); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("300 cheap conditions: %v", err)
	}
	// A check of a subject in every group evaluates them all.
	s := h.as(t, "u", groups...)
	if err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"ip": "10.0.249.1"}), s, login, cluster); err != nil {
		t.Fatalf("the last group's address: %v", err)
	}
}

// The most conditions a change carries, each distinct and as costly to compile as any, take about
// as long to check as compiling sixteen of them alone, before the host is asked. And none is kept
// compiled: the cache is the checks', and one change's conditions would otherwise evict what they
// read, though no check may read them.
func TestAChangesConditionsCompileBriefly(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"env": rbac.AttrString}}
	})
	ctx := t.Context()
	n := 0
	costly := func(bytes int) []rbac.Binding {
		var bs []rbac.Binding
		for total := 0; ; n++ {
			s := fmt.Sprintf(`[%d,2,3] == [1,2,3]`, n)
			for len(s)+len(` && [1,2,3] == [1,2,3]`) <= rbac.MaxExpression {
				s += ` && [1,2,3] == [1,2,3]`
			}
			if total += len(s); total > bytes {
				return bs
			}
			bs = append(bs, rbac.Binding{Role: "cluster.login", Principal: identity(fmt.Sprintf("u%d", n)), Condition: rbac.Condition{Expression: s}})
		}
	}
	took := func(bs []rbac.Binding) time.Duration {
		t.Helper()
		start := time.Now()
		if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: bs}); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	one := min(took(costly(rbac.MaxExpression)), took(costly(rbac.MaxExpression)))
	most := costly(rbac.MaxConditionBytes)
	before := rbac.Compiled(h.authz)
	if all := min(took(most), took(costly(rbac.MaxConditionBytes))); all > 24*one {
		t.Errorf("a change of %d conditions took %v, one alone %v", len(most), all, one)
	}
	if after := rbac.Compiled(h.authz); after != before {
		t.Errorf("changes kept %d conditions compiled that no check has read", after-before)
	}
	// u1's holds; u0's doesn't.
	if allowed(t, h, h.as(t, "u0"), login, cluster) || !allowed(t, h, h.as(t, "u1"), login, cluster) || rbac.Compiled(h.authz) != before+2 {
		t.Error("checks keep what they compile")
	}
}

// An actor holding its power under a condition hands it on under that condition, which a change
// parses for whether it reads the subject once, however many bindings and permissions carry it:
// parsing one takes milliseconds, and the change decides again in its transaction.
func TestAChangeHandingOnUnderAConditionParsesItOnce(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	cond := rbac.Condition{Expression: strings.Repeat(`"x" != "" && `, 145) + "true"}
	g := grant(cluster.Scope(), "cluster.admin", rbac.User, "admin")
	g.Condition = cond
	h.seed(t, g)
	bs := make([]rbac.Binding, rbac.MaxBindings)
	for i := range bs {
		bs[i] = rbac.Binding{Role: "cluster.login", Principal: identity(fmt.Sprintf("u%d", i)), Condition: cond}
	}
	admin := h.as(t, "admin")
	parsed := 0
	rbac.SetParsingCondition(t, func() { parsed++ })
	if err := h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: bs}); err != nil {
		t.Fatal(err)
	}
	// Once as the change is decided, and once as it is decided again in its transaction.
	if parsed == 0 || parsed > 2 {
		t.Errorf("handing on under one condition on %d bindings parsed it %d times", len(bs), parsed)
	}
}

// The requirements of groups' eligibilities for a role on a scope are bounded together where they
// are stored, as activating evaluates those of each group the subject is in: so an eligibility set
// beside another, as by an actor who can't delete it, never changes what that one allows.
func TestGroupsRequirementsForARoleOnAScopeAreBoundedTogether(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner := h.as(t, "owner")
	h.groups(t, "g0", "g1", "g2", "g3", "g4")
	set := func(on rbac.Resource, p rbac.Principal, role rbac.Role, requires string) error {
		return h.authz.SetEligibility(ctx, owner, on, rbac.Eligibility{Role: role, Principal: p, MaxDuration: time.Hour, Requires: requires})
	}
	for i := range 3 {
		if err := set(cluster, groupOf(fmt.Sprint("g", i)), "cluster.sudo", spending(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := set(cluster, groupOf("g3"), "cluster.sudo", spending(3)); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a fourth costly requirement: %v", err)
	}
	// One they have counts once; another role's, and an identity's own, count apart.
	for name, err := range map[string]error{
		"one they have": set(cluster, groupOf("g3"), "cluster.sudo", spending(0)),
		"another role":  set(cluster, groupOf("g4"), "cluster.login", spending(4)),
		"an identity's": set(cluster, identity("x"), "cluster.sudo", "true || "+spending(5)),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Activating evaluates them whole, and reaches the one that holds, though it is the costliest.
	act := rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}
	if _, err := h.authz.Activate(ctx, h.as(t, "x", "g0", "g1", "g2", "g3", "g4"), cluster, act); err != nil {
		t.Fatalf("Activate: %v", err)
	}
}

// Where groups' requirements stored before there were bounds cost more than activating may spend,
// a group's eligibility set again as it is, or with a requirement another holds, adds nothing
// activating reads, so it isn't refused; one adding a requirement is.
func TestAnEligibilitySetPastTheBoundIsRefusedOnlyForARequirementItAdds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g0", "g1", "g2", "g3")
	for i := range 4 {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role,
			max_seconds, requires) VALUES ('t1', 'cluster', 'c1', 'group', $1, 'cluster.sudo', 3600, $2)`, fmt.Sprint("g", i), spending(i)); err != nil {
			t.Fatal(err)
		}
	}
	set := func(note, requires string) error {
		return h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{
			Role: "cluster.sudo", Principal: groupOf("g0"), MaxDuration: time.Hour, Requires: requires, Note: note,
		})
	}
	for name, err := range map[string]error{
		"as it is":                     set("", spending(0)),
		"with another note":            set("on call", spending(0)),
		"with a requirement they hold": set("on call", spending(1)),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := set("on call", spending(9)); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("with a requirement they don't hold: %v", err)
	}
}

// Activate evaluates the cheapest requirement first, as a check does conditions, so one that holds
// is reached however many costly ones stored around the bounds the subject is also eligible
// through, whatever order the database's collation would put them in, however many approvers each
// names, and however much longer the paths to them last than the one to it.
func TestActivateTriesTheCheapestRequirementFirst(t *testing.T) {
	boss := identity("boss")
	for name, approvers := range map[string]struct {
		costly, cheap []rbac.Principal
		// group is whether the cheap one is a group's the subject is in for a while, rather than its
		// own.
		group bool
	}{
		"no approvers":                   {},
		"more approvers on it":           {costly: []rbac.Principal{boss}, cheap: []rbac.Principal{boss, identity("lead")}},
		"a group's it is in for a while": {group: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			owner := h.as(t, "owner")
			// Each runs up to its cost on the request's list, which spends it all, and together they
			// spend what activating may.
			var groups []string
			for i := range 20 {
				groups = append(groups, fmt.Sprintf("g%02d", i))
			}
			h.groups(t, groups...)
			x := h.as(t, "x", groups...)
			costly := []string{}
			for _, p := range approvers.costly {
				costly = append(costly, string(p.Kind)+":"+p.ID)
			}
			for i, g := range groups {
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role,
					max_seconds, requires, approvers) VALUES ('t1', 'cluster', 'c1', 'group', $1, 'cluster.sudo', 3600, $2, $3)`,
					g, fmt.Sprintf(`request.attributes.big.map(x, x + %d).size() < 0`, i), costly); err != nil {
					t.Fatal(err)
				}
			}
			if approvers.group {
				// Stored around the bounds too: setting it past the groups' bound is refused.
				h.groups(t, "cheap")
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
					VALUES ('t1', 'cheap', 'user', 'x', $1)`, h.now.Add(3*time.Hour)); err != nil {
					t.Fatal(err)
				}
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role,
					max_seconds, requires) VALUES ('t1', 'cluster', 'c1', 'group', 'cheap', 'cluster.sudo', 3600, 'true')`); err != nil {
					t.Fatal(err)
				}
			} else {
				cheap := rbac.Eligibility{Role: "cluster.sudo", Principal: x.Principal, MaxDuration: time.Hour, Requires: "true", Approvers: approvers.cheap}
				if err := h.authz.SetEligibility(ctx, owner, cluster, cheap); err != nil {
					t.Fatal(err)
				}
			}
			big := make([]any, 20000)
			for i := range big {
				big[i] = i
			}
			req := rbac.WithRequest(ctx, map[string]any{"big": big})
			act := rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}
			if len(approvers.cheap) > 0 {
				act.Approver = h.as(t, "boss")
			}
			if _, err := h.authz.Activate(req, x, cluster, act); err != nil {
				t.Fatalf("Activate: %v", err)
			}
		})
	}
}
