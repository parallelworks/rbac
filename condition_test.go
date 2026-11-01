package rbac_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/pb"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

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
// "NaN", which CEL orders and equates as false with anything: so comparing one fails too, and so
// do keying a map by one, which CEL finds no key equal to, whatever the map holds, and converting
// one to a string, which compares as any string does.
func TestADoubleAConditionMakesThatIsntFiniteFailsWhatComparesIt(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
		c.Attributes = rbac.Attributes{Request: map[string]rbac.AttributeType{
			"failed": rbac.AttrDouble, "total": rbac.AttrDouble, "score": rbac.AttrString,
		}}
	})
	ctx := t.Context()
	const ratio = `request.attributes.failed / request.attributes.total`
	keyed := `{` + ratio + `: 1}`
	grants := []string{
		ratio + ` < 0.5`, `!(` + ratio + ` >= 0.5)`, ratio + ` != 1.0`,
		keyed + ` != {0.5: 1}`, `[` + keyed + `] != [{0.5: 1}]`, `!(0.5 in ` + keyed + `)`,
		`[` + ratio + `].all(r, {r: 1} != {0.5: 1})`, `string(` + ratio + `) != "0.5"`,
	}
	denies := []string{
		ratio + ` >= 0.5`, ratio + ` == 1.0`, `double(request.attributes.score) >= 0.5`,
		keyed + ` == {0.5: 1}`, `{0.5: 1} == ` + keyed, `0.5 in {double(request.attributes.score): 1}`,
		`[` + ratio + `].exists(r, {r: 1} == {0.5: 1})`, `string(double(request.attributes.score)) == "0.5"`,
	}
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
	for i := range grants {
		if !is(fmt.Sprint("u", i), finite) || !is(fmt.Sprint("v", i), finite) {
			t.Fatalf("finite doubles: %s, %s", grants[i], denies[i])
		}
	}
	for name, request := range map[string]map[string]any{
		"NaN":       {"failed": 0.0, "total": 0.0, "score": "NaN"},
		"infinity":  {"failed": 1.0, "total": 0.0, "score": "inf"},
		"-infinity": {"failed": -1.0, "total": 0.0, "score": "-inf"},
	} {
		for i := range grants {
			if is(fmt.Sprint("u", i), request) {
				t.Errorf("a grant's condition %s held for %s", grants[i], name)
			}
			if is(fmt.Sprint("v", i), request) {
				t.Errorf("a deny's condition %s was lifted for %s", denies[i], name)
			}
		}
	}
}

// hostDouble is a host's own type CEL reads as a double, which compares as CEL's own does.
type hostDouble float64

func (d hostDouble) ConvertToNative(t reflect.Type) (any, error) {
	return types.Double(d).ConvertToNative(t)
}
func (d hostDouble) ConvertToType(t ref.Type) ref.Val { return types.Double(d).ConvertToType(t) }
func (d hostDouble) Equal(other ref.Val) ref.Val      { return types.Double(d).Equal(other) }
func (d hostDouble) Compare(other ref.Val) ref.Val    { return types.Double(d).Compare(other) }
func (d hostDouble) Type() ref.Type                   { return types.DoubleType }
func (d hostDouble) Value() any                       { return float64(d) }

// hostString is a host's own type CEL reads as a string, which compares as CEL's own does.
type hostString string

func (s hostString) ConvertToNative(t reflect.Type) (any, error) {
	return types.String(s).ConvertToNative(t)
}
func (s hostString) ConvertToType(t ref.Type) ref.Val { return types.String(s).ConvertToType(t) }
func (s hostString) Equal(other ref.Val) ref.Val      { return types.String(s).Equal(other) }
func (s hostString) Type() ref.Type                   { return types.StringType }
func (s hostString) Value() any                       { return string(s) }

// selfDouble is a host's own type CEL reads as a double that holds no value but itself.
type selfDouble struct{ hostDouble }

func (d selfDouble) Value() any { return d }

// ownList is a host's own list type, which yields what the list it embeds holds.
type ownList struct{ traits.Lister }

// A value of the host's own type that says it is of one of CEL's, as a double or a string, CEL
// reads by its own methods: a deny's `request.attributes.risk >= 0.5` was false for a NaN and
// lifted, `0.5 == risk` was false for 0.5, which the host's double finds equal from its side, and a
// role of the host's string type in a map keyed by it was found by the map as CEL finds it, where
// one read as CEL's own string wasn't, so a deny's `role in blocked` lifted. A check reads no value
// by the host's methods: each fails what reads it, finite or not, in a list or a map, as a key too.
func TestAValueOfAHostsOwnTypeSayingItIsCELsFailsItsConditions(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
	})
	ctx := t.Context()
	grants := []rbac.Grant{grant(cluster.Scope(), "guard", rbac.User, "guardian")}
	conditions := map[string][2]string{
		"risk": {`request.attributes.risk < 0.5`, `request.attributes.risk >= 0.5`},
		"role": {`!(request.attributes.role in request.attributes.blocked)`, `request.attributes.role in request.attributes.blocked`},
	}
	for name, c := range conditions {
		g := grant(cluster.Scope(), "cluster.login", rbac.User, "granted-"+name)
		g.Condition = rbac.Condition{Expression: c[0]}
		grants = append(grants, g, grant(cluster.Scope(), "cluster.login", rbac.User, "denied-"+name))
	}
	h.seed(t, grants...)
	for name, c := range conditions {
		d := rbac.Deny{
			ID: name, Principals: []rbac.Principal{h.as(t, "denied-"+name).Principal}, Permissions: []rbac.Permission{login},
			Condition: rbac.Condition{Expression: c[1]},
		}
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	is := func(who string, attributes map[string]any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, attributes), h.as(t, who), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	if !is("granted-risk", map[string]any{"risk": 0.1}) || !is("denied-risk", map[string]any{"risk": 0.1}) ||
		!is("granted-role", map[string]any{"role": "user", "blocked": map[string]bool{"admin": true}}) {
		t.Fatal("values the conditions take")
	}
	for _, risk := range []hostDouble{0.1, 0.5, 0.9, hostDouble(math.NaN()), hostDouble(math.Inf(1)), hostDouble(math.Inf(-1))} {
		if is("granted-risk", map[string]any{"risk": risk}) || is("denied-risk", map[string]any{"risk": risk}) {
			t.Errorf("a condition decided on a risk of the host's own type, %v", float64(risk))
		}
	}
	for name, blocked := range map[string]any{
		"a map of ref.Vals": map[ref.Val]ref.Val{hostString("admin"): types.True},
		"a map of CEL's":    types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{hostString("admin"): types.True}),
		"a map of Go's":     map[any]any{heldKey{0.5}: true},
	} {
		for _, role := range []any{hostString("admin"), "admin"} {
			attributes := map[string]any{"role": role, "blocked": blocked}
			if is("granted-role", attributes) || is("denied-role", attributes) {
				t.Errorf("a condition decided on %#v in %s keyed by the host's own type", role, name)
			}
		}
	}
	half := hostDouble(0.5)
	reads := map[string][]string{
		"%s":    {"%s == %[1]s", "%s != 0.5", `%s != "a"`, "%s != [0.5]", `%s != {"a": 0.5}`, "0.5 in %s", `"a" in %s`, `string(%s) != ""`},
		"%s[0]": {"%s == %[1]s", "%s != 0.5", "%s != [0.5]"}, "%s.a": {"%s == %[1]s", "%s != 0.5", `has(%s)`},
	}
	for name, c := range map[string]struct {
		v    any
		read string
	}{
		"a double": {half, "%s"}, "a string": {hostString("a"), "%s"}, "holding itself": {selfDouble{0.5}, "%s"},
		"keying a map": {map[any]any{half: 1}, "%s"}, "keying a map of ref.Vals": {map[ref.Val]ref.Val{hostString("a"): types.Int(1)}, "%s"},
		"in a list": {[]any{half}, "%s[0]"}, "in a map": {map[string]any{"a": half}, "%s.a"},
	} {
		for _, of := range reads[c.read] {
			expr := fmt.Sprintf(of, fmt.Sprintf(c.read, "request.attributes.v"))
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": c.v}); err != nil || evaluated {
				t.Errorf("%s of %s of the host's own type: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
}

// A map the host passes keyed by a double, which can be NaN, or by an array, which can hold one,
// was found by and compared as CEL does: a map keyed by NaN equaled none, and one keyed by an array
// holding NaN found no key, so a grant's `!=` held, and its infinite key was found by one a
// condition reads, where `in` fails. Each fails whatever reads it, finite or not, empty too. A
// double that isn't finite a condition makes in a list still fails what compares it.
func TestAMapTheHostPassesKeyedByADoubleOrAnArrayFailsItsConditions(t *testing.T) {
	for name, m := range map[string]any{
		"NaN": map[float64]any{math.NaN(): 1}, "infinity": map[float64]any{math.Inf(1): 1}, "a half": map[float64]any{0.5: 1},
		"none": map[float64]any{}, "an array holding NaN": map[[1]float64]int{{math.NaN()}: 1}, "an array": map[[1]float64]int{{0.5}: 1},
		"a double in a map of Go's": map[any]any{0.5: 1}, "an array in a map of Go's": map[any]any{[1]int{1}: 1},
		"a struct": map[struct{ A int }]int{{1}: 1}, "a pointer": map[*int]int{new(int): 1},
	} {
		for _, expr := range []string{
			`request.attributes.m == request.attributes.m`, `request.attributes.m != {0.5: 1}`, `0.5 in request.attributes.m`,
			`size(request.attributes.m) >= 0`, `has(request.attributes.m.a)`, `request.attributes.m.all(k, true)`,
			`[request.attributes.m] != []`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"m": m}); err != nil || evaluated {
				t.Errorf("%s of a map keyed by %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	for _, expr := range []string{`!([[0.0 / 0.0]] in [[[0.5]]])`, `!(dyn("a") in [[0.0 / 0.0]])`, `{[0.0 / 0.0]: 1} != {[0.5]: 1}`} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, nil); err != nil || evaluated {
			t.Errorf("%s: evaluated %t, %v", expr, evaluated, err)
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `!("a key longer than the map it is looked up in" in {"k": 0.0 / 0.0})`, nil); err != nil || !held {
		t.Errorf("in a map holding NaN as a value: held %t, %v", held, err)
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

// A map's entries are named for it beside its kind's attributes, so names that are each an
// identifier can name one thing between them, or a map's entries no identifier: New refuses them,
// naming the attributes, where declaring them would fail with an error naming neither.
func TestDeclaredAttributesNamingAMapsEntriesAreRefusedByName(t *testing.T) {
	h := setup(t)
	for _, c := range []struct {
		attrs rbac.Attributes
		names []string
	}{
		{rbac.Attributes{Subject: map[string]rbac.AttributeType{"a_b": rbac.AttrStringMap, "aB": rbac.AttrStringMap}}, []string{`"aB"`, `"a_b"`}},
		{rbac.Attributes{Resource: map[string]rbac.AttributeType{"tags": rbac.AttrStringMap, "TagsEntry": rbac.AttrString}}, []string{`"tags"`, `"TagsEntry"`}},
		{rbac.Attributes{Request: map[string]rbac.AttributeType{"_1": rbac.AttrStringMap}}, []string{`"_1"`}},
	} {
		cfg := h.cfg
		cfg.Attributes = c.attrs
		_, err := rbac.New(h.pool, cfg)
		if err == nil {
			t.Errorf("%v declared", c.attrs)
			continue
		}
		for _, name := range c.names {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("%v refused without naming %s: %v", c.attrs, name, err)
			}
		}
	}
	// Names alike that name nothing twice in a kind are declared.
	cfg := h.cfg
	cfg.Attributes = rbac.Attributes{
		Resource: map[string]rbac.AttributeType{"a_b": rbac.AttrStringMap, "aEntry": rbac.AttrStringMap, "AEntry": rbac.AttrString, "__": rbac.AttrStringMap},
		Request:  map[string]rbac.AttributeType{"aB": rbac.AttrStringMap, "a_1": rbac.AttrStringMap},
	}
	if _, err := rbac.New(h.pool, cfg); err != nil {
		t.Fatal(err)
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

// CEL reads a nil timestamp or duration message as zero and a nil list message as empty, so a
// declared attribute passed as one met a grant's condition. A nil pointer is null, which no declared
// type takes, so each fails, and a pointer to a list is the list it points to.
func TestADeclaredAttributePassedAsANilPointerFailsItsConditions(t *testing.T) {
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
	for name, vs := range map[string][]any{
		"at": {timestamppb.New(time.Unix(0, 0))}, "age": {durationpb.New(time.Minute)}, "tags": {[]string{}, &[]string{}},
	} {
		for _, v := range vs {
			if !allowed(t, h, h.as(t, "granted-"+name), login, at(name, v)) || !allowed(t, h, h.as(t, "denied-"+name), login, at(name, v)) {
				t.Fatalf("%s: %#v, a value the conditions take", name, v)
			}
		}
	}
	for name, vs := range map[string][]any{
		"at":   {(*timestamppb.Timestamp)(nil), (*time.Time)(nil)},
		"age":  {(*durationpb.Duration)(nil), (*time.Duration)(nil)},
		"tags": {(*structpb.ListValue)(nil), (*[]string)(nil), []any{&[]string{}}},
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
	for id, compare := range map[string]string{"equal": "x == x", "unequal": "!(x != x)", "in": "x in [x]"} {
		// A value no host can pass, which counts each comparison of it.
		n := 0
		leaf := map[string]ref.Val{"leaf": compared{&n}}
		if held, _, _ := rbac.EvaluateConditionOn(t, doubling("request.attributes.leaf", 16, compare), leaf); held {
			t.Errorf("%s: a condition past its cost held", id)
		}
		if n > 0 {
			t.Errorf("%s: a check compared %d of the values of a comparison past its cost", id, n)
		}
		// Within its cost the comparison reads the leaf, so a count of none above is one refused.
		if held, _, _ := rbac.EvaluateConditionOn(t, doubling("request.attributes.leaf", 1, compare), leaf); !held || n == 0 {
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

// A message literal converts the values its fields are given whole, as an Any unpacks its bytes,
// which CEL charges a constant for however large they are: a deny converting a list the request
// passes held a check for seconds, though within its bound. Building one is no condition, declared
// attributes or not, and one stored before fails: a grant's gives nothing, and a deny's applies.
func TestAConditionBuildingAMessageIsRefused(t *testing.T) {
	declared := rbac.Attributes{Request: map[string]rbac.AttributeType{"l": rbac.AttrStrings, "m": rbac.AttrStringMap, "s": rbac.AttrString}}
	for _, declares := range []rbac.Attributes{{}, declared} {
		h := setup(t, func(c *rbac.Config) {
			c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
			c.Attributes = declares
		})
		ctx := t.Context()
		h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "guardian"))
		for _, expr := range []string{
			`google.protobuf.ListValue{values: request.attributes.l} != []`,
			`google.protobuf.Struct{fields: request.attributes.m} != {}`,
			`google.protobuf.Value{list_value: google.protobuf.ListValue{values: request.attributes.l}} != null`,
			`google.protobuf.Any{type_url: "type.googleapis.com/google.protobuf.ListValue", value: bytes(request.attributes.s)} != []`,
			`[1, 2, 3].all(i, google.protobuf.ListValue{values: request.attributes.l} != [])`,
			`google.protobuf.Struct{fields: {"a": 1.0}} == {"a": 1.0} && .google.protobuf.Timestamp{seconds: 1} < request.time`,
		} {
			c := rbac.Condition{Expression: expr}
			g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
			g.Condition = c
			if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{g}); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("Import of %s: %v", expr, err)
			}
			if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Grant: []rbac.Binding{g.Binding}}); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("Apply of %s: %v", expr, err)
			}
			d := rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("v")}, Permissions: []rbac.Permission{login}, Condition: c}
			if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("SetDeny of %s: %v", expr, err)
			}
			e := rbac.Eligibility{Role: "cluster.login", Principal: identity("w"), MaxDuration: time.Hour, Requires: expr}
			if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("SetEligibility of %s: %v", expr, err)
			}
		}
	}
	// Written directly, as stored before.
	h := setup(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "v"))
	for _, stmt := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, condition)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login', 'google.protobuf.ListValue{values: request.attributes.l} != []')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions, condition)
		 VALUES ('t1', 'cluster', 'c1', 'd', '{user:v}', '{cluster:login}', 'google.protobuf.ListValue{values: request.attributes.l} == []')`,
	} {
		if _, err := h.pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	request := rbac.WithRequest(ctx, map[string]any{"l": []any{"a"}})
	if err := h.authz.Authorize(request, h.as(t, "u"), login, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("a grant whose condition builds a message: %v", err)
	}
	if err := h.authz.Authorize(request, h.as(t, "v"), login, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("a deny whose condition builds a message: %v", err)
	}
}

// holder is a host's type CEL can't read, which it writes out whole in its error.
type holder struct{ M map[string]any }

// A value the host passes that holds itself, as a graph of objects it converts may, fails each
// condition reading it, as a comparison or a loop does, rather than recursing until the stack
// overflows, which kills the process: no recover catches it. A message literal converted one so,
// and so did reading a value CEL can't read that holds one, as a struct, which it writes out in its
// error, or a message of a dynamic type, which it merges into one of its own. One that is its own
// reflection, as dynamic types other than dynamicpb's are, was read by its reflection without end,
// and comparing a list of the host's own that yields itself when indexed, though iterating it yields
// none, recursed without end. Each runs in a child process, so one that overflows fails this test
// rather than the test binary.
func TestAValueHoldingItselfFailsItsConditions(t *testing.T) {
	if expr := os.Getenv("RBAC_CONDITION_OF_A_CYCLE"); expr != "" {
		m := map[string]any{"a": "b"}
		m["self"] = m
		l := []any{"x", nil}
		l[1] = l
		refused := os.Getenv("RBAC_CONDITION_OF_A_CYCLE_REFUSED") != ""
		var pointed any
		pointed = &pointed
		message := &structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewStringValue("b")}}
		message.Fields["self"] = structpb.NewStructValue(message)
		listed := &structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("x")}}
		listed.Values = append(listed.Values, structpb.NewListValue(listed))
		attributes := map[string]any{
			"m": m, "l": l, "s": holder{m}, "p": &holder{m}, "d": dynamicStruct(), "r": &reflecting{dynamicStruct()},
			"g":       indexedAsItself{types.NewDynamicList(types.DefaultTypeAdapter, []any{"x", "y"})},
			"pointed": pointed, "message": message, "listed": listed, "ok": true,
		}
		// One holding itself fails what reads it alone, not the attributes beside it.
		if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, attributes); err != nil || !held {
			t.Errorf("an attribute beside values holding themselves: held %t, %v", held, err)
		}
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, attributes); evaluated || (err != nil) != refused {
			t.Errorf("%s evaluated %t, %v", expr, evaluated, err)
		}
		return
	}
	for expr, refused := range map[string]bool{
		`request.attributes.s == request.attributes.p || [request.attributes.s] != []`:                                   false,
		`request.attributes.d.self.self != {}`:                                                                           false,
		`request.attributes.r.self.self != {}`:                                                                           false,
		`request.attributes.g == request.attributes.g || [request.attributes.g] != [request.attributes.g]`:               false,
		`google.protobuf.Struct{fields: request.attributes.m} != {}`:                                                     true,
		`google.protobuf.ListValue{values: request.attributes.l} != []`:                                                  true,
		`request.attributes.m == request.attributes.m`:                                                                   false,
		`request.attributes.l != request.attributes.l`:                                                                   false,
		`request.attributes.m in [request.attributes.m]`:                                                                 false,
		`[request.attributes.l] == [request.attributes.l] || {"a": request.attributes.m} == {"a": request.attributes.m}`: false,
		`request.attributes.l.all(x, x == x)`:                                                                            false,
		`request.attributes.m.exists(k, request.attributes.m[k] == request.attributes.m)`:                                false,
		`{"a": 1}[request.attributes.l] == 1 || {request.attributes.m: 1}[request.attributes.m] == 1`:                    false,
		`request.attributes.pointed != 1 || request.attributes.message.self.self != {}`:                                  false,
		`request.attributes.message == request.attributes.message || request.attributes.listed[1][1] != []`:              false,
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAValueHoldingItselfFailsItsConditions$")
		cmd.Env = append(os.Environ(), "RBAC_CONDITION_OF_A_CYCLE="+expr)
		if refused {
			cmd.Env = append(cmd.Env, "RBAC_CONDITION_OF_A_CYCLE_REFUSED=1")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%.2000s", expr, err, out)
		}
	}
}

// Values holding each other, as a node and its parent, each fail whatever reads them, whichever a
// check reaches first. Only the one converting reached again failed, so where a holds b and b holds
// a, a.b or b.a failed by the order the attributes came in, and a grant's
// `has(request.attributes.a.b)` held for one check and not the next. One holding them reads the rest.
func TestValuesHoldingEachOtherFailWhicheverIsReachedFirst(t *testing.T) {
	a, b := map[string]any{"x": 1}, map[string]any{"x": 1}
	a["b"], b["a"] = b, a
	parent := map[string]any{"name": "p"}
	child := map[string]any{"name": "c", "parent": parent}
	parent["children"] = []any{child}
	self := map[string]any{"x": 1}
	self["self"] = self
	attributes := map[string]any{
		"a": a, "b": b, "parent": parent, "child": child, "self": self,
		"holding": map[string]any{"a": a, "y": 1}, "ok": true,
	}
	for range 20 {
		for _, expr := range []string{
			`has(request.attributes.a.b)`, `has(request.attributes.b.a)`, `request.attributes.a.x == 1`, `request.attributes.b.x == 1`,
			`request.attributes.child.name == "c"`, `request.attributes.parent.name == "p"`, `size(request.attributes.parent.children) == 1`,
			`request.attributes.self.x == 1`, `has(request.attributes.holding.a)`, `"a" in request.attributes.holding`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, attributes); err != nil || evaluated {
				t.Fatalf("%s: evaluated %t, %v", expr, evaluated, err)
			}
		}
		if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.ok && request.attributes.holding.y == 1`, attributes); err != nil || !held {
			t.Fatalf("attributes beside values holding each other: held %t, %v", held, err)
		}
	}
}

// indexedAsItself is a host's own list that yields itself when indexed, though not when iterated.
type indexedAsItself struct{ traits.Lister }

func (l indexedAsItself) Get(ref.Val) ref.Val { return l }

// reflecting is a message of a dynamic type that is its own reflection, as dynamic types other than
// dynamicpb's are.
type reflecting struct{ *dynamicpb.Message }

func (m *reflecting) Interface() protoreflect.ProtoMessage { return m }
func (m *reflecting) ProtoReflect() protoreflect.Message   { return m }

// hostListValue is a host's type embedding a ListValue.
type hostListValue struct{ *structpb.ListValue }

// dynamicStruct is a Struct of a dynamic type one of whose fields, self, holds it.
func dynamicStruct() *dynamicpb.Message {
	s := dynamicpb.NewMessage((&structpb.Struct{}).ProtoReflect().Descriptor())
	v := dynamicpb.NewMessage((&structpb.Value{}).ProtoReflect().Descriptor())
	v.Set(v.Descriptor().Fields().ByName("struct_value"), protoreflect.ValueOfMessage(s))
	s.Mutable(s.Descriptor().Fields().ByName("fields")).Map().Set(protoreflect.ValueOfString("self").MapKey(), protoreflect.ValueOfMessage(v))
	return s
}

// CEL decodes JSON text, a JSON number or a packed message whole each time a condition reads it,
// though it charges the read as one value: a loop of a thousand steps reading JSON text of a
// mebibyte took three seconds and was charged 8,004. A check decodes each once, however many times
// its conditions read it, wherever the host holds it.
func TestAValueCELDecodesWholeIsDecodedOnceForACheck(t *testing.T) {
	long := strings.Repeat("x", 1<<16)
	raw := json.RawMessage(`"` + long + `"`)
	packed, err := anypb.New(wrapperspb.String(long))
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{
		"JSON text": raw, "a JSON number": json.Number("0.5" + strings.Repeat("0", 1<<16)), "a packed message": packed,
		"JSON text in a list": []any{raw}, "JSON text in a map": map[string]any{"v": raw}, "JSON text in a typed list": []json.RawMessage{raw},
	} {
		read := "request.attributes.v"
		switch v.(type) {
		case []any, []json.RawMessage:
			read += "[0]"
		case map[string]any:
			read += ".v"
		}
		expr := `request.attributes.l.all(x, ` + read + ` != "a")`
		held, evaluated, allocated, err := rbac.EvaluateCondition(t, expr, map[string]any{"l": make([]any, 1000), "v": v})
		if err != nil || !evaluated || !held {
			t.Errorf("%s: held %t, evaluated %t, %v", name, held, evaluated, err)
		}
		if allocated > 32<<16 {
			t.Errorf("%s read a thousand times allocated %d bytes", name, allocated)
		}
	}
}

// A map of Go's keyed by an interface, as a map[any]any, is read through the check's conversion,
// and so is each value it holds, but reading a value one held wrapped what the conversion had
// already wrapped again, so a value d maps deep was read through about 2d wrappers: comparing one
// nested 400 deep with itself took 60 times as long as comparing a map[string]any nested as deep,
// charged alike. Each is wrapped once.
func TestAMapKeyedByAnInterfaceNestedDeepCostsWhatAnyMapDoes(t *testing.T) {
	var keyed, listed, named, namedListed any = "x", "x", "x", "x"
	for range 400 {
		keyed, named = map[any]any{"a": keyed}, map[string]any{"a": named}
		listed, namedListed = map[any]any{"a": []any{listed}}, map[string]any{"a": []any{namedListed}}
	}
	expr := `request.attributes.v == request.attributes.v`
	for name, v := range map[string][2]any{"maps": {keyed, named}, "maps of lists": {listed, namedListed}} {
		_, _, want, _ := rbac.EvaluateCondition(t, expr, map[string]any{"v": v[1]})
		held, evaluated, allocated, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v[0]})
		if err != nil || !evaluated || !held {
			t.Errorf("%s: held %t, evaluated %t, %v", name, held, evaluated, err)
		}
		if allocated > 4*want {
			t.Errorf("%s nested 400 deep compared allocated %d bytes, map[string]any nested so %d", name, allocated, want)
		}
	}
}

// A condition that panics, as one comparing a value whose Equal panics does, was charged what it
// cost before the call that panicked, which CEL never charges, though the
// call reads as much as comparing is charged for before it panics: comparing two lists of 4,000
// strings ending in one cost 6 and took a millisecond. It costs its limit, as one stopped at it does.
func TestAConditionThatPanicsCostsItsLimit(t *testing.T) {
	listed := func() ref.Val {
		vs := make([]ref.Val, 0, 4001)
		for i := range 4000 {
			vs = append(vs, types.String(fmt.Sprint(i)))
		}
		return types.NewRefValList(types.DefaultTypeAdapter, append(vs, panicking{}))
	}
	expr := `request.attributes.x == request.attributes.y`
	limit, _ := rbac.ConditionCost(t, expr, nil)
	// A value no host can pass, whose Equal panics.
	if _, evaluated, cost := rbac.EvaluateConditionOn(t, expr, map[string]ref.Val{"x": listed(), "y": listed()}); evaluated || cost < limit {
		t.Errorf("a condition that panicked cost %d of its limit %d, evaluated %t", cost, limit, evaluated)
	}
}

// panicking is a host's own value whose Equal panics.
type panicking struct{}

func (panicking) ConvertToNative(reflect.Type) (any, error) { return nil, errors.New("panicking") }
func (panicking) ConvertToType(ref.Type) ref.Val            { return types.NewErr("panicking") }
func (panicking) Equal(ref.Val) ref.Val                     { panic("panicking") }
func (panicking) Type() ref.Type                            { return panickingType }
func (panicking) Value() any                                { return nil }

var panickingType = types.NewOpaqueType("panicking")

// formatted counts the times it is written out.
type formatted struct{ n *int }

func (f formatted) String() string {
	*f.n++
	return "formatted"
}

// CEL writes a value it can't read, as a struct, into its error, whole, each time a condition
// reads it, as declaring its type does once for a check: a struct holding a long list took as
// long to write out as it is long each time, though the read was charged as one value, and one
// holding a map holding itself recursed until the stack overflowed (TestAValueHoldingItselfFailsItsConditions).
// Each fails unwritten.
func TestAValueCELCantReadFailsUnwritten(t *testing.T) {
	n := 0
	for expr, v := range map[string]any{
		`request.attributes.v != 1`:              formatted{&n},
		`request.attributes.v != "a"`:            &formatted{&n},
		`request.attributes.v[0] != 1`:           []any{formatted{&n}},
		`request.attributes.v.v != 1`:            map[string]any{"v": formatted{&n}},
		`request.attributes.v.exists(k, k != 1)`: map[formatted]int{{&n}: 1},
		`request.attributes.v.all(k, k.n == 1)`:  []formatted{{&n}},
	} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v}); err != nil || evaluated {
			t.Errorf("%s on a %T: evaluated %t, %v", expr, v, evaluated, err)
		}
	}
	h := setup(t, func(c *rbac.Config) {
		c.Attributes = rbac.Attributes{Resource: map[string]rbac.AttributeType{"v": rbac.AttrString}}
	})
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `resource.attributes.v != "x"`}
	h.seed(t, g)
	r := cluster
	r.Attributes = map[string]any{"v": formatted{&n}}
	if allowed(t, h, h.as(t, "u"), login, r) {
		t.Error("a struct declared a string held")
	}
	if n > 0 {
		t.Errorf("values a condition can't read were written out %d times", n)
	}
}

// CEL copies an array of bytes whole into bytes of its own each time a condition reads it, and an
// array or a struct a list or a map holds each time a condition reads one, though it charges the
// read as one value: a loop reading an element of a list of arrays of 512 KiB took sixty times
// longer than its charge. Those of more than 1 KiB fail; smaller ones, as an id of 16 bytes, are
// read as CEL reads them.
// CEL unpacks a packed message packing another in turn, copying all each packs, though it charges
// the read as one value: reading one packing others as deep as a mebibyte allows took two seconds,
// once for each check. One packing another fails, whether of its generated type, of a dynamic type
// or embedded in a host's type; one packing any other message is read as CEL reads it.
func TestAPackedMessagePackingAnotherFails(t *testing.T) {
	inner, err := anypb.New(wrapperspb.String("a"))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := anypb.New(inner)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proto.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := dynamicpb.NewMessage(outer.ProtoReflect().Descriptor())
	if err := proto.Unmarshal(b, dynamic); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"its type": outer, "a dynamic type": dynamic, "a host's type": envelope{Message: outer}} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.v != "b"`, map[string]any{"v": v}); err != nil || evaluated {
			t.Errorf("one of %s: evaluated %t, %v", name, evaluated, err)
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.v == "a"`, map[string]any{"v": inner}); err != nil || !held {
		t.Errorf("one packing a string: held %t, %v", held, err)
	}
}

// A check converts what the host passes into CEL's own values, from those Attributes names, and
// reads anything else by no method of its own: CEL read a value of the host's own list, map or
// scalar type by its methods, which could disagree with each other, yield themselves, or panic, a
// list, a map or an optional of CEL's own by the adapter it was made with, which decoded and wrote
// out what it held on each read, and a message other than those it names by merging it. Each
// fails whatever reads it, and a list or a map holding one reads the rest, but for whether it holds
// that one: `in` found it by its key alone, so a deny's `!("v" in request.attributes)` lifted where
// has() of it failed.
func TestAValueOutsideWhatAttributesNamesFailsItsConditions(t *testing.T) {
	registry, err := types.NewRegistry(&descriptorpb.FileDescriptorProto{})
	if err != nil {
		t.Fatal(err)
	}
	db := pb.NewDb()
	if _, err := db.RegisterMessage(&structpb.Struct{}); err != nil {
		t.Fatal(err)
	}
	described, _ := db.DescribeType("google.protobuf.Struct")
	object, _ := types.NewObject(registry, described, types.NewObjectType("google.protobuf.Struct"),
		&structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewStringValue("a")}}).(traits.Indexer)
	if object == nil {
		t.Fatal("a message of CEL's can't be indexed")
	}
	listed := &structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("a")}}
	mutable := types.NewMutableList(types.DefaultTypeAdapter)
	mutable.Add(types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{types.String("a")}))
	own := types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{types.String("a")})
	for name, v := range map[string]any{
		"a message of CEL's":          registry.NativeToValue(&descriptorpb.FileDescriptorProto{Name: proto.String("a")}),
		"a map of a message of CEL's": object.Get(types.String("fields")), "a message CEL knows": &emptypb.Empty{},
		"a message of a dynamic type": dynamicStruct(), "a message of another dynamic type": &reflecting{dynamicStruct()},
		"a host's type embedding a message": hostListValue{listed},
		"a list of messages":                listed.ProtoReflect().Get(listed.ProtoReflect().Descriptor().Fields().ByName("values")).List(),
		"a list of CEL's":                   types.DefaultTypeAdapter.NativeToValue([]any{"a"}), "a list of CEL's of its own": own,
		"a map of CEL's": types.DefaultTypeAdapter.NativeToValue(map[string]any{"a": "a"}),
		"an optional":    types.OptionalOf(types.String("a")), "no optional": types.OptionalNone, "a mutable list": mutable,
		"a type": types.StringType, "a list of the host's": ownList{own}, "a pointer to a list of the host's": &ownList{own}, "a map of the host's": ownMap{types.NewRefValMap(types.DefaultTypeAdapter, nil)},
		"a list indexing as itself": indexedAsItself{own}, "a struct": struct{ A string }{"a"}, "a pointer to a struct": &struct{ A string }{"a"},
		"a channel": make(chan int), "a func": func() {}, "a complex number": complex(1, 2), "a uintptr": uintptr(1),
		"a time zone": time.UTC, "an error": errors.New("a"),
	} {
		for _, expr := range []string{
			`request.attributes.v == request.attributes.v`, `request.attributes.v != 1`, `request.attributes.v != "a"`,
			`request.attributes.v != []`, `request.attributes.v != {}`, `has(request.attributes.v.a)`, `size(request.attributes.v) >= 0`,
			`string(request.attributes.v) != ""`, `[request.attributes.v] != []`, `"a" in request.attributes.v`,
			`request.attributes.v.all(x, true)`, `"v" in request.attributes`, `!("v" in request.attributes)`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v}); err != nil || evaluated {
				t.Errorf("%s of %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	listing := map[string]any{"l": []any{"a", struct{}{}}, "m": map[string]any{"a": "a", "b": make(chan int)}}
	for expr, holds := range map[string]bool{
		`size(request.attributes.l) == 2`: true, `request.attributes.l[0] == "a"`: true, `"a" in request.attributes.l`: true,
		`request.attributes.m.a == "a"`: true, `size(request.attributes.m) == 2`: true, `"a" in request.attributes.m`: true,
		`"c" in request.attributes.m`: false,
	} {
		if held, _, _, err := rbac.EvaluateCondition(t, expr, listing); err != nil || held != holds {
			t.Errorf("%s: held %t, %v", expr, held, err)
		}
	}
	for _, expr := range []string{
		`request.attributes.l[1] != 1`, `!("b" in request.attributes.l)`, `request.attributes.m.b != 1`, `has(request.attributes.m.b)`,
		`request.attributes.l != ["a", 1]`, `"b" in request.attributes.m`, `!("b" in request.attributes.m)`,
	} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, listing); err != nil || evaluated {
			t.Errorf("%s: evaluated %t, %v", expr, evaluated, err)
		}
	}
}

// A map of Go's keyed by an interface can hold two keys CEL reads as the same value, as an int and
// an int64 of 1, 1 and 1u, or "a" of two string types: CEL's own map of such keys holds one of them,
// and finding the other finds it. A map holding two fails whatever reads it.
func TestAMapHoldingTwoKeysReadAsOneFailsItsConditions(t *testing.T) {
	type named string
	for name, m := range map[string]any{
		"an int and an int64": map[any]any{1: "a", int64(1): "b"}, "an int and a uint": map[any]any{1: "a", uint(1): "a"},
		"two string types": map[any]any{named("a"): 1, "a": 2}, "CEL's own int and Go's": map[any]any{types.Int(1): 1, 1: 1},
	} {
		for _, expr := range []string{
			`request.attributes.m == request.attributes.m`, `size(request.attributes.m) == 2`, `size(request.attributes.m) == 1`,
			`1 in request.attributes.m`, `"a" in request.attributes.m`, `has(request.attributes.m.a)`, `request.attributes.m.all(k, true)`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"m": m}); err != nil || evaluated {
				t.Errorf("%s of a map holding %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `size(request.attributes.m) == 2 && 2u in request.attributes.m`,
		map[string]any{"m": map[any]any{1: "a", uint(2): "b"}}); err != nil || !held {
		t.Errorf("a map holding 1 and 2u: held %t, %v", held, err)
	}
}

// A value reached twice is converted once: a list holding one map a thousand times, which no
// check could convert a thousand times within what it may, is read.
func TestAValueReachedTwiceIsConvertedOnce(t *testing.T) {
	fields := map[string]any{}
	pbFields := map[string]*structpb.Value{}
	for i := range 2000 {
		fields[fmt.Sprint(i)] = fmt.Sprint(i)
		pbFields[fmt.Sprint(i)] = structpb.NewStringValue(fmt.Sprint(i))
	}
	message := &structpb.Struct{Fields: pbFields}
	shared, pbShared := make([]any, 1000), &structpb.ListValue{}
	for i := range shared {
		shared[i] = fields
		pbShared.Values = append(pbShared.Values, structpb.NewStructValue(message))
	}
	for name, v := range map[string]any{"maps": shared, "messages": pbShared} {
		if held, _, _, err := rbac.EvaluateCondition(t, `size(request.attributes.l) == 1000 && request.attributes.l[999]["1"] == "1"`,
			map[string]any{"l": v}); err != nil || !held {
			t.Errorf("a list of %s reached a thousand times: held %t, %v", name, held, err)
		}
	}
}

// Converting what the host passes isn't charged to a condition, so a check converts no more of it
// than it may (MaxConverted), or every condition reading an attribute of any kind fails, as no
// condition can then read the rest of what the host passed: JSON texts sharing a mebibyte of bytes
// each took the check as long as decoding a mebibyte did.
func TestAttributesLargerThanACheckConvertsFailEveryCondition(t *testing.T) {
	expr := `request.attributes.mfa == true`
	small := map[string]any{"mfa": true, "l": make([]int, rbac.MaxConverted/4)}
	if held, _, _, err := rbac.EvaluateCondition(t, expr, small); err != nil || !held {
		t.Fatalf("attributes a check converts: held %t, %v", held, err)
	}
	buf := []byte(strings.Repeat(" ", 1<<20) + "1")
	overlapping := make([]any, 1000)
	for i := range overlapping {
		overlapping[i] = json.RawMessage(buf[i:])
	}
	for name, large := range map[string]any{
		"a long list": make([]int, rbac.MaxConverted), "a long string": strings.Repeat("x", 10*rbac.MaxConverted),
		"overlapping JSON texts": overlapping, "a list longer than memory holds": make([]struct{}, 1<<40),
	} {
		held, evaluated, allocated, err := rbac.EvaluateCondition(t, expr, map[string]any{"mfa": true, "l": large})
		if err != nil || evaluated {
			t.Errorf("attributes holding %s: held %t, evaluated %t, %v", name, held, evaluated, err)
		}
		if allocated > 64<<20 {
			t.Errorf("attributes holding %s allocated %d bytes", name, allocated)
		}
	}
}

// Decoding what a host passes reads more than a check charged for it: parsing a JSON number reads it
// whole, and copies it into its error where it isn't one, but one that wasn't was charged one, so a
// thousand sharing a mebibyte took seconds; finding a packed message's type hashes its URL whole,
// charged nothing; and JSON text or a packed message of a mebibyte holding more values than a check
// may convert, as a list of zeros, were decoded whole, taking a tenth of a second and 80 MB, before
// converting found them past it. A value of a type whose name is long, as a struct of many fields,
// was named in its error whole, though charged one.
func TestDecodingWhatAHostPassesCostsWhatItIsCharged(t *testing.T) {
	notNumbers, outOfRange, packedFar := make([]any, 1000), make([]any, 1000), make([]any, 1000)
	url := "type.googleapis.com/" + strings.Repeat("x", 1<<20)
	for i := range notNumbers {
		notNumbers[i] = json.Number(strings.Repeat("x", 1<<20))
		outOfRange[i] = json.Number("1" + strings.Repeat("0", 1<<20))
		packedFar[i] = &anypb.Any{TypeUrl: url}
	}
	empty := &structpb.ListValue{Values: make([]*structpb.Value, 790_000)}
	for i := range empty.Values {
		empty.Values[i] = &structpb.Value{}
	}
	packed, err := anypb.New(empty)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{
		"JSON numbers that aren't one": notNumbers, "JSON numbers out of range": outOfRange,
		"packed messages of a long type URL": packedFar, "JSON text of many values": json.RawMessage("[" + strings.Repeat("0,", 790_000) + "0]"),
		"a message packing many values": packed,
	} {
		if allocated, over := rbac.Converting(t, map[string]any{"v": v}); !over || allocated > 16<<20 {
			t.Errorf("%s: past what a check converts %t, allocated %d bytes", name, over, allocated)
		}
	}
	fields := make([]reflect.StructField, 1000)
	for i := range fields {
		fields[i] = reflect.StructField{Name: fmt.Sprintf("Field%d", i), Type: reflect.TypeFor[struct{}]()}
	}
	long := reflect.MakeSlice(reflect.SliceOf(reflect.StructOf(fields)), 5000, 5000).Interface()
	if allocated, over := rbac.Converting(t, map[string]any{"v": long}); over || allocated > 16<<20 {
		t.Errorf("values of a long-named type: past what a check converts %t, allocated %d bytes", over, allocated)
	}
	small, err := anypb.New(&structpb.ListValue{Values: []*structpb.Value{{}, {}}})
	if err != nil {
		t.Fatal(err)
	}
	expr := `request.attributes.n == 1 && request.attributes.j == ["[{,:\"", 0.0, 1.0] && size(request.attributes.p) == 2`
	if held, _, _, err := rbac.EvaluateCondition(t, expr,
		map[string]any{"n": json.Number("1"), "j": json.RawMessage(`["[{,:\"", 0, 1]`), "p": small}); err != nil || !held {
		t.Errorf("a JSON number, JSON text and a packed message: held %t, %v", held, err)
	}
}

// Converting what a host passes allocates for what it converts it to, a string boxed as a value
// and a map of its own: reading a map's entries by reflection allocated for each key and each
// value again.
func TestConvertingAttributesAllocatesForWhatItConvertsThemTo(t *testing.T) {
	maps := [3]map[string]any{}
	for i := range maps {
		maps[i] = map[string]any{}
		for j := range 100 {
			maps[i][fmt.Sprint(j)] = fmt.Sprint(j)
		}
	}
	none := rbac.ConvertingAllocates(t, nil, nil, nil)
	// Two for each entry, its key and its value, and a few for each map and each kind.
	if n := rbac.ConvertingAllocates(t, map[string]any{"m": maps[0]}, map[string]any{"m": maps[1]}, map[string]any{"m": maps[2]}); n > none+600+75 {
		t.Errorf("converting three maps of 100 strings took %.0f allocations, and nothing %.0f", n, none)
	}
}

// A host can nest a value as deep as it likes, which converting it recurses into: a chain of
// pointers two million deep, which cost nothing, overflowed the stack, which no recover catches,
// and a list a hundred thousand deep, each level costing one, took a check a fifth of a second
// and a hundred mebibytes of stack. A value nested deeper than JSON text may fails there, and the
// condition reading it with it. It runs in a child process, on a smaller stack, which converting a
// value as deep as a check may afford, but no deeper than JSON, overflows.
func TestAValueNestedDeepFailsItsConditions(t *testing.T) {
	if os.Getenv("RBAC_VALUE_NESTED_DEEP") != "" {
		debug.SetMaxStack(32 << 20)
		var pointed, listed, mapped any = "x", "x", "x"
		for range 2_000_000 {
			p := pointed
			pointed, listed, mapped = &p, []any{listed}, map[string]any{"a": mapped}
		}
		for name, v := range map[string]any{"pointers": pointed, "lists": listed, "maps": mapped} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.v == request.attributes.v`, map[string]any{"v": v}); err != nil || evaluated {
				t.Errorf("%s nested deep: evaluated %t, %v", name, evaluated, err)
			}
			// The rest is read.
			if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"v": v, "ok": true}); err != nil || !held {
				t.Errorf("an attribute beside %s nested deep: held %t, %v", name, held, err)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAValueNestedDeepFailsItsConditions$")
	cmd.Env = append(os.Environ(), "RBAC_VALUE_NESTED_DEEP=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%v\n%.2000s", err, out)
	}
}

// hostByte is a byte type of the host's own.
type hostByte byte

// CEL copies an array of bytes whole each time a condition reads it, and a list or a map holding
// arrays or structs copies each it reads, though it charges the read as one value. A check copies
// an array of bytes once, however long, and fails a struct. Copying an array of a byte type of the
// host's own panicked outside any condition, ending the check.
func TestAnArrayOfBytesIsCopiedOnceForACheck(t *testing.T) {
	id := [16]byte{1}
	for name, c := range map[string]struct {
		v     any
		reads bool
	}{
		"an id": {id, true}, "a list of ids": {[][16]byte{id}, true}, "a map of ids": {map[string][16]byte{"a": id}, true},
		"a long array of bytes": {[2 << 10]byte{1}, true}, "a list of long arrays": {[][2 << 10]byte{{1}}, true},
		"a map of long arrays": {map[string][1 << 10]int{"a": {1}}, true}, "a pointer to a long array": {&[2 << 10]byte{1}, true},
		"a long array of other kinds": {[2 << 10]int16{1}, true}, "an array of a byte type of the host's": {[4]hostByte{1}, true},
		"a list of arrays of a byte type of the host's": {[][2 << 10]hostByte{{1}}, true},
		"a map keyed by ids":                            {map[[16]byte]int{id: 1}, false}, "a list of small structs": {[]struct{ A int }{{1}}, false},
		"a list of large structs": {[]struct{ A [2 << 10]byte }{{}}, false},
	} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.v == request.attributes.v`, map[string]any{"v": c.v}); err != nil || evaluated != c.reads {
			t.Errorf("%s: evaluated %t, %v", name, evaluated, err)
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.v == b"\x01\x02"`, map[string]any{"v": [2]hostByte{1, 2}}); err != nil || !held {
		t.Errorf("an array of a byte type of the host's: held %t, %v", held, err)
	}
	held, evaluated, allocated, err := rbac.EvaluateCondition(t, `request.attributes.l.all(x, request.attributes.v[0] != b"")`,
		map[string]any{"l": make([]any, 1000), "v": [][64 << 10]byte{{1}}})
	if err != nil || !evaluated || !held {
		t.Errorf("a long array of bytes read a thousand times: held %t, evaluated %t, %v", held, evaluated, err)
	}
	if allocated > 4*64<<10 {
		t.Errorf("a long array of bytes read a thousand times allocated %d bytes", allocated)
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
	r.Attributes = map[string]any{"l": make([]int, 20000)}
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
		{`{"dev": 1, "prod": 2}["dev"] <= request.attributes.n && [{"n": 2}].exists(r, r.n == request.attributes.n)`, true},
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
		// A map hashes a key it looks up, or a map literal's, whole, as `in` reads what it finds.
		{`{"dev": 1, "prod": 2}[resource.attributes.env] <= request.attributes.n`, false},
		{`{request.attributes.ip: 1, "a": request.attributes.ip}[request.attributes.ip] == 1`, false},
		{`request.attributes.m[dyn(request.attributes.ip)] == "v" || request.attributes.m[request.attributes.team] == 1`, false},
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

// CEL's cost tracking holds what a loop's steps evaluate until they are charged, and a loop's own
// values until it ends, and reads all it holds in search of what a step didn't evaluate, as the
// argument a failing call never reached: each step of a loop over a list the host passes would
// take longer than the one before, past what it is charged, and one failing, charged little, the
// most. It holds no more for a step than the step evaluates, whatever came before.
func TestALoopsStepsTakeNoLongerForTheStepsBefore(t *testing.T) {
	l := make([]any, 3000)
	for i := range l {
		l[i] = strings.Repeat("q", i%50)
	}
	attributes := map[string]any{"l": l, "zero": uint(0), "m": map[string]any{"a": uint(1)}, "secret": 1}
	declares := rbac.Attributes{Resource: map[string]rbac.AttributeType{"secret": rbac.AttrString}}
	for name, expr := range map[string]string{
		"indexing a string":     `request.attributes.l.exists_one(z, 1u == z[0])`,
		"an index out of range": `request.attributes.l.exists_one(z, [1u, z][2] == z)`,
		"a missing key":         `request.attributes.l.exists_one(z, 1u == request.attributes.m[z])`,
		"a type mismatch":       `request.attributes.l.exists_one(z, 1u < z)`,
		"a division by zero":    `request.attributes.l.exists_one(z, 1u / request.attributes.zero == 1u)`,
		"a refused attribute":   `request.attributes.l.exists_one(z, 1u == resource.attributes.secret)`,
		"failing in map()":      `request.attributes.l.map(z, 1u > 0u, 1u + z).size() == 0`,
		"failing in filter()":   `request.attributes.l.filter(z, 1u < z).size() == 0`,
		"failing in all()":      `request.attributes.l.all(z, 1u < z)`,
		"failing in exists()":   `request.attributes.l.exists(z, 1u < z)`,
		"failing in a nested":   `request.attributes.l.exists(y, [y, y].exists_one(z, 1u < z))`,
		"steps that don't fail": `request.attributes.l.all(z, uint(size(z)) < 100u) && request.attributes.l.exists_one(z, 1u > uint(size(z)))`,
	} {
		cost, most, reached := rbac.TrackedValues(t, declares, expr, attributes)
		if reached < 500 {
			t.Fatalf("%s: %s reached a uint literal %d times, costing %d", name, expr, reached, cost)
		}
		if most > 16 {
			t.Errorf("%s: %s held %d values, costing %d", name, expr, most, cost)
		}
	}
}

// CEL charges a loop's step only what it evaluates, which can be nothing, as for a step reading
// only literals, or what it loops over only in the branch it takes, so a loop over a list the host
// passes cost nothing for each element, however long. Each step costs at least 1, and a loop
// taking more steps than its condition may cost stops as one costing more does. A loop whose steps
// are charged costs as it did.
func TestALoopsStepsCostAtLeastOneEach(t *testing.T) {
	falses := func(n int) map[string]any { return map[string]any{"l": make([]any, n)} }
	for _, expr := range []string{
		`request.attributes.l.filter(z, false).size() == 0`,
		`!request.attributes.l.exists_one(z, false)`,
		`request.attributes.l.map(z, false, z).size() == 0`,
		`request.attributes.l.exists_one(z, false ? true : z) || true`,
		`[1, 2].all(x, request.attributes.l.filter(z, false).size() == 0)`,
	} {
		for _, n := range []int{3000, 20000} {
			limit, cost := rbac.ConditionCost(t, expr, falses(n))
			if cost < min(uint64(n), limit) {
				t.Errorf("%s over %d elements cost %d", expr, n, cost)
			}
		}
	}
	l := make([]any, 1000)
	for i := range l {
		l[i] = i%2 == 0
	}
	for _, c := range []struct {
		expr string
		cost uint64
	}{
		{`request.attributes.l.all(z, z || !z)`, 5004},
		{`request.attributes.l.exists(z, z && !z)`, 6004},
		{`request.attributes.l.exists_one(z, z) || true`, 3006},
		{`request.attributes.l.filter(z, z).size() == 500`, 8518},
	} {
		if _, cost := rbac.ConditionCost(t, c.expr, map[string]any{"l": l}); cost != c.cost {
			t.Errorf("%s cost %d, not %d", c.expr, cost, c.cost)
		}
	}
}

// CEL copies the keys of a map the host passes before a loop over it takes its first step, however
// few it takes, so a loop over one, inside another loop, took time growing with the map's size and
// the outer loop's steps, charged only for the steps. Such a loop costs 1 for each key, however the
// host passed the map, and one over a literal map no more than its bound, though the bound counts a
// step of map() whose transform is a literal only 1 more than it costs.
func TestALoopOverAMapCostsEachOfItsKeys(t *testing.T) {
	m, n := map[string]any{}, map[string]int{}
	for i := range 3000 {
		m[fmt.Sprint(i)], n[fmt.Sprint(i)] = i, i
	}
	for expr, least := range map[string]uint64{
		`request.attributes.m.exists(k, true)`:                   3000,
		`!request.attributes.m.all(k, false)`:                    3000,
		`[1, 2, 3].all(i, request.attributes.m.exists(k, true))`: 9000,
		`request.attributes.n.exists(k, true)`:                   3000,
	} {
		if _, cost := rbac.ConditionCost(t, expr, map[string]any{"m": m, "n": n}); cost < least {
			t.Errorf("%s over %d keys cost %d", expr, len(m), cost)
		}
	}
	literal := `{"a": 1, "b": 2, "c": 3}`
	for _, expr := range []string{
		literal + `.exists(k, true)`, literal + `.exists_one(k, false) || true`, literal + `.map(k, k).size() == 3`,
		`[1, 2].all(i, ` + literal + `.all(k, true))`, literal + `.map(k, 1).size() == 3`,
		`[` + literal + `][0].map(k, 1).size() == 3`,
	} {
		if limit, cost := rbac.ConditionCost(t, expr, nil); cost > limit {
			t.Errorf("%s cost %d, past its bound, %d", expr, cost, limit)
		}
	}
}

// A map hashes a key it looks up, or a map literal's, whole, which CEL charges as 1 however long
// the key is, so a loop looking up a long string the request passes took time growing with its
// length, charged only for the steps. A key a condition computes costs a tenth of its bytes more,
// once however CEL plans it: an index whose key isn't an attribute it plans twice where the index
// is itself a key.
func TestAKeyCostsItsLength(t *testing.T) {
	long := strings.Repeat("k", 10000)
	for expr, keys := range map[string]uint64{
		`request.attributes.m[request.attributes.s] == 1`:                                                    1,
		`{request.attributes.s: 1} != {}`:                                                                    1,
		`[1, 2, 3].all(i, request.attributes.m[request.attributes.s] == 1)`:                                  3,
		`request.attributes.m[{"k": request.attributes.s}["k"]] == 1`:                                        1,
		`{request.attributes.s: 1}[request.attributes.s] == 1`:                                               2,
		`request.attributes.m[true ? request.attributes.s : ""] == 1`:                                        1,
		`request.attributes.m[{request.attributes.s: request.attributes.s}[dyn(request.attributes.s)]] == 1`: 3,
		`request.attributes.m["k"] == 1 && {"k": request.attributes.s}["k"] != ""`:                           0,
	} {
		_, short := rbac.ConditionCost(t, expr, map[string]any{"s": "", "m": map[string]any{"": 1, "k": 1}})
		_, cost := rbac.ConditionCost(t, expr, map[string]any{"s": long, "m": map[string]any{long: 1, "k": 1}})
		if cost-short != keys*uint64(len(long))/10 {
			t.Errorf("%s with a key of %d bytes cost %d, and with an empty one %d", expr, len(long), cost, short)
		}
	}
	// A map literal reads a key the host passes as another Go value as the string CEL converts it to.
	type name string
	for _, s := range []any{&long, name(long), json.RawMessage(`"` + long + `"`)} {
		expr := `{request.attributes.s: 1} != {}`
		_, short := rbac.ConditionCost(t, expr, map[string]any{"s": ""})
		if _, cost := rbac.ConditionCost(t, expr, map[string]any{"s": s}); cost-short != uint64(len(long))/10 {
			t.Errorf("%s with a key of %d bytes as a %T cost %d, and with an empty one %d", expr, len(long), s, cost, short)
		}
	}
}

// finds counts the keys a map is asked for.
type finds struct {
	traits.Mapper
	n *int
}

func (f finds) Find(key ref.Val) (ref.Val, bool) {
	*f.n++
	return f.Mapper.Find(key)
}

// longKeys counts the lookups of a map by a key of more than past bytes.
type longKeys struct {
	traits.Mapper
	n    *int
	past int
}

func (m longKeys) Find(key ref.Val) (ref.Val, bool) {
	m.count(key)
	return m.Mapper.Find(key)
}

func (m longKeys) Get(key ref.Val) ref.Val {
	m.count(key)
	return m.Mapper.Get(key)
}

func (m longKeys) count(key ref.Val) {
	if s, ok := key.(types.String); ok && len(s) > m.past {
		*m.n++
	}
}

// Finding a key in a map hashes it whole, and comparing maps finds the keys of one in the other,
// though comparing them is charged only as far as the smaller reads: a long key of the larger,
// found in a map literal or a large map the host passes, was hashed uncharged each time a loop
// compared them, as was a key past what reading a map may cost, found in it to read its value.
func TestComparingMapsFindsNoKeyLongerThanTheSmallerHolds(t *testing.T) {
	long := strings.Repeat("k", 10*10000+1)
	for expr, holds := range map[string]bool{
		`request.attributes.long != request.attributes.short`:               true,
		`request.attributes.short != request.attributes.long`:               true,
		`request.attributes.long in [request.attributes.short]`:             false,
		`[request.attributes.long] == [request.attributes.short]`:           false,
		`{"a": request.attributes.long} != {"a": request.attributes.short}`: true,
	} {
		n := 0
		// Values no host can pass, which count the lookups of a long key.
		attributes := map[string]ref.Val{
			"long":  longKeys{types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{types.String(long): types.Int(1)}), &n, len(long) - 1},
			"short": longKeys{types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{types.String("a"): types.Int(1)}), &n, len(long) - 1},
		}
		if held, evaluated, _ := rbac.EvaluateConditionOn(t, expr, attributes); !evaluated || held != holds {
			t.Errorf("%s: held %t, evaluated %t", expr, held, evaluated)
		}
		if n > 0 {
			t.Errorf("%s found a key of %d bytes %d times", expr, len(long), n)
		}
	}
	// Nor does a search find a key once for each of many maps smaller than it, which it is charged
	// for reading together.
	n, key := 0, strings.Repeat("k", 5000)
	small := make([]ref.Val, 2000)
	for i := range small {
		small[i] = longKeys{types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{types.String("a"): types.Int(1)}), &n, len(key) - 1}
	}
	expr := `request.attributes.long in request.attributes.small`
	attributes := map[string]ref.Val{
		"long":  types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{types.String(key): types.Int(1)}),
		"small": types.NewRefValList(types.DefaultTypeAdapter, small),
	}
	if held, evaluated, _ := rbac.EvaluateConditionOn(t, expr, attributes); !evaluated || held {
		t.Errorf("%s: held %t, evaluated %t", expr, held, evaluated)
	}
	if n > 0 {
		t.Errorf("%s found a key of %d bytes %d times", expr, len(key), n)
	}
}

// Comparing maps decides as CEL does, though it finds no key longer than the smaller value holds:
// it finds the keys of the left in the right. Where a map holds keys CEL counts as equal, as 1 and
// 1u, or a double, which finds an int key though no int finds a double key, finding the right's
// keys in the left instead decided otherwise, and a grant's comparison held where CEL's doesn't.
func TestComparingMapsDecidesAsCELDoes(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		expr string
		m    any
	}{
		{`{1: "aaaaaaaaaaaa", dyn(1u): "aaaaaaaaaaaa"} == {1: "aaaaaaaaaaaa", 2: "b"}`, nil},
		{`{1: "a", 2: "bbbbbbbbbbbb"} == {1: "a", dyn(1u): "a"}`, nil},
		{`{1: "a", 2: "bbbbbbbbbbbb"} != {1: "a", dyn(1u): "a"}`, nil},
		{`[{1: "a", 2: "bbbbbbbbbbbb"}] == [{1: "a", dyn(1u): "a"}]`, nil},
		{`{"k": {1: "a", 2: "bbbbbbbbbbbb"}} == {"k": {1: "a", dyn(1u): "a"}}`, nil},
		{`{1: "a", 2: "bbbbbbbbbbbb"} in [{1: "a", dyn(1u): "a"}]`, nil},
	} {
		checked, iss := env.Compile(c.expr)
		if iss.Err() != nil {
			t.Fatal(iss.Err())
		}
		prg, err := env.Program(checked)
		if err != nil {
			t.Fatal(err)
		}
		attributes := map[string]any{"m": c.m}
		out, _, err := prg.Eval(map[string]any{"request": map[string]any{"attributes": attributes}})
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if held, evaluated, _, err := rbac.EvaluateCondition(t, c.expr, attributes); err != nil || !evaluated || held != out.Value() {
			t.Errorf("%s: held %t, evaluated %t, %v; CEL decides %v", c.expr, held, evaluated, err, out)
		}
	}
}

// Converting a finite value to a string, comparing optional values the host passes and comparing
// maps keyed by numbers of different types decide as CEL does. A conversion ran CEL's own for the
// Go type of the value, not the overload CEL picks by the type it checked, which a value CEL
// checks as of another's type needn't have: converting `(dyn([true]) + [""])[0]` made "true" where
// CEL's conversion fails, and a grant's `!=` held.
func TestFiniteValuesDecideAsCELDoes(t *testing.T) {
	celEval := func(expr string, attributes map[string]any) (ref.Val, error) {
		return evaluatedByCEL(t, expr, attributes)
	}
	decides := func(expr string, attributes map[string]any) {
		t.Helper()
		out, err := celEval(expr, attributes)
		held, evaluated, _, rerr := rbac.EvaluateCondition(t, expr, attributes)
		if rerr != nil {
			t.Fatalf("%s: %v", expr, rerr)
		}
		if evaluated != (err == nil) || evaluated && held != out.Value() {
			t.Errorf("%s: held %t, evaluated %t; CEL decides %v, %v", expr, held, evaluated, out, err)
		}
	}
	strs := map[string]any{
		"string": "a", "bytes": []byte("a"), "invalid UTF-8": []byte{0xff}, "bool": true, "int": -1, "uint": uint(1),
		"double": 0.5, "negative zero": math.Copysign(0, -1), "large double": 1e300,
		"timestamp": time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC), "duration": 90 * time.Minute, "null": nil,
		"list": []any{"a"}, "map": map[string]any{"a": "a"},
		"string wrapper": wrapperspb.String("a"), "double wrapper": wrapperspb.Double(0.5), "bytes wrapper": wrapperspb.Bytes([]byte("a")),
		"JSON string": structpb.NewStringValue("a"), "JSON number": structpb.NewNumberValue(0.5), "JSON number text": json.Number("1.5"),
	}
	for name, v := range strs {
		for _, of := range []string{
			"%s", "dyn(%s)", `(dyn([%s]) + [""])[0]`, `(dyn([%s]) + [b""])[0]`, `(dyn([%s]) + [true])[0]`, `(dyn([%s]) + [1])[0]`,
			`(dyn([%s]) + [1u])[0]`, `(dyn([%s]) + [1.0])[0]`, `(dyn([%s]) + [duration("1s")])[0]`, `(dyn([%s]) + [timestamp(0)])[0]`,
		} {
			conversion := "string(" + fmt.Sprintf(of, "request.attributes.v") + ")"
			attributes := map[string]any{"v": v, "want": ""}
			if s, err := celEval(conversion, attributes); err == nil {
				attributes["want"] = s.Value()
			}
			for _, op := range []string{" == ", " != "} {
				decides(conversion+op+"request.attributes.want", attributes)
			}
		}
		if t.Failed() {
			t.Fatalf("converting a %s", name)
		}
	}
	values := map[string]any{
		"bare 1": 1, "bare null": nil, "{1}": map[int64]any{1: "a"}, "{1u}": map[uint64]any{1: "a"},
		"{1, 2u}": map[any]any{int64(1): "a", uint64(2): "a"},
	}
	for x := range values {
		for y := range values {
			for _, of := range []string{"%s == %s", "%s in [%s]"} {
				decides(fmt.Sprintf(of, "request.attributes.x", "request.attributes.y"), map[string]any{"x": values[x], "y": values[y]})
			}
		}
		for _, literal := range []string{`{1: "a"}`, `{1u: "a"}`, `{1.0: "a"}`, `{1: "a", 2u: "a"}`, `{1.0: "a", 2.0: "a"}`} {
			decides("request.attributes.x == "+literal, map[string]any{"x": values[x]})
			decides(literal+" == request.attributes.x", map[string]any{"x": values[x]})
		}
	}
	// What the host passes decides as CEL decides on what a check converts it to: a value of the
	// host's own type read by its kind, JSON parsed, a message by its fields, a nil pointer as null,
	// and a map's keys as CEL's own values, so a map of Go's keyed by an int is found by one, as CEL
	// itself doesn't find it, where it looks up an int64.
	type named string
	type level int
	type ratio float64
	packed, err := anypb.New(structpb.NewStringValue("a"))
	if err != nil {
		t.Fatal(err)
	}
	listed := &structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("a"), structpb.NewNumberValue(0.5)}}
	at := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	text, celText, nothing, id := "a", types.String("a"), (*string)(nil), make([]byte, 16)
	id[0] = 1
	converted := map[string][2]any{
		"JSON text": {json.RawMessage(`{"a": "a"}`), map[string]any{"a": "a"}}, "a JSON list": {json.RawMessage(`["a", 0.5]`), []any{"a", 0.5}},
		"a JSON string": {json.RawMessage(`"a"`), "a"}, "a JSON number": {json.Number("0.5"), 0.5}, "a JSON integer": {json.Number("2"), 2},
		"a packed message": {packed, "a"}, "a ListValue": {listed, []any{"a", 0.5}},
		"a Struct": {&structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewStringValue("a")}}, map[string]any{"a": "a"}},
		"a Value":  {structpb.NewStringValue("a"), "a"}, "a null Value": {structpb.NewNullValue(), nil},
		"a NullValue": {structpb.NullValue_NULL_VALUE, nil}, "a wrapper": {wrapperspb.Int64(3), 3},
		"a timestamp": {timestamppb.New(at), at}, "a duration": {durationpb.New(time.Minute), time.Minute},
		"a list": {[]any{"a", 0.5}, []any{"a", 0.5}}, "a map": {map[string]any{"a": "a"}, map[string]any{"a": "a"}},
		"an id": {[16]byte{1}, id}, "ids": {[][16]byte{{1}}, []any{id}}, "bytes": {[]byte("a"), []byte("a")},
		"a list of a type's name": {[]any{"int", "a"}, []any{"int", "a"}}, "a named string": {named("a"), "a"},
		"a named int": {level(3), 3}, "a named float": {ratio(0.5), 0.5}, "a pointer": {&text, "a"}, "a nil pointer": {nothing, nil},
		"a map of Go's keyed by ints":   {map[any]any{1: "a", 2: "b"}, map[int64]any{1: "a", 2: "b"}},
		"a map keyed by a named string": {map[named]string{"a": "a"}, map[string]any{"a": "a"}},
		"a map of ref.Vals":             {map[ref.Val]ref.Val{types.String("a"): types.String("a")}, map[string]any{"a": "a"}},
		"CEL's own string":              {types.String("a"), "a"}, "a pointer to CEL's own string": {&celText, "a"},
		"an array of a byte type of the host's": {[2]hostByte{1, 2}, []byte{1, 2}},
	}
	convertedDecides := func(expr, x, y string) {
		t.Helper()
		out, err := celEval(expr, map[string]any{"x": converted[x][1], "y": converted[y][1]})
		held, evaluated, _, rerr := rbac.EvaluateCondition(t, expr, map[string]any{"x": converted[x][0], "y": converted[y][0]})
		if rerr != nil || evaluated != (err == nil) || evaluated && held != out.Value() {
			t.Errorf("%s of %s and %s: held %t, evaluated %t, %v; CEL decides %v, %v of what they convert to", expr, x, y, held, evaluated, rerr, out, err)
		}
	}
	for x := range converted {
		for y := range converted {
			for _, of := range []string{"%s == %s", "%s != %s", "%s in [%s]"} {
				convertedDecides(fmt.Sprintf(of, "request.attributes.x", "request.attributes.y"), x, y)
			}
		}
		for _, of := range []string{
			`%s.a == "a"`, `%s[0] == "a"`, `size(%s) == 2`, `%s.exists(v, v == "a")`, `"a" in %s`, `string(%s) == "a"`,
			`%s.all(k, k in %[1]s)`, `%s.exists(k, %[1]s[k] == "a")`, `1 in %s`, `%s[1] == "a"`, `%s == null`,
		} {
			convertedDecides(fmt.Sprintf(of, "request.attributes.x"), x, x)
		}
	}
}

// evaluatedByCEL is what expr evaluates to on a request with attributes in CEL, as it would without
// this package.
func evaluatedByCEL(t *testing.T, expr string, attributes map[string]any) (ref.Val, error) {
	t.Helper()
	env, err := plainEnv()
	if err != nil {
		t.Fatal(err)
	}
	checked, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	prg, err := env.Program(checked)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := prg.Eval(map[string]any{"request": map[string]any{"attributes": attributes}})
	return out, err
}

var plainEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)))
})

// CEL indexes a map or a list by a key as the Go value the host passed, and fails for one of a type
// it doesn't index by, as an int8, a named type, a pointer, a JSON number or text, or a wrapper,
// though it reads each as one of its own everywhere else, so `k in m` held where `m[k]` failed. A
// check reads each as CEL reads it, so indexing by one decides as CEL decides indexing by the value
// it reads it as.
func TestAKeyIndexesAsTheValueItIsReadAs(t *testing.T) {
	one, a := 1, "a"
	keys := map[string]any{
		"an int8": int8(1), "a uint16": uint16(1), "a float32": float32(1), "a named string": named("a"),
		"a pointer to an int": &one, "a pointer to a string": &a, "a JSON number": json.Number("1"),
		"JSON text": json.RawMessage(`"a"`), "a JSON number's text": json.RawMessage(`1`),
		"a string wrapper": wrapperspb.String("a"), "an int wrapper": wrapperspb.Int64(1),
	}
	indexed := map[string]any{
		"a list": []any{"x", "a"}, "a map of ints": map[int64]any{1: "a"}, "a map of strings": map[string]any{"a": "a"},
		"a map of either": map[any]any{int64(1): "a", "a": "a"}, "a map of int8s": map[int8]string{1: "a"},
	}
	evaluated := 0
	for k, key := range keys {
		for m, of := range indexed {
			for _, expr := range []string{`request.attributes.m[request.attributes.k] == "a"`, `request.attributes.m[request.attributes.k] != "a"`} {
				out, err := evaluatedByCEL(t, expr, map[string]any{"m": of, "k": types.DefaultTypeAdapter.NativeToValue(key)})
				held, ok, _, rerr := rbac.EvaluateCondition(t, expr, map[string]any{"m": of, "k": key})
				if rerr != nil || ok != (err == nil) || ok && held != out.Value() {
					t.Errorf("%s by %s in %s: held %t, evaluated %t, %v; CEL decides %v, %v of the value it reads", expr, k, m, held, ok, rerr, out, err)
				}
				if ok {
					evaluated++
				}
			}
		}
	}
	if evaluated == 0 {
		t.Error("no key indexed")
	}
}

// ownMap is a host's own map type, which yields what the map it embeds holds.
type ownMap struct{ traits.Mapper }

// heldKey is a host's own type CEL reads as a double, which a map of Go's keyed by an interface finds
// as itself.
type heldKey struct{ hostDouble }

func (k heldKey) ConvertToNative(t reflect.Type) (any, error) {
	if t.Kind() == reflect.Interface && reflect.TypeOf(k).Implements(t) {
		return k, nil
	}
	return k.hostDouble.ConvertToNative(t)
}

// iterated counts the elements a loop over a list takes.
type iterated struct {
	traits.Lister
	n *int
}

func (l iterated) Iterator() traits.Iterator { return iterating{l.Lister.Iterator(), l.n} }

type iterating struct {
	traits.Iterator
	n *int
}

func (i iterating) Next() ref.Val {
	*i.n++
	return i.Iterator.Next()
}

// CEL doesn't count what a condition's keys cost past its own charge: one whose keys cost more
// than its limit stops before a map reads the next, as one CEL charges more stops, and one they
// take past its limit, though CEL charges it less, fails as if it had stopped.
func TestAConditionsKeysPastItsLimitFailIt(t *testing.T) {
	key := strings.Repeat("k", 2000)
	n := 0
	m := finds{types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{key: 1}), &n}
	steps := "[" + strings.Repeat("0, ", 99) + "0]"
	expr := steps + `.all(i, request.attributes.m[request.attributes.key] == 1)`
	if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"m": m, "key": key}); err != nil || evaluated {
		t.Errorf("a hundred keys of %d bytes: evaluated %t, %v", len(key), evaluated, err)
	}
	// 10,000 is all a condition may cost, and each key costs 200.
	if n > 50 {
		t.Errorf("a condition whose keys cost more than its limit looked up %d", n)
	}
	// Nor does a loop after keys costing all but a step of the limit take more than that step.
	n = 0
	l := iterated{types.NewDynamicList(types.DefaultTypeAdapter, make([]any, 20000)), &n}
	key = strings.Repeat("k", 99990)
	expr = `request.attributes.m[request.attributes.key] == 1 && request.attributes.l.all(i, true)`
	if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"m": map[string]any{key: 1}, "key": key, "l": l}); err != nil || evaluated {
		t.Errorf("a loop after a key of %d bytes: evaluated %t, %v", len(key), evaluated, err)
	}
	if n > 2 {
		t.Errorf("a loop after keys costing the limit took %d steps", n)
	}
	key = strings.Repeat("k", 60000)
	attributes := map[string]any{"m": map[string]any{key: 1}, "key": key, "t": key}
	for expr, evaluates := range map[string]bool{
		`request.attributes.m[request.attributes.key] == 1`:                                   true,
		`size(request.attributes.t) > 0`:                                                      true,
		`request.attributes.m[request.attributes.key] == 1 && size(request.attributes.t) > 0`: false,
	} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, attributes); err != nil || evaluated != evaluates {
			t.Errorf("%s: evaluated %t, %v", expr, evaluated, err)
		}
	}
}

// A key that CEL plans as neither an attribute nor a call, or where no decorator sees it, as
// another version of CEL may, isn't a condition: a map would read it uncharged.
func TestAKeyPlannedOtherwiseIsNoCondition(t *testing.T) {
	for _, expr := range []string{
		`request.attributes.m[request.attributes.k] == 1`, `{request.attributes.k + "x": 1} != {}`,
		`{"a": 1}[dyn(request.attributes.k)] == 1`, `{int: 1} != {}`,
	} {
		for how, replan := range map[string]func(interpreter.InterpretableV2) interpreter.InterpretableV2{
			"as something else": func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, i.ID()} },
			"under another id":  func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, -i.ID()} },
		} {
			if err := rbac.PlanKeysOtherwise(t, expr, replan); err == nil {
				t.Errorf("%s with its key planned %s is a condition", expr, how)
			}
		}
		if err := rbac.PlanKeysOtherwise(t, expr, func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return i }); err != nil {
			t.Errorf("%s planned as CEL plans it: %v", expr, err)
		}
	}
}

// A key folded into a double that isn't finite, as another version of CEL may fold one, isn't a
// condition: no key it computes is left to fail.
func TestAKeyFoldedIntoADoubleThatIsntFiniteIsNoCondition(t *testing.T) {
	fold := func(i interpreter.InterpretableV2) interpreter.InterpretableV2 {
		return interpreter.NewConstValue(i.ID(), i.Eval(interpreter.EmptyActivation()))
	}
	for expr, isCondition := range map[string]bool{
		`{0.0 / 0.0: 1} != {0.5: 1}`: false, `{1.0 / 0.0: 1} != {0.5: 1}`: false, `{1.0 / 2.0: 1} == {0.5: 1}`: true,
	} {
		if err := rbac.PlanKeysOtherwise(t, expr, fold); (err == nil) != isCondition {
			t.Errorf("%s with its key folded: %v", expr, err)
		}
	}
}

// A conversion to a string where string() has no binding a program can find, as another version of
// CEL may bind one only once it runs, isn't a condition: it would convert a double that isn't finite
// unchecked.
func TestAConversionToAStringBoundOtherwiseIsNoCondition(t *testing.T) {
	declared := func(opts ...cel.OverloadOpt) *cel.Env {
		env, err := cel.NewCustomEnv(cel.Variable("x", cel.DoubleType),
			cel.Function("string", cel.Overload("double_to_string", []*cel.Type{cel.DoubleType}, cel.StringType, opts...)))
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	converts := cel.UnaryBinding(func(v ref.Val) ref.Val { return v.ConvertToType(types.StringType) })
	for how, c := range map[string]struct {
		env         *cel.Env
		isCondition bool
	}{
		"unbound": {declared(), false}, "bound once it runs": {declared(cel.LateFunctionBinding()), false},
		"bound": {declared(converts), true},
	} {
		if err := rbac.PlanIn(t, c.env, `string(x)`); (err == nil) != c.isCondition {
			t.Errorf("string() %s: %v", how, err)
		}
	}
}

// Loading a time zone copies its name for each place it looks for it, which zoneCost doesn't count
// however long the name is, so a condition reading a time in a zone the request names, in a loop,
// took time growing with its length, charged as a short one. A zone is at most 64 bytes, longer
// than any zone's name: reading a time in a longer one fails before it loads it.
func TestATimeInAZoneLongerThanAnyFailsBeforeLoadingIt(t *testing.T) {
	expr := `request.time.getHours(request.attributes.zone) >= 0`
	for zone, evaluated := range map[string]bool{
		"America/New_York": true, "+05:00": true, strings.Repeat("A", 64): false, strings.Repeat("A", 1<<20): false,
	} {
		_, ok, allocated, err := rbac.EvaluateCondition(t, expr, map[string]any{"zone": zone})
		if err != nil || ok != evaluated {
			t.Errorf("a zone of %d bytes: evaluated %t, %v", len(zone), ok, err)
		}
		if allocated > 1<<20 {
			t.Errorf("a zone of %d bytes allocated %d", len(zone), allocated)
		}
	}
}

// A loop taking more steps than its condition may cost fails, however little CEL charges them: a
// grant's condition gives nothing, and a deny's applies.
func TestALoopOfMoreStepsThanItsConditionMayCostFails(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
	})
	ctx := t.Context()
	free := `resource.attributes.l.filter(z, false).size() == 0`
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: free}
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	u, v := h.as(t, "u"), h.as(t, "v")
	d := rbac.Deny{
		ID: "loop", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: "!(" + free + ")"},
	}
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
		t.Fatal(err)
	}
	for n, within := range map[int]bool{3000: true, 20000: false} {
		r := cluster
		r.Attributes = map[string]any{"l": make([]any, n)}
		if allowed(t, h, u, login, r) != within {
			t.Errorf("a grant's condition looping over %d elements held: %t", n, !within)
		}
		if allowed(t, h, v, login, r) != within {
			t.Errorf("a deny's condition looping over %d elements applied: %t", n, within)
		}
	}
}

// otherwise is a loop's condition or range as another version of CEL may plan it, under the id it
// gives it.
type otherwise struct {
	interpreter.InterpretableV2
	id int64
}

func (o otherwise) ID() int64 { return o.id }

// A loop whose condition CEL plans as neither of those of its macros, or where no decorator sees
// it, as another version of CEL may, isn't a condition: its steps would be neither counted nor
// dropped, so it would run unbounded. Nor is one whose range it plans under another id: its first
// step wouldn't find the range, so a loop over a map would copy its keys uncharged.
func TestALoopPlannedOtherwiseIsNoCondition(t *testing.T) {
	somethingElse := func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, i.ID()} }
	anotherID := func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, -i.ID()} }
	for _, expr := range []string{`[1, 2].all(x, x > 0)`, `[1, 2].exists_one(x, x > 1)`, `{"a": 1}.exists(k, k == "a")`} {
		for how, c := range map[string]struct {
			ranges bool
			replan func(interpreter.InterpretableV2) interpreter.InterpretableV2
		}{
			"its condition planned as something else": {false, somethingElse},
			"its condition planned under another id":  {false, anotherID},
			"its range planned under another id":      {true, anotherID},
		} {
			if err := rbac.PlanLoopsOtherwise(t, expr, c.ranges, c.replan); err == nil {
				t.Errorf("%s with %s is a condition", expr, how)
			}
		}
		same := func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return i }
		for _, ranges := range []bool{false, true} {
			if err := rbac.PlanLoopsOtherwise(t, expr, ranges, same); err != nil {
				t.Errorf("%s planned as CEL plans it: %v", expr, err)
			}
		}
	}
}

// A check passes ids, a kind, a type and a tenant of at most MaxID bytes, and a permission as the
// action, so a condition comparing an attribute with one, as an owner's does, or finding one in a
// map, costs little, and no more than its bound however long they are. A comprehension's variable
// of the same name is what it ranges over, which the request decides.
func TestAConditionReadingTheIDsACheckPassesCostsLittle(t *testing.T) {
	longest := strings.Repeat("x", rbac.MaxID)
	name := "k" + strings.Repeat("x", 62)
	// The action is bounded at the longest permission, so a pattern admitting longer ones fails here.
	action := rbac.Permission(name + ":" + name)
	if !action.Valid() || len(action) != rbac.MaxPermission || rbac.Permission(name+"x:"+name).Valid() ||
		rbac.Permission(name+":"+name+"x").Valid() {
		t.Fatalf("the longest permission isn't the %d bytes an action is bounded at", rbac.MaxPermission)
	}
	big := strings.Repeat("y", 20000)
	attributes := map[string]any{"owner": big, "dept": big, "id": big, "tags": []any{big, big}}
	s := rbac.Subject{Principal: rbac.Principal{Kind: rbac.PrincipalKind(name), ID: longest}, Attributes: attributes}
	r := rbac.Resource{Tenant: longest, Type: name, ID: longest, Attributes: attributes}
	for _, c := range []struct {
		expr  string
		cheap bool
	}{
		{`resource.attributes.owner == subject.id`, true},
		{`subject.id == resource.attributes.owner && resource.tenant != subject.attributes.dept`, true},
		{`resource.id.startsWith(subject.id) && subject.id.endsWith(resource.tenant)`, true},
		{`subject.kind + ":" + resource.type + ":" + resource.id == action + subject.id`, true},
		{`subject.id in {"alice": true} || action in {"cluster:login": true} || resource.type in {"cluster": 1}`, true},
		{`subject.id.matches("^svc-") && size(resource.id) > 0 && string(resource.tenant) == subject.id`, true},
		{`[resource.attributes].exists(subject, subject.owner == .subject.id)`, true},
		{`[resource.attributes.owner].exists(action, action.startsWith(.action))`, true},
		{`{"alice": true}[subject.id] || {subject.id: 1, resource.id: 2}[dyn(resource.tenant)] == 1`, true},
		{`{"x": 1}[{subject.id: "x"}[dyn(resource.id)]] == 1 && {subject.kind + ":" + resource.type: 1}[action] == 1`, true},
		{`subject.id in resource.attributes.tags`, false},
		{`[resource.attributes].exists(subject, subject.id == resource.attributes.owner)`, false},
		{`resource.attributes.tags.exists(action, action == resource.attributes.owner)`, false},
	} {
		limit, actual := rbac.ConditionCostOn(t, c.expr, s, action, r, attributes)
		if actual > limit {
			t.Errorf("%s cost %d, past its bound, %d", c.expr, actual, limit)
		}
		if c.cheap != (limit < 1000) {
			t.Errorf("%s is bounded at %d", c.expr, limit)
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
		{`[1, 2, 3].all(i, i > 0) && [1, 2, 3].exists_one(i, i == 2) && {"a": 1}.exists(k, k == "a")`, 128},
		{`[[1, 2], [3]].all(l, l.all(i, i > 0))`, 86},
		{`[1, 2, 3].map(x, x > 1, x * 2) == [4, 6]`, 108},
		{`[1, 2].map(x, "ab").all(s, s.contains("a"))`, 70},
		{`["10.0.0.1", "10.0.0.2"].filter(ip, ip.startsWith("10.")).exists(ip, request.attributes.ip == ip)`, 100},
		{`[["10.0.0.1"], ["10.0.0.2"]].exists(g, request.attributes.ip in g) && "time" in request`, 70},
		{`{"dev": 1, "prod": 2}["dev"] <= request.attributes.n`, 44},
		{`request.time.getHours(subject.attributes.zone) >= 9`, 112},
		{`[{"level": 2}, {"level": 3}].exists(r, r.level == request.attributes.n)`, 112},
		// The ids, kinds, types and tenant a check passes are of at most MaxID bytes, and its action a
		// permission's.
		{`resource.attributes.owner == subject.id`, 63},
		{`resource.id.startsWith(subject.id) && resource.tenant == subject.attributes.dept`, 123},
		{`subject.kind + ":" + resource.type in {"user:cluster": true} && subject.id.matches("^svc-")`, 672},
		{`action in {"cluster:login": true, "cluster:read": true}`, 46},
		{`[resource.attributes].exists(subject, subject.owner == .subject.id)`, 83},
		{`{"alice": true, "bob": false}[subject.id]`, 87},
		{`"gpu" in request.attributes.tags`, 10000},
		{`{"dev": 1, "prod": 2}[resource.attributes.env] <= request.attributes.n`, 10000},
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

// Conditions comparing an attribute with the subject's id, as an owner's, cost little too, as ids
// are bounded, so the grants a check reads together on a scope may carry a hundred.
func TestOwnerConditionsFitAScopeByTheHundred(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var groups []string
	var grants []rbac.Grant
	for i := range 100 {
		g := fmt.Sprintf("g%02d", i)
		groups = append(groups, g)
		b := rbac.Binding{Role: "cluster.login", Principal: groupOf(g), Condition: rbac.Condition{
			Expression: fmt.Sprintf(`resource.attributes.owner == subject.id && resource.attributes.team == "t%02d"`, i),
		}}
		grants = append(grants, rbac.Grant{Scope: cluster.Scope(), Binding: b})
	}
	h.groups(t, groups...)
	if err := h.authz.Import(ctx, host, "t1", grants); err != nil {
		t.Fatalf("100 owner conditions: %v", err)
	}
	// A check of a subject in every group evaluates them all.
	r := cluster
	r.Attributes = map[string]any{"owner": "u", "team": "t99"}
	if err := h.authz.Authorize(ctx, h.as(t, "u", groups...), login, r); err != nil {
		t.Fatalf("the last group's team: %v", err)
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
