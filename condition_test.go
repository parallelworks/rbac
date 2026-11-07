package rbac_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/pb"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/runtime/protoimpl"
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

// wideDouble is a host's own type CEL reads as a double, which holds 8 KiB in place.
type wideDouble [1 << 10]float64

func (d wideDouble) ConvertToNative(t reflect.Type) (any, error) {
	return types.Double(d[0]).ConvertToNative(t)
}
func (d wideDouble) ConvertToType(t ref.Type) ref.Val { return types.Double(d[0]).ConvertToType(t) }
func (d wideDouble) Equal(other ref.Val) ref.Val      { return types.Double(d[0]).Equal(other) }
func (d wideDouble) Type() ref.Type                   { return types.DoubleType }
func (d wideDouble) Value() any                       { return d[0] }

// intByte is a host's own byte type CEL reads as an int, a slice or an array of which is bytes.
type intByte byte

func (b intByte) ConvertToNative(t reflect.Type) (any, error) {
	return types.Int(b).ConvertToNative(t)
}
func (b intByte) ConvertToType(t ref.Type) ref.Val { return types.Int(b).ConvertToType(t) }
func (b intByte) Equal(other ref.Val) ref.Val      { return types.Int(b).Equal(other) }
func (b intByte) Type() ref.Type                   { return types.IntType }
func (b intByte) Value() any                       { return int64(b) }

// intMessage is a host's own message that isn't a struct.
type intMessage int32

func (m *intMessage) ProtoReflect() protoreflect.Message { return nil }

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
// by the host's methods: each fails every condition reading its kind, finite or not, in a list or a
// map, as a key too.
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
// condition reads, where `in` fails. Each fails every condition reading its kind, finite or not,
// empty too. A double that isn't finite a condition makes in a list fails too, as building the list
// does.
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
}

// A map of structs, which no condition reads, is refused unread, and so is one holding none, as a
// map keyed by a double is: read as {}, it left a kind readable until the map held a struct, and
// converting made room for one of its values, so 19,000 empty maps of a struct of 64 KiB took a
// check 1.4 GB. An empty map of times, or of arrays holding no struct, is read.
func TestAMapOfStructsFailsItsConditionsEmptyToo(t *testing.T) {
	type tag struct{ Name string }
	for name, m := range map[string]any{
		"one": map[string]tag{"a": {"a"}}, "none": map[string]tag{}, "nil": map[string]tag(nil),
		"arrays of one": map[string][1]tag{}, "none keyed by an interface": map[any]tag{},
	} {
		for _, expr := range []string{
			`request.attributes.m != 1`, `request.attributes.m == {}`, `size(request.attributes.m) == 0`,
			`has(request.attributes.m.a)`, `request.attributes.ok == true`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"m": m, "ok": true}); err != nil || evaluated {
				t.Errorf("%s of a map of structs holding %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	for name, m := range map[string]any{
		"times": map[string]time.Time{}, "CEL's timestamps": map[string]types.Timestamp{},
		"CEL's durations": map[string]types.Duration{}, "arrays of no struct": map[string][0]tag{},
	} {
		if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.m == {}`, map[string]any{"m": m}); err != nil || !held {
			t.Errorf("an empty map of %s: held %t, %v", name, held, err)
		}
	}
}

// A slice, an array, a pointer or a map of values no condition reads, as structs, channels, funcs,
// complex numbers, a host's own ref.Val or another message, is refused by its type, empty or nil
// too, as a map of structs is: read as [], {} or null, an empty slice of structs, or a nil pointer
// to one, left a kind readable until it held one. A slice or an array of a byte type is bytes,
// whatever its type's methods, an array of none holds none whatever its value, and a type holding
// itself, as `type list []list`, holds nothing else: each is read.
func TestAListOrAPointerOfValuesNoConditionReadsFailsItsConditionsEmptyToo(t *testing.T) {
	type tag struct{ Name string }
	type list []list
	for name, v := range map[string]any{
		"an empty slice of structs": []tag{}, "a nil slice of structs": []tag(nil), "a nil pointer to a struct": (*tag)(nil),
		"a nil pointer to an array of structs": (*[2]tag)(nil), "an empty slice of slices of structs": [][]tag{},
		"an empty slice of arrays of a struct": [][1]tag{}, "an array of nil slices of structs": [1][]tag{},
		"an empty slice of pointers to structs": []*tag{}, "a slice of nil pointers to structs": []*tag{nil},
		"an empty map of pointers to structs": map[string]*tag{}, "an empty slice of maps of structs": []map[string]tag{},
		"an empty slice of funcs": []func(){}, "an empty map of channels": map[string]chan int{},
		"an empty slice of complex numbers": []complex128{}, "an empty slice of uintptrs": []uintptr{},
		"an empty map of a host's doubles": map[string]hostDouble{}, "a nil pointer to a host's double": (*hostDouble)(nil),
		"a nil message of another type": (*emptypb.Empty)(nil), "an empty slice of messages of another type": []*emptypb.Empty{},
		"an empty slice of maps keyed by doubles": []map[float64]int{}, "an empty slice of messages of an int": []*intMessage{},
	} {
		for _, expr := range []string{`request.attributes.v != 1`, `request.attributes.ok == true`} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v, "ok": true}); err != nil || evaluated {
				t.Errorf("%s of %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	for name, v := range map[string]any{
		"an array of no structs": [0]tag{}, "an empty slice of arrays of no structs": [][0]tag{},
		"an empty slice of bytes saying they are ints": []intByte{}, "an empty slice of arrays of them": [][2]intByte{},
		"an empty map of slices of them": map[string][]intByte{}, "a nil pointer to a slice of them": (*[]intByte)(nil),
		"an empty slice of times": []time.Time{}, "an empty slice of CEL's strings": []types.String{},
		"a nil pointer to CEL's timestamp": (*types.Timestamp)(nil), "a nil Struct": (*structpb.Struct)(nil),
		"an empty slice of Values": []*structpb.Value{}, "a nil pointer to an int": (*int)(nil),
		"an empty slice of interfaces": []any{}, "an empty slice of maps keyed by an interface": []map[any]int{},
		"a nil list holding lists": list(nil), "an empty list holding lists": list{},
	} {
		expr := `request.attributes.v != 1 && request.attributes.ok`
		if held, _, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v, "ok": true}); err != nil || !held {
			t.Errorf("%s: held %t, %v", name, held, err)
		}
	}
}

// Comparing reads the smaller value whole and the larger only as far, so a list or a map holding a
// double that isn't finite was decided by another value it held where it was the larger: comparing
// failed where the smaller held one, but `[0.0 / 0.0, "<long>"] != [1, 2]` held, and a deny's
// `request.attributes.scores == [1, 2]` lifted where the request's scores held NaN beside a long
// string. No list or map a condition reads holds one: a literal holding one fails as it is built,
// and a host's attribute holding one, however deep, is refused, as a declared double that isn't
// finite is, and where no declarations cover its kind, so are the kind's others, but request.time is
// read. `in` a map a condition makes holding one as a value, which reads no value, was false for a
// key it lacks, and now fails as building the map does.
func TestNoListOrMapAConditionReadsHoldsADoubleThatIsntFinite(t *testing.T) {
	long := strings.Repeat("x", 100)
	quoted := strconv.Quote(long)
	for _, expr := range []string{
		`[0.0 / 0.0, ` + quoted + `] != [1, 2]`, `[1, 2] != [0.0 / 0.0, ` + quoted + `]`, `[[1.0 / 0.0], ` + quoted + `] != [[1], 2]`,
		`{"a": 0.0 / 0.0, "b": ` + quoted + `} != {"a": 1, "c": 2}`, `[double("-inf")].size() == 1`, `has({"k": 0.0 / 0.0}.k)`,
		`!("a key longer than the map it is looked up in" in {"k": 0.0 / 0.0})`, `[1.0, 0.0].map(x, 1.0 / x).size() == 2`,
		`[1.0, 0.0].map(x, 1.0 / x).exists(r, r > 0.5)`, `!(dyn(0.0 / 0.0) in {"a": 1})`, `!(1.0 / 0.0 in [1.0, 2.0])`,
	} {
		if held, evaluated := rbac.EvaluateConditionOf(t, expr, nil, nil, nil); evaluated {
			t.Errorf("%s: held %t", expr, held)
		}
	}
	for _, expr := range []string{
		`[1.0 / 2.0, ` + quoted + `] != [1, 2]`, `has({"k": 0.5}.k)`, `[1.0, 2.0].map(x, 1.0 / x).size() == 2`,
	} {
		if held, _ := rbac.EvaluateConditionOf(t, expr, nil, nil, nil); !held {
			t.Errorf("%s: didn't hold", expr)
		}
	}
	nan, inf := math.NaN(), math.Inf(1)
	for name, scores := range map[string]any{
		"a float64":     []any{nan, long},
		"a float32":     []any{float32(inf), long},
		"CEL's double":  []any{types.Double(-inf), long},
		"a DoubleValue": []any{wrapperspb.Double(nan), long},
		"a FloatValue":  []any{wrapperspb.Float(float32(inf)), long},
		"a Value":       &structpb.ListValue{Values: []*structpb.Value{structpb.NewNumberValue(nan), structpb.NewStringValue(long)}},
		"a map":         []any{map[string]any{"a": []any{nan}}, long},
		"a pointer":     []any{&nan, long},
	} {
		attributes := map[string]any{"scores": scores, "other": "x"}
		for _, expr := range []string{
			`request.attributes.scores != [1, 2]`, `[request.attributes.scores] != [[1, 2]]`, `size(request.attributes.scores) == 2`,
			`has(request.attributes.scores)`, `request.attributes.scores[1] != ""`, `"scores" in request.attributes`,
			`request.attributes != {"scores": [1, 2], "other": "x"}`, `size(request) == 2`, `request.attributes.other == "x"`,
		} {
			if held, evaluated := rbac.EvaluateConditionOf(t, expr, nil, nil, attributes); evaluated {
				t.Errorf("%s of scores holding %s that isn't finite: held %t", expr, name, held)
			}
		}
		if held, _ := rbac.EvaluateConditionOf(t, `request.time > timestamp(0)`, nil, nil, attributes); !held {
			t.Errorf("the time of a request whose scores hold %s that isn't finite: didn't hold", name)
		}
	}
	// So a grant comparing them gives nothing, and a deny applies.
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole) })
	given := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	given.Condition = rbac.Condition{Expression: `request.attributes.scores != [1, 2]`}
	h.seed(t, given, grant(cluster.Scope(), "cluster.login", rbac.User, "d"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	ctx := t.Context()
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "scored", Principals: []rbac.Principal{identity("d")}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `request.attributes.scores == [1, 2]`},
	}); err != nil {
		t.Fatal(err)
	}
	is := func(id string, scores []any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"scores": scores}), h.as(t, id), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	for _, id := range []string{"u", "d"} {
		if !is(id, []any{0.5, long}) {
			t.Fatalf("%s, passing finite scores, can't log in", id)
		}
		if is(id, []any{nan, long}) {
			t.Errorf("%s, passing scores holding NaN, logs in", id)
		}
	}
}

// A kind no declarations cover is read whole or not at all: where an attribute holds a double that
// isn't finite, however deep, none of the kind's can be read, as where one holds a value of no type
// Attributes names, while request.time and the other kinds' are read. Refused by name alone, a
// condition reading another attribute decided without it: a deny's
// `request.attributes.region == "eu" && request.attributes.risk > 0.5` lifted outside the EU for an
// infinite float64 risk, and applied for the same infinity as JSON text, which a host reading JSON
// reads none of, and so a grant's `request.attributes.region == "us"` gave its role. A kind
// declarations cover refuses such an attribute by name, and reads the others.
func TestADoubleThatIsntFiniteFailsEveryConditionReadingAKindNoDeclarationsCover(t *testing.T) {
	nan, inf := math.NaN(), math.Inf(1)
	for name, risk := range map[string]any{
		"NaN": nan, "an infinity": inf, "a float32": float32(-inf), "CEL's double": types.Double(nan),
		"a DoubleValue": wrapperspb.Double(inf), "a Value": structpb.NewNumberValue(nan), "a pointer": &inf,
		"a map holding NaN": map[string]any{"a": []any{nan}}, "JSON text": json.RawMessage(`1e400`),
	} {
		attributes := map[string]any{"region": "us", "risk": risk}
		for _, expr := range []string{
			`request.attributes.region == "us"`, `request.attributes.region == "eu" && request.attributes.risk > 0.5`,
			`has(request.attributes.region)`, `!has(request.attributes.missing)`, `request.attributes["region"] != "eu"`,
		} {
			if held, evaluated := rbac.EvaluateConditionOf(t, expr, nil, nil, attributes); evaluated {
				t.Errorf("%s of a request whose risk holds %s: held %t", expr, name, held)
			}
		}
		if held, _ := rbac.EvaluateConditionOf(t, `request.time > timestamp(0) && subject.attributes.region == "us"`,
			map[string]any{"region": "us"}, nil, attributes); !held {
			t.Errorf("the time and the subject's attributes beside a request whose risk holds %s: didn't hold", name)
		}
	}
	declares := rbac.Attributes{Subject: map[string]rbac.AttributeType{"region": rbac.AttrString, "risk": rbac.AttrDouble}}
	for expr, want := range map[string]bool{`subject.attributes.region == "us"`: true, `subject.attributes.risk < 0.5`: false} {
		held, evaluated, condition := rbac.EvaluateDeclared(t, declares, expr, map[string]any{"region": "us", "risk": inf})
		if !condition || held != want || evaluated != want {
			t.Errorf("%s of a declared infinite risk: held %t, evaluated %t, a condition %t", expr, held, evaluated, condition)
		}
	}
	// So a grant reading another attribute gives nothing, and a deny applies.
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole) })
	given := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	given.Condition = rbac.Condition{Expression: `request.attributes.region == "us"`}
	h.seed(t, given, grant(cluster.Scope(), "cluster.login", rbac.User, "d"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	ctx := t.Context()
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "risky", Principals: []rbac.Principal{identity("d")}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `request.attributes.region == "eu" && request.attributes.risk > 0.5`},
	}); err != nil {
		t.Fatal(err)
	}
	is := func(id string, risk any) bool {
		t.Helper()
		err := h.authz.Authorize(rbac.WithRequest(ctx, map[string]any{"region": "us", "risk": risk}), h.as(t, id), login, cluster)
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		return err == nil
	}
	for _, id := range []string{"u", "d"} {
		if !is(id, 0.9) {
			t.Fatalf("%s, passing a finite risk, can't log in", id)
		}
		for name, risk := range map[string]any{"NaN": nan, "an infinity": inf, "JSON text": json.RawMessage(`1e400`)} {
			if is(id, risk) {
				t.Errorf("%s, passing a risk of %s, logs in", id, name)
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
		// One holding itself fails every condition reading its kind's attributes, one reading only
		// those beside it too, and the other kinds' are read.
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, attributes); err != nil || evaluated {
			t.Errorf("an attribute beside values holding themselves: evaluated %t, %v", evaluated, err)
		}
		if held, _ := rbac.EvaluateConditionOf(t, `subject.attributes.ok == true`, map[string]any{"ok": true}, attributes, attributes); !held {
			t.Error("the subject's attributes beside a request's holding themselves")
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

// Values holding each other, as a node and its parent, fail every condition reading their kind's
// attributes, whichever a check reaches first. Only the one converting reached again failed, so
// where a holds b and b holds a, a.b or b.a failed by the order the attributes came in, and a
// grant's `has(request.attributes.a.b)` held for one check and not the next.
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
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok && request.attributes.holding.y == 1`, attributes); err != nil || evaluated {
			t.Fatalf("attributes beside values holding each other: evaluated %t, %v", evaluated, err)
		}
		if held, _ := rbac.EvaluateConditionOf(t, `subject.attributes.ok == true`, map[string]any{"ok": true}, nil, attributes); !held {
			t.Fatal("the subject's attributes beside a request's holding each other")
		}
	}
}

// Whether a kind's attributes nest past what a check converts, 10,000 deep, is of the longest path
// through what they hold, whatever order a map's entries come in and wherever a value they share
// was first reached. Kept as first converted, a value reached first near the limit was read cut
// short where it was reached again less deep, so a node of a ring holding itself was read whole,
// and a grant's `has(resource.attributes.node.next)` held, and one nested but a little failed; and
// a value kept whole was read where another path reached it too deep for it.
func TestWhetherAttributesNestTooDeepIsOfTheLongestPathThroughThem(t *testing.T) {
	ring := make([]map[string]any, 20)
	for i := range ring {
		ring[i] = map[string]any{"x": i}
	}
	for i := range ring {
		ring[i]["next"] = ring[(i+1)%len(ring)]
	}
	nests := func(levels int, in any) any {
		for range levels {
			in = []any{in}
		}
		return in
	}
	nested, shared := map[string]any{"a": map[string]any{"b": 1}}, nests(9_000, "x")
	ok := map[string]any{"ok": true}
	for range 20 {
		for name, c := range map[string]struct {
			subject, resource, request map[string]any
			expr                       string
			held                       bool
		}{
			// The request's attributes are converted before the subject's, and those before the
			// resource's.
			"a value reached less deep after a path too deep for it": {
				ok, map[string]any{"v": shared}, map[string]any{"v": nests(1_500, shared)}, `size(resource.attributes.v) == 1`, true,
			},
			"a value too deep where a kind reaches it, beside a path less deep": {
				ok, nil, map[string]any{"short": shared, "long": nests(1_500, shared)}, `size(request.attributes.short) == 1`, false,
			},
			"a node of a ring reached first ten thousand deep": {
				ok, map[string]any{"node": ring[0]}, map[string]any{"ring": nests(10_000-10, ring[0])}, `has(resource.attributes.node.next)`, false,
			},
			"a value nested a little reached first ten thousand deep": {
				ok, map[string]any{"v": nested}, map[string]any{"v": nests(10_000-1, nested)}, `resource.attributes.v.a.b == 1`, true,
			},
			"the subject's beside them": {
				ok, map[string]any{"node": ring[0]}, map[string]any{"short": shared, "long": nests(1_500, shared)}, `subject.attributes.ok == true`, true,
			},
		} {
			if held, evaluated := rbac.EvaluateConditionOf(t, c.expr, c.subject, c.resource, c.request); held != c.held || evaluated != c.held {
				t.Fatalf("%s: %s held %t, evaluated %t", name, c.expr, held, evaluated)
			}
		}
	}
}

// A value many paths reach past what a check converts, 10,000 deep, fails the kind nesting it, and
// the other kinds' attributes are read. Converted again for each path reaching it, a ladder of a
// hundred maps each holding both of the next two went past what a check converts, so every
// condition reading any kind's attributes failed.
func TestAValueManyPathsReachTooDeepFailsOnlyItsKind(t *testing.T) {
	rungs := [2]map[string]any{{"end": 1}, {"end": 2}}
	for range 100 {
		rungs = [2]map[string]any{{"a": rungs[0], "b": rungs[1]}, {"a": rungs[0], "b": rungs[1]}}
	}
	var nested any = rungs[0]
	for range 10_000 - 50 {
		nested = []any{nested}
	}
	ok := map[string]any{"ok": true}
	if held, evaluated := rbac.EvaluateConditionOf(t, `has(resource.attributes.v)`, ok, map[string]any{"v": nested}, ok); held || evaluated {
		t.Errorf("a ladder nested too deep: held %t, evaluated %t", held, evaluated)
	}
	for _, expr := range []string{`subject.attributes.ok == true`, `request.attributes.ok == true`} {
		if held, _ := rbac.EvaluateConditionOf(t, expr, ok, map[string]any{"v": nested}, ok); !held {
			t.Errorf("%s beside a resource nesting a ladder too deep", expr)
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

// typedReflecting is a reflecting whose type makes its own, though it promotes New from the dynamic
// message it embeds.
type typedReflecting struct{ *dynamicpb.Message }

func (m *typedReflecting) Interface() protoreflect.ProtoMessage { return m }
func (m *typedReflecting) ProtoReflect() protoreflect.Message   { return m }
func (m *typedReflecting) Type() protoreflect.MessageType {
	return typedReflectingType{m.Message.Type()}
}

type typedReflectingType struct{ protoreflect.MessageType }

func (t typedReflectingType) New() protoreflect.Message {
	made, _ := t.MessageType.New().(*dynamicpb.Message)
	return &typedReflecting{made}
}

func (t typedReflectingType) Zero() protoreflect.Message {
	made, _ := t.MessageType.Zero().(*dynamicpb.Message)
	return &typedReflecting{made}
}

// reflected is a host's type that is its own reflection by a generated message's it embeds.
type reflected struct{ protoreflect.Message }

func (m *reflected) Interface() protoreflect.ProtoMessage { return m }
func (m *reflected) ProtoReflect() protoreflect.Message   { return m }

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
		held, evaluated, allocated, err := rbac.EvaluateCondition(t, expr, map[string]any{"l": make([]any, 900), "v": v})
		if err != nil || !evaluated || !held {
			t.Errorf("%s: held %t, evaluated %t, %v", name, held, evaluated, err)
		}
		if allocated > 32<<16 {
			t.Errorf("%s read nine hundred times allocated %d bytes", name, allocated)
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

// A nil json.RawMessage is null, as encoding/json writes it, wherever it is held, so the attributes
// beside it are read; it failed its kind's attributes as JSON text that doesn't parse, which an
// empty one, and any other that doesn't parse, still is.
func TestANilJSONTextIsNull(t *testing.T) {
	var none json.RawMessage
	for name, v := range map[string]any{
		"nil": none, "in a list": []json.RawMessage{none}, "in a map": map[string]json.RawMessage{"a": none}, "behind a pointer": &none,
	} {
		attributes := map[string]any{"v": v, "ok": true}
		if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, attributes); err != nil || !held {
			t.Errorf("an attribute beside JSON text %s: held %t, %v", name, held, err)
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `request.attributes.v == null && request.attributes.l == [null]`,
		map[string]any{"v": none, "l": []json.RawMessage{none}}); err != nil || !held {
		t.Errorf("nil JSON text isn't null: held %t, %v", held, err)
	}
	for name, v := range map[string]json.RawMessage{"empty": {}, "cut short": json.RawMessage(`{"a": `)} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"v": v, "ok": true}); err != nil || evaluated {
			t.Errorf("an attribute beside JSON text %s: evaluated %t, %v", name, evaluated, err)
		}
	}
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

// hostMessageType is a message type of the host's own, whose New panics, as code of the host's
// decoding what it can't read can.
type hostMessageType struct{ protoreflect.MessageType }

func (hostMessageType) New() protoreflect.Message {
	panic("rbac_test: a host's message type made a message")
}

// registeringHostType registers a hostMessageType, rbac_test.Host, once for the test binary, as a
// host registers its own.
var registeringHostType = sync.OnceValue(func() error {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("rbac_test/host.proto"), Package: proto.String("rbac_test"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Host")}},
	}, nil)
	if err != nil {
		return err
	}
	return protoregistry.GlobalTypes.RegisterMessage(hostMessageType{dynamicpb.NewMessageType(file.Messages().Get(0))})
})

// wideMessage is a message of the host's own type holding 8 KiB in place, as one of a few hundred
// fields does, and wideMessages one holding a list of them.
type (
	wideMessage  struct{ _ [8 << 10]byte }
	wideMessages struct {
		Items []*wideMessage `protobuf:"bytes,1,rep,name=items"`
	}
)

func (m *wideMessage) ProtoReflect() protoreflect.Message  { return wideTypes()[0].MessageOf(m) }
func (m *wideMessages) ProtoReflect() protoreflect.Message { return wideTypes()[1].MessageOf(m) }

// wideTypes are wideMessage's and wideMessages' types, as generated code makes a message's.
var wideTypes = sync.OnceValue(func() [2]*protoimpl.MessageInfo {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("rbac_test/wide.proto"), Package: proto.String("rbac_test"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Wide")}, {
			Name: proto.String("Wides"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name: proto.String("items"), Number: proto.Int32(1), JsonName: proto.String("items"),
				Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
				Type:  descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: proto.String(".rbac_test.Wide"),
			}},
		}},
	}, nil)
	if err != nil {
		panic(err)
	}
	return [2]*protoimpl.MessageInfo{
		{GoReflectType: reflect.TypeFor[*wideMessage](), Desc: file.Messages().Get(0)},
		{GoReflectType: reflect.TypeFor[*wideMessages](), Desc: file.Messages().Get(1)},
	}
})

// wideReflecting is a host's type that is its own reflection by a wideMessage's it embeds, so it
// makes a wideMessage.
type wideReflecting struct{ protoreflect.Message }

func (m *wideReflecting) Interface() protoreflect.ProtoMessage { return m }
func (m *wideReflecting) ProtoReflect() protoreflect.Message   { return m }

// An Any packing a message of another type than those a condition reads was unpacked through the
// registry, which ran the host's own code for it, its type's New, or a message's own Unmarshal of
// what it packs, outside any condition: one that panicked ended the check. It fails every condition
// reading its kind's attributes, decoding nothing, and the other kinds' are read.
func TestAPackedMessageOfAnotherTypeIsntDecoded(t *testing.T) {
	if err := registeringHostType(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("converting a packed message of the host's type: %v", r)
		}
	}()
	packed := &anypb.Any{TypeUrl: "type.googleapis.com/rbac_test.Host"}
	if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"ok": true, "v": packed}); err != nil || evaluated {
		t.Errorf("an attribute beside a packed message of the host's type: evaluated %t, %v", evaluated, err)
	}
	if held, _ := rbac.EvaluateConditionOf(t, `subject.attributes.ok == true`, map[string]any{"ok": true}, nil, map[string]any{"v": packed}); !held {
		t.Error("the subject's attributes beside a request's packed message of the host's type")
	}
	if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.v != 1`, map[string]any{"v": packed}); err != nil || evaluated {
		t.Errorf("a packed message of the host's type: evaluated %t, %v", evaluated, err)
	}
}

// A check converts what the host passes into CEL's own values, from those Attributes names, and
// reads anything else by no method of its own: CEL read a value of the host's own list, map or
// scalar type by its methods, which could disagree with each other, yield themselves, or panic, a
// list, a map or an optional of CEL's own by the adapter it was made with, which decoded and wrote
// out what it held on each read, and a message other than those it names by merging it. One such
// value, however deep in a kind's attributes, makes them all unreadable: reading the rest left each
// operator to tell what it read from what it couldn't, and `in` found it by its key alone, so a
// deny's `!("v" in request.attributes)` lifted where has() of it failed, as did a loop over the
// map's keys. Every condition reading that kind's attributes fails, one reading only those beside it
// too, and the other kinds' are read.
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
			`!request.attributes.exists(k, k == "v")`, `request.attributes.all(k, k != "v")`,
			`!("v" in request.attributes.map(k, k))`,
		} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"v": v}); err != nil || evaluated {
				t.Errorf("%s of %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
		nested := map[string]any{"ok": true, "m": map[string]any{"a": "a", "l": []any{"a", v}}}
		for _, expr := range []string{
			`request.attributes.ok == true`, `!has(request.attributes.no)`, `"ok" in request.attributes`, `!("no" in request.attributes)`,
			`size(request.attributes) == 2`, `request.attributes.m.a == "a"`, `request.attributes.m.l[0] == "a"`, `"a" in request.attributes.m.l`,
			`size(request.attributes.m.l) == 2`, `request.attributes.exists(k, k == "ok")`, `request.attributes.m.all(k, k != "b")`,
		} {
			if _, evaluated := rbac.EvaluateConditionOf(t, expr, nil, nil, nested); evaluated {
				t.Errorf("%s beside %s: evaluated", expr, name)
			}
		}
		if held, _ := rbac.EvaluateConditionOf(t, `subject.attributes.ok == true && resource.attributes.ok == true`, map[string]any{"ok": true},
			map[string]any{"ok": true}, nested); !held {
			t.Errorf("the other kinds' attributes beside a request holding %s", name)
		}
	}
}

// One value no condition can read, as a struct, deep in a kind's attributes, fails every condition
// reading that kind's, wherever conditions run, one reading only the attributes beside it too: a
// grant's gives nothing and a deny's applies, in a check, a listing of its permissions and a change;
// a requirement isn't met; a label value a condition gives isn't held, on the bare tenant, for a
// check, a holding, Filter or an approver; and the constraints are still asked. A condition
// reading another kind's attributes still decides.
func TestAKindHoldingAValueOutsideTheSetFailsEveryConditionReadingIt(t *testing.T) {
	asked := 0
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog, guardRole)
		c.Constraints = []rbac.Constraint{{Name: "asked", Deny: func(_ context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if in.Subject != nil && in.Subject.Attributes["dept"] == "eng" {
				asked++
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	if _, err := h.pool.Exec(ctx, `CREATE TABLE points (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL, labels text[] NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO points VALUES ('t1', 'p', $1, '{level:high}')`, h.path(t, cluster)); err != nil {
		t.Fatal(err)
	}
	when := func(g rbac.Grant, expr string) rbac.Grant {
		g.Condition = rbac.Condition{Expression: expr}
		return g
	}
	eng := `subject.attributes.dept == "eng"`
	h.hold(t, "owner", "level:high")
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "guardian"), grant(cluster.Scope(), "cluster.login", rbac.User, "denied"),
		when(grant(cluster.Scope(), "cluster.login", rbac.User, "granted"), eng),
		when(grant(cluster.Scope(), "cluster.login", rbac.User, "requested"), `request.attributes.mfa == true`),
		when(grant(cluster.Scope(), "cluster.admin", rbac.User, "handing"), `request.attributes.ticket == "T-1"`),
		grant(cluster.Scope(), "cluster.login", rbac.User, "cleared"), when(grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "cleared"), eng),
		when(grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "approver"), eng))
	owner := h.as(t, "owner")
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "outsiders", Principals: []rbac.Principal{identity("denied")}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `subject.attributes.dept != "eng"`},
	}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []struct {
		on rbac.Resource
		e  rbac.Eligibility
	}{
		{cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: identity("pager"), MaxDuration: time.Hour, Requires: eng}},
		{secret, rbac.Eligibility{Role: "cluster.login", Principal: identity("u"), MaxDuration: time.Hour, Approvers: []rbac.Principal{identity("approver")}}},
	} {
		if err := h.authz.SetEligibility(ctx, owner, e.on, e.e); err != nil {
			t.Fatal(err)
		}
	}
	good := map[string]any{"dept": "eng", "tags": map[string]any{"team": "a"}}
	bad := map[string]any{"dept": "eng", "tags": map[string]any{"team": "a", "badge": struct{}{}}}
	mfa := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	// Handed on under the condition the actor holds its power under.
	handed := rbac.Binding{Role: "cluster.login", Principal: identity("x"), Condition: rbac.Condition{Expression: `request.attributes.ticket == "T-1"`}}
	decides := func(attributes map[string]any, unreadable bool) map[string]bool {
		t.Helper()
		as := func(id string) rbac.Subject {
			s := h.as(t, id)
			s.Attributes = attributes
			return s
		}
		ticket := map[string]any{"ticket": "T-1"}
		if unreadable {
			ticket["badge"] = struct{}{}
		}
		holding, err := h.authz.Holding(ctx, "t1", as("cleared"))
		if err != nil {
			t.Fatal(err)
		}
		pred, err := h.authz.Filter(ctx, as("cleared"), view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "labels"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := h.pool.Query(ctx, `SELECT id FROM points WHERE `+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		var filtered []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			filtered = append(filtered, id)
		}
		rows.Close()
		permissions, err := h.authz.Permissions(ctx, as("granted"), cluster)
		if err != nil {
			t.Fatal(err)
		}
		_, activated := h.authz.Activate(ctx, as("pager"), cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "x"})
		_, approved := h.authz.Activate(ctx, h.as(t, "u"), secret, rbac.Activation{Role: "cluster.login", Duration: time.Minute, Justification: "x", Approver: as("approver")})
		return map[string]bool{
			"a grant":                     h.authz.Authorize(ctx, as("granted"), login, cluster) == nil,
			"a deny":                      h.authz.Authorize(ctx, as("denied"), login, cluster) == nil,
			"Permissions":                 slices.Contains(permissions, login),
			"a requirement":               activated == nil,
			"a label value":               h.authz.Authorize(ctx, as("cleared"), view, secret) == nil,
			"a holding":                   holding.Satisfies(secret.Labels),
			"Filter":                      slices.Equal(filtered, []string{"p"}),
			"an approver's label value":   approved == nil,
			"a change, by the request's":  h.authz.Apply(rbac.WithRequest(ctx, ticket), h.as(t, "handing"), cluster, rbac.Change{Grant: []rbac.Binding{handed}}) == nil,
			"another kind's, the request": h.authz.Authorize(mfa, as("requested"), login, cluster) == nil,
		}
	}
	// Refused first, as an activation, a grant or an approval that holds stays.
	for name, ok := range decides(bad, true) {
		if ok != (name == "another kind's, the request") {
			t.Errorf("%s, of a subject holding a struct: decided %t", name, ok)
		}
	}
	for name, ok := range decides(good, false) {
		if !ok {
			t.Errorf("%s, of a subject the conditions read: refused", name)
		}
	}
	if asked == 0 {
		t.Error("no constraint was asked")
	}
}

// A map of Go's keyed by an interface can hold two keys CEL reads as the same value, as an int and
// an int64 of 1, 1 and 1u, or "a" of two string types: CEL's own map of such keys holds one of them,
// and finding the other finds it. A map holding two fails every condition reading its kind.
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

// JSON text and a message an Any packs can hold a key twice, which each reader picks one of as it
// likes: encoding/json and protobuf read the last, so `{"role": "user", "role": "admin"}` was read as
// "admin" where a host reading the first checked "user", and so was a packed Struct with two entries
// of "role", or a Value setting a Struct twice, which decoding merges, though a map of the host's
// holding two keys read as one fails. Text that isn't UTF-8, or escapes half a surrogate pair, holds
// what encoding/json reads as U+FFFD, so two names of either were read as one too; and a JSON number
// that isn't one, as "0x1p4", was read as what strconv makes of it. Each fails every condition reading
// its kind.
func TestJSONTextOrAPackedMessageHoldingAKeyTwiceFailsItsConditions(t *testing.T) {
	marshaled := func(m proto.Message) []byte {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	field := func(n protowire.Number, b []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, protowire.BytesType), b)
	}
	entry := func(key string, value []byte) []byte {
		return field(1, slices.Concat(field(1, []byte(key)), field(2, value)))
	}
	user, admin := marshaled(structpb.NewStringValue("user")), marshaled(structpb.NewStringValue("admin"))
	twice := slices.Concat(entry("role", user), entry("role", admin))
	packed := func(name string, b []byte) *anypb.Any {
		return &anypb.Any{TypeUrl: "type.googleapis.com/google.protobuf." + name, Value: b}
	}
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1)
	for name, v := range map[string]any{
		"JSON text":              json.RawMessage(`{"role": "user", "role": "admin"}`),
		"JSON text escaping one": json.RawMessage(`{"role": "user", "r\u006fle": "admin"}`),
		"JSON text, deep":        json.RawMessage(`[{"a": {"role": "user", "b": [], "role": "admin"}}]`),
		"JSON text naming bytes that aren't UTF-8":   json.RawMessage("{\"\xff\": \"user\", \"\xfe\": \"admin\"}"),
		"JSON text holding bytes that aren't UTF-8":  json.RawMessage("{\"role\": \"\xff\"}"),
		"JSON text naming halves of surrogate pairs": json.RawMessage(`{"\ud800": "user", "\udc00": "admin"}`),
		"JSON text holding half a surrogate pair":    json.RawMessage(`["\ud83d", "x"]`),
		"JSON text holding a pair reversed":          json.RawMessage(`["\ude00\ud83d"]`),
		"JSON text of two values":                    json.RawMessage(`{"role": "user"} {"role": "admin"}`),
		"JSON text closing once more":                json.RawMessage(`{"role": "admin"}}`),
		"a packed Struct":                            packed("Struct", twice),
		"a packed Struct, deep":                      packed("ListValue", field(1, field(5, twice))),
		"a packed Value setting a Struct twice":      packed("Value", slices.Concat(field(5, entry("role", user)), field(5, entry("role", admin)))),
		"a packed Value set twice":                   packed("Value", slices.Concat(field(3, []byte("admin")), protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.VarintType), 1))),
		"a packed wrapper set twice":                 packed("StringValue", slices.Concat(field(1, []byte("user")), field(1, []byte("admin")))),
		"a packed entry keyed twice":                 packed("Struct", field(1, slices.Concat(field(1, []byte("x")), field(1, []byte("role")), field(2, admin)))),
	} {
		for _, expr := range []string{`request.attributes.ok == true`, `request.attributes.v.role == "admin"`} {
			if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"ok": true, "v": v}); err != nil || evaluated {
				t.Errorf("%s beside %s: evaluated %t, %v", expr, name, evaluated, err)
			}
		}
	}
	for _, n := range []string{"0x1p4", "Inf", "NaN", "+1", "01", "1.", ".5", "1e", "-", "", " 1", "1_0", "1e+"} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"ok": true, "n": json.Number(n)}); err != nil || evaluated {
			t.Errorf("an attribute beside the JSON number %q: evaluated %t, %v", n, evaluated, err)
		}
	}
	once, err := anypb.New(&structpb.Struct{Fields: map[string]*structpb.Value{
		"role": structpb.NewStringValue("admin"), "Role": structpb.NewStringValue("user"),
		"l": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
			"role": structpb.NewStringValue("admin"),
		}})}}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		expr string
		v    any
	}{
		"JSON text naming two in two cases":                      {`request.attributes.v.role == "admin" && request.attributes.v.Role == "user"`, json.RawMessage(`{"role": "admin", "Role": "user"}`)},
		"JSON text naming one in two objects":                    {`request.attributes.v.a.r == 1 && request.attributes.v.b.r == 2`, json.RawMessage(`{"a": {"r": 1}, "b": {"r": 2}}`)},
		"JSON text escaping a surrogate pair":                    {`request.attributes.v == ["\U0001F600", "\uFFFD", "\uFFFD"]`, json.RawMessage(`["\ud83d\ude00", "\ufffd", "�"]`)},
		"a packed Struct":                                        {`request.attributes.v.role == "admin" && request.attributes.v.l[0].role == "admin"`, once},
		"a packed Struct of a field unknown":                     {`request.attributes.v.role == "admin"`, packed("Struct", slices.Concat(unknown, entry("role", admin), unknown))},
		"a packed Struct setting its field in another wire type": {`request.attributes.v.role == "admin"`, packed("Struct", slices.Concat(protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1), entry("role", admin)))},
		"JSON numbers":                                           {`request.attributes.v == [1, 0, 1500.0, 0.25, -0.01]`, []json.Number{"1", "-0", "1.5e3", "0.25", "-1E-2"}},
	} {
		if held, _, _, err := rbac.EvaluateCondition(t, c.expr, map[string]any{"v": c.v}); err != nil || !held {
			t.Errorf("%s: held %t, %v", name, held, err)
		}
	}
}

// JSON text nested deeper than encoding/json parses, 10,000 deep, fails its kind's conditions, and is
// parsed no deeper: built without jsonv2 (GOEXPERIMENT=nojsonv2), encoding/json's decoder counts no
// depth of the brackets and braces it returns as tokens, so objects nested 79,000 deep were parsed
// whole, allocating 48 MB, and lists 159,000 deep 20 MB, where json.Unmarshal refused either at
// once. Text a little less deep is read.
func TestJSONTextNestedPastWhatEncodingJSONParsesIsParsedNoDeeper(t *testing.T) {
	nested := func(opening, inner, closing string, n int) json.RawMessage {
		return json.RawMessage(strings.Repeat(opening, n) + inner + strings.Repeat(closing, n))
	}
	for name, text := range map[string]json.RawMessage{
		"lists just past it": nested("[", "", "]", 10_001), "lists": nested("[", "", "]", 159_000),
		"objects": nested(`{"a":`, "1", "}", 79_000),
	} {
		if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"ok": true, "j": text}); err != nil || evaluated {
			t.Errorf("an attribute beside JSON text of %s nested deep: evaluated %t, %v", name, evaluated, err)
		}
		if allocated, _ := rbac.Converting(t, map[string]any{"j": text}); allocated > 12<<20 {
			t.Errorf("converting JSON text of %s nested deep allocated %d MB", name, allocated>>20)
		}
	}
	if held, _, _, err := rbac.EvaluateCondition(t, `size(request.attributes.j) == 1`, map[string]any{"j": nested("[", "", "]", 9_998)}); err != nil || !held {
		t.Errorf("JSON text of lists nested 9,998 deep: held %t, %v", held, err)
	}
}

// Attributes no condition reads are each one value, whichever kind's they are, so a condition
// hashing them, as a map literal keyed by them or `in` a map, read the subject's and the request's
// as one where both were, as every kind's are past what a check converts: there,
// `request.attributes in {subject.attributes: true}` held, and a deny guarded by its negation lifted.
// A comparison or `in` a list reading a list or map that holds them, a key, an index and a loop over
// a map's keys fail too, as reading them by name does, wherever they are.
func TestAttributesNoConditionReadsFailWhereverAConditionHashesOrComparesThem(t *testing.T) {
	readable := map[string]map[string]any{"subject": {"x": 1}, "request": {"risk": 9}}
	for kinds, unreadable := range map[string]map[string]map[string]any{
		"each holding a struct":        {"subject": {"x": struct{}{}}, "request": {"risk": 9, "x": struct{}{}}},
		"past what a check converts":   {"subject": {"x": 1}, "request": {"risk": 9, "l": make([]int, rbac.MaxConverted)}},
		"the request's holding struct": {"subject": {"x": 1}, "request": {"risk": 9, "x": struct{}{}}},
	} {
		for _, c := range []struct {
			expr      string
			evaluated bool
		}{
			{`!(request.attributes in {subject.attributes: true}) && request.attributes.risk > 5`, true},
			{`request.attributes in {subject.attributes: true}`, true},
			{`size({request.attributes: 1, subject.attributes: 2}) == 1`, true},
			{`{request.attributes: 1}.all(k, true)`, true},
			{`[subject.attributes].exists(m, request.attributes in {m: 1})`, true},
			{`{true ? request.attributes : 1: 1}.size() == 1`, true},
			{`request.attributes in {"risk": 1}`, true},
			{`[request.attributes] in {[subject.attributes]: true}`, true},
			{`{[request.attributes]: 1} == {[subject.attributes]: 1}`, true},
			{`[request.attributes, 1] == [subject.attributes, 2]`, true},
			{`{"a": request.attributes, "b": 1} != {"a": subject.attributes, "b": 2}`, true},
			{`1 in [request.attributes, 1]`, true},
			{`{dyn([request.attributes]): 1}.exists(k, k[0] in {"risk": 1})`, true},
			{`size({dyn(request.attributes): 1, dyn(subject.attributes): 2}) == 1`, true},
			{`size({"n": {request.attributes: 1, subject.attributes: 2}}["n"]) == 1`, true},
			{`(true ? request.attributes : {}) in {(true ? subject.attributes : {}): 1}`, true},
			{`[request.attributes, subject.attributes].map(x, {x: 1}).exists(m, subject.attributes in m)`, true},
			{`[request.attributes, subject.attributes].exists_one(x, x in {subject.attributes: 1})`, true},
			{`request.attributes in [subject.attributes] || {} in [request.attributes]`, true},
			{`{"risk": 1}[request.attributes] == 1`, false},
			{`dyn({"risk": 1})[dyn(request.attributes)] == 1`, false},
		} {
			if _, evaluated := rbac.EvaluateConditionOf(t, c.expr, readable["subject"], nil, readable["request"]); evaluated != c.evaluated {
				t.Errorf("%s of attributes a condition reads: evaluated %t", c.expr, evaluated)
			}
			if _, evaluated := rbac.EvaluateConditionOf(t, c.expr, unreadable["subject"], nil, unreadable["request"]); evaluated {
				t.Errorf("%s of attributes %s: evaluated", c.expr, kinds)
			}
		}
	}
}

// A kind's attributes no condition can read whole, as where one holds a struct, and those
// declarations refuse in part, as where a declared int is passed as a string, are each a value no
// operator reads, and fail alike whatever reads them whole: comparing them, finding them or in
// them, size(), a macro, and a list or a map holding them, as building one fails, and the subject,
// the resource or the request holding them read whole. Built, a list or a map holding them was
// decided without them where its size or another value it held decided, as comparing read only the
// smaller value whole: `[subject.attributes] != []`, size(), has() and a loop over it held, and
// `[subject.attributes, 1] == [{}, 2]` failed for a kind no condition can read but was false for one
// refused in part, which is larger; and read whole, `subject != {"kind": "user"}` held. Read by
// name, a kind refused in part reads the names declarations pass. type(), which reads no value, and
// `||` or `&&` that the other side decides, are what they are of any value in their place.
func TestAttributesNoConditionReadsFailWhateverHoldsThem(t *testing.T) {
	declares := rbac.Attributes{Subject: map[string]rbac.AttributeType{"team": rbac.AttrString, "level": rbac.AttrInt}}
	readable := map[string]any{"team": "a", "level": 1}
	whole := map[string]any{"team": "a", "level": 1, "badge": struct{ X int }{1}}
	inPart := map[string]any{"team": "a", "level": "one"}
	for _, expr := range []string{
		`[subject.attributes] != []`, `[subject.attributes] == [{}]`, `[subject.attributes, 1] == [{}, 2]`,
		`[subject.attributes, 1] == [{}, 2, 3]`, `size([subject.attributes]) == 1`, `[subject.attributes].exists(x, true)`,
		`has({"a": subject.attributes}.a)`, `{"a": subject.attributes} == {"a": {}}`,
		`{"a": subject.attributes, "b": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"} != {"a": {}, "b": "y"}`,
		`subject.attributes == {}`, `subject.attributes != {}`, `"team" in subject.attributes`, `!("team" in subject.attributes)`,
		`subject.attributes in []`, `subject.attributes.all(k, false)`, `subject.attributes.exists(k, true)`,
		`size(subject.attributes) == 2`, `dyn(subject.attributes) == dyn(request.attributes)`, `subject.attributes in [request.attributes]`,
		`[subject.attributes] in [[request.attributes]]`, `{subject.attributes: 1} != {}`, `{[subject.attributes]: 1} != {}`,
		`size({[subject.attributes]: 1, [request.attributes]: 2}) == 2`, `(true ? subject.attributes : {}) == {}`,
		`[subject.attributes].map(x, 1) == [1]`, `[subject.attributes].filter(x, true).size() == 1`, `[subject.attributes][0] == {}`,
		`[[subject.attributes]] != [[]]`, `[subject.attributes, "x"] in [[{}, "y"]]`, `[1].map(x, subject.attributes).size() == 1`,
		`[1].map(x, {"a": subject.attributes}).size() == 1`, `subject != {"kind": "user"}`, `subject == subject`, `size(subject) == 3`,
		`subject.exists(k, k == "id")`, `"id" in subject`, `[subject] != []`, `{"s": subject}.s.id == "u"`, `subject in [resource]`,
	} {
		if _, evaluated := rbac.EvaluateConditionOf(t, expr, readable, nil, nil); !evaluated {
			t.Errorf("%s of attributes a condition reads: failed", expr)
		}
		if held, evaluated := rbac.EvaluateConditionOf(t, expr, whole, nil, nil); evaluated {
			t.Errorf("%s of attributes no condition reads whole: held %t", expr, held)
		}
		if held, evaluated, condition := rbac.EvaluateDeclared(t, declares, expr, inPart); evaluated {
			t.Errorf("%s of attributes declarations refuse in part: held %t, a condition %t", expr, held, condition)
		}
	}
	for _, c := range []struct {
		expr          string
		inPart, whole bool
	}{
		{`subject.attributes.team == "a"`, true, false},
		{`has(subject.attributes.team)`, true, false},
		{`[1, 2].exists(i, subject.attributes.team == "a")`, true, false},
		{`[subject.attributes.team] == ["a"]`, true, false},
		{`subject.attributes.level == 1`, false, false},
		{`has(subject.attributes.level)`, false, false},
		{`!has(subject.attributes.level)`, false, false},
		{`type(subject.attributes) == map`, true, true},
		{`type(subject) == type(resource)`, true, true},
		{`subject.attributes.level > 0 || true`, true, true},
		{`has(subject.attributes)`, true, true},
		{`subject.id == "u" && subject.kind == "user"`, true, true},
		{`resource.type == "cluster"`, true, true},
	} {
		if held, evaluated, condition := rbac.EvaluateDeclared(t, declares, c.expr, inPart); !condition || held != c.inPart || evaluated != c.inPart {
			t.Errorf("%s of attributes declarations refuse in part: held %t, evaluated %t, a condition %t", c.expr, held, evaluated, condition)
		}
		if held, evaluated := rbac.EvaluateConditionOf(t, c.expr, whole, nil, nil); held != c.whole || evaluated != c.whole {
			t.Errorf("%s of attributes no condition reads whole: held %t, evaluated %t", c.expr, held, evaluated)
		}
	}
	// So a grant reading them so gives nothing, and a deny applies.
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole) })
	given := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	given.Condition = rbac.Condition{Expression: `[subject.attributes] != []`}
	h.seed(t, given, grant(cluster.Scope(), "cluster.login", rbac.User, "d"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	ctx := t.Context()
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "sized", Principals: []rbac.Principal{identity("d")}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `size([subject.attributes]) != 1`},
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"u", "d"} {
		s := h.as(t, id)
		if !allowed(t, h, s, login, cluster) {
			t.Fatalf("%s, passing attributes a condition reads, can't log in", id)
		}
		s.Attributes = whole
		if allowed(t, h, s, login, cluster) {
			t.Errorf("%s, passing attributes no condition reads whole, logs in", id)
		}
	}
}

// A map literal naming a key twice is built holding the value named last, so attributes no
// condition can read, or a double that isn't finite, named before it were dropped unread:
// `{"a": subject.attributes, "a": 1}.a == 1` held where `{"a": 1, "a": subject.attributes}.a == 1`
// failed, deciding by which was built last, and so did one whose keys are the same only as it runs,
// as `{subject.id: subject.attributes, "u": 1}`. One naming a key twice fails, as a map the host
// passes holding two keys read as one does.
func TestAMapLiteralNamingAKeyTwiceFails(t *testing.T) {
	whole := map[string]any{"badge": struct{ X int }{1}}
	for _, expr := range []string{
		`{"a": subject.attributes, "a": 1}.a == 1`, `{"a": 1, "a": subject.attributes}.a == 1`,
		`{subject.id: subject.attributes, "u": 1} == {"u": 1}`, `{subject.kind: subject, "user": 1}.user == 1`,
		`{"a": 0.0 / 0.0, "a": 1.0} == {"a": 1.0}`, `{"a": 1, "a": 2}.a == 2`,
	} {
		for name, subject := range map[string]map[string]any{"a condition reads": {"team": "a"}, "no condition reads whole": whole} {
			if held, evaluated := rbac.EvaluateConditionOf(t, expr, subject, nil, nil); evaluated {
				t.Errorf("%s of attributes %s: held %t", expr, name, held)
			}
		}
	}
	for _, expr := range []string{`{"a": 1, "b": 2}.a == 1`, `{subject.id: 1, "v": 2}[subject.id] == 1`, `{1: "a", 2: "b"}.size() == 2`} {
		if held, _ := rbac.EvaluateConditionOf(t, expr, nil, nil, nil); !held {
			t.Errorf("%s: didn't hold", expr)
		}
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
// each took the check as long as decoding a mebibyte did, and a kind's attributes were gathered
// into a map made for as many as the host passed, a million taking 80 MB.
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
	// A kind passing none reads none past it either, where a test of an attribute's absence would hold.
	for _, expr := range []string{`size(subject.attributes) == 0`, `size(resource.attributes) == 0`} {
		if held, evaluated := rbac.EvaluateConditionOf(t, expr, nil, nil, map[string]any{"l": make([]int, rbac.MaxConverted)}); held || evaluated {
			t.Errorf("%s beside a request past what a check converts: held %t, evaluated %t", expr, held, evaluated)
		}
	}
	// A kind's own map, as the host passes it, too.
	many := make(map[string]any, 1<<20)
	for i := range 1 << 20 {
		many[fmt.Sprint(i)] = true
	}
	if allocated, over := rbac.Converting(t, many); !over || allocated > 16<<20 {
		t.Errorf("a million attributes: past what a check converts %t, allocated %d bytes", over, allocated)
	}
}

// Whether a check's attributes fit what it converts, and which kinds it can read, turns on no
// order, of the kinds or of a map's entries, but where a value nests past what it converts, 10,000
// deep: JSON text was parsed only where it might hold no more values than were left, which it
// counted by its brackets, commas and colons, more than it holds where it is invalid, holds an
// empty list or object, or a key twice. So `[]` beside a string just fitting what a check converts
// failed every kind's attributes where the string was converted first, and not where the text was,
// and a call converting the subject's attributes before the resource's, rather than after, read
// them where it failed them before.
func TestWhetherAttributesFitTurnsOnNoOrder(t *testing.T) {
	// A kind's map costs what building one does, a string's name and value two, and a tenth of its
	// length, and `[]`'s name, text and list two, what a slice of bytes costs past its one, and what
	// building a list costs.
	exact := func(kinds int) string {
		return strings.Repeat("x", 10*(rbac.MaxConverted-kinds*rbac.MapCost-4-(rbac.BytesCost-1)-rbac.ListCost))
	}
	empty := json.RawMessage("[]")
	if held, _ := rbac.EvaluateConditionOf(t, `has(subject.attributes.s) && size(resource.attributes.j) == 0`,
		map[string]any{"s": exact(2)}, map[string]any{"j": empty}, nil); !held {
		t.Error("the resource's empty JSON list after the subject's string, just fitting what a check converts")
	}
	for range 50 {
		if held, _ := rbac.EvaluateConditionOf(t, `has(request.attributes.s) && size(request.attributes.j) == 0`,
			nil, nil, map[string]any{"s": exact(1), "j": empty}); !held {
			t.Fatal("a request's empty JSON list beside its string, just fitting what a check converts")
		}
	}
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 31))
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	for trial := range 20 {
		shared := drawnShared(rng, false)
		kinds := [3]map[string]any{drawnAttributes(rng, shared, false), drawnAttributes(rng, shared, false), drawnAttributes(rng, shared, false)}
		// Half the time, invalid JSON text of many commas in one kind, and in another a list taking
		// about what the text leaves of what a check converts, so they fit together but the text may
		// hold more than the list leaves.
		if rng.IntN(2) == 0 {
			commas := rbac.MaxConverted/4 + rng.IntN(rbac.MaxConverted/4)
			text, list := rng.IntN(3), rng.IntN(3)
			kinds[text]["text"] = json.RawMessage(strings.Repeat(",", commas))
			kinds[list]["list"] = make([]int, rbac.MaxConverted-commas/10-rng.IntN(commas))
		}
		var first []bool
		var firstOver bool
		for i, o := range orders {
			read, over := rbac.ConvertedInOrder(t, kinds[o[0]], kinds[o[1]], kinds[o[2]])
			inOrder := make([]bool, 3)
			for j, k := range o {
				inOrder[k] = read[j] && !over
			}
			if i == 0 {
				first, firstOver = inOrder, over
				continue
			}
			if over != firstOver || !slices.Equal(inOrder, first) {
				t.Fatalf("trial %d: in order %v, read %v and over %t; in order %v, read %v and over %t", trial, orders[0], first, firstOver, o, inOrder, over)
			}
		}
	}
}

// What a check reads of each kind's attributes is what a check alone reads, however many checks of
// its call converted the subject's and the request's before it, and which kinds it reads is what
// converting all three at once would read, the resource's sharing none of the others' values: it
// counts the subject's and the request's, converted once for the call, as its own, a value they
// share once, and its resource's apart, and past what a check converts it reads none, the
// resource's though it passes none. A hook of the host's that drops the subject's between checks
// changes nothing they read, as the call reads them as it first converted them, and no check knows
// a value by where one the call converted before was, so none made where a dropped one was is
// read as converted from it.
func TestAChecksAttributesAreAsConvertedAloneWhateverItsCallConvertedBefore(t *testing.T) {
	for trial := range 10 {
		// Drawn from the trial's own seed, so a failing trial draws alike when run again.
		rng := rand.New(rand.NewPCG(uint64(trial), 37))
		sharedSeed := rng.Uint64()
		shared := drawnShared(rand.New(rand.NewPCG(sharedSeed, 0)), true)
		// Shared by the kinds that hold it, about what a check converts, so a check counting it
		// otherwise, or not counting what was converted before it, reads what converting them doesn't.
		big := make([]int, []int{rbac.MaxConverted / 3, rbac.MaxConverted/2 + 1000, rbac.MaxConverted - 1000}[rng.IntN(3)])
		request := drawnAttributes(rng, shared, true)
		if rng.IntN(2) == 0 {
			request["big"] = big
		}
		ctx := rbac.WithRequest(t.Context(), request)
		subjectSeed, resourceSeed := rng.Uint64(), rng.Uint64()
		// The subject's attributes as the host passes them, with values of its own in a map and a list
		// of types of the host's own, which drop drops, as a hook might.
		passed := func() (subject map[string]any, drop func()) {
			rng := rand.New(rand.NewPCG(subjectSeed, 0))
			subject = drawnAttributes(rng, shared, true)
			switch rng.IntN(4) {
			case 0:
				subject["big"] = big
			case 1:
				subject["own"] = make([]int, rbac.MaxConverted/2+1000)
			}
			byName, listed := map[string]map[string]any{}, make([]*map[string]any, 20)
			for i := range 20 {
				byName[fmt.Sprint(i)] = map[string]any{"by": "subject", "i": i}
				listed[i] = &map[string]any{"by": "subject", "i": i}
			}
			subject["byName"], subject["listed"] = byName, listed
			return subject, func() {
				clear(byName)
				clear(listed)
				subject["a0"] = struct{}{}
				runtime.GC()
			}
		}
		// The resource of each check, of shared and big, made as it is asked for, after what a hook
		// dropped before it.
		resourceOf := func(i int, shared []any, big []int) map[string]any {
			rng := rand.New(rand.NewPCG(resourceSeed, uint64(i)))
			if rng.IntN(5) == 0 {
				return nil
			}
			attributes := drawnAttributes(rng, shared, true)
			if rng.IntN(2) == 0 {
				attributes["big"] = big
			}
			many := make([]any, 200)
			for j := range many {
				many[j] = map[string]any{"by": "resource", "i": j}
			}
			attributes["many"] = many
			return attributes
		}
		resource := func(i int) map[string]any { return resourceOf(i, shared, big) }
		subject, drop := passed()
		together, alone := rbac.AttributesRead(t, 4, func(i int) (context.Context, map[string]any, map[string]any) {
			return ctx, subject, resource(i)
		}, func(i int) {
			if i == 2 {
				drop()
			}
		})
		for i := range together {
			for k, kind := range []string{"subject", "resource", "request"} {
				if together[i][k] != alone[i][k] {
					got, want := differing(together[i][k], alone[i][k])
					t.Fatalf("trial %d, check %d: the %s's attributes read\n%s\nwhere alone\n%s", trial, i, kind, got, want)
				}
			}
			// The kinds converted at once, in the order a check converts them, the resource's made again
			// of values of its own, sharing none of the others', as a check converts its resource's
			// apart. A copy of it (DeepCopy) is nil where it is past what a check converts, where the
			// check, converting it whole, is past it too.
			passing, _ := passed()
			apart := resourceOf(i, drawnShared(rand.New(rand.NewPCG(sharedSeed, 0)), true), make([]int, len(big)))
			read, over := rbac.ConvertedInOrder(t, request, passing, apart)
			for k, j := range []int{2, 0, 1} {
				if unread := alone[i][j] == rbac.Unreadable; unread != (over || !read[k]) {
					t.Fatalf("trial %d, check %d: the %s's attributes unreadable %t, where converted at once %t, past what a check converts %t",
						trial, i, []string{"request", "subject", "resource"}[k], unread, !read[k], over)
				}
			}
		}
	}
}

// A call shares what it converted of a subject's and a request's attributes only with checks of
// the same: by a subject passing the same map, on a request passing the same, or none, as an
// approver's label values are decided on. So two subjects, or one with a request and without, as
// one activating and its approver are, are each read as passed, a nil map as an empty one, and a
// check after the host changes a map it passed reads it as the call first converted it.
func TestACallSharesWhatItConvertedOnlyWithChecksOfTheSame(t *testing.T) {
	plain := t.Context()
	asked, other := rbac.WithRequest(plain, map[string]any{"site": "hq"}), rbac.WithRequest(plain, map[string]any{"site": "remote"})
	ops, dev := map[string]any{"team": "ops"}, map[string]any{"team": "dev"}
	checks := []struct {
		ctx     context.Context
		subject map[string]any
	}{
		{asked, ops},
		{asked, dev},
		{other, ops},
		{plain, ops},
		{rbac.WithoutRequest(asked), ops},
		{rbac.WithoutRequest(plain), ops},
		{rbac.WithRequest(plain, nil), ops},
		{rbac.WithRequest(plain, map[string]any{}), ops},
		{asked, nil},
		{asked, map[string]any{}},
		{rbac.WithoutRequest(plain), nil},
		{plain, nil},
		{asked, ops},
	}
	together, alone := rbac.AttributesRead(t, len(checks), func(i int) (context.Context, map[string]any, map[string]any) {
		return checks[i].ctx, checks[i].subject, map[string]any{"i": i}
	}, func(i int) {
		if i == len(checks)-1 {
			ops["team"] = "changed"
		}
	})
	for i := range checks {
		if together[i] != alone[i] {
			t.Errorf("check %d read %q, where alone %q", i, together[i], alone[i])
		}
	}
}

// What converting decodes, JSON text and packed messages, is kept while its converter knows it by
// where it points: freed once converted, the request's JSON text was where the subject's, decoded
// after it, was decoded, and a condition reading the subject's read the request's, and so for a
// packed message.
func TestWhatOneKindDecodesIsNeverReadAsAnothers(t *testing.T) {
	rbac.CollectBetweenKinds(t)
	packing := func(s string) *anypb.Any {
		v, err := structpb.NewStruct(map[string]any{"k": s})
		if err != nil {
			t.Fatal(err)
		}
		a, err := anypb.New(v)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	for i := range 50 {
		kinds := map[string]map[string]any{}
		for _, kind := range []string{"subject", "resource", "request"} {
			text := fmt.Sprintf("%s%d", kind, i)
			kinds[kind] = map[string]any{"j": json.RawMessage(`{"k": "` + text + `"}`), "p": packing(text)}
		}
		for _, kind := range []string{"subject", "resource", "request"} {
			expr := fmt.Sprintf(`%[1]s.attributes.j.k == "%[1]s%[2]d" && %[1]s.attributes.p.k == "%[1]s%[2]d"`, kind, i)
			if held, evaluated := rbac.EvaluateConditionOf(t, expr, kinds["subject"], kinds["resource"], kinds["request"]); !held {
				t.Fatalf("%s: held %t, evaluated %t", expr, held, evaluated)
			}
		}
	}
}

// No value converting knows by where it points is read as another, wherever one was freed before
// another was made: a map, of a type of the host's own too, a slice, empty or nil too, an array of
// them, a pointer, to nothing too, which Go may give one address, JSON text and what converting
// decodes of it, and a Struct, a ListValue, a Value and an Any and what it packs. Garbage is
// collected before each kind is converted, and between checks, after a hook of the host's empties
// every map and list the subject's and the request's attributes held once the call converted them,
// so nothing the host holds keeps what they held, and each check's resource is made after.
func TestNoValueConvertedIsReadAsAnother(t *testing.T) {
	rbac.CollectBetweenKinds(t)
	for trial := range 5 {
		subject, dropSubject := heldShapes(t, "subject", trial)
		request, dropRequest := heldShapes(t, "request", trial)
		ctx := rbac.WithRequest(t.Context(), request)
		together, alone := rbac.AttributesRead(t, 6, func(i int) (context.Context, map[string]any, map[string]any) {
			resource, _ := heldShapes(t, "resource", 100*trial+i)
			return ctx, subject, resource
		}, func(i int) {
			if i == 1 {
				dropSubject()
				dropRequest()
			}
			runtime.GC()
		})
		for i := range together {
			for k, kind := range []string{"subject", "resource", "request"} {
				if alone[i][k] == rbac.Unreadable {
					t.Fatalf("trial %d, check %d: the %s's attributes unreadable alone", trial, i, kind)
				}
				if together[i][k] != alone[i][k] {
					got, want := differing(together[i][k], alone[i][k])
					t.Fatalf("trial %d, check %d: the %s's attributes read\n%s\nwhere alone\n%s", trial, i, kind, got, want)
				}
			}
		}
	}
}

// heldShapes are attributes holding, by, values of each shape a converter knows by where it points,
// telling by and i apart, a few of each, and drop, which empties every map and list they hold, as a
// hook of the host's might, so that nothing the host holds keeps what they held.
func heldShapes(t *testing.T, by string, i int) (attributes map[string]any, drop func()) {
	t.Helper()
	tag := map[string]int{"subject": 1, "resource": 2, "request": 3}[by]
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	var drops []func()
	shapes := func(j int) map[string]any {
		n, s := tag*1000+j, fmt.Sprint(by, i, j)
		a, b := n, n+1
		// Many of a type of the host's own, each of whose entries is read into the same value.
		maps, pointers, slices := map[string]map[string]int{}, map[string]*[4]int{}, map[string][]int{}
		listed, lists := make([]*[4]int, 64), make([][]any, 64)
		for k := range 64 {
			maps[fmt.Sprint(k)], pointers[fmt.Sprint(k)], slices[fmt.Sprint(k)] = map[string]int{s: k}, &[4]int{tag, i, j, k}, []int{tag, i, j, k}
			listed[k], lists[k] = &[4]int{tag, i, j, k}, []any{s, k}
		}
		list, m := []any{s, n}, map[string]any{"by": s}
		arrays, spare := [][2]*int{{&a, &b}}, append(make([]any, 0, 8), s, n)
		st, err := structpb.NewStruct(map[string]any{"by": s, "l": []any{s, float64(n)}})
		must(err)
		lv, err := structpb.NewList([]any{s, map[string]any{"by": s}})
		must(err)
		packed, err := structpb.NewStruct(map[string]any{"by": s})
		must(err)
		packedStruct, err := anypb.New(packed)
		must(err)
		packedList, err := structpb.NewList([]any{s, float64(n)})
		must(err)
		packedValue, err := anypb.New(structpb.NewListValue(packedList))
		must(err)
		valued, err := structpb.NewStruct(map[string]any{"by": s})
		must(err)
		shaped := map[string]any{
			"map":      map[string]any{"by": s, "n": n},
			"maps":     maps,
			"pointers": pointers,
			"slices":   slices,
			"pointer":  &[4]int{tag, i, j},
			"int":      &a,
			"string":   &s,
			"list":     []any{s, n},
			"listed":   listed,
			"lists":    lists,
			"array":    [2]map[string]any{{"by": s}, {"n": n}},
			"arrays":   arrays,
			"toList":   &list,
			"toMap":    &m,
			"spare":    spare,
			"text":     json.RawMessage(fmt.Sprintf(`{"by": %q, "l": [%d, {"by": %q}, [%q]]}`, s, n, s, s)),
			"struct":   st,
			"listV":    lv,
			"value":    structpb.NewStructValue(valued),
			"packed":   packedStruct,
			"packedV":  packedValue,
			"zero":     &[0]int{},
			"zeros":    [][0]int{{}, {}},
			"empty":    []any{},
			"capped":   make([]any, 0, 4),
			"nil":      []any(nil),
			"nilMap":   map[string]any(nil),
		}
		drops = append(drops, func() {
			clear(maps)
			clear(pointers)
			clear(slices)
			clear(listed)
			clear(lists)
			clear(list)
			clear(m)
			clear(arrays)
			clear(spare[:cap(spare)])
			clear(st.GetFields())
			clear(lv.GetValues())
			clear(valued.GetFields())
			clear(shaped)
		})
		return shaped
	}
	held := map[string]any{}
	for j := range 4 {
		held[fmt.Sprint(j)] = shapes(j)
	}
	return map[string]any{"held": held}, func() {
		for _, drop := range drops {
			drop()
		}
		clear(held)
	}
}

// differing is where a and b, written out, first differ, and a little before.
func differing(a, b string) (string, string) {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	from := max(i-200, 0)
	return a[from:min(i+300, len(a))], b[from:min(i+300, len(b))]
}

// drawnShared are values a test's kinds' attributes share, drawn from rng (drawnValue), and with
// deep, a value nested past what a check converts.
func drawnShared(rng *rand.Rand, deep bool) []any {
	cyclic := map[string]any{"x": 1}
	cyclic["self"] = cyclic
	shared := []any{
		make([]int, drawnSize(rng)), drawnValue(rng, nil, 0, deep), drawnValue(rng, nil, 0, deep), cyclic,
		json.RawMessage(`{"a": [1, 2, {"b": "c"}]}`),
		map[string]map[string]any{"x": {"y": 1}, "z": {"y": 2}},
	}
	if deep {
		var nested any = "x"
		for range 10_001 {
			nested = []any{nested}
		}
		shared = append(shared, nested)
	}
	return shared
}

// drawnAttributes are a kind's attributes drawn from rng: a few values, some of them shared.
func drawnAttributes(rng *rand.Rand, shared []any, deep bool) map[string]any {
	out := map[string]any{}
	for i := range rng.IntN(4) {
		out[fmt.Sprint("a", i)] = drawnValue(rng, shared, 0, deep)
	}
	return out
}

// drawnSize is a size of a value drawn from rng, a few or a part of what a check converts.
func drawnSize(rng *rand.Rand) int {
	return []int{0, 1, 7, 1000, rbac.MaxConverted / 8, rbac.MaxConverted / 4, rbac.MaxConverted / 3, rbac.MaxConverted / 2}[rng.IntN(8)]
}

// drawnValue is a value of a shape a host passes drawn from rng, as deep as depth, of shared too, and
// with deep, nested past what a check converts.
func drawnValue(rng *rand.Rand, shared []any, depth int, deep bool) any {
	n := drawnSize(rng)
	switch rng.IntN(16) {
	case 0, 1:
		if len(shared) > 0 {
			return shared[rng.IntN(len(shared))]
		}
		return rng.IntN(10)
	case 2:
		return strings.Repeat("s", 10*n)
	case 3:
		return make([]int, n)
	case 4:
		return json.RawMessage("[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]")
	case 5:
		return json.RawMessage([]string{"[]", "{}", `[[], {}, []]`, `{"a": 1, "a": 2}`, `[1e400]`, ""}[rng.IntN(6)])
	case 6:
		return json.RawMessage(strings.Repeat(",", n))
	case 7:
		return struct{}{}
	case 8:
		if depth < 3 {
			m := map[string]any{}
			for i := range rng.IntN(4) {
				m[fmt.Sprint("m", i)] = drawnValue(rng, shared, depth+1, deep)
			}
			return m
		}
		return true
	case 9:
		if depth < 3 {
			l := make([]any, rng.IntN(4))
			for i := range l {
				l[i] = drawnValue(rng, shared, depth+1, deep)
			}
			return l
		}
		return 1.5
	case 10:
		return map[string]map[string]any{"a": {"b": rng.IntN(3)}, "c": {"d": "e"}}
	case 11:
		return []*[]any{{"x"}, {rng.IntN(3)}}
	case 12:
		return []any{nil, math.NaN(), time.Unix(int64(rng.IntN(1000)), 0), time.Duration(rng.IntN(1000)), []byte("bytes")}
	case 13:
		v, _ := structpb.NewList([]any{"a", 1.0, map[string]any{"b": true}})
		return v
	case 14:
		if deep {
			var nested any = rng.IntN(3)
			for range 10_000 - rng.IntN(3) {
				nested = []any{nested}
			}
			return nested
		}
		return map[int]string{1: "one"}
	default:
		return map[any]int{1: 1, uint(2): 2, "3": 3, true: 4}
	}
}

// Decoding what a host passes reads more than a check charged for it: parsing a JSON number reads it
// whole, and copies it into its error where it isn't one, but one that wasn't was charged one, so a
// thousand sharing a mebibyte took seconds; finding a packed message's type hashes its URL whole,
// charged nothing; and JSON text or a packed message of a mebibyte holding more values than a check
// may convert, as a list of zeros, were decoded whole, taking a tenth of a second and 80 MB, before
// converting found them past it. A value of a type whose name is long, as a struct of many fields,
// was named in its error whole, though charged one, and so was a map keyed by one, or of them.
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
	named := reflect.StructOf(fields)
	keyed, held, twice := make([]any, 5000), make([]any, 5000), make([]any, 5000)
	for i := range keyed {
		keyed[i] = reflect.MakeMap(reflect.MapOf(named, reflect.TypeFor[int]())).Interface()
		held[i] = map[any]int{reflect.Zero(named).Interface(): 1}
		m := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[any](), named))
		m.SetMapIndex(reflect.ValueOf(any(1)), reflect.Zero(named))
		m.SetMapIndex(reflect.ValueOf(any(uint(1))), reflect.Zero(named))
		twice[i] = m.Interface()
	}
	for name, v := range map[string]any{
		"values of a long-named type": reflect.MakeSlice(reflect.SliceOf(named), 5000, 5000).Interface(), "maps keyed by one": keyed,
		"maps keyed by an interface holding one": held, "maps of them holding two keys read as one": twice,
	} {
		if allocated, over := rbac.Converting(t, map[string]any{"v": v}); over || allocated > 16<<20 {
			t.Errorf("%s: past what a check converts %t, allocated %d bytes", name, over, allocated)
		}
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

// Converting a value costs a check, and copying it a hook, what building it does, counted alike
// (MapCost): each map, Struct and JSON object was charged one, as a number is, though it allocates
// several times, so 160,000 empty maps took a check 93 ms to convert and a hook 83 ms to copy, where
// as many ints took 12 ms and 6 ms, and a check of a resource whose user-written tags held 156,000
// empty maps 108 ms; and each JSON text and slice of bytes was charged one and a tenth of its
// length, though converting a text made a json.Decoder and a copy keeps each slice apart, so a
// check took 80 ms to convert 79,000 texts of a byte, and a hook 76 ms to copy 150,000 slices of a
// byte. Timed, a unit now takes 20 to 145 ns to convert and 25 to 360 ns to copy, whatever holds
// it, where reading one in a condition takes 70 to 145. What each allocates stands in for the time
// here, as -race and a slower machine change neither: no unit charged allocates more
// than a few times what one of a string does, by count or by bytes. Converting an empty map made
// room for one of its values, charged 8, so 19,000 empty maps of a type of 64 KiB took 1.4 GB and
// 270 ms to convert, where as many maps of ints took 10 MB and 15 ms.
func TestConvertingOrCopyingAValueCostsWhatBuildingItDoes(t *testing.T) {
	const n = 2000
	listed := func(made func(i int) any) map[string]any {
		l := make([]any, n)
		for i := range l {
			l[i] = made(i)
		}
		return map[string]any{"l": l}
	}
	text := func(each func(i int) string) map[string]any {
		var b strings.Builder
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(each(i))
		}
		return map[string]any{"l": json.RawMessage("[" + b.String() + "]")}
	}
	// The least of a few, as another goroutine can allocate meanwhile.
	least := func(work func(map[string]any) rbac.Work, attributes map[string]any) rbac.Work {
		w := work(attributes)
		for range 2 {
			if again := work(attributes); again.Allocations < w.Allocations {
				w = again
			}
		}
		return w
	}
	strs := least(rbac.ConvertingWork, listed(func(i int) any { return strconv.Itoa(i) }))
	allocations, bytes := float64(strs.Allocations)/float64(strs.Charged), float64(strs.Bytes)/float64(strs.Charged)
	for name, attributes := range map[string]map[string]any{
		"ints":                             listed(func(i int) any { return i + 1000 }),
		"lists":                            listed(func(i int) any { return []any{i} }),
		"empty lists":                      listed(func(int) any { return make([]any, 0, 1) }),
		"maps":                             listed(func(i int) any { return map[string]any{"a": i} }),
		"empty maps":                       listed(func(int) any { return map[string]any{} }),
		"empty maps of an array of 64 KiB": listed(func(int) any { return map[string][8 << 10]int64{} }),
		"pointers":                         listed(func(i int) any { return &i }),
		"Structs": listed(func(i int) any {
			return &structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewNumberValue(float64(i))}}
		}),
		"empty Structs": listed(func(int) any { return &structpb.Struct{} }),
		"ListValues": listed(func(i int) any {
			return &structpb.ListValue{Values: []*structpb.Value{structpb.NewNumberValue(float64(i))}}
		}),
		"empty ListValues":        listed(func(int) any { return &structpb.ListValue{} }),
		"Values":                  listed(func(i int) any { return structpb.NewStringValue(strconv.Itoa(i)) }),
		"timestamps":              listed(func(i int) any { return timestamppb.New(time.Unix(int64(i), 0)) }),
		"wrappers":                listed(func(i int) any { return wrapperspb.Int64(int64(i)) }),
		"JSON objects":            text(func(int) string { return "{}" }),
		"JSON objects of a value": text(func(i int) string { return fmt.Sprintf(`{"a":%d}`, i) }),
		"JSON lists":              text(func(i int) string { return fmt.Sprintf("[%d]", i) }),
		"JSON texts":              listed(func(i int) any { return json.RawMessage(strconv.Itoa(i)) }),
		"slices of bytes":         listed(func(i int) any { return []byte{byte(i)} }),
	} {
		for doing, work := range map[string]func(map[string]any) rbac.Work{"converting": rbac.ConvertingWork, "copying": rbac.CopyingWork} {
			w := least(work, attributes)
			if !w.Done {
				t.Fatalf("%s %d %s: not done, charging %d", doing, n, name, w.Charged)
			}
			if a, b := float64(w.Allocations)/float64(w.Charged), float64(w.Bytes)/float64(w.Charged); a > 2.5*allocations || b > 5*bytes {
				t.Errorf("%s %d %s allocated %.2f times and %.0f bytes for each unit charged, where converting strings allocates %.2f times "+
					"and %.0f bytes", doing, n, name, a, b, allocations, bytes)
			}
		}
	}
	// A struct no condition reads is refused whatever it holds, but converting a map of them read
	// each entry into one value, moving it whole, charged two, and a hook's copy set a struct holding
	// a map whole, its unexported fields too, charged one, and moved each of a slice's elements whole
	// before copying it: converting a map of 2,000 structs of 64 KiB took 7 ms, charged 4,017, and
	// copying a slice of 2,000 holding a map and 64 KiB took 38 ms, charged 4,013. Converting refuses
	// a map of them unread, and copying charges a struct the bytes it moves, as it charges one holding
	// no map, so neither allocates more for each unit charged than for a string. Converting made room
	// for a value of a map's type in an empty map too, and copied each value of the host's own
	// saying it is one of CEL's, which it refuses, charged one: it makes no room in an empty map,
	// refuses those by their type, unread, and charges each of a map's entries at least what its
	// value holds in place, which reading the entry moves.
	type hidden struct {
		M map[string]int
		_ [64 << 10]byte
	}
	type wide struct{ X [64 << 10]byte }
	widely := map[string]wide{}
	// A copy shares a map's keys, but reading an entry moves its key whole, and setting it hashes it:
	// copying 2,000 keyed by arrays of 4 KiB took 8 ms, charged 4,017.
	arrayKeyed := map[[4 << 10]byte]int{}
	for i := range n {
		widely[strconv.Itoa(i)] = wide{}
		var k [4 << 10]byte
		k[0], k[1] = byte(i), byte(i>>8)
		arrayKeyed[k] = i
	}
	// Maps whose values lie past what a condition reads, each moved to be found so.
	deep := listed(func(int) any { return map[string][1 << 10]float64{"a": {}} })["l"]
	for range 10_000 - 2 {
		deep = []any{deep}
	}
	// A dynamic message's field holds the host's own reflections, each of whose types makes a
	// message of 8 KiB, which a copy makes in its place: charged by the host's type, of 16 bytes,
	// copying them allocated 2 KB for each unit charged.
	reflections := dynamicpb.NewMessage(wideTypes()[1].Desc)
	items := reflections.Mutable(reflections.Descriptor().Fields().ByName("items")).List()
	for range n {
		items.Append(protoreflect.ValueOfMessage(&wideReflecting{(&wideMessage{}).ProtoReflect()}))
	}
	for name, attributes := range map[string]map[string]any{
		"a dynamic message holding the host's own reflections":   {"m": reflections},
		"maps of a struct of 64 KiB":                             listed(func(int) any { return map[string]wide{"a": {}} }),
		"empty maps of a struct of 64 KiB":                       listed(func(int) any { return map[string]wide{} }),
		"arrays of 8 KiB of the host's saying they are doubles":  {"l": make([]wideDouble, n)},
		"maps of an array of 8 KiB of the host's":                listed(func(int) any { return map[string]wideDouble{"a": {}} }),
		"maps of an array of 8 KiB nested past 10,000 deep":      {"l": deep},
		"a map of structs of 64 KiB":                             {"m": widely},
		"maps of a struct holding a map and 64 KiB":              listed(func(int) any { return map[string]hidden{"a": {}} }),
		"structs holding a map and 64 KiB":                       listed(func(int) any { return hidden{} }),
		"pointers to a struct holding a map and 64 KiB":          listed(func(int) any { return &hidden{} }),
		"slices of a struct holding a map and 64 KiB":            listed(func(int) any { return []hidden{{}} }),
		"arrays of two structs holding a map and 64 KiB":         listed(func(int) any { return [2]hidden{} }),
		"slices of arrays of two holding a map and 64 KiB":       listed(func(int) any { return [][2]hidden{{}} }),
		"maps of arrays of two structs holding a map and 64 KiB": listed(func(int) any { return map[string][2]hidden{"a": {}} }),
		"a map keyed by arrays of 4 KiB":                         {"m": arrayKeyed},
		"messages of the host's of 8 KiB":                        listed(func(int) any { return &wideMessage{} }),
		"a message of the host's holding nil ones of 8 KiB":      {"m": &wideMessages{Items: make([]*wideMessage, n)}},
		"the host's own reflections making messages of 8 KiB":    listed(func(int) any { return &wideReflecting{(&wideMessage{}).ProtoReflect()} }),
	} {
		for doing, work := range map[string]func(map[string]any) rbac.Work{"converting": rbac.ConvertingWork, "copying": rbac.CopyingWork} {
			w := least(work, attributes)
			if a, b := float64(w.Allocations)/float64(w.Charged), float64(w.Bytes)/float64(w.Charged); a > 2.5*allocations || b > 5*bytes {
				t.Errorf("%s %s allocated %.2f times and %.0f bytes for each unit charged, where converting strings allocates %.2f times "+
					"and %.0f bytes", doing, name, a, b, allocations, bytes)
			}
		}
	}
	// A copy reads a map's entry, moving its key and its value whole, before it copies them, so it
	// charges what they hold in place first: one holding a struct of 4 MiB, past what a copy holds,
	// moved it only to find so, and one holding an array of 4 MiB allocated 12 MB; and it moves a
	// slice's elements before it copies each, so 2,000 arrays of 4,096 interfaces, 125 MiB, past what
	// a copy holds, allocated 133 MB. Nor does it make room for what a pointer points to, or an array
	// whole, before it finds what they hold in place fits, nor make the zero value of one it finds
	// past what a copy holds to set in its place: a pointer to an array of 128 MiB allocated 268 MB,
	// an array of two structs each holding a map beside 64 MiB 335 MB, and a struct holding a map
	// beside 4 MiB 4 MB, each only to be found past it.
	type huge struct{ X [4 << 20]byte }
	type heavy struct {
		M map[string]int
		_ [4 << 20]byte
	}
	for name, attributes := range map[string]map[string]any{
		"a map holding a struct of 4 MiB":                         {"m": map[string]huge{"a": {}}},
		"a map holding an array of 4 MiB":                         {"m": map[string][4 << 20]byte{"a": {}}},
		"a map holding an array of 4 MiB of any":                  {"m": map[string][256 << 10]any{"a": {}}},
		"a list of 2,000 arrays of 4,096 interfaces":              {"l": make([][4 << 10]any, 2000)},
		"a pointer to an array of 4 MiB":                          {"p": new([4 << 20]byte)},
		"a struct holding a map beside 4 MiB":                     {"s": heavy{}},
		"an array of two structs each holding a map beside 4 MiB": {"a": [2]heavy{}},
	} {
		if w := rbac.CopyingWork(attributes); w.Done || w.Bytes > 1<<20 {
			t.Errorf("copying %s copied it %t, allocating %d bytes", name, w.Done, w.Bytes)
		}
	}
	// Nor does it read a map's entry where what the entries before it held left less than its value
	// holds in place: one of two arrays of 100,000 interfaces, past what a copy holds once the other
	// was copied, was read, 1.6 MB, only to be found so. The other is read, copied and set, three
	// times its bytes.
	type wideAny [100_000]any
	if w := rbac.CopyingWork(map[string]any{"m": map[string]wideAny{"a": {}, "b": {}}}); w.Done || w.Bytes > 7*uint64(reflect.TypeFor[wideAny]().Size())/2 {
		t.Errorf("copying a map of two arrays of 100,000 interfaces copied it %t, allocating %d bytes", w.Done, w.Bytes)
	}
	// A copy charges a struct's padding too, which moving it moves, so it reserves for a value no more
	// than copying the value costs: uncounted, an array of 60,000 structs of a bool, each padded to 16
	// bytes, cost 6,000, where 40,000 were reserved for a pointer to it, so a copy reaching it after a
	// string past 30,000 was refused, and one reaching it first wasn't.
	type padded struct {
		A bool
		_ [0]int64
	}
	spaced, long := &struct{ X [60_000]padded }{}, strings.Repeat("s", 1_300_000)
	_, first := rbac.CopyingCharge(map[string]any{"l": []any{spaced, long}})
	if _, after := rbac.CopyingCharge(map[string]any{"l": []any{long, spaced}}); first != after {
		t.Errorf("a copy reaching an array of padded structs first copied it %t, and after a long string %t", first, after)
	}
	// Converting reads a map's entries into one value it makes room for, which reading each moves
	// whole, so it makes none where what the map's values hold in place costs more than is left: it
	// checked one for each, and a map holding an array of 4 MiB allocated 4 MB.
	for name, attributes := range map[string]map[string]any{
		"a map holding an array of 4 MiB":        {"m": map[string][4 << 20]byte{"a": {}}},
		"a map holding an array of 4 MiB of any": {"m": map[string][256 << 10]any{"a": {}}},
	} {
		if w := rbac.ConvertingWork(attributes); w.Done || w.Bytes > 1<<20 {
			t.Errorf("converting %s read it %t, allocating %d bytes", name, w.Done, w.Bytes)
		}
	}
}

// JSON text is read as encoding/json reads it into an any, where a condition can read it at all:
// converting parses it itself, as a json.Decoder made for each text, and read a token at a time,
// took a microsecond for a text of one byte. Texts drawn at random are read so, each naming a
// member of an object once, and a text a byte or three from one is read so too or refused, a
// number to its bits: compared by reflect.DeepEqual, -0 read as 0 passed, which a condition tells
// apart, as string() does.
func TestJSONTextIsReadAsEncodingJSONReadsIt(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	bytes := []byte(" \t\n\r[]{},:\"\\/-+.0123456789eEtrufalsnbu\x00\x01\x7f\xc3\xa9\xff")
	for i := range 50_000 {
		var b strings.Builder
		jsonDraw(rng, 4, &b)
		text, whole := []byte(b.String()), i%2 == 0
		for j := 0; !whole && j < rng.IntN(3)+1; j++ {
			switch at := rng.IntN(len(text) + 1); {
			case at == len(text):
				text = append(text, bytes[rng.IntN(len(bytes))])
			case rng.IntN(2) == 0:
				text = append(text[:at], text[at+1:]...)
			default:
				text[at] = bytes[rng.IntN(len(bytes))]
			}
		}
		read, ok := rbac.ParseJSON(text)
		var want any
		err := json.Unmarshal(text, &want)
		if ok && (err != nil || !sameJSON(read, want)) || !ok && whole {
			t.Fatalf("%q read %t as %#v, where encoding/json reads %#v, %v", text, ok, read, want, err)
		}
	}
}

// Text a fuzzer writes, where a condition can read it, is read as encoding/json reads it: any it
// reads otherwise, or that encoding/json refuses, a condition would read as a value the host
// doesn't.
func FuzzJSONTextIsReadAsEncodingJSONReadsIt(f *testing.F) {
	for _, text := range []string{
		``, ` `, `0`, `-0`, `01`, `1.`, `.1`, `+1`, `0x10`, `1e`, `1E+2`, `1e400`, `1e-400`, `123456789012345678901234567890`,
		`4.9e-324`, `NaN`, `-`, `true`, `tru`, `truex`, `null`, `""`, `"\"\\\/\b\f\n\r\t"`, `"\u00e9\uD83D\ude00"`, `"\ud83d"`,
		`"\ude00\ud83d"`, `"\ud83d\u0041"`, `"\u0000"`, `"\x41"`, "\"\x00\"", "\"\x7f\"", "\"\xff\"", "\"\xed\xa0\x80\"",
		"\xef\xbb\xbf1", "\f1", `[]`, `{}`, `[1,]`, `[1 2]`, `{"a":1,}`, `{"a":1,"\u0061":2}`, `[1] [2]`, `[[]`, "[1]\x00",
		` {"a": [true, false, null, -1.5e3, "b"], "": {}} `,
	} {
		f.Add([]byte(text))
	}
	f.Fuzz(func(t *testing.T, text []byte) {
		read, ok := rbac.ParseJSON(text)
		var want any
		if err := json.Unmarshal(text, &want); ok && (err != nil || !sameJSON(read, want)) {
			t.Fatalf("%q read as %#v, where encoding/json reads %#v, %v", text, read, want, err)
		}
	})
}

// sameJSON reports whether a and b, read from JSON text into an any, are the same value, a number
// to its bits, as reflect.DeepEqual finds -0 and 0 equal.
func sameJSON(a, b any) bool {
	switch a := a.(type) {
	case float64:
		b, ok := b.(float64)
		return ok && math.Float64bits(a) == math.Float64bits(b)
	case []any:
		b, ok := b.([]any)
		return ok && (a == nil) == (b == nil) && slices.EqualFunc(a, b, sameJSON)
	case map[string]any:
		b, ok := b.(map[string]any)
		return ok && (a == nil) == (b == nil) && maps.EqualFunc(a, b, sameJSON)
	}
	return reflect.DeepEqual(a, b)
}

// jsonNumbers and jsonCharacters are what jsonDraw writes numbers and strings of.
var (
	jsonNumbers    = []string{"0", "-0", "7", "-12", "1.5", "-1.25e-3", "1E+2", "123456789012345678901234567890", "1e308", "5e-324", "0.1"}
	jsonCharacters = []string{
		"a", "é", "日本", "😀", " ", "\x7f", `\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\u0041`, `\u00E9`, `\ud83d\ude00`, `\u0000`, `\uFFFF`,
	}
)

// jsonDraw writes JSON text of values nested no more than depth deep, with whitespace around them.
func jsonDraw(rng *rand.Rand, depth int, b *strings.Builder) {
	space := func() {
		for range rng.IntN(3) {
			b.WriteByte(" \t\n\r"[rng.IntN(4)])
		}
	}
	space()
	switch k := rng.IntN(10); {
	case k == 0:
		b.WriteString([]string{"true", "false", "null"}[rng.IntN(3)])
	case k < 3:
		b.WriteString(jsonNumbers[rng.IntN(len(jsonNumbers))])
	case k < 7 || depth == 0:
		b.WriteByte('"')
		for range rng.IntN(5) {
			b.WriteString(jsonCharacters[rng.IntN(len(jsonCharacters))])
		}
		b.WriteByte('"')
	case k < 9:
		b.WriteByte('[')
		for i := range rng.IntN(4) {
			if i > 0 {
				b.WriteByte(',')
			}
			jsonDraw(rng, depth-1, b)
		}
		space()
		b.WriteByte(']')
	default:
		b.WriteByte('{')
		names := []string{"a", "b", "", "é", `k\n`}
		rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
		for i := range rng.IntN(4) {
			if i > 0 {
				b.WriteByte(',')
			}
			space()
			b.WriteString(`"` + names[i] + `"`)
			space()
			b.WriteByte(':')
			jsonDraw(rng, depth-1, b)
		}
		space()
		b.WriteByte('}')
	}
	space()
}

// Converting one of CEL's own values reads none of its type's methods, nor does converting a value
// of a type without methods: told one of CEL's by reflection's Implements, which reads them, a list
// of CEL's strings, and a map keyed by them, took a check three times what Go's did, charged alike;
// timed against Go's, CEL's took 2.8 times as long once on a loaded machine, though read so. A type
// of the host's own with methods is asked about, as a value, a map's key and a map's type, and its
// values once for the type: asked of each, converting the host's messages, which no condition reads,
// took four times what converting a list does.
func TestConvertingCELsOwnValuesReadsNoMethodsOfTheirTypes(t *testing.T) {
	read := rbac.CountMethodsRead(t)
	cels := []any{
		types.String("a"), types.Bytes("b"), types.Bytes(nil), types.Double(1.5), types.Int(-1), types.Uint(2), types.True, types.NullValue,
		types.Timestamp{Time: time.Unix(1, 0)},
		types.Duration{Duration: time.Second},
	}
	for name, attributes := range map[string]map[string]any{
		"CEL's own values": {"l": cels, "s": []types.String{"a"}, "m": map[string]types.Int{"a": 1}},
		"maps keyed by CEL's own values": {
			"s": map[types.String]int{"a": 1}, "i": map[types.Int]types.String{1: "a"}, "b": map[types.Bool]int{true: 1},
			"u": map[types.Uint]int{2: 1}, "a": map[any]any{types.String("k"): types.Int(1), types.Int(2): 1},
		},
		"Go's own values": {
			"s": "a", "i": 1, "l": []any{1.5, true, uint8(2), []byte("b"), [1]byte{}, json.RawMessage(`{"a": [1]}`)},
			"m": map[string]any{"a": time.Second, "t": time.Unix(1, 0)}, "k": map[int]bool{1: true}, "p": new(int),
		},
	} {
		*read = 0
		if _, ok := rbac.ConvertingCharge(attributes); !ok || *read != 0 {
			t.Errorf("%s: read %t, the methods of their types read %d times", name, ok, *read)
		}
	}
	for name, attributes := range map[string]map[string]any{
		"a value": {"v": stringer("a")}, "a map's key": {"m": map[any]int{stringer("a"): 1}}, "a map's type": {"m": map[stringer]int{}},
	} {
		*read = 0
		if _, ok := rbac.ConvertingCharge(attributes); !ok || *read == 0 {
			t.Errorf("%s of a type with methods: read %t, the methods of its type read %d times", name, ok, *read)
		}
	}
	strs, messages := make([]stringer, 1000), make([]*wideMessage, 1000)
	for i := range messages {
		messages[i] = &wideMessage{}
	}
	*read = 0
	if rbac.ConvertingCharge(map[string]any{"s": strs, "m": messages}); *read > 10 {
		t.Errorf("1,000 strings of the host's type and 1,000 messages of the host's: the methods of their types read %d times", *read)
	}
}

// stringer is a host's own string type with a method, which conditions read as a string.
type stringer string

func (s stringer) String() string { return string(s) }

// Converting a value, or copying it for a hook, allocates no more for each unit it charges than a
// few times what converting a string does, whatever types the host passes: nothing is made, read or
// moved whole before what it holds in place is charged, nor made once either is past what it may
// spend. Values of types drawn by reflection, arrays narrow and wide, structs, pointers, slices and
// maps of them, interfaces holding them, and the host's own types and messages, nested in one
// another, many of one type, empty, nil or full, and some of a mebibyte or more, each allocate
// within that, slices of bytes and JSON text among them: charged as one value and a tenth of its
// length, parsing a short text made a decoder, 950 bytes, and a copy kept each short slice apart,
// 290 bytes.
func TestConvertingOrCopyingAValueOfAnyTypeAllocatesWhatItCharges(t *testing.T) {
	l := make([]any, 2000)
	for i := range l {
		l[i] = strconv.Itoa(i)
	}
	// The least of a few, as another goroutine can allocate meanwhile.
	least := func(work func(map[string]any) rbac.Work, attributes map[string]any) rbac.Work {
		w := work(attributes)
		for range 2 {
			if again := work(attributes); again.Bytes < w.Bytes {
				w = again
			}
		}
		return w
	}
	strs := least(rbac.ConvertingWork, map[string]any{"l": l})
	bytes := float64(strs.Bytes) / float64(strs.Charged)
	within := func(drawn string, attributes map[string]any, of string) {
		t.Helper()
		for doing, work := range map[string]func(map[string]any) rbac.Work{"converting": rbac.ConvertingWork, "copying": rbac.CopyingWork} {
			// A few kibibytes a kind, made whatever it holds.
			if w := least(work, attributes); float64(w.Bytes) > 5*bytes*float64(w.Charged)+(16<<10) {
				t.Errorf("%s: %s %s allocated %d bytes, charged %d, %.0f for each unit, where converting strings allocates %.0f",
					drawn, doing, of, w.Bytes, w.Charged, float64(w.Bytes)/float64(w.Charged), bytes)
			}
		}
	}
	for seed := range uint64(160) {
		d := &typeDraw{rng: rand.New(rand.NewPCG(seed, 127)), empty: int(seed % 4), most: 64 << 10, all: 4 << 20}
		if seed%8 == 7 {
			d.most, d.all = 48<<20, 48<<20
		}
		attributes, of := d.attributes()
		within(fmt.Sprint("seed ", seed), attributes, of)
	}
	// And 2,000 of each type drawn alone, which a type holding few among others may not show.
	for i, typ := range drawnTypes {
		d := &typeDraw{rng: rand.New(rand.NewPCG(uint64(i), 127)), most: 64 << 10, all: 4 << 20}
		attributes, of := d.many(typ, 2000)
		within(fmt.Sprint("type ", i), attributes, of)
	}
}

// typeDraw draws types a host may pass, by reflection, and values of them: Go's and the host's own
// scalars, times, bytes, JSON text, interfaces, the host's own messages and the well-known ones,
// and arrays, structs, pointers, slices and maps of them, nested.
type typeDraw struct {
	rng *rand.Rand
	// empty is how often, in sixths, a map, slice, pointer or interface drawn holds nothing.
	empty int
	// most is the most a type drawn holds in place, all about the most the values attributes draws
	// hold together, past which what they hold is empty, and held what those drawn hold, in bytes.
	most, all, held uintptr
}

var drawnTypes = []reflect.Type{
	reflect.TypeFor[int64](), reflect.TypeFor[string](), reflect.TypeFor[bool](), reflect.TypeFor[float64](),
	reflect.TypeFor[uint8](), reflect.TypeFor[int32](), reflect.TypeFor[time.Time](), reflect.TypeFor[any](),
	reflect.TypeFor[hostDouble](), reflect.TypeFor[wideDouble](), reflect.TypeFor[hostString](), reflect.TypeFor[intByte](),
	reflect.TypeFor[types.String](), reflect.TypeFor[*structpb.Struct](),
	reflect.TypeFor[*timestamppb.Timestamp](), reflect.TypeFor[*descriptorpb.FileOptions](), reflect.TypeFor[*wideMessage](),
	reflect.TypeFor[[]byte](), reflect.TypeFor[json.RawMessage](),
}

// drawnTexts are the JSON texts typeDraw draws, short, as a value of each kind takes.
var drawnTexts = []string{`1`, `-2.5e3`, `"s"`, `true`, `null`, `[]`, `{}`, ` [1, "a"] `, `{"a": {}}`, `"\u00e9"`}

// attributes are many values of one type drawn, in a list, a slice or a map of their type, or a few
// where it is wide, and what they are.
func (d *typeDraw) attributes() (map[string]any, string) {
	t := d.typ(3)
	return d.many(t, d.rng.IntN(2000)+1)
}

// many are n values of t, or as many as d.all holds, in a list, a slice or a map of t, and what
// they are.
func (d *typeDraw) many(t reflect.Type, n int) (map[string]any, string) {
	n = min(n, int(d.all/max(t.Size(), 1)))
	switch d.rng.IntN(3) {
	case 0:
		l := make([]any, n)
		for i := range l {
			l[i] = d.value(t, 3).Interface()
		}
		return map[string]any{"l": l}, fmt.Sprintf("a list of %d %v", n, t)
	case 1:
		l := reflect.MakeSlice(reflect.SliceOf(t), n, n)
		for i := range n {
			l.Index(i).Set(d.value(t, 3))
		}
		return map[string]any{"l": l.Interface()}, fmt.Sprintf("a slice of %d %v", n, t)
	default:
		m := reflect.MakeMapWithSize(reflect.MapOf(reflect.TypeFor[string](), t), n)
		for i := range n {
			m.SetMapIndex(reflect.ValueOf(strconv.Itoa(i)), d.value(t, 3))
		}
		return map[string]any{"m": m.Interface()}, fmt.Sprintf("a map of %d %v", n, t)
	}
}

// typ is a type nesting no more than depth deep, holding no more than d.most in place.
func (d *typeDraw) typ(depth int) reflect.Type {
	for {
		if t := d.draw(depth); t.Size() <= d.most {
			return t
		}
	}
}

func (d *typeDraw) draw(depth int) reflect.Type {
	if depth <= 0 {
		return drawnTypes[d.rng.IntN(len(drawnTypes))]
	}
	switch d.rng.IntN(14) {
	case 0, 1:
		return drawnTypes[d.rng.IntN(len(drawnTypes))]
	case 2:
		return reflect.ArrayOf([]int{0, 1, 2, 16}[d.rng.IntN(4)], d.typ(depth-1))
	case 3, 12, 13:
		// Wide, of anything but bytes, or of bytes.
		e := []reflect.Type{drawnTypes[d.rng.IntN(len(drawnTypes))], reflect.TypeFor[uint8]()}[d.rng.IntN(2)]
		return reflect.ArrayOf(d.rng.IntN(int(d.most/max(e.Size(), 1))+1), e)
	case 4, 5:
		fields := make([]reflect.StructField, d.rng.IntN(3)+1)
		for i := range fields {
			fields[i] = reflect.StructField{Name: fmt.Sprint("F", i), Type: d.typ(depth - 1)}
		}
		return reflect.StructOf(fields)
	case 6, 7:
		return reflect.PointerTo(d.typ(depth - 1))
	case 8, 9:
		return reflect.SliceOf(d.typ(depth - 1))
	default:
		key := []reflect.Type{reflect.TypeFor[string](), reflect.TypeFor[int64](), reflect.TypeFor[any]()}[d.rng.IntN(3)]
		return reflect.MapOf(key, d.typ(depth-1))
	}
}

// value is a value of t, holding values nested no more than depth deep.
func (d *typeDraw) value(t reflect.Type, depth int) reflect.Value {
	v := reflect.New(t).Elem()
	d.held += t.Size()
	empty := d.rng.IntN(6) < d.empty || depth <= 0 || d.held > d.all
	if t == reflect.TypeFor[json.RawMessage]() {
		if !empty {
			v.SetBytes([]byte(drawnTexts[d.rng.IntN(len(drawnTexts))]))
		}
		return v
	}
	switch t.Kind() {
	case reflect.Bool:
		v.SetBool(d.rng.IntN(2) == 0)
	case reflect.Int32, reflect.Int64:
		v.SetInt(int64(d.rng.IntN(1000)))
	case reflect.Uint8:
		v.SetUint(uint64(d.rng.IntN(256)))
	case reflect.Float64:
		v.SetFloat(d.rng.Float64())
	case reflect.String:
		v.SetString(strings.Repeat("s", d.rng.IntN(100)))
	case reflect.Interface:
		// One a host's type implements holds none, as the types drawn may not.
		if !empty && t.NumMethod() == 0 {
			v.Set(d.value(d.typ(depth-1), depth-1))
		}
	case reflect.Struct:
		if t == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Unix(int64(d.rng.IntN(1000)), 0)))
			break
		}
		for i := range t.NumField() {
			if f := v.Field(i); f.CanSet() {
				f.Set(d.value(t.Field(i).Type, depth-1))
			}
		}
	case reflect.Array:
		for range min(t.Len(), 4) {
			v.Index(d.rng.IntN(t.Len())).Set(d.value(t.Elem(), depth-1))
		}
	case reflect.Pointer:
		if !empty {
			v.Set(reflect.New(t.Elem()))
			v.Elem().Set(d.value(t.Elem(), depth-1))
		}
	case reflect.Slice:
		if d.rng.IntN(2) == 0 && empty {
			break
		}
		n := 0
		if !empty {
			n = d.rng.IntN(4) + 1
		}
		v.Set(reflect.MakeSlice(t, n, n))
		for i := range n {
			v.Index(i).Set(d.value(t.Elem(), depth-1))
		}
	case reflect.Map:
		if d.rng.IntN(2) == 0 && empty {
			break
		}
		v.Set(reflect.MakeMap(t))
		for i := range d.rng.IntN(4) + 1 {
			if empty {
				break
			}
			key := reflect.New(t.Key()).Elem()
			switch t.Key().Kind() {
			case reflect.String:
				key.SetString(strconv.Itoa(i))
			case reflect.Int64:
				key.SetInt(int64(i))
			default:
				key.Set(reflect.ValueOf(strconv.Itoa(i)))
			}
			v.SetMapIndex(key, d.value(t.Elem(), depth-1))
		}
	default:
	}
	return v
}

// A copy sets each of a map's keys in a map of its own, which hashes the key whole: the strings an
// array or a struct key holds, and what the interfaces it holds hold, as well as its bytes in place.
// Charged those bytes alone, 50 entries keyed by structs each holding a string of 1 MiB took 1.4 ms
// to copy, charged 167. Each such key costs at least what the string or the array it holds costs
// as a key of its own.
func TestCopyingAMapChargesWhatHashingItsKeysReads(t *testing.T) {
	type text struct{ S string }
	type held struct{ A any }
	// keyed is a map of 100 entries keyed by key's values, as a key of type t.
	keyed := func(t reflect.Type, key func(i int) any) map[string]any {
		m := reflect.MakeMap(reflect.MapOf(t, reflect.TypeFor[int]()))
		for i := range 100 {
			m.SetMapIndex(reflect.ValueOf(key(i)), reflect.ValueOf(i))
		}
		return map[string]any{"m": m.Interface()}
	}
	long := func(i int) string { return fmt.Sprintf("%01024d", i) }
	array := func(i int) (a [1 << 10]byte) {
		a[0], a[1] = byte(i), byte(i>>8)
		return a
	}
	anything := reflect.TypeFor[any]()
	texts := keyed(reflect.TypeFor[string](), func(i int) any { return long(i) })
	arrays := keyed(reflect.TypeFor[[1 << 10]byte](), func(i int) any { return array(i) })
	for name, c := range map[string]struct{ attributes, least map[string]any }{
		"structs holding a string":                     {keyed(reflect.TypeFor[text](), func(i int) any { return text{long(i)} }), texts},
		"arrays of a string":                           {keyed(reflect.TypeFor[[1]string](), func(i int) any { return [1]string{long(i)} }), texts},
		"structs holding a string in an interface":     {keyed(reflect.TypeFor[held](), func(i int) any { return held{long(i)} }), texts},
		"interfaces holding a struct holding a string": {keyed(anything, func(i int) any { return text{long(i)} }), texts},
		"structs holding an array in an interface":     {keyed(reflect.TypeFor[held](), func(i int) any { return held{array(i)} }), arrays},
		"interfaces holding an array":                  {keyed(anything, func(i int) any { return array(i) }), arrays},
	} {
		charged, copied := rbac.CopyingCharge(c.attributes)
		least, _ := rbac.CopyingCharge(c.least)
		if !copied || charged < least {
			t.Errorf("copying a map of 100 keyed by %s charged %d, copied %t, where keyed by what they hold it charged %d", name, charged, copied, least)
		}
	}
}

// A host can nest a value as deep as it likes, which converting it recurses into: a chain of
// pointers two million deep, which cost nothing, overflowed the stack, which no recover catches,
// and a list a hundred thousand deep, each level costing one, took a check a fifth of a second
// and a hundred mebibytes of stack. A value nested deeper than JSON text may makes its kind's
// attributes unreadable, and every condition reading them fails, while the other kinds' are read.
// It runs in a child process, on a smaller stack, which converting a value as deep as a check may
// afford, but no deeper than JSON, overflows.
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
			if _, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.ok == true`, map[string]any{"v": v, "ok": true}); err != nil || evaluated {
				t.Errorf("an attribute beside %s nested deep: evaluated %t, %v", name, evaluated, err)
			}
			if held, _ := rbac.EvaluateConditionOf(t, `subject.attributes.ok == true`, map[string]any{"ok": true}, nil, map[string]any{"v": v}); !held {
				t.Errorf("the subject's attributes beside a request's holding %s nested deep", name)
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
		map[string]any{"l": make([]any, 900), "v": [][64 << 10]byte{{1}}})
	if err != nil || !evaluated || !held {
		t.Errorf("a long array of bytes read nine hundred times: held %t, evaluated %t, %v", held, evaluated, err)
	}
	if allocated > 4*64<<10 {
		t.Errorf("a long array of bytes read nine hundred times allocated %d bytes", allocated)
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
		// A search of what isn't a string fails without reading it, and one with an empty side costs
		// reading the other, or for startsWith and endsWith the empty one.
		{"[[" + strings.Repeat("0, ", 499) + "0]].all(l, dyn(l).contains(dyn(l)))", true},
		{`"abc".contains("") && "".contains("abc") && "".startsWith("") && "abc".endsWith("")`, true},
		{`"` + strings.Repeat("ab", 100) + `".contains("` + strings.Repeat("ab", 50) + `z")`, true},
		{`request.attributes.ip.startsWith("") || "".endsWith(request.attributes.ip) || "10.".startsWith(request.attributes.ip)`, true},
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
		{`request.attributes.ip.contains("") || "".contains(request.attributes.ip)`, false},
		{`request.attributes.tags.exists(t, t.contains(request.attributes.ip))`, false},
		{`request.attributes.tags.filter(t, t != "").exists(t, t == "gpu")`, false},
		// CEL checks a dyn() value that meets another as of the other's type, which it needn't have.
		{`(dyn([{"a": 1}]) + [[]]).exists(m, request.attributes.n in m)`, false},
		{`(dyn([request.attributes.tags]) + [1])[0] == request.attributes.tags`, false},
		{`(dyn([{"a": request.attributes.tags}]) + [{"a": 1}]).exists(m, m.a == request.attributes.tags)`, false},
		{`(dyn([[request.attributes.tags]]) + [""]).exists(s, s + s == request.attributes.tags)`, false},
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
// are charged costs as it did, but 1 more at each step for each logical operator or choice it may
// evaluate, its macro's own among them (TestALoopsStepCostsEachLogicalOperatorItEvaluates), and
// filter() 1 more for each element it keeps, which it adds as a list literal of one
// (TestALiteralCostsWhatItBuilds).
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
	l := make([]any, 800)
	for i := range l {
		l[i] = i%2 == 0
	}
	for _, c := range []struct {
		expr string
		cost uint64
	}{
		{`request.attributes.l.all(z, z || !z)`, 5604},
		{`request.attributes.l.exists(z, z && !z)`, 6404},
		{`request.attributes.l.exists_one(z, z) || true`, 3206},
		{`request.attributes.l.filter(z, z).size() == 400`, 8018},
	} {
		if _, cost := rbac.ConditionCost(t, c.expr, map[string]any{"l": l}); cost != c.cost {
			t.Errorf("%s cost %d, not %d", c.expr, cost, c.cost)
		}
	}
}

// CEL charges a logical operator or a choice nothing, nor a literal it reads, though evaluating one
// takes about as long as a unit of cost does, so a loop whose steps each evaluated two hundred took
// twenty times what it was charged. A step costs 1 more for each its condition and step may
// evaluate, its macro's own among them, on top of what CEL charges it, however much that is, and the
// bound counts each.
func TestALoopsStepCostsEachLogicalOperatorItEvaluates(t *testing.T) {
	ands := strings.TrimSuffix(strings.Repeat("true && ", 200), " && ")
	ors := strings.TrimSuffix(strings.Repeat("false || ", 100), " || ")
	choices := strings.Repeat("false ? false : ", 12) + "true"
	attributes := map[string]any{"l": make([]any, 30)}
	for expr, least := range map[string]uint64{
		`request.attributes.l.all(z, ` + ands + `)`:                      30 * (1 + 1 + 199),
		`request.attributes.l.exists(z, !(` + choices + `))`:             30 * (1 + 1 + 12),
		`request.attributes.l.map(z, ` + ors + `).size() == 30`:          30 * (1 + 99),
		`[1, 2, 3].all(i, !request.attributes.l.exists(z, ` + ors + `))`: 3 * 30 * (1 + 1 + 99),
		"[" + strings.Repeat("0, ", 29) + "0].all(z, " + ands + ")":      30 * (1 + 1 + 199),
	} {
		limit, cost := rbac.ConditionCost(t, expr, attributes)
		if cost < least || cost > limit {
			t.Errorf("%s... cost %d, bounded at %d", expr[:50], cost, limit)
		}
	}
	// Counted only toward the least a step costs, a hundred in a step comparing strings of a
	// kilobyte cost nothing more.
	attributes["s"], attributes["t"] = strings.Repeat("x", 1000), strings.Repeat("x", 1000)
	compared := `request.attributes.l.all(z, request.attributes.s == request.attributes.t`
	_, alone := rbac.ConditionCost(t, compared+`)`, attributes)
	limit, cost := rbac.ConditionCost(t, compared+strings.Repeat(" && true", 100)+`)`, attributes)
	if cost < alone+30*100 || cost > limit {
		t.Errorf("a loop comparing strings cost %d, and %d with a hundred operators at each step, bounded at %d", alone, cost, limit)
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

// A loop gave a map's keys in the order Go ranges over the map, which changes from one evaluation
// to the next, so the same check of the same request decided otherwise from call to call: a grant
// whose condition read the first key map() made allowed in 55 of 100 calls, Explain disagreeing
// with the check before it in 51, and a deny reading the first filter() kept lifted in 84, so a
// requester could ask until it lifted. A loop gives a map's keys in one order, so each call decides
// alike, and Explain as Authorize does.
func TestALoopOverAMapDecidesAlikeOnEveryCall(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole) })
	ctx := t.Context()
	given := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	given.Condition = rbac.Condition{Expression: `request.attributes.scopes.map(k, k)[0] == "admin"`}
	h.seed(t, given, grant(cluster.Scope(), "cluster.login", rbac.User, "d"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "ordered", Principals: []rbac.Principal{identity("d")}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `request.attributes.scopes.filter(k, true)[0] == "admin"`},
	}); err != nil {
		t.Fatal(err)
	}
	request := rbac.WithRequest(ctx, map[string]any{"scopes": map[string]any{"read": true, "write": true, "admin": true}})
	for id, want := range map[string]bool{"u": true, "d": false} {
		s := h.as(t, id)
		for i := range 200 {
			err := h.authz.Authorize(request, s, login, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				t.Fatal(err)
			}
			d, explained := h.authz.Explain(request, s, login, cluster)
			if explained != nil {
				t.Fatal(explained)
			}
			if (err == nil) != want || d.Allowed != want {
				t.Fatalf("call %d: %s allowed %t, and by Explain %t", i, id, err == nil, d.Allowed)
			}
		}
	}
}

// A loop gives a map's keys in one order, however the map was made: bools, ints, uints, doubles and
// strings, each by its value, and a map keyed by anything else, as a list, a map literal can be,
// has no order and fails a loop over it, but where it holds one key. So a loop over a map decides,
// and costs, alike in each evaluation, and so does whatever reads a map whole, comparing it, `in`
// and size(): over random maps, the host's and literals, keyed by values of each type, through
// loops whose steps fail for some keys and decide for others, as all() and exists() take an error
// from one key and a decision from another, each of 50 evaluations decides alike and costs alike.
func TestALoopOverAMapGivesItsKeysInOneOrder(t *testing.T) {
	scopes := map[string]bool{"read": true, "write": true, "admin": true}
	packed := &structpb.Struct{Fields: map[string]*structpb.Value{"c": structpb.NewNullValue(), "a": structpb.NewNullValue(), "b": structpb.NewNullValue()}}
	attributes := map[string]any{
		"scopes": scopes, "mixed": map[any]any{"b": 1, uint(7): 2, "a": 3, 1: 4, true: 5, -2: 6},
		"json": json.RawMessage(`{"c": 1, "a": 2, "b": 3}`), "packed": packed, "listed": map[string]any{"z": []any{1}, "y": []any{2}},
	}
	for _, c := range []struct {
		expr            string
		held, evaluated bool
	}{
		{`{"b": 0, 2: 0, true: 0, 1u: 0, 1.5: 0, "a": 0, false: 0, -1: 0, 0.5: 0}.map(k, k) == [false, true, -1, 2, 1u, 0.5, 1.5, "a", "b"]`, true, true},
		{`request.attributes.mixed.map(k, k) == [true, -2, 1, 7u, "a", "b"]`, true, true},
		{`request.attributes.scopes.map(k, k) == ["admin", "read", "write"]`, true, true},
		{`request.attributes.scopes.filter(k, k != "admin")[0] == "read"`, true, true},
		{`dyn(request.attributes.scopes).exists_one(k, k < "b") && request.attributes.scopes.map(k, k)[2] == "write"`, true, true},
		{`(true ? request.attributes.scopes : {}).map(k, k)[0] == "admin"`, true, true},
		{`request.attributes.json.map(k, k) == ["a", "b", "c"] && request.attributes.packed.map(k, k) == ["a", "b", "c"]`, true, true},
		{`request.attributes.listed.map(k, request.attributes.listed[k][0]) == [2, 1]`, true, true},
		{`subject.map(k, k) == ["attributes", "id", "kind"] && request.map(k, k) == ["attributes", "time"]`, true, true},
		{`[request.attributes.scopes].all(m, m.map(k, k)[0] == "admin")`, true, true},
		{`!request.attributes.mixed.all(k, k < 5) && request.attributes.mixed.exists(k, k > 5)`, true, true},
		{`{[1]: 1}.all(k, k == [1])`, true, true},
		{`{[1]: 1, [2]: 2}.all(k, true)`, false, false},
		{`{null: 1, 1: 2}.exists(k, true)`, false, false},
	} {
		decided, err := rbac.Evaluations(t, c.expr, attributes, 50)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		for i, d := range decided {
			if d.Held != c.held || d.Evaluated != c.evaluated {
				t.Fatalf("%s, evaluation %d: held %t, evaluated %t", c.expr, i, d.Held, d.Evaluated)
			}
		}
	}

	rng := rand.New(rand.NewPCG(1, 15))
	key := func() (literal string, host any) {
		switch n := rng.IntN(9) - 4; rng.IntN(5) {
		case 0:
			return strconv.FormatBool(n > 0), n > 0
		case 1:
			return strconv.Itoa(n), n
		case 2:
			return fmt.Sprintf("%du", n+4), uint(n + 4)
		case 3:
			return fmt.Sprintf("%d.5", n), nil
		default:
			s := strings.Repeat("k", rng.IntN(3)) + string(rune('a'+n+4))
			return strconv.Quote(s), s
		}
	}
	for seed := range 120 {
		var entries, keys []string
		host := map[any]any{}
		for i := range rng.IntN(7) + 2 {
			k, v := key()
			if slices.Contains(keys, k) {
				continue
			}
			keys = append(keys, k)
			entries = append(entries, fmt.Sprintf("%s: %d", k, i))
			if v != nil {
				host[v] = i
			}
		}
		shuffled := slices.Clone(entries)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		literal := "{" + strings.Join(entries, ", ") + "}"
		k := keys[rng.IntN(len(keys))]
		for _, m := range []string{literal, "request.attributes.m"} {
			for _, expr := range []string{
				m + ".map(k, k)[0] == " + k,
				m + `.filter(k, k != ` + k + `)[0] == ` + keys[0],
				m + ".map(k, [k, " + m + "[k]])[1][1] == 1",
				m + ".all(k, k < 2)",
				m + ".exists(k, k > 2)",
				"!" + m + ".exists_one(k, k == " + k + " || k > 0)",
				m + ".all(k, " + m + ".exists(j, j == k))",
				m + ".exists(k, " + m + ".map(j, j)[0] == k && k != " + k + ")",
				m + " == {" + strings.Join(shuffled, ", ") + "}",
				k + " in " + m + " && size(" + m + ") == " + strconv.Itoa(len(entries)),
			} {
				attributes := map[string]any{"m": host}
				// One CEL doesn't check, as one ordering strings by ints, isn't a condition.
				decided, err := rbac.Evaluations(t, expr, attributes, 50)
				if err != nil {
					continue
				}
				if limit, cost := rbac.ConditionCost(t, expr, attributes); cost > limit {
					t.Errorf("seed %d: %s cost %d, past its bound, %d", seed, expr, cost, limit)
				}
				for i, d := range decided {
					if d != decided[0] {
						t.Fatalf("seed %d: %s decided %+v, and in evaluation %d %+v", seed, expr, decided[0], i, d)
					}
				}
			}
		}
	}
}

// Every loop gives a map's keys in one order, however the condition reaches the map: random
// conditions loop, nest loops, and reach maps the host passes, JSON objects, Structs, map literals,
// the request and maps a loop's variable holds through selects, indexes, dyn() and choices, each
// evaluated 50 times with its attributes converted afresh, decide alike and cost alike, within
// their bounds, as do ones reaching only literals, which bound them below what any condition may.
func TestEveryLoopOverAMapDecidesAndCostsAlike(t *testing.T) {
	inner, err := structpb.NewStruct(map[string]any{"c": 1, "a": 2, "bb": 3, "d": 4})
	if err != nil {
		t.Fatal(err)
	}
	attributes := map[string]any{
		"m":      map[any]any{"b": 1, uint(7): 2, "a": 3, 1: 4, true: 5, -2: 6, "ccc": 7},
		"s":      map[string]any{"read": 1, "write": 2, "admin": 3, "zz": 4},
		"list":   []any{map[string]any{"c": 1, "a": 2, "b": 3}, map[string]any{"z": 1, "y": 2}},
		"nested": map[string]any{"p": map[string]any{"c": 1, "a": 2}, "q": map[string]any{"z": 1, "y": 2, "x": 3}},
		"json":   json.RawMessage(`{"o": {"c": 1, "a": 2, "b": 3}, "k": "a"}`),
		"packed": &structpb.Struct{Fields: map[string]*structpb.Value{"o": structpb.NewStructValue(inner)}},
	}
	rng := rand.New(rand.NewPCG(15, 1))
	pick := func(xs ...string) string { return xs[rng.IntN(len(xs))] }
	literal := func() string {
		var entries []string
		for i := range rng.IntN(5) + 2 {
			entries = append(entries, fmt.Sprintf("%s: %d", pick(`"a"`, `"bb"`, `"c"`, `"dddd"`, `"e"`, "1", "2u", "true", "-3", "0.5"), i))
		}
		return "{" + strings.Join(entries, ", ") + "}"
	}
	literals := false
	var ranged func(depth int, bound string) string
	ranged = func(depth int, bound string) string {
		switch n := rng.IntN(14); {
		case n == 0 && bound != "":
			return bound
		case n == 1 || literals && n < 9:
			return literal()
		case n == 2:
			return "request.attributes." + pick("m", "s")
		case n == 3:
			return `request.attributes["` + pick("m", "s", "nested") + `"]`
		case n == 4:
			return "request.attributes.json.o"
		case n == 5:
			return "request.attributes.packed.o"
		case n == 6:
			return "request.attributes.nested." + pick("p", "q")
		case n == 7:
			return "request.attributes.list[" + pick("0", "1") + "]"
		case n == 8:
			return pick("request", "subject", "resource.attributes")
		case n == 9 && depth > 0:
			return "dyn(" + ranged(depth-1, bound) + ")"
		case n == 10 && depth > 0:
			return "(size(request.attributes.s) " + pick(">", "<") + " 2 ? dyn(" + ranged(depth-1, bound) + ") : dyn(" + ranged(depth-1, bound) + "))"
		case n == 11 && depth > 0:
			return `{"x": ` + ranged(depth-1, bound) + `}` + pick(`["x"]`, ".x")
		case n == 12 && depth > 0:
			return "[" + ranged(depth-1, bound) + "][0]"
		default:
			return "request.attributes.s"
		}
	}
	var looped func(depth int, bound string) string
	looped = func(depth int, bound string) string {
		r := ranged(2, bound)
		v := fmt.Sprintf("k%d", depth)
		cond := func() string {
			if depth > 0 && rng.IntN(3) == 0 {
				return looped(depth-1, v)
			}
			return pick(v+` < "b"`, v+` == "a"`, v+" > 0", "true", "false", "string("+v+`) < "c"`, r+"["+v+"] == 2")
		}
		switch rng.IntN(6) {
		case 0:
			return r + ".map(" + v + ", " + v + ")[0] == " + pick(`"a"`, "true", "1", `"admin"`, `"attributes"`)
		case 1:
			return r + ".filter(" + v + ", " + cond() + ").map(" + v + ", string(" + v + ")).exists(x, x == " + pick(`"a"`, `"c"`, `"zz"`) + ")"
		case 2:
			return r + ".all(" + v + ", " + cond() + ")"
		case 3:
			return r + ".exists_one(" + v + ", " + cond() + ")"
		case 4:
			return r + ".map(" + v + ", " + cond() + ", string(" + v + "))[0] == " + pick(`"a"`, `"c"`, `"zz"`)
		default:
			return r + ".exists(" + v + ", " + cond() + ")"
		}
	}
	conditions, bounded := 0, 0
	for i := range 600 {
		literals = i >= 400
		expr := looped(2, "")
		decided, err := rbac.Evaluations(t, expr, attributes, 50)
		if err != nil {
			continue
		}
		conditions++
		for i, d := range decided {
			if d != decided[0] {
				t.Fatalf("%s decided %+v, and in evaluation %d %+v", expr, decided[0], i, d)
			}
		}
		limit, cost := rbac.ConditionCost(t, expr, attributes)
		if cost > limit {
			t.Errorf("%s cost %d, past its bound, %d", expr, cost, limit)
		}
		if limit < 10000 {
			bounded++
		}
	}
	if conditions < 450 || bounded < 100 {
		t.Errorf("of 600 random conditions, %d were conditions, %d bounded below what any may cost", conditions, bounded)
	}
}

// Sorting a map's keys compares each with others at each of a few levels, reading as much of both
// as they share, so a loop over a map is charged, before it starts, 1 for each two keys at each
// level and what reading each costs past 1 once, as its bound counts it: charged 1 for each key and
// its bytes at each level, a loop over 500 keys of 36 bytes, as ids, cost past what a condition
// may, though sorting them took 64 µs. One over a map of long keys sharing all but their last
// bytes, which would read them over and over, fails before it sorts them.
func TestALoopOverAMapCostsSortingItsKeys(t *testing.T) {
	keyed := func(n, length int) map[string]any {
		m, l := map[string]any{}, []any{}
		for i := range n {
			k := fmt.Sprintf("%s%03d", strings.Repeat("k", length-3), i)
			m[k], l = i, append(l, k)
		}
		return map[string]any{"m": m, "l": l}
	}
	for _, c := range []struct{ n, length, levels int }{{16, 300, 4}, {500, 36, 9}, {2, 5, 1}, {3, 40, 2}} {
		attributes := keyed(c.n, c.length)
		limit, cost := rbac.ConditionCost(t, `request.attributes.m.exists(k, k == "")`, attributes)
		_, listed := rbac.ConditionCost(t, `request.attributes.l.exists(k, k == "")`, attributes)
		// Each key 1 at the loop's first step, as before, each two 1 at each level, and its bytes once.
		if want := uint64(c.n + (c.n+1)/2*c.levels + c.n*(c.length/10)); cost != listed+want || cost > limit {
			t.Errorf("a loop over %d keys of %d bytes cost %d, bounded at %d, where over a list of them it cost %d, not %d less",
				c.n, c.length, cost, limit, listed, want)
		}
		if held, evaluated, _, err := rbac.EvaluateCondition(t, `!request.attributes.m.exists(k, k == "")`, attributes); err != nil || !held || !evaluated {
			t.Errorf("a loop over %d keys of %d bytes held %t, evaluated %t: %v", c.n, c.length, held, evaluated, err)
		}
	}
	_, alone := rbac.ConditionCost(t, `request.attributes.m.exists(k, false)`, keyed(1, 300))
	if alone > 10 {
		t.Errorf("a loop over one key of 300 bytes cost %d", alone)
	}
	if held, evaluated, _, err := rbac.EvaluateCondition(t, `!request.attributes.m.exists(k, false)`, keyed(100, 1000)); err != nil || held || evaluated {
		t.Errorf("a loop over 100 keys of a kilobyte held %t, evaluated %t: %v", held, evaluated, err)
	}
	literal := `{"aaaaaaaaaaaaaaaaaaaa": 1, "aaaaaaaaaaaaaaaaaaab": 2, "aaaaaaaaaaaaaaaaaaac": 3, "b": 4, "c": 5}`
	for _, expr := range []string{
		literal + `.map(k, k)[0] == "aaaaaaaaaaaaaaaaaaaa"`, `[1, 2].all(i, ` + literal + `.exists(k, k == "c"))`,
		`(true ? dyn(` + literal + `) : dyn([1])).all(k, k != "")`,
	} {
		limit, cost := rbac.ConditionCost(t, expr, nil)
		// Three for each of 3 levels, and 2 more for each key.
		if cost > limit || limit < 3*3+5*2 {
			t.Errorf("%s cost %d, bounded at %d", expr, cost, limit)
		}
	}
}

// Nothing but how deep a value nests turns on the order Go ranges over a map in, which changes from
// one time to the next: converting a kind's attributes charges each map, and finds whether they can
// be read, alike whatever order its entries come in, a hook's copy of them is charged alike, and
// comparing maps, finding one in a list or a key in one, and size() decide and cost alike. Values
// of random shapes, nesting every type both handle and sharing some, do so in each of 20 tries.
func TestConvertingCopyingOrComparingAMapTurnsOnNoOrder(t *testing.T) {
	const compared = `request.attributes.a0 == request.attributes.a1 || request.attributes.a0 == request.attributes.a0 && ` +
		`request.attributes.a1 in [request.attributes.a0, request.attributes.a1] && "a1" in request.attributes && size(request.attributes) > 1`
	for seed := range uint64(300) {
		d := &copyDraw{rng: rand.New(rand.NewPCG(seed, 15)), decoded: seed%2 == 0, sharing: seed%3 == 0}
		attributes := map[string]any{}
		for i := range d.rng.IntN(4) + 2 {
			attributes[fmt.Sprint("a", i)] = d.value(3)
		}
		converted, read := rbac.ConvertingCharge(attributes)
		copied, ok := rbac.CopyingCharge(attributes)
		decided, err := rbac.Evaluations(t, compared, attributes, 20)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 20 {
			if again, readAgain := rbac.ConvertingCharge(attributes); again != converted || readAgain != read {
				t.Fatalf("seed %d: converting cost %d, read %t, and in try %d %d, %t", seed, converted, read, i, again, readAgain)
			}
			if again, okAgain := rbac.CopyingCharge(attributes); again != copied || okAgain != ok {
				t.Fatalf("seed %d: copying cost %d, copied %t, and in try %d %d, %t", seed, copied, ok, i, again, okAgain)
			}
			if decided[i] != decided[0] {
				t.Fatalf("seed %d: comparing decided %+v, and in try %d %+v", seed, decided[0], i, decided[i])
			}
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

// CEL charges contains a tenth of each side's characters, multiplied, and startsWith and endsWith a
// tenth of what they look for, each rounded up: nothing where a side is empty, though counting the
// characters copies the other side whole, so a check whose conditions called contains("") in loops
// on a string of a mebibyte and a half the request passed took twenty seconds, each condition within
// its bound. contains costs what reading both sides does, multiplied, and startsWith and endsWith
// what reading the shorter does, each at least 1, so an empty side costs what a short one does, and
// no character is counted.
func TestASearchOfAStringCostsWhatItReads(t *testing.T) {
	ten := "[" + strings.Repeat("0, ", 9) + "0]"
	attributes := map[string]any{"s": strings.Repeat("x", 500)}
	for search, least := range map[string]uint64{
		`request.attributes.s.contains(%q)`: 51, `%q.contains(request.attributes.s)`: 51,
		`request.attributes.s.startsWith(%q)`: 1, `%q.startsWith(request.attributes.s)`: 1,
		`request.attributes.s.endsWith(%q)`: 1, `%q.endsWith(request.attributes.s)`: 1,
	} {
		looped := func(side string) string { return ten + ".all(i, " + fmt.Sprintf(search, side) + " || true)" }
		limit, empty := rbac.ConditionCost(t, looped(""), attributes)
		_, short := rbac.ConditionCost(t, looped("z"), attributes)
		if empty != short || empty < 10*least || empty > limit {
			t.Errorf("%s cost %d ten times, %d with a side of one character, bounded at %d", fmt.Sprintf(search, ""), empty, short, limit)
		}
	}
	long := map[string]any{"s": strings.Repeat("x", 600_000)}
	for _, expr := range []string{
		`request.attributes.s.contains("")`, `"".contains(request.attributes.s)`, `request.attributes.s.startsWith(request.attributes.s)`,
		`"".endsWith(request.attributes.s) && request.attributes.s.contains("x")`,
	} {
		if _, _, allocated, err := rbac.EvaluateCondition(t, expr, long); err != nil || allocated > 64<<10 {
			t.Errorf("%s on a string of %d bytes allocated %d bytes: %v", expr, 600_000, allocated, err)
		}
	}
}

// contains of a string the request passes in another tries each place in it, comparing as much of
// what it looks for as matches there: one of a mebibyte in another of half that, matching far at each
// of many places, took a third of a second, though a call is charged only once it has run, and so
// did every condition reading them so in a check. A search costing more than a condition may is
// refused before it runs.
func TestASearchCostingMoreThanAConditionMayIsRefusedBeforeItRuns(t *testing.T) {
	n := rbac.CountSearches(t)
	block := "ab" + strings.Repeat("c", 15)
	attributes := map[string]any{"s": strings.Repeat(block, 6000), "sub": strings.Repeat(block, 300) + "z"}
	for _, expr := range []string{
		`request.attributes.s.contains(request.attributes.sub)`, `request.attributes.s.contains("")`,
		`request.attributes.s.startsWith(request.attributes.s)`, `request.attributes.s.endsWith(request.attributes.s)`,
	} {
		*n = 0
		if _, evaluated, _, err := rbac.EvaluateCondition(t, expr, attributes); err != nil || evaluated {
			t.Errorf("%s: evaluated %t, %v", expr, evaluated, err)
		}
		if *n > 0 {
			t.Errorf("%s ran %d searches past what a condition may cost", expr, *n)
		}
	}
	// Within its cost a search runs, so a count of none above is one refused.
	*n = 0
	expr := `request.attributes.sub.startsWith("ab") && request.attributes.sub.contains("z") && request.attributes.sub.endsWith("z")`
	if held, _, _, err := rbac.EvaluateCondition(t, expr, attributes); err != nil || !held || *n != 3 {
		t.Errorf("searches within their cost: held %t, ran %d, %v", held, *n, err)
	}
}

// CEL charges a list literal 10 and a map literal 30 however many elements or entries they hold, so
// a loop rebuilding a list of 700 or a map of 230 at each step took ten times what a condition
// charged as much takes. A literal costs 1 more for each element it builds, and 2 for each entry,
// which the map hashes too, each time it is built, and its bound counts them alike.
func TestALiteralCostsWhatItBuilds(t *testing.T) {
	ten := "[" + strings.Repeat("0, ", 9) + "0]"
	list := func(n int) string { return "[" + strings.Repeat("1, ", n-1) + "1]" }
	dict := func(n int) string {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = fmt.Sprintf("%d: 1", i)
		}
		return "{" + strings.Join(entries, ", ") + "}"
	}
	for _, c := range []struct {
		literal func(int) string
		each    uint64
	}{{list, 1}, {dict, 2}} {
		looped := func(n int) string { return fmt.Sprintf("%s.all(i, size(%s) == %d)", ten, c.literal(n), n) }
		bound, cost := rbac.ConditionCost(t, looped(1), nil)
		for _, n := range []int{100, 200} {
			more := 10 * c.each * uint64(n-1)
			if b, got := rbac.ConditionCost(t, looped(n), nil); got != cost+more || b != bound+more {
				t.Errorf("%s cost %d, bounded at %d, and with one element %d, bounded at %d", looped(n)[:60], got, b, cost, bound)
			}
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

// Comparing two values is charged as reading the smaller once, but it measured them again at each
// doubling of how far it read, again in search of a double that isn't finite, and again for CEL's
// charge once it had run, making an iterator of each map and list each time: comparing JSON a
// request passes nested 3,300 deep took a microsecond and a half for each unit charged, twenty
// times what reading a flat map took. Each is read once, in step with the other, and charged as
// read, before the comparison runs.
func TestComparingValuesNestedDeepReadsThemOnce(t *testing.T) {
	for name, text := range map[string]string{
		"maps":  strings.Repeat(`{"a":`, 3300) + `"x"` + strings.Repeat("}", 3300),
		"lists": strings.Repeat(`[`, 4900) + `"x"` + strings.Repeat("]", 4900),
	} {
		attributes := map[string]any{"a": json.RawMessage(text), "b": json.RawMessage(strings.Clone(text))}
		for _, expr := range []string{
			`request.attributes.a == request.attributes.b`, `request.attributes.a != request.attributes.b`,
			`request.attributes.a in [request.attributes.b]`,
		} {
			held, evaluated, allocated, err := rbac.EvaluateCondition(t, expr, attributes)
			if err != nil || !evaluated || held == strings.Contains(expr, "!=") {
				t.Errorf("%s nested deep: %s held %t, evaluated %t, %v", name, expr, held, evaluated, err)
			}
			if allocated > 256<<10 {
				t.Errorf("%s nested deep: %s allocated %d bytes", name, expr, allocated)
			}
			if limit, cost := rbac.ConditionCost(t, expr, attributes); cost < 4900 || cost > limit {
				t.Errorf("%s nested deep: %s cost %d, bounded at %d", name, expr, cost, limit)
			}
		}
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
		"a Value whose kind is a nil of its type": {&structpb.Value{Kind: (*structpb.Value_StructValue)(nil)}, nil},
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

// A list or map literal that CEL plans as no literal, or where no decorator sees it, as another
// version of CEL may, isn't a condition: it would build what it holds uncharged.
func TestALiteralPlannedOtherwiseIsNoCondition(t *testing.T) {
	for _, expr := range []string{`size([1, 2, 3]) == 3`, `{"a": 1}["a"] == 1`, `request.attributes.ip in ["10.0.0.1"]`} {
		for how, replan := range map[string]func(interpreter.InterpretableV2) interpreter.InterpretableV2{
			"as something else": func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, i.ID()} },
			"under another id":  func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, -i.ID()} },
		} {
			if err := rbac.PlanLiteralsOtherwise(t, expr, replan); err == nil {
				t.Errorf("%s with its literal planned %s is a condition", expr, how)
			}
		}
		if err := rbac.PlanLiteralsOtherwise(t, expr, func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return i }); err != nil {
			t.Errorf("%s planned as CEL plans it: %v", expr, err)
		}
	}
}

// A comparison, a search or a match that CEL plans as no call, or as a call of another name, as
// another version of CEL may, isn't a condition: no decorator would refuse it before it runs, so a
// contains of one long string in another would run whole however long it took, and a comparison
// would read a double that isn't finite as CEL does.
func TestACallRefusedBeforeItRunsPlannedOtherwiseIsNoCondition(t *testing.T) {
	for _, expr := range []string{
		`request.attributes.s.contains("a")`, `request.attributes.s.startsWith("a")`, `request.attributes.s.endsWith("a")`,
		`request.attributes.x == 1.0`, `request.attributes.x != 1.0`, `request.attributes.x < 1.0`, `"a" in request.attributes.l`,
		`request.time.getHours(request.attributes.zone) > 9`, `request.attributes.s.matches("^a")`,
	} {
		for how, replan := range map[string]func(interpreter.InterpretableV2) interpreter.InterpretableV2{
			"as something else": func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, i.ID()} },
			"as a call of another name": func(i interpreter.InterpretableV2) interpreter.InterpretableV2 {
				c, ok := i.(interpreter.InterpretableCall)
				if !ok {
					t.Fatalf("%s plans %T where it calls", expr, i)
				}
				return interpreter.NewCall(c.ID(), "@"+c.Function(), c.OverloadID(), c.Args(), func(...ref.Val) ref.Val { return types.True })
			},
		} {
			if err := rbac.PlanGuardedOtherwise(t, expr, replan); err == nil {
				t.Errorf("%s with its call planned %s is a condition", expr, how)
			}
		}
		if err := rbac.PlanGuardedOtherwise(t, expr, func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return i }); err != nil {
			t.Errorf("%s planned as CEL plans it: %v", expr, err)
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

// CEL loads a time zone from the platform's files each time a condition reads a time in one: a check
// of 54 conditions, each reading the hour 85 times, took 23 ms in America/New_York, and 254 ms in
// tzdata.zi, a file kept beside the zones that isn't one, which each load read whole, failed to
// parse and then searched the other places for, each charged as reading a time. The process loads
// each zone once, and finds a name names none once, whether a literal or the request names it, the
// request's charged as loading it at each read (TestLoadingAZoneTheRequestNamesCostsWhatItTakes).
func TestATimeInAZoneLoadsTheZoneOnceForTheProcess(t *testing.T) {
	loads := rbac.CountZoneLoads(t)
	ones := "[" + strings.TrimSuffix(strings.Repeat("1, ", 15), ", ") + "]"
	for zone, evaluated := range map[string]bool{"Pacific/Chatham": true, "Etc/GMT+5": true, "Zz/Nowhere": false} {
		for _, expr := range []string{
			ones + `.all(i, request.time.getHours(request.attributes.zone) >= 0)`,
			ones + `.all(i, request.time.getHours("` + zone + `") >= 0)`,
		} {
			*loads = 0
			for range 3 {
				if _, ok, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"zone": zone}); err != nil || ok != evaluated {
					t.Errorf("%s in %s: evaluated %t, %v", expr[len(ones):], zone, ok, err)
				}
			}
			if *loads > 1 {
				t.Errorf("%s in %s loaded the zone %d times", expr[len(ones):], zone, *loads)
			}
		}
	}
}

// A name holding a byte no zone's name does, as tzdata.zi's dot, fails before anything is loaded, so
// no file kept beside the zones is read as one; and so do Local, the zone the process runs in, by
// which a condition would decide by where each replica runs, and localtime, which some platforms
// keep beside the zones as a link to it, as any part of a name, in any case: platforms keeping
// posix as a link to the zones' own directory loaded the process's zone as posix/localtime, and a
// file system ignoring case would as LocalTime. A fixed offset loads nothing.
func TestATimeInANameOfNoZoneFailsBeforeLoadingAnything(t *testing.T) {
	// zone is as a CEL string literal spells it.
	evaluate := func(zone string, evaluated bool) {
		t.Helper()
		name, err := strconv.Unquote(`"` + zone + `"`)
		if err != nil {
			t.Fatal(err)
		}
		for _, expr := range []string{`request.time.getHours(request.attributes.zone) >= 0`, `request.time.getHours("` + zone + `") >= 0`} {
			if _, ok, _, err := rbac.EvaluateCondition(t, expr, map[string]any{"zone": name}); err != nil || ok != evaluated {
				t.Errorf("%s in %q: evaluated %t, %v", expr, name, ok, err)
			}
		}
	}
	for _, zone := range []string{"UTC", "", "+05:30", "-11:00"} {
		evaluate(zone, true)
	}
	loads := rbac.CountZoneLoads(t)
	for _, zone := range []string{
		"tzdata.zi", "zone.tab", "../UTC", "America/New York", "Local", "localtime", `UTC\u0000`, "+05:30", "posix/localtime",
		"posix/posix/localtime", "right/localtime", "LocalTime", "LOCALTIME", "posix/Local", "localtime/", "local",
	} {
		evaluate(zone, zone == "+05:30")
	}
	if *loads != 0 {
		t.Errorf("names of no zone, and an offset, loaded %d", *loads)
	}
}

// A zone the request names can be a new one each time, which loading costs: a loop reading a time in
// each of a list of new names stops at its condition's limit having loaded no more than that pays
// for, where charged as reading a time in a zone loaded, it loaded a hundred. A zone the process has
// loaded costs as much again: charged only where it hadn't, the same condition on the same request
// cost 500 more the first time, so a check of conditions reading many was refused the first time and
// allowed after, and decided by which zones each replica had loaded.
func TestLoadingAZoneTheRequestNamesCostsWhatItTakes(t *testing.T) {
	loads := rbac.CountZoneLoads(t)
	run := rand.Uint64()
	names := make([]any, 1000)
	for i := range names {
		names[i] = fmt.Sprintf("Zz/Load%d/%d", run, i)
	}
	_, evaluated, _, err := rbac.EvaluateCondition(t, `request.attributes.zones.exists(z, request.time.getHours(z) == 99)`, map[string]any{"zones": names})
	if err != nil || evaluated {
		t.Errorf("a loop over a thousand new zones evaluated %t, %v", evaluated, err)
	}
	if *loads > 10000/rbac.ZoneLoad {
		t.Errorf("a loop over a thousand new zones loaded %d", *loads)
	}
	expr, zone := `request.time.getHours(request.attributes.zone) >= 0`, map[string]any{"zone": fmt.Sprintf("Zz/Load%d/once", run)}
	limit, loading := rbac.ConditionCost(t, expr, zone)
	_, loaded := rbac.ConditionCost(t, expr, zone)
	if loading > limit || loaded != loading || loading < rbac.ZoneLoad {
		t.Errorf("reading a time in a new zone cost %d, and in one loaded %d, bounded at %d", loading, loaded, limit)
	}
}

// A check decides alike whatever zones the process loaded before it: conditions reading the hour in
// each of eighteen zones the request names, charged for loading only those the process hadn't,
// cost past what a condition may the first time and not after, so Authorize refused where Explain
// right after allowed, and a deny applied and then lifted, on the same request.
func TestTheSameCheckDecidesAlikeWhateverZonesTheProcessLoaded(t *testing.T) {
	var zones []any
	var names []string
	for i := 1; i <= 18; i++ {
		name := fmt.Sprintf("Etc/GMT+%d", i%12+1)
		if i > 12 {
			name = fmt.Sprintf("Etc/GMT-%d", i-12)
		}
		zones, names = append(zones, name), append(names, name)
	}
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
	})
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `request.attributes.zones.all(z, request.time.getHours(z) >= 0)`}
	h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, "v"), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	u, v := h.as(t, "u"), h.as(t, "v")
	if err := h.authz.SetDeny(t.Context(), h.as(t, "guardian"), cluster, rbac.Deny{
		ID: "zones", Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
		Condition: rbac.Condition{Expression: `request.attributes.zones.exists(z, request.time.getHours(z) == 99)`},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := rbac.WithRequest(t.Context(), map[string]any{"zones": zones})
	rbac.ForgetZones(names...)
	first := h.authz.Authorize(ctx, u, login, cluster)
	explained, err := h.authz.Explain(ctx, u, login, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if again := h.authz.Authorize(ctx, u, login, cluster); first == nil || explained.Allowed || again == nil {
		t.Errorf("a grant reading eighteen zones: Authorize %v, then Explain allowed %t, then Authorize %v", first, explained.Allowed, again)
	}
	rbac.ForgetZones(names...)
	if first, again := h.authz.Authorize(ctx, v, login, cluster), h.authz.Authorize(ctx, v, login, cluster); first == nil || again == nil {
		t.Errorf("a deny reading eighteen zones: Authorize %v, then %v", first, again)
	}
}

// The zones a process keeps are bounded, as requests name them, and a condition naming one in a
// literal loads it when it is planned, so evaluating it loads nothing however many the process has
// dropped since, and is bounded as loading none.
func TestTheZonesAProcessKeepsAreBounded(t *testing.T) {
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `request.time.getHours("Australia/Lord_Howe") >= 0`}
	h.seed(t, g)
	u := h.as(t, "u")
	if !allowed(t, h, u, login, cluster) {
		t.Fatal("u should log in at any hour in Lord Howe")
	}
	// Each name past the bound drops one kept at random, so few survive eight times as many.
	run, names := rand.Uint64(), make([]string, 8*rbac.MaxZones)
	for i := range names {
		names[i] = fmt.Sprintf("Zz/Kept%d/%d", run, i)
	}
	if kept := rbac.LoadZones(names); kept > rbac.MaxZones {
		t.Errorf("the process keeps %d zones", kept)
	}
	loads := rbac.CountZoneLoads(t)
	if ok := allowed(t, h, u, login, cluster); !ok || *loads != 0 {
		t.Errorf("a condition naming its zone in a literal, once the process dropped it: allowed %t, loaded %d zones", ok, *loads)
	}
}

// A zone the platform's files fail to give for a while, as once the process has run out of file
// descriptors, loads once they give it again: kept, the zone of a check's condition, named by an
// attribute or a literal, failed for the process until it was dropped, though loading it again
// would have found it, and a literal's for as long as checks kept the condition's program.
func TestAZoneThatFailsToLoadForAWhileLoadsOnceItCan(t *testing.T) {
	const zone = "Asia/Kathmandu"
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `request.time.getHours("` + zone + `") >= 0`}
	h.seed(t, g)
	u := h.as(t, "u")
	attribute := `request.time.getHours(request.attributes.zone) >= 0`
	rbac.ForgetZones(zone)
	restore := rbac.FailZoneLoads(t, syscall.EMFILE)
	if _, ok, _, _ := rbac.EvaluateCondition(t, attribute, map[string]any{"zone": zone}); ok {
		t.Fatal("a zone that fails to load was read")
	}
	if allowed(t, h, u, login, cluster) {
		t.Fatal("a condition reading a time in a zone that fails to load allowed")
	}
	restore()
	if _, ok, _, err := rbac.EvaluateCondition(t, attribute, map[string]any{"zone": zone}); !ok {
		t.Errorf("a zone an attribute names that failed to load for a while: %v", err)
	}
	if !allowed(t, h, u, login, cluster) {
		t.Error("a zone a literal names that failed to load for a while still fails")
	}
}

// The host's clock is read in UTC, as a time it passes as an attribute is, and as CEL reads one
// with no zone: string() writes a time in its own zone, so a clock or a database returning times in
// each replica's local zone decided by where the replica runs, a deny comparing the request's time
// as a string lifting in one zone and not in another.
func TestTimesAreReadInUTCWhateverZoneTheHostKeepsThemIn(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 5, 17, 0, 0, 0, time.UTC)
	h := setup(t)
	g := grant(cluster.Scope(), "cluster.login", rbac.User, "u")
	g.Condition = rbac.Condition{Expression: `string(request.time) == "2026-01-05T17:00:00Z" && request.time.getHours() == 17 && ` +
		`string(request.attributes.at) == "2026-01-05T17:00:00Z" && string(request.attributes.cel) == "2026-01-05T17:00:00Z" && ` +
		`string(request.attributes.at - duration("4380h")) == "2025-07-07T05:00:00Z"`}
	h.seed(t, g)
	u := h.as(t, "u")
	for _, zone := range []*time.Location{time.UTC, ny, time.FixedZone("", 5*3600)} {
		h.now = at.In(zone)
		ctx := rbac.WithRequest(t.Context(), map[string]any{"at": at.In(zone), "cel": types.Timestamp{Time: at.In(zone)}})
		if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
			t.Errorf("the clock and the times passed in %s: %v", zone, err)
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

// A literal costs for each element it builds, so a condition rebuilding one at each step of a loop
// can cost more than a condition may, as one stored when a literal was charged as one now does: it
// fails, so a grant's gives nothing and a deny's applies.
func TestAConditionWhoseLiteralsCostMoreThanItMayFails(t *testing.T) {
	h := setup(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog[:len(c.Catalog):len(c.Catalog)], guardRole)
	})
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	ten := "[" + strings.Repeat("0, ", 9) + "0]"
	for n, within := range map[int]bool{10: true, 90: false} {
		rebuilt := fmt.Sprintf("%s.all(i, %s.all(j, size([%s1]) == %d))", ten, ten, strings.Repeat("1, ", n-1), n)
		u, v := h.as(t, fmt.Sprint("u", n)), h.as(t, fmt.Sprint("v", n))
		g := grant(cluster.Scope(), "cluster.login", rbac.User, u.Principal.ID)
		g.Condition = rbac.Condition{Expression: rebuilt}
		h.seed(t, g, grant(cluster.Scope(), "cluster.login", rbac.User, v.Principal.ID))
		d := rbac.Deny{
			ID: v.Principal.ID, Principals: []rbac.Principal{v.Principal}, Permissions: []rbac.Permission{login},
			Condition: rbac.Condition{Expression: "!(" + rebuilt + ")"},
		}
		if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), cluster, d); err != nil {
			t.Fatal(err)
		}
		if allowed(t, h, u, login, cluster) != within {
			t.Errorf("a grant's condition rebuilding a list of %d at each step held: %t", n, !within)
		}
		if allowed(t, h, v, login, cluster) != within {
			t.Errorf("a deny's condition rebuilding a list of %d at each step applied: %t", n, within)
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
// step wouldn't find the range, so a loop over a map would copy its keys uncharged. Nor is one
// whose range, which may be a map, it plans as something else, which nothing orders, so a loop
// over it would give its keys as Go ranges over it, but where CEL checks the range as a list.
func TestALoopPlannedOtherwiseIsNoCondition(t *testing.T) {
	asIs := func(i interpreter.InterpretableV2) interpreter.InterpretableV2 { return otherwise{i, i.ID()} }
	if err := rbac.PlanLoopsOtherwise(t, `request.attributes.m.exists(k, k == "a")`, true, asIs); err == nil {
		t.Error("a loop over a map whose range is planned as something else is a condition")
	}
	if err := rbac.PlanLoopsOtherwise(t, `([1] + [2]).exists(y, y == 2)`, true, asIs); err != nil {
		t.Errorf("a loop over a list whose range is planned as something else: %v", err)
	}
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
// upgrade that moves one shows. This package's own charges move them too: a literal costs 1 for each
// element and 2 for each entry it builds, and a logical operator or a choice 1, so most were bounded
// a few units higher, and one rebuilding a literal of hundreds at each step of a loop at all a
// condition may cost, which fails where it costs more, though it held when it was stored, as a
// grant's gives nothing and a deny's applies (TestAConditionWhoseLiteralsCostMoreThanItMayFails).
// Conditions a scope holds past the bound so are
// evaluated cheapest first within a check's budget
// (TestACheckSpendsABoundedBudgetOnConditionsStoredAroundTheBounds), and a change among them adding
// none isn't refused (TestAChangePastTheBoundIsRefusedOnlyForAConditionItAdds).
func TestStoredConditionsKeepTheirBounds(t *testing.T) {
	rebuilt := "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].all(i, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10].all(j, size([" + strings.Repeat("1,", 699) + "1]) == 700))"
	for _, c := range []struct {
		expr  string
		bound uint64
	}{
		{`request.attributes.mfa == true`, 8},
		{`request.attributes.ip == "10.0.0.1" || request.attributes.ip == "10.0.0.2"`, 17},
		{`resource.attributes.env != "prod" && subject.id in ["a", "b", "c"]`, 31},
		{`request.time < timestamp("2027-01-01T00:00:00Z") && request.time.getHours("America/New_York") >= 9`, 117},
		// The request's time is the timestamp a check passes, which adding to or converting was bounded
		// at 10,000 as anything a map may hold, but where a loop's variable is named request.
		{`request.time + duration("1h") > timestamp("2027-01-01T00:00:00Z")`, 15},
		{`int(request.time) > 1700000000 && string(request.time).startsWith("2026")`, 16},
		{`[request.attributes].exists(request, request.time + "" == "")`, 10000},
		{`request.attributes.ip.startsWith("10.") && "abcdefghijk".contains("bc")`, 10},
		{`request.attributes.ip.endsWith("") || "10.0.0.0/8".startsWith(request.attributes.ip)`, 16},
		{`"abc".matches("^a(b|c){2}$")`, 11},
		{`has(request.attributes.mfa) && request.attributes.x != null`, 15},
		{`dyn(request.attributes)["team"] == "sre" && [1, 2, 3][1] == 2`, 27},
		{`(request.attributes.mfa ? request.attributes.team : "none") == "sre"`, 15},
		{`[request.attributes.x] == [1] && {"a": request.attributes.x} == {"a": 1}`, 106},
		{`[1, 2] + [3] == [1, 2, 3] && "a" + "b" == "ab" && size("abc") == 3 && action == "cluster:login"`, 61},
		{`int("12") == 12 && string(1) == "1" && duration("1h") > duration("1m")`, 16},
		{`[1, 2, 3].all(i, i > 0) && [1, 2, 3].exists_one(i, i == 2) && {"a": 1}.exists(k, k == "a")`, 145},
		{`[[1, 2], [3]].all(l, l.all(i, i > 0))`, 97},
		{`[1, 2, 3].map(x, x > 1, x * 2) == [4, 6]`, 119},
		{`[1, 2].map(x, "ab").all(s, s.contains("a"))`, 76},
		{`["10.0.0.1", "10.0.0.2"].filter(ip, ip.startsWith("10.")).exists(ip, request.attributes.ip == ip)`, 108},
		{`[["10.0.0.1"], ["10.0.0.2"]].exists(g, request.attributes.ip in g) && "time" in request`, 77},
		{`{"dev": 1, "prod": 2}["dev"] <= request.attributes.n`, 48},
		// A zone a literal names is loaded when the condition is planned, and one an attribute names
		// may be loaded as it runs, which costs 500.
		{`request.time.getHours(subject.attributes.zone) >= 9`, 612},
		{`request.time.getHours("+05:30") >= 9 && request.time.getDayOfWeek("Asia/Kolkata") < 5`, 213},
		{`[{"level": 2}, {"level": 3}].exists(r, r.level == request.attributes.n)`, 120},
		// The ids, kinds, types and tenant a check passes are of at most MaxID bytes, and its action a
		// permission's.
		{`resource.attributes.owner == subject.id`, 63},
		{`resource.id.startsWith(subject.id) && resource.tenant == subject.attributes.dept`, 124},
		{`subject.kind + ":" + resource.type in {"user:cluster": true} && subject.id.matches("^svc-")`, 675},
		{`action in {"cluster:login": true, "cluster:read": true}`, 50},
		{`[resource.attributes].exists(subject, subject.owner == .subject.id)`, 85},
		{`{"alice": true, "bob": false}[subject.id]`, 91},
		{`"gpu" in request.attributes.tags`, 10000},
		{`request.attributes.tags.exists(t, t.contains(request.attributes.query))`, 10000},
		// Each step rebuilds the list, which was bounded at 2,082 while a literal cost 10 however long.
		{rebuilt, 10000},
		{`{"dev": 1, "prod": 2}[resource.attributes.env] <= request.attributes.n`, 10000},
		{`request.attributes.tags.exists(t, t == "gpu")`, 10000},
		// A loop over a map sorts its keys first: 1 for each two at each level, and what reading each
		// costs past 1, once.
		{`{"dev": 1, "prod": 2, "staging": 3}.exists(k, k == request.attributes.env)`, 93},
		{`[1, 2, 3].all(i, {"b": i, "a": 2}.map(k, k)[0] == "a")`, 300},
		{`{"a": {"y": 1, "x": 2}, "b": {"z": 3}}.all(k, {"a": {"y": 1, "x": 2}, "b": {"z": 3}}[k].exists(j, j != k))`, 881},
		{`dyn({"b": 1, "a": 2}).map(k, k)[0] == "a"`, 88},
		{`(request.attributes.mfa ? {"b": 1, "a": 2} : {"c": 3}).exists(k, k == "c")`, 98},
	} {
		if limit, _ := rbac.ConditionCost(t, c.expr, nil); limit != c.bound {
			t.Errorf("%s is bounded at %d, not %d", c.expr, limit, c.bound)
		}
	}
	if held, evaluated, _, err := rbac.EvaluateCondition(t, rebuilt, nil); err != nil || held || evaluated {
		t.Errorf("a condition rebuilding a list of 700 at each of 100 steps held %t, evaluated %t: %v", held, evaluated, err)
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
