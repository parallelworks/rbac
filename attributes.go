package rbac

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Attributes declares the attributes conditions read, so that a condition reading one that isn't
// declared, or reading one as another type, is refused when it is stored, rather than being false
// whenever it runs. Each map names attributes and their types; a nil one leaves that kind
// undeclared, read as any value under any name. Declared, they are read as fields, such as
// `resource.attributes.env`, and named as identifiers. A map's entries are declared beside them
// under the map's name in camel case and then Entry, as `TagsEntry` for `tags` and for `_tags`: a
// name no other attribute of its kind may have, nor another map's entries, and that can't begin
// with a digit, as `_1`'s would. A condition stored under other declarations is checked against
// these too, once, when a check first reads it: one that no longer passes, as one reading an
// attribute since declared another type or no longer declared, fails, so a grant's gives nothing, a
// deny's applies, and a requirement isn't met.
//
// A condition reading an attribute a request doesn't carry, or carries as a value CEL reads as
// another type than it is declared, as nil, or as a double that is NaN or infinite, is false when
// it runs, and a deny's applies: a declared attribute passed so fails whatever reads it, comparing
// it with `!=`, testing it with has(), or a map or list holding it, included, and so does reading
// the kind's attributes as a whole, by `in`, size(), a macro or comparing them. A name a declared
// kind doesn't declare, which a condition reads only through dyn(), fails so too. An undeclared
// kind's are read as converted, and CEL compares values of different types as unequal.
//
// What a host passes as a kind's attributes, the subject's, the resource's or the request's, is
// converted, for each check that reads a condition, once and whole, into CEL's own values, and
// conditions read only those, by CEL's own semantics: a string, an int, a uint, a double, a bool,
// bytes, a timestamp, a duration, null, and lists and maps of them. A host may pass, as an
// attribute or within one:
//
//   - nil, and a nil pointer, read as null;
//   - a bool, a string, or an int, a uint or a float of any size, of a type of its own too, as a
//     named string, read by its kind, as no method of the type runs;
//   - a time.Time, a time.Duration, and CEL's own scalar values (types.String and the rest);
//   - bytes ([]byte or an array of bytes), read as bytes;
//   - a slice or an array of these, read as a list;
//   - a map keyed by a bool, a string, an int or a uint, of a type of its own too, or by an
//     interface holding one, of these, read as a map;
//   - a pointer to any of these, read as what it points to;
//   - JSON text (json.RawMessage) and a JSON number (json.Number), parsed;
//   - the protobuf well-known types: a Struct, a ListValue, a Value or a NullValue, a wrapper, a
//     Timestamp, a Duration, and an Any packing one of them but another Any, by its type's name,
//     as no packed message of another type is decoded.
//
// A kind's attributes holding anything else, however deep, are unreadable as a whole, as a policy
// engine fails input it can't read: every condition reading any of them fails, a test of one's
// presence too, so a grant's gives nothing, a deny's applies and a requirement isn't met, while the
// other kinds' are read. So are those holding a ref.Val of the host's own, though it says it is of
// one of CEL's types, a list, a map or an optional of CEL's a host makes, a struct, a channel, a
// func, a complex number, a uintptr, any other message, a map keyed by any other value, as a double
// or an array, a map holding two keys read as the same value, as 1 and 1u, or "a" twice of two
// string types, invalid JSON, a value holding itself, or holding one that does, however long the
// cycle, and a value nested deeper than JSON text may, 10,000 deep, along the longest path through
// what the kind holds, wherever a value it shares with another was reached first. Reading the rest
// would leave each operator to tell what it read from what it couldn't, as `in`, has() and a loop
// over a map's keys each found a key whose value it couldn't read. A value reached twice, as a map
// two lists hold, is converted once, for any kind reaching it. A check converts at most
// maxConverted of what the host passes, counted as reading it costs a condition, one for each value
// and a tenth of each string's, bytes', JSON number's, JSON text's or packed type URL's length, and
// half a packed message's, as a packed value takes as few as two bytes, each kind whole, whether it
// can be read or not: past that, every condition reading an attribute of any kind fails, and JSON
// text that may hold more values than are left isn't parsed. Where a kind nests past 10,000 deep,
// converting stops there, so what it is charged, and whether the kinds after it fit what is left,
// can turn on the order a map's entries come in: either way it can't be read, and the others are
// read or, past what is left, fail. The subject's, the resource's and the request's attributes
// share it, so attributes a tenant's users write, as a resource's tags, can take every check of the
// resource past that, where a grant's condition reading an attribute gives nothing and a deny's
// applies, whoever asks: bound what users may store, or pass conditions only what they read. A
// declared attribute is a value of its type as converted, so a named string type is a string.
type Attributes struct {
	Subject, Resource, Request map[string]AttributeType
}

// AttributeType is a declared attribute's type.
type AttributeType string

// takes reports whether v, an attribute a check converted (Attributes), is a value of type t: a
// []any of strings decoded from JSON is a list of strings, as a []string is.
func (t AttributeType) takes(v ref.Val) bool {
	switch v := v.(type) {
	case types.String:
		return t == AttrString
	case types.Int:
		return t == AttrInt
	case types.Double:
		// NaN compares as false with anything, so a deny ordering it, as `risk >= 0.5`, would lift,
		// and an infinity is NaN once a condition takes it from another.
		return t == AttrDouble && !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0)
	case types.Bool:
		return t == AttrBool
	case types.Timestamp:
		return t == AttrTimestamp
	case types.Duration:
		return t == AttrDuration
	case traits.Lister:
		return t == AttrStrings && allStrings(v.Iterator(), nil)
	case traits.Mapper:
		return t == AttrStringMap && allStrings(v.Iterator(), v)
	}
	return false
}

// allStrings reports whether it yields only strings, and m holds a string under each, if it is a map.
func allStrings(it traits.Iterator, m traits.Mapper) bool {
	for it.HasNext() == types.True {
		k := it.Next()
		if _, ok := k.(types.String); !ok {
			return false
		}
		if m != nil {
			if _, ok := m.Get(k).(types.String); !ok {
				return false
			}
		}
	}
	return true
}

// maxConverted is the most a check converts of what the host passes (Attributes), counted as
// valueSize counts what a condition reads. It is what a check reading a condition may spend at the
// least on one scope's grants' conditions (grantBudget), as converting one costs about what reading
// it does, so converting what a check passes costs no more than its conditions may.
const maxConverted = 2 * maxCheckCost

// maxNested is how deep a value a host passes may nest, as JSON text may (encoding/json): a kind's
// attributes nesting deeper can't be read, and converting them recurses no deeper, as though each
// level costs one, a hundred thousand levels took a check a fifth of a second, growing the stack to
// a hundred mebibytes.
const maxNested = 10000

// converter converts what a host passes for a check into CEL's own values (Attributes), a kind's
// attributes at a time, spending no more than left on them all. It keeps each list, map, pointer,
// message and JSON text it converts by where it points, its length and its type (copiedKey), with
// what it found of it, so one reached twice is converted once, for any kind that reaches it.
type converter struct {
	left uint64
	// over is set once converting cost more than was left, which fails every kind's attributes.
	over bool
	// depth is how deep converting is in the kind it converts.
	depth int
	// unread counts the values converting found no condition can read, as a struct, one holding
	// itself, or one holding either, and deep those it found nested past maxNested.
	unread, deep int
	// done is where in converted each it converted is, by where it points.
	done      map[copiedKey]int
	converted []conversion
	// cut are those of done converting cut short at maxNested in the kind it converts, which it
	// forgets once the kind is converted, as a kind after it may reach them less deep.
	cut []copiedKey
}

// conversion is what a converter found of a value it converted, while open converting it: what it
// is to conditions, and how deep it nests, counting itself, or that no condition can read it.
type conversion struct {
	to                    ref.Val
	height                int
	open, unreadable, cut bool
}

func newConverter() *converter { return &converter{left: maxConverted} }

// attributes is a kind's attributes as conditions read them, by their names, nil for none, and
// whether a condition can read them: where any value they hold, however deep, can't be read, as a
// struct, or nests past maxNested, or holds itself, none can, as the attributes beside one would
// leave each operator reading them to tell what it reads from what it can't. Each is converted, and
// charged, whether one before it could be read or not, so what is left for the kinds after it
// doesn't turn on the order a map's entries come in, but where they nest past maxNested: converting
// stops there, so they are charged for as much of them as it reached first, which that order picks,
// and whether the kinds after them fit what is left can turn on it, failing closed.
func (c *converter) attributes(attributes map[string]any) (map[ref.Val]ref.Val, bool) {
	if len(attributes) == 0 {
		return nil, true
	}
	// Each costs at least its name and its value, so a map for more than are left isn't made, as
	// one for a million took 80 MB, only to find them past it.
	if 2*length(len(attributes)) > c.left {
		c.over, c.left = true, 0
		return nil, false
	}
	unread, deep := c.unread, c.deep
	out := make(map[ref.Val]ref.Val, len(attributes))
	for name, v := range attributes {
		if !c.pay(textLength(len(name))) {
			return nil, false
		}
		out[types.String(name)], _ = c.of(reflect.ValueOf(v))
	}
	for _, k := range c.cut {
		delete(c.done, k)
	}
	c.cut = c.cut[:0]
	return out, c.unread == unread && c.deep == deep
}

var (
	timeType     = reflect.TypeFor[time.Time]()
	durationType = reflect.TypeFor[time.Duration]()
	rawType      = reflect.TypeFor[json.RawMessage]()
	numberType   = reflect.TypeFor[json.Number]()
	nullType     = reflect.TypeFor[structpb.NullValue]()
	refValType   = reflect.TypeFor[ref.Val]()
	messageType  = reflect.TypeFor[proto.Message]()
)

// of is v as a condition reads it, one of CEL's own values, and how deep it nests, counting itself,
// or nil where no condition can read it (refuse), it nests past maxNested, or converting it costs
// more than is left. It reads v by its kind, but for the types Attributes names, and calls no
// method of the host's. Each value costs one, one that can't be read too, and a string, bytes or
// JSON text a tenth of its length more, as reading it does, so converting reaches no more values
// than it may cost.
func (c *converter) of(v reflect.Value) (ref.Val, int) {
	if !c.pay(1) {
		return nil, 0
	}
	if c.depth >= maxNested {
		c.deep++
		return nil, 0
	}
	c.depth++
	defer func() { c.depth-- }()
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return types.NullValue, 1
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return types.NullValue, 1
	}
	t := v.Type()
	switch t {
	case timeType:
		at, _ := v.Interface().(time.Time)
		return types.Timestamp{Time: at}, 1
	case durationType:
		return types.Duration{Duration: time.Duration(v.Int())}, 1
	case rawType:
		return c.json(v)
	case numberType:
		return c.number(v.String()), 1
	case nullType:
		return types.NullValue, 1
	}
	// A value of a type of the host's own CEL would read by its methods, as one saying it is a
	// double or a list, is read so by none. A pointer has the methods of what it points to, so one to
	// CEL's own string is read as the string, as any other pointer is read as what it points to.
	if t.Implements(refValType) && (t.Kind() != reflect.Pointer || !t.Elem().Implements(refValType)) {
		if v, ok := v.Interface().(ref.Val); ok && celScalar(v) {
			return c.spend(textSize(v)-1, v), 1
		}
		return c.refuse(), 1
	}
	if t.Implements(messageType) {
		return c.message(v)
	}
	switch v.Kind() {
	case reflect.Bool:
		return types.Bool(v.Bool()), 1
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return types.Int(v.Int()), 1
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return types.Uint(v.Uint()), 1
	case reflect.Float32, reflect.Float64:
		return types.Double(v.Float()), 1
	case reflect.String:
		s := v.String()
		return c.spend(uint64(len(s))/10, types.String(s)), 1
	case reflect.Pointer:
		if v.IsNil() {
			return types.NullValue, 1
		}
		return c.once(v, func() (ref.Val, int) {
			to, height := c.of(v.Elem())
			return to, height + 1
		})
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return c.bytes(v), 1
		}
		return c.once(v, func() (ref.Val, int) { return c.list(v) })
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return c.bytes(v), 1
		}
		return c.list(v)
	case reflect.Map:
		return c.once(v, func() (ref.Val, int) { return c.dict(v) })
	default:
	}
	return c.refuse(), 1
}

// refuse counts a value no condition can read, which makes its kind's attributes unreadable.
func (c *converter) refuse() ref.Val {
	c.unread++
	return nil
}

// celScalar reports whether v is one of CEL's own values that holds no other.
func celScalar(v ref.Val) bool {
	switch v.(type) {
	case types.Bool, types.Bytes, types.Double, types.Duration, types.Int, types.Null, types.String, types.Timestamp,
		types.Uint:
		return true
	}
	return false
}

// textLength is what reading text of n bytes costs, as textSize counts it.
func textLength(n int) uint64 { return 1 + length(n)/10 }

func length(n int) uint64 { return uint64(max(n, 0)) }

// pay spends n, or reports that it can't, once converting has cost more than maxConverted.
func (c *converter) pay(n uint64) bool {
	if c.over || n > c.left {
		c.over, c.left = true, 0
		return false
	}
	c.left -= n
	return true
}

// spend is v, which converting cost n, or nil once it costs more than is left.
func (c *converter) spend(n uint64, v ref.Val) ref.Val {
	if !c.pay(n) {
		return nil
	}
	return v
}

// once is what convert makes of v, which points somewhere, and how deep it nests, converted once
// for the check. One reached again while it is converted holds itself, or holds one that holds it,
// and can't be read, nor can one holding it, of any kind. One that can't be read is kept so, as no
// kind reaching it can read it; one nesting past maxNested where it was reached is kept so for the
// rest of the kind, which nests too deep wherever it reaches it again, but not for a kind after it,
// which may reach it less deep: converted again for each path reaching it, a ladder of a hundred
// maps each holding both of the next two, nested 10,000 deep, went past maxConverted, failing every
// kind; and one converted whole is kept with how deep it nests, so it fails where it is reached too
// deep for that, wherever it was first reached: whether a kind's attributes nest past maxNested, as
// whether they hold one holding itself, is of what they hold, whatever order a map's entries come
// in or a kind before it reached a value first.
func (c *converter) once(v reflect.Value, convert func() (ref.Val, int)) (ref.Val, int) {
	k, _ := copiedKeyOf(v)
	if i, ok := c.done[k]; ok {
		switch d := c.converted[i]; {
		case d.open || d.unreadable:
			return c.refuse(), 0
		case d.cut || c.depth+d.height-1 > maxNested:
			c.deep++
			return nil, 0
		default:
			return d.to, d.height
		}
	}
	if c.done == nil {
		c.done = map[copiedKey]int{}
	}
	i := len(c.converted)
	c.done[k] = i
	c.converted = append(c.converted, conversion{open: true})
	unread, deep := c.unread, c.deep
	to, height := convert()
	d := &c.converted[i]
	d.open = false
	switch {
	case c.unread != unread:
		d.unreadable = true
	case c.over:
		delete(c.done, k)
	case c.deep != deep:
		d.cut = true
		c.cut = append(c.cut, k)
	default:
		d.to, d.height = to, height
	}
	return to, height
}

// bytes is v, a slice or an array of bytes, as bytes, an array's copied into one of its own type:
// reflection copies only between arrays of one element type, and panicked, outside any condition,
// copying an array of a byte type of the host's own into a []byte.
func (c *converter) bytes(v reflect.Value) ref.Val {
	if !c.pay(length(v.Len()) / 10) {
		return nil
	}
	if v.Kind() == reflect.Slice {
		return types.Bytes(v.Bytes())
	}
	b := reflect.New(v.Type()).Elem()
	b.Set(v)
	return types.Bytes(b.Bytes())
}

// list is v, a slice or an array, as a list of what it holds, and how deep it nests.
func (c *converter) list(v reflect.Value) (ref.Val, int) {
	// Each costs at least one, so a list longer than is left can't be converted.
	if length(v.Len()) > c.left {
		c.over, c.left = true, 0
		return nil, 0
	}
	out, height := make([]ref.Val, v.Len()), 0
	for i := range out {
		var h int
		if out[i], h = c.of(v.Index(i)); c.over {
			return nil, 0
		}
		height = max(height, h)
	}
	return types.NewRefValList(types.DefaultTypeAdapter, out), height + 1
}

// dict is v, a map, as a map of what it holds by what its keys are read as, and how deep it nests.
// No condition can read one keyed by another kind than Attributes names, nor one holding two keys
// read as the same value.
func (c *converter) dict(v reflect.Value) (ref.Val, int) {
	if kt := v.Type().Key(); kt.Kind() != reflect.Interface && !keyType(kt) {
		return c.refuse(), 1
	}
	if 2*length(v.Len()) > c.left {
		c.over, c.left = true, 0
		return nil, 0
	}
	out, height := make(map[ref.Val]ref.Val, v.Len()), 0
	// Each entry is read into the same two values, as reading it into new ones allocates for each,
	// a string key or an interface value too: nothing converting reads keeps them.
	key, value := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
	for it := v.MapRange(); it.Next(); {
		key.SetIterKey(it)
		value.SetIterValue(it)
		k := c.key(key)
		held, h := c.of(value)
		if c.over {
			return nil, 0
		}
		height = max(height, h)
		switch {
		case k == nil:
		case holdsKey(out, k):
			c.refuse()
		default:
			out[k] = held
		}
	}
	return types.NewRefValMap(types.DefaultTypeAdapter, out), height + 1
}

// key is k, a map's key, as a condition reads it: a bool, a string, an int or a uint, or nil.
func (c *converter) key(k reflect.Value) ref.Val {
	if !c.pay(1) {
		return nil
	}
	if k.Kind() == reflect.Interface {
		if k.IsNil() {
			return c.refuse()
		}
		k = k.Elem()
	}
	t := k.Type()
	if t.Implements(refValType) {
		if v, ok := k.Interface().(ref.Val); ok && keyType(t) {
			return c.spend(textSize(v)-1, v)
		}
		return c.refuse()
	}
	switch k.Kind() {
	case reflect.Bool:
		return types.Bool(k.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return types.Int(k.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return types.Uint(k.Uint())
	case reflect.String:
		s := k.String()
		return c.spend(uint64(len(s))/10, types.String(s))
	default:
	}
	return c.refuse()
}

// keyType reports whether a map keyed by values of type t is keyed as Attributes names, empty too.
func keyType(t reflect.Type) bool {
	if t.Implements(refValType) {
		switch t {
		case reflect.TypeFor[types.Bool](), reflect.TypeFor[types.Int](), reflect.TypeFor[types.String](), reflect.TypeFor[types.Uint]():
			return true
		}
		return false
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.String:
		return true
	default:
	}
	return false
}

// holdsKey reports whether m holds k, or a key CEL finds equal to it, as 1u for 1.
func holdsKey(m map[ref.Val]ref.Val, k ref.Val) bool {
	if _, ok := m[k]; ok {
		return true
	}
	var other ref.Val
	switch k := k.(type) {
	case types.Int:
		if k >= 0 {
			other = types.Uint(k)
		}
	case types.Uint:
		if k <= math.MaxInt64 {
			other = types.Int(k)
		}
	}
	_, ok := m[other]
	return other != nil && ok
}

// json is v, JSON text, parsed, at a tenth of its length, once for each text a check passes, and
// how deep it nests. Text that may hold more values than are left isn't parsed: a value takes as
// few as two bytes, as `0,`, and parsing a mebibyte of them, only to find more than a check may
// convert, took a tenth of a second and 80 MB.
func (c *converter) json(v reflect.Value) (ref.Val, int) {
	return c.once(v, func() (ref.Val, int) {
		if !c.pay(length(v.Len()) / 10) {
			return nil, 0
		}
		if jsonValues(v.Bytes()) > c.left {
			c.over, c.left = true, 0
			return nil, 0
		}
		var parsed any
		if err := json.Unmarshal(v.Bytes(), &parsed); err != nil {
			return c.refuse(), 1
		}
		to, height := c.of(reflect.ValueOf(parsed))
		return to, height + 1
	})
}

// jsonValues is at least how many values and keys JSON text text holds: each but the first follows
// a bracket, a brace, a comma or a colon outside a string.
func jsonValues(text []byte) uint64 {
	n, quoted := uint64(1), false
	for i := 0; i < len(text); i++ {
		switch b := text[i]; {
		case quoted && b == '\\':
			i++
		case b == '"':
			quoted = !quoted
		case !quoted && (b == '[' || b == '{' || b == ',' || b == ':'):
			n++
		}
	}
	return n
}

// number is n, a JSON number, an int where it is one and a double where it isn't, as CEL reads it,
// at a tenth of its length whether it is one or not, as parsing it reads it whole, or nil.
func (c *converter) number(n string) ref.Val {
	if !c.pay(uint64(len(n)) / 10) {
		return nil
	}
	if i, err := json.Number(n).Int64(); err == nil {
		return types.Int(i)
	}
	if f, err := json.Number(n).Float64(); err == nil {
		return types.Double(f)
	}
	return c.refuse()
}

// message is v, a protobuf message, as a condition reads it, one of the well-known types
// Attributes names, read by its fields, each as of reads it, and how deep it nests; or nil.
func (c *converter) message(v reflect.Value) (ref.Val, int) {
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return types.NullValue, 1
	}
	switch m := v.Interface().(type) {
	case *structpb.Struct:
		return c.once(v, func() (ref.Val, int) {
			if 2*uint64(len(m.GetFields())) > c.left {
				c.over, c.left = true, 0
				return nil, 0
			}
			out, height := make(map[ref.Val]ref.Val, len(m.GetFields())), 0
			for k, field := range m.GetFields() {
				key := c.spend(textLength(len(k)), types.String(k))
				held, h := c.of(reflect.ValueOf(field))
				if c.over {
					return nil, 0
				}
				out[key], height = held, max(height, h)
			}
			return types.NewRefValMap(types.DefaultTypeAdapter, out), height + 1
		})
	case *structpb.ListValue:
		return c.once(v, func() (ref.Val, int) {
			if uint64(len(m.GetValues())) > c.left {
				c.over, c.left = true, 0
				return nil, 0
			}
			out, height := make([]ref.Val, len(m.GetValues())), 0
			for i, e := range m.GetValues() {
				var h int
				if out[i], h = c.of(reflect.ValueOf(e)); c.over {
					return nil, 0
				}
				height = max(height, h)
			}
			return types.NewRefValList(types.DefaultTypeAdapter, out), height + 1
		})
	case *structpb.Value:
		// A kind that is a nil of its type, as `Kind: (*structpb.Value_StructValue)(nil)`, is none to
		// protobuf's reflection, and so to a hook's copy, as an unset kind is; reading what it holds
		// panicked, outside any condition, ending the check.
		if k := reflect.ValueOf(m.GetKind()); k.IsValid() && k.IsNil() {
			return types.NullValue, 1
		}
		var held reflect.Value
		switch k := m.GetKind().(type) {
		case *structpb.Value_NumberValue:
			return types.Double(k.NumberValue), 1
		case *structpb.Value_StringValue:
			return c.spend(uint64(len(k.StringValue))/10, types.String(k.StringValue)), 1
		case *structpb.Value_BoolValue:
			return types.Bool(k.BoolValue), 1
		case *structpb.Value_StructValue:
			held = reflect.ValueOf(k.StructValue)
		case *structpb.Value_ListValue:
			held = reflect.ValueOf(k.ListValue)
		default:
			return types.NullValue, 1
		}
		to, height := c.of(held)
		return to, height + 1
	case *wrapperspb.BoolValue:
		return types.Bool(m.GetValue()), 1
	case *wrapperspb.BytesValue:
		return c.spend(uint64(len(m.GetValue()))/10, types.Bytes(m.GetValue())), 1
	case *wrapperspb.DoubleValue:
		return types.Double(m.GetValue()), 1
	case *wrapperspb.FloatValue:
		return types.Double(m.GetValue()), 1
	case *wrapperspb.Int32Value:
		return types.Int(m.GetValue()), 1
	case *wrapperspb.Int64Value:
		return types.Int(m.GetValue()), 1
	case *wrapperspb.StringValue:
		return c.spend(uint64(len(m.GetValue()))/10, types.String(m.GetValue())), 1
	case *wrapperspb.UInt32Value:
		return types.Uint(m.GetValue()), 1
	case *wrapperspb.UInt64Value:
		return types.Uint(m.GetValue()), 1
	case *timestamppb.Timestamp:
		return types.Timestamp{Time: m.AsTime()}, 1
	case *durationpb.Duration:
		return types.Duration{Duration: m.AsDuration()}, 1
	case *anypb.Any:
		return c.once(v, func() (ref.Val, int) {
			// Finding the type hashes its URL whole, and a packed value takes as few as two bytes, as an
			// empty one in a list does: Anys sharing a mebibyte's URL, each charged one, took a third of
			// a millisecond each, and decoding a mebibyte of values, only to find more than a check may
			// convert, took a tenth of a second.
			if !c.pay(uint64(len(m.GetTypeUrl()))/10 + uint64(len(m.GetValue()))/2) {
				return nil, 0
			}
			unpacked, ok := packable[m.MessageName()]
			if !ok {
				return c.refuse(), 1
			}
			packed := unpacked()
			if err := proto.Unmarshal(m.GetValue(), packed); err != nil {
				return c.refuse(), 1
			}
			to, height := c.of(reflect.ValueOf(packed))
			return to, height + 1
		})
	}
	return c.refuse(), 1
}

// packable makes a new message of each type a condition reads packed in an Any, by the type's
// name, so no other is decoded: finding one of another type by the registry, as unpacking an Any
// does, runs the host's own code, its type's New or a message's own Unmarshal, which can panic on
// what it decodes, outside any condition, ending the check.
var packable = func() map[protoreflect.FullName]func() proto.Message {
	made := map[protoreflect.FullName]func() proto.Message{}
	for _, m := range []proto.Message{
		&structpb.Struct{}, &structpb.ListValue{}, &structpb.Value{}, &wrapperspb.BoolValue{}, &wrapperspb.BytesValue{},
		&wrapperspb.DoubleValue{}, &wrapperspb.FloatValue{}, &wrapperspb.Int32Value{}, &wrapperspb.Int64Value{},
		&wrapperspb.StringValue{}, &wrapperspb.UInt32Value{}, &wrapperspb.UInt64Value{}, &timestamppb.Timestamp{},
		&durationpb.Duration{},
	} {
		t := m.ProtoReflect().Type()
		made[t.Descriptor().FullName()] = func() proto.Message { return t.New().Interface() }
	}
	return made
}()

// The types an attribute can be declared as, with the Go value a host passes for each, or any
// other converted to that type (Attributes), such as a pointer to a string, number or bool, a
// protobuf timestamp or duration, or a []any or map[string]any of strings. A nil pointer is null,
// which is none.
const (
	AttrString    AttributeType = "string"              // string
	AttrInt       AttributeType = "int"                 // int or int64
	AttrDouble    AttributeType = "double"              // float64, finite
	AttrBool      AttributeType = "bool"                // bool
	AttrTimestamp AttributeType = "timestamp"           // time.Time
	AttrDuration  AttributeType = "duration"            // time.Duration
	AttrStrings   AttributeType = "list(string)"        // []string
	AttrStringMap AttributeType = "map(string, string)" // map[string]string
)

var attributeName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

// celReserved are the words CEL refuses as a field name.
var celReserved = []string{
	"as", "break", "const", "continue", "else", "false", "for", "function", "if", "import", "in", "let", "loop",
	"package", "namespace", "null", "return", "true", "var", "void", "while",
}

// mapEntryName is the name protobuf requires of a map field's entry: the field's name in camel
// case, then Entry.
func mapEntryName(field string) string {
	var b strings.Builder
	upper := true
	for _, r := range field {
		switch {
		case r == '_':
			upper = true
		case upper:
			b.WriteRune(unicode.ToUpper(r))
			upper = false
		default:
			b.WriteRune(r)
		}
	}
	return b.String() + "Entry"
}

// typing returns an environment that type-checks conditions against the declared attributes, or
// nil when none are. Conditions run in the untyped one, where an attribute a request doesn't
// carry is an error, and so false: proto fields, which this declares them as, read as their zero
// value instead.
func typing(attrs Attributes) (*cel.Env, error) {
	if attrs.Subject == nil && attrs.Resource == nil && attrs.Request == nil {
		return nil, nil
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:       proto.String("rbac/attributes.proto"),
		Package:    proto.String("rbac"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"google/protobuf/duration.proto", "google/protobuf/struct.proto", "google/protobuf/timestamp.proto"},
	}
	field := func(name string, number int32, t descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(number), Type: t.Enum(),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), JsonName: proto.String(name),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	str, message := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	// attributes is a kind's attributes field, numbered n: a message of the declared ones, or for an
	// undeclared kind a Struct, any value under any name.
	attributes := func(kind string, n int32, declared map[string]AttributeType) (*descriptorpb.FieldDescriptorProto, error) {
		if declared == nil {
			return field("attributes", n, message, ".google.protobuf.Struct"), nil
		}
		msg := &descriptorpb.DescriptorProto{Name: proto.String(kind + "Attributes")}
		// entries are the maps by the name of their entries.
		entries := map[string]string{}
		for i, name := range slices.Sorted(maps.Keys(declared)) {
			if !attributeName.MatchString(name) || slices.Contains(celReserved, name) {
				return nil, fmt.Errorf("rbac: %s attribute %q is not an identifier", kind, name)
			}
			number := int32(i + 1)
			var f *descriptorpb.FieldDescriptorProto
			switch declared[name] {
			case AttrString:
				f = field(name, number, str, "")
			case AttrInt:
				f = field(name, number, descriptorpb.FieldDescriptorProto_TYPE_INT64, "")
			case AttrDouble:
				f = field(name, number, descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, "")
			case AttrBool:
				f = field(name, number, descriptorpb.FieldDescriptorProto_TYPE_BOOL, "")
			case AttrTimestamp:
				f = field(name, number, message, ".google.protobuf.Timestamp")
			case AttrDuration:
				f = field(name, number, message, ".google.protobuf.Duration")
			case AttrStrings:
				f = field(name, number, str, "")
				f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
			case AttrStringMap:
				// A map is a repeated entry of a key and a value, a message named for its field beside the
				// fields, which protobuf refuses named as a field or another map's entry is, or beginning
				// with a digit, with an error naming neither attribute.
				entry := mapEntryName(name)
				if !protoreflect.Name(entry).IsValid() {
					return nil, fmt.Errorf("rbac: %s attribute %q can't be a map: its entries would be named %q, which isn't an identifier", kind, name, entry)
				}
				if _, ok := declared[entry]; ok {
					return nil, fmt.Errorf("rbac: %s attributes %q and %q can't both be declared: the entries of the map %q are named %q", kind, name, entry, name, entry)
				}
				if other, ok := entries[entry]; ok {
					return nil, fmt.Errorf("rbac: %s attributes %q and %q can't both be declared: the entries of both maps are named %q", kind, other, name, entry)
				}
				entries[entry] = name
				msg.NestedType = append(msg.NestedType, &descriptorpb.DescriptorProto{
					Name:    proto.String(entry),
					Field:   []*descriptorpb.FieldDescriptorProto{field("key", 1, str, ""), field("value", 2, str, "")},
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				})
				f = field(name, number, message, ".rbac."+kind+"Attributes."+entry)
				f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
			default:
				return nil, fmt.Errorf("rbac: %s attribute %q has no type %q", kind, name, declared[name])
			}
			msg.Field = append(msg.Field, f)
		}
		file.MessageType = append(file.MessageType, msg)
		return field("attributes", n, message, ".rbac."+kind+"Attributes"), nil
	}
	subject, err := attributes("Subject", 3, attrs.Subject)
	if err != nil {
		return nil, err
	}
	resource, err := attributes("Resource", 4, attrs.Resource)
	if err != nil {
		return nil, err
	}
	request, err := attributes("Request", 2, attrs.Request)
	if err != nil {
		return nil, err
	}
	file.MessageType = append(file.MessageType,
		&descriptorpb.DescriptorProto{Name: proto.String("Subject"), Field: []*descriptorpb.FieldDescriptorProto{
			field("kind", 1, str, ""), field("id", 2, str, ""), subject,
		}},
		&descriptorpb.DescriptorProto{Name: proto.String("Resource"), Field: []*descriptorpb.FieldDescriptorProto{
			field("type", 1, str, ""), field("id", 2, str, ""), field("tenant", 3, str, ""), resource,
		}},
		&descriptorpb.DescriptorProto{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{
			field("time", 1, message, ".google.protobuf.Timestamp"), request,
		}},
	)
	desc, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		return nil, fmt.Errorf("rbac: declaring attributes: %w", err)
	}
	return cel.NewEnv(
		cel.ParserRecursionLimit(maxDepth),
		cel.TypeDescs(desc),
		cel.Variable("subject", cel.ObjectType("rbac.Subject")),
		cel.Variable("resource", cel.ObjectType("rbac.Resource")),
		cel.Variable("request", cel.ObjectType("rbac.Request")),
		cel.Variable("action", cel.StringType),
	)
}

// deepCopy is a copy of v whose maps, slices, arrays, pointers and structs' exported fields are its
// own, to maxCopied deep, past which it holds their zero values, a protobuf message among them
// copied field by field, as cloning it would, and a value reached twice copied once, a message too,
// so a cycle ends. A struct's fields an
// unexported struct it embeds promotes are its own too, but its other unexported fields are shared,
// a pointer it embeds unexported among them, and so the fields that one promotes: reflection can't
// set them. A map's keys are shared too, and what a pointer among them reaches: a copied key would
// be another key, so the copy would find nothing under the one the host passed.
func deepCopy[T any](v T) T {
	out := reflect.ValueOf(&v).Elem()
	out.Set(copier{}.copy(out, 0))
	return v
}

// maxCopied is how deep deepCopy copies a value, past which the copy holds the zero value, or the
// copy of one it copied less deep: copying recurses as deep as the value nests, and a list nested
// three million deep overflowed the stack, which no recover catches, ending the process wherever a
// hook was asked about it. No condition reads what lies deeper (maxNested), and sharing it would let
// a hook write to what the host holds less deep too.
const maxCopied = 2 * maxNested

// copier copies values for deepCopy, keeping each map, slice and pointer it copied by where it
// points, its length and its type.
type copier map[copiedKey]reflect.Value

type copiedKey struct {
	t   reflect.Type
	at  uintptr
	len int
}

// copiedKeyOf is how copier and converter know v: a map, pointer, slice or string by where it
// points, its length and its type. One held by value, which points nowhere, has no key.
func copiedKeyOf(v reflect.Value) (copiedKey, bool) {
	switch v.Kind() {
	case reflect.Map, reflect.Pointer:
		return copiedKey{v.Type(), v.Pointer(), 0}, true
	case reflect.Slice, reflect.String:
		return copiedKey{v.Type(), v.Pointer(), v.Len()}, true
	default:
		return copiedKey{}, false
	}
}

// copy is a copy of v, which is depth deep, or past maxCopied deep its zero value, not kept, so a
// copy reaching it less deep copies it.
func (c copier) copy(v reflect.Value, depth int) reflect.Value {
	if v.Kind() != reflect.Interface {
		if depth >= maxCopied {
			if k, ok := copiedKeyOf(v); ok && c[k].IsValid() {
				return c[k]
			}
			return reflect.Zero(v.Type())
		}
		depth++
	}
	switch v.Kind() {
	case reflect.Interface:
		if unreachable(v) {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(c.copy(v.Elem(), depth))
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		k, _ := copiedKeyOf(v)
		if done, ok := c[k]; ok {
			return done
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		c[k] = out
		for it := v.MapRange(); it.Next(); {
			out.SetMapIndex(it.Key(), c.copy(it.Value(), depth))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		k, _ := copiedKeyOf(v)
		if done, ok := c[k]; ok {
			return done
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		c[k] = out
		// Each hook is given its own, so elements no write could reach through are copied at once.
		reflect.Copy(out, v)
		if flat(v.Type().Elem()) {
			return out
		}
		for i := range v.Len() {
			if e := v.Index(i); !unreachable(e) {
				out.Index(i).Set(c.copy(e, depth))
			}
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		c.fields(out, v, depth)
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := range v.Len() {
			out.Index(i).Set(c.copy(v.Index(i), depth))
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		k, _ := copiedKeyOf(v)
		if done, ok := c[k]; ok {
			return done
		}
		if m, ok := v.Interface().(proto.Message); ok && itself(m) {
			return reflect.ValueOf(c.message(m.ProtoReflect(), depth).Interface())
		}
		out := reflect.New(v.Type().Elem())
		c[k] = out
		out.Elem().Set(c.copy(v.Elem(), depth))
		return out
	default:
		return v
	}
}

// message is a copy of m, as cloning it would make, but keeping each message it copies by where it
// points, as copy keeps pointers: cloning keeps none, so a message holding itself, as a Struct one
// of whose fields holds it, recursed until the stack overflowed, which no recover catches, and one
// reaching another twice copied it for each path to it. A nil message, as a list may hold, is copied
// as a new one each time, as cloning copies it: each is the same nil, but none is another's.
func (c copier) message(m protoreflect.Message, depth int) protoreflect.Message {
	if !m.IsValid() {
		return m.New()
	}
	k, keyed := copiedKeyOf(reflect.ValueOf(m.Interface()))
	if depth >= maxCopied {
		if done, ok := c[k]; keyed && ok {
			if d, ok := done.Interface().(proto.Message); ok {
				return d.ProtoReflect()
			}
		}
		return m.New()
	}
	depth++
	if done, ok := c[k]; keyed && ok {
		if d, ok := done.Interface().(proto.Message); ok {
			return d.ProtoReflect()
		}
	}
	out := m.New()
	if keyed {
		c[k] = reflect.ValueOf(out.Interface())
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			from, to := v.List(), out.Mutable(fd).List()
			for i := range from.Len() {
				to.Append(c.field(fd, from.Get(i), depth))
			}
		case fd.IsMap():
			to := out.Mutable(fd).Map()
			v.Map().Range(func(key protoreflect.MapKey, v protoreflect.Value) bool {
				to.Set(key, c.field(fd.MapValue(), v, depth))
				return true
			})
		default:
			out.Set(fd, c.field(fd, v, depth))
		}
		return true
	})
	if unknown := m.GetUnknown(); len(unknown) > 0 {
		out.SetUnknown(slices.Clone(unknown))
	}
	return out
}

// field is a copy of v, a value of a field fd describes or of one of its elements: a message as
// message copies it, bytes as bytes of its own, and the rest as it is, which nothing writes to.
func (c copier) field(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protoreflect.ValueOfMessage(c.message(v.Message(), depth))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(slices.Clone(v.Bytes()))
	default:
		return v
	}
}

// itself reports whether m is a message as itself, so copied as one: a host's type embedding one is
// a message by the methods it promotes, and copying its message would return the embedded one in
// its place, or panic where it embeds the message interface holding none.
func itself(m proto.Message) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return m.ProtoReflect().Interface() == m
}

// fields copies into out, a copy of the struct v, the fields a hook can write to: its exported
// ones, and those an unexported struct it embeds promotes, which reflection sets as the language
// does. Its other unexported fields a hook reaches only through the type's methods.
func (c copier) fields(out, v reflect.Value, depth int) {
	for i := range v.NumField() {
		switch f := out.Field(i); {
		case f.CanSet():
			f.Set(c.copy(v.Field(i), depth))
		case v.Type().Field(i).Anonymous && f.Kind() == reflect.Struct:
			c.fields(f, v.Field(i), depth)
		}
	}
}

// unreachable reports whether no write could reach through v, an interface: nil, or holding a value
// of a flat type, as each of an []any of strings decoded from JSON does, which boxing again would
// cost an allocation for each.
func unreachable(v reflect.Value) bool {
	return v.Kind() == reflect.Interface && (v.IsNil() || flat(v.Elem().Type()))
}

// flat reports whether a value of type t holds no map, slice or pointer a copy would share.
func flat(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
		return true
	default:
		return false
	}
}
