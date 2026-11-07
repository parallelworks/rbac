package rbac

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/encoding/protowire"
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
// the kind's attributes as a whole, by `in`, size(), a macro, comparing them or a list or a map
// holding them, or the subject, the resource or the request holding them, as reading the attributes
// of a kind no condition can read does. A name a declared kind doesn't declare, which a condition
// reads only through dyn(), fails so too, and so does one holding a double that is NaN or
// infinite, however deep: comparing reads the smaller value whole and the larger only as far, so a
// list holding NaN beside a long string was compared by the string, and
// `request.attributes.scores != [1, 2]` held. An undeclared kind's are read as converted, and CEL
// compares values of different types as unequal; but one holding such a double, however deep, is
// unreadable as a whole, below.
//
// What a host passes as a kind's attributes, the subject's, the resource's or the request's, is
// converted, where a check reads a condition, once and whole, into CEL's own values, and
// conditions read only those, by CEL's own semantics: a string, an int, a uint, a double, a bool,
// bytes, a timestamp, a duration, null, and lists and maps of them. A host may pass, as an
// attribute or within one:
//
//   - nil, and a nil pointer, read as null;
//   - a bool, a string, or an int, a uint or a float of any size, of a type of its own too, as a
//     named string, read by its kind, as no method of the type runs;
//   - a time.Time, a time.Duration, and CEL's own scalar values (types.String and the rest), a
//     time read as the instant it is, in UTC, as a protobuf Timestamp is, whatever zone the host
//     keeps it in: CEL keeps a time's zone, which string() writes it in, so a time read from a
//     clock or a database in each replica's local zone would decide by where the replica runs;
//   - bytes ([]byte or an array of bytes), read as bytes;
//   - a slice or an array of these, read as a list;
//   - a map keyed by a bool, a string, an int or a uint, of a type of its own too, or by an
//     interface holding one, of these, read as a map;
//   - a pointer to any of these, read as what it points to;
//   - JSON text (json.RawMessage) and a JSON number (json.Number), parsed, a nil json.RawMessage
//     read as null, as encoding/json writes it;
//   - the protobuf well-known types: a Struct, a ListValue, a Value or a NullValue, a wrapper, a
//     Timestamp, a Duration, and an Any packing one of them but another Any, by its type's name,
//     as no packed message of another type is decoded.
//
// A kind's attributes holding anything else, however deep, are unreadable as a whole, as a policy
// engine fails input it can't read: every condition reading any of them fails, a test of one's
// presence too, so a grant's gives nothing, a deny's applies and a requirement isn't met, while the
// other kinds' are read. So are an undeclared kind's holding a double that is NaN or infinite,
// however deep, as no declarations name what its conditions read: refused by name alone, a deny's
// `request.attributes.region == "eu" && request.attributes.risk > 0.5` lifted outside the EU for an
// infinite float64 risk, where the same infinity as JSON text, 1e400, which a host reading JSON
// reads none of, applied it. So are those holding a ref.Val of the host's own, though it says it is
// of one of CEL's types, a list, a map or an optional of CEL's a host makes, a struct, a channel, a
// func, a complex number, a uintptr, any other message, a map keyed by any other value, as a double
// or an array, a map holding two keys read as the same value, as 1 and 1u, or "a" twice of two
// string types, and so JSON text naming a member of an object twice, as "role" and "r\u006fle" are
// once unescaped, or an Any packing a message that sets a field twice, as a Struct with two entries
// of "role", which decoding reads as the last, where a reader of the first reads another: a Struct
// the host passes holds each key once, as a Go map does. So are invalid JSON, JSON text that isn't
// UTF-8 or escapes half a surrogate pair, which encoding/json reads as U+FFFD, a json.Number that
// isn't a number as JSON writes one, as "0x1p4" or "Inf", a value holding itself, or holding one
// that does, however long the cycle, and a value nested deeper than JSON text may, 10,000 deep,
// along the longest path through what the kind holds, wherever a value it shares with another was
// reached first. Reading the rest would leave each operator to tell what it read from what it
// couldn't, as `in`, has() and a loop over a map's keys each found a key whose value it couldn't
// read; and a condition keying a map by them, comparing them or finding them in a list, building a
// list or a map holding them, or reading the subject, the resource or the request holding them
// whole, fails too, as every kind's no condition reads are the same value: built, a list holding
// them was decided by its size, or by another value it held. A value reached twice, as a map two
// lists hold, is converted once, for any kind reaching it, but a resource's sharing it, below. A
// check converts at most maxConverted of what the host passes, counted as reading it costs a
// condition, one for each value and a tenth of each string's, bytes', JSON number's, JSON text's or
// packed type URL's length, and half a packed message's, as a packed value takes as few as two
// bytes, but for what building a value costs more: 8 for each map, Struct or JSON object, and 4 for
// each list, ListValue or JSON array, each pointer, but to a message, and each other message. So a
// unit converted costs about what one read does, 20 to 115 ns, and a check converts no more than
// its conditions may spend reading, about 20 ms, where charged one each, as a number is, 160,000
// empty maps took 93 ms. Each kind is converted whole, whether it can be read or not, but a map of
// structs, which no condition reads, is refused unread, charged 2 for each entry: reading an entry
// copies it whole, and a map of 2,000 structs of 64 KiB, charged as much, took 7 ms. Past that,
// every condition reading an attribute of any kind fails, as it does where JSON text may cost more
// than that, by its brackets, braces, commas and colons, which isn't parsed. A call converts the
// subject's and the request's attributes once, the first time one of its checks reads a condition,
// for every check it makes with them, as a change does on each scope it reaches, and each check its
// resource's apart, after them, from what they left, counting all three as its own, so whether a
// check is past that doesn't turn on how many the call makes: a value the resource's share with
// them is converted, and counted, again. So change none of what the host passed while the call
// runs, as from a hook: a check after the change can read the subject's or the request's attributes
// as they were, though never another value as one of them. Where a kind nests past 10,000 deep,
// converting stops there, so what it is charged, and whether the kinds after it fit what is left,
// can turn on the order a map's entries come in: either way it can't be read, and the others are
// read or, past what is left, fail. Nothing else converting finds turns on that order, nor on the
// order of the kinds, and no condition reads it: a loop gives a map's keys in an order of their
// own (Condition). The subject's, the resource's and the request's attributes share what a check
// converts, so attributes a tenant's users write, as a resource's tags, can take every check of the
// resource past it, where a grant's condition reading an attribute gives nothing and a deny's
// applies, whoever asks: bound what users may store, or pass conditions only what they read. A
// hook, a constraint or ValidateGrant, is given a copy of the subject's or the resource's
// attributes, or the actor's, of no more than that either, counted as converting counts it,
// whatever the copy shares, but for what JSON text and packed messages decode to, which it holds as
// bytes, so it can be given whatever a check converts; past that it can't be asked and the call is
// refused (ConstraintInput), as it is where what it would be given nests past 20,000 deep along any
// path, wherever a value reached twice is reached first, so a hook is never given a part of it, and
// where it holds itself and reaches 20,000 maps, lists, pointers, structs, arrays and messages,
// counting each time it reaches one, as a path around the cycle could nest that deep: how deep the
// one the copy takes nests turns on where it enters the cycle, which the order a map's entries come
// in picks, so neither refusal turns on that order. A declared attribute is a value of its type as
// converted, so a named string type is a string.
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
// valueSize counts what a condition reads, but for what building a value costs more (mapCost). It
// is what a check reading a condition may spend at the least on one scope's grants' conditions
// (grantBudget), as converting a unit costs about what reading one does, so converting what a check
// passes costs no more than its conditions may.
const maxConverted = 2 * maxCheckCost

// What converting a value costs, and a hook's copy of it (deepCopy), counted alike, where building
// it costs more than the one each value costs: each map, Struct or JSON object, each list, ListValue
// or JSON array, each pointer, but to a message, and each other message, each kept by where it
// points and allocated, and a copied message built by reflection. Counted one, as a number is,
// 160,000 empty maps took a check 93 ms to convert and a hook 83 ms to copy, where as many ints took
// 12 ms and 6 ms; so weighed, a unit takes 20 to 115 ns to convert and 25 to 200 ns to copy,
// whatever holds it, a copied message the most.
const (
	mapCost     = 8
	listCost    = 4
	pointerCost = 4
	messageCost = 4
)

// maxNested is how deep a value a host passes may nest, as JSON text may (encoding/json): a kind's
// attributes nesting deeper can't be read, and converting them recurses no deeper, as though each
// level costs one, a hundred thousand levels took a check a fifth of a second, growing the stack to
// a hundred mebibytes.
const maxNested = 10000

// converter converts what a host passes into CEL's own values (Attributes), a kind's attributes at
// a time, spending no more than left on them all: a call's subject's and request's together, and a
// check's resource's on one of its own, from what they left (asking). It keeps each list, map,
// pointer, message and JSON text it converts by where it points, its length and its type
// (copiedKey), with what it found of it, so one reached twice is converted once, for any kind it
// converts that reaches it. It is kept only while it converts, which runs none of the host's code,
// so what the host passed stays where it is, and no check knows a value by where one another
// converter converted was.
type converter struct {
	left uint64
	// over is set once converting cost more than was left, which fails every kind's attributes.
	over bool
	// depth is how deep converting is in the kind it converts.
	depth int
	// unread counts the values converting found no condition can read, as a struct, one holding
	// itself, or one holding either, and deep those it found nested past maxNested.
	unread, deep int
	// infinite counts the doubles converting found that aren't finite, and the values holding one,
	// which make the attribute holding them refused (attributes).
	infinite int
	// done is where in converted each it converted is, by where it points.
	done      map[copiedKey]int
	converted []conversion
	// cut are those of done converting cut short at maxNested in the kind it converts, which it
	// forgets once the kind is converted, as a kind after it may reach them less deep.
	cut []copiedKey
}

// conversion is what a converter found of a value it converted, while open converting it: what it
// is to conditions, and how deep it nests, counting itself, or that no condition can read it, and
// whether it holds a double that isn't finite.
type conversion struct {
	to ref.Val
	// of is where the value points, kept so that it is no other value's, which the converter would
	// read as this one, while the converter is kept: nothing else keeps what it decodes of JSON text
	// and packed messages once converted, and freed, what a kind after decoded came to be where it
	// was and was read as converted from it. It is where the value points, not the value as read,
	// as each of a map's entries is read into the same value (dict).
	of                              any
	height                          int
	open, unreadable, cut, infinite bool
}

func newConverter() *converter { return &converter{left: maxConverted} }

// rest is a converter that has converted nothing, spending what c left: a check converts its
// resource's attributes on one, after the subject's and the request's its call converted (asking).
func (c *converter) rest() converter { return converter{left: c.left, over: c.over} }

// attributes is a kind's attributes as conditions read them, by their names, nil for none, and
// whether a condition can read them: where any value they hold, however deep, can't be read, as a
// struct, or nests past maxNested, or holds itself, none can, as the attributes beside one would
// leave each operator reading them to tell what it reads from what it can't. One holding a double
// that isn't finite, however deep, is an error, which declared makes a declared kind refuse, as it
// refuses a declared double that isn't finite, and an undeclared kind unreadable: comparing a list
// or a map reads the smaller value whole and the larger only as far, so a list holding NaN beside a
// long string was compared by the string, and `request.attributes.scores != [1, 2]` held. Each is
// converted, and charged, whether one before it could be read or not, so what is left for the
// kinds after it doesn't turn on the order a map's entries come in, but where they nest past
// maxNested: converting stops there, so they are charged for as much of them as it reached first,
// which that order picks, and whether the kinds after them fit what is left can turn on it, failing
// closed.
func (c *converter) attributes(attributes map[string]any) (map[ref.Val]ref.Val, bool) {
	if len(attributes) == 0 {
		return nil, true
	}
	convertingKind()
	// Each costs at least its name and its value, so a map for more than are left isn't made, as
	// one for a million took 80 MB, only to find them past it.
	if !c.building(mapCost, 2*length(len(attributes))) {
		return nil, false
	}
	unread, deep := c.unread, c.deep
	out := make(map[ref.Val]ref.Val, len(attributes))
	for name, v := range attributes {
		if !c.pay(textLength(len(name))) {
			return nil, false
		}
		infinite := c.infinite
		out[types.String(name)], _ = c.of(reflect.ValueOf(v))
		if c.infinite != infinite {
			out[types.String(name)] = types.NewErr("rbac: attribute %q holds a double that isn't finite", name)
		}
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
// JSON text a tenth of its length more, as reading it does, and a map, a list, a pointer or a
// message what building it does (mapCost), so converting reaches no more values than it may cost.
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
		// The instant, in UTC, as a protobuf Timestamp is read: CEL keeps a time's zone, which only
		// string() shows, so a time read from a clock or a database in each replica's local zone would
		// otherwise decide by where the replica runs.
		at, _ := v.Interface().(time.Time)
		return types.Timestamp{Time: at.UTC()}, 1
	case durationType:
		return types.Duration{Duration: time.Duration(v.Int())}, 1
	case rawType:
		// A nil one is no JSON text, which encoding/json writes as null, as it writes a nil pointer.
		if v.IsNil() {
			return types.NullValue, 1
		}
		return c.json(v)
	case numberType:
		return c.number(v.String()), 1
	case nullType:
		return types.NullValue, 1
	}
	if wellKnown[t] {
		return c.message(v)
	}
	// A value of a type of the host's own CEL would read by its methods, as one saying it is a
	// double or a list, is read so by none. A pointer has the methods of what it points to, so one to
	// CEL's own string is read as the string, as any other pointer is read as what it points to.
	if t.Implements(refValType) && (t.Kind() != reflect.Pointer || !t.Elem().Implements(refValType)) {
		if v, ok := v.Interface().(ref.Val); ok && celScalar(v) {
			switch s := v.(type) {
			case types.Timestamp:
				v = types.Timestamp{Time: s.UTC()}
			case types.Double:
				v = c.double(float64(s))
			}
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
		return c.double(v.Float()), 1
	case reflect.String:
		s := v.String()
		return c.spend(uint64(len(s))/10, types.String(s)), 1
	case reflect.Pointer:
		if v.IsNil() {
			return types.NullValue, 1
		}
		return c.once(v, func() (ref.Val, int) {
			if !c.pay(pointerCost - 1) {
				return nil, 0
			}
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

// double is d as a condition reads it, counting one that isn't finite, which makes the attribute
// holding it refused, and an undeclared kind holding it unreadable (attributes).
func (c *converter) double(d float64) ref.Val {
	if math.IsNaN(d) || math.IsInf(d, 0) {
		c.infinite++
	}
	return types.Double(d)
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

// building pays n for building a value whose contents cost at least least, or reports, before
// anything is built, that the two are more than is left.
func (c *converter) building(n, least uint64) bool {
	if least > c.left || n > c.left-least {
		c.over, c.left = true, 0
		return false
	}
	return c.pay(n)
}

// spend is v, which converting cost n, or nil once it costs more than is left.
func (c *converter) spend(n uint64, v ref.Val) ref.Val {
	if !c.pay(n) {
		return nil
	}
	return v
}

// once is what convert makes of v, which points somewhere, and how deep it nests, converted once by
// c. One reached again while it is converted holds itself, or holds one that holds it, and can't be
// read, nor can one holding it, of any kind. One that can't be read is kept so, as no kind reaching
// it can read it; one nesting past maxNested where it was reached is kept so for the rest of the
// kind, which nests too deep wherever it reaches it again, but not for a kind after it, which may
// reach it less deep: converted again for each path reaching it, a ladder of a hundred maps each
// holding both of the next two, nested 10,000 deep, went past maxConverted, failing every kind; and
// one converted whole is kept with how deep it nests, so it fails where it is reached too deep for
// that, wherever it was first reached: whether a kind's attributes nest past maxNested, as whether
// they hold one holding itself, is of what they hold, whatever order a map's entries come in or a
// kind before it reached a value first.
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
			if d.infinite {
				c.infinite++
			}
			return d.to, d.height
		}
	}
	if c.done == nil {
		c.done = map[copiedKey]int{}
	}
	i := len(c.converted)
	c.done[k] = i
	c.converted = append(c.converted, conversion{of: v.UnsafePointer(), open: true})
	unread, deep, infinite := c.unread, c.deep, c.infinite
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
		d.to, d.height, d.infinite = to, height, c.infinite != infinite
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

// noValues is the empty list, which every nil slice converts to.
var noValues = types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{})

// list is v, a slice or an array, as a list of what it holds, and how deep it nests: a nil slice
// is the empty list, as nothing is built for it.
func (c *converter) list(v reflect.Value) (ref.Val, int) {
	if v.Kind() == reflect.Slice && v.IsNil() {
		return noValues, 1
	}
	// Each costs at least one, so a list longer than is left can't be converted.
	if !c.building(listCost-1, length(v.Len())) {
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
	if v.IsNil() {
		return noAttributes, 1
	}
	if !c.building(mapCost-1, 2*length(v.Len())) {
		return nil, 0
	}
	// Reading an entry copies its value whole, though a struct is refused whatever it holds: a map of
	// 2,000 structs of 64 KiB took 7 ms to convert, charged 4,017. One that holds any is refused once,
	// unread, at the least its entries cost.
	if v.Len() > 0 && refusedWhole(v.Type().Elem()) {
		if !c.pay(2 * length(v.Len())) {
			return nil, 0
		}
		return c.refuse(), 1
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

// refusedWhole reports whether of refuses every value of type t, whatever it holds: a struct, but
// for a time, and an array of one.
func refusedWhole(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct:
		return t != timeType && t != celTimestampType && t != celDurationType
	case reflect.Array:
		return t.Len() > 0 && refusedWhole(t.Elem())
	default:
		return false
	}
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

// json is v, JSON text, parsed, at a tenth of its length, once for each text c converts, and how
// deep it nests. Text whose values may cost more than a check converts isn't parsed: a value takes
// as few as two bytes, as `0,`, and parsing a mebibyte of them, only to find more than a check may
// convert, took a tenth of a second and 80 MB. That is of the text alone, not of what is left: what
// it may hold is more than it holds where it is invalid, holds an empty list or object, or a key
// twice, so compared with what was left, a text of `[]` beside a resource's string just fitting
// what a check converts failed every kind's attributes where the string was converted first, and
// not where the text was, as the order a map's entries come in decides. A converter so parses at
// most one text it can't afford, which then fails every kind, of no more values than one it can.
func (c *converter) json(v reflect.Value) (ref.Val, int) {
	return c.once(v, func() (ref.Val, int) {
		if !c.pay(length(v.Len()) / 10) {
			return nil, 0
		}
		if jsonValues(v.Bytes()) > maxConverted {
			c.over, c.left = true, 0
			return nil, 0
		}
		parsed, ok := parseJSON(v.Bytes())
		if !ok {
			return c.refuse(), 1
		}
		to, height := c.of(reflect.ValueOf(parsed))
		return to, height + 1
	})
}

// parseJSON is text parsed as encoding/json parses it into an any, and whether it is JSON a
// condition can read: not where an object holds a name twice, as `"role"` and `"r\u006fle"` are
// once unescaped, where text that isn't UTF-8 or escapes half a surrogate pair, which encoding/json
// reads as U+FFFD, could hold two names read as one. Each reader of JSON picks one of two values of
// a name as it likes, encoding/json the last, so a host checking the first read "user" of
// `{"role": "user", "role": "admin"}` where a condition read "admin", as a map of the host's holding
// two keys read as one would have it. Text nested deeper than maxNested is refused, as
// encoding/json refuses it, so jsonValue recurses no deeper: built without jsonv2
// (GOEXPERIMENT=nojsonv2), the decoder counts no depth of the brackets and braces Token returns, so
// objects nested 79,000 deep were parsed, taking 70 ms and 48 MB, where json.Unmarshal refused them.
func parseJSON(text []byte) (any, bool) {
	if !utf8.Valid(text) || !pairedSurrogates(text) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	v, err := jsonValue(dec, 0)
	if err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

var errJSON = errors.New("rbac: JSON text no condition can read")

// jsonValue is the next value dec reads, inside depth lists and objects, as encoding/json parses it
// into an any, or why no condition can read it (parseJSON).
func jsonValue(dec *json.Decoder, depth int) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	if depth++; depth > maxNested {
		return nil, errJSON
	}
	switch delim {
	case '[':
		list := []any{}
		for dec.More() {
			v, err := jsonValue(dec, depth)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err := dec.Token()
		return list, err
	case '{':
		object := map[string]any{}
		for dec.More() {
			token, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, _ := token.(string)
			if _, twice := object[name]; twice {
				return nil, errJSON
			}
			if object[name], err = jsonValue(dec, depth); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return object, err
	}
	return nil, errJSON
}

// pairedSurrogates reports whether each surrogate text escapes in a string, as `\ud83d\ude00`, is
// half of a pair, the high one followed by the low one: encoding/json reads either half alone as
// U+FFFD, as it reads bytes that aren't UTF-8.
func pairedSurrogates(text []byte) bool {
	// escaped is the code unit of the escape at text[i:], if it is one.
	escaped := func(i int) (rune, bool) {
		if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
			return 0, false
		}
		n, err := strconv.ParseUint(string(text[i+2:i+6]), 16, 16)
		return rune(n), err == nil
	}
	quoted := false
	for i := 0; i < len(text); i++ {
		switch b := text[i]; {
		case quoted && b == '\\':
			r, ok := escaped(i)
			switch {
			case ok && utf16.IsSurrogate(r) && r < 0xdc00:
				if low, ok := escaped(i + 6); !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 11
			case ok && utf16.IsSurrogate(r):
				return false
			default:
				i++
			}
		case b == '"':
			quoted = !quoted
		}
	}
	return true
}

// jsonValues is the most converting the values and keys JSON text text holds may cost, each one but
// a list or an object, which costs what building one does: each but the first follows a bracket, a
// brace, a comma or a colon outside a string, and a bracket or a brace opens a list or an object.
// Parsed, it may cost less.
func jsonValues(text []byte) uint64 {
	n, quoted := uint64(1), false
	for i := 0; i < len(text); i++ {
		switch b := text[i]; {
		case quoted && b == '\\':
			i++
		case b == '"':
			quoted = !quoted
		case quoted:
		case b == '[':
			n += listCost
		case b == '{':
			n += mapCost
		case b == ',' || b == ':':
			n++
		}
	}
	return n
}

// number is n, a JSON number, an int where it is one and a double where it isn't, as CEL reads it,
// at a tenth of its length whether it is one or not, as parsing it reads it whole, or nil. Text that
// isn't a JSON number no condition can read, though strconv reads some as one, as "+1", "0x1p4" as
// 16 and "Inf", where a host reading it as JSON reads none.
func (c *converter) number(n string) ref.Val {
	if !c.pay(uint64(len(n)) / 10) {
		return nil
	}
	if !jsonNumber(n) {
		return c.refuse()
	}
	if i, err := json.Number(n).Int64(); err == nil {
		return types.Int(i)
	}
	if f, err := json.Number(n).Float64(); err == nil {
		return types.Double(f)
	}
	return c.refuse()
}

// jsonNumber reports whether n is a number as JSON writes one: an optional minus, an integer with
// no leading zero, then optionally a fraction and an exponent.
func jsonNumber(n string) bool {
	digits := func(i int) int {
		for i < len(n) && '0' <= n[i] && n[i] <= '9' {
			i++
		}
		return i
	}
	i := 0
	if i < len(n) && n[i] == '-' {
		i++
	}
	switch {
	case i < len(n) && n[i] == '0':
		i++
	case i < len(n) && '1' <= n[i] && n[i] <= '9':
		i = digits(i)
	default:
		return false
	}
	if i < len(n) && n[i] == '.' {
		if j := digits(i + 1); j > i+1 {
			i = j
		} else {
			return false
		}
	}
	if i < len(n) && (n[i] == 'e' || n[i] == 'E') {
		i++
		if i < len(n) && (n[i] == '+' || n[i] == '-') {
			i++
		}
		if j := digits(i); j > i {
			i = j
		} else {
			return false
		}
	}
	return i == len(n)
}

// message is v, a protobuf message, as a condition reads it, one of the well-known types
// Attributes names, read by its fields, each as of reads it, and how deep it nests; or nil. Each
// costs what building it does, and a tenth of the fields it doesn't know, as a hook's copy holds
// them.
func (c *converter) message(v reflect.Value) (ref.Val, int) {
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return types.NullValue, 1
	}
	if !wellKnown[v.Type()] {
		return c.refuse(), 1
	}
	m, _ := v.Interface().(proto.Message)
	unknown := length(len(m.ProtoReflect().GetUnknown())) / 10
	switch m := m.(type) {
	case *structpb.Struct:
		return c.once(v, func() (ref.Val, int) {
			if !c.building(mapCost-1+unknown, 2*length(len(m.GetFields()))) {
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
			if !c.building(listCost-1+unknown, length(len(m.GetValues()))) {
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
	case *anypb.Any:
		return c.once(v, func() (ref.Val, int) {
			// Finding the type hashes its URL whole, and a packed value takes as few as two bytes, as an
			// empty one in a list does: Anys sharing a mebibyte's URL, each charged one, took a third of
			// a millisecond each, and decoding a mebibyte of values, only to find more than a check may
			// convert, took a tenth of a second.
			if !c.pay(messageCost - 1 + unknown + length(len(m.GetTypeUrl()))/10 + length(len(m.GetValue()))/2) {
				return nil, 0
			}
			unpacked, ok := packable[m.MessageName()]
			if !ok {
				return c.refuse(), 1
			}
			packed := unpacked()
			if err := proto.Unmarshal(m.GetValue(), packed); err != nil || !setOnce(m.GetValue(), packed.ProtoReflect().Descriptor()) {
				return c.refuse(), 1
			}
			to, height := c.of(reflect.ValueOf(packed))
			return to, height + 1
		})
	}
	if !c.pay(messageCost - 1 + unknown) {
		return nil, 0
	}
	switch m := m.(type) {
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
			return c.double(k.NumberValue), 1
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
		return c.double(m.GetValue()), 1
	case *wrapperspb.FloatValue:
		return c.double(float64(m.GetValue())), 1
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
	}
	return c.refuse(), 1
}

// setOnce reports whether b, a message md describes as an Any packs it, sets each of its fields of
// one value at most once, a oneof's as one, and each of its maps' keys once, however deep. Decoding
// keeps the last of two values of a field and of two entries of a key, and merges a message set
// twice, so a Struct packing "role" twice, or packing it in each of two messages its Value sets, was
// read as the last where a host reading the first read another, as a map of the host's holding two
// keys read as one would have it. A field of another wire type than its own, decoding keeps apart as
// one it doesn't know, and so does this. b is of no more than proto.Unmarshal decoded, so as deep.
func setOnce(b []byte, md protoreflect.MessageDescriptor) bool {
	// The fields and oneofs set, by their numbers and indexes, each below 64 in the types packable
	// names: one past that is refused.
	var fields, oneofs uint64
	var keys map[string]bool
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		b = b[n:]
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return false
		}
		value := b[:n]
		b = b[n:]
		fd := md.Fields().ByNumber(num)
		if fd == nil || typ != wireType(fd) {
			continue
		}
		if fd.Kind() == protoreflect.MessageKind {
			if value, n = protowire.ConsumeBytes(value); n < 0 || !setOnce(value, fd.Message()) {
				return false
			}
		}
		switch {
		case fd.IsMap():
			if fd.MapKey().Kind() != protoreflect.StringKind {
				return false
			}
			key := mapKey(value)
			if keys[key] {
				return false
			}
			if keys == nil {
				keys = map[string]bool{}
			}
			keys[key] = true
		case fd.IsList():
		default:
			if num >= 64 || fields&(1<<num) != 0 {
				return false
			}
			fields |= 1 << num
			if o := fd.ContainingOneof(); o != nil {
				if o.Index() >= 64 || oneofs&(1<<o.Index()) != 0 {
					return false
				}
				oneofs |= 1 << o.Index()
			}
		}
	}
	return true
}

// mapKey is the key of entry, a map's entry setOnce read: its first field, empty where it sets none.
func mapKey(entry []byte) string {
	for len(entry) > 0 {
		num, typ, n := protowire.ConsumeTag(entry)
		if n < 0 {
			return ""
		}
		entry = entry[n:]
		if num == 1 && typ == protowire.BytesType {
			key, _ := protowire.ConsumeBytes(entry)
			return string(key)
		}
		if n = protowire.ConsumeFieldValue(num, typ, entry); n < 0 {
			return ""
		}
		entry = entry[n:]
	}
	return ""
}

// wireType is the wire type a value of the field fd describes is written in, or an element of it.
func wireType(fd protoreflect.FieldDescriptor) protowire.Type {
	switch fd.Kind() {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	case protoreflect.GroupKind:
		return protowire.StartGroupType
	default:
		return protowire.VarintType
	}
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

// wellKnown are the types of the messages conditions read (Attributes), each a pointer to a
// generated message: finding a type of so many methods a message by reflection's Implements took
// most of what converting one did, five times what converting a number does.
var wellKnown = func() map[reflect.Type]bool {
	known := map[reflect.Type]bool{reflect.TypeFor[*anypb.Any](): true}
	for _, made := range packable {
		known[reflect.TypeOf(made())] = true
	}
	return known
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
// own, a protobuf message among them copied field by field, as cloning it would, but for one of a
// host's type that makes messages of another, copied as any other pointer (itself), and a value
// reached twice copied once, a message too, so a cycle ends. A slice is copied once for where it
// starts and its capacity, however many lengths it is reached with, each a slice of the one copy,
// as each is of the host's, but for one reached while its elements are copied, before a longer
// length outgrew that copy, which is a slice of a copy of its own: copied for each length, the
// prefixes of one slice of 3,000 maps took half a second. A value holding no map, slice or pointer,
// as an array of bytes, is copied whole, and shared where an interface holds it, as nothing writes
// through one: copied element by element for each interface holding it, a hundred holding one array
// of 100 KB took 170 ms. So is a time, whose fields are unexported. A struct's fields an unexported
// struct it embeds promotes are its own too, but its other unexported fields are shared, a pointer
// it embeds unexported among them, and so the fields that one promotes: reflection can't set them.
// A map's keys are shared too, and what a pointer among them reaches: a copied key would be another
// key, so the copy would find nothing under the one the host passed. It copies at most what a check
// converts (maxConverted), counted as converting counts it, whatever it shares or copies whole
// (mapCost), and no value nesting past maxCopied deep, nor one holding itself that reaches as many
// values holding others (copier.around), past which it reports false, and the copy is v's zero
// value: copying recurses as far as v reaches, as a check's converting does, which stops there.
func deepCopy[T any](v T) (T, bool) {
	copying()
	c := copier{left: maxConverted}
	out := reflect.ValueOf(&v).Elem()
	out.Set(c.copy(out, 0))
	if c.over {
		var none T
		return none, false
	}
	return v, true
}

// copying runs as deepCopy copies a value, as a test's counter.
var copying = func() {}

// maxCopied is how deep deepCopy copies a value, past which it copies none: copying recurses as
// deep as the value nests, and a list nested three million deep overflowed the stack, which no
// recover catches, ending the process wherever a hook was asked about it. No condition reads what
// lies deeper (maxNested), and sharing it would let a hook write to what the host holds less deep
// too. A copy holding the zero value there instead, or the copy of a value it reached less deep
// before, as the order a map's entries come in decided, gave a hook a value on one call and its
// zero value on the next, by which a constraint could deny one and allow the other: a chain of
// 19,999 pointers ending at a value the map also held one level deep was copied 34 times and zeroed
// 6 in 40. Whether a value nests that deep is of what it holds, wherever a value it reaches twice
// was reached first (kept, copied.reached), but where it holds itself: a path around the cycle
// nests as deep as where the copy entered it, so whether it nested past maxCopied turned on that
// order too, and a value holding itself beside a chain of 9,998 links to it was refused in 22 of 200
// calls and copied whole in the others. One holding itself is refused where it reaches as many
// values holding others as could nest that deep (copier.around), in every order.
const maxCopied = 2 * maxNested

// copier copies values for deepCopy, keeping each map and pointer it copied by where it points and
// its type, and apart, with a length of -1, a message of a host's type it copied as the message that
// type makes (message), and each slice by where it starts, its capacity and its type (sliceKey); and
// what it may still copy (left), past which it is over.
type copier struct {
	done map[copiedKey]kept
	// slices are the copies of each slice's elements, each changed where it is kept as its elements
	// are copied: kept by value, each element cost the copy five lookups of it, as much as copying
	// the element did.
	slices map[copiedKey]*copied
	// outgrown are the copies of each slice that a longer length it was reached with replaced, each
	// perhaps given to what reached it while it still held the host's elements, so each element
	// copied after is set in them too: set in the longer copy alone, one holding a shorter slice of
	// what holds it gave a hook the host's own map.
	outgrown map[copiedKey][]reflect.Value
	left     uint64
	over     bool
	// deepest is the deepest copy has reached in what it is copying (descend).
	deepest int
	// holders counts each time copy reached a value holding others (hold), and cycled is set once it
	// reached one it was still copying (around).
	holders int
	cycled  bool
}

// kept is the copy of a map, pointer or message, and once it is copied whole, how much deeper than
// where it was reached what it holds reaches, so reaching it again deeper copies none past
// maxCopied either, as copying it there would have (reached); and whether it is a message, which
// nests a level below a pointer reaching it (hold).
type kept struct {
	out            reflect.Value
	height         int
	whole, message bool
}

// copied is the copy of a slice's elements from where it starts, as many as the longest it was
// reached with, of which filled are copied: a copy reaching it again while it is copied, as a slice
// holding itself, is a slice of this one. measured are how many of its elements, in turn from the
// first, are copied whole, and rises where among those how much deeper than the slice they reach
// grows, and to what, as each length it is reached with reaches no deeper than its own elements.
type copied struct {
	out      reflect.Value
	filled   int
	measured int
	rises    []rise
}

// rise is where among a slice's elements how deep they reach grows: from the one at, height deeper
// than the slice.
type rise struct{ at, height int }

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

// pay spends n, or reports that it can't, once copying has cost more than it may.
func (c *copier) pay(n uint64) bool {
	if c.over || n > c.left {
		c.over, c.left = true, 0
		return false
	}
	c.left -= n
	return true
}

// building pays n for building a copy whose contents cost at least least, or reports, before
// anything is built, that the two are more than is left.
func (c *copier) building(n, least uint64) bool {
	if least > c.left || n > c.left-least {
		c.over, c.left = true, 0
		return false
	}
	return c.pay(n)
}

// copy is a copy of v, which is depth deep, or once c is over, the zero value: past maxCopied deep,
// c is over.
func (c *copier) copy(v reflect.Value, depth int) reflect.Value {
	at := depth
	if v.Kind() != reflect.Interface {
		if depth >= maxCopied {
			c.overflow()
			return reflect.Zero(v.Type())
		}
		c.deepest = max(c.deepest, depth)
		depth++
		if !c.pay(1) {
			return reflect.Zero(v.Type())
		}
	}
	if shared(v.Type()) {
		// Set whole where the copy holds it.
		if !c.payWhole(v) {
			return reflect.Zero(v.Type())
		}
		return v
	}
	if v.Kind() != reflect.Interface {
		c.hold()
	}
	switch v.Kind() {
	case reflect.Interface:
		// Shared, but counted as the value it holds is converted, so an array of them costs what it
		// holds: uncounted, an array of a million of them cost a copy one.
		if unreachable(v) {
			if !c.payHeld(v) {
				return reflect.Zero(v.Type())
			}
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(c.copy(v.Elem(), depth))
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		return c.dict(v, at, depth)
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		return c.slice(v, depth)
	case reflect.Struct:
		// Set whole, its unexported fields too, and so charged its bytes, as a flat one is (payWhole):
		// charged one, a copy of 2,000 structs each holding a map and 64 KiB took 38 ms.
		if !c.pay(tenths(v.Type()) / 10) {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		c.fields(out, v, depth)
		return out
	case reflect.Array:
		// Each element costs at least one, so an array of more than is left isn't copied.
		if !c.building(listCost-1, length(v.Len())) {
			return reflect.Zero(v.Type())
		}
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len() && !c.over; i++ {
			out.Index(i).Set(c.copy(v.Index(i), depth))
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		return c.pointer(v, at, depth)
	default:
		return v
	}
}

// dict is a copy of v, a map that isn't nil, reached at, whose entries are depth deep. It is apart
// from copy, which copying recurses through as deep as maxCopied, so its frame holds none of what
// this needs.
func (c *copier) dict(v reflect.Value, at, depth int) reflect.Value {
	k, _ := copiedKeyOf(v)
	if done := c.done[k]; done.out.IsValid() {
		c.reachedAgain(done, at)
		return done.out
	}
	// Each entry costs at least its key and what its value holds in place (leastCopied), so a map
	// of more than is left isn't made, nor an entry read, which moves it whole: a map holding an
	// array of 4 MiB allocated 12 MB before being found past what a copy holds.
	if !c.building(mapCost-1, length(v.Len())*(1+leastCopied(v.Type().Elem()))) {
		return reflect.Zero(v.Type())
	}
	out := reflect.MakeMapWithSize(v.Type(), v.Len())
	c.keep(k, out, false)
	outer := c.descend(at)
	// Reading an entry moves its key and its value whole, and setting it hashes the key, so each is
	// charged what it holds in place first: a key of another type than a string its bytes, held
	// in an interface too, and what hashing reads past them (payHashed), and a value the structs it
	// holds (inlineTenths), as lengthen charges a slice's elements. Uncharged, a copy of 2,000
	// entries keyed by arrays of 4 KiB took 8 ms, charged 4,017, and one reached 20,000 deep moved
	// each struct it held only to drop it.
	kt := v.Type().Key()
	moved, hashed := (keyTenths(kt)+inlineTenths(v.Type().Elem()))/10, kt.Kind() != reflect.String && hashesHeld(kt)
	for it := v.MapRange(); it.Next() && c.pay(moved); {
		key := it.Key()
		if !c.pay(textLength(textOf(key))) || hashed && !c.payHashed(key) {
			break
		}
		out.SetMapIndex(key, c.copy(it.Value(), depth))
	}
	c.ascendFrom(k, at, outer)
	return out
}

// pointer is a copy of v, a pointer that isn't nil, reached at, what it points to depth deep, apart
// from copy as dict is.
func (c *copier) pointer(v reflect.Value, at, depth int) reflect.Value {
	k, _ := copiedKeyOf(v)
	if done := c.done[k]; done.out.IsValid() {
		if done.message {
			c.hold()
		}
		c.reachedAgain(done, at)
		return done.out
	}
	if m, ok := v.Interface().(proto.Message); ok && itself(m) {
		c.hold()
		return reflect.ValueOf(c.message(m.ProtoReflect(), depth).Interface())
	}
	if !c.pay(pointerCost - 1) {
		return reflect.Zero(v.Type())
	}
	out := reflect.New(v.Type().Elem())
	c.keep(k, out, false)
	outer := c.descend(at)
	out.Elem().Set(c.copy(v.Elem(), depth))
	c.ascendFrom(k, at, outer)
	return out
}

// keep keeps out, the copy of the map, pointer or message k knows.
func (c *copier) keep(k copiedKey, out reflect.Value, message bool) {
	if c.done == nil {
		c.done = map[copiedKey]kept{}
	}
	c.done[k] = kept{out: out, message: message}
}

// overflow is c over, as it is past maxCopied deep.
func (c *copier) overflow() { c.over, c.left = true, 0 }

// descend starts measuring how deep what is reached at reaches, returning how deep what holds it
// had reached, for ascend.
func (c *copier) descend(at int) (outer int) {
	outer, c.deepest = c.deepest, at
	return outer
}

// ascend is how much deeper than at what descend measured from there reaches, which what holds it
// reaches too.
func (c *copier) ascend(at, outer int) int {
	height := c.deepest - at
	c.deepest = max(outer, c.deepest)
	return height
}

// ascendFrom keeps how much deeper than at what k knows reaches, copied whole (ascend).
func (c *copier) ascendFrom(k copiedKey, at, outer int) {
	done := c.done[k]
	done.height, done.whole = c.ascend(at, outer), true
	c.done[k] = done
}

// reached notes that what is reached at reaches height deeper, as it did where it was copied, and
// is over where that is past maxCopied, as copying it there would be.
func (c *copier) reached(at, height int) {
	if at+height >= maxCopied {
		c.overflow()
		return
	}
	c.deepest = max(c.deepest, at+height)
}

// reachedAgain is reached for done, copied before, unless it is still being copied, as a value
// holding itself is when it reaches itself.
func (c *copier) reachedAgain(done kept, at int) {
	if done.whole {
		c.reached(at, done.height)
	} else {
		c.around()
	}
}

// hold counts a value holding others that copy reaches, a map, list, pointer, struct, array or
// message, each time it reaches one, a message a pointer reaches as well as the pointer, a level
// below it (holders), and is over once so many are reached around a cycle (around).
func (c *copier) hold() {
	if c.holders++; c.cycled && c.holders >= maxCopied {
		c.overflow()
	}
}

// around notes that copy reached a value it is still copying, as a value holding itself does, and
// is over where it has reached values holding others so often that a path around the cycle could
// nest past maxCopied in another order: the path it copies around one nests as deep as where it
// entered it, which turns on the order a map's entries come in, but how often it reaches each such
// value doesn't, and each level of a path above its deepest value is one of them.
func (c *copier) around() {
	if c.cycled = true; c.holders >= maxCopied {
		c.overflow()
	}
}

// set sets the ith element of s, the copy of the slice k knows, and of each copy of it outgrown
// that holds one.
func (c *copier) set(s *copied, k copiedKey, i int, v reflect.Value) {
	s.out.Index(i).Set(v)
	for _, o := range c.outgrown[k] {
		if i < o.Len() {
			o.Index(i).Set(v)
		}
	}
}

// sliceKey is how copier knows a slice: by where it starts, its capacity and its type, which every
// length of it shares.
func sliceKey(v reflect.Value) copiedKey {
	if v.Kind() != reflect.Slice {
		return copiedKey{}
	}
	return copiedKey{v.Type(), v.Pointer(), v.Cap()}
}

// slice is a copy of v, a slice that isn't nil, which is depth deep: a slice of the copy of its
// elements from where it starts, made as long as the longest length it is reached with, and no
// longer than it may grow to, so each element is copied once. Each copy is as long as its capacity,
// so appending to one writes to none of the others.
func (c *copier) slice(v reflect.Value, depth int) reflect.Value {
	n, k, at := v.Len(), sliceKey(v), depth-1
	s := c.slices[k]
	if s != nil {
		// An element it reaches that isn't measured holds the slice: it is still being copied, or was
		// around a cycle.
		if min(n, s.filled) > s.measured {
			c.around()
		}
		// The elements it copied before reach as much deeper from here.
		c.reached(at, s.reach(n))
	}
	if s == nil || s.out.Len() < n {
		if s = c.lengthen(v, k, s); s == nil {
			return reflect.Zero(v.Type())
		}
		// Copying an element may reach a longer slice of v, which grows the copy, so each is set in
		// the copy as it is once it is copied, and in those it outgrew.
		for i := s.filled; i < n && !c.over; i = max(i+1, s.filled) {
			switch e := v.Index(i); {
			case !unreachable(e):
				s.filled = i + 1
				outer := c.descend(at)
				c.set(s, k, i, c.copy(e, depth))
				s.reached(i, c.ascend(at, outer))
			case !c.payHeld(e):
				return reflect.Zero(v.Type())
			default:
				s.reached(i, 0)
			}
		}
		s.filled = max(n, s.filled)
	}
	if s.out.Len() == n && s.out.Cap() == n {
		return s.out
	}
	return s.out.Slice3(0, n, n)
}

// reached notes how much deeper than the slice its ith element reaches, copied whole, where those
// before it were: one copied before them reaches the slice again around a cycle, which leaves the
// lengths past it unmeasured.
func (s *copied) reached(i, height int) {
	if i != s.measured {
		return
	}
	s.measured++
	if height > s.reach(i) {
		s.rises = append(s.rises, rise{i, height})
	}
}

// reach is how much deeper than the slice its first n elements reach, of those measured.
func (s *copied) reach(n int) int {
	n = min(n, s.measured)
	i, _ := slices.BinarySearchFunc(s.rises, n, func(r rise, n int) int { return cmp.Compare(r.at, n) })
	if i == 0 {
		return 0
	}
	return s.rises[i-1].height
}

// lengthen makes s, the copy of v's elements, which k knows, as long as v, holding the host's
// elements where it held none, a new one kept where s is nil, or reports that it costs more than is
// left. It is apart from slice, which copying recurses through as deep as maxCopied, so its frame
// holds none of what this needs.
func (c *copier) lengthen(v reflect.Value, k copiedKey, s *copied) *copied {
	n, had := v.Len(), 0
	if s != nil {
		had = s.out.Len()
	}
	// Each element costs what converting it does, one and what it holds, where it holds nothing a
	// copy would share as converting it costs (payWhole), and bytes a tenth of each, and the copy
	// what building a list does, once for where it starts. Each costs at least one, but a byte, so a
	// slice of more than is left isn't made. Counted once more for each, a list of 100,000 short
	// strings, which a check converts, couldn't be copied, so a constrained check of it was refused.
	// Elements of another type are moved whole here before each is copied, and so charged the
	// structs they hold in place (inlineTenths), as each costs again when copied, and moved only
	// where what they hold in place costs no more than is left (leastCopied): 2,000 arrays of 4,096
	// interfaces allocated 133 MB before being found past what a copy holds.
	elem, made := v.Type().Elem(), uint64(listCost-1)
	if s != nil {
		made = 0
	}
	switch {
	case elem.Kind() == reflect.Uint8:
		if !c.pay(length(n-had) / 10) {
			return nil
		}
	case shared(elem):
		if !c.building(made, length(n-had)) || !c.pay(length(n-had)) {
			return nil
		}
		for i := had; i < n && textual(elem); i++ {
			if !c.payWhole(v.Index(i)) {
				return nil
			}
		}
	case !c.building(made, length(n-had)*leastCopied(elem)) || !c.pay(length(n-had)*(inlineTenths(elem)/10)):
		return nil
	}
	switch {
	case s == nil:
		s = &copied{out: reflect.MakeSlice(v.Type(), n, n)}
		if c.slices == nil {
			c.slices = map[copiedKey]*copied{}
		}
		c.slices[k] = s
	case n > s.out.Cap():
		grown := reflect.MakeSlice(v.Type(), n, min(max(n, 2*s.out.Cap()), v.Cap()))
		reflect.Copy(grown, s.out)
		if c.outgrown == nil {
			c.outgrown = map[copiedKey][]reflect.Value{}
		}
		c.outgrown[k] = append(c.outgrown[k], s.out.Slice(0, s.out.Cap()))
		s.out = grown
	default:
		s.out = s.out.Slice(0, n)
	}
	// Each hook is given its own, so elements no write could reach through are copied at once.
	if s.filled == 0 {
		reflect.Copy(s.out, v)
	} else {
		reflect.Copy(s.out.Slice(s.filled, n), v.Slice(s.filled, n))
	}
	if shared(elem) {
		s.filled, s.measured = n, n
	}
	return s
}

// message is a copy of m, as cloning it would make, but keeping each message it copies by where it
// points, as copy keeps pointers: cloning keeps none, so a message holding itself, as a Struct one
// of whose fields holds it, recursed until the stack overflowed, which no recover catches, and one
// reaching another twice copied it for each path to it. A nil message, as a list may hold, is copied
// as a new one each time, as cloning copies it: each is the same nil, but none is another's. What
// reaches m pays the one it costs as a value, as converting a message the host passes counts it
// once: counted again here, a copy of a resource's nearly 40,000 timestamps, which a check converts,
// cost a quarter more than converting them did, so a check converting them couldn't ask a
// constraint about them.
func (c *copier) message(m protoreflect.Message, depth int) protoreflect.Message {
	if !m.IsValid() {
		return m.New()
	}
	k, keyed := copiedKeyOf(reflect.ValueOf(m.Interface()))
	// One of a host's type that a dynamic message's field holds, which is copied as any other pointer
	// where it is reached as itself (itself), is copied here as the message it makes, a valid one
	// however deep, and kept apart, so the copy of either is found only where it can be held.
	if keyed && !itself(m.Interface()) {
		k.len = -1
	}
	if depth >= maxCopied {
		c.overflow()
		return m.New()
	}
	// It is measured from what reached it, as a pointer copy gives it, so reaching it again either way
	// finds how much deeper it reaches alike.
	at := depth - 1
	depth++
	if done := c.done[k]; keyed && done.out.IsValid() {
		if d, ok := done.out.Interface().(proto.Message); ok {
			c.reachedAgain(done, at)
			return d.ProtoReflect()
		}
	}
	out := m.New()
	if !c.pay(ownCost(m.Descriptor())) {
		return out
	}
	outer := c.descend(at)
	c.deepest = at + 1
	if keyed {
		c.keep(k, reflect.ValueOf(out.Interface()), true)
	}
	// Each element of a list, and each key and value of a map, costs one, as converting counts it,
	// a key a tenth of its bytes more, and each message a field holds one, and what it costs.
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			from, to := v.List(), out.Mutable(fd).List()
			if !c.pay(length(from.Len())) {
				return false
			}
			for i := 0; i < from.Len() && !c.over; i++ {
				to.Append(c.field(fd, from.Get(i), depth))
			}
		case fd.IsMap():
			if 2*length(v.Map().Len()) > c.left {
				c.over, c.left = true, 0
				return false
			}
			to := out.Mutable(fd).Map()
			v.Map().Range(func(key protoreflect.MapKey, v protoreflect.Value) bool {
				if c.pay(1 + textLength(textOf(reflect.ValueOf(key.Interface())))) {
					to.Set(key, c.field(fd.MapValue(), v, depth))
				}
				return !c.over
			})
		case holdsMessages(fd) && !c.pay(1):
		default:
			out.Set(fd, c.field(fd, v, depth))
		}
		return !c.over
	})
	if unknown := m.GetUnknown(); len(unknown) > 0 && c.pay(length(len(unknown))/10) {
		out.SetUnknown(slices.Clone(unknown))
	}
	if keyed {
		c.ascendFrom(k, at, outer)
	} else {
		c.ascend(at, outer)
	}
	return out
}

// ownCost is what copying a message md describes costs past the one it costs as a value, as
// converting it costs: a Struct what building a map does, a ListValue a list, and another a message.
func ownCost(md protoreflect.MessageDescriptor) uint64 {
	switch md.FullName() {
	case structName:
		return mapCost - 1
	case listValueName:
		return listCost - 1
	}
	return messageCost - 1
}

var (
	structName    = (&structpb.Struct{}).ProtoReflect().Descriptor().FullName()
	listValueName = (&structpb.ListValue{}).ProtoReflect().Descriptor().FullName()
	// anyValue is the field an Any packs its message's bytes in, each half a unit, as converting
	// counts them.
	anyValue = (&anypb.Any{}).ProtoReflect().Descriptor().Fields().ByName("value")
)

// holdsMessages reports whether a value of the field fd describes, or each of its elements, is a
// message, which costs a copy what copying it does.
func holdsMessages(fd protoreflect.FieldDescriptor) bool {
	return fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind
}

// field is a copy of v, a value of a field fd describes or of one of its elements: a message as
// message copies it, bytes as bytes of its own, and the rest as it is, which nothing writes to, a
// string and bytes at a tenth of their length, and an Any's packed bytes at half, as converting
// counts them.
func (c *copier) field(fd protoreflect.FieldDescriptor, v protoreflect.Value, depth int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		c.hold()
		return protoreflect.ValueOfMessage(c.message(v.Message(), depth))
	case protoreflect.BytesKind:
		n := length(len(v.Bytes())) / 10
		if fd == anyValue {
			n = length(len(v.Bytes())) / 2
		}
		if !c.pay(n) {
			return protoreflect.ValueOfBytes(nil)
		}
		return protoreflect.ValueOfBytes(slices.Clone(v.Bytes()))
	case protoreflect.StringKind:
		c.pay(length(len(v.String())) / 10)
		return v
	default:
		return v
	}
}

// itself reports whether m is a message as itself, of a type that makes its own, so copied as one: a
// host's type embedding one is a message by the methods it promotes, and copying its message would
// return the embedded one in its place, or panic where it embeds the message interface holding none;
// and one of a host's type that is its own reflection by a dynamic message it embeds makes a dynamic
// message, which a list, a field or a map of the host's type can't hold, and a hook would read as
// another type than the host passed. Either is copied as any other pointer, by what it points to,
// its message among it.
func itself(m proto.Message) (ok bool) {
	if wellKnown[reflect.TypeOf(m)] {
		return true
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	r := m.ProtoReflect()
	return r.Interface() == m && reflect.TypeOf(r.New().Interface()) == reflect.TypeOf(m)
}

// fields copies into out, a copy of the struct v, the fields a hook can write to: its exported
// ones, and those an unexported struct it embeds promotes, which reflection sets as the language
// does. Its other unexported fields a hook reaches only through the type's methods.
func (c *copier) fields(out, v reflect.Value, depth int) {
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
// of a type a copy shares, as each of an []any of strings decoded from JSON does, which boxing again
// would cost an allocation for each.
func unreachable(v reflect.Value) bool {
	if v.Kind() != reflect.Interface || v.IsNil() {
		return v.Kind() == reflect.Interface
	}
	switch e := v.Elem(); e.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Slice:
		return e.IsNil()
	default:
		return shared(e.Type())
	}
}

// payHeld pays for v, an interface no write could reach through (unreachable), as converting what
// it holds costs: one for nil.
func (c *copier) payHeld(v reflect.Value) bool {
	if v.IsNil() {
		return c.pay(1)
	}
	return c.pay(1) && c.payWhole(v.Elem())
}

// payWhole pays for v, of a type a copy shares, past the one it costs as a value, as converting it
// costs: a string or an array of bytes a tenth of its length, and an array a list of what it holds.
// A struct, which no condition reads, costs a tenth of its bytes, each string's as one (tenths).
func (c *copier) payWhole(v reflect.Value) bool {
	t := v.Type()
	switch {
	case t.Kind() == reflect.String:
		return c.pay(length(v.Len()) / 10)
	case t.Kind() == reflect.Array && t.Elem().Kind() == reflect.Uint8:
		return c.pay(length(v.Len()) / 10)
	case t.Kind() == reflect.Array:
		if !c.pay(listCost - 1 + length(v.Len())) {
			return false
		}
		for i := 0; i < v.Len() && textual(t.Elem()); i++ {
			if !c.payWhole(v.Index(i)) {
				return false
			}
		}
		return true
	case t.Kind() == reflect.Struct && t != timeType && t != celTimestampType:
		return c.pay(tenths(t) / 10)
	default:
		return true
	}
}

// textual reports whether a value of t, which a copy shares, costs more than the one it costs as a
// value.
func textual(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Array, reflect.Struct:
		return t != timeType && t != celTimestampType
	default:
		return false
	}
}

// textOf is the length of the string v, a map's key, is, or holds in an interface, or 0 for a key
// of another kind, as converting reads it.
func textOf(v reflect.Value) int {
	if v.Kind() == reflect.Interface && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() != reflect.String {
		return 0
	}
	return v.Len()
}

// tenths is what copying a value of t whole costs, in tenths: a tenth of each of its bytes, as
// converting counts bytes, but for a string's, which is one value, as converting counts it, though
// moving it moves 16 bytes.
func tenths(t reflect.Type) uint64 {
	switch t.Kind() {
	case reflect.String:
		return 10
	case reflect.Array:
		return length(t.Len()) * tenths(t.Elem())
	case reflect.Struct:
		var n uint64
		for i := range t.NumField() {
			n += tenths(t.Field(i).Type)
		}
		return n
	default:
		return uint64(t.Size())
	}
}

// inlineTenths is what moving the structs a value of t holds in place whole costs, in tenths
// (tenths), but times and durations, which converting reads: copying anything else a value holds
// costs at least one for each 24 bytes moving it moves.
func inlineTenths(t reflect.Type) uint64 {
	switch {
	case t.Kind() == reflect.Struct && t != timeType && t != celTimestampType && t != celDurationType:
		return tenths(t)
	case t.Kind() == reflect.Array:
		return length(t.Len()) * inlineTenths(t.Elem())
	default:
		return 0
	}
}

var celTimestampType, celDurationType = reflect.TypeFor[types.Timestamp](), reflect.TypeFor[types.Duration]()

// leastCopied is what copying a value of type t costs at the least: one for each 24 bytes it holds
// in place, and at least one, as each value it holds costs at least one and holds no more, and a
// byte, or a struct's, a tenth of one (payWhole).
func leastCopied(t reflect.Type) uint64 { return max(1, uint64(t.Size())/24) }

// keyTenths is what moving a map's key of type t whole costs past what converting a key costs, in
// tenths (tenths): the bytes of an array or a struct, which converting refuses as a key, and nothing
// for the rest, which hold no more than 16 in place. Hashing it reads what the strings and
// interfaces it holds hold too (payHashed).
func keyTenths(t reflect.Type) uint64 {
	if t.Kind() == reflect.Array || t.Kind() == reflect.Struct {
		return tenths(t)
	}
	return 0
}

// payHashed pays for what hashing key, which setting it in the copy does, reads past what reading it
// moved and its text cost: an array or a struct an interface key holds, which reading it moved none
// of, a tenth of its bytes in place (keyTenths), and the strings an array or a struct key holds, and
// what the interfaces it holds hold, a tenth of their bytes (payHashing), as Go hashes a key whole.
// Charged an array's or a struct's bytes in place alone, a copy of 50 entries keyed by structs each
// holding a string of 1 MiB took 1.4 ms, charged 167.
func (c *copier) payHashed(key reflect.Value) bool {
	if key.Kind() != reflect.Interface {
		return c.payHashing(key)
	}
	if key.IsNil() {
		return true
	}
	key = key.Elem()
	return c.pay(keyTenths(key.Type())/10) && (key.Kind() == reflect.String || !hashesHeld(key.Type()) || c.payHashing(key))
}

// payHashing pays a tenth of the bytes of each string v holds in place, and of what each interface it
// holds holds, in place and in turn, as hashing v reads them (payHashed).
func (c *copier) payHashing(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return c.pay(length(v.Len()) / 10)
	case reflect.Interface:
		if v.IsNil() {
			return true
		}
		e := v.Elem()
		return c.pay(tenths(e.Type())/10) && (!hashesHeld(e.Type()) || c.payHashing(e))
	case reflect.Array:
		for i := range v.Len() {
			if !c.payHashing(v.Index(i)) {
				return false
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); hashesHeld(f.Type()) && !c.payHashing(f) {
				return false
			}
		}
	default:
	}
	return true
}

// hashesHeld reports whether hashing a value of type t reads more than it holds in place: a string's
// bytes, or what an interface holds, or an array or struct holding either.
func hashesHeld(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.String, reflect.Interface:
		return true
	case reflect.Array:
		return t.Len() > 0 && hashesHeld(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if hashesHeld(t.Field(i).Type) {
				return true
			}
		}
	default:
	}
	return false
}

// shared reports whether a copy shares a value of type t, setting it whole where the copy holds it:
// one holding no map, slice, pointer or interface a copy would share (flat), and a time, whose
// fields are unexported, which no hook can write to but by replacing it whole.
func shared(t reflect.Type) bool {
	return t == timeType || t == celTimestampType || flat(t)
}

// flat reports whether a value of type t holds no map, slice, pointer or interface a copy would
// share: a scalar, a string, or an array or struct of them, which setting it copies whole.
func flat(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
		return true
	case reflect.Array:
		return flat(t.Elem())
	case reflect.Struct:
		for i := range t.NumField() {
			if !flat(t.Field(i).Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
