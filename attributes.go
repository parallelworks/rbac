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
	"cel.dev/cel-go/common/types/pb"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"

	// The well-known types the declarations refer to, registered by importing them.
	_ "google.golang.org/protobuf/types/known/durationpb"
	_ "google.golang.org/protobuf/types/known/structpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
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
// kind's are read as passed, and CEL compares values of different types as unequal. A map passed
// there may be keyed by a double that isn't finite, or by a list holding one, as an array of
// doubles, as no declared one may: comparing it, or a value holding it, fails, but `in` it is false
// for any key it doesn't hold, as CEL finds none equal to NaN.
//
// Whatever a host passes is read as CEL reads it, at what reading any value of its size costs,
// however it is passed. A value CEL decodes or merges whole to read, JSON text (json.RawMessage), a
// JSON number (json.Number), a packed message (anypb.Any), or a message of a dynamic type or of a
// host's type embedding one, is converted once for each check, the first time a condition reads
// it, at about what decoding it cost the host, rather than each time; such a message reaching one
// message twice, itself included, fails. So does a value CEL can't read, as a struct, which it
// would write out whole, and an array of more than 1 KiB of bytes, or a list or a map holding
// arrays or structs of more than 1 KiB each, which it copies whole each time a condition reads it.
// A value of a host's own type CEL reads as one of its own, as a double or a string, is read as
// the value it holds (its Value), so it compares as CEL's own does, from either side, and fails
// where it isn't finite; a list or a map of the host's own is read by its own methods, each value
// it yields read so. A value holding itself fails whatever reads it whole.
type Attributes struct {
	Subject, Resource, Request map[string]AttributeType
}

// AttributeType is a declared attribute's type.
type AttributeType string

// takes reports whether CEL reads v as a value of type t, whatever Go type a host passes it as:
// a named string type, or a []any of strings decoded from JSON, is a string or a list of them. It
// reads v through c, as conditions do.
func (t AttributeType) takes(c *converting, v any) (ok bool) {
	// Converting some values panics, such as a pointer to a slice, held or not: a condition reading
	// one fails, as CEL recovers it there, but this runs outside a condition, in the host's check.
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	switch v.(type) {
	case []string:
		return t == AttrStrings
	case map[string]string:
		return t == AttrStringMap
	}
	// A nil pointer is none, though CEL reads a nil timestamp or duration message as zero, and a
	// nil list or map message as empty.
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return false
	}
	switch v := c.NativeToValue(v).(type) {
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

// maxCopied is the most bytes a value CEL copies whole each time a condition reads it may hold: an
// array of bytes, which it copies into bytes of its own, or an array or a struct a list or a map
// holds, which reading one of them copies. Copying 1 KiB takes about as long as a read is charged.
const maxCopied = 1 << 10

// converting is how the conditions of a check read what the host passes: as CEL's own adapter does,
// each list and map a value holds read through it too, but for what that adapter reads whole each
// time a condition reads it, which CEL charges as one value however large it is, so a loop reading
// it would take time growing with its size and the loop's steps, charged only for the steps.
//
//   - A value CEL decodes, JSON text (json.RawMessage), a JSON number (json.Number) or a packed
//     message (anypb.Any), or merges into a message of its own, as a message of a dynamic type or
//     of a host's type embedding one, is converted once for the check, when a condition first
//     reads it, at about what decoding it cost the host, and read from then on as any value is. A
//     message it would merge that reaches a message twice, itself included, fails: merging one
//     holding itself recurses until the stack overflows, which no recover catches, and copies one
//     reached twice for each path to it.
//   - A value CEL can't read, as a struct, fails without being written out: CEL writes it whole into
//     its error, and without end where it holds itself.
//   - An array of bytes of more than maxCopied, or a list or a map holding arrays or structs of more
//     than maxCopied bytes each, fails: CEL copies each whole each time a condition reads it.
//   - A list, a map or an optional of CEL's own a host makes, as with CEL's adapter, is read as what
//     it holds, through this, so what it holds is converted once too.
//   - A ref.Val of a type of the host's own that CEL reads as a double, a string or another value
//     of a type of its own holding none is read as that value, what it holds (its Value), so a
//     double is one of CEL's own, which comparing fails where it isn't finite, and a string's length
//     counts in what reading it costs; one holding no such value fails. A list or a map of the
//     host's own is read as it reads itself, by its own methods, which are the host's to bound, but
//     each value it yields read through this. Any other, an opaque value, is read as it is.
//
// Each check makes its own, which keeps what it converted only while the check runs.
type converting struct {
	once map[copiedKey]converted
	// base is the adapter the conditions run with, which reads the rest as CEL does: the well-known
	// messages it knows past those of DefaultTypeAdapter, as google.protobuf.Empty, among them.
	base types.Adapter
}

func (c *converting) adapter() types.Adapter {
	if c.base == nil {
		return types.DefaultTypeAdapter
	}
	return c.base
}

// converted is what a value was converted to, and the value, kept so that no other comes to be
// where it was while its conversion is kept.
type converted struct {
	from any
	to   ref.Val
}

var byteType = reflect.TypeFor[byte]()

func (c *converting) NativeToValue(v any) ref.Val {
	switch v := v.(type) {
	case ref.Val:
		return c.own(v)
	case map[string]any:
		return types.NewStringInterfaceMap(c, v)
	case []ref.Val:
		return types.NewRefValList(c, v)
	case json.RawMessage, json.Number, *anypb.Any:
		return c.decoded(v)
	// Before protoreflect.Message: a dynamic message, as dynamicpb's, is its own reflection, so
	// reading it by its reflection would never end.
	case proto.Message:
		if itself(v) && generated(v) {
			return c.adapter().NativeToValue(v)
		}
		return c.merged(v)
	case *pb.Map:
		return types.NewProtoMap(c, v)
	case protoreflect.List:
		return types.NewProtoList(c, v)
	case protoreflect.Message:
		return c.NativeToValue(v.Interface())
	case protoreflect.Value:
		return c.NativeToValue(v.Interface())
	case nil, time.Time, []byte, []string, map[string]string:
		return c.adapter().NativeToValue(v)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Struct:
		return unreadableValue(v)
	case reflect.Pointer:
		// CEL reads a pointer to a list or a map by panicking, which fails the whole condition, as
		// an error a logical operator could absorb wouldn't: so it still does.
		if !rv.IsNil() && rv.Elem().Kind() == reflect.Struct {
			return unreadableValue(v)
		}
	case reflect.Array:
		if rv.Type().Elem() != byteType {
			return types.NewDynamicList(c, v)
		}
		if rv.Len() > maxCopied {
			return copiedWhole(v)
		}
	case reflect.Slice:
		if rv.Type().Elem() == byteType {
			break
		}
		if large(rv.Type().Elem()) {
			return copiedWhole(v)
		}
		return types.NewDynamicList(c, v)
	case reflect.Map:
		if large(rv.Type().Key()) || large(rv.Type().Elem()) {
			return copiedWhole(v)
		}
		return types.NewDynamicMap(c, v)
	default:
	}
	return c.adapter().NativeToValue(v)
}

// generated reports whether m is of the type protobuf generated for its message, which CEL reads
// as it is: one of another type, as a dynamic one, it merges whole into one of that type to read.
func generated(m proto.Message) bool {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(m.ProtoReflect().Descriptor().FullName())
	return err == nil && reflect.TypeOf(mt.Zero().Interface()) == reflect.TypeOf(m)
}

// large reports whether reading a value of type t a list or a map holds copies more than maxCopied
// bytes: an array or a struct, which it holds in place.
func large(t reflect.Type) bool {
	return (t.Kind() == reflect.Array || t.Kind() == reflect.Struct) && t.Size() > maxCopied
}

func unreadableValue(v any) ref.Val { return types.NewErr("rbac: a condition can't read a %T", v) }

func copiedWhole(v any) ref.Val {
	return types.NewErr("rbac: a condition can't read a %T: each read copies more than %d bytes", v, maxCopied)
}

// own is v as one of CEL's own values: v itself where it holds no other; for a list, a map or an
// optional of CEL's own, what it holds, read through c, and any other of CEL's own, as a message,
// itself, as CEL's adapter reads it; and for one of a type of the host's own, what it holds where
// CEL reads it as a value of a type of its own, and otherwise itself, reading through c each value
// it yields.
func (c *converting) own(v ref.Val) ref.Val {
	if holdsNone(v) {
		return v
	}
	if o, ok := v.(*types.Optional); ok {
		return c.keep(v, func() ref.Val { return c.optional(o) })
	}
	if ofCEL(v) {
		switch v.(type) {
		case traits.Lister, traits.Mapper:
			return c.keep(v, func() ref.Val { return c.held(v, true) })
		}
		return v
	}
	switch v := v.(type) {
	case traits.Mapper:
		return hostMap{v, c}
	case traits.Lister:
		return hostList{v, c}
	}
	if slices.Contains(celScalars, v.Type().TypeName()) {
		return c.held(v, false)
	}
	return v
}

// optional is o, what it holds read through c, unwrapping the optionals it nests in a loop: a host
// can nest them deep enough that recursing would overflow the stack, which no recover catches.
func (c *converting) optional(o *types.Optional) ref.Val {
	depth := 0
	for o.HasValue() {
		inner, ok := o.GetValue().(*types.Optional)
		if !ok {
			break
		}
		o, depth = inner, depth+1
	}
	var out ref.Val = o
	if o.HasValue() {
		out = types.OptionalOf(c.own(o.GetValue()))
	}
	for range depth {
		out = types.OptionalOf(out)
	}
	return out
}

// held is what v holds, its Value, read through c: what holds only a ref.Val holds nothing more
// to read, and else stands for v where it is of CEL's own, and fails where it is the host's, as
// reading one holding itself would never end.
func (c *converting) held(v ref.Val, ofCEL bool) ref.Val {
	switch held := v.Value().(type) {
	case ref.Val:
		if holdsNone(held) {
			return held
		}
		if ofCEL {
			return v
		}
		return unreadableValue(v)
	default:
		return c.NativeToValue(held)
	}
}

// ofCEL reports whether v is of one of CEL's own types, which are of the package celPackage names.
func ofCEL(v ref.Val) bool {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.PkgPath() == celPackage
}

var celPackage = reflect.TypeFor[types.Bool]().PkgPath()

// celScalars are the names of the types of CEL's own values that hold no other, which a host's own
// can be read as: their costs and guards read CEL's own values alone.
var celScalars = []string{
	types.BoolType.TypeName(), types.BytesType.TypeName(), types.DoubleType.TypeName(), types.DurationType.TypeName(),
	types.IntType.TypeName(), types.NullType.TypeName(), types.StringType.TypeName(), types.TimestampType.TypeName(),
	types.UintType.TypeName(),
}

// hostList is a list of a type of the host's own, read as it reads itself, but each value it yields
// read through c, as its own lists' values are.
type hostList struct {
	traits.Lister
	c *converting
}

func (l hostList) Get(i ref.Val) ref.Val     { return l.c.own(l.Lister.Get(i)) }
func (l hostList) Iterator() traits.Iterator { return hostIterator{l.Lister.Iterator(), l.c} }

// Add is the list it makes, read so too.
func (l hostList) Add(other ref.Val) ref.Val {
	sum := l.Lister.Add(other)
	if s, ok := sum.(traits.Lister); ok {
		return hostList{s, l.c}
	}
	return sum
}

// hostMap is a map of a type of the host's own, read as hostList reads a list.
type hostMap struct {
	traits.Mapper
	c *converting
}

func (m hostMap) Get(k ref.Val) ref.Val     { return m.c.own(m.Mapper.Get(k)) }
func (m hostMap) Iterator() traits.Iterator { return hostIterator{m.Mapper.Iterator(), m.c} }

func (m hostMap) Find(k ref.Val) (ref.Val, bool) {
	v, found := m.Mapper.Find(k)
	if found {
		v = m.c.own(v)
	}
	return v, found
}

type hostIterator struct {
	traits.Iterator
	c *converting
}

func (it hostIterator) Next() ref.Val { return it.c.own(it.Iterator.Next()) }

// holdsNone reports whether v is one of CEL's own values that holds no other.
func holdsNone(v ref.Val) bool {
	switch v.(type) {
	case types.Bool, types.Bytes, types.Double, types.Duration, types.Int, types.Null, types.String, types.Timestamp,
		types.Uint, *types.Err, *types.Unknown, *types.Type:
		return true
	}
	return false
}

// decoded is v, which CEL decodes whole to read, converted once.
func (c *converting) decoded(v any) ref.Val {
	return c.keep(v, func() ref.Val { return c.adapter().NativeToValue(v) })
}

// merged is m, a message CEL merges whole into one of its own to read, converted once, or failing
// where it reaches a message twice.
func (c *converting) merged(m proto.Message) ref.Val {
	r := m.ProtoReflect()
	return c.keep(r.Interface(), func() ref.Val {
		if !reachesOnce(r, map[proto.Message]bool{}) {
			return types.NewErr("rbac: a condition can't read a %T that reaches a message twice", m)
		}
		return c.adapter().NativeToValue(m)
	})
}

// reachesOnce reports whether m reaches no message twice, itself included, by its fields, of those
// not in seen, adding them to it. A nil message, as a list may hold, reaches none: each is the same
// nil, but none is another's.
func reachesOnce(m protoreflect.Message, seen map[proto.Message]bool) bool {
	if !m.IsValid() {
		return true
	}
	if seen[m.Interface()] {
		return false
	}
	seen[m.Interface()] = true
	once := true
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
					once = reachesOnce(v.Message(), seen)
					return once
				})
			}
		case fd.Message() == nil:
		case fd.IsList():
			for i := 0; once && i < v.List().Len(); i++ {
				once = reachesOnce(v.List().Get(i).Message(), seen)
			}
		default:
			once = reachesOnce(v.Message(), seen)
		}
		return once
	})
	return once
}

// keep is what convert makes of v, converted once for the check: a value is known as copier knows
// one (copiedKeyOf), so one held by value, which points nowhere, is converted each time.
func (c *converting) keep(v any, convert func() ref.Val) ref.Val {
	k, ok := copiedKeyOf(reflect.ValueOf(v))
	if !ok {
		return convert()
	}
	if done, ok := c.once[k]; ok {
		return done.to
	}
	to := convert()
	if c.once == nil {
		c.once = map[copiedKey]converted{}
	}
	c.once[k] = converted{v, to}
	return to
}

// The types an attribute can be declared as, with the Go value a host passes for each, or any
// other CEL reads as that type, such as a pointer to a string, number or bool, a protobuf
// timestamp or duration, or a []any or map[string]any of strings. A nil pointer is none.
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
// own, however deep, a protobuf message among them copied field by field, as cloning it would, and
// a value reached twice copied once, a message too, so a cycle ends. A struct's fields an
// unexported struct it embeds promotes are its own too, but its other unexported fields are shared,
// a pointer it embeds unexported among them, and so the fields that one promotes: reflection can't
// set them. A map's keys are shared too, and what a pointer among them reaches: a copied key would
// be another key, so the copy would find nothing under the one the host passed.
func deepCopy[T any](v T) T {
	out := reflect.ValueOf(&v).Elem()
	out.Set(copier{}.copy(out))
	return v
}

// copier copies values for deepCopy, keeping each map, slice and pointer it copied by where it
// points, its length and its type.
type copier map[copiedKey]reflect.Value

type copiedKey struct {
	t   reflect.Type
	at  uintptr
	len int
}

// copiedKeyOf is how copier and converting know v: a map, pointer, slice or string by where it
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

func (c copier) copy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if unreachable(v) {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(c.copy(v.Elem()))
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
			out.SetMapIndex(it.Key(), c.copy(it.Value()))
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
				out.Index(i).Set(c.copy(e))
			}
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		c.fields(out, v)
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := range v.Len() {
			out.Index(i).Set(c.copy(v.Index(i)))
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
			return reflect.ValueOf(c.message(m.ProtoReflect()).Interface())
		}
		out := reflect.New(v.Type().Elem())
		c[k] = out
		out.Elem().Set(c.copy(v.Elem()))
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
func (c copier) message(m protoreflect.Message) protoreflect.Message {
	if !m.IsValid() {
		return m.New()
	}
	k, keyed := copiedKeyOf(reflect.ValueOf(m.Interface()))
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
				to.Append(c.field(fd, from.Get(i)))
			}
		case fd.IsMap():
			to := out.Mutable(fd).Map()
			v.Map().Range(func(key protoreflect.MapKey, v protoreflect.Value) bool {
				to.Set(key, c.field(fd.MapValue(), v))
				return true
			})
		default:
			out.Set(fd, c.field(fd, v))
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
func (c copier) field(fd protoreflect.FieldDescriptor, v protoreflect.Value) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return protoreflect.ValueOfMessage(c.message(v.Message()))
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
func (c copier) fields(out, v reflect.Value) {
	for i := range v.NumField() {
		switch f := out.Field(i); {
		case f.CanSet():
			f.Set(c.copy(v.Field(i)))
		case v.Type().Field(i).Anonymous && f.Kind() == reflect.Struct:
			c.fields(f, v.Field(i))
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
