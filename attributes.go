package rbac

import (
	"fmt"
	"maps"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/traits"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	// The well-known types the declarations refer to, registered by importing them.
	_ "google.golang.org/protobuf/types/known/durationpb"
	_ "google.golang.org/protobuf/types/known/structpb"
	_ "google.golang.org/protobuf/types/known/timestamppb"
)

// Attributes declares the attributes conditions read, so that a condition reading one that isn't
// declared, or reading one as another type, is refused when it is stored, rather than being false
// whenever it runs. Each map names attributes and their types; a nil one leaves that kind
// undeclared, read as any value under any name. Declared, they are read as fields, such as
// `resource.attributes.env`, and named as identifiers.
//
// A condition reading an attribute a request doesn't carry, or carries as a value CEL reads as
// another type than it is declared, as nil, or as a double that is NaN or infinite, is false when
// it runs, and a deny's applies: a declared attribute passed so fails whatever reads it, comparing
// it with `!=`, testing it with has(), or a map or list holding it, included, and so does reading
// the kind's attributes as a whole, by `in`, size(), a macro or comparing them. A name a declared
// kind doesn't declare, which a condition reads only through dyn(), fails so too. An undeclared
// kind's are read as passed, and CEL compares values of different types as unequal.
type Attributes struct {
	Subject, Resource, Request map[string]AttributeType
}

// AttributeType is a declared attribute's type.
type AttributeType string

// takes reports whether CEL reads v as a value of type t, whatever Go type a host passes it as:
// a named string type, or a []any of strings decoded from JSON, is a string or a list of them.
func (t AttributeType) takes(v any) (ok bool) {
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
	switch v := types.DefaultTypeAdapter.NativeToValue(v).(type) {
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
				// A map is a repeated entry of a key and a value, named for its field.
				entry := mapEntryName(name)
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
// own, however deep, a protobuf message among them cloned, and a value reached twice copied once,
// so a cycle ends.
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

func (c copier) copy(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(c.copy(v.Elem()))
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		k := copiedKey{v.Type(), v.Pointer(), 0}
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
		k := copiedKey{v.Type(), v.Pointer(), v.Len()}
		if done, ok := c[k]; ok {
			return done
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		c[k] = out
		// Each hook is given its own, so elements no write could reach through are copied at once.
		if flat(v.Type().Elem()) {
			reflect.Copy(out, v)
			return out
		}
		for i := range v.Len() {
			out.Index(i).Set(c.copy(v.Index(i)))
		}
		return out
	case reflect.Struct:
		// Its exported fields, which a hook can write to: an unexported one is out of its reach, as
		// out of reflection's to set.
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := range v.NumField() {
			if f := out.Field(i); f.CanSet() {
				f.Set(c.copy(v.Field(i)))
			}
		}
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
		if m, ok := v.Interface().(proto.Message); ok {
			return reflect.ValueOf(proto.Clone(m))
		}
		k := copiedKey{v.Type(), v.Pointer(), 0}
		if done, ok := c[k]; ok {
			return done
		}
		out := reflect.New(v.Type().Elem())
		c[k] = out
		out.Elem().Set(c.copy(v.Elem()))
		return out
	default:
		return v
	}
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
