package rbac

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"
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
// Declaring changes only what is refused when stored: a condition reading an attribute a request
// doesn't carry, or carries as another type, is still false when it runs, and a deny's applies.
type Attributes struct {
	Subject, Resource, Request map[string]AttributeType
}

// AttributeType is a declared attribute's type.
type AttributeType string

// The types an attribute can be declared as, with the Go value a host passes for each.
const (
	AttrString    AttributeType = "string"              // string
	AttrInt       AttributeType = "int"                 // int or int64
	AttrDouble    AttributeType = "double"              // float64
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
		cel.TypeDescs(desc),
		cel.Variable("subject", cel.ObjectType("rbac.Subject")),
		cel.Variable("resource", cel.ObjectType("rbac.Resource")),
		cel.Variable("request", cel.ObjectType("rbac.Request")),
		cel.Variable("action", cel.StringType),
	)
}
