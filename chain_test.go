package rbac_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"maps"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// exportAll exports history in batches of two, as an exporter would, until it has every record
// history held when it began, and returns the records and the checkpoint after each batch.
func exportAll(t *testing.T, h *harness, signer crypto.Signer) ([]rbac.Record, []rbac.Checkpoint) {
	t.Helper()
	var want int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM rbac_history WHERE entity <> 'commit'`).Scan(&want); err != nil {
		t.Fatal(err)
	}
	var records []rbac.Record
	var checkpoints []rbac.Checkpoint
	var at rbac.Checkpoint
	for deadline := time.Now().Add(10 * time.Second); len(records) < want; {
		got, next, err := h.authz.Export(t.Context(), at, 2, signer)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			// Another session's open transaction holds the export back.
			if time.Now().After(deadline) {
				t.Fatalf("exported %d of %d records", len(records), want)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		records, at = append(records, got...), next
		checkpoints = append(checkpoints, next)
	}
	return records, checkpoints
}

func TestAnExportIsChainedAndSigned(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"ecdsa": ecKey, "ed25519": edKey, "rsa": rsaKey} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			ctx := t.Context()
			// A clock finer than the stores a checkpoint is kept in.
			h.now = h.now.Add(time.Nanosecond)
			h.as(t, "u", "ops")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.login", rbac.Group, "ops"))
			if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); err != nil {
				t.Fatal(err)
			}
			records, checkpoints := exportAll(t, h, key)
			last := checkpoints[len(checkpoints)-1]
			genesis := rbac.Genesis(last.Cursor.Generation)
			if err := rbac.VerifyChain(genesis, records, stored(last), key.Public()); err != nil {
				t.Fatalf("the whole export: %v", err)
			}
			// Each batch between its checkpoints.
			from, i := genesis, 0
			for _, c := range checkpoints {
				n := int(c.Count - from.Count)
				if err := rbac.VerifyChain(from, records[i:i+n], c, key.Public()); err != nil {
					t.Fatalf("records %d to %d: %v", i, i+n, err)
				}
				from, i = c, i+n
			}
			// A record changed, dropped or out of its order breaks the chain; another key, or another
			// signature, the checkpoint.
			changed := slices.Clone(records)
			changed[1].Actor = rbac.Principal{Kind: rbac.User, ID: "mallory"}
			swapped := slices.Clone(records)
			swapped[1], swapped[2] = swapped[2], swapped[1]
			otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			resigned := last
			resigned.Signature = slices.Clone(last.Signature)
			resigned.Signature[len(resigned.Signature)-1] ^= 1
			for what, err := range map[string]error{
				"a record changed":   rbac.VerifyChain(genesis, changed, last, key.Public()),
				"a record dropped":   rbac.VerifyChain(genesis, slices.Delete(slices.Clone(records), 1, 2), last, key.Public()),
				"records reordered":  rbac.VerifyChain(genesis, swapped, last, key.Public()),
				"another key":        rbac.VerifyChain(genesis, records, last, otherKey.Public()),
				"another signature":  rbac.VerifyChain(genesis, records, resigned, key.Public()),
				"another generation": rbac.VerifyChain(rbac.Genesis("1/1"), records, last, key.Public()),
			} {
				if !errors.Is(err, rbac.ErrUnverified) {
					t.Errorf("%s: %v", what, err)
				}
			}
		})
	}
}

// stored is c as a store gives it back: its times to the microsecond, in a location of the store's
// own.
func stored(c rbac.Checkpoint) rbac.Checkpoint {
	zone := time.FixedZone("", 5*3600+1800)
	c.Cursor.RecordedAt = c.Cursor.RecordedAt.In(zone)
	c.At = c.At.Truncate(time.Microsecond).In(zone)
	return c
}

// garbled is a signer whose signatures are in no form Verify reads.
type garbled struct{ *ecdsa.PrivateKey }

func (garbled) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte("garbled"), nil
}

func TestAnExportIsSigned(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	if _, _, err := h.authz.Export(ctx, rbac.Checkpoint{}, 10, nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("an export with no signer: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, at, err := h.authz.Export(ctx, rbac.Checkpoint{}, 10, key)
	if err != nil {
		t.Fatal(err)
	}
	// A signature that doesn't verify is refused, and the export stays where it was.
	if _, got, err := h.authz.Export(ctx, at, 10, garbled{key}); !errors.Is(err, rbac.ErrUnverified) || !reflect.DeepEqual(got, at) {
		t.Fatalf("an export its signature doesn't verify: %v, at %+v", err, got)
	}
	// A cursor isn't a checkpoint: chained onto no genesis, its export would never verify.
	for what, from := range map[string]rbac.Checkpoint{"a cursor": {Cursor: at.Cursor}, "a count": {Count: 1}} {
		if _, _, err := h.authz.Export(ctx, from, 10, key); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("an export from %s: %v", what, err)
		}
	}
	// A checkpoint is dated when it is made, not as of a time read.
	if err := h.authz.AsOf(ctx, "t1", h.now.Add(-time.Hour), func(a *rbac.Authorizer) error {
		_, _, err := a.Export(ctx, at, 10, key)
		return err
	}); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("an export as of a time: %v", err)
	}
}

// racedSigner is a signer whose key is read from PostgreSQL, which refused the read: its error.
type racedSigner struct {
	*ecdsa.PrivateKey
	err error
}

func (s racedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, s.err }

// A signer's error holding PostgreSQL's refusal for a race, as of a read of its key, matches
// ErrConflict, still wrapping the signer's own, from every exported function or method given a
// signer, as a hook's does: the package's source names each, so one added without mapping it fails
// here, and History, which Export reads first, doesn't map it for Export.
func TestASignersRaceConflicts(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	errKey := errors.New("reading the signing key")
	signer := racedSigner{key, fmt.Errorf("%w: %w", errKey, &pgconn.PgError{Code: "55P03", Message: "canceling statement due to lock timeout"})}
	calls := map[string]func() error{
		"Authorizer.Export": func() error {
			_, _, err := h.authz.Export(ctx, rbac.Checkpoint{}, 10, signer)
			return err
		},
		"Checkpoint.Sign": func() error { return second(rbac.Genesis("g").Sign(signer)) },
	}
	given := givenSigners(t)
	for _, name := range given {
		if calls[name] == nil {
			t.Errorf("%s isn't checked for a signer refused for a race", name)
		}
	}
	for name, call := range calls {
		if !slices.Contains(given, name) {
			t.Errorf("%s isn't found to be given a signer", name)
		}
		if err := call(); !errors.Is(err, rbac.ErrConflict) || !errors.Is(err, errKey) {
			t.Errorf("%s, whose signer was refused for a race: %v", name, err)
		}
	}
}

// givenSigners names the package's exported functions, and the methods of its exported types, theirs
// or promoted from a type of the package's they embed, that are given a crypto.Signer or
// crypto.MessageSigner by a parameter: as it is, or in a type of the package's, a pointer, a list,
// a map, a variadic parameter, a function, an interface or a type parameter's constraint.
// Reflection reads no function, and only the methods of the types it is given, so the source is
// read; a receiver it can't name fails it, so no method goes unread.
func givenSigners(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// Each declaration with the name its file imports crypto by.
	type declared struct {
		of     ast.Expr
		params *ast.FieldList
		alias  string
	}
	types := map[string]declared{}
	type fn struct {
		decl  *ast.FuncDecl
		alias string
	}
	var funcs []fn
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		alias := ""
		for _, imp := range f.Imports {
			if imp.Path.Value == `"crypto"` {
				alias = "crypto"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
			}
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if s, ok := s.(*ast.TypeSpec); ok {
						types[s.Name.Name] = declared{s.Type, s.TypeParams, alias}
					}
				}
			case *ast.FuncDecl:
				funcs = append(funcs, fn{d, alias})
			}
		}
	}
	// A type parameter in scope, by its name: its constraint, read with its file's crypto.
	type param struct {
		constraint ast.Expr
		alias      string
	}
	// A method's receiver can name its type's parameters anew, in order, as named reads them.
	paramsOf := func(fl *ast.FieldList, alias string, names []string) map[string]param {
		ps := map[string]param{}
		i := 0
		for _, f := range fieldsOf(fl) {
			for _, n := range f.Names {
				if names != nil && i < len(names) {
					n = ast.NewIdent(names[i])
				}
				ps[n.Name] = param{f.Type, alias}
				i++
			}
		}
		return ps
	}
	var holds func(e ast.Expr, alias string, params map[string]param, seen map[any]bool) bool
	fields := func(fl *ast.FieldList, alias string, params map[string]param, seen map[any]bool) bool {
		return fl != nil && slices.ContainsFunc(fl.List, func(f *ast.Field) bool { return holds(f.Type, alias, params, seen) })
	}
	holds = func(e ast.Expr, alias string, params map[string]param, seen map[any]bool) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			pkg, ok := x.X.(*ast.Ident)
			return ok && alias != "" && pkg.Name == alias && (x.Sel.Name == "Signer" || x.Sel.Name == "MessageSigner")
		case *ast.Ident:
			if p, ok := params[x.Name]; ok {
				if seen[p.constraint] {
					return false
				}
				seen[p.constraint] = true
				return holds(p.constraint, p.alias, params, seen)
			}
			d, ok := types[x.Name]
			if !ok || seen[x.Name] {
				return false
			}
			seen[x.Name] = true
			return holds(d.of, d.alias, paramsOf(d.params, d.alias, nil), seen)
		case *ast.StarExpr:
			return holds(x.X, alias, params, seen)
		case *ast.ParenExpr:
			return holds(x.X, alias, params, seen)
		case *ast.UnaryExpr:
			return holds(x.X, alias, params, seen)
		case *ast.BinaryExpr:
			return holds(x.X, alias, params, seen) || holds(x.Y, alias, params, seen)
		case *ast.ArrayType:
			return holds(x.Elt, alias, params, seen)
		case *ast.Ellipsis:
			return holds(x.Elt, alias, params, seen)
		case *ast.MapType:
			return holds(x.Key, alias, params, seen) || holds(x.Value, alias, params, seen)
		case *ast.ChanType:
			return holds(x.Value, alias, params, seen)
		case *ast.StructType:
			return fields(x.Fields, alias, params, seen)
		case *ast.InterfaceType:
			return fields(x.Methods, alias, params, seen)
		case *ast.FuncType:
			return fields(x.Params, alias, params, seen) || fields(x.Results, alias, params, seen)
		case *ast.IndexExpr:
			return holds(x.X, alias, params, seen) || holds(x.Index, alias, params, seen)
		case *ast.IndexListExpr:
			return holds(x.X, alias, params, seen) || slices.ContainsFunc(x.Indices, func(i ast.Expr) bool { return holds(i, alias, params, seen) })
		}
		return false
	}
	// named is the type a receiver or an embedded field names, and the names it gives the type's
	// parameters.
	named := func(e ast.Expr) (string, []string, bool) {
		if star, ok := e.(*ast.StarExpr); ok {
			e = star.X
		}
		var indices []ast.Expr
		switch x := e.(type) {
		case *ast.IndexExpr:
			e, indices = x.X, []ast.Expr{x.Index}
		case *ast.IndexListExpr:
			e, indices = x.X, x.Indices
		}
		id, ok := e.(*ast.Ident)
		if !ok {
			return "", nil, false
		}
		var names []string
		for _, i := range indices {
			if n, ok := i.(*ast.Ident); ok {
				names = append(names, n.Name)
			}
		}
		return id.Name, names, true
	}
	given := map[string][]string{}
	for _, f := range funcs {
		if !f.decl.Name.IsExported() {
			continue
		}
		params := paramsOf(f.decl.Type.TypeParams, f.alias, nil)
		recv := ""
		if f.decl.Recv != nil {
			name, indices, ok := named(f.decl.Recv.List[0].Type)
			if !ok {
				t.Fatalf("the receiver of %s names no type this reads", f.decl.Name.Name)
			}
			recv = name
			maps.Copy(params, paramsOf(types[name].params, types[name].alias, indices))
		}
		if fields(f.decl.Type.Params, f.alias, params, map[any]bool{}) {
			given[recv] = append(given[recv], f.decl.Name.Name)
		}
	}
	names := slices.Clone(given[""])
	// An exported type's methods, and those of the unexported types it embeds, which it promotes.
	var promoted func(of string, seen map[string]bool) []string
	promoted = func(of string, seen map[string]bool) []string {
		if seen[of] {
			return nil
		}
		seen[of] = true
		methods := slices.Clone(given[of])
		if st, ok := types[of].of.(*ast.StructType); ok {
			for _, f := range st.Fields.List {
				if name, _, ok := named(f.Type); ok && len(f.Names) == 0 && !ast.IsExported(name) {
					methods = append(methods, promoted(name, seen)...)
				}
			}
		}
		return methods
	}
	for of := range types {
		if ast.IsExported(of) {
			for _, m := range promoted(of, map[string]bool{}) {
				names = append(names, of+"."+m)
			}
		}
	}
	return names
}

// fieldsOf is fl's fields, none where it is nil.
func fieldsOf(fl *ast.FieldList) []*ast.Field {
	if fl == nil {
		return nil
	}
	return fl.List
}

// An export chains and signs history, not a session's temporary table named as it, which any role
// may make and a pool keeps on its connection.
func TestAnExportSignsHistoryWhateverTablesASessionMakes(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records, checkpoints := exportAll(t, h, key)
	last := checkpoints[len(checkpoints)-1]
	// On a session of its own, which has planned none of History's statements.
	h.pool.Reset()
	if _, err := h.pool.Exec(ctx, `CREATE TEMP TABLE rbac_history AS SELECT * FROM rbac_history;
		INSERT INTO pg_temp.rbac_history (id, txid, recorded_at, effective_at, tenant, entity, key, op)
		VALUES (0, '1', now(), now(), 't1', 'grant', 'forged', 'create')`); err != nil {
		t.Fatal(err)
	}
	got, from, err := h.authz.Export(ctx, rbac.Checkpoint{}, rbac.MaxHistory, key)
	if err != nil || !reflect.DeepEqual(got, records) || from.Hash != last.Hash || from.Count != last.Count || from.Cursor.Generation != last.Cursor.Generation {
		t.Fatalf("an export beside a session's own history = %+v, %+v, %v", got, from, err)
	}
	if more, _, err := h.authz.Export(ctx, last, 1, key); err != nil || len(more) != 0 {
		t.Fatalf("an export from its checkpoint, beside a session's own history = %+v, %v", more, err)
	}
}

// full is a record with every field set: its ids hold colons, and its reason U+FFFD, which JSON
// writes for a byte that isn't UTF-8.
func full() rbac.Record {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	ids := rbac.Principal{Kind: rbac.User, ID: "a:b"}
	return rbac.Record{
		ID: 1, TxID: 2, RecordedAt: at, EffectiveAt: at.Add(time.Second), Tenant: "t1", Entity: "grant", Key: "k", Op: "update",
		Principal: ids, Role: "cluster.login", Scope: rbac.Scope{Type: "org", ID: "a:b"}, Group: "ops", ExpiresAt: at.Add(time.Hour),
		Before: json.RawMessage(`{"a": 1}`), After: json.RawMessage(`{"a": 2}`), Actor: ids, OnBehalfOf: ids,
		How: "Apply", Request: "r", Reason: "why" + string(utf8.RuneError), DBUser: "app", CommittedAt: at.Add(2 * time.Second),
	}
}

// Every field of a record is chained, a principal's or scope's kind and id apart, and a record
// that isn't as history holds them, its row not JSON or its text not UTF-8, doesn't chain.
func TestAChainedRecordIsEveryField(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := full()
	genesis := rbac.Genesis("g")
	at, err := genesis.Chain([]rbac.Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if at, err = at.Sign(key); err != nil {
		t.Fatal(err)
	}
	changed := map[string]rbac.Record{}
	var each func(name string, index []int, typ reflect.Type)
	each = func(name string, index []int, typ reflect.Type) {
		for i := range typ.NumField() {
			f, index := typ.Field(i), append(slices.Clone(index), i)
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeFor[time.Time]() {
				each(name+f.Name+".", index, f.Type)
				continue
			}
			r := record
			v := reflect.ValueOf(&r).Elem().FieldByIndex(index)
			switch x := v.Addr().Interface().(type) {
			case *time.Time:
				*x = x.Add(time.Microsecond)
			case *json.RawMessage:
				*x = json.RawMessage(`{"a": 3}`)
			case *int64:
				*x++
			case *uint64:
				*x++
			default:
				if v.Kind() != reflect.String {
					t.Fatalf("%s%s is a %s, which this test doesn't change", name, f.Name, f.Type)
				}
				v.SetString(v.String() + "x")
			}
			changed[name+f.Name] = r
		}
	}
	each("", nil, reflect.TypeFor[rbac.Record]())
	moved := rbac.Principal{Kind: "user:a", ID: "b"}
	principal, scope, actor, onBehalfOf, row, text := record, record, record, record, record, record
	principal.Principal, scope.Scope, actor.Actor, onBehalfOf.OnBehalfOf = moved, rbac.Scope{Type: "org:a", ID: "b"}, moved, moved
	row.After = json.RawMessage("{")
	text.Reason = "why\xff"
	maps.Copy(changed, map[string]rbac.Record{
		"principal's colon": principal, "scope's colon": scope, "actor's colon": actor, "on behalf of's colon": onBehalfOf,
		"row": row, "text": text,
	})
	for what, r := range changed {
		if err := rbac.VerifyChain(genesis, []rbac.Record{r}, at, key.Public()); !errors.Is(err, rbac.ErrUnverified) {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// The chain's encoding is fixed, so a checkpoint made with one Go, and verified with another or
// in another language, holds. A checkpoint without a Horizon is signed as before Cursor had one,
// and a record without a CommittedAt or a Cluster, as one of a transaction that committed before
// history recorded commits, chains as before Record had either. One with a Cluster but no
// CommittedAt, as one a dump carried from a cluster whose commit records are gone, chains an empty
// CommittedAt before it.
func TestTheChainsEncodingIsFixed(t *testing.T) {
	c := rbac.Genesis("g")
	genesis := hex.EncodeToString(c.Hash[:])
	committed, err := c.Chain([]rbac.Record{full()})
	if err != nil {
		t.Fatal(err)
	}
	stamped := full()
	stamped.Cluster = "7698052984130977836"
	clustered, err := c.Chain([]rbac.Record{stamped})
	if err != nil {
		t.Fatal(err)
	}
	stamped.CommittedAt = time.Time{}
	restored, err := c.Chain([]rbac.Record{stamped})
	if err != nil {
		t.Fatal(err)
	}
	before := full()
	before.CommittedAt = time.Time{}
	c, err = c.Chain([]rbac.Record{before})
	if err != nil {
		t.Fatal(err)
	}
	c.At = time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC)
	digest := c.Digest()
	c.Cursor.Horizon = 3
	horizon := c.Digest()
	got := map[string]string{
		"genesis": genesis, "link": hex.EncodeToString(c.Hash[:]), "digest": hex.EncodeToString(digest[:]),
		"horizon": hex.EncodeToString(horizon[:]), "committed": hex.EncodeToString(committed.Hash[:]),
		"clustered": hex.EncodeToString(clustered.Hash[:]), "restored": hex.EncodeToString(restored.Hash[:]),
	}
	want := map[string]string{
		"genesis":   "928df9c16fcd6389159e046198b064eedcc7a780dfe164845c5fd47663f081ac",
		"link":      "4079403bdbf717782762c3391d6a334dcc6f2fbda933e8ae01ffc57e7c16d31e",
		"digest":    "7dab694ab96cc22d6be1a0dab37af4f06c9cb1931c533e0843ad365ff0a89b8b",
		"horizon":   "c4965b59b9651be1ddd59a15d7b4eb88949af51668d163ee1eeb6f6fc0cb2ce2",
		"committed": "2ae926382b3b391249ac8a624910204494a632b3fb47eae0df99d3de9fdaf51f",
		"clustered": "1ccba01a50885a14b9f451627456e2d8f362e44d4f2ebc10a70f81bc767b8958",
		"restored":  "9b923726c183e672857445f1b8b654ef6c24e7927dba9a852ad061d32e844901",
	}
	if !maps.Equal(got, want) {
		t.Errorf("%v, not %v", got, want)
	}
}

// exportNext exports up to limit records after from until it reads one, as another session's open
// transaction can hold an export back, and returns them and their checkpoint.
func exportNext(t *testing.T, h *harness, from rbac.Checkpoint, limit int, signer crypto.Signer) ([]rbac.Record, rbac.Checkpoint) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		records, next, err := h.authz.Export(t.Context(), from, limit, signer)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) > 0 {
			return records, next
		}
		if time.Now().After(deadline) {
			t.Fatal("read 0 records")
		}
	}
}

// A checkpoint's Horizon tells History which prunes to refuse its cursor for: one moved past a
// prune that deleted records the export hadn't read would read on past them. So the signature
// covers it, Export refuses a checkpoint whose Horizon was moved, and VerifyChain refuses to go on
// from an export begun before the prune with a checkpoint of one begun after it, which can stand at
// a record with the same chain but goes on past what the prune deleted.
func TestACheckpointVouchesForItsHorizon(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := interleaved(t, h)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// An export that has read the first record, behind what a prune through the end deletes.
	_, behind := exportNext(t, h, rbac.Checkpoint{}, 1, key)
	if behind.Cursor.Horizon == 0 {
		t.Fatalf("an export from the start has no Horizon: %+v", behind.Cursor)
	}
	if n, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); err != nil || n != 8 {
		t.Fatalf("PruneHistory = %d, %v", n, err)
	}
	if _, _, err := h.authz.Export(ctx, behind, 10, key); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("Export from before what a prune deleted: %v", err)
	}
	for _, horizon := range []uint64{0, behind.Cursor.Horizon + 1, math.MaxUint64} {
		c := behind
		c.Cursor.Horizon = horizon
		if err := c.Verify(key.Public()); !errors.Is(err, rbac.ErrUnverified) {
			t.Errorf("a checkpoint whose Horizon was moved to %d: %v", horizon, err)
		}
		if got, next, err := h.authz.Export(ctx, c, 10, key); !errors.Is(err, rbac.ErrUnverified) || !reflect.DeepEqual(next, c) {
			t.Errorf("Export from a checkpoint whose Horizon was moved to %d: %d records, %v", horizon, len(got), err)
		}
	}
	// An export from the start after the prune reads the same first record, which the prune kept.
	_, again := exportNext(t, h, rbac.Checkpoint{}, 1, key)
	if again.Hash != behind.Hash || again.Count != behind.Count || again.Cursor.Horizon <= behind.Cursor.Horizon {
		t.Fatalf("an export from the start after a prune = %+v, before it %+v", again, behind)
	}
	records, next := exportNext(t, h, again, 10, key)
	if err := rbac.VerifyChain(again, records, next, key.Public()); err != nil {
		t.Fatalf("an export begun after a prune: %v", err)
	}
	if err := rbac.VerifyChain(behind, records, next, key.Public()); !errors.Is(err, rbac.ErrUnverified) {
		t.Errorf("records exported past what a prune deleted, after a checkpoint of an export begun before it: %v", err)
	}
}

// What AsOf answers turns on nothing an export leaves out, so history's owner can't change it
// unseen: it dates each version by its own transaction's commit records within its cluster, as
// History does for CommittedAt. A commit record no version names, holding as its bound on the
// transactions then running one past them all, as an earlier build's commit records held one,
// changes no answer, where counting every change of a transaction below that bound as committed had
// a revoke held open read as in force with every record History returns as it was. And rewriting a
// restored record's cluster, which History returns, no longer verifies against what an export kept.
func TestAsOfAnswersByNothingAnExportLeavesOut(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	ours, theirs := otherCluster(t, h)
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.login", rbac.User, "tmpl"))
	restored := dbNow(t, h).UTC().Format("2006-01-02 15:04:05.999999+00")
	restoreRows(t, h, fakeGrant("restored", restored, theirs, "9", false), fakeCommit(restored, theirs, "9"))
	// A revoke of u's grant held open past mid.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	mid := dbNow(t, h)
	time.Sleep(20 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kept, at := exportNext(t, h, rbac.Checkpoint{}, rbac.MaxHistory, key)
	for _, c := range []struct {
		name     string
		rewrite  []string
		verifies bool
	}{
		{"a commit record no version names, bounding every transaction", []string{
			`ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_committed`,
			fmt.Sprintf(`INSERT INTO rbac_history (effective_at, txid, cluster, tenant, entity, key, op, after, bytes)
				VALUES (timestamptz '%s', '7'::xid8, %s, '', 'commit', '', 'commit', '{"xmin": "18446744073709551000"}', 0)`, restored, ours),
			`ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed`,
		}, true},
		{"a restored record's cluster", []string{
			`ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_append_only`,
			`UPDATE rbac_history SET cluster = ` + ours + ` WHERE txid = '9'`,
			`ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_append_only`,
		}, false},
	} {
		for _, q := range c.rewrite {
			if _, err := h.pool.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		if err := h.authz.AsOf(ctx, "t1", mid, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) }); err != nil {
			t.Errorf("with %s written, as of while the revoke was held open, u's login: %v", c.name, err)
		}
		again, _ := exportNext(t, h, rbac.Checkpoint{}, rbac.MaxHistory, key)
		if len(again) < len(kept) {
			t.Fatalf("with %s written, an export again read %d records, before %d", c.name, len(again), len(kept))
		}
		if err := rbac.VerifyChain(rbac.Genesis(at.Cursor.Generation), again[:len(kept)], at, key.Public()); (err == nil) != c.verifies {
			t.Errorf("with %s written, history against the checkpoint kept before: %v", c.name, err)
		}
	}
}

// Export reads on from a checkpoint's cursor and chains onto its hash, which VerifyChain checks
// against the checkpoint kept: given one whose cursor was moved ahead, its hash kept, it would skip
// the records between with a chain that verifies. So it goes on only from a checkpoint its signer's
// key verifies, and a host changing keys signs the latest with the new one.
func TestAnExportGoesOnOnlyFromACheckpointItsKeyVerifies(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	interleaved(t, h)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, at := exportNext(t, h, rbac.Checkpoint{}, 1, key)
	_, ahead := exportNext(t, h, at, 2, key)
	moved := at
	moved.Cursor = ahead.Cursor
	unsigned := rbac.Genesis(at.Cursor.Generation)
	for what, from := range map[string]struct {
		rbac.Checkpoint
		crypto.Signer
	}{
		"whose cursor was moved ahead": {moved, key},
		"another key signed":           {at, newKey},
		"no key signed":                {unsigned, key},
	} {
		if got, next, err := h.authz.Export(ctx, from.Checkpoint, 10, from.Signer); !errors.Is(err, rbac.ErrUnverified) || !reflect.DeepEqual(next, from.Checkpoint) {
			t.Errorf("Export from a checkpoint %s: %d records, %v", what, len(got), err)
		}
	}
	rotated, err := at.Sign(newKey)
	if err != nil {
		t.Fatal(err)
	}
	records, next := exportNext(t, h, rotated, 10, newKey)
	if err := rbac.VerifyChain(rbac.Genesis(at.Cursor.Generation), first, rotated, newKey.Public()); err != nil {
		t.Errorf("a checkpoint signed again with a new key: %v", err)
	}
	if err := rbac.VerifyChain(rotated, records, next, newKey.Public()); err != nil {
		t.Errorf("an export from a checkpoint signed again with a new key: %v", err)
	}
}

func TestACheckpointIsVerifiedByItsPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	c := rbac.Genesis("g")
	d := c.Digest()
	if c.Signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(key.Public()); err != nil {
		t.Errorf("an RSA key's PSS signature: %v", err)
	}
	// A PSS salt is as long as the hash, as a key management service's is: FIPS 186-5 approves none
	// longer, which Go's FIPS 140-only mode verifies all the same.
	salted := c
	if salted.Signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: 20}); err != nil {
		t.Fatal(err)
	}
	if err := salted.Verify(key.Public()); !errors.Is(err, rbac.ErrUnverified) {
		t.Errorf("a PSS signature with a salt shorter than the hash: %v", err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	short := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1023, 1), E: 65537}
	for what, pub := range map[string]crypto.PublicKey{
		"a private key":            key,
		"an RSA key of 1024 bits":  short,
		"an RSA key of 2048 bits":  &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 2047, 1), E: 65537},
		"a P-224 key":              p224.Public(),
		"an Ed25519 key too short": ed25519.PublicKey(make([]byte, ed25519.PublicKeySize-1)),
		"no ECDSA key":             (*ecdsa.PublicKey)(nil),
		"no RSA key":               (*rsa.PublicKey)(nil),
	} {
		if err := c.Verify(pub); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", what, err)
		}
	}
}
