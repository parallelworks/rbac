package rbac_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math/big"
	"reflect"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/parallelworks/rbac"
)

// exportAll exports history in batches of two, as an exporter would, until it has every record
// history held when it began, and returns the records and the checkpoint after each batch.
func exportAll(t *testing.T, h *harness, signer crypto.Signer) ([]rbac.Record, []rbac.Checkpoint) {
	t.Helper()
	var want int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM rbac_history`).Scan(&want); err != nil {
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

// full is a record with every field set: its ids hold colons, and its reason U+FFFD, which JSON
// writes for a byte that isn't UTF-8.
func full() rbac.Record {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	ids := rbac.Principal{Kind: rbac.User, ID: "a:b"}
	return rbac.Record{
		ID: 1, TxID: 2, RecordedAt: at, EffectiveAt: at.Add(time.Second), Tenant: "t1", Entity: "grant", Key: "k", Op: "update",
		Principal: ids, Role: "cluster.login", Scope: rbac.Scope{Type: "org", ID: "a:b"}, Group: "ops", ExpiresAt: at.Add(time.Hour),
		Before: json.RawMessage(`{"a": 1}`), After: json.RawMessage(`{"a": 2}`), Actor: ids, OnBehalfOf: ids,
		How: "Apply", Request: "r", Reason: "why" + string(utf8.RuneError), DBUser: "app",
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
// in another language, holds.
func TestTheChainsEncodingIsFixed(t *testing.T) {
	c := rbac.Genesis("g")
	genesis := hex.EncodeToString(c.Hash[:])
	c, err := c.Chain([]rbac.Record{full()})
	if err != nil {
		t.Fatal(err)
	}
	c.At = time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC)
	digest := c.Digest()
	got := map[string]string{"genesis": genesis, "link": hex.EncodeToString(c.Hash[:]), "digest": hex.EncodeToString(digest[:])}
	want := map[string]string{
		"genesis": "928df9c16fcd6389159e046198b064eedcc7a780dfe164845c5fd47663f081ac",
		"link":    "4079403bdbf717782762c3391d6a334dcc6f2fbda933e8ae01ffc57e7c16d31e",
		"digest":  "7dab694ab96cc22d6be1a0dab37af4f06c9cb1931c533e0843ad365ff0a89b8b",
	}
	if !maps.Equal(got, want) {
		t.Errorf("%v, not %v", got, want)
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
