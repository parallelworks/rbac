package rbac

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"
)

// Checkpoint is where an export of history stands: the cursor of the last record exported, how
// many records the export has chained since its generation began, and the SHA-256 hash chain over
// them, each record's link hashing the last link and the record. Signed, and kept on storage that
// can't be rewritten, it shows that the records exported up to it are the ones history held, in
// their order, with none dropped or changed.
type Checkpoint struct {
	Cursor Cursor
	Count  uint64
	Hash   [sha256.Size]byte
	// At is when it was made, to the microsecond as history's own times are, so a store that keeps
	// no finer keeps it signed; Signature is the host's signature over its digest (Digest), empty
	// until Sign.
	At        time.Time
	Signature []byte
}

// chainVersion names the encoding the chain hashes, so a later one can't be read as this one.
const chainVersion = "rbac history chain v1"

// Genesis is the checkpoint an export of a generation's history starts from: none of its records
// chained yet.
func Genesis(generation string) Checkpoint {
	return Checkpoint{Cursor: Cursor{Generation: generation}, Hash: sha256.Sum256([]byte(chainVersion + "\n" + generation))}
}

// Chain returns c with records, which follow its cursor in History's order, chained onto it, its
// cursor at the last of them, and neither dated nor signed.
func (c Checkpoint) Chain(records []Record) (Checkpoint, error) {
	for _, r := range records {
		b, err := r.chained()
		if err != nil {
			return Checkpoint{}, err
		}
		c.Hash = sha256.Sum256(append(c.Hash[:], b...))
		c.Count++
		c.Cursor = Cursor{Generation: c.Cursor.Generation, TxID: r.TxID, ID: r.ID, RecordedAt: r.RecordedAt}
	}
	c.At, c.Signature = time.Time{}, nil
	return c, nil
}

// chained is the record as the chain hashes it: every field, in a fixed order, its times in UTC. A
// principal's or scope's kind and id are kept apart, as their key joins them with a colon an id
// can hold too. Its text is UTF-8, as the database keeps it: JSON writes other bytes as U+FFFD,
// so two records would encode alike, and in a form that differs between Go's JSON encoders.
func (r Record) chained() ([]byte, error) {
	utc := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	principal := func(p Principal) [2]string { return [2]string{string(p.Kind), p.ID} }
	scope := [2]string{r.Scope.Type, r.Scope.ID}
	fields := []any{
		r.ID, r.TxID, utc(r.RecordedAt), utc(r.EffectiveAt), r.Tenant, r.Entity, r.Key, r.Op,
		principal(r.Principal), string(r.Role), scope, r.Group, utc(r.ExpiresAt),
		rawOrNull(r.Before), rawOrNull(r.After),
		principal(r.Actor), principal(r.OnBehalfOf), r.How, r.Request, r.Reason, r.DBUser,
	}
	for _, f := range fields {
		var text []string
		switch f := f.(type) {
		case string:
			text = []string{f}
		case [2]string:
			text = f[:]
		}
		if slices.ContainsFunc(text, func(s string) bool { return !utf8.ValidString(s) }) {
			return nil, errors.New("rbac: a record's text isn't UTF-8")
		}
	}
	return json.Marshal(fields)
}

// equal reports whether c and d are at the same record. A store gives a time back in a location
// of its own, which == would tell apart.
func (c Cursor) equal(d Cursor) bool {
	return c.Generation == d.Generation && c.TxID == d.TxID && c.ID == d.ID && c.RecordedAt.Equal(d.RecordedAt)
}

// rawOrNull is a row as JSON, or JSON's null where there was none.
func rawOrNull(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}

// Digest is what Sign signs: the checkpoint's generation, cursor, count, hash and time.
func (c Checkpoint) Digest() [sha256.Size]byte {
	b, _ := json.Marshal([]any{
		chainVersion + " checkpoint", c.Cursor.Generation, c.Cursor.TxID, c.Cursor.ID, c.Cursor.RecordedAt.UTC().Format(time.RFC3339Nano),
		c.Count, c.Hash[:], c.At.UTC().Format(time.RFC3339Nano),
	})
	return sha256.Sum256(b)
}

// Sign returns c signed by signer, a key the host keeps for nothing else, as in a key management
// service: one that signs any digest it is given could be made to sign a checkpoint's. An ECDSA
// key on P-256, P-384 or P-521, or an RSA key of at least 3072 bits, signs the digest as a SHA-256
// hash (RSA with PKCS #1 v1.5, or PSS with a salt as long as the hash); an Ed25519 key signs the
// digest itself.
func (c Checkpoint) Sign(signer crypto.Signer) (Checkpoint, error) {
	d := c.Digest()
	pub := signer.Public()
	opts := crypto.SignerOpts(crypto.SHA256)
	if _, ok := pub.(ed25519.PublicKey); ok {
		opts = crypto.Hash(0)
	}
	sig, err := signer.Sign(rand.Reader, d[:], opts)
	if err != nil {
		return Checkpoint{}, err
	}
	c.Signature = sig
	// A key of a type Verify doesn't check, or a signature in a form it doesn't read, would leave
	// checkpoints on write-once storage that never verify.
	if err := c.Verify(pub); err != nil {
		return Checkpoint{}, err
	}
	return c, nil
}

// ErrUnverified is matched by a checkpoint whose signature, or a chain whose hash, doesn't hold.
var ErrUnverified = errors.New("rbac: unverified")

// Verify checks that c is signed, as Sign signs, by the private half of pub, one of the keys Sign
// names: no RSA key under 3072 bits, whose strength NIST SP 800-57 approves only through 2030,
// short of how long an audit record is kept, and no other curve.
func (c Checkpoint) Verify(pub crypto.PublicKey) error {
	d := c.Digest()
	var supported, ok bool
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		supported = k != nil && (k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521())
		ok = supported && ecdsa.VerifyASN1(k, d[:], c.Signature)
	case *rsa.PublicKey:
		supported = k != nil && k.N != nil && k.N.BitLen() >= 3072
		// A key management service's RSA key signs PSS or PKCS #1 v1.5 as it was made to. A salt
		// longer than the hash isn't approved, and Go's FIPS 140-only mode doesn't refuse one.
		ok = supported && (rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], c.Signature) == nil ||
			rsa.VerifyPSS(k, crypto.SHA256, d[:], c.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil)
	case ed25519.PublicKey:
		// ed25519.Verify panics on a key of another length.
		supported = len(k) == ed25519.PublicKeySize
		ok = supported && ed25519.Verify(k, d[:], c.Signature)
	}
	if !supported {
		return fmt.Errorf("%w: a checkpoint is signed with an ECDSA key on P-256, P-384 or P-521, an RSA key of at least 3072 bits, or an Ed25519 key, not this %T", ErrInvalid, pub)
	}
	if !ok {
		return fmt.Errorf("%w: the checkpoint's signature doesn't hold", ErrUnverified)
	}
	return nil
}

// VerifyChain checks that records, chained onto from, end at to, and that to is signed by pub:
// the records an export kept between two checkpoints are those history held, as it held them.
// from is the generation's Genesis or a checkpoint verified already, as VerifyChain checks no
// signature of its. It shows nothing of the records after to: an audit verifies up to the latest
// checkpoint kept, and checks that it is as recent as the host exports, since Export signs one on
// every call.
func VerifyChain(from Checkpoint, records []Record, to Checkpoint, pub crypto.PublicKey) error {
	if err := to.Verify(pub); err != nil {
		return err
	}
	got, err := from.Chain(records)
	if err != nil {
		// Every record History reads chains, so one that doesn't was changed.
		return fmt.Errorf("%w: %w", ErrUnverified, err)
	}
	if got.Hash != to.Hash || got.Count != to.Count || !got.Cursor.equal(to.Cursor) {
		return fmt.Errorf("%w: the records don't chain from one checkpoint to the other", ErrUnverified)
	}
	return nil
}

// Export reads up to limit records after from's cursor, as History does, and returns them with
// the checkpoint they chain to, signed by signer and dated now, even when it read none. from is
// the zero Checkpoint, which starts the current generation's export from its genesis, or one
// Export returned. On an error it returns from, as History returns its cursor, so an export goes
// on from where it was. Keep each checkpoint, and the records, where they can't be rewritten:
// PruneHistory deletes only what a checkpoint's cursor has passed.
//
// A generation exported from the start again, as after History refuses a cursor, is chained
// anew from its genesis: the last export's records are what history held up to its last
// checkpoint, whatever the new one holds, as a superuser can make History refuse a cursor by
// deleting its record.
func (a *Authorizer) Export(ctx context.Context, from Checkpoint, limit int, signer crypto.Signer) ([]Record, Checkpoint, error) {
	zero := from.Count == 0 && from.Cursor == (Cursor{})
	switch {
	case signer == nil:
		return nil, from, fmt.Errorf("%w: an export's checkpoints are signed", ErrInvalid)
	case a.asOf:
		return nil, from, fmt.Errorf("%w: an export dates its checkpoints now, not as of a time", ErrInvalid)
	// As a cursor of History's given as a checkpoint: chained onto no genesis, nothing after it
	// would verify.
	case !zero && from.Hash == [sha256.Size]byte{}:
		return nil, from, fmt.Errorf("%w: an export goes on from the zero checkpoint or one it returned", ErrInvalid)
	}
	records, cursor, err := a.History(ctx, from.Cursor, limit)
	if err != nil {
		return nil, from, err
	}
	start := from
	if zero {
		start = Genesis(cursor.Generation)
	}
	next, err := start.Chain(records)
	if err != nil {
		return nil, from, err
	}
	next.At = a.cfg.Now().Truncate(time.Microsecond)
	if next, err = next.Sign(signer); err != nil {
		return nil, from, err
	}
	return records, next, nil
}
