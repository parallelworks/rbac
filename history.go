package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Audit is what a change records in its history beside its actor and how it was made: on whose
// behalf it was made, and the host's request and reason. WithAudit attaches it to the changes
// made with a context.
type Audit struct {
	// OnBehalfOf is the identity the actor acts for, such as the person a service account serves.
	OnBehalfOf Principal
	// Request is the host's id for the request, which finds it in the host's own logs.
	Request string
	// Reason is why it was made, such as the ticket behind it.
	Reason string
}

// MaxRequest is the most characters an Audit's Request holds; its Reason holds MaxNote.
const MaxRequest = 256

type auditKey struct{}

// WithAudit returns ctx carrying what the changes made with it record in their history.
func WithAudit(ctx context.Context, a Audit) context.Context {
	return context.WithValue(ctx, auditKey{}, a)
}

// checkAudit returns why history can't record a change by actor with audit as they are: JSON
// would carry invalid UTF-8 as another character, and the trigger fails on a NUL.
func (a *Authorizer) checkAudit(actor Principal, audit Audit) error {
	switch {
	case !validText(actor.ID):
		return fmt.Errorf("%w: the actor's id is text without NUL", ErrInvalid)
	case audit.OnBehalfOf != (Principal{}) && (!a.acts(audit.OnBehalfOf.Kind) || audit.OnBehalfOf.ID == "" || !validText(audit.OnBehalfOf.ID)):
		return fmt.Errorf("%w: a change is made on behalf of an identity, a user or a declared kind, whose id is text without NUL", ErrInvalid)
	case utf8.RuneCountInString(audit.Request) > MaxRequest || !validText(audit.Request):
		return fmt.Errorf("%w: a request id is text of at most %d characters", ErrInvalid, MaxRequest)
	case !validNote(audit.Reason):
		return fmt.Errorf("%w: a reason is text of at most %d characters", ErrInvalid, MaxNote)
	}
	return nil
}

// changeContext is what rbac_record writes into history with each row a change writes.
type changeContext struct {
	Actor      string `json:"actor,omitempty"`
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	How        string `json:"how,omitempty"`
	Request    string `json:"request,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Op is "expire" for rows DeleteExpired removes; otherwise the trigger reads it from the write.
	Op string `json:"op,omitempty"`
}

// recording sets, for the rest of tx, the context its writes record in history: actor's change,
// made by how, the name of the call that makes it, with what ctx carries for history. done clears
// it, so the writes that follow, OnChange's and the host's own under WithTx, aren't recorded as
// this change's.
func (a *Authorizer) recording(ctx context.Context, tx pgx.Tx, actor Principal, how, op string) (done func() error, err error) {
	audit, _ := ctx.Value(auditKey{}).(Audit)
	if err := a.checkAudit(actor, audit); err != nil {
		return nil, err
	}
	c := changeContext{Actor: actorKey(actor), How: how, Request: audit.Request, Reason: audit.Reason, Op: op}
	if audit.OnBehalfOf != (Principal{}) {
		c.OnBehalfOf = audit.OnBehalfOf.key()
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('rbac.change', $1, true)`, string(b)); err != nil {
		return nil, err
	}
	// In a transaction of its own that hands nothing to OnChange, nothing writes after the change,
	// so the setting ends with it.
	if _, own := a.db.(ownTx); own && a.cfg.OnChange == nil {
		return func() error { return nil }, nil
	}
	return func() error {
		_, err := tx.Exec(ctx, `SELECT set_config('rbac.change', '', true)`)
		return err
	}, nil
}

// Record is one change to a row the package keeps, as its history recorded it.
type Record struct {
	ID   int64
	TxID uint64
	// RecordedAt is when it was written, and EffectiveAt when it took effect: the same, but for an
	// expiry, when it expired.
	RecordedAt, EffectiveAt time.Time
	Tenant                  string
	// Entity is what changed: grant, role, deny, eligibility, membership, group or member. Key is
	// which, in the tenant.
	Entity, Key string
	// Op is create, update, delete or expire.
	Op string
	// Principal, Role, Scope, Group and ExpiresAt are those of the row, where it has them.
	Principal Principal
	Role      Role
	Scope     Scope
	Group     string
	ExpiresAt time.Time
	// Before and After are the row as it was and as it became, as JSON, nil where there was none.
	Before, After json.RawMessage
	// Actor is who made it through the package, by How, the call that made it; zero for a write
	// that bypassed the package, which DBUser, the database role whose session wrote it, names.
	// Actor, OnBehalfOf, How, Request and Reason are what the writing session said; DBUser is what
	// the database knows.
	Actor      Principal
	OnBehalfOf Principal
	How        string
	Request    string
	Reason     string
	DBUser     string
}

// Cursor is where a read of history stopped. The zero Cursor is its start.
type Cursor struct {
	// Generation names the database the records were read from, by its system and timeline, which
	// failing over to a replica or recovering to a point in time changes.
	Generation string
	TxID       uint64
	ID         int64
	// RecordedAt is the last record's, to the microsecond: a restore numbers a record it lost again,
	// with the same transaction and id, but not at the same time.
	RecordedAt time.Time
}

// MaxHistory is the most records one History call reads.
const MaxHistory = 10000

// History reads up to limit records after a cursor, and the cursor after them, to export history
// to storage of the host's own. It orders records by the transaction that wrote them and reads
// only those of transactions older than any still running, so a transaction that commits after a
// later one is read after it, never skipped. Transaction ids are the database cluster's, so a
// transaction running anywhere in it, in any database, holds the read back until it ends: a long
// one, or a prepared transaction left open, delays the export. A record can be read twice, as when
// a host retries a read whose result it lost: dedupe on ID and RecordedAt, since a restore can
// give another record the ID of one it lost.
//
// It reads the primary, and fails on a replica, which can't tell which timeline it follows until
// long after a failover. A failover or a recovery to a point in time starts a new generation, and
// a restore that starts none, as from a disk snapshot, loses what came after it: either can use
// again ids and transactions the last one used past what it kept. History refuses a cursor from
// another generation, or whose last record the database no longer holds, and history is exported
// again from the start, kept apart from the last export. A logical dump restored into another
// cluster numbers its transactions anew, which a cursor can't follow: move history with physical
// backups and replicas.
func (a *Authorizer) History(ctx context.Context, after Cursor, limit int) ([]Record, Cursor, error) {
	if limit < 1 || limit > MaxHistory {
		return nil, after, fmt.Errorf("%w: a read of history takes from 1 to %d records", ErrInvalid, MaxHistory)
	}
	var generation string
	var records []Record
	// On one connection, so the cursor is checked on the server it reads: a pool's connections can
	// reach both an old primary and the new one. Not a.begin, which refuses changes as of a time:
	// this only reads.
	err := begin(ctx, a.db, func(tx pgx.Tx) error {
		// The timeline WAL is written on, which promotion changes at once; the last checkpoint's
		// changes only once the next completes, minutes later.
		var held bool
		if err := tx.QueryRow(ctx, `SELECT s.system_identifier::text || '/' || left(pg_walfile_name(pg_current_wal_lsn()), 8),
			  EXISTS (SELECT 1 FROM rbac_history WHERE txid = $1::xid8 AND id = $2 AND recorded_at = $3)
			FROM pg_control_system() s`, after.TxID, after.ID, after.RecordedAt).Scan(&generation, &held); err != nil {
			return err
		}
		if after != (Cursor{}) && after.Generation != generation {
			return fmt.Errorf("%w: the cursor is another generation's, as before a failover: export this one from the start", ErrInvalid)
		}
		if (after.TxID != 0 || after.ID != 0) && !held {
			return fmt.Errorf("%w: the database no longer holds the cursor's last record, as after a restore: export it again from the start", ErrInvalid)
		}
		rows, err := tx.Query(ctx, `
			SELECT id, txid, recorded_at, effective_at, tenant, entity, key, op, coalesce(principal, ''), coalesce(role, ''),
			  coalesce(scope, ''), coalesce(group_id, ''), expires_at, before, after, actor, on_behalf_of, how, request, reason, db_user
			FROM rbac_history
			WHERE (txid, id) > ($1::xid8, $2) AND txid < pg_snapshot_xmin(pg_current_snapshot())
			ORDER BY txid, id LIMIT $3`, after.TxID, after.ID, limit)
		if err != nil {
			return err
		}
		records, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) {
			var r Record
			var principal, role, scope, actor, onBehalfOf string
			var expires *time.Time
			var before, afterRow []byte
			err := row.Scan(&r.ID, &r.TxID, &r.RecordedAt, &r.EffectiveAt, &r.Tenant, &r.Entity, &r.Key, &r.Op, &principal, &role,
				&scope, &r.Group, &expires, &before, &afterRow, &actor, &onBehalfOf, &r.How, &r.Request, &r.Reason, &r.DBUser)
			if expires != nil {
				r.ExpiresAt = *expires
			}
			r.Principal, r.Scope, r.Actor, r.OnBehalfOf = parsePrincipal(principal), parseScope(scope), parsePrincipal(actor), parsePrincipal(onBehalfOf)
			r.Role, r.Before, r.After = Role(role), before, afterRow
			return r, err
		})
		return err
	})
	if err != nil {
		return nil, after, err
	}
	after.Generation = generation
	if len(records) == 0 {
		return nil, after, nil
	}
	last := records[len(records)-1]
	return records, Cursor{Generation: generation, TxID: last.TxID, ID: last.ID, RecordedAt: last.RecordedAt}, nil
}
