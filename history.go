package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

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
	Actor      Principal
	OnBehalfOf Principal
	How        string
	Request    string
	Reason     string
	DBUser     string
}

// Cursor is where a read of history stopped. The zero Cursor is its start.
type Cursor struct {
	TxID uint64
	ID   int64
}

// MaxHistory is the most records one History call reads.
const MaxHistory = 10000

// History reads up to limit records after a cursor, and the cursor after them, to export history
// to storage of the host's own. It orders records by the transaction that wrote them and reads
// only those of transactions older than any still running, so a transaction that commits after a
// later one is read after it, never skipped. A record can be read twice, as when a host retries a
// read whose result it lost: dedupe on ID. History restored into another database starts its
// transactions over, below the cursor; History refuses the cursor then, and is read again from the
// start.
func (a *Authorizer) History(ctx context.Context, after Cursor, limit int) ([]Record, Cursor, error) {
	if limit < 1 || limit > MaxHistory {
		return nil, after, fmt.Errorf("%w: a read of history takes from 1 to %d records", ErrInvalid, MaxHistory)
	}
	var next uint64
	if err := a.db.QueryRow(ctx, `SELECT pg_snapshot_xmax(pg_current_snapshot())`).Scan(&next); err != nil {
		return nil, after, err
	}
	if after.TxID >= next {
		return nil, after, fmt.Errorf("%w: the cursor is past this database's transactions, as after a restore from another: read history again from the start", ErrInvalid)
	}
	rows, err := a.db.Query(ctx, `
		SELECT id, txid, recorded_at, effective_at, tenant, entity, key, op, coalesce(principal, ''), coalesce(role, ''),
		  coalesce(scope, ''), coalesce(group_id, ''), expires_at, before, after, actor, on_behalf_of, how, request, reason, db_user
		FROM rbac_history
		WHERE (txid, id) > ($1::xid8, $2) AND txid < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY txid, id LIMIT $3`, after.TxID, after.ID, limit)
	if err != nil {
		return nil, after, err
	}
	records, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) {
		var r Record
		var principal, role, scope, actor, onBehalfOf string
		var expires *time.Time
		var before, afterRow []byte
		err := row.Scan(&r.ID, &r.TxID, &r.RecordedAt, &r.EffectiveAt, &r.Tenant, &r.Entity, &r.Key, &r.Op, &principal, &role,
			&scope, &r.Group, &expires, &before, &afterRow, &actor, &onBehalfOf, &r.How, &r.Request, &r.Reason, &r.DBUser)
		if principal != "" {
			r.Principal = parsePrincipal(principal)
		}
		if scope != "" {
			r.Scope = parseScope(scope)
		}
		if actor != "" {
			r.Actor = parsePrincipal(actor)
		}
		if onBehalfOf != "" {
			r.OnBehalfOf = parsePrincipal(onBehalfOf)
		}
		if expires != nil {
			r.ExpiresAt = *expires
		}
		r.Role, r.Before, r.After = Role(role), before, afterRow
		return r, err
	})
	if err != nil || len(records) == 0 {
		return records, after, err
	}
	last := records[len(records)-1]
	return records, Cursor{TxID: last.TxID, ID: last.ID}, nil
}
