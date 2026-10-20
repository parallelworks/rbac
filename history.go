package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	case audit.OnBehalfOf != (Principal{}) && (!a.acts(audit.OnBehalfOf.Kind) || !validID(audit.OnBehalfOf.ID)):
		return fmt.Errorf("%w: a change is made on behalf of an identity, a user or a declared kind, whose id is text without NUL of at most %d bytes", ErrInvalid, MaxID)
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

// packageSchema returns the schema tx reads the package's tables in, by which history's reads name
// its tables: any role may make a temporary table, which a search_path that doesn't name pg_temp
// reads before every schema, and a pooled connection keeps, so one named as history's would stand
// in for it, and Export would sign what it holds. It refuses the session's temporary schema, which
// a search_path naming pg_temp first makes the current one.
func packageSchema(ctx context.Context, tx pgx.Tx) (string, error) {
	var schema string
	var temporary bool
	if err := tx.QueryRow(ctx, `SELECT n.nspname, n.oid = pg_catalog.pg_my_temp_schema()
		FROM pg_catalog.pg_namespace n WHERE n.nspname = pg_catalog.current_schema()`).Scan(&schema, &temporary); err != nil {
		return "", err
	}
	if temporary {
		return "", fmt.Errorf("%w: the search_path names pg_temp first, where any role may make tables named as the package's", ErrInvalid)
	}
	return schema, nil
}

// followable refuses, on tx, a cursor of another generation, or whose last record history in schema
// no longer holds, and returns the generation tx reads. The zero Cursor, or one from a read that
// found nothing, is followable from any.
func followable(ctx context.Context, tx pgx.Tx, schema string, after Cursor) (generation string, err error) {
	history := pgx.Identifier{schema, "rbac_history"}.Sanitize()
	// The timeline WAL is written on, which promotion changes at once; the last checkpoint's
	// changes only once the next completes, minutes later. And the database and schema of the
	// history read, by OIDs, which a physical copy keeps: every database and schema in a cluster
	// would otherwise share a generation, and with one key, checkpoints. The catalogs by schema
	// too, as a temporary table is read before them.
	var held bool
	if err := tx.QueryRow(ctx, `SELECT s.system_identifier::text || '/' || left(pg_walfile_name(pg_current_wal_lsn()), 8)
		    || '/' || d.oid::text || '/' || c.relnamespace::text,
		  EXISTS (SELECT 1 FROM `+history+` WHERE txid = $1::xid8 AND id = $2 AND recorded_at = $3)
		FROM pg_control_system() s, pg_catalog.pg_database d, pg_catalog.pg_class c
		WHERE d.datname = current_database() AND c.oid = $4::text::regclass`,
		after.TxID, after.ID, storedTime(after.RecordedAt), history).Scan(&generation, &held); err != nil {
		return "", err
	}
	if after != (Cursor{}) && after.Generation != generation {
		return "", fmt.Errorf("%w: the cursor is another generation's, as before a failover: export this one from the start", ErrInvalid)
	}
	if (after.TxID != 0 || after.ID != 0) && !held {
		return "", fmt.Errorf("%w: the database no longer holds the cursor's last record, as after a restore or a prune past it: export it again from the start", ErrInvalid)
	}
	return generation, nil
}

// MaxPrune is the most records one PruneHistory deletes, so its transaction, which holds every
// export in the cluster back while it runs, stays short: call it again while it returns as many.
const MaxPrune = 10000

// maxPrune is MaxPrune, which a test lowers.
var maxPrune = MaxPrune

// pruneKey and pruneThrough are a prune's time, $1, and cursor, $2 and $3, as its record holds
// them, by which a prune of the same finds where the last stopped.
const (
	pruneKey     = `to_char($1::timestamptz AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
	pruneThrough = `jsonb_build_object('txid', $2::xid8::text, 'id', $3::bigint)`
)

// PruneHistory deletes from history, on db, records that an export has read past and that later
// ones supersede, and returns how many. Of each row it keeps the last version at or before before,
// so AsOf answers as it did for any time from then on, and refuses an earlier one, and it removes
// every version of a row whose last one then was its delete or expiry, unless an earlier one stays.
// It deletes nothing at or past through, the cursor of the last export the host has checkpointed,
// so that export goes on from it, and it records the prune in history. Run it as a role with the
// rights of history's owner, as the README's administrator's, never the application's; keep at
// least as much as the host's audit retention requires. It refuses a before yet to come and, like
// AsOf, history whose ids can't order a row's changes. It deletes at most MaxPrune records:
// call it again while it deletes as many, and it goes on from where the last prune of the same
// before and through stopped.
func PruneHistory(ctx context.Context, db DB, before time.Time, through Cursor) (int64, error) {
	if through.TxID == 0 && through.ID == 0 {
		return 0, fmt.Errorf("%w: a prune goes only as far as an export has read: through is the export's cursor", ErrInvalid)
	}
	var n int64
	err := begin(ctx, db, func(tx pgx.Tx) error {
		schema, err := historySchema(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := followable(ctx, tx, schema, through); err != nil {
			return err
		}
		history := pgx.Identifier{schema, "rbac_history"}.Sanitize()
		// AsOf refuses a time before the prune's, so one yet to come would refuse the present.
		var future bool
		if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > statement_timestamp()`, before).Scan(&future); err != nil {
			return err
		}
		if future {
			return fmt.Errorf("%w: a prune is of history up to a time that has passed", ErrInvalid)
		}
		// A prune of the same time and cursor goes on from the last record the last one deleted:
		// those before it that it kept, the last versions of their rows by then, stay so for both,
		// as any record written since that could change it is past the cursor. Otherwise each call
		// would read them all again, as many as the rows there are. One it kept on a snapshot older
		// than the export, as a host's at REPEATABLE READ, can since be superseded by an end the
		// snapshot missed: it stays for this call, so the end does too. So a call can go on from
		// where any of them stopped, and goes on from the furthest: the last by date or id can have
		// stopped short of it, as one dated by its host transaction's start, or one that waited on
		// another's batch and deleted none of it.
		var from int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max((after->>'reached')::bigint), 0) FROM `+history+`
			WHERE tenant = '' AND entity = 'history' AND key = `+pruneKey+`
			  AND op = 'prune' AND after->'through' = `+pruneThrough, before, through.TxID, through.ID).Scan(&from); err != nil {
			return err
		}
		// The planner can't know that what a batch deletes is history's oldest, and would rather
		// read all of it and sort what it finds: by history's ids, a call reads only as far as its
		// batch reaches.
		var sorting string
		if err := tx.QueryRow(ctx, `SELECT current_setting('enable_sort')`).Scan(&sorting); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('rbac.prune', 'on', true), set_config('enable_sort', 'off', true)`); err != nil {
			return err
		}
		// Of each row's versions at or before the time, the last, by when it was written, as AsOf
		// orders them, stays unless it ended the row. An end goes only with every version before it:
		// one that stays, as one the export hasn't read or one dated later but written first, as
		// history written before its versions were dated in order can hold, would otherwise be the
		// last AsOf finds. Each record is judged by its own row's versions, not every row's.
		var reached int64
		if err := tx.QueryRow(ctx, `
			WITH doomed AS (
			  SELECT h.id FROM `+history+` h
			  WHERE h.id > $5 AND h.effective_at <= $1 AND (h.txid, h.id) < ($2::xid8, $3) AND h.entity <> 'history'
			    AND (EXISTS (
			      SELECT FROM `+history+` n
			      WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key AND n.effective_at <= $1 AND n.id > h.id)
			    OR h.op IN ('delete', 'expire') AND NOT EXISTS (
			      SELECT FROM `+history+` s
			      WHERE s.tenant = h.tenant AND s.entity = h.entity AND s.key = h.key AND s.id < h.id
			        AND (s.id <= $5 OR s.effective_at > $1 OR (s.txid, s.id) >= ($2::xid8, $3))))
			  -- A batch, oldest first: of a row, its end goes after every version before it, so a
			  -- batch that stops between them leaves the end, which still reads as the row's.
			  ORDER BY h.id LIMIT $4
			), pruned AS (
			  -- By id, from the batch: a join could read all of history to find it.
			  DELETE FROM `+history+` WHERE id = ANY (ARRAY(SELECT id FROM doomed)) RETURNING id
			)
			SELECT count(*), coalesce(max(id), $5) FROM pruned`, before, through.TxID, through.ID, maxPrune, from).Scan(&n, &reached); err != nil {
			return err
		}
		// Under a host's transaction, which goes on past the prune.
		if _, err := tx.Exec(ctx, `SELECT set_config('rbac.prune', '', true), set_config('enable_sort', $1, true)`, sorting); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO `+history+` (effective_at, tenant, entity, key, op, after, how)
			VALUES (now(), '', 'history', `+pruneKey+`, 'prune',
			  jsonb_build_object('before', $1::timestamptz, 'through', `+pruneThrough+`, 'deleted', $4::bigint, 'reached', $5::bigint),
			  'PruneHistory')`, before, through.TxID, through.ID, n, reached)
		return err
	})
	return n, err
}

// Record is one change to a row the package keeps, as its history recorded it, its times in UTC.
// A time.Time holds no infinity, as PostgreSQL's times can, so a time of a record written before
// the tables refused one, or by history's owner, reads as an instant PostgreSQL can't hold:
// infinity as 294277-01-01T00:00:00Z, just after the latest it holds, and -infinity as
// -4713-11-23T23:59:59.999999Z, just before the earliest.
type Record struct {
	ID   int64
	TxID uint64
	// RecordedAt is when it was written, and EffectiveAt when it took effect: when the statement
	// that made it began, or for an expiry, when it expired, but never before the row's record
	// before it.
	RecordedAt, EffectiveAt time.Time
	Tenant                  string
	// Entity is what changed: grant, role, deny, eligibility, membership, group or member, or
	// history itself, in no tenant, for a prune. Key is which, in the tenant.
	Entity, Key string
	// Op is create, update, delete or expire, or prune, whose After is what PruneHistory was given,
	// how many records it deleted, and the id it reached, which a prune of the same goes on from.
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

// The instants a Record reads PostgreSQL's infinity and -infinity as, which no time it holds is.
var (
	pastLatest     = time.Date(294277, time.January, 1, 0, 0, 0, 0, time.UTC)
	beforeEarliest = time.Date(-4713, time.November, 24, 0, 0, 0, 0, time.UTC).Add(-time.Microsecond)
)

// recordTime is t as a Record holds it: the zero time for none, and in UTC, so a record reads the
// same whatever the host's time zone.
func recordTime(t pgtype.Timestamptz) time.Time {
	switch {
	case !t.Valid:
		return time.Time{}
	case t.InfinityModifier == pgtype.Infinity:
		return pastLatest
	case t.InfinityModifier == pgtype.NegativeInfinity:
		return beforeEarliest
	}
	return t.Time.UTC()
}

// storedTime is t as history stores it, which recordTime reads as t.
func storedTime(t time.Time) pgtype.Timestamptz {
	switch {
	case t.Equal(pastLatest):
		return pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}
	case t.Equal(beforeEarliest):
		return pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// Cursor is where a read of history stopped. The zero Cursor is its start.
type Cursor struct {
	// Generation names the history the records were read from: its database cluster, by its
	// system and timeline, which failing over to a replica or recovering to a point in time
	// changes, and the database and schema in it, by their OIDs, so no two installations in one
	// cluster share one.
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
//
// It reads history in the current schema by name, so a session's temporary table named as
// history's stands in for none of it, and refuses a search_path that names pg_temp first.
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
		schema, err := packageSchema(ctx, tx)
		if err != nil {
			return err
		}
		if generation, err = followable(ctx, tx, schema, after); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, txid, recorded_at, effective_at, tenant, entity, key, op, coalesce(principal, ''), coalesce(role, ''),
			  coalesce(scope, ''), coalesce(group_id, ''), expires_at, before, after, actor, on_behalf_of, how, request, reason, db_user
			FROM `+pgx.Identifier{schema, "rbac_history"}.Sanitize()+`
			WHERE (txid, id) > ($1::xid8, $2) AND txid < pg_snapshot_xmin(pg_current_snapshot())
			ORDER BY txid, id LIMIT $3`, after.TxID, after.ID, limit)
		if err != nil {
			return err
		}
		records, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) {
			var r Record
			var principal, role, scope, actor, onBehalfOf string
			var recorded, effective, expires pgtype.Timestamptz
			var before, afterRow []byte
			err := row.Scan(&r.ID, &r.TxID, &recorded, &effective, &r.Tenant, &r.Entity, &r.Key, &r.Op, &principal, &role,
				&scope, &r.Group, &expires, &before, &afterRow, &actor, &onBehalfOf, &r.How, &r.Request, &r.Reason, &r.DBUser)
			r.RecordedAt, r.EffectiveAt, r.ExpiresAt = recordTime(recorded), recordTime(effective), recordTime(expires)
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

// Refusal is a change refused, as Config.OnRefused is told of it. Its fields are what the call was
// given, which one refused as ErrInvalid may have refused as malformed, such as text with a NUL.
type Refusal struct {
	// Tenant is empty for DeletePrincipalEverywhere and DeleteExpired, which change every tenant.
	Tenant string
	// Actor is zero for DeleteExpired, which no one makes.
	Actor Principal
	// How is the call refused, as Record.How names a change's.
	How   string
	Audit Audit
	// Err is why: it matches ErrDenied or ErrInvalid.
	Err error
	// At is when, by Config.Now.
	At time.Time
}

// refused tells Config.OnRefused of a change *err refused as ErrDenied or ErrInvalid, as actor's in
// a tenant by how.
func (a *Authorizer) refused(ctx context.Context, err *error, tenant string, actor Principal, how string) {
	// One AsOf gave refuses every change, which is no actor's attempt: what it checked first, it
	// checked against the past, and its clock is the time it reads.
	if a.cfg.OnRefused == nil || a.asOf || *err == nil || !errors.Is(*err, ErrDenied) && !errors.Is(*err, ErrInvalid) {
		return
	}
	audit, _ := ctx.Value(auditKey{}).(Audit)
	a.cfg.OnRefused(ctx, Refusal{Tenant: tenant, Actor: actor, How: how, Audit: audit, Err: *err, At: a.cfg.Now()})
}
