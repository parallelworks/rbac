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
// in for it, and Export would sign what it holds. A temporary type is read before pg_catalog's
// too, so those reads name their types by pg_catalog's. It refuses the session's temporary schema,
// which a search_path naming pg_temp first makes the current one.
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

// historyTable is history's table in schema, as packageSchema returns it.
func historyTable(schema string) string {
	return pgx.Identifier{schema, "rbac_history"}.Sanitize()
}

// followable refuses, on tx, a cursor of another generation, whose last record history in schema
// no longer holds, or after which a prune since its export began deleted records, and returns the
// generation tx reads. The zero Cursor, or one from a read that found nothing, is followable from
// any.
func followable(ctx context.Context, tx pgx.Tx, schema string, after Cursor) (generation string, err error) {
	// A record holds a time PostgreSQL holds, or reads as one just past either end of them. pgx
	// drops a time's nanoseconds, which takes one less than a microsecond before the earliest to one
	// PostgreSQL refuses.
	if t := after.RecordedAt; t.Before(earliest) && !t.Equal(beforeEarliest) || t.After(pastLatest) {
		return "", fmt.Errorf("%w: the cursor's last record is dated past the times history holds", ErrInvalid)
	}
	history := historyTable(schema)
	from := after.prunesFrom()
	// The timeline WAL is written on, which promotion changes at once; the last checkpoint's
	// changes only once the next completes, minutes later. And the database and schema of the
	// history read, by OIDs, which a physical copy keeps: every database and schema in a cluster
	// would otherwise share a generation, and with one key, checkpoints. The catalogs by schema
	// too, as a temporary table is read before them.
	var held, pruned bool
	if err := tx.QueryRow(ctx, `SELECT s.system_identifier::pg_catalog.text || '/' || left(pg_walfile_name(pg_current_wal_lsn()), 8)
		    || '/' || d.oid::pg_catalog.text || '/' || c.relnamespace::pg_catalog.text,
		  EXISTS (SELECT 1 FROM `+history+` WHERE txid = $1::pg_catalog.xid8 AND id = $2 AND recorded_at = $3),
		  $5::boolean AND `+prunedPast(history, "$1::pg_catalog.xid8", "$2", "$6::pg_catalog.xid8", "$7")+`
		FROM pg_control_system() s, pg_catalog.pg_database d, pg_catalog.pg_class c
		WHERE d.datname = current_database() AND c.oid = $4::pg_catalog.text::pg_catalog.regclass`,
		after.TxID, after.ID, storedTime(after.RecordedAt), history, after.following(), from.TxID, from.ID).Scan(&generation, &held, &pruned); err != nil {
		return "", err
	}
	if after != (Cursor{}) && after.Generation != generation {
		return "", fmt.Errorf("%w: the cursor is another generation's, as before a failover: export this one from the start", ErrInvalid)
	}
	if after.following() && !held {
		return "", fmt.Errorf("%w: the database no longer holds the cursor's last record, as after a restore or a prune past it: export it again from the start", ErrInvalid)
	}
	if pruned {
		return "", errPrunedPast()
	}
	return generation, nil
}

// following reports whether c is past history's start, as a cursor History returned after reading
// a record is.
func (c Cursor) following() bool { return c.TxID != 0 || c.ID != 0 }

// prunesFrom is where in History's order the prunes that can have deleted, after c, records its
// export could have read start: after c, as a prune is recorded after what it deletes, and at its
// export's Horizon, as one of an earlier transaction had ended before the export began, which read
// none of what it deleted.
func (c Cursor) prunesFrom() Cursor {
	if c.Horizon > c.TxID {
		return Cursor{TxID: c.Horizon}
	}
	return c
}

// prunedPast is SQL for whether a prune recorded in history, SQL for its table, after from, SQL for
// its txid and id, deleted a record after the cursor at txid and id, SQL for them: by the last it
// deleted, or for one recorded before migration 0020, the cursor it went through, past which it
// deleted none. A prune is recorded after what it deletes, as rbac_history_pruned holds each to,
// and from is no earlier than the cursor (prunesFrom), so of the prunes, which are never pruned,
// only those after it can have, and history's index of them finds those alone.
func prunedPast(history, txid, id, fromTxid, fromID string) string {
	return `EXISTS (SELECT FROM ` + history + ` g WHERE g.entity = 'history' AND g.op = 'prune' AND (g.txid, g.id) > (` + fromTxid + `, ` + fromID + `)
		AND ((coalesce(g.after->'last', g.after->'through')->>'txid')::pg_catalog.xid8,
		     (coalesce(g.after->'last', g.after->'through')->>'id')::bigint) > (` + txid + `, ` + id + `))`
}

// unsettled is SQL for whether history, SQL for its table, holds a prune of a transaction no older
// than one the statement sees running: an export that began now would read what follows the
// prune's records as the prune left it, but its Horizon, the oldest transaction running, would
// count the prune as one since, and refuse its cursor before the last record the prune deleted.
func unsettled(history string) string {
	return `EXISTS (SELECT FROM ` + history + ` g WHERE g.entity = 'history' AND g.op = 'prune'
		AND g.txid >= pg_snapshot_xmin(pg_current_snapshot()))`
}

// errPrunedPast is why History refuses a cursor after which a prune deleted records.
func errPrunedPast() error {
	return fmt.Errorf("%w: a prune deleted records after the cursor, which an export from it hasn't read, as one through the cursor of an export further on does: export it again from the start", ErrInvalid)
}

// followed runs in History once followable has checked the cursor, on its transaction, which a
// test sets.
var followed = func(pgx.Tx) {}

// MaxPrune is the most records one PruneHistory call deletes, and the most of history each of its
// transactions reads, so each, which holds every export in the cluster back while it runs, stays
// short however long history is: call it again while it deletes as many.
const MaxPrune = 10000

// maxPrune is MaxPrune, which a test lowers.
var maxPrune = MaxPrune

// prunedWindow runs at the end of each of PruneHistory's transactions, on it, which a test sets.
var prunedWindow = func(pgx.Tx) {}

// inUTC puts a timestamptz in UTC by an offset, whatever the session's TimeZone: from PostgreSQL 18
// a zone's name is first read as one of the TimeZone's own abbreviations, so under UTC+5, AT TIME
// ZONE 'UTC' puts it five hours west.
const inUTC = `AT TIME ZONE pg_catalog.interval '00:00'`

// pruneKey and pruneThrough are a prune's time, $1, and cursor, $2 and $3, as its record holds
// them, by which a prune of the same finds where the last stopped, and AsOf the latest prune: in
// UTC, as text that sorts as its time, as every prune's key has been.
const (
	pruneKey     = `to_char($1::pg_catalog.timestamptz ` + inUTC + `, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`
	pruneThrough = `jsonb_build_object('txid', $2::pg_catalog.xid8::pg_catalog.text, 'id', $3::bigint)`
)

// PruneHistory deletes from history, on db, records that an export has read past and that later
// ones supersede, and returns how many. Of each row it keeps the last version at or before before,
// so AsOf answers as it did for any time from then on, and refuses an earlier one, and it removes
// every version of a row whose last one then was its delete or expiry, unless an earlier one stays.
// It deletes nothing at or past through, the cursor of the last export the host has checkpointed,
// so that export goes on from it, and it records in history each of its transactions that deleted
// any, with the last record it deleted in History's order: one that deleted none changed nothing,
// and AsOf reads every time as it did. History refuses the cursor of an export begun before a prune
// where it is before the last record the prune deleted, as that export would read on past what the
// prune deleted: where several exports read history, through is the cursor of the one furthest
// behind. Run it as a role with the rights of history's owner, as the README's administrator's,
// never the application's: a delete from history that no prune its transaction records reaches is
// refused as the transaction commits, and that role can delete otherwise only by disabling
// history's triggers. Keep at least as much as the host's audit retention requires. It refuses a
// before yet to come or before year 1, earlier than history dates anything, a through History
// would refuse, as one whose export an earlier prune went past, and, like AsOf, history whose ids
// can't order a row's changes. It deletes at most MaxPrune records: call it again while it deletes
// as many, and it goes on from where the last prune of the same before and through stopped. It
// reads history MaxPrune records at a time, on a pool or a connection each in a transaction of its
// own, so none holds exports back for long, and on an error what those before deleted stays
// deleted; on a host's transaction, all in it.
func PruneHistory(ctx context.Context, db DB, before time.Time, through Cursor) (int64, error) {
	if through.TxID == 0 && through.ID == 0 {
		return 0, fmt.Errorf("%w: a prune goes only as far as an export has read: through is the export's cursor", ErrInvalid)
	}
	// AsOf finds the last prune's time by its record's key, which holds it as text that sorts as
	// time only from year 1: a year BC is written as the year AD of the same number.
	if before.Before(time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		return 0, fmt.Errorf("%w: a prune is of history up to a time in year 1 or later", ErrInvalid)
	}
	// Past the times the package stores, it is yet to come, which pruneWindow refuses in the
	// database, but which pgx would send as another time from year 294,000 or so on.
	if before.After(latest) {
		return 0, fmt.Errorf("%w: a prune is of history up to a time that has passed", ErrInvalid)
	}
	// Where the next window starts, once the first has read where the last prune stopped.
	from := int64(-1)
	var total int64
	for {
		var n int64
		var next *int64
		err := begin(ctx, db, func(tx pgx.Tx) error {
			var err error
			n, next, err = pruneWindow(ctx, tx, before, through, from, int64(maxPrune)-total)
			if err == nil {
				prunedWindow(tx)
			}
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
		// The window held no record, or the call deleted as many as it may: what follows reached is
		// the next call's.
		if next == nil || total >= int64(maxPrune) {
			return total, nil
		}
		from = *next
	}
}

// pruneWindow deletes, in tx, up to most records of the next MaxPrune after from, or after where
// the last prune of the same before and through stopped where from is -1. It returns how many it
// deleted, and the last record it judged, which the next window starts after: nil for a window that
// held no record.
func pruneWindow(ctx context.Context, tx pgx.Tx, before time.Time, through Cursor, from, most int64) (n int64, next *int64, err error) {
	schema, err := historySchema(ctx, tx)
	if err != nil {
		return 0, nil, err
	}
	if _, err := followable(ctx, tx, schema, through); err != nil {
		return 0, nil, err
	}
	history := historyTable(schema)
	// AsOf refuses a time before the prune's, so one yet to come would refuse the present.
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::pg_catalog.timestamptz > statement_timestamp()`, before).Scan(&future); err != nil {
		return 0, nil, err
	}
	if future {
		return 0, nil, fmt.Errorf("%w: a prune is of history up to a time that has passed", ErrInvalid)
	}
	// A prune of the same time and cursor goes on from the last record the last one deleted, or
	// the end of the last window it read past: those before it that it kept, the last versions of
	// their rows by then, stay so for both, as any record written since that could change it is
	// past the cursor. Otherwise each call would read them all again, as many as the rows there
	// are. One it kept on a snapshot older than the export, as a host's at REPEATABLE READ, can
	// since be superseded by an end the snapshot missed: it stays for this call, so the end does
	// too. So a call can go on from where any of them stopped, and goes on from the furthest: the
	// last by date or id can have stopped short of it, as one dated by its host transaction's
	// start, or one that waited on another's batch and deleted none of it.
	if from < 0 {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max((after->>'reached')::bigint), 0) FROM `+history+`
			WHERE tenant = '' AND entity = 'history' AND key = `+pruneKey+`
			  AND op = 'prune' AND after->'through' = `+pruneThrough, before, through.TxID, through.ID).Scan(&from); err != nil {
			return 0, nil, err
		}
	}
	// The planner can't know that what a batch deletes is history's oldest, and would rather
	// read all of it and sort what it finds: by history's ids, a call reads only as far as its
	// batch reaches. Finding the last record deleted still sorts, which with sorting off costs
	// past jit_above_cost before PostgreSQL 18, and compiling took far longer than the prune.
	var sorting, jit string
	if err := tx.QueryRow(ctx, `SELECT current_setting('enable_sort'), current_setting('jit')`).Scan(&sorting, &jit); err != nil {
		return 0, nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('rbac.prune', 'on', true), set_config('enable_sort', 'off', true),
		set_config('jit', 'off', true)`); err != nil {
		return 0, nil, err
	}
	// Of each row's versions at or before the time, the last, by when it was written, as AsOf
	// orders them, stays unless it ended the row. An end goes only with every version before it:
	// one that stays, as one the export hasn't read or one dated later but written first, as
	// history written before its versions were dated in order can hold, would otherwise be the
	// last AsOf finds. Each record is judged by its own row's versions, not every row's, and only
	// those of the window, the next MaxPrune records by id, so a transaction reads no more of
	// history however few records it finds to delete.
	//
	// The window's record is written in the statement that deletes, and only where it deleted any. It
	// holds the last record it deleted in History's order, before which History refuses the cursor of
	// an export begun before it: one further behind than through would otherwise read on past what
	// it deleted.
	//
	// It judged its window to the end, unless its batch filled first: by what it picked, not what it
	// deleted, as a prune of the same that deleted some of them meanwhile leaves fewer to delete,
	// and the rest of the window, which it never judged, is the next's. The window's record and the
	// call go on from the same.
	if err := tx.QueryRow(ctx, `
		WITH win AS (
		  SELECT max(id) AS last FROM (SELECT id FROM `+history+` WHERE id > $5 ORDER BY id LIMIT $6) w
		), doomed AS (
		  SELECT h.id FROM `+history+` h
		  WHERE h.id > $5 AND h.id <= (SELECT last FROM win) AND h.effective_at <= $1 AND (h.txid, h.id) < ($2::pg_catalog.xid8, $3)
		    AND h.entity <> 'history'
		    AND (EXISTS (
		      SELECT FROM `+history+` n
		      WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key AND n.effective_at <= $1 AND n.id > h.id)
		    OR h.op IN ('delete', 'expire') AND NOT EXISTS (
		      SELECT FROM `+history+` s
		      WHERE s.tenant = h.tenant AND s.entity = h.entity AND s.key = h.key AND s.id < h.id
		        AND (s.id <= $5 OR s.effective_at > $1 OR (s.txid, s.id) >= ($2::pg_catalog.xid8, $3))))
		  -- A batch, oldest first: of a row, its end goes after every version before it, so a
		  -- batch that stops between them leaves the end, which still reads as the row's.
		  ORDER BY h.id LIMIT $4
		), pruned AS (
		  -- By id, from the batch: a join could read all of history to find it.
		  DELETE FROM `+history+` WHERE id = ANY (ARRAY(SELECT id FROM doomed)) RETURNING txid, id
		), reach AS (
		  SELECT CASE WHEN (SELECT count(*) FROM doomed) = $4 THEN (SELECT max(id) FROM doomed) ELSE (SELECT last FROM win) END AS id
		), latest AS (
		  SELECT txid, id FROM pruned ORDER BY txid DESC, id DESC LIMIT 1
		), recorded AS (
		  INSERT INTO `+history+` (effective_at, tenant, entity, key, op, after, how)
		  SELECT now(), '', 'history', `+pruneKey+`, 'prune',
		    jsonb_build_object('before', $1::pg_catalog.timestamptz, 'through', `+pruneThrough+`,
		      'deleted', (SELECT count(*) FROM pruned), 'reached', (SELECT id FROM reach),
		      'last', jsonb_build_object('txid', l.txid::pg_catalog.text, 'id', l.id)),
		    'PruneHistory'
		  FROM latest l
		)
		SELECT (SELECT count(*) FROM pruned), (SELECT id FROM reach)`,
		before, through.TxID, through.ID, most, from, maxPrune).Scan(&n, &next); err != nil {
		return 0, nil, err
	}
	// Under a host's transaction, which goes on past the prune.
	if _, err := tx.Exec(ctx, `SELECT set_config('rbac.prune', '', true), set_config('enable_sort', $1, true),
		set_config('jit', $2, true)`, sorting, jit); err != nil {
		return 0, nil, err
	}
	// One that deleted none left history as it was, and recorded nothing, and the call goes on to the
	// next window itself: a record would account for no record gone, refuse AsOf times history still
	// holds, and grow history with each window of each call of a host that prunes on a schedule.
	return n, next, nil
}

// Record is one change to a row the package keeps, as its history recorded it, its times in UTC.
// A time.Time holds no infinity, as PostgreSQL's times can, so a time of a record written before
// the tables refused one, or by history's owner, reads as an instant PostgreSQL can't hold:
// infinity as 294277-01-01T00:00:00Z, just after the latest it holds, and -infinity as
// -4713-11-23T23:59:59.999999Z, just before the earliest. An expiry at the first instant of year 1,
// which a record written before the tables refused one can hold, is a time.Time's zero, so it
// reads, and chains, as none; its row's Before or After holds it.
type Record struct {
	ID   int64
	TxID uint64
	// RecordedAt is when it was written, and EffectiveAt when it took effect: when the statement
	// that made it began, or its transaction, where that began later, as one a procedure that
	// commits as it goes starts does; or for an expiry, when it expired; but never before the row's
	// record before it.
	RecordedAt, EffectiveAt time.Time
	Tenant                  string
	// Entity is what changed: grant, role, deny, eligibility, membership, group or member, or
	// history itself, in no tenant, for a prune. Key is which, in the tenant.
	Entity, Key string
	// Op is create, update, delete or expire; baseline, a row written before history was installed,
	// as migrating found it, dated when it was created, or a role when it last changed, or at the
	// epoch where that was before year 1 or at its first instant; or prune, whose After is what
	// PruneHistory was given, how many records one of its transactions deleted, the last of them in
	// History's order, before which History refuses the cursor of an export begun before it, and
	// the id it reached, which a prune of the same goes on from. A prune recorded before migration
	// 0020 holds no last record.
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
	beforeEarliest = earliest.Add(-time.Microsecond)
)

// earliest is the earliest time PostgreSQL holds, the first instant of 24 November 4714 BC, and
// latest the last the package stores: the end of 9999-12-30, which is in 9999 in every time zone,
// the last year JSON and RFC 3339 write. pgx sends a time as 64 bits of microseconds, which a time
// past year 294,000 or so wraps, so that it reaches PostgreSQL as another time, or one it refuses:
// a time a caller passes is checked against these first.
var (
	earliest = time.Date(-4713, time.November, 24, 0, 0, 0, 0, time.UTC)
	latest   = time.Date(9999, time.December, 30, 23, 59, 59, 999999000, time.UTC)
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
	// with the same transaction and id, but not at the same time. History refuses one past the
	// times history holds.
	RecordedAt time.Time
	// Horizon is the oldest transaction running as the export began, by its first read from the
	// start: a prune of an earlier one had ended by then, and the export read none of what it
	// deleted. History refuses the cursor where a prune of a transaction from it on deleted a record
	// after the cursor: by where it stands alone, a cursor of an export begun before a prune can't
	// be told from one of an export begun after it. Keep it with the cursor as History returns it,
	// and never set it, or give one export's cursor another's: a later one would hide from History a
	// prune since the export began, so a checkpoint's signature covers it. Without it, as in a
	// cursor kept from before it was added, History counts every prune recorded after the cursor,
	// and refuses one of an export that began after the prune too, as PruneHistory does given it as
	// through: export again from the start.
	Horizon uint64
}

// MaxHistory is the most records one History call reads, and MaxHistoryBytes the most bytes of
// JSON and text it reads in records after the first: of the largest the package writes, a deny's
// changes, as many records would hold gigabytes.
const (
	MaxHistory      = 10000
	MaxHistoryBytes = 64 << 20
)

// maxHistoryBytes is MaxHistoryBytes, which a test lowers.
var maxHistoryBytes = MaxHistoryBytes

// maxUnsized is the most records one History call measures that no trigger counted the bytes of, as
// history written before migration 0013 or a prune's own: measuring one writes its rows out as
// JSON, so a call reads no more of them than this, and stops at the next. A test lowers it.
var maxUnsized = 100

// History reads up to limit records after a cursor, and the cursor after them, to export history
// to storage of the host's own, but stops short of the record that would bring the bytes of their
// rows' JSON and their text past MaxHistoryBytes, unless it is the first: a read of fewer than limit
// records doesn't mean history holds no more, so read until one reads none. It orders records by
// the transaction that wrote them, by the id each takes at its first write, and reads only those
// of transactions older than any still running, so one that commits after a transaction that took
// its id later is read before it all the same, never skipped. That is the order of transactions,
// not of each row's changes: a transaction that took its id first and changed a row after another
// committed a change to it is read before that one, though its change came after. So a row's
// versions are in the order of their IDs, in which they were written while history's id sequence
// caches one, as AsOf reads them and requires: a consumer replaying an export applies a row's
// versions by ID, not in the order read, or it ends with one the row no longer held. Transaction
// ids are the database cluster's, so a transaction running anywhere in it, in any database, that
// has taken one holds the read back until it ends: a long one, an AsOf whose read runs long, or a
// prepared transaction left open, delays the export. One that took it before a prune history holds
// holds back a read from the start entirely: the export that read begins is told from one begun
// before the prune by its Horizon, the oldest transaction running as it began, which would count
// the prune as one since. A session may turn off the timeouts that would end one it leaves open, so
// watch pg_stat_activity for one held too long and end it, as the README says. A record can be read
// twice, as when a host retries a read whose result it lost: dedupe on ID and RecordedAt, since a
// restore can give another record the ID of one it lost.
//
// It reads the primary, and fails on a replica, which can't tell which timeline it follows until
// long after a failover. A failover or a recovery to a point in time starts a new generation, and
// a restore that starts none, as from a disk snapshot, loses what came after it: either can use
// again ids and transactions the last one used past what it kept. History refuses a cursor from
// another generation, whose last record the database no longer holds, or after which a prune since
// its export began deleted records, as one through the cursor of an export further on does, and
// history is exported again from the start, kept apart from the last export: an export from it
// would read on past what is gone, and its chain vouch for history without it. That export reads
// history as the prunes before it left it, and none of them refuses its cursors. A restore that
// keeps a cursor's record but not what came after it, as one from a disk snapshot taken since the
// cursor was read, leaves no mark the database can tell from a crash's recovery, which loses
// nothing that committed: restore by recovering to a point in time, which starts a generation, or
// export from the start after one. A logical dump restored into another cluster numbers its
// transactions anew, which a cursor can't follow: move history with physical backups and replicas.
//
// It reads history in the current schema by name, so a session's temporary table or type named
// as history's or a catalog's stands in for none of it, and refuses a search_path that names
// pg_temp first. A schema the session's role made, or can create in, named first there is read as
// the package's, so that role must be able to do neither: the README's database roles say how.
func (a *Authorizer) History(ctx context.Context, after Cursor, limit int) ([]Record, Cursor, error) {
	if limit < 1 || limit > MaxHistory {
		return nil, after, fmt.Errorf("%w: a read of history takes from 1 to %d records", ErrInvalid, MaxHistory)
	}
	var generation string
	var records []Record
	// The export's, which this read begins from the start, or which began before.
	horizon := after.Horizon
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
		followed(tx)
		// Of the records up to limit, those within the bytes, counted by what rbac_record counted of
		// their rows, so the rows of those past them are never read; or, for one it didn't count, by
		// its rows, of at most maxUnsized such records, the next counted as past the bytes. Each text
		// column is measured on its own, which reads a stored value's length without detoasting it,
		// as joining them would.
		//
		// And whether a prune since the export began deleted a record after the cursor, as followable
		// read, again in the statement that reads the records, which is of a snapshot of its own at
		// READ COMMITTED: a prune committing since would otherwise delete what it reads past unseen. A
		// read that finds no record chains nothing, and the next refuses the cursor in followable. An
		// export begins with the oldest transaction it sees running as its Horizon, and while a prune
		// it sees is of one no older, reads nothing (unsettled).
		from := after.prunesFrom()
		rows, err := tx.Query(ctx, `
			SELECT id, txid, recorded_at, effective_at, tenant, entity, key, op, coalesce(principal, ''), coalesce(role, ''),
			  coalesce(scope, ''), coalesce(group_id, ''), expires_at, before, after, actor, on_behalf_of, how, request, reason, db_user,
			  $6::boolean AND `+prunedPast(historyTable(schema), "$1::pg_catalog.xid8", "$2", "$7::pg_catalog.xid8", "$8")+`,
			  pg_snapshot_xmin(pg_current_snapshot())
			FROM (
			  SELECT h.*, row_number() OVER w AS n,
			    sum(CASE WHEN h.bytes IS NOT NULL THEN h.bytes
			        WHEN h.unsized <= $5 THEN coalesce(pg_catalog.octet_length(h.before::pg_catalog.text), 0) + coalesce(pg_catalog.octet_length(h.after::pg_catalog.text), 0)
			        ELSE $4 + 1 END
			      + pg_catalog.octet_length(h.tenant) + pg_catalog.octet_length(h.entity) + pg_catalog.octet_length(h.key) + pg_catalog.octet_length(h.op)
			      + coalesce(pg_catalog.octet_length(h.principal), 0) + coalesce(pg_catalog.octet_length(h.role), 0)
			      + coalesce(pg_catalog.octet_length(h.scope), 0) + coalesce(pg_catalog.octet_length(h.group_id), 0)
			      + pg_catalog.octet_length(h.actor) + pg_catalog.octet_length(h.on_behalf_of) + pg_catalog.octet_length(h.how)
			      + pg_catalog.octet_length(h.request) + pg_catalog.octet_length(h.reason) + pg_catalog.octet_length(h.db_user)) OVER w AS reached
			  FROM (
			    SELECT h.*, count(*) FILTER (WHERE h.bytes IS NULL) OVER (ORDER BY h.txid, h.id ROWS UNBOUNDED PRECEDING) AS unsized
			    FROM (
			      SELECT * FROM `+historyTable(schema)+`
			      WHERE (txid, id) > ($1::pg_catalog.xid8, $2) AND txid < pg_snapshot_xmin(pg_current_snapshot())
			        AND ($6::boolean OR NOT `+unsettled(historyTable(schema))+`)
			      ORDER BY txid, id LIMIT $3
			    ) h
			  ) h
			  WINDOW w AS (ORDER BY h.txid, h.id ROWS UNBOUNDED PRECEDING)
			) p
			WHERE n = 1 OR reached <= $4
			ORDER BY txid, id`, after.TxID, after.ID, limit, maxHistoryBytes, maxUnsized, after.following(), from.TxID, from.ID)
		if err != nil {
			return err
		}
		var skipped bool
		var oldest uint64
		records, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Record, error) {
			var r Record
			var principal, role, scope, actor, onBehalfOf string
			var recorded, effective, expires pgtype.Timestamptz
			var before, afterRow []byte
			err := row.Scan(&r.ID, &r.TxID, &recorded, &effective, &r.Tenant, &r.Entity, &r.Key, &r.Op, &principal, &role,
				&scope, &r.Group, &expires, &before, &afterRow, &actor, &onBehalfOf, &r.How, &r.Request, &r.Reason, &r.DBUser, &skipped, &oldest)
			r.RecordedAt, r.EffectiveAt, r.ExpiresAt = recordTime(recorded), recordTime(effective), recordTime(expires)
			r.Principal, r.Scope, r.Actor, r.OnBehalfOf = parsePrincipal(principal), parseScope(scope), parsePrincipal(actor), parsePrincipal(onBehalfOf)
			r.Role, r.Before, r.After = Role(role), before, afterRow
			return r, err
		})
		if err == nil && skipped {
			return errPrunedPast()
		}
		if !after.following() {
			horizon = oldest
		}
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
	return records, Cursor{Generation: generation, TxID: last.TxID, ID: last.ID, RecordedAt: last.RecordedAt, Horizon: horizon}, nil
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
	// At is when, by Config.Now: the time the call decided at.
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
	// The call's clock, which a change's transaction refusing it read under its locks (begin).
	a.cfg.OnRefused(ctx, Refusal{Tenant: tenant, Actor: actor, How: how, Audit: audit, Err: *err, At: a.cfg.Now()})
}
