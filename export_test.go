package rbac

import (
	"context"
	"fmt"
	"maps"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/parallelworks/rbac/internal/pgtest"
)

// Every change a test makes holds all it waits for before it reads the time it decides at.
func init() {
	watched = func(tx pgx.Tx, c *callClock) (pgx.Tx, func(error) error) {
		w := &clockWatched{Tx: tx, clock: c}
		if conn := tx.Conn(); conn != nil {
			w.pid = conn.PgConn().PID()
		}
		rowWaits.push(w)
		return w, func(err error) error {
			waited, lost := rowWaits.pop(w)
			if waited != "" {
				panic("rbac: a change waits for a row lock once it has read the time it decides at: " + strings.Join(strings.Fields(waited), " "))
			}
			if lost != nil {
				panic("rbac: the watch for row waits lost its connection while a change that had read its time ran, so it could have waited unseen: " + lost.Error())
			}
			return err
		}
	}
}

// clockWatched is a change's transaction, which panics on a statement that may wait for a lock once
// the change has read the time it decides at (callClock): a wait would leave that time behind. A
// write's own locks show nowhere in its text, as an upsert's on the row it conflicts with, a
// foreign key's on the group or a delete's on a row the change never held, nor do a trigger's:
// rowWaits sees those waits as they happen, which needs another transaction to hold the row
// meanwhile.
type clockWatched struct {
	pgx.Tx
	clock *callClock
	// pid is the change's session; read, once the change has read its time, waited, the
	// statement it waited for a row in, and lost, why rowWaits stopped watching it, are rowWaits'.
	pid    uint32
	read   bool
	waited string
	lost   error
}

var (
	// rowLock is a row-locking clause, and noWait what after one keeps it from waiting.
	rowLock = regexp.MustCompile(`(?i)\bFOR\s+(NO\s+KEY\s+UPDATE|UPDATE|KEY\s+SHARE|SHARE)\b`)
	noWait  = regexp.MustCompile(`(?i)^\s+(NOWAIT|SKIP\s+LOCKED)\b`)
	// write is a statement that writes, whose own locks take again what the change holds.
	write = regexp.MustCompile(`(?i)\b(DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+(\s+AS\s+\w+)?\s+SET)\b`)
)

func (w *clockWatched) check(ctx context.Context, sql string) {
	if !w.clock.read {
		return
	}
	rowWaits.read(ctx, w)
	if write.MatchString(sql) {
		return
	}
	waits := strings.Contains(sql, "pg_advisory_xact_lock")
	for _, at := range rowLock.FindAllStringIndex(sql, -1) {
		waits = waits || !noWait.MatchString(sql[at[1]:])
	}
	if waits {
		panic("rbac: a change locks once it has read the time it decides at: " + strings.Join(strings.Fields(sql), " "))
	}
}

// rowWaits watches, on a connection of its own, the sessions of the changes that have read their
// time, for a wait on a row: for another transaction to end, as one holding the row does, or to
// finish inserting a key. A wait on a relation, as for a migration, or for its extension, is none
// a change could take first. It polls each millisecond while any change is so, and sees a wait that
// lasts longer. Where its connection fails, it connects again, and each change it was watching
// fails, as it could have waited unseen meanwhile; where it can't connect, every change from then
// on fails, rather than passing unwatched.
var rowWaits = &waitWatch{by: map[uint32][]*clockWatched{}, woken: make(chan struct{}, 1)}

// rowWaitsTimeout bounds each of the watch's connections and queries.
const rowWaitsTimeout = 10 * time.Second

type waitWatch struct {
	mu sync.Mutex
	// by is each session's changes, innermost last: one made in another's OnChange runs on its
	// session, and its waits are its own.
	by    map[uint32][]*clockWatched
	once  sync.Once
	woken chan struct{}
	// pid is the watch's own session, 0 while it connects; gone is why it stopped for good.
	pid  uint32
	gone error
}

func (ww *waitWatch) push(w *clockWatched) {
	if w.pid == 0 {
		return
	}
	ww.mu.Lock()
	defer ww.mu.Unlock()
	ww.by[w.pid] = append(ww.by[w.pid], w)
}

// pop ends watching w, and returns the statement it waited for a row in, if any, and why the watch
// lost sight of it, if it did.
func (ww *waitWatch) pop(w *clockWatched) (waited string, lost error) {
	ww.mu.Lock()
	defer ww.mu.Unlock()
	ws := ww.by[w.pid]
	if i := slices.Index(ws, w); i >= 0 {
		ws = slices.Delete(ws, i, i+1)
	}
	if len(ws) == 0 {
		delete(ww.by, w.pid)
	} else {
		ww.by[w.pid] = ws
	}
	return w.waited, w.lost
}

// lose marks every change that has read its time as unwatched since err.
func (ww *waitWatch) lose(err error) {
	ww.mu.Lock()
	defer ww.mu.Unlock()
	ww.pid = 0
	for _, ws := range ww.by {
		for _, w := range ws {
			if w.read && w.lost == nil {
				w.lost = err
			}
		}
	}
}

// read marks w as having read its time, from when its waits count, once the watch is connected to
// see them: a change that reads its time while the watch connects, as after its connection failed,
// waits for it, as a wait on a row meanwhile would go unseen, and fails where it doesn't connect. The
// watch outlives the change that starts it, so it keeps none of its context's cancellation.
func (ww *waitWatch) read(ctx context.Context, w *clockWatched) {
	if w.pid == 0 {
		return
	}
	ww.mu.Lock()
	was := w.read
	w.read = true
	ww.mu.Unlock()
	if was {
		return
	}
	ww.once.Do(func() { go ww.watch(context.WithoutCancel(ctx), os.Getenv(pgtest.URLEnv)) })
	select {
	case ww.woken <- struct{}{}:
	default:
	}
	// Past every wait the watch's own bounds allow it, to close a failed connection and open another.
	connecting, cancel := context.WithTimeout(ctx, 3*rowWaitsTimeout)
	defer cancel()
	// Where the change's own context ends first, it sends nothing more that could wait.
	if _, err := ww.connected(connecting); err != nil && ctx.Err() == nil {
		ww.mu.Lock()
		if w.lost == nil {
			w.lost = err
		}
		ww.mu.Unlock()
	}
}

func (ww *waitWatch) watch(ctx context.Context, database string) {
	for {
		conn, err := connectWatch(ctx, database)
		if err != nil {
			gone := fmt.Errorf("connecting: %w", err)
			ww.mu.Lock()
			ww.gone = gone
			ww.mu.Unlock()
			ww.lose(gone)
			return
		}
		ww.mu.Lock()
		ww.pid = conn.PgConn().PID()
		ww.mu.Unlock()
		err = ww.poll(ctx, conn)
		ww.lose(err)
		closing, cancel := context.WithTimeout(ctx, rowWaitsTimeout)
		_ = conn.Close(closing)
		cancel()
	}
}

// connectWatch connects to database, trying again until rowWaitsTimeout passes: a server refusing a
// connection for a moment, as one at max_connections does, would otherwise end the watch for good.
func connectWatch(ctx context.Context, database string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, rowWaitsTimeout)
	defer cancel()
	for {
		conn, err := pgx.Connect(ctx, database)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// poll watches on conn until a query on it fails, and returns why.
func (ww *waitWatch) poll(ctx context.Context, conn *pgx.Conn) error {
	for {
		ww.mu.Lock()
		var pids []int32
		var watching []*clockWatched
		for pid, ws := range ww.by {
			if w := ws[len(ws)-1]; w.read {
				pids, watching = append(pids, int32(pid)), append(watching, w)
			}
		}
		ww.mu.Unlock()
		if len(pids) == 0 {
			<-ww.woken
			continue
		}
		waiting, err := ww.waiting(ctx, conn, pids)
		if err != nil {
			return err
		}
		// Only a change still innermost on its session since before the read waited there.
		ww.mu.Lock()
		for i, w := range watching {
			if q, ok := waiting[pids[i]]; ok && w.waited == "" && slices.Index(ww.by[w.pid], w) == len(ww.by[w.pid])-1 {
				w.waited = "(session " + strconv.Itoa(int(pids[i])) + ") " + q
			}
		}
		ww.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
}

// waiting is the statement each of pids waits for a row in, read on conn.
func (ww *waitWatch) waiting(ctx context.Context, conn *pgx.Conn, pids []int32) (map[int32]string, error) {
	ctx, cancel := context.WithTimeout(ctx, rowWaitsTimeout)
	defer cancel()
	rows, err := conn.Query(ctx, `SELECT pid, query FROM pg_stat_activity WHERE pid = ANY($1)
		AND wait_event_type = 'Lock' AND wait_event IN ('transactionid', 'tuple', 'speculative token')`, pids)
	if err != nil {
		return nil, err
	}
	waiting := map[int32]string{}
	var pid int32
	var query string
	_, err = pgx.ForEachRow(rows, []any{&pid, &query}, func() error {
		waiting[pid] = query
		return nil
	})
	return waiting, err
}

// RowWaitWatch returns the session the tests watch changes' row waits on, once the watch, which the
// first change to read its time starts, has connected.
func RowWaitWatch(ctx context.Context) (uint32, error) { return rowWaits.connected(ctx) }

// connected waits until the watch is connected, and returns its session, or why it stopped for good.
func (ww *waitWatch) connected(ctx context.Context) (uint32, error) {
	for {
		ww.mu.Lock()
		pid, gone := ww.pid, ww.gone
		ww.mu.Unlock()
		switch {
		case gone != nil:
			return 0, gone
		case pid != 0:
			return pid, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

// A change that reads its time while the watch connects, as after its connection failed, goes on
// once the watch is connected, and not before, as a wait on a row meanwhile would go unseen; and
// where the watch can't connect, it fails as it ends.
func TestTheWatchHoldsAChangeThatReadsItsTimeUntilItIsConnected(t *testing.T) {
	for _, connects := range []bool{true, false} {
		t.Run(fmt.Sprintf("connects=%t", connects), func(t *testing.T) {
			// Started, as watch is, but not yet connected.
			ww := &waitWatch{by: map[uint32][]*clockWatched{}, woken: make(chan struct{}, 1)}
			ww.once.Do(func() {})
			w := &clockWatched{pid: 1}
			ww.push(w)
			read := make(chan struct{})
			go func() {
				defer close(read)
				ww.read(t.Context(), w)
			}()
			select {
			case <-read:
				t.Fatal("the change went on while the watch connected")
			case <-time.After(50 * time.Millisecond):
			}
			ww.mu.Lock()
			if connects {
				ww.pid = 2
			} else {
				ww.gone = fmt.Errorf("connecting: refused")
			}
			ww.mu.Unlock()
			select {
			case <-read:
			case <-time.After(10 * time.Second):
				t.Fatal("the change never went on")
			}
			if _, lost := ww.pop(w); (lost == nil) != connects {
				t.Errorf("the change, as the watch connected (%t), was lost: %v", connects, lost)
			}
		})
	}
}

func (w *clockWatched) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	w.check(ctx, sql)
	return w.Tx.Exec(ctx, sql, args...)
}

func (w *clockWatched) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	w.check(ctx, sql)
	return w.Tx.Query(ctx, sql, args...)
}

func (w *clockWatched) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	w.check(ctx, sql)
	return w.Tx.QueryRow(ctx, sql, args...)
}

func (w *clockWatched) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	for _, q := range b.QueuedQueries {
		w.check(ctx, q.SQL)
	}
	return w.Tx.SendBatch(ctx, b)
}

// SetSavepointEnd bounds a savepoint's release or rollback by d until t ends.
func SetSavepointEnd(t *testing.T, d time.Duration) {
	t.Helper()
	old := savepointEnd
	savepointEnd = d
	t.Cleanup(func() { savepointEnd = old })
}

// Transacted is whether a change on db runs in a transaction of its own, rather than in a savepoint
// of the host's, as Migrate tells them apart, and the isolation it runs at.
func Transacted(ctx context.Context, db DB) (own bool, level string, err error) {
	err = beginOwn(ctx, db, func(tx pgx.Tx, fresh bool) error {
		own = fresh
		return tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level)
	})
	return own, level, err
}

// Snapshotted is whether a read of several statements on a's DB runs in a transaction of its own,
// rather than on the host's, and the isolation it reads at, with read only where it does.
func Snapshotted(ctx context.Context, a *Authorizer) (own bool, level string, err error) {
	level, err = snapshot(ctx, a, func(b *Authorizer) (string, error) {
		own = b != a
		var level, readOnly string
		err := b.db.QueryRow(ctx, `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')`).Scan(&level, &readOnly)
		if readOnly == "on" {
			level += ", read only"
		}
		return level, err
	})
	return own, level, err
}

// SetMigrateAttempts has Migrate try each migration at most n times, waiting backoff before the
// second, until t ends.
func SetMigrateAttempts(t *testing.T, n int, backoff time.Duration) {
	t.Helper()
	oldAttempts, oldBackoff := migrateAttempts, migrateBackoff
	migrateAttempts, migrateBackoff = n, backoff
	t.Cleanup(func() { migrateAttempts, migrateBackoff = oldAttempts, oldBackoff })
}

// SetMaxPrune bounds what one PruneHistory deletes to n until t ends.
func SetMaxPrune(t *testing.T, n int) {
	t.Helper()
	old := maxPrune
	maxPrune = n
	t.Cleanup(func() { maxPrune = old })
}

// SetPrunedWindow runs f at the end of each of PruneHistory's transactions, on it, until t ends.
func SetPrunedWindow(t *testing.T, f func(pgx.Tx)) {
	t.Helper()
	old := prunedWindow
	prunedWindow = f
	t.Cleanup(func() { prunedWindow = old })
}

// SetFollowed runs f in History once it has checked its cursor, on its transaction, until t ends.
func SetFollowed(t *testing.T, f func(pgx.Tx)) {
	t.Helper()
	old := followed
	followed = f
	t.Cleanup(func() { followed = old })
}

// SetMaxHistoryBytes bounds the bytes one History call reads to n until t ends.
func SetMaxHistoryBytes(t *testing.T, n int) {
	t.Helper()
	old := maxHistoryBytes
	maxHistoryBytes = n
	t.Cleanup(func() { maxHistoryBytes = old })
}

// SetMaxUnsized bounds the records one History call measures that no trigger counted to n until t
// ends.
func SetMaxUnsized(t *testing.T, n int) {
	t.Helper()
	old := maxUnsized
	maxUnsized = n
	t.Cleanup(func() { maxUnsized = old })
}

// SetExpiryBatch bounds what one of DeleteExpired's transactions deletes from a table to n until t
// ends.
func SetExpiryBatch(t *testing.T, n int) {
	t.Helper()
	old := expiryBatch
	expiryBatch = n
	t.Cleanup(func() { expiryBatch = old })
}

// SetMaxContainerOverlap makes Filter look up the grants on containers and the tenant of a subject
// that holds more than n of them, rather than overlap them with each row's path, until t ends.
func SetMaxContainerOverlap(t *testing.T, n int) {
	t.Helper()
	old := maxContainerOverlap
	maxContainerOverlap = n
	t.Cleanup(func() { maxContainerOverlap = old })
}

// SetReadingRoles runs f once a read has read grants and the custom roles with them, until t
// ends.
func SetReadingRoles(t *testing.T, f func()) {
	t.Helper()
	old := readingRoles
	readingRoles = f
	t.Cleanup(func() { readingRoles = old })
}

// SetReadingKeys runs f once an activation has read its approver's keys, until t ends.
func SetReadingKeys(t *testing.T, f func()) {
	t.Helper()
	old := readingKeys
	readingKeys = f
	t.Cleanup(func() { readingKeys = old })
}

// BeforeStatement runs f once, the first time a change's transaction sends a statement whose text
// holds marker once the change has read the time it decides at, or with anyTime, at any time, until
// t ends.
func BeforeStatement(t *testing.T, marker string, anyTime bool, f func()) {
	t.Helper()
	old := watched
	var once sync.Once
	watched = func(tx pgx.Tx, c *callClock) (pgx.Tx, func(error) error) {
		w, end := old(tx, c)
		return &beforeStatement{Tx: w, clock: c, marker: marker, anyTime: anyTime, f: func() { once.Do(f) }}, end
	}
	t.Cleanup(func() { watched = old })
}

// beforeStatement is a change's transaction BeforeStatement watches.
type beforeStatement struct {
	pgx.Tx
	clock   *callClock
	marker  string
	anyTime bool
	f       func()
}

func (b *beforeStatement) at(sql string) {
	if (b.anyTime || b.clock != nil && b.clock.read) && strings.Contains(sql, b.marker) {
		b.f()
	}
}

func (b *beforeStatement) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	b.at(sql)
	return b.Tx.Exec(ctx, sql, args...)
}

func (b *beforeStatement) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	b.at(sql)
	return b.Tx.Query(ctx, sql, args...)
}

func (b *beforeStatement) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	b.at(sql)
	return b.Tx.QueryRow(ctx, sql, args...)
}

func (b *beforeStatement) SendBatch(ctx context.Context, batch *pgx.Batch) pgx.BatchResults {
	for _, q := range batch.QueuedQueries {
		b.at(q.SQL)
	}
	return b.Tx.SendBatch(ctx, batch)
}

// HeldMarker is text only readHeld's statement, which reads an actor's or a subject's grants and
// what binds it, holds.
const HeldMarker = "SELECT 0, id, principal, scope, role, expires_at, conditional"

// ExcludesMarker is text only the statement reading who holds two values of an exclusive dimension
// (conflictsIn) holds, which a change runs once it has read its actor.
const ExcludesMarker = "HAVING count(DISTINCT value) > 1"

// SetCheckingRole runs f each time a decision begins checking a role for a grant, until t ends.
func SetCheckingRole(t *testing.T, f func()) {
	t.Helper()
	old := checkingRole
	checkingRole = f
	t.Cleanup(func() { checkingRole = old })
}

// SetReadingEntries runs f each time a decision reads n entries of a role's permissions and types, or of
// what the constraints answered, until t ends.
func SetReadingEntries(t *testing.T, f func(n int)) {
	t.Helper()
	old := readingEntries
	readingEntries = f
	t.Cleanup(func() { readingEntries = old })
}

// SetReadingDenies runs f each time a decision reads n entries of a deny's permissions, comparing
// them with a permission or indexing them, until t ends.
func SetReadingDenies(t *testing.T, f func(n int)) {
	t.Helper()
	old := readingDenies
	readingDenies = f
	t.Cleanup(func() { readingDenies = old })
}

// SetMatchingKeys runs f each time Holders' read of its identities' label values looks n keys up to
// find the denies binding them, until t ends.
func SetMatchingKeys(t *testing.T, f func(n int)) {
	t.Helper()
	old := matchingKeys
	matchingKeys = f
	t.Cleanup(func() { matchingKeys = old })
}

// SetCheckingCondition runs f each time a change begins checking a condition it hasn't, until t
// ends.
func SetCheckingCondition(t *testing.T, f func()) {
	t.Helper()
	old := checkingCondition
	checkingCondition = f
	t.Cleanup(func() { checkingCondition = old })
}

// SetParsingCondition runs f each time a change begins parsing a condition for whether it reads
// the subject, until t ends.
func SetParsingCondition(t *testing.T, f func()) {
	t.Helper()
	old := parsingCondition
	parsingCondition = f
	t.Cleanup(func() { parsingCondition = old })
}

// SetDecidingGrants runs f as a change begins deciding its grants, and what f returns once it has,
// until t ends.
func SetDecidingGrants(t *testing.T, f func() func()) {
	t.Helper()
	old := decidingGrants
	decidingGrants = f
	t.Cleanup(func() { decidingGrants = old })
}

// ExcludedOn is, for each of on, resources of one tenant, the exclusive dimensions whose values
// actor's grants on its path could give two of, as a change's authorities on all of them decide
// them together, and as excludedBy decides them from that path's grants alone, as each authority
// once decided its own.
func ExcludedOn(t *testing.T, a *Authorizer, actor Subject, on []Resource) (together, alone []map[string]bool) {
	t.Helper()
	a = a.still()
	aus, err := a.authorities(t.Context(), a.db, actor, on, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, au := range aus {
		together = append(together, au.excluded)
		alone = append(alone, a.excludedBy(au.roles, au.held))
	}
	return together, alone
}

// ReadAuthority reads, on a's DB, actor's authority on each of on, a tenant's resources, with the
// types of scope whose power to change grants a deny anywhere in the tenant binding it lists, in
// one statement, as a change reads what it acts by (authoritiesIn).
func ReadAuthority(ctx context.Context, a *Authorizer, actor Subject, on []Resource) error {
	a = a.still()
	_, _, err := a.authoritiesIn(ctx, a.db, actor, on[0].Tenant, on, nil, alsoRead{grantsDenied: true})
	return err
}

// ReadGrantsDenied reads, on a's DB, the types of scope whose power to change grants a deny
// anywhere in a tenant binding actor lists, as a change to members reads them before its
// transaction (grantsDenied).
func ReadGrantsDenied(ctx context.Context, a *Authorizer, tenant string, actor Subject) error {
	a = a.still()
	_, err := a.grantsDenied(ctx, a.db, tenant, actor)
	return err
}

// Planned reads sql on q with sequential scans off for its plan alone, as a check reads its
// subject's grants (planned), handing its rows to read.
func Planned(ctx context.Context, q DB, read func(pgx.Rows) error, sql string, args ...any) error {
	return planned(ctx, q, indexed, read, sql, args...)
}

// QueriedIndexed is q.Query of sql with sequential scans off for its plan alone, as a list reads
// its rows on (plannedQuery).
func QueriedIndexed(ctx context.Context, q DB, sql string, args ...any) (pgx.Rows, error) {
	return plannedQuery(ctx, q, indexed, sql, args...)
}

// HeldByMembers is why making custom role id privileged in tenant is refused at now, read on q, as
// its tenant's members hold it (heldByMembers).
func HeldByMembers(ctx context.Context, q DB, tenant string, id Role, now time.Time) error {
	return heldByMembers(ctx, q, tenant, id, now)
}

// LabelValuesDecided is, for each of labels, the values it asks for that actor holds in tenant on
// ctx's request: decided together, as a change checking them all by one read of what the actor's
// values are decided by decides them, label after label; and each alone, by a read of its own, of
// every grant it holds on the tenant and every permission of their roles.
func LabelValuesDecided(t *testing.T, ctx context.Context, a *Authorizer, actor Subject, tenant string, labels []Label) (together, alone [][]Permission) {
	t.Helper()
	together, alone, _, _ = HoldingDecided(t, ctx, a, actor, tenant, labels)
	return together, alone
}

// HoldingDecided is LabelValuesDecided, and then all that actor holds: its label values and powers
// to release, and "excluding <dimension>" for each exclusive dimension it holds none of. Decided by
// the same read once the labels are, as a change checking them and then whether the actor's values
// satisfy every label decides them (clearsAll); and alone, by a read of its own of every grant and
// permission.
func HoldingDecided(t *testing.T, ctx context.Context, a *Authorizer, actor Subject, tenant string, labels []Label) (together, alone [][]Permission, all, whole []string) {
	t.Helper()
	a = a.still()
	v, err := a.valuesOn(ctx, a.db, tenant, actor)
	if err != nil {
		t.Fatal(err)
	}
	c := a.constrain(ctx, actor, tenantResource(tenant))
	for _, l := range labels {
		h, err := c.decidedBy(ctx, a.db, v, a.askedBy(l))
		if err != nil {
			t.Fatal(err)
		}
		together = append(together, a.heldOf(h, l))
	}
	h, err := c.decidedBy(ctx, a.db, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	all = everything(h)
	for _, l := range labels {
		h, _, err := a.walkingEvery(ctx, actor, tenant, v, l)
		if err != nil {
			t.Fatal(err)
		}
		alone = append(alone, a.heldOf(h, l))
	}
	h, _, err = a.walkingEvery(ctx, actor, tenant, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	return together, alone, all, everything(h)
}

// LabeledChecksDecided is, for each of labels and then for every label, what actor holds in tenant
// on ctx's request of the values each asks for, as HoldingDecided writes them, and those of them a
// condition or a constraint decided, which Holders marks a holder by, or the error deciding them
// returned: as a check of a resource it labels decides them (holdingFor), and Reachable and
// Holding every one (holdingOf), by a read narrowed to the grants giving values and of their roles
// those (labeling); and by a read of every grant actor holds on the tenant and every permission of
// their roles. Each is decided by a read and asks of the constraints of its own, as checks are.
func LabeledChecksDecided(t *testing.T, ctx context.Context, a *Authorizer, actor Subject, tenant string, labels []Label) (narrowed, full []string) {
	t.Helper()
	a = a.still()
	v, err := a.valuesOn(ctx, a.db, tenant, actor)
	if err != nil {
		t.Fatal(err)
	}
	return a.checksDecided(ctx, actor, tenant, labels, func() *valuesRead { return &valuesRead{held: v.held, ds: v.ds, roles: v.roles} }, v)
}

// ListedChecksDecided is LabeledChecksDecided of each of subjects, identities that are members or
// guests of tenant, deciding by Holders' read of every subject's values at once, narrowed once for
// all of them (valuesOfAll), as Holders decides each holder's, in place of a read of its own.
func ListedChecksDecided(t *testing.T, ctx context.Context, a *Authorizer, subjects []Subject, tenant string, labels []Label) (listed, full [][]string) {
	t.Helper()
	a = a.still()
	identities := make([]string, len(subjects))
	for i, s := range subjects {
		identities[i] = s.Principal.key()
	}
	read, err := a.valuesOfAll(ctx, a.db, tenant, identities)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		v, err := a.valuesOn(ctx, a.db, tenant, s)
		if err != nil {
			t.Fatal(err)
		}
		r := read[s.Principal.key()]
		if r == nil {
			t.Fatalf("Holders' read has nothing of %v", s.Principal)
		}
		by, whole := a.checksDecided(ctx, s, tenant, labels, func() *valuesRead { return r }, v)
		listed, full = append(listed, by), append(full, whole)
	}
	return listed, full
}

// HoldersListedBothWays is how Holders lists each of subjects, identities that are members or
// guests of r's tenant, as holders of p on r, deciding its label values by Holders' read of every
// subject's at once (valuesOfAll): as Holders decides them, evaluating no condition, and evaluating
// every one with ctx's request. Each is "out", "kept" or "marked", as MaybeDenied.
func HoldersListedBothWays(t *testing.T, ctx context.Context, a *Authorizer, subjects []Subject, p Permission, r Resource) (unevaluated, evaluated []string) {
	t.Helper()
	a = a.still()
	identities := make([]string, len(subjects))
	for i, s := range subjects {
		identities[i] = s.Principal.key()
	}
	read, err := a.valuesOfAll(ctx, a.db, r.Tenant, identities)
	if err != nil {
		t.Fatal(err)
	}
	asked := a.askedBy(r.Labels)
	listed := func(s Subject, shared *runs) string {
		keep, mark, err := a.listing(ctx, s, p, r, read[s.Principal.key()], func(q Permission) bool { return asked[q] }, shared)
		switch {
		case err != nil:
			t.Fatal(err)
		case mark:
			return "marked"
		case keep:
			return "kept"
		}
		return "out"
	}
	for _, s := range subjects {
		unevaluated, evaluated = append(unevaluated, listed(s, &runs{unevaluated: true})), append(evaluated, listed(s, nil))
	}
	return unevaluated, evaluated
}

// checksDecided is LabeledChecksDecided of actor, deciding by what read returns, and by v walked
// whole.
func (a *Authorizer) checksDecided(ctx context.Context, actor Subject, tenant string, labels []Label, read func() *valuesRead, v *valuesRead) (by, full []string) {
	decided := func(h Holding, byCondition map[Permission]bool, l Label, err error) string {
		conditioned := fmt.Sprint(" by condition ", slices.Sorted(maps.Keys(byCondition)))
		switch {
		case err != nil:
			return "error: " + err.Error()
		case l == nil:
			return strings.Join(everything(h), " ") + conditioned
		}
		return fmt.Sprint(a.heldOf(h, l), h.excluded, conditioned)
	}
	for _, l := range append(slices.Clone(labels), nil) {
		var h Holding
		var byCondition map[Permission]bool
		var err error
		if l == nil {
			h, byCondition, err = a.holdingOf(ctx, tenant, actor, read())
		} else {
			h, byCondition, err = a.holdingFor(ctx, tenant, actor, read(), l)
		}
		by = append(by, decided(h, byCondition, l, err))
		h, byCondition, err = a.walkingEvery(ctx, actor, tenant, v, l)
		full = append(full, decided(h, byCondition, l, err))
	}
	return by, full
}

// walkingEvery is actor's holding in tenant decided by v as it is read, of the values l asks for,
// or of every one where l is nil, walking every grant v holds and every permission of their roles,
// and those of them a condition or a constraint decided.
func (a *Authorizer) walkingEvery(ctx context.Context, actor Subject, tenant string, v *valuesRead, l Label) (Holding, map[Permission]bool, error) {
	only := a.labelPermission
	if l != nil {
		asked := a.askedBy(l)
		only = func(p Permission) bool { return asked[p] }
	}
	return a.holdingFrom(ctx, a.db, actor, a.constrain(ctx, actor, tenantResource(tenant)), &valuesRead{held: v.held, ds: v.ds, roles: v.roles}, only, nil)
}

// heldOf is the values l asks for that h holds, sorted.
func (a *Authorizer) heldOf(h Holding, l Label) []Permission {
	var held []Permission
	for _, p := range slices.Sorted(maps.Keys(a.askedBy(l))) {
		if dim, value := p.parts(); h.values[dim][value] {
			held = append(held, p)
		}
	}
	return held
}

// everything is the label values and powers to release h holds, and "excluding <dimension>" for
// each exclusive dimension it holds none of.
func everything(h Holding) []string {
	var held []string
	for _, p := range h.Values() {
		held = append(held, string(p))
	}
	for _, dim := range slices.Sorted(maps.Keys(h.releases)) {
		if h.releases[dim] {
			held = append(held, string(ReleasePermission(dim)))
		}
	}
	for _, dim := range slices.Sorted(maps.Keys(h.excluded)) {
		if h.excluded[dim] {
			held = append(held, "excluding "+dim)
		}
	}
	return held
}

// GrantDecision is what deciding a grant found: the permission the actor lacks to make it, ""
// where it may, and the constraint whose removal of it refused it, if one did.
type GrantDecision struct {
	Lacks Permission
	By    string
}

// GrantsDecided is, for each of grants actor makes on r on ctx's request, what deciding it found
// (GrantDecision): as a change granting them all decides them, by one read of its authority there
// and one ask of each constraint, a role once for each condition and end its grants tell apart; and
// as deciding each alone does, by a read and asks of its own, under the grant's own condition, by
// those of its grants that each last until the grant ends (holding.lasts), as though they lasted
// for good, and the grant were made for good, under the denies binding it and those exempting it
// only until before the grant ends, as though they bound it.
func GrantsDecided(t *testing.T, ctx context.Context, a *Authorizer, actor Subject, r Resource, grants []Binding) (together, alone []GrantDecision) {
	t.Helper()
	a = a.still()
	authority := func(grants []Binding) authority {
		au, err := a.authorityOn(ctx, a.db, actor, r, roleIDs(grants))
		if err != nil {
			t.Fatal(err)
		}
		au.constrained = a.constrain(ctx, actor, r)
		return au
	}
	au := authority(grants)
	for _, d := range a.grantsDecided(au, au.over(r.Type), r.Type, grants) {
		together = append(together, GrantDecision{d.lacks, d.by})
	}
	for _, b := range grants {
		au := authority([]Binding{b})
		def, known := au.roles.role(b.Role)
		var decided GrantDecision
		if known && a.grantableOn(def, r.Type) {
			// Its power to change grants now is what all its grants give, whenever they end.
			pw := au.over(r.Type)
			au.held = slices.DeleteFunc(slices.Clone(au.held), func(g holding) bool { return !g.lasts(b.ExpiresAt) })
			for i := range au.held {
				au.held[i].ends = time.Time{}
			}
			exempt := au.exemptUntil
			au.exemptUntil = func(p Permission) time.Time {
				if until := exempt(p); !(holding{ends: until}).lasts(b.ExpiresAt) {
					return until
				}
				return time.Time{}
			}
			decided.Lacks, decided.By, _ = a.mayGrant(au, pw, r.Type, def, b.Condition.Expression, time.Time{}, newChecked())
		}
		alone = append(alone, decided)
	}
	return together, alone
}

// overlapSQL is how the denies binding a subject were matched to its keys before they were looked
// up in objects, kept as what the lookups must agree with: by the overlap of arrays, which compares
// each of a deny's keys with every one of the subject's. It reads the denies, on the scopes $3 or
// every scope where it is NULL, naming a key the identity $2, empty for the anonymous, is bound by
// in the tenant $1 at $4, of any permission, with whether one exempts it, and where one does but not
// for good, when its exemption ends where the deny binds it past then.
var overlapSQL = `WITH RECURSIVE ` + keysSQL("$1::text", "$2::text", "$4") + `, ` + endsSQL("$2", "$4") + `, ` +
	lastingSQL("$1::text", "$2::text") + `
	SELECT id, scope, permissions, exempt && ARRAY(SELECT k FROM exempted),
	  CASE WHEN exempt && ARRAY(SELECT k FROM exempted) THEN ` + overlapUntilSQL("principals", "exempt") + ` END
	FROM rbac_denies WHERE tenant = $1 AND ($3::text[] IS NULL OR scope = ANY($3::text[])) AND principals && ARRAY(SELECT k FROM bound)`

// overlapUntilSQL is exemptUntilSQL as the overlap of arrays wrote it, kept as what its lookups in
// lasts must agree with: each of the deny's keys compared with every key lastingSQL reads.
func overlapUntilSQL(principals, exempt string) string {
	return fmt.Sprintf(`CASE WHEN NOT %[2]s && ARRAY(SELECT k FROM lasting WHERE exempts AND e IS NULL) THEN (
	  SELECT max(x.e) FROM lasting x WHERE x.exempts AND x.k = ANY(%[2]s)
	  HAVING max(x.e) < (SELECT max(coalesce(y.e, 'infinity')) FROM lasting y WHERE y.k = ANY(%[1]s))) END`, principals, exempt)
}

// The fragments matching a deny's keys to its subject's, and the reference for exemptUntilSQL, for
// a test to evaluate on values of its own.
var (
	Keyed            = keyed
	BindsIfRead      = bindsIfRead
	ExemptForGoodSQL = exemptForGoodSQL
	ExemptUntilSQL   = exemptUntilSQL
	OverlapUntilSQL  = overlapUntilSQL
	LastingSQL       = lastingSQL
)

// DenyRead is what one read of the denies binding a subject found, and what it should have, as the
// overlap of arrays finds them (overlapSQL): each "id on scope", with " until" and a time for one a
// change reads as exempting the subject only until then, sorted. On and Permission are what it read
// them on and of, where it did.
type DenyRead struct {
	Read       string
	On         string
	Permission Permission
	Got, Want  []string
}

// DeniesMatched is each read of the denies binding s in a tenant: on each of resources, a check's of
// each of permissions and of its label values with it (readHeld), Explain's (deniesOn), Permissions'
// of any permission, and a change's with when its exemptions end; Holders' of its label values, read
// with those of the others in together, as Holders reads every identity's at once (valuesOfAll),
// which keeps only the denies listing a label value or a power to release; and those of
// DeniesAnywhereMatched; each with what the overlap of arrays finds for it.
func DeniesMatched(t *testing.T, ctx context.Context, a *Authorizer, s Subject, together []Subject, resources []Resource, permissions []Permission) []DenyRead {
	t.Helper()
	a = a.still()
	tenant := resources[0].Tenant
	tenantKey := TenantRoot(tenant).Key()
	found := overlapping(t, ctx, a, tenant, s)
	keys, binding, err := a.keysOf(ctx, a.db, tenant, s)
	if err != nil {
		t.Fatal(err)
	}
	want := func(keep func(o overlapped) bool) []string {
		var names []string
		for _, o := range found {
			switch {
			case !keep(o):
			case o.exempts:
				names = append(names, exemptingUntil(o.name, o.until))
			default:
				names = append(names, o.name)
			}
		}
		slices.Sort(names)
		return names
	}
	names := func(ds []denial) []string {
		var names []string
		for _, d := range ds {
			names = append(names, d.id+" on "+d.scope)
		}
		return names
	}
	var reads []DenyRead
	add := func(read string, r *Resource, p Permission, got, want []string) {
		slices.Sort(got)
		on := ""
		if r != nil {
			on = r.ID
		}
		reads = append(reads, DenyRead{read, on, p, got, want})
	}
	fail := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range resources {
		path := r.path()
		onPath := func(o overlapped) bool { return slices.Contains(path, o.scope) }
		for _, p := range permissions {
			listing := func(o overlapped) bool { return onPath(o) && o.binds() && denies(o.permissions, p) }
			// A check reads none for a subject none of whose keys count, and none of its label values
			// for the anonymous where the public's don't.
			counts := a.counting(p, r.Type)
			counted := len(countedOf(keys, counts)) > 0
			checked, err := a.readHeld(ctx, a.db, tenant, s, counts, path, p, namedRoles, alsoRead{values: true})
			fail(err)
			add("check", &r, p, names(checked.ds), want(func(o overlapped) bool { return counted && listing(o) }))
			valued := s.Principal != (Principal{}) || counts.public
			add("label values", &r, p, names(checked.values.ds), want(func(o overlapped) bool { return valued && o.scope == tenantKey && o.binds() }))
			explained, err := a.deniesOn(ctx, a.db, tenant, binding, exempting(keys, s), path, p)
			fail(err)
			add("explain", &r, p, names(explained), want(listing))
		}
		_, ds, _, err := a.heldOrDenied(ctx, a.db, tenant, s, all, path, namedRoles)
		fail(err)
		add("permissions", &r, "", names(ds), want(func(o overlapped) bool { return onPath(o) && o.binds() }))
		changing, err := a.readHeld(ctx, a.db, tenant, s, all, path, "", tenantRoles, alsoRead{ending: true})
		fail(err)
		got := names(changing.ds)
		for _, e := range changing.exempt {
			got = append(got, exemptingUntil(e.id+" on "+e.scope, e.until))
		}
		add("change", &r, "", got, want(func(o overlapped) bool { return onPath(o) && (o.binds() || !o.until.IsZero()) }))
	}
	if s.Principal != (Principal{}) {
		identities := []string{s.identityKey()}
		for _, o := range together {
			if o.Principal != (Principal{}) && o.Principal != s.Principal {
				identities = append(identities, o.identityKey())
			}
		}
		values, err := a.valuesOfAll(ctx, a.db, tenant, identities)
		fail(err)
		add("holders' label values", nil, "", names(values[s.identityKey()].ds), want(func(o overlapped) bool {
			return o.scope == tenantKey && o.binds() && slices.ContainsFunc(o.permissions, a.labelPermission)
		}))
	}
	return append(reads, anywhereMatched(t, ctx, a, tenant, s, found)...)
}

// DeniesAnywhereMatched is each read of the denies binding s anywhere in a tenant: the types
// ChangeMembers reads (grantsDenied), and whether SetRole finds one below the tenant (belowSQL);
// each with what the overlap of arrays finds for it. Each answers for every deny at once, so of
// several binding s, any one decides it.
func DeniesAnywhereMatched(t *testing.T, ctx context.Context, a *Authorizer, tenant string, s Subject) []DenyRead {
	t.Helper()
	a = a.still()
	return anywhereMatched(t, ctx, a, tenant, s, overlapping(t, ctx, a, tenant, s))
}

// anywhereMatched is DeniesAnywhereMatched of the denies overlapping found.
func anywhereMatched(t *testing.T, ctx context.Context, a *Authorizer, tenant string, s Subject, found []overlapped) []DenyRead {
	t.Helper()
	types, err := a.grantsDenied(ctx, a.db, tenant, s)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{}
	for _, o := range found {
		for _, x := range o.permissions {
			if typ, verb := x.parts(); o.binds() && (verb == "grant" || verb == "*") {
				wanted[typ] = true
			}
		}
	}
	reads := []DenyRead{{Read: "grants denied", Got: slices.Sorted(maps.Keys(types)), Want: slices.Sorted(maps.Keys(wanted))}}
	// As a change reads them under its locks, with its authority on the tenant or on nothing.
	for _, on := range [][]Resource{{tenantResource(tenant)}, nil} {
		_, read, err := a.authoritiesIn(ctx, a.db, s, tenant, on, nil, alsoRead{grantsDenied: true})
		if err != nil {
			t.Fatal(err)
		}
		reads = append(reads, DenyRead{
			Read: fmt.Sprint("grants denied with the authority on ", len(on), " resources"),
			Got:  slices.Sorted(maps.Keys(read.grantsDenied)), Want: slices.Sorted(maps.Keys(wanted)),
		})
	}
	// As a change to a custom role reads them with its authority on the tenant, before its
	// transaction and under its lock.
	_, below, err := a.authoritiesIn(ctx, a.db, s, tenant, []Resource{tenantResource(tenant)}, nil, alsoRead{below: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, exempting := range []bool{false, true} {
		bound := slices.ContainsFunc(found, func(o overlapped) bool {
			return !strings.HasPrefix(o.scope, TenantScope+":") && (o.binds() || exempting && !o.until.IsZero())
		})
		got := below.bound || exempting && below.exemptUntil
		reads = append(reads, DenyRead{Read: fmt.Sprint("denied below, exempting ", exempting), Got: []string{fmt.Sprint(got)}, Want: []string{fmt.Sprint(bound)}})
	}
	return reads
}

// overlapped is a deny binding a subject as the overlap of arrays reads it (overlapSQL): "id on
// scope", what it removes, whether it exempts the subject, and if so but not for good, when that
// ends, where it binds the subject past then.
type overlapped struct {
	name, scope string
	permissions []Permission
	exempts     bool
	until       time.Time
}

// binds is whether the deny binds its subject, exempting it not at all.
func (o overlapped) binds() bool { return !o.exempts }

// overlapping reads the denies binding s anywhere in a tenant as the overlap of arrays does.
func overlapping(t *testing.T, ctx context.Context, a *Authorizer, tenant string, s Subject) []overlapped {
	t.Helper()
	var found []overlapped
	rows, err := a.db.Query(ctx, overlapSQL, tenant, s.identityKey(), nil, a.cfg.Now())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	var o overlapped
	var perms []string
	var until *time.Time
	if _, err := pgx.ForEachRow(rows, []any{&id, &o.scope, &perms, &o.exempts, &until}, func() error {
		o.name, o.permissions, o.until = id+" on "+o.scope, nil, time.Time{}
		for _, x := range perms {
			o.permissions = append(o.permissions, Permission(x))
		}
		if until != nil {
			o.until = *until
		}
		found = append(found, o)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

// exemptingUntil names a deny exempting its subject until a time, as DenyRead does.
func exemptingUntil(name string, until time.Time) string {
	return name + " until " + until.UTC().Format(time.RFC3339Nano)
}

// StandSQL is the statement a change reads the standing of its principals with.
var StandSQL = standSQL

// Conflicted is err as an exported call returns it: matching ErrConflict where it holds a race.
var Conflicted = conflicted

// LockKey is the key of a tenant's lock of a kind on key, in the tables of schema, as a change
// takes it: a lock on no key takes its 64 bits as two int4 keys, high and low.
func LockKey(schema, kind, tenant, key string) int64 {
	return lockKey(lockName(schema, kind, tenant, key))
}

// Lock takes a change's locks in tx: its tenant's shared, then each of its scopes' and principals'.
var Lock = lock

// HoldSQL is the statement Activate holds the places it rests on and reads its subject's paths
// with: tenant $1, the identity's key $2, now $3, until $4.
var HoldSQL = holdSQL

// RestsSQL is the statement a change ending places reads the paths left to activations with:
// tenant $1, the activations' ids $2, now $3.
var RestsSQL = restsSQL

// CutSQL is the statement a change cuts activations short with: their ids $1, their ends $2 in the
// same order, the actor's key $3.
const CutSQL = cutSQL

// EndsSQL is the statement a change reads when its actor's paths to each key it holds end with:
// tenant $1, the identity's key $2, now $3.
var EndsSQL = `WITH RECURSIVE ` + endsSQL("$2::text", "$3") + ` SELECT k, e FROM ends`

// DeepCopy is the copy of attributes each hook is given, nil where they can't be copied (Copies).
func DeepCopy(attributes map[string]any) map[string]any {
	copied, _ := deepCopy(attributes)
	return copied
}

// Copies reports whether attributes can be copied for a hook, within what a check converts.
func Copies(attributes map[string]any) bool {
	_, ok := deepCopy(attributes)
	return ok
}

// CopyAllocates is how many bytes copying attributes for a hook allocates.
func CopyAllocates(attributes map[string]any) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	deepCopy(attributes)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// CountZoneLoads counts the time zones conditions load, until t ends.
func CountZoneLoads(t *testing.T) *int {
	t.Helper()
	old, n := loadingZone, new(int)
	loadingZone = func() { *n++ }
	t.Cleanup(func() { loadingZone = old })
	return n
}

// LoadZones loads each zone named, or finds it names none, as a condition reading a time in it does
// where the process hasn't, and returns how many zones the process keeps.
func LoadZones(names []string) int {
	for _, name := range names {
		loadZone(name)
	}
	zones.RLock()
	defer zones.RUnlock()
	return len(zones.byName)
}

// ForgetZones drops the zones named from those the process keeps.
func ForgetZones(names ...string) {
	zones.Lock()
	defer zones.Unlock()
	for _, name := range names {
		delete(zones.byName, name)
	}
}

// FailZoneLoads makes loading a time zone fail with err, until the func it returns is called or t
// ends.
func FailZoneLoads(t *testing.T, err error) (restore func()) {
	t.Helper()
	old := locating
	locating = func(string) (*time.Location, error) { return nil, err }
	restore = func() { locating = old }
	t.Cleanup(restore)
	return restore
}

// MaxZones is how many time zones the process keeps loaded.
const MaxZones = maxZones

// ZoneLoad is what loading a time zone costs a condition.
const ZoneLoad = zoneLoad

// CountCopies counts the copies made of what the host passes for its hooks, until t ends.
func CountCopies(t *testing.T) *int {
	t.Helper()
	old, n := copying, new(int)
	copying = func() { *n++ }
	t.Cleanup(func() { copying = old })
	return n
}

// CopiedInOneCall is what one call gives a hook of each of n values made by fresh, asked about one
// after another, each dropped and the garbage collected before the next is made.
func CopiedInOneCall(n int, fresh func(i int) map[string]any) []map[string]any {
	a := (&Authorizer{}).still()
	copies := make([]map[string]any, n)
	for i := range n {
		copies[i], _ = copiedFor(a, 0, fresh(i))
		runtime.GC()
	}
	return copies
}

// Compiled is how many conditions a keeps compiled for checks.
func Compiled(a *Authorizer) int {
	a.conds.mu.RLock()
	defer a.conds.mu.RUnlock()
	return len(a.conds.programs)
}

// Limits is how many conditions a keeps the limit of, the most evaluating each can cost.
func Limits(a *Authorizer) int {
	a.conds.mu.RLock()
	defer a.conds.mu.RUnlock()
	return len(a.conds.limits)
}

// CountEvaluations counts the conditions evaluated until t ends.
func CountEvaluations(t *testing.T) *int {
	t.Helper()
	old, n := evaluating, new(int)
	evaluating = func() { *n++ }
	t.Cleanup(func() { evaluating = old })
	return n
}

// CountSearches counts the searches of a string conditions run, contains, startsWith and endsWith,
// until t ends.
func CountSearches(t *testing.T) *int {
	t.Helper()
	old, n := searching, new(int)
	searching = func() { *n++ }
	t.Cleanup(func() { searching = old })
	return n
}

// ConvertingAllocates is how many allocations building what conditions read takes, for a check
// whose subject, resource and request each pass attributes of their own.
func ConvertingAllocates(t *testing.T, subject, resource, request map[string]any) float64 {
	t.Helper()
	a := &Authorizer{cfg: Config{Now: time.Now}}
	ctx := WithRequest(t.Context(), request)
	s, r := Subject{Principal: Principal{Kind: User, ID: "u"}, Attributes: subject}, Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: resource}
	return testing.AllocsPerRun(20, func() { a.vars(ctx, s, "cluster:login", r) })
}

// CountConversions counts the times what conditions read is built, converting what the host
// passes, until t ends.
func CountConversions(t *testing.T) *int {
	t.Helper()
	old, n := converting, new(int)
	converting = func() { *n++ }
	t.Cleanup(func() { converting = old })
	return n
}

// CountKindsConverted counts the kinds' attributes, the subject's, the resource's or the request's,
// converted for conditions to read, none counted where a kind passes none, until t ends.
func CountKindsConverted(t *testing.T) *int {
	t.Helper()
	old, n := convertingKind, new(int)
	convertingKind = func() { *n++ }
	t.Cleanup(func() { convertingKind = old })
	return n
}

// ConditionCost is the most evaluating expr can cost, which a check runs it within, and what
// evaluating it on a request with attributes, which the resource carries too, costs, up to
// maxCost, built with the package's CEL environment extended by opts.
func ConditionCost(t *testing.T, expr string, attributes map[string]any, opts ...cel.EnvOption) (limit, actual uint64) {
	t.Helper()
	return ConditionCostOn(t, expr, Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes}, attributes, opts...)
}

// MaxPermission is the longest action conditions are bounded for.
const MaxPermission = maxPermission

// ConditionCostOn is ConditionCost for s asking to do p to r, on a request with attributes.
func ConditionCostOn(t *testing.T, expr string, s Subject, p Permission, r Resource, attributes map[string]any, opts ...cel.EnvOption) (limit, actual uint64) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) > 0 {
		if c.env, err = c.env.Extend(opts...); err != nil {
			t.Fatal(err)
		}
	}
	prg, err := c.build(expr)
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	unlimited, err := plan(c.env, checked, patterns, maxCost)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), s, p, r)
	return prg.limit, evaluate(program{Program: unlimited, limit: maxCost}, vars).cost
}

// EvaluateCondition evaluates expr as a check does, on a request with attributes, which the
// resource carries too, and reports whether it held, whether it could be evaluated and the bytes
// evaluating it allocated, or why it isn't a condition.
func EvaluateCondition(t *testing.T, expr string, attributes map[string]any) (held, evaluated bool, allocated uint64, err error) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	prg, err := c.build(expr)
	if err != nil {
		return false, false, 0, err
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := evaluate(prg, vars)
	runtime.ReadMemStats(&after)
	return r.held, r.evaluated, after.TotalAlloc - before.TotalAlloc, nil
}

// EvaluateConditionOf is whether expr held, and whether it could be evaluated, on a request whose
// subject, resource and request each pass attributes of their own.
func EvaluateConditionOf(t *testing.T, expr string, subject, resource, request map[string]any) (held, evaluated bool) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	prg, err := c.build(expr)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(WithRequest(t.Context(), request), Subject{Principal: Principal{Kind: User, ID: "u"}, Attributes: subject}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: resource})
	r := evaluate(prg, vars)
	return r.held, r.evaluated
}

// Decided is what an evaluation of a condition decided, and what it cost.
type Decided struct {
	Held, Evaluated bool
	Cost            uint64
}

// Evaluations is what each of n evaluations of expr decides as a check does, the attributes
// converted again for each, on a request with attributes, which the resource carries too, or why
// expr isn't a condition.
func Evaluations(t *testing.T, expr string, attributes map[string]any, n int) ([]Decided, error) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	prg, err := c.build(expr)
	if err != nil {
		return nil, err
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	decided := make([]Decided, n)
	for i := range decided {
		vars := a.vars(WithRequest(t.Context(), attributes), Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
			Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes})
		r := evaluate(prg, vars)
		decided[i] = Decided{r.held, r.evaluated, r.cost}
	}
	return decided, nil
}

// EvaluateDeclared is EvaluateConditionOf under declares, the subject's attributes alone passed,
// and false where expr is no condition under them, which a change refuses to store.
func EvaluateDeclared(t *testing.T, declares Attributes, expr string, subject map[string]any) (held, evaluated, condition bool) {
	t.Helper()
	c, err := newConditions(declares)
	if err != nil {
		t.Fatal(err)
	}
	if c.check(expr) != nil {
		return false, false, false
	}
	prg, err := c.compile(expr)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now, Attributes: declares}, conds: c}
	vars := a.vars(t.Context(), Subject{Principal: Principal{Kind: User, ID: "u"}, Attributes: subject}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c"})
	r := evaluate(prg, vars)
	return r.held, r.evaluated, true
}

// MaxConverted is the most a check converts of what the host passes.
const MaxConverted = maxConverted

// MapCost, ListCost, PointerCost and MessageCost are what converting, or copying for a hook, each
// map, list, pointer and other message costs.
const MapCost, ListCost, PointerCost, MessageCost = mapCost, listCost, pointerCost, messageCost

// Work is what converting a kind's attributes, or copying them for a hook, charged, and the
// allocations and bytes it made, and whether it could: for converting, whether it read them.
type Work struct {
	Charged, Allocations, Bytes uint64
	Done                        bool
}

// ConvertingWork is the work converting attributes, as a check converts a kind's, does.
func ConvertingWork(attributes map[string]any) Work {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := newConverter()
	_, read := c.attributes(attributes)
	runtime.ReadMemStats(&after)
	return Work{maxConverted - c.left, after.Mallocs - before.Mallocs, after.TotalAlloc - before.TotalAlloc, read && !c.over}
}

// CopyingWork is the work copying attributes for a hook does.
func CopyingWork(attributes map[string]any) Work {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := copier{left: maxConverted}
	v := attributes
	c.copy(reflect.ValueOf(&v).Elem(), 0)
	runtime.ReadMemStats(&after)
	return Work{maxConverted - c.left, after.Mallocs - before.Mallocs, after.TotalAlloc - before.TotalAlloc, !c.over}
}

// ConvertingCharge is what converting attributes, as a check converts a kind's, charges, and
// whether it read them, as ConvertingWork has them, without counting allocations.
func ConvertingCharge(attributes map[string]any) (uint64, bool) {
	c := newConverter()
	_, read := c.attributes(attributes)
	return maxConverted - c.left, read && !c.over
}

// CopyingCharge is what copying attributes for a hook charges, and whether it could, as
// CopyingWork has them, without counting allocations.
func CopyingCharge(attributes map[string]any) (uint64, bool) {
	c := copier{left: maxConverted}
	v := attributes
	c.copy(reflect.ValueOf(&v).Elem(), 0)
	return maxConverted - c.left, !c.over
}

// Converting is what converting attributes as a check does allocates, and whether they were more
// than a check converts.
func Converting(t *testing.T, attributes map[string]any) (allocated uint64, over bool) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	c := newConverter()
	c.attributes(attributes)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, c.over
}

// ConvertedInOrder is whether a check converting kinds' attributes in the order given, by one
// converter, could read each, none declared, and whether they cost more than a check converts,
// which fails them all.
func ConvertedInOrder(t *testing.T, kinds ...map[string]any) (read []bool, over bool) {
	t.Helper()
	c := newConverter()
	for _, attributes := range kinds {
		converted, ok := c.attributes(attributes)
		_, refused := declared(nil, converted).(refusedAttributes)
		read = append(read, ok && !refused)
	}
	return read, c.over
}

// CollectBetweenKinds collects garbage before each kind's attributes are converted, until t ends,
// as any allocation converting makes may.
func CollectBetweenKinds(t *testing.T) {
	t.Helper()
	old := convertingKind
	convertingKind = runtime.GC
	t.Cleanup(func() { convertingKind = old })
}

// AttributesRead is what conditions read of the subject's, the resource's and the request's
// attributes, written out, in n checks of what a user may do to a cluster, the ith on check(i)'s
// context, carrying its request, by a subject and of a resource with check(i)'s attributes:
// together, the checks of one call, which share what it converted of a subject's and a request's
// (askingOf), and alone, each a call of its own, made first. Before each check of the call,
// between runs, where not nil, as a host's hook might.
func AttributesRead(t *testing.T, n int, check func(i int) (ctx context.Context, subject, resource map[string]any),
	between func(i int),
) (together, alone [][3]string) {
	t.Helper()
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	call := func() *Authorizer { return (&Authorizer{cfg: Config{Now: func() time.Time { return at }}}).still() }
	read := func(a *Authorizer, i int) [3]string {
		ctx, subject, resource := check(i)
		vars := a.vars(ctx, Subject{Principal: Principal{Kind: User, ID: "u"}, Attributes: subject}, "cluster:login",
			Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: resource})
		var out [3]string
		for j, kind := range []string{"subject", "resource", "request"} {
			out[j] = written(attributesOf(vars[kind]))
		}
		return out
	}
	for i := range n {
		alone = append(alone, read(call(), i))
	}
	a := call()
	for i := range n {
		if between != nil {
			between(i)
		}
		together = append(together, read(a, i))
	}
	return together, alone
}

// attributesOf is what a condition reads as v.attributes, where v is the subject, the resource or
// the request as vars has it.
func attributesOf(v any) any {
	if r, ok := v.(refusedAttributes); ok {
		attributes, _ := r.Find(types.String("attributes"))
		return attributes
	}
	m, _ := v.(map[string]any)
	return m["attributes"]
}

// Unreadable is how AttributesRead writes out attributes no condition reads.
const Unreadable = "unreadable"

// WithoutRequest is ctx carrying no request's attributes for conditions to read, as for an approver.
func WithoutRequest(ctx context.Context) context.Context { return withoutRequest(ctx) }

// written is v, a kind's attributes as conditions read them, written out, so that two are written
// alike where conditions read them alike: those no condition reads as such, and a map's entries
// sorted.
func written(v any) string {
	var b strings.Builder
	writeOut(&b, v)
	return b.String()
}

func writeOut(b *strings.Builder, v any) {
	switch v := v.(type) {
	case refusedAttributes:
		if v.all {
			b.WriteString(Unreadable)
			return
		}
		b.WriteString("refusing ")
		writeOut(b, v.Mapper)
	case traits.Mapper:
		var entries []string
		for it := v.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			entries = append(entries, written(k)+": "+written(v.Get(k)))
		}
		slices.Sort(entries)
		b.WriteString("{" + strings.Join(entries, ", ") + "}")
	case traits.Lister:
		n, _ := v.Size().(types.Int)
		b.WriteString("[")
		for i := range int(n) {
			if i > 0 {
				b.WriteString(", ")
			}
			writeOut(b, v.Get(types.Int(i)))
		}
		b.WriteString("]")
	case types.Int:
		b.WriteString("int " + strconv.FormatInt(int64(v), 10))
	case types.Double:
		b.WriteString("double " + strconv.FormatFloat(float64(v), 'g', -1, 64))
	case types.String:
		b.WriteString("string " + strconv.Quote(string(v)))
	case ref.Val:
		fmt.Fprintf(b, "%T %v", v, v.Value())
	default:
		fmt.Fprintf(b, "%T %v", v, v)
	}
}

// EvaluateConditionOn is what evaluating expr costs, on a request whose attributes are as given,
// none converted, as values no host can pass are, which a test reads a condition's work by, and
// whether it held and could be evaluated.
func EvaluateConditionOn(t *testing.T, expr string, attributes map[string]ref.Val) (held, evaluated bool, cost uint64) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	prg, err := c.build(expr)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(t.Context(), Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login", Resource{Tenant: "t", Type: "cluster", ID: "c"})
	given := map[ref.Val]ref.Val{}
	for k, v := range attributes {
		given[types.String(k)] = v
	}
	vars["request"] = map[string]any{"time": time.Now(), "attributes": types.NewRefValMap(types.DefaultTypeAdapter, given)}
	r := evaluate(prg, vars)
	return r.held, r.evaluated, r.cost
}

// compiled is expr as c compiles it, and the sizes of its patterns.
func compiled(t *testing.T, c *conditions, expr string) (*cel.Ast, map[string]uint64) {
	t.Helper()
	checked, iss := c.env.Compile(expr)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		t.Fatal(err)
	}
	return checked, patterns
}

// TrackedValues is what evaluating expr costs, on a request with attributes, which the resource
// carries too, as declares declares them, and how many values CEL's cost tracking holds at most as
// the evaluation reaches a uint literal, and how many times it does.
func TrackedValues(t *testing.T, declares Attributes, expr string, attributes map[string]any) (cost uint64, most, reached int) {
	t.Helper()
	c, err := newConditions(declares)
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	limit := worstCost(checked, patterns)
	p := &probing{}
	prg, err := plan(c.env, checked, patterns, limit, cel.CustomDecoratorV2(p.decorate))
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now, Attributes: declares}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes})
	return evaluate(program{Program: prg, limit: limit}, vars).cost, p.most, p.reached
}

// PlanLoopsOtherwise is why expr can't be planned as a condition where CEL plans each of its loops'
// conditions, or with ranges each of their ranges, as replan makes it, as another version of CEL
// may, or nil.
func PlanLoopsOtherwise(t *testing.T, expr string, ranges bool, replan func(interpreter.InterpretableV2) interpreter.InterpretableV2) error {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	replanned := map[int64]bool{}
	for cond, over := range newStepping(checked.NativeRep(), maxCost).ranges {
		replanned[cond], replanned[over] = !ranges, ranges
	}
	_, err = plan(c.env, checked, patterns, maxCost, cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if replanned[i.ID()] {
			return replan(i), nil
		}
		return i, nil
	}))
	return err
}

// PlanKeysOtherwise is why expr can't be planned as a condition where CEL plans each key it
// computes as replan makes it, as another version of CEL may, or nil.
func PlanKeysOtherwise(t *testing.T, expr string, replan func(interpreter.InterpretableV2) interpreter.InterpretableV2) error {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	keys := newKeying(c.env, checked.NativeRep(), maxCost).keys
	if len(keys) == 0 {
		t.Fatalf("%s computes no key", expr)
	}
	_, err = plan(c.env, checked, patterns, maxCost, cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if keys[i.ID()] {
			return replan(i), nil
		}
		return i, nil
	}))
	return err
}

// PlanLiteralsOtherwise is why expr can't be planned as a condition where CEL plans each list or map
// literal holding any as replan makes it, as another version of CEL may, or nil.
func PlanLiteralsOtherwise(t *testing.T, expr string, replan func(interpreter.InterpretableV2) interpreter.InterpretableV2) error {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	sizes := newLiterals(checked.NativeRep(), maxCost).sizes
	if len(sizes) == 0 {
		t.Fatalf("%s builds no literal", expr)
	}
	_, err = plan(c.env, checked, patterns, maxCost, cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if _, constructs := i.(interpreter.InterpretableConstructor); constructs && sizes[i.ID()] > 0 {
			return replan(i), nil
		}
		return i, nil
	}))
	return err
}

// PlanGuardedOtherwise is why expr can't be planned as a condition where CEL plans each comparison,
// search or match it refuses before it runs as replan makes it, as another version of CEL may, or
// nil.
func PlanGuardedOtherwise(t *testing.T, expr string, replan func(interpreter.InterpretableV2) interpreter.InterpretableV2) error {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	ids := newGuards(checked.NativeRep(), maxCost).ids
	if len(ids) == 0 {
		t.Fatalf("%s makes no call refused before it runs", expr)
	}
	_, err = plan(c.env, checked, patterns, maxCost, cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if ids[i.ID()] {
			return replan(i), nil
		}
		return i, nil
	}))
	return err
}

// PlanIn is why expr can't be planned as a condition in env, which may bind its functions as
// another version of CEL does, or nil.
func PlanIn(t *testing.T, env *cel.Env, expr string) error {
	t.Helper()
	checked, patterns := compiled(t, &conditions{env: env}, expr)
	_, err := plan(env, checked, patterns, maxCost)
	return err
}

// probing plans each uint literal as a probe, which evaluates and is charged as the literal, but
// which CEL's cost tracking reads as a call of an argument none of the values it holds is of, so
// it reads them all.
type probing struct{ read, most, reached int }

func (p *probing) decorate(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	if c, ok := i.(interpreter.InterpretableConst); ok {
		if _, isUint := c.Value().(types.Uint); isUint {
			return &probe{InterpretableV2: i, p: p}, nil
		}
	}
	return i, nil
}

type probe struct {
	interpreter.InterpretableV2
	p *probing
}

func (*probe) Function() string   { return "@probe" }
func (*probe) OverloadID() string { return "" }
func (r *probe) Args() []interpreter.InterpretableV2 {
	return []interpreter.InterpretableV2{unheld{r.p}}
}

func (r *probe) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	r.p.read = 0
	r.p.reached++
	return r.InterpretableV2.Exec(frame)
}

// unheld counts each value the tracking reads in search of it.
type unheld struct{ p *probing }

func (u unheld) ID() int64 {
	u.p.read++
	u.p.most = max(u.p.most, u.p.read)
	return -1
}

func (unheld) Eval(interpreter.Activation) ref.Val      { return types.NullValue }
func (unheld) Exec(*interpreter.ExecutionFrame) ref.Val { return types.NullValue }

// SetHoldingPlaces runs f as Activate begins holding the places in groups it can rest on, and what
// f returns once it holds them, until t ends.
func SetHoldingPlaces(t *testing.T, f func() func()) {
	t.Helper()
	old := holdingPlaces
	holdingPlaces = f
	t.Cleanup(func() { holdingPlaces = old })
}

// AsOfView is the query of AsOf's view of table, one of the package's in schema with columns, as
// byTime has AsOf and PruneHistory read history: what 0028_as_of_views makes it, for a test to hold
// the view to. A grant, an eligibility, a deny, a membership, a group or a place in one reads the
// columns history copies beside each version, as columns, by the table's column each copies.
func AsOfView(schema, table string, columns []string) string {
	entities := map[string]struct {
		entity string
		copied map[string]string
	}{
		"rbac_grants":        {"grant", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
		"rbac_roles":         {"role", map[string]string{"tenant": "tenant", "id": "key"}},
		"rbac_denies":        {"deny", map[string]string{"tenant": "tenant", "scope": "scope"}},
		"rbac_eligibilities": {"eligibility", map[string]string{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}},
		"rbac_memberships":   {"membership", map[string]string{"tenant": "tenant", "principal": "key"}},
		"rbac_groups":        {"group", map[string]string{"tenant": "tenant", "id": "key"}},
		"rbac_members":       {"member", map[string]string{"tenant": "tenant", "group_id": "group_id", "principal": "principal"}},
	}
	e, ok := entities[table]
	if !ok {
		return ""
	}
	s := pgx.Identifier{schema}.Sanitize()
	selected := make([]string, len(columns))
	for i, name := range columns {
		selected[i] = "r." + pgx.Identifier{name}.Sanitize()
		if h, ok := e.copied[name]; ok {
			selected[i] = "h." + h + " AS " + pgx.Identifier{name}.Sanitize()
		}
		if table == "rbac_denies" && name == "principals" {
			selected[i] = s + `.rbac_text_array(h.after -> 'principals') COLLATE "C" AS principals`
		}
		if name == "expires_at" {
			selected[i] = `CASE r.expires_at WHEN 'infinity' THEN NULL WHEN '-infinity' THEN pg_catalog.timestamptz 'epoch' ELSE r.expires_at END AS expires_at`
		}
	}
	at := `pg_catalog.to_timestamp(pg_catalog.current_setting('rbac.as_of'), '` + asOfTime + `')`
	tenant := `pg_catalog.current_setting('rbac.as_of_tenant')`
	history := s + ".rbac_history"
	b := byTime{history: history, at: at, cluster: `pg_catalog.current_setting('rbac.as_of_cluster')::pg_catalog.int8`}
	entity := "'" + e.entity + "'"
	from := ` h, LATERAL pg_catalog.jsonb_populate_record(NULL::` + s + `.` + pgx.Identifier{table}.Sanitize() + `, h.after) r`
	if e.entity == "role" {
		return `SELECT ` + strings.Join(selected, ", ") + ` FROM (SELECT DISTINCT ON (h.key) h.* FROM ` + history + ` h
			WHERE h.tenant = ` + tenant + ` AND h.entity = ` + entity + ` AND ` + b.counts("h") + `
			ORDER BY h.key, h.id DESC)` + from + `
			WHERE h.op NOT IN ('delete', 'expire')`
	}
	return `SELECT ` + strings.Join(selected, ", ") + ` FROM ` + history + from + `
		WHERE h.tenant = ` + tenant + ` AND h.entity = ` + entity + `
		  AND h.op NOT IN ('delete', 'expire') AND h.effective_at <= ` + at + `
		  AND ` + b.byAnother("h") + `
		  AND CASE WHEN ` + b.later("h", entity) + ` IS NOT NULL THEN false
		    ELSE ` + b.byCommit("h", "NOT "+b.writtenLater("h", entity), "c.at <= "+at) + ` END`
}
