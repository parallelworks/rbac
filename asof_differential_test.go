package rbac_test

import (
	"context"
	"errors"
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/parallelworks/rbac"
)

// What a worker's connection does next, as the schedule picks it.
type diffOp int

const (
	diffBegin diffOp = iota
	// A grant or revoke written around the package.
	diffWrite
	// A grant or revoke through Apply on the worker's transaction.
	diffApply
	diffSavepoint
	diffRollbackTo
	diffImmediate
	diffCommit
	diffRollback
	// A grant or revoke through Apply on the pool, which commits in the package's own transaction.
	diffPoolApply
)

type diffCmd struct {
	op      diffOp
	subject int
	grant   bool
	level   int
}

type diffResult struct {
	worker int
	cmd    diffCmd
	err    error
	// A commit's window by the database's clock: read before COMMIT is sent, and after it returns,
	// so the commit's record and the moment others see it both fall in it.
	start, end time.Time
}

type diffWorker struct {
	conn *pgx.Conn
	tx   pgx.Tx
	cmds chan diffCmd
}

// diffTx is a worker's transaction as the schedule models it: what it has done to each subject it
// wrote, and that at each savepoint.
type diffTx struct {
	open, failed bool
	now          map[int]bool
	saved        []diffSaved
	owned        map[int]bool
	// The step of its first write, and how many observations it was held open across.
	first, held int
	immediate   bool
}

type diffQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type diffSaved struct {
	now       map[int]bool
	immediate bool
}

type diffCommitted struct {
	start, end time.Time
	effects    map[int]bool
	first      int
	immediate  bool
}

type diffObservation struct {
	t0, t1  time.Time
	allowed []bool
}

// AsOf of a time answers as the checks made then did, while transactions overlap, hold open across
// checks, commit in another order than their statements ran, roll back to savepoints, set
// constraints immediate, and roll back. Each transaction's commit is bracketed by the database's
// clock, read before COMMIT is sent and after it returns, and each observation's checks by its
// clock before and after them, taken while no commit is under way: so every commit came wholly
// before or after an observation, and AsOf of its time reads what its checks read. Each subject's
// state is modeled too, from the commits that changed it, which never overlap as only one open
// transaction writes a subject at a time; AsOf of a microsecond before a commit began reads the
// subject as before it, its statements however long before, and AsOf of when the commit had
// returned reads it as after.
func TestAsOfAgreesWithChecksAsTransactionsOverlap(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	if s := os.Getenv("RBAC_DIFFERENTIAL_SEED"); s != "" {
		var err error
		if seed, err = strconv.ParseUint(s, 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("seed %d (RBAC_DIFFERENTIAL_SEED)", seed)
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	// The package's own transactions hold their commit a moment after their change, as a hook does.
	var hookMu sync.Mutex
	hookRNG := rand.New(rand.NewPCG(seed+1, seed))
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(ctx context.Context, _ pgx.Tx, _ rbac.ChangeEvent) error {
			hookMu.Lock()
			d := time.Duration(hookRNG.IntN(6)) * time.Millisecond
			hookMu.Unlock()
			select {
			case <-time.After(d):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	owner := h.as(t, "owner")
	const subjects, workers, steps = 6, 4, 220
	us := make([]rbac.Subject, subjects)
	initial := make([]bool, subjects)
	var seeded []rbac.Grant
	for i := range us {
		us[i] = h.as(t, "u"+strconv.Itoa(i))
		if initial[i] = rng.IntN(2) == 0; initial[i] {
			seeded = append(seeded, grant(cluster.Scope(), "cluster.login", rbac.User, us[i].Principal.ID))
		}
	}
	if len(seeded) > 0 {
		h.seed(t, seeded...)
	}
	seededAt := dbNow(t, h)
	change := func(u int, grant bool) rbac.Change {
		b := []rbac.Binding{{Role: "cluster.login", Principal: us[u].Principal}}
		if grant {
			return rbac.Change{Grant: b}
		}
		return rbac.Change{Revoke: b}
	}
	clock := func(q diffQuerier) (time.Time, error) {
		var at time.Time
		err := q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at)
		return at, err
	}

	results := make(chan diffResult, workers)
	ws := make([]*diffWorker, workers)
	var running sync.WaitGroup
	for i := range ws {
		conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(ctx)) })
		w := &diffWorker{conn: conn, cmds: make(chan diffCmd, 1)}
		ws[i] = w
		running.Go(func() {
			for {
				var c diffCmd
				select {
				case <-ctx.Done():
					return
				case cmd, ok := <-w.cmds:
					if !ok {
						return
					}
					c = cmd
				}
				r := diffResult{worker: i, cmd: c}
				switch c.op {
				case diffBegin:
					w.tx, r.err = w.conn.Begin(ctx)
				case diffWrite:
					if c.grant {
						_, r.err = w.tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
							VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login') ON CONFLICT DO NOTHING`, us[c.subject].Principal.ID)
					} else {
						_, r.err = w.tx.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = $1`,
							"user:"+us[c.subject].Principal.ID)
					}
				case diffApply:
					r.err = h.authz.WithTx(w.tx).Apply(ctx, owner, cluster, change(c.subject, c.grant))
				case diffSavepoint:
					_, r.err = w.tx.Exec(ctx, `SAVEPOINT s`+strconv.Itoa(c.level))
				case diffRollbackTo:
					_, r.err = w.tx.Exec(ctx, `ROLLBACK TO SAVEPOINT s`+strconv.Itoa(c.level))
				case diffImmediate:
					_, r.err = w.tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
				case diffCommit:
					if r.start, r.err = clock(w.tx); r.err == nil {
						if r.err = w.tx.Commit(ctx); r.err == nil {
							r.end, r.err = clock(w.conn)
						}
					}
					if r.err != nil {
						_ = w.tx.Rollback(ctx)
					}
					w.tx = nil
				case diffRollback:
					r.err = w.tx.Rollback(ctx)
					w.tx = nil
				case diffPoolApply:
					if r.start, r.err = clock(h.pool); r.err == nil {
						if r.err = h.authz.Apply(ctx, owner, cluster, change(c.subject, c.grant)); r.err == nil {
							r.end, r.err = clock(h.pool)
						}
					}
				}
				// Each worker has at most one command outstanding, so this never waits.
				results <- r
			}
		})
	}
	defer func() {
		for _, w := range ws {
			close(w.cmds)
		}
		running.Wait()
	}()

	owners := slices.Repeat([]int{-1}, subjects)
	busy := make([]bool, workers)
	txs := make([]diffTx, workers)
	inCommit := 0
	var commits []diffCommitted
	var observations []diffObservation
	stats := map[string]int{}
	step := 0
	release := func(w int) {
		for u := range txs[w].owned {
			owners[u] = -1
		}
		txs[w] = diffTx{}
	}
	handle := func(r diffResult) {
		w, c, tx := r.worker, r.cmd, &txs[r.worker]
		busy[w] = false
		if r.err != nil {
			var pgErr *pgconn.PgError
			code := "other"
			if errors.As(r.err, &pgErr) {
				code = pgErr.Code
			}
			stats["error "+code]++
			if code == "other" {
				t.Logf("%v: %v", c, r.err)
			}
		}
		switch c.op {
		case diffBegin:
			if r.err != nil {
				t.Errorf("begin: %v", r.err)
				return
			}
			*tx = diffTx{open: true, now: map[int]bool{}, owned: map[int]bool{}, first: -1}
		case diffWrite, diffApply:
			if r.err != nil {
				tx.failed = true
				return
			}
			tx.now[c.subject] = c.grant
		case diffSavepoint:
			if r.err != nil {
				tx.failed = true
				return
			}
			tx.saved = append(tx.saved, diffSaved{maps.Clone(tx.now), tx.immediate})
		case diffRollbackTo:
			if r.err != nil {
				t.Errorf("roll back to a savepoint: %v", r.err)
				tx.failed, tx.saved = true, nil
				return
			}
			tx.now, tx.immediate = maps.Clone(tx.saved[c.level].now), tx.saved[c.level].immediate
			tx.saved, tx.failed = tx.saved[:c.level+1], false
			stats["rolled back to a savepoint"]++
		case diffImmediate:
			if r.err != nil {
				tx.failed = true
				return
			}
			tx.immediate = true
		case diffCommit:
			inCommit--
			if r.err == nil {
				commits = append(commits, diffCommitted{start: r.start, end: r.end, effects: tx.now, first: tx.first, immediate: tx.immediate})
				stats["committed"]++
				if tx.held > 0 && len(tx.now) > 0 {
					stats["committed after being held across an observation"]++
				}
				if tx.immediate && len(tx.now) > 0 {
					stats["committed having set constraints immediate"]++
				}
			}
			release(w)
		case diffRollback:
			stats["rolled back"]++
			release(w)
		case diffPoolApply:
			inCommit--
			owners[c.subject] = -1
			if r.err == nil {
				commits = append(commits, diffCommitted{start: r.start, end: r.end, effects: map[int]bool{c.subject: c.grant}, first: step})
				stats["committed by the package"]++
			}
		}
	}
	wait := func() {
		select {
		case r := <-results:
			handle(r)
		case <-ctx.Done():
			t.Fatalf("waiting for a worker: %v", ctx.Err())
		}
	}
	drain := func() {
		for {
			select {
			case r := <-results:
				handle(r)
			default:
				return
			}
		}
	}
	issue := func(w int, c diffCmd) {
		busy[w] = true
		switch c.op {
		case diffWrite, diffApply:
			owners[c.subject] = w
			txs[w].owned[c.subject] = true
			if txs[w].first < 0 {
				txs[w].first = step
			}
		case diffPoolApply:
			owners[c.subject] = w
			inCommit++
		case diffCommit:
			inCommit++
		case diffBegin, diffSavepoint, diffRollbackTo, diffImmediate, diffRollback:
		}
		ws[w].cmds <- c
	}
	// A subject no other open transaction has written.
	free := func(w int) (int, bool) {
		var candidates []int
		for u, o := range owners {
			if o == -1 || o == w && txs[w].open {
				candidates = append(candidates, u)
			}
		}
		if len(candidates) == 0 {
			return 0, false
		}
		return candidates[rng.IntN(len(candidates))], true
	}
	// After a statement fails, a savepoint taken before it is rolled back to, or the transaction.
	recovery := func(w int) diffCmd {
		if n := len(txs[w].saved); n > 0 {
			return diffCmd{op: diffRollbackTo, level: n - 1}
		}
		return diffCmd{op: diffRollback}
	}
	choose := func(w int) (diffCmd, bool) {
		tx := &txs[w]
		if !tx.open {
			if rng.IntN(4) == 0 {
				u, ok := free(w)
				return diffCmd{op: diffPoolApply, subject: u, grant: rng.IntN(2) == 0}, ok
			}
			return diffCmd{op: diffBegin}, true
		}
		if tx.failed {
			return recovery(w), true
		}
		switch n := rng.IntN(100); {
		case n < 35:
			u, ok := free(w)
			return diffCmd{op: diffWrite, subject: u, grant: rng.IntN(2) == 0}, ok
		case n < 50:
			u, ok := free(w)
			return diffCmd{op: diffApply, subject: u, grant: rng.IntN(2) == 0}, ok
		case n < 60:
			return diffCmd{op: diffSavepoint, level: len(tx.saved)}, true
		case n < 70:
			if len(tx.saved) == 0 {
				return diffCmd{}, false
			}
			return diffCmd{op: diffRollbackTo, level: rng.IntN(len(tx.saved))}, true
		case n < 76:
			return diffCmd{op: diffImmediate}, true
		case n < 94:
			return diffCmd{op: diffCommit}, true
		default:
			return diffCmd{op: diffRollback}, true
		}
	}
	pause := func() {
		select {
		case <-time.After(time.Duration(rng.IntN(8)) * time.Millisecond):
		case <-ctx.Done():
		}
	}
	// The checks of every subject, between two readings of the database's clock, while no commit is
	// under way: blocked statements may wait meanwhile, but none commits.
	observe := func() {
		o := diffObservation{allowed: make([]bool, subjects)}
		var err error
		if o.t0, err = clock(h.pool); err != nil {
			t.Fatal(err)
		}
		for i, s := range us {
			err := h.authz.Authorize(ctx, s, login, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				t.Fatal(err)
			}
			o.allowed[i] = err == nil
		}
		if o.t1, err = clock(h.pool); err != nil {
			t.Fatal(err)
		}
		observations = append(observations, o)
		for w := range txs {
			if txs[w].open && len(txs[w].now) > 0 {
				txs[w].held++
			}
		}
	}

	for ; step < steps; step++ {
		drain()
		if inCommit == 0 && rng.IntN(5) == 0 {
			observe()
			pause()
			continue
		}
		var idle []int
		for w := range busy {
			if !busy[w] {
				idle = append(idle, w)
			}
		}
		if len(idle) == 0 {
			wait()
			continue
		}
		w := idle[rng.IntN(len(idle))]
		if c, ok := choose(w); ok {
			issue(w, c)
		}
		pause()
	}
	// Every transaction ends, those blocked once those they wait for do.
	for {
		drain()
		pending := false
		for w := range busy {
			pending = pending || busy[w] || txs[w].open
		}
		if !pending {
			break
		}
		issued := false
		for w := range busy {
			if busy[w] || !txs[w].open {
				continue
			}
			c := diffCmd{op: diffCommit}
			if txs[w].failed {
				c = recovery(w)
			} else if rng.IntN(5) == 0 {
				c = diffCmd{op: diffRollback}
			}
			issue(w, c)
			issued = true
		}
		if !issued {
			wait()
		}
	}
	slices.SortFunc(commits, func(a, b diffCommitted) int { return a.start.Compare(b.start) })
	for i, c := range commits {
		if slices.ContainsFunc(commits[:i], func(d diffCommitted) bool { return d.first > c.first }) {
			stats["committed before one whose statements ran earlier"]++
		}
	}
	t.Logf("%d observations, %v", len(observations), stats)

	// A subject's state at a time, by the commits that changed it, or none where one of them was
	// under way then.
	expected := func(u int, at time.Time) (state, ok bool) {
		state = initial[u]
		for _, c := range commits {
			effect, changed := c.effects[u]
			switch {
			case !changed:
			case !at.After(c.start):
				return state, true
			case at.Before(c.end):
				return false, false
			default:
				state = effect
			}
		}
		return state, true
	}
	// Each subject's commits never overlap, as one open transaction at a time writes it.
	for u := range subjects {
		var last time.Time
		for _, c := range commits {
			if _, changed := c.effects[u]; changed {
				if c.start.Before(last) {
					t.Fatalf("u%d's commits overlap: one began at %v before another ended at %v", u, c.start, last)
				}
				last = c.end
			}
		}
	}
	asOf := func(at time.Time) []bool {
		allowed := make([]bool, subjects)
		if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			for i, s := range us {
				err := a.Authorize(ctx, s, login, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				allowed[i] = err == nil
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return allowed
	}
	for _, o := range observations {
		for _, c := range commits {
			if !c.end.Before(o.t0) && !c.start.After(o.t1) {
				t.Fatalf("a commit from %v to %v overlaps an observation from %v to %v", c.start, c.end, o.t0, o.t1)
			}
		}
		got := asOf(o.t0)
		for u := range subjects {
			if got[u] != o.allowed[u] {
				t.Errorf("as of %v, u%d's login is %t, where the checks from then to %v read %t", o.t0, u, got[u], o.t1, o.allowed[u])
			}
			if want, ok := expected(u, o.t0); !ok || want != o.allowed[u] {
				t.Errorf("the model of u%d at %v is %t (%t), where the checks read %t", u, o.t0, want, ok, o.allowed[u])
			}
		}
	}
	// A microsecond before each commit began, after every statement it made, and as it had
	// returned.
	times := []time.Time{seededAt}
	for _, c := range commits {
		times = append(times, c.start.Add(-time.Microsecond), c.end)
	}
	checked := 0
	for _, at := range times {
		got := asOf(at)
		for u := range subjects {
			if want, ok := expected(u, at); ok {
				checked++
				if got[u] != want {
					t.Errorf("as of %v, u%d's login is %t, where its commits make it %t", at, u, got[u], want)
				}
			}
		}
	}
	t.Logf("%d commits, %d checks as of their edges", len(commits), checked)
}
