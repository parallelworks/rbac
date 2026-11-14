package rbac_test

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// dbNow is the database's clock, which history dates changes by.
func dbNow(t *testing.T, h *harness) time.Time {
	t.Helper()
	var now time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now
}

// committedAt is when the transaction that wrote the record where finds committed, as its commit
// record says, which AsOf counts its changes from.
func committedAt(t *testing.T, h *harness, where string) time.Time {
	t.Helper()
	var at time.Time
	if err := h.pool.QueryRow(t.Context(), `SELECT max(c.effective_at) FROM rbac_history c
		WHERE c.entity = 'commit' AND c.txid = (SELECT txid FROM rbac_history WHERE `+where+`)`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

func TestAsOfReadsATenantAsItWas(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	u, v := h.as(t, "u", "sre"), h.as(t, "v")
	h.groups(t, "sre")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"))
	// x's login expires between the two times. Then is when its grant's transaction committed,
	// which AsOf counts the grant from, and its expiry is 200 ms after its statement began.
	x := h.as(t, "x")
	var expires time.Time
	if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', statement_timestamp() + interval '200 milliseconds')
		RETURNING expires_at`).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	then := committedAt(t, h, `entity = 'grant' AND principal = 'user:x'`)
	if !then.Before(expires) {
		t.Fatalf("x's grant committed at %v, once it had expired at %v", then, expires)
	}
	// Since: u left sre, a deny took login from u, and v was granted login.
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_members WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "v"))
	// Until x's login expires by the database's clock, which dates it, not this machine's.
	if _, err := h.pool.Exec(ctx, `SELECT pg_sleep(extract(epoch FROM $1 - clock_timestamp()))`, expires); err != nil {
		t.Fatal(err)
	}
	now := dbNow(t, h)
	for _, c := range []struct {
		name        string
		at          time.Time
		uRoot       bool
		uLogin      bool
		vLogin      bool
		xLogin      bool
		loginHeldBy []rbac.Principal
	}{
		{"then", then, true, true, false, true, []rbac.Principal{u.Principal, x.Principal}},
		{"now", now, false, false, true, false, []rbac.Principal{v.Principal}},
	} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for _, check := range []struct {
				s    rbac.Subject
				p    rbac.Permission
				want bool
			}{{u, root, c.uRoot}, {u, login, c.uLogin}, {v, login, c.vLogin}, {x, login, c.xLogin}} {
				err := a.Authorize(ctx, check.s, check.p, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != check.want {
					t.Errorf("%s: Authorize(%s, %s) = %v", c.name, check.s.Principal.ID, check.p, err)
				}
			}
			d, err := a.Explain(ctx, u, login, cluster)
			if err != nil || d.Allowed != c.uLogin || (d.DeniedBy != "") == c.uLogin {
				t.Errorf("%s: Explain = %+v, %v", c.name, d, err)
			}
			holders, err := a.Holders(ctx, login, cluster)
			if err != nil || !slices.Equal(holderPrincipals(holders), c.loginHeldBy) {
				t.Errorf("%s: Holders = %+v, %v", c.name, holders, err)
			}
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
}

func TestAsOfChangesNothing(t *testing.T) {
	asked := 0
	h := setup(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			asked++
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "later"))
	asked = 0
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if err := a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "u"}}}}); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply as of a time: %v", err)
		}
		if asked != 0 {
			t.Errorf("the host was asked about a change as of a time %d times", asked)
		}
		if _, err := a.DeleteExpired(ctx); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteExpired as of a time: %v", err)
		}
		// On another transaction it still reads the past, not the grant made since.
		other, err := h.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = other.Rollback(ctx) }()
		if got, err := a.WithTx(other).Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "later"}}}); err != nil || len(got) != 0 {
			t.Errorf("Grants on another transaction = %+v, %v", got, err)
		}
		if err := a.AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf as of a time: %v", err)
		}
		// History is a read, which changes nothing.
		if _, _, err := a.History(ctx, rbac.Cursor{}, 1); err != nil {
			t.Errorf("History as of a time: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
	if err := h.authz.AsOf(ctx, "", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("AsOf with no tenant: %v", err)
	}
}

// AsOf refuses a nil read, as it has nothing to run, rather than fail in its transaction.
func TestAsOfRefusesNoRead(t *testing.T) {
	h := setup(t)
	if err := h.authz.AsOf(t.Context(), "t1", dbNow(t, h), nil); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("AsOf with a nil read: %v", err)
	}
}

// AsOf on a host's DB that has no BeginTx reads the past at REPEATABLE READ, as on a pool, so a
// read of several statements reads one snapshot; on a wrapper around the host's transaction, at
// that transaction's isolation, as under WithTx.
func TestAsOfOnAWrapperReadsOneSnapshot(t *testing.T) {
	var level string
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "level", Deny: func(ctx context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			return false, q.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level)
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, c := range []struct {
		name string
		db   rbac.DB
		want string
	}{{"a pool", h.pool, "repeatable read"}, {"the host's transaction", tx, "read committed"}} {
		a, err := rbac.New(struct{ rbac.DB }{c.db}, h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		level = ""
		if err := a.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, owner, login, cluster) }); err != nil {
			t.Fatalf("on a wrapper around %s: %v", c.name, err)
		}
		if level != c.want {
			t.Errorf("on a wrapper around %s, AsOf read at %q, not %q", c.name, level, c.want)
		}
	}
}

func TestAsOfLeavesTheHostsTransactionAsItWas(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL plan_cache_mode = force_generic_plan`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		_, err := a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The views are gone with its savepoint, and the host plans as it did: the host's transaction
	// reads the tables again.
	var name, plans string
	if err := tx.QueryRow(ctx, `SELECT 'rbac_grants'::regclass::text, current_setting('plan_cache_mode')`).Scan(&name, &plans); err != nil ||
		name != "rbac_grants" || plans != "force_generic_plan" {
		t.Fatalf("rbac_grants is %q, plan_cache_mode %q, %v", name, plans, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
}

// Planned for their arguments over history's views, statements as of a time cost past
// jit_above_cost though they read little, and compiling one takes far longer than running it: a
// read as of a time runs without JIT, and leaves the host its own setting, on its own transaction
// and under WithTx, whether read returns, fails or panics.
func TestAsOfReadsWithoutJIT(t *testing.T) {
	var seen []string
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=2&jit=on"), func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "jit", Deny: func(ctx context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			var jit string
			err := q.QueryRow(ctx, `SELECT current_setting('jit')`).Scan(&jit)
			seen = append(seen, jit)
			return false, err
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	failed := errors.New("read failed")
	for _, onHosts := range []bool{false, true} {
		for _, end := range []string{"returns", "fails", "panics"} {
			func() {
				q, a := rbac.DB(h.pool), h.authz
				if onHosts {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
					if _, err := tx.Exec(ctx, `SET LOCAL jit = on`); err != nil {
						t.Fatal(err)
					}
					q, a = tx, h.authz.WithTx(tx)
				}
				seen = nil
				func() {
					defer func() { _ = recover() }()
					err := a.AsOf(ctx, "t1", at, func(b *rbac.Authorizer) error {
						if err := b.Authorize(ctx, owner, login, cluster); err != nil {
							return err
						}
						switch end {
						case "fails":
							return failed
						case "panics":
							panic(failed)
						}
						return nil
					})
					if want := map[string]error{"returns": nil, "fails": failed}[end]; !errors.Is(err, want) {
						t.Errorf("on the host's transaction %t, a read that %s: %v", onHosts, end, err)
					}
				}()
				if !slices.Equal(seen, []string{"off"}) {
					t.Errorf("on the host's transaction %t, a read that %s: jit as of a time %v", onHosts, end, seen)
				}
				var jit string
				if err := q.QueryRow(ctx, `SELECT current_setting('jit')`).Scan(&jit); err != nil || jit != "on" {
					t.Errorf("on the host's transaction %t, after a read that %s: jit %q, %v", onHosts, end, jit, err)
				}
			}()
		}
	}
}

// pgx sends a time in microseconds from 2000 in 64 bits, which wrap: 2^64 microseconds after a
// time reaches PostgreSQL as that time, and one past PostgreSQL's times as one it refuses as out of
// range. AsOf refuses one past the last the package stores, or before PostgreSQL's earliest, and
// reads those between, each as pgx sends it, to the microsecond, rounded down: the last
// microsecond's every nanosecond is the last time, which it read as one past it.
func TestAsOfRefusesATimePastThoseItReads(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	held := dbNow(t, h)
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	read := func(at time.Time) error {
		return h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if err := a.Authorize(ctx, u, login, cluster); err == nil {
				t.Errorf("as of %v, u holds what it held at %v alone", at, held)
			}
			return nil
		})
	}
	earliest := time.Date(-4713, time.November, 24, 0, 0, 0, 0, time.UTC)
	latest := time.Date(9999, time.December, 30, 23, 59, 59, 999999000, time.UTC)
	past := []time.Time{
		wrapped(held, 1), time.Date(300000, time.January, 1, 0, 0, 0, 0, time.UTC), latest.Add(time.Microsecond),
		earliest.Add(-time.Microsecond), earliest.Add(-time.Nanosecond),
	}
	for _, at := range past {
		if err := read(at); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("as of %v: %v", at, err)
		}
	}
	for _, at := range []time.Time{earliest, earliest.Add(999 * time.Nanosecond), latest, latest.Add(999 * time.Nanosecond)} {
		if err := read(at); err != nil {
			t.Errorf("as of %v: %v", at, err)
		}
	}
}

func TestAsOfRefusesASearchPathThatReadsTheTablesFirst(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('search_path', current_schema() || ', pg_temp', true)`); err != nil {
			return err
		}
		err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil })
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf with pg_temp after the package's schema: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// AsOf and a prune, which keeps each row's last version by its id, refuse ids a cache can take out
// of order.
func TestAsOfRefusesCachedHistoryIds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	through := exported(t, h)
	if _, err := h.pool.Exec(ctx, `ALTER TABLE rbac_history ALTER COLUMN id SET CACHE 2`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("AsOf with history's ids cached: %v", err)
	}
	if _, err := rbac.PruneHistory(ctx, h.pool, dbNow(t, h), through); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("PruneHistory with history's ids cached: %v", err)
	}
}

func TestAsOfRollsBackOnceItsContextIsDone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The read ends as its context does, before AsOf rolls back its savepoint.
	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := h.authz.WithTx(tx).AsOf(readCtx, "t1", at, func(*rbac.Authorizer) error {
		cancel()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := h.authz.WithTx(tx).Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}}); err != nil || len(got) != 0 {
		t.Errorf("after AsOf, the host's transaction reads u's grants as %+v, %v", got, err)
	}
}

// stalled is a pool whose transactions' rollbacks wait until their context is done, or the
// test's, as on a connection that has stopped answering.
type stalled struct {
	*pgxpool.Pool
	test context.Context
}

func (s stalled) BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
	tx, err := s.Pool.BeginTx(ctx, opts)
	return stalledTx{tx, s.test}, err
}

type stalledTx struct {
	pgx.Tx
	test context.Context
}

func (s stalledTx) Rollback(ctx context.Context) error {
	select {
	case <-ctx.Done():
	case <-s.test.Done():
	}
	_ = s.Tx.Rollback(context.WithoutCancel(ctx))
	return ctx.Err()
}

// AsOf's rollback is bounded, as a savepoint's end is, so a connection that stops answering fails
// it rather than holding it for good.
func TestAsOfEndsOnAConnectionThatStopsAnswering(t *testing.T) {
	rbac.SetSavepointEnd(t, 100*time.Millisecond)
	h := setup(t)
	authz, err := rbac.New(stalled{h.pool, t.Context()}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	at := dbNow(t, h)
	done := make(chan error, 1)
	go func() { done <- authz.AsOf(t.Context(), "t1", at, func(*rbac.Authorizer) error { return nil }) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("AsOf on a connection that stops answering: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AsOf waited for good on a rollback its connection never answers")
	}
}

func TestAsOfRebuildsEveryTableAsItIs(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	h.as(t, "u", "sre")
	h.as(t, "v", "devs")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(workspace.Scope(), "cluster.login", rbac.Group, "devs"))
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at, condition, note)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.login', now() + interval '1 day', 'request.time > timestamp("2020-01-01T00:00:00Z")', 'n')`,
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles) VALUES ('t1', 'custom.x', '{cluster:view}', '{cluster}', '{cluster.login}')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.sudo', 3600, '{user:u}')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, source, expires_at) VALUES ('t1', 'devs', 'group', 'sre', 'sync', now() + interval '1 hour')`,
		`UPDATE rbac_memberships SET suspended = true, note = 'x' WHERE principal = 'user:v'`,
		`DELETE FROM rbac_grants WHERE principal = 'user:u'`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t2', 'user', 'u')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t2', 'cluster', 'c1', 'user', 'u', 'cluster.login')`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.User, ID: "v"}}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	rebuilt(t, h, dbNow(t, h))
}

// rebuilt checks that AsOf as of at reads each of the package's tables as t1's rows of it are now,
// but the times DeleteExpired deleted by, which no tenant has and AsOf doesn't read.
func rebuilt(t *testing.T, h *harness, at time.Time) {
	t.Helper()
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT quote_ident(current_schema()), relname::text FROM pg_class
		WHERE relnamespace = current_schema()::regnamespace AND relkind = 'r' AND relname NOT IN ('rbac_history', 'rbac_migrations', 'rbac_expired') ORDER BY 2`)
	if err != nil {
		t.Fatal(err)
	}
	type table struct{ Schema, Name string }
	tables, err := pgx.CollectRows(rows, pgx.RowToStructByPos[table])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error {
		for _, tb := range tables {
			// The tenant's rows, each whole, generated columns included, in columns of the table's
			// names, types and collations, in its order, of the view the read names it by, not the
			// table.
			var missing, extra, columns int
			if err := tx.QueryRow(ctx, `SELECT
				  (SELECT count(*) FROM (SELECT * FROM `+tb.Schema+`.`+tb.Name+` WHERE tenant = 't1' EXCEPT ALL SELECT * FROM `+tb.Name+`) x),
				  (SELECT count(*) FROM (SELECT * FROM `+tb.Name+` EXCEPT ALL SELECT * FROM `+tb.Schema+`.`+tb.Name+` WHERE tenant = 't1') x),
				  (SELECT count(*) FROM (
				    SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped
				    EXCEPT SELECT attnum, attname, atttypid, atttypmod, attcollation FROM pg_attribute
				      WHERE attrelid = (SELECT c.oid FROM pg_class c WHERE c.oid = to_regclass($2) AND c.relkind = 'v')) x)`,
				tb.Schema+"."+tb.Name, tb.Name).Scan(&missing, &extra, &columns); err != nil {
				return err
			}
			if missing != 0 || extra != 0 || columns != 0 {
				t.Errorf("%s as of %v: %d rows missing, %d extra, %d columns differ", tb.Name, at, missing, extra, columns)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAsOfOrdersARowsChangesAsTheyWereMade(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "m")
	// Each transaction begins before another's change, which it then undoes: one revokes a grant
	// made after it began, and one makes again a membership ended after it began.
	var txs []pgx.Tx
	for range 2 {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		txs = append(txs, tx)
	}
	revoke, rejoin := txs[0], txs[1]
	var id string
	if err := h.pool.QueryRow(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'w', 'cluster.login') RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := revoke.Exec(ctx, `DELETE FROM rbac_grants WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_memberships WHERE principal = 'user:m'`); err != nil {
		t.Fatal(err)
	}
	if _, err := rejoin.Exec(ctx, `INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'm')`); err != nil {
		t.Fatal(err)
	}
	for _, tx := range txs {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "w"}}})
		if err != nil || len(grants) != 0 {
			t.Errorf("as of now, w holds %+v, %v", grants, err)
		}
		ms, err := a.Memberships(ctx, "t1", []rbac.Principal{{Kind: rbac.User, ID: "m"}})
		if err != nil || len(ms) != 1 {
			t.Errorf("as of now, m's memberships are %+v, %v", ms, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A change counts from its statement, not its transaction's start: a revoke made in a host's
// transaction that began before the grant counts from after it, so the grant was held between.
func TestAsOfReadsARevokeInAnOlderTransactionAfterItsGrant(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), rbac.Principal{Kind: rbac.User, ID: "u"}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	h.seed(t, grant(cluster.Scope(), "cluster.login", u.Kind, u.ID))
	time.Sleep(20 * time.Millisecond)
	between := dbNow(t, h)
	time.Sleep(20 * time.Millisecond)
	if err := h.authz.WithTx(tx).Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u}}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]int{between: 1, dbNow(t, h): 0} {
		if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u}})
			if err == nil && len(grants) != want {
				t.Errorf("as of %v, u holds %+v, want %d", at, grants, want)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// RecordedAt is when each was written: the revoke's after the grant's.
	rows, err := h.pool.Query(ctx, `SELECT recorded_at FROM rbac_history WHERE principal = 'user:u' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	written, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil || len(written) != 2 || !written[0].Before(written[1]) {
		t.Fatalf("written at %v, %v", written, err)
	}
}

// A procedure or a DO block that commits as it goes starts a transaction with each COMMIT: what each
// changes counts from when it commits, not the block's start, so as of a moment while the first ran,
// its own grant reads as yet to come, and a revoke and a move of a later one too. A delete is an
// expiry, and a row an update moves ended with its expiry, where the row had expired by when the
// change took effect.
func TestAsOfCountsAChangeInABlockThatCommitsFromItsOwnTransaction(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, v := h.as(t, "u"), h.as(t, "v")
	w, x := identity("w"), identity("x")
	h.as(t, w.ID)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	// The block's first transaction gives v a login and y a membership, both ending 100 ms after it
	// began, and runs 200 ms. Its second revokes u's login, moves w's membership to x and y's to z,
	// and deletes v's login as DeleteExpired does.
	if _, err := h.pool.Exec(ctx, `DO $$ BEGIN
		INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.login', statement_timestamp() + interval '100 milliseconds');
		INSERT INTO rbac_memberships (tenant, principal_kind, principal_id, expires_at)
		  VALUES ('t1', 'user', 'y', statement_timestamp() + interval '100 milliseconds');
		PERFORM pg_sleep(0.2);
		COMMIT;
		DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u';
		UPDATE rbac_memberships SET principal_id = 'x' WHERE tenant = 't1' AND principal = 'user:w';
		UPDATE rbac_memberships SET principal_id = 'z' WHERE tenant = 't1' AND principal = 'user:y';
		PERFORM set_config('rbac.change', '{"op": "expire"}', true);
		DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:v';
	END $$`, pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	// v's login is dated by when the block began.
	var began time.Time
	if err := h.pool.QueryRow(ctx, `SELECT effective_at FROM rbac_history WHERE principal = 'user:v' AND op = 'create'`).Scan(&began); err != nil {
		t.Fatal(err)
	}
	during := began.Add(50 * time.Millisecond)
	if err := h.authz.AsOf(ctx, "t1", during, func(a *rbac.Authorizer) error {
		for _, c := range []struct {
			s    rbac.Subject
			held bool
		}{{u, true}, {v, false}} {
			err := a.Authorize(ctx, c.s, login, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				return err
			}
			if (err == nil) != c.held {
				t.Errorf("as of %v, while the block's first transaction ran, %s's login: %v", during, c.s.Principal.ID, err)
			}
		}
		ms, err := a.Memberships(ctx, "t1", []rbac.Principal{w, x})
		if err != nil {
			return err
		}
		if len(ms) != 1 || ms[0].Principal != w {
			t.Errorf("as of %v, while the block's first transaction ran, w and x are members by %+v", during, ms)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, `SELECT principal || ' ' || op FROM rbac_history
		WHERE principal IN ('user:v', 'user:y') AND op IN ('delete', 'expire') ORDER BY principal`)
	if err != nil {
		t.Fatal(err)
	}
	ends, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || !slices.Equal(ends, []string{"user:v expire", "user:y expire"}) {
		t.Errorf("v's login and y's membership ended by %q, %v", ends, err)
	}
}

// A statement reads a row by the columns history copies beside its versions, but only its last
// version counts: a grant moved to another principal and scope, in place, as by hand, is the new
// one's from then on, not the old one's too.
func TestAsOfReadsARowChangedInPlaceAsItsLastVersion(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, v := h.as(t, "u"), h.as(t, "v")
	h.seed(t, grant(workspace.Scope(), "cluster.login", rbac.User, "u"))
	before := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET principal_id = 'v', scope_type = 'cluster', scope_id = 'c1'
		WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	after := dbNow(t, h)
	for _, c := range []struct {
		at               time.Time
		holder, other    rbac.Subject
		scope, elsewhere rbac.Scope
	}{{before, u, v, workspace.Scope(), cluster.Scope()}, {after, v, u, cluster.Scope(), workspace.Scope()}} {
		if err := h.authz.AsOf(ctx, "t1", c.at, func(a *rbac.Authorizer) error {
			for _, f := range []struct {
				filter rbac.GrantFilter
				held   bool
			}{
				{rbac.GrantFilter{Principals: []rbac.Principal{c.holder.Principal}}, true},
				{rbac.GrantFilter{Principals: []rbac.Principal{c.other.Principal}}, false},
				{rbac.GrantFilter{Scopes: []rbac.Scope{c.scope}}, true},
				{rbac.GrantFilter{Scopes: []rbac.Scope{c.elsewhere}}, false},
			} {
				grants, err := a.Grants(ctx, "t1", f.filter)
				if err != nil {
					return err
				}
				if held := slices.ContainsFunc(grants, func(g rbac.Grant) bool { return g.Role == "cluster.login" }); held != f.held {
					t.Errorf("as of %v, Grants(%+v) = %+v", c.at, f.filter, grants)
				}
			}
			for _, s := range []rbac.Subject{c.holder, c.other} {
				err := a.Authorize(ctx, s, login, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != (s.Principal == c.holder.Principal) {
					t.Errorf("as of %v, Authorize(%s) = %v", c.at, s.Principal.ID, err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// As of a time, a check, Permissions and Grantable seek their subject's grants on the resource's
// path, however their statements are planned, beside thousands of its grants elsewhere, as one on
// each cluster it created: history's index of a principal's versions held no scope, so in a history
// of many tenants a plan read every version of the subject's grants to find the few on the path.
func TestAsOfChecksSeekTheirSubjectsGrantsOnThePath(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	granted := 0
	more := func(n int) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', 'k' || i, 'user', 'u', 'cluster.login' FROM generate_series($1::int + 1, $2::int) i`, granted, n); err != nil {
			t.Fatal(err)
		}
		granted = n
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_grants, rbac_history`); err != nil {
			t.Fatal(err)
		}
	}
	read := func(at time.Time, plans string) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
				return err
			}
			for what, f := range map[string]func() error{
				"Authorize":   func() error { return a.Authorize(ctx, u, login, cluster) },
				"Permissions": func() error { return second(a.Permissions(ctx, u, cluster)) },
				"Grantable":   func() error { return second(a.Grantable(ctx, u, cluster)) },
			} {
				// Once before, as the calls share statements, which the first to run plans: planning
				// reads the metapage of each empty index of history for each time a statement names
				// it, which a later call, as each call in a map's random order can be, doesn't. Then
				// the least a run reads, as runs planned again do (leastPages).
				if err := f(); err != nil {
					return fmt.Errorf("%s: %w", what, err)
				}
				n, err := leastPages(ctx, t, tx, f)
				if err != nil {
					return fmt.Errorf("%s: %w", what, err)
				}
				pages[what+" planned "+plans] = n
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	plans := []string{"force_custom_plan", "force_generic_plan"}
	more(500)
	few := map[string]int64{}
	at := dbNow(t, h)
	for _, p := range plans {
		maps.Copy(few, read(at, p))
	}
	more(5000)
	at = dbNow(t, h)
	for _, p := range plans {
		for what, many := range read(at, p) {
			if many > few[what]*3/2+deeper {
				t.Errorf("as of a time, %s read %d pages of history beside 500 grants of its subject's on other clusters, and %d beside 5000", what, few[what], many)
			}
		}
	}
}

// A check as of a time reads the history of its subject's grants, memberships and groups, not
// every row's, and of a conditional grant it holds, for its condition: other principals' history
// costs it nothing.
func TestAsOfReadsOnlyTheRowsAStatementNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, w := h.as(t, "u", "sre"), h.as(t, "w")
	conditional := grant(cluster.Scope(), "cluster.login", rbac.User, "w")
	conditional.Condition = rbac.Condition{Title: "t", Expression: `action == "cluster:login"`}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"), conditional)
	// Other principals' grants on the cluster, each changed once since.
	others := func(n int) {
		t.Helper()
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', 'c1', 'user', 'other-' || gen_random_uuid(), 'cluster.login' FROM generate_series(1, $1)`, []any{n}},
			{`UPDATE rbac_grants SET note = 'changed' WHERE principal LIKE 'user:other-%' AND note = ''`, nil},
			{`ANALYZE rbac_history`, nil},
		} {
			if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The pages of history and its indexes a check reads, as of at.
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			if err := a.Authorize(ctx, u, root, cluster); err != nil {
				return err
			}
			err := a.Authorize(ctx, w, login, cluster)
			read = historyPages(ctx, t, tx) - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	// Each time as deep in history's indexes, so a check reads as many pages unless it reads
	// other principals' history.
	others(500)
	few := read(dbNow(t, h))
	others(2000)
	if many := read(dbNow(t, h)); many > few {
		t.Fatalf("a check as of a time read %d pages of history, and %d once 2000 more principals had grants", few, many)
	}
}

// As of a time, a group's members and the denies on a resource's path are read by the rows they
// name too: other groups' members and denies on other scopes cost about nothing.
func TestAsOfReadsAGroupsMembersAndAScopesDeniesAlone(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	u := h.as(t, "u", "sre")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "sre"))
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	h.groups(t, "other")
	// Members of another group and denies on other clusters, each changed once since.
	others := func(n int) {
		t.Helper()
		for _, q := range []string{
			`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'other', 'user', gen_random_uuid()::text FROM generate_series(1, $1)`,
			`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'd', '{user:u}', '{cluster:sudo}' FROM generate_series(1, $1)`,
			`UPDATE rbac_members SET note = 'changed' WHERE group_id = 'other' AND note = ''`,
			`UPDATE rbac_denies SET name = 'changed' WHERE scope_id <> 'c1' AND name = ''`,
			`ANALYZE rbac_history`,
		} {
			var args []any
			if strings.Contains(q, "$1") {
				args = []any{n}
			}
			if _, err := h.pool.Exec(ctx, q, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			members, err := a.Members(ctx, "t1", "sre")
			if err != nil || len(members) != 1 {
				return fmt.Errorf("members of sre: %v, %w", members, err)
			}
			if err := a.Authorize(ctx, u, root, cluster); !errors.Is(err, rbac.ErrDenied) {
				return fmt.Errorf("the deny: %w", err)
			}
			read = historyPages(ctx, t, tx) - start
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	// Their longer keys deepen history's indexes, which each lookup reads a page more of.
	others(500)
	few := read(dbNow(t, h))
	others(2000)
	if many := read(dbNow(t, h)); many > few*3/2 {
		t.Fatalf("a group's members and a cluster's denies as of a time read %d pages of history, and %d once 2000 more of each were changed", few, many)
	}
}

// As of a time, each deny a statement reads is tested for a later version by its key, beside
// thousands of the tenant's denies on other scopes, in a history of many tenants, analyzed: a plan
// read its later versions through history's index of denies by scope, by the tenant and the time
// alone, so each deny read cost every later version of the tenant's denies. Beside 6,000 denies on
// volumes binding its subject, Reachable read 18 million pages of history, a host's query of
// Filter's condition 36 million, and Denies of one volume 6,875 to list its two. What the first two
// read grows with the denies they read, not with their square, and what Denies reads not at all.
func TestAsOfReadsADenysLaterVersionsByItsKey(t *testing.T) {
	volumes := rbac.RoleDefinition{ID: "volume.admin", Permissions: []rbac.Permission{"volume:view"}, ResourceTypes: []string{"volume"}}
	h := crowded(t, pgtest.Open(t, ""), func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), volumes) })
	ctx := t.Context()
	u := h.as(t, "u", "g")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`CREATE TABLE clusters (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`)
	exec(`INSERT INTO clusters VALUES ('t1', 'c1', $1)`, h.path(t, cluster))
	denied := 0
	// Two denies on each volume, one naming u's group and one the public.
	more := func(n int) {
		t.Helper()
		exec(`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			SELECT 't1', 'volume', 'v' || i, d.id, d.principals, '{volume:view}'
			FROM generate_series($1::int + 1, $2::int) i, (VALUES ('d', '{group:g}'::text[]), ('e', '{public:}')) d(id, principals)`, denied, n)
		denied = n
		exec(`ANALYZE rbac_history`)
	}
	read := func(at time.Time) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			pred, err := a.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
			if err != nil {
				return err
			}
			for what, f := range map[string]func() error{
				"Reachable": func() error { return second(a.Reachable(ctx, u, login, "t1", "cluster")) },
				"a query of Filter's condition": func() error {
					rows, err := tx.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL, pred.Args...)
					if err != nil {
						return err
					}
					ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
					if err == nil && !slices.Equal(ids, []string{"c1"}) {
						err = fmt.Errorf("the clusters u may log in to: %v", ids)
					}
					return err
				},
				"Denies of one volume": func() error {
					ds, err := a.Denies(ctx, "t1", []rbac.Scope{{Type: "volume", ID: "v1"}})
					if err == nil && len(ds) != 2 {
						err = fmt.Errorf("the denies on v1: %+v", ds)
					}
					return err
				},
			} {
				n, err := leastPages(ctx, t, tx, f)
				if err != nil {
					return fmt.Errorf("%s: %w", what, err)
				}
				pages[what] = n
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	// Each size is read by statistics of its own, by any of which a plan could read the later
	// versions so, as by one of these one did: some 80 pages of history for each deny beside 1,000,
	// and 3,000 beside 6,000, against about 3, and 6 for Filter's, each sought by its key.
	more(1)
	few := read(dbNow(t, h))
	for _, n := range []int{500, 3000} {
		more(n)
		for what, many := range read(dbNow(t, h)) {
			most := few[what] + 10*int64(2*n)
			if what == "Denies of one volume" {
				most = few[what]*3/2 + deeper
			}
			if many > most {
				t.Errorf("as of a time, %s read %d pages of history beside two denies on volumes, and %d beside %d", what, few[what], many, 2*n)
			}
		}
	}
}

func TestAsOfReadsPastAStatementTheSessionPrepared(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	// A temporary table gives the session its temporary schema for good.
	if _, err := h.pool.Exec(ctx, `CREATE TEMP TABLE scratch (x int)`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	held := func(a *rbac.Authorizer) int {
		got, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{{Kind: rbac.User, ID: "u"}}})
		if err != nil {
			t.Error(err)
		}
		return len(got)
	}
	if n := held(h.authz); n != 1 {
		t.Fatalf("u holds %d grants", n)
	}
	at := dbNow(t, h)
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if n := held(a); n != 1 {
			t.Errorf("as of before the revoke, u holds %d grants", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := held(h.authz); n != 0 {
		t.Errorf("after AsOf, u holds %d grants", n)
	}
}

// A connection's statement is the same one as of a time as now, and from its sixth run can take a
// generic plan, which costs history's indexes by an average tenant's few rows. As of a time, each
// run of a check reads as much history as the first, in a tenant whose custom roles have each been
// defined three times, one of which the check's subject holds.
func TestAsOfReadsAsMuchOnEveryRunOfACheck(t *testing.T) {
	h := crowded(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	u := h.as(t, "u")
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.r' || i, '{cluster:login}', '{cluster}' FROM generate_series(1, 300) i`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'custom.r1')`,
		`UPDATE rbac_roles SET name = 'again' WHERE tenant = 't1'`,
		`UPDATE rbac_roles SET name = 'and again' WHERE tenant = 't1'`,
		`ANALYZE rbac_history, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	at := dbNow(t, h)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		var first int64
		for run := range 8 {
			start := historyPages(ctx, t, tx)
			if err := a.Authorize(ctx, u, login, cluster); err != nil {
				return err
			}
			read := historyPages(ctx, t, tx) - start
			if run == 0 {
				first = read
			} else if read > first*3/2+deeper {
				t.Errorf("as of a time, a check read %d pages of history on its first run, and %d on run %d", first, read, run+1)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// As of a time, a statement reads as much history whatever history's statistics count, as when
// they are from before most of it was written, which autovacuum leaves them until a tenth of its rows
// are new: the test for a later version of each row it read found, by such statistics, every version
// of the entity in the tenant for each, the key only a filter, so Holders of a role a group of eight
// members holds, whose places a host's sync rewrote a hundred times, read seven times the pages it
// read once history was analyzed, and, in a history of 15,000 records never analyzed, took seconds.
func TestAsOfReadsAsMuchWhateverHistorysStatisticsCount(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// Autovacuum would analyze the tables as they grow.
	for _, table := range []string{"rbac_history", "rbac_members", "rbac_memberships", "rbac_grants", "rbac_groups"} {
		if _, err := h.pool.Exec(ctx, `ALTER TABLE `+table+` SET (autovacuum_enabled = off)`); err != nil {
			t.Fatal(err)
		}
	}
	// Eight members in each of six groups, g2 in g1 and g1 in g0, which holds a role on the cluster.
	groups := []string{"g0", "g1", "g2", "g3", "g4", "g5"}
	for i := range 8 {
		h.as(t, fmt.Sprintf("u%d", i), groups...)
	}
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "g0"))
	analyze := func() {
		t.Helper()
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history, rbac_members, rbac_memberships, rbac_grants, rbac_groups`); err != nil {
			t.Fatal(err)
		}
	}
	// History is analyzed while it holds mostly other tenants' grants, and then each place has a
	// hundred versions, as a host's sync rewriting their notes writes.
	for _, q := range []string{
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g0', 'group', 'g1'), ('t1', 'g1', 'group', 'g2')`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  SELECT 's' || j, 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.login' FROM generate_series(1, 250) j, generate_series(1, 20) i`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	analyze()
	for i := range 100 {
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET note = $1 WHERE tenant = 't1'`, fmt.Sprint("sync ", i)); err != nil {
			t.Fatal(err)
		}
	}
	u := rbac.Subject{Principal: identity("u3")}
	reads := map[string]func(a *rbac.Authorizer) error{
		"Authorize": func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, root, cluster) },
		"Reachable": func(a *rbac.Authorizer) error { return second(a.Reachable(ctx, u, root, "t1", "cluster")) },
		"GroupsOf":  func(a *rbac.Authorizer) error { return second(a.GroupsOf(ctx, "t1", u.Principal)) },
		"Members":   func(a *rbac.Authorizer) error { return second(a.Members(ctx, "t1", "g0")) },
		"Holders":   func(a *rbac.Authorizer) error { return second(a.Holders(ctx, root, cluster)) },
	}
	at := dbNow(t, h)
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range reads {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
					start := historyPages(ctx, t, tx)
					err := f(a)
					pages[what] = historyPages(ctx, t, tx) - start
					return err
				}); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
			}()
		}
		return pages
	}
	stale := read()
	analyze()
	for what, analyzed := range read() {
		if stale[what] > analyzed*3/2+deeper {
			t.Errorf("as of a time, %s read %d pages of history by statistics from before most of it was written, and %d once it was analyzed", what, stale[what], analyzed)
		}
	}
}

// As of a time, Holders of a large group reads as much of history whatever its statistics count. By
// statistics from before the group's members were written, the planner counted them, and the
// tenant's memberships, as a row each: it joined the two by reading every membership in the tenant
// again for each member, each tested for a later version, so a group of 500 read history's pages
// hundreds of times over, and one of 4,000 took 52 seconds; and looking each member's up on its
// own by its principal, it read every membership in the tenant by the entity instead, where the
// statistics held other tenants' memberships and one of the tenant's.
func TestAsOfHoldersOfALargeGroupReadAsMuchWhateverHistorysStatisticsCount(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Autovacuum would analyze the tables as they grow.
	for _, table := range []string{"rbac_history", "rbac_members", "rbac_memberships", "rbac_grants", "rbac_groups"} {
		exec(`ALTER TABLE ` + table + ` SET (autovacuum_enabled = off)`)
	}
	h.groups(t, "everyone")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "everyone"))
	h.as(t, "first", "everyone")
	exec(`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 's' || (i % 50), 'user', 'u' || i FROM generate_series(1, 5000) i`)
	analyze := func() {
		t.Helper()
		exec(`ANALYZE rbac_history, rbac_members, rbac_memberships, rbac_grants, rbac_groups`)
	}
	analyze()
	const n = 500
	exec(`WITH others AS (SELECT gen_random_uuid()::text AS id FROM generate_series(1, $1)),
		memberships AS (INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', id FROM others)
		INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) SELECT 't1', 'everyone', 'user', id FROM others`, n)
	at := dbNow(t, h)
	read := func() int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var pages int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			hs, err := a.Holders(ctx, login, cluster)
			pages = historyPages(ctx, t, tx) - start
			if err == nil && len(hs) != n+1 {
				err = fmt.Errorf("Holders listed %d of the group's %d", len(hs), n+1)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	stale := read()
	analyze()
	if analyzed := read(); stale > analyzed*3/2+deeper {
		t.Errorf("as of a time, Holders of a group of %d read %d pages of history by statistics from before its members were written, and %d once it was analyzed", n, stale, analyzed)
	}
}

// As of a time, a session that plans each statement generically lists a principal's memberships
// from its own versions: planned by the averages, the read leads to the tenant and reads every
// member's.
func TestAsOfListsAPrincipalsMembershipsAloneWhateverTheSessionsPlans(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	u := h.as(t, "u")
	read := func(at time.Time) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var read int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := historyPages(ctx, t, tx)
			ms, err := a.Memberships(ctx, "t1", []rbac.Principal{u.Principal})
			if err == nil && len(ms) != 1 {
				err = fmt.Errorf("u's memberships: %+v", ms)
			}
			read = historyPages(ctx, t, tx) - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return read
	}
	manyMembers(t, h, 500, `SELECT FROM others`, "rbac_history")
	few := read(dbNow(t, h))
	manyMembers(t, h, 4500, `SELECT FROM others`, "rbac_history")
	if many := read(dbNow(t, h)); many > few*3/2+deeper {
		t.Errorf("as of a time, a principal's memberships read %d pages of history beside 500 other members, and %d beside 5000", few, many)
	}
}

// leastPages is the fewest pages of history tx's session reads in a run of f, once two runs have
// read that few and three have run, or the fewest of ten. A session plans a statement it cached
// again once it takes an invalidation of what the plan reads, which other sessions' catalog changes
// on a shared server can send it at any moment, and several runs in a row, and planning reads the
// metapage of each empty index of history, as those of prunes before any, for each time a
// statement names it: a run planned again so read some 2,000 pages where the one before and after
// it read 376, and three in a row did, with views made for each read or made by migrating alike.
// Two runs planned again in a row, each planning the same statements, read alike, so the first two
// agreeing doesn't end it. A run that isn't planned again reads as many pages each time, and none
// reads fewer, so a statement that reads more on every run reads more here too.
func leastPages(ctx context.Context, t *testing.T, tx pgx.Tx, f func() error) (int64, error) {
	t.Helper()
	pages, err := least(func() (map[string]int64, error) {
		start := historyPages(ctx, t, tx)
		if err := f(); err != nil {
			return nil, err
		}
		return map[string]int64{"rbac_history": historyPages(ctx, t, tx) - start}, nil
	})
	return pages["rbac_history"], err
}

// least is the least of each value f measures in a run, once two runs have measured that least of
// every value and three have run, or the least of ten, as leastPages is of history's pages: a run
// that other work lands in, as planning statements again, measures more, and none measures less, so
// what costs more on every run costs more here too.
func least[K comparable, V cmp.Ordered](f func() (map[K]V, error)) (map[K]V, error) {
	fewest, seen := map[K]V{}, map[K]int{}
	for run := 1; run <= 10; run++ {
		values, err := f()
		if err != nil {
			return nil, err
		}
		settled := run >= 3
		for k, v := range values {
			switch l, ok := fewest[k]; {
			case !ok || v < l:
				fewest[k], seen[k] = v, 1
			case v == l:
				seen[k]++
			}
			settled = settled && seen[k] >= 2
		}
		if settled {
			break
		}
	}
	return fewest, nil
}

// customRolesAsOf is how many pages of history each of reads reads as of now, beside many tenants'
// history, before the tenant has other custom roles and once it has 200, each defined four times.
// With plans, the reads set their transaction's plan_cache_mode to it first.
func customRolesAsOf(t *testing.T, h *harness, plans string, reads map[string]func(tx pgx.Tx, a *rbac.Authorizer) error) (few, many map[string]int64) {
	t.Helper()
	ctx := t.Context()
	read := func(at time.Time) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if plans != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
					return err
				}
			}
			for what, f := range reads {
				// Once before, as the reads share statements, which the first to run plans: a plan
				// made generically, as force_generic_plan has it, is made once a transaction, and
				// planning reads the metapage of each empty index of history, as those of prunes
				// before any, for each time a statement names it, so the read that ran first, in a
				// map's random order, was counted hundreds of pages more than one that ran later.
				// Then the least a run reads, as runs planned again do (leastPages).
				if err := f(tx, a); err != nil {
					return fmt.Errorf("%s: %w", what, err)
				}
				n, err := leastPages(ctx, t, tx, func() error { return f(tx, a) })
				if err != nil {
					return fmt.Errorf("%s: %w", what, err)
				}
				pages[what] = n
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history, rbac_roles`); err != nil {
		t.Fatal(err)
	}
	few = read(dbNow(t, h))
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.other' || i, '{cluster:view}', '{cluster}' FROM generate_series(1, 200) i`,
		`UPDATE rbac_roles SET name = 'again' WHERE tenant = 't1' AND id LIKE 'custom.other%'`,
		`UPDATE rbac_roles SET name = 'and again' WHERE tenant = 't1' AND id LIKE 'custom.other%'`,
		`UPDATE rbac_roles SET name = 'once more' WHERE tenant = 't1' AND id LIKE 'custom.other%'`,
		`ANALYZE rbac_history, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	return few, read(dbNow(t, h))
}

// checkAsOf is customRolesAsOf of a check by s.
func checkAsOf(t *testing.T, h *harness, s rbac.Subject, plans string) (few, many int64) {
	t.Helper()
	f, m := customRolesAsOf(t, h, plans, map[string]func(pgx.Tx, *rbac.Authorizer) error{
		"a check": func(_ pgx.Tx, a *rbac.Authorizer) error { return a.Authorize(t.Context(), s, login, cluster) },
	})
	return f["a check"], m["a check"]
}

// heldCustomRoleAsOf is checkAsOf for a subject whose grant names a custom role.
func heldCustomRoleAsOf(t *testing.T, h *harness) (few, many int64) {
	t.Helper()
	u := h.as(t, "u")
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.login', '{cluster:login}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.login", rbac.User, "u"))
	return checkAsOf(t, h, u, "")
}

// skewed is crowded where history's statistics leave out the tenant's custom roles: they hold
// only the commonest tenant and entity, another tenant's grants.
func skewed(t *testing.T) *harness {
	t.Helper()
	h := crowded(t, pgtest.Open(t, "default_statistics_target=1"))
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 'large', 'cluster', 'c' || i, 'user', 'u' || i, 'cluster.login' FROM generate_series(1, 5000) i`); err != nil {
		t.Fatal(err)
	}
	return h
}

// As of a time, a check reads the custom role its grant names by its id, however few of history's
// records, among many tenants', are the tenant's custom roles: counted as a row, they would all be
// read for each version of the one it holds.
func TestAsOfReadsACheckersCustomRoleAloneAmongManyTenants(t *testing.T) {
	if few, many := heldCustomRoleAsOf(t, crowded(t, pgtest.Open(t, ""))); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no other custom role, and %d beside 200", few, many)
	}
}

// As of a time, a check seeks the custom role its grant names by its key where history's
// statistics leave out the tenant's: by its role column, which every grant of the role shares too,
// a plan counting the tenant's roles as a few reads every version of each.
func TestAsOfReadsAHeldCustomRoleByItsKey(t *testing.T) {
	if few, many := heldCustomRoleAsOf(t, skewed(t)); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no other custom role, and %d beside 200", few, many)
	}
}

// As of a time, a check reads no custom role its grants don't name, however its statements are
// planned: a read may plan its transaction's generically, which, matching the roles to the grants,
// reads every version of the tenant's custom roles again for each.
func TestAsOfReadsNoCustomRoleACheckDoesntName(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	if few, many := checkAsOf(t, h, u, "force_generic_plan"); many > few*3/2+deeper {
		t.Errorf("a check as of a time read %d pages of history beside no custom role, and %d beside 200", few, many)
	}
}

// As of a time, Filter, Reachable and Holders, of a labeled resource too, read of the custom roles
// only those the grants they read name, by key, however their statements are planned: they read
// every version of each of the tenant's giving the permission, and Holders, for its holders' label
// values, every version of each their grants on the tenant name, matched to the grants, which a
// generic plan does by reading every version of the tenant's roles again for each.
func TestAsOfSearchesReadOnlyTheCustomRolesTheirGrantsName(t *testing.T) {
	for _, plans := range []string{"", "force_generic_plan"} {
		t.Run(cmp.Or(plans, "as AsOf plans"), func(t *testing.T) {
			h := crowded(t, pgtest.Open(t, ""), withLabels, banks)
			ctx := t.Context()
			c0 := hostTable(t, h)[0]
			u, v := h.as(t, "u"), h.as(t, "v")
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
				VALUES ('t1', 'custom.cleared', '{level:high}', '{tenant}'), ('t1', 'custom.bank', '{bank:a}', '{tenant}')`); err != nil {
				t.Fatal(err)
			}
			// The members, whose label values Holders reads apart, hold bank a and login on c0 too.
			members := rbac.TenantMembers("t1")
			h.seed(t, grant(c0.Scope(), "cluster.login", rbac.User, "u"), grant(c0.Scope(), "cluster.login", rbac.User, "v"),
				grant(rbac.TenantRoot("t1"), "custom.cleared", rbac.User, "u"),
				grant(c0.Scope(), "cluster.login", members.Kind, members.ID), grant(rbac.TenantRoot("t1"), "custom.bank", members.Kind, members.ID))
			secret := c0
			secret.Labels = rbac.Label{"level": {"high"}, "bank": {"a"}}
			holders := func(r rbac.Resource, want ...rbac.Principal) func(pgx.Tx, *rbac.Authorizer) error {
				return func(_ pgx.Tx, a *rbac.Authorizer) error {
					hs, err := a.Holders(ctx, login, r)
					if err == nil && !slices.Equal(holderPrincipals(hs), want) {
						err = fmt.Errorf("Holders of %+v = %+v", r, hs)
					}
					return err
				}
			}
			few, many := customRolesAsOf(t, h, plans, map[string]func(pgx.Tx, *rbac.Authorizer) error{
				"Filter": func(tx pgx.Tx, a *rbac.Authorizer) error {
					pred, err := a.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path", Labels: "'{}'::text[]"}, 1)
					if err != nil {
						return err
					}
					rows, err := tx.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL, pred.Args...)
					if err != nil {
						return err
					}
					ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
					if err == nil && !slices.Equal(ids, []string{c0.ID}) {
						err = fmt.Errorf("Filter kept %v", ids)
					}
					return err
				},
				"Reachable": func(_ pgx.Tx, a *rbac.Authorizer) error {
					reach, err := a.Reachable(ctx, u, login, "t1", "cluster")
					if err == nil && !slices.Equal(reach.Scopes, []rbac.Scope{c0.Scope()}) {
						err = fmt.Errorf("Reachable = %+v", reach)
					}
					return err
				},
				"Holders":                       holders(c0, members, u.Principal, v.Principal),
				"Holders of a labeled resource": holders(secret, members, u.Principal),
			})
			for what, n := range many {
				if n > few[what]*3/2+deeper {
					t.Errorf("as of a time, %s read %d pages of history beside no other custom role, and %d beside 200", what, few[what], n)
				}
			}
		})
	}
}

// As of a time, Grantable reads each version of the tenant's custom roles once, however its
// statements are planned, as it reads every role, any of which can be grantable: whether a later
// version replaced each, planned generically, read every version of them again for each.
func TestAsOfGrantableReadsEachVersionOfTheCustomRolesOnce(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	ctx := t.Context()
	owner := h.as(t, "owner")
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.other' || i, '{cluster:view}', '{cluster}' FROM generate_series(1, 200) i`,
		`UPDATE rbac_roles SET name = 'again' WHERE tenant = 't1'`,
		`ANALYZE rbac_history, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	at := dbNow(t, h)
	read := func(plans string) int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var pages int64
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if plans != "" {
				if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
					return err
				}
			}
			start := historyPages(ctx, t, tx)
			roles, err := a.Grantable(ctx, owner, cluster)
			pages = historyPages(ctx, t, tx) - start
			custom := slices.DeleteFunc(roles, func(r rbac.RoleDefinition) bool { return !strings.HasPrefix(string(r.ID), rbac.CustomPrefix) })
			if err == nil && len(custom) != 200 {
				err = fmt.Errorf("Grantable offers %d custom roles of 200", len(custom))
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	if custom, generic := read(""), read("force_generic_plan"); generic > custom*3/2+deeper {
		t.Errorf("as of a time, Grantable read %d pages of history planned as AsOf plans it, and %d planned generically", custom, generic)
	}
}

// As of a time, a custom role is its last version by then, however its statements are planned: one
// redefined since, one deleted, and one deleted and made again, as a check reads each by its id, a
// search those its grants name, and CustomRoles every one. Their view takes each role's newest
// version apart from the other tables', and a deleted role's last version is its delete.
func TestAsOfReadsACustomRoleAsItsLastVersionThen(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	define := func(qs ...string) {
		t.Helper()
		for _, q := range qs {
			if _, err := h.pool.Exec(ctx, q); err != nil {
				t.Fatal(err)
			}
		}
	}
	define(`INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES
		('t1', 'custom.widened', '{cluster:view}', '{cluster}'),
		('t1', 'custom.deleted', '{cluster:view,cluster:login}', '{cluster}'),
		('t1', 'custom.again', '{cluster:view,cluster:login}', '{cluster}')`)
	on := map[rbac.Role]rbac.Resource{}
	for i, id := range []rbac.Role{"custom.widened", "custom.deleted", "custom.again"} {
		r := cluster
		r.ID = fmt.Sprint("c", i+1)
		on[id] = r
		h.seed(t, grant(r.Scope(), id, rbac.User, "u"))
	}
	then := dbNow(t, h)
	define(`UPDATE rbac_roles SET permissions = '{cluster:view,cluster:login}' WHERE tenant = 't1' AND id = 'custom.widened'`,
		`DELETE FROM rbac_roles WHERE tenant = 't1' AND id IN ('custom.deleted', 'custom.again')`,
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.again', '{cluster:view}', '{cluster}')`)
	now := dbNow(t, h)
	for _, at := range []struct {
		name   string
		at     time.Time
		logins []rbac.Role
	}{
		{"then", then, []rbac.Role{"custom.again", "custom.deleted"}},
		{"now", now, []rbac.Role{"custom.widened"}},
	} {
		for _, plans := range []string{"", "force_generic_plan"} {
			t.Run(at.name+" "+plans, func(t *testing.T) {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at.at, func(a *rbac.Authorizer) error {
					if plans != "" {
						if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
							return err
						}
					}
					var checked, defined []rbac.Role
					for id, r := range on {
						err := a.Authorize(ctx, u, login, r)
						if err != nil && !errors.Is(err, rbac.ErrDenied) {
							return err
						}
						if err == nil {
							checked = append(checked, id)
						}
					}
					slices.Sort(checked)
					if !slices.Equal(checked, at.logins) {
						t.Errorf("u may log in through %v", checked)
					}
					reach, err := a.Reachable(ctx, u, login, "t1", "cluster")
					if err != nil {
						return err
					}
					var reached []rbac.Role
					for id, r := range on {
						if slices.Contains(reach.Scopes, r.Scope()) {
							reached = append(reached, id)
						}
					}
					slices.Sort(reached)
					if !slices.Equal(reached, at.logins) {
						t.Errorf("Reachable = %+v", reach)
					}
					roles, err := a.CustomRoles(ctx, "t1")
					if err != nil {
						return err
					}
					for _, r := range roles {
						if slices.Contains(r.Permissions, login) {
							defined = append(defined, r.ID)
						}
					}
					if !slices.Equal(defined, at.logins) {
						t.Errorf("the custom roles giving login are %v", defined)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Migrating counts the history recorded before it by tenant and entity together, rather than once
// autovacuum next analyzes it, which on a large history is long after.
func TestMigratingCountsHistoryByTenantAndEntity(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0015")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		SELECT 't1', 'custom.r' || i, '{cluster:login}', '{cluster}' FROM generate_series(1, 100) i`); err != nil {
		t.Fatal(err)
	}
	migrateFiles(t, pool, "0015", "")
	var counted bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_catalog.pg_stats_ext WHERE statistics_schemaname = current_schema()
		AND statistics_name = 'rbac_history_tenant_entity' AND most_common_vals IS NOT NULL)`).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if !counted {
		t.Error("once migrated, history's statistics of tenant and entity together are empty")
	}
}

// History's index of the keys denies name reads each deny record's principals, which a record
// written as history's owner can hold as any JSON: one that isn't an array is indexed as naming
// none, an array's arrays as their values and its other values as their text, and history takes
// each, as it takes any record.
func TestHistoryTakesADenyRecordWhosePrincipalsArentStrings(t *testing.T) {
	h := setup(t)
	for _, principals := range []string{`"user:u"`, `1`, `null`, `{"user": "u"}`, `[1, null, {"a": "b"}, ["user:u"]]`} {
		if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after)
			VALUES (now(), 't1', 'deny', 'cluster:c1 d', 'create', jsonb_build_object('principals', $1::jsonb))`, principals); err != nil {
			t.Errorf("history refuses a deny record whose principals are %s: %v", principals, err)
		}
	}
}

// History's index of the keys denies name calls rbac_tenant_keys and rbac_text_array as history's
// owner, as migrating builds it and each time a deny is recorded. Where history's role holds no
// EXECUTE on them, as a host that revoked it from PUBLIC and granted it to the application's role
// alone has it, migrating gives it that, so neither migrating nor a change to a deny fails.
func TestMigratingLetsHistorysRoleCallWhatItsIndexCalls(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0015")
	if _, err := pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{user:u}', '{cluster:login}')`); err != nil {
		t.Fatal(err)
	}
	migration, err := fs.ReadFile(rbac.Migrations(), "0015_history_seeks.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	history, schema := role(t, tx)
	app, _ := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + history + `, ` + app,
		`ALTER TABLE rbac_history OWNER TO ` + history,
		`ALTER FUNCTION rbac_record() OWNER TO ` + history,
		`REVOKE EXECUTE ON FUNCTION rbac_tenant_keys(text, text[]) FROM PUBLIC`,
		`GRANT EXECUTE ON FUNCTION rbac_tenant_keys(text, text[]) TO ` + app,
		`GRANT INSERT ON rbac_denies TO ` + app,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("migrating where history's role may not call rbac_tenant_keys: %v", err)
	}
	for _, sql := range []string{
		`SET LOCAL ROLE ` + app,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		  VALUES ('t1', 'cluster', 'c2', 'd', '{user:u}', '{cluster:login}')`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("once migrated, %s: %v", sql, err)
		}
	}
}

// Migrating to 0019 locks history before it builds the grants' index, so a change that starts while
// it builds and writes history before a grant, as DeleteScope removes a scope's eligibilities and
// then its grants, waits for it to commit: locked once the index was built, history was the change's
// while the change waited for the grants, so migrating gave way, having built the index, or
// PostgreSQL ended one of the two as a deadlock.
func TestMigratingThePrincipalSeeksWaitsForAChangeStartedAsItBuilds(t *testing.T) {
	// Little memory to sort in, so building the index takes a while.
	pool := pgtest.Open(t, "maintenance_work_mem=64kB")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0019")
	recordMigrations(t, pool, "0019")
	// So a Migrate that gave way would give up at once.
	rbac.SetMigrateAttempts(t, 1, time.Millisecond)
	for _, q := range []string{
		`ALTER TABLE rbac_grants DISABLE TRIGGER USER`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  SELECT 't1', 'cluster', 'k' || i, 'user', 'u' || i, 'custom.r' FROM generate_series(1, 100000) i`,
		`ALTER TABLE rbac_grants ENABLE TRIGGER USER`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		  VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 3600)`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	h := migrated(t, pool)
	done := make(chan error, 1)
	go func() { done <- rbac.Migrate(ctx, pool) }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		var building bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_progress_create_index WHERE relid = 'rbac_grants'::regclass)`).Scan(&building); err != nil {
			t.Fatal(err)
		}
		if building {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("migrated before the grants' index was seen building: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("migrating never built the grants' index")
		}
	}
	if err := h.authz.DeleteScope(ctx, host, "t1", cluster.Scope()); err != nil {
		t.Errorf("deleting a scope while migrating builds the grants' index: %v", err)
	}
	if err := <-done; err != nil {
		t.Errorf("Migrate while a scope is deleted: %v", err)
	}
}

// As of a time, Filter, its condition, Reachable and Holders seek their subject's grants, and the
// public's and the members' they count, on each listed type, in a history of one tenant or of many,
// however their statements are planned: history's index of a principal's versions held no scope, so
// a plan read every version of a principal's grants once for each type, a group's on thousands of
// volumes for a list of clusters; and by history's index of scopes, every version on a type's
// scopes in the tenant, the members' grants on thousands of clusters for the anonymous or a guest,
// who count none of them.
func TestAsOfSearchesSeekTheirPrincipalsGrantsOnEachType(t *testing.T) {
	volumes := rbac.RoleDefinition{ID: "volume.admin", Permissions: []rbac.Permission{"volume:view"}, ResourceTypes: []string{"volume"}}
	withVolumes := func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), volumes) }
	for _, tenants := range []string{"one tenant", "many tenants"} {
		for _, plans := range []string{"", "force_generic_plan"} {
			t.Run(tenants+"/"+cmp.Or(plans, "as AsOf plans"), func(t *testing.T) {
				var h *harness
				if tenants == "many tenants" {
					h = crowded(t, pgtest.Open(t, ""), withVolumes)
				} else {
					h = setup(t, withVolumes)
				}
				ctx := t.Context()
				c0 := hostTable(t, h)[0]
				g := h.guest(t, "g", "builders")
				h.seed(t, grant(c0.Scope(), "cluster.login", rbac.User, "g"))
				granted := 0
				more := func(n int) {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
						SELECT 't1', 'cluster', 'k' || i, 'members', 't1', 'cluster.login' FROM generate_series($1::int + 1, $2::int) i
						UNION ALL SELECT 't1', 'volume', 'v' || i, 'group', 'builders', 'volume.admin' FROM generate_series($1::int + 1, $2::int) i`,
						granted, n); err != nil {
						t.Fatal(err)
					}
					granted = n
					if _, err := h.pool.Exec(ctx, `ANALYZE rbac_grants, rbac_history`); err != nil {
						t.Fatal(err)
					}
				}
				read := func(at time.Time) map[string]int64 {
					t.Helper()
					pages := map[string]int64{}
					searches := map[string]func(pgx.Tx, *rbac.Authorizer) error{
						"Holders": func(_ pgx.Tx, a *rbac.Authorizer) error {
							hs, err := a.Holders(ctx, view, c0)
							if err == nil && !slices.Equal(holderPrincipals(hs), []rbac.Principal{g.Principal}) {
								err = fmt.Errorf("Holders = %+v", hs)
							}
							return err
						},
					}
					for who, c := range map[string]struct {
						s    rbac.Subject
						kept []string
					}{"anonymous": {rbac.Subject{}, nil}, "guest": {g, []string{c0.ID}}} {
						searches[who+" Filter"] = func(tx pgx.Tx, a *rbac.Authorizer) error {
							pred, err := a.Filter(ctx, c.s, view, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
							if err != nil {
								return err
							}
							rows, err := tx.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
							if err != nil {
								return err
							}
							ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
							if err == nil && !slices.Equal(ids, c.kept) {
								err = fmt.Errorf("Filter kept %v", ids)
							}
							return err
						}
						searches[who+" Reachable"] = func(_ pgx.Tx, a *rbac.Authorizer) error {
							reach, err := a.Reachable(ctx, c.s, view, "t1", "cluster")
							if err == nil && len(reach.Scopes) != len(c.kept) {
								err = fmt.Errorf("Reachable = %+v", reach)
							}
							return err
						}
					}
					for what, f := range searches {
						func() {
							tx, err := h.pool.Begin(ctx)
							if err != nil {
								t.Fatal(err)
							}
							defer func() { _ = tx.Rollback(ctx) }()
							if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
								if plans != "" {
									if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plans); err != nil {
										return err
									}
								}
								start := historyPages(ctx, t, tx)
								err := f(tx, a)
								pages[what] = historyPages(ctx, t, tx) - start
								return err
							}); err != nil {
								t.Fatalf("%s: %v", what, err)
							}
						}()
					}
					return pages
				}
				more(500)
				few := read(dbNow(t, h))
				more(5000)
				for what, many := range read(dbNow(t, h)) {
					if many > few[what]*3/2+deeper {
						t.Errorf("as of a time, %s read %d pages of history beside 500 grants of the members' on clusters and of a group of the guest's on volumes, and %d beside 5000", what, few[what], many)
					}
				}
			})
		}
	}
}

// As of a time, a list of the grants or the eligibilities on a scope reads their history, not every
// grant's and eligibility's in the tenant.
func TestAsOfListsAScopesGrantsAndEligibilitiesAlone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 3600)`); err != nil {
		t.Fatal(err)
	}
	// Grants and eligibilities on other clusters.
	others := func(n int) {
		t.Helper()
		for _, q := range []string{
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'user', gen_random_uuid()::text, 'cluster.login' FROM generate_series(1, $1)`,
			`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
			  SELECT 't1', 'cluster', gen_random_uuid()::text, 'user', gen_random_uuid()::text, 'cluster.sudo', 3600 FROM generate_series(1, $1)`,
		} {
			if _, err := h.pool.Exec(ctx, q, n); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
			t.Fatal(err)
		}
	}
	scopes := rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}
	lists := []struct {
		what string
		list func(a *rbac.Authorizer) (int, error)
	}{
		{"the grants on a cluster", func(a *rbac.Authorizer) (int, error) {
			gs, err := a.Grants(ctx, "t1", scopes)
			return len(gs), err
		}},
		{"the eligibilities on a cluster", func(a *rbac.Authorizer) (int, error) {
			es, err := a.Eligibilities(ctx, "t1", scopes)
			return len(es), err
		}},
	}
	read := func(at time.Time) map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		pages := map[string]int64{}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			for _, l := range lists {
				start := historyPages(ctx, t, tx)
				n, err := l.list(a)
				if err == nil && n == 0 {
					err = errors.New("none listed")
				}
				if err != nil {
					return fmt.Errorf("%s: %w", l.what, err)
				}
				pages[l.what] = historyPages(ctx, t, tx) - start
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	others(1000)
	few := read(dbNow(t, h))
	others(9000)
	for what, many := range read(dbNow(t, h)) {
		if many > few[what]*3/2+deeper {
			t.Errorf("as of a time, %s read %d pages of history beside 1000 others in the tenant, and %d beside 10,000", what, few[what], many)
		}
	}
}

// As of a time, Filter and Reachable find the denies binding their subject by the keys those name,
// as they do now, and count those on scopes of the types they read by the versions history holds of
// them: thousands of denies naming others on other clusters cost them nothing, nor do thousands set
// there and deleted, which, counted through the views, as those read every version of each to find
// its last, were all read, and for want of live ones read again by type; nor do thousands denying
// everyone on scopes of another type, which history's few versions on the types leave them to find
// by type. The one naming the subject's group still leaves its cluster out.
func TestAsOfListsFindTheDeniesNamingTheirSubjectByItsKeys(t *testing.T) {
	set := `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		SELECT 't1', 'cluster', 'other' || i, 'd', ARRAY['user:other' || i], '{cluster:login}' FROM generate_series($1::int + 1, $2::int) i`
	for shape, others := range map[string][]string{
		"naming others on other clusters": {set},
		"set and deleted on other clusters": {set, `DELETE FROM rbac_denies
			WHERE tenant = 't1' AND scope_type = 'cluster' AND scope_id IN (SELECT 'other' || i FROM generate_series($1::int + 1, $2::int) i)`},
		"denying everyone on another type": {`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
			SELECT 't1', 'group', 'other' || i, 'd', ARRAY[CASE WHEN i % 2 = 0 THEN 'public:' ELSE 'members:t1' END], '{cluster:login}'
			FROM generate_series($1::int + 1, $2::int) i`},
	} {
		t.Run(shape, func(t *testing.T) {
			h, guardian := guarded(t)
			ctx := t.Context()
			resources := hostTable(t, h)
			ann := h.as(t, "ann", "oncall")
			h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "ann"))
			if err := h.authz.SetDeny(ctx, guardian, resources[1], rbac.Deny{ID: "d", Principals: []rbac.Principal{{Kind: rbac.Group, ID: "oncall"}}, Permissions: []rbac.Permission{login}}); err != nil {
				t.Fatal(err)
			}
			denies := 0
			more := func(n int) {
				t.Helper()
				for _, q := range others {
					if _, err := h.pool.Exec(ctx, q, denies, n); err != nil {
						t.Fatal(err)
					}
				}
				denies = n
				if _, err := h.pool.Exec(ctx, `ANALYZE rbac_history`); err != nil {
					t.Fatal(err)
				}
			}
			lists := []struct {
				what string
				list func(tx pgx.Tx, a *rbac.Authorizer) error
			}{
				{"Reachable", func(_ pgx.Tx, a *rbac.Authorizer) error {
					reach, err := a.Reachable(ctx, ann, login, "t1", "cluster")
					if err == nil && (!reach.All || !slices.Equal(reach.Except, []rbac.Scope{resources[1].Scope()})) {
						err = fmt.Errorf("reach %+v", reach)
					}
					return err
				}},
				{"Filter", func(tx pgx.Tx, a *rbac.Authorizer) error {
					pred, err := a.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
					if err != nil {
						return err
					}
					rows, err := tx.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
					if err != nil {
						return err
					}
					ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
					if err == nil && !slices.Equal(ids, []string{"c0", "c2", "c3"}) {
						err = fmt.Errorf("kept %v", ids)
					}
					return err
				}},
			}
			read := func(at time.Time) map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for _, l := range lists {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
							start := historyPages(ctx, t, tx)
							err := l.list(tx, a)
							pages[l.what] = historyPages(ctx, t, tx) - start
							return err
						}); err != nil {
							t.Fatalf("%s: %v", l.what, err)
						}
					}()
				}
				return pages
			}
			more(500)
			few := read(dbNow(t, h))
			more(5000)
			for what, many := range read(dbNow(t, h)) {
				if many > few[what]*3/2+deeper {
					t.Errorf("as of a time, %s read %d pages of history beside 500 denies %s, and %d beside 5000", what, few[what], shape, many)
				}
			}
		})
	}
}

// Before 0016 the tables took a list in more than one dimension, as a write around the package with
// the application's rights could store, and every check and list took its elements in order: a
// deny naming '{{user:u}}' bound u. As of a time, history's reads took the inner array as one key,
// its JSON, so the deny bound no one. Migrating writes its row in one dimension, and as of a time
// before, every check and list reads the deny as they did then, as they read it now: by history's
// index of the keys denies name too, past enough denies naming others that lists find theirs by it.
func TestAsOfReadsAListOfMoreDimensionsAsChecksDid(t *testing.T) {
	pool := pgtest.Open(t, "")
	ctx := t.Context()
	migrateFiles(t, pool, "", "0016")
	h := migrated(t, pool)
	hostTable(t, h)
	u := h.as(t, "u")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "u"))
	for _, sql := range []string{
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 VALUES ('t1', 'workspace', 'w1', 'd', '{{user:u}}', '{{user:x}}', '{{cluster:login}}')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		 SELECT 't1', 'cluster', 'other' || i, 'd', ARRAY['user:other' || i], '{cluster:login}' FROM generate_series(1, 2000) i`,
		`ANALYZE rbac_history`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	before := dbNow(t, h)
	migrateFiles(t, pool, "0016", "")
	answers := func(a *rbac.Authorizer, q pgx.Tx) []string {
		t.Helper()
		err := a.Authorize(ctx, u, login, cluster)
		out := []string{fmt.Sprintf("Authorize: %v", err)}
		reach, err := a.Reachable(ctx, u, login, "t1", "cluster")
		out = append(out, fmt.Sprintf("Reachable: all %t except %v, %v", reach.All, reach.Except, err))
		pred, err := a.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		var kept []string
		if err == nil {
			var rows pgx.Rows
			if rows, err = q.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...); err == nil {
				kept, err = pgx.CollectRows(rows, pgx.RowTo[string])
			}
		}
		out = append(out, fmt.Sprintf("Filter: %v, %v", kept, err))
		holders, err := a.Holders(ctx, login, cluster)
		var who []string
		for _, x := range holders {
			who = append(who, x.Principal.ID)
		}
		out = append(out, fmt.Sprintf("Holders: %v, %v", who, err))
		denies, err := a.Denies(ctx, "t1", []rbac.Scope{{Type: "workspace", ID: "w1"}})
		for _, d := range denies {
			out = append(out, fmt.Sprintf("Denies: %+v %+v %v", d.Principals, d.Exempt, d.Permissions))
		}
		return append(out, fmt.Sprintf("Denies: %v", err))
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := answers(h.authz.WithTx(tx), tx)
	want := []string{
		"Authorize: rbac: cluster:login denied",
		"Reachable: all true except [{workspace w1}], <nil>",
		"Filter: [c1 c2 c3], <nil>",
		"Holders: [], <nil>",
		"Denies: [{Kind:user ID:u}] [{Kind:user ID:x}] [cluster:login]",
		"Denies: <nil>",
	}
	if !slices.Equal(now, want) {
		t.Fatalf("now:\n%s", strings.Join(now, "\n"))
	}
	var then []string
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", before, func(a *rbac.Authorizer) error {
		then = answers(a, tx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(then, now) {
		t.Errorf("as of a time before migrating:\n%s\nnow:\n%s", strings.Join(then, "\n"), strings.Join(now, "\n"))
	}
}

// AsOf reads history as of its time to the microsecond, whatever the session's DateStyle and
// TimeZone and whatever its read sets them to: a time's text in a DateStyle but ISO names its
// zone by an abbreviation, which another TimeZone reads as its own zone's, and one of another
// field order reads its month as its day. From PostgreSQL 18 a TimeZone's own abbreviations name
// zones too, as UTC+5's UTC, five hours west, does in AT TIME ZONE 'UTC', and in a time's text
// as Z or AD would.
func TestAsOfReadsItsTimeWhateverTheSessionsDateStyle(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	// When the grant's transaction committed, which AsOf counts it from.
	granted := committedAt(t, h, `entity = 'grant' AND principal = 'user:u'`)
	for _, c := range []struct{ dateStyle, timeZone, inRead string }{
		{"ISO, MDY", "UTC", ""},
		{"Postgres, DMY", "America/Los_Angeles", ""},
		{"SQL, MDY", "Europe/Dublin", ""},
		{"German", "Asia/Kolkata", ""},
		{"Postgres, YMD", "Pacific/Chatham", ""},
		{"Postgres, MDY", "XYZ-3", `SET LOCAL TimeZone = 'XYZ+5'`},
		{"SQL, MDY", "Australia/Lord_Howe", `SET LOCAL DateStyle = 'SQL, DMY'`},
		{"ISO, MDY", "UTC+5", ""},
		{"ISO, MDY", "UTC", `SET LOCAL TimeZone = '<Z>+5'`},
		{"SQL, DMY", "<AD>-2", ""},
	} {
		for _, at := range []time.Time{granted, granted.Add(-time.Microsecond), time.Date(-100, time.March, 15, 12, 0, 0, 0, time.UTC)} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				if _, err := tx.Exec(ctx, `SELECT set_config('DateStyle', $1, true), set_config('TimeZone', $2, true)`, c.dateStyle, c.timeZone); err != nil {
					t.Fatal(err)
				}
				var held error
				if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
					if c.inRead != "" {
						if _, err := tx.Exec(ctx, c.inRead); err != nil {
							return err
						}
					}
					held = a.Authorize(ctx, u, login, cluster)
					return nil
				}); err != nil {
					t.Errorf("%s, %s, %s: as of %v: %v", c.dateStyle, c.timeZone, c.inRead, at, err)
				} else if (held == nil) != at.Equal(granted) {
					t.Errorf("%s, %s, %s: as of %v, granted at %v: %v", c.dateStyle, c.timeZone, c.inRead, at, granted, held)
				}
			}()
		}
	}
}

// A change counts from its transaction's commit, before which no other session sees it: a revoke
// that a host's transaction makes and then holds open, as while it calls another service, reads as
// of a moment then as every check then read it, the grant still held, and a grant so held as not yet
// made. Every transaction that had begun by then has ended, so what that moment reads is final.
func TestAsOfCountsAChangeFromItsCommit(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u, v := h.as(t, "owner"), h.as(t, "u"), h.as(t, "v")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authz.WithTx(tx).Apply(ctx, owner, cluster, rbac.Change{
		Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u.Principal}},
		Grant:  []rbac.Binding{{Role: "cluster.login", Principal: v.Principal}},
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	mid := dbNow(t, h)
	h.now = mid
	for _, c := range []struct {
		s    rbac.Subject
		held bool
	}{{u, true}, {v, false}} {
		if err := h.authz.Authorize(ctx, c.s, login, cluster); (err == nil) != c.held {
			t.Fatalf("a check of %s while the change is uncommitted: %v", c.s.Principal.ID, err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for at, held := range map[time.Time]map[string]bool{mid: {"u": true, "v": false}, dbNow(t, h): {"u": false, "v": true}} {
		if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			for _, s := range []rbac.Subject{u, v} {
				err := a.Authorize(ctx, s, login, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != held[s.Principal.ID] {
					t.Errorf("as of %v, %s's login: %v", at, s.Principal.ID, err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// A revoke still running as later transactions commit counts from its own commit record, not from
// theirs, which are dated by then: before its commit every check allowed what it revokes, and after
// it none did.
func TestAsOfCountsAChangeRunningAsOthersCommitFromItsOwnCommit(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, v := h.as(t, "u"), h.as(t, "v")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	// Others commit while it runs, the latest dated by mid too.
	for i := range 3 {
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET note = $1 WHERE tenant = 't1' AND principal = 'user:v'`, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	mid := dbNow(t, h)
	h.now = mid
	if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
		t.Fatalf("a check while the revoke runs: %v", err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET note = 'after' WHERE tenant = 't1' AND principal = 'user:v'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// And others after it.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET note = 'later' WHERE tenant = 't1' AND principal = 'user:v'`); err != nil {
		t.Fatal(err)
	}
	for at, held := range map[time.Time]bool{mid: true, dbNow(t, h): false} {
		err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) })
		if err != nil && !errors.Is(err, rbac.ErrDenied) {
			t.Fatal(err)
		}
		if (err == nil) != held {
			t.Errorf("as of %v, u's login: %v", at, err)
		}
	}
	_ = v
}

// Under WithTx, a read as of a time counts none of the host transaction's own changes, which no
// other session sees until it commits: a revoke and a grant it made read as not yet made, as every
// check by another session then read them.
func TestAsOfCountsNoneOfItsOwnTransactionsChanges(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u, v := h.as(t, "owner"), h.as(t, "u"), h.as(t, "v")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authz.WithTx(tx).Apply(ctx, owner, cluster, rbac.Change{
		Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u.Principal}},
		Grant:  []rbac.Binding{{Role: "cluster.login", Principal: v.Principal}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		for _, c := range []struct {
			s    rbac.Subject
			held bool
		}{{u, true}, {v, false}} {
			err := a.Authorize(ctx, c.s, login, cluster)
			if err != nil && !errors.Is(err, rbac.ErrDenied) {
				return err
			}
			if (err == nil) != c.held {
				t.Errorf("as of now, in the transaction that changed it, %s's login: %v", c.s.Principal.ID, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The package's own transaction commits once Config.OnChange returns: a revoke whose hook takes a
// while counts from after it, as checks meanwhile read the grant held.
func TestAsOfCountsAChangeFromItsCommitAfterItsHook(t *testing.T) {
	var slow func()
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error {
			if slow != nil {
				slow()
			}
			return nil
		}
	})
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	var mid time.Time
	var during error
	slow = func() {
		time.Sleep(50 * time.Millisecond)
		if err := h.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&mid); err != nil {
			t.Error(err)
		}
		h.now = mid
		during = h.authz.Authorize(ctx, u, login, cluster)
		time.Sleep(50 * time.Millisecond)
	}
	if err := h.authz.Apply(ctx, owner, cluster, rbac.Change{Revoke: []rbac.Binding{{Role: "cluster.login", Principal: u.Principal}}}); err != nil {
		t.Fatal(err)
	}
	slow = nil
	if during != nil {
		t.Fatalf("a check while the revoke's hook ran: %v", during)
	}
	if err := h.authz.AsOf(ctx, "t1", mid, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) }); err != nil {
		t.Errorf("as of %v, while the revoke's hook ran, u's login: %v", mid, err)
	}
}

// A session that may write the package's tables, as the application's, can fire a transaction's
// deferred triggers before it commits, with SET CONSTRAINTS ... IMMEDIATE, which takes no privilege,
// and then hold the transaction open while it uses access it revoked: its commit is recorded again
// as it commits, so AsOf counts the revoke from then, however and whenever constraints were set
// immediate. Code of its own can run as the transaction commits, after its commit record is
// written: a cursor WITH HOLD, which commit runs to its end, declared in the transaction, also in a
// block's or a procedure's later transaction, which the cursor's creation time dates by the block,
// before its change too, and a deferrable trigger on a temporary table. Each is refused, so the
// grant stays; so is a block's change with a cursor it declared in an earlier transaction still
// open, which nothing tells from one it declared in this.
func TestHistoryDatesAChangeNoEarlierThanItsCommit(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	revoke := func(u rbac.Subject) string {
		return `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:` + u.Principal.ID + `'`
	}
	connect := func(t *testing.T) *pgx.Conn {
		t.Helper()
		conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(ctx)) })
		return conn
	}
	refused := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "0A000"
	}
	for _, c := range []struct {
		name          string
		before, after []string
		// block is run on its own, outside a transaction, with the revoke as %s.
		block string
	}{
		{name: "cursor", after: []string{`DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)`}},
		{name: "cursor declared first", before: []string{`DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)`}},
		{name: "cursor in a block's later transaction", block: `DO $$ BEGIN COMMIT; %s;
			EXECUTE 'DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)'; END $$`},
		{name: "cursor in a block's later transaction, before its change", block: `DO $$ BEGIN COMMIT;
			EXECUTE 'DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)'; %s; END $$`},
		{name: "cursor a block declared in an earlier transaction", block: `DO $$ BEGIN
			EXECUTE 'DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)'; COMMIT; %s; END $$`},
		{name: "cursor in a procedure's later transaction", before: []string{
			`CREATE PROCEDURE pg_temp.held() LANGUAGE plpgsql AS $$ BEGIN COMMIT; %s;
				EXECUTE 'DECLARE held CURSOR WITH HOLD FOR SELECT pg_sleep(0)'; END $$`,
		}, block: `CALL pg_temp.held()`},
		{name: "temporary trigger", before: []string{
			`CREATE TEMP TABLE held (a int)`,
			`CREATE FUNCTION pg_temp.held() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`,
			`CREATE CONSTRAINT TRIGGER held AFTER INSERT ON held DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pg_temp.held()`,
		}, after: []string{`INSERT INTO held VALUES (1)`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			u := h.as(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
			conn := connect(t)
			var failed error
			queries := slices.Concat([]string{`BEGIN`}, c.before, []string{revoke(u)}, c.after, []string{`COMMIT`})
			if c.block != "" {
				queries = slices.Concat(c.before, []string{c.block})
				if !strings.Contains(c.block, "%s") {
					queries[0] = fmt.Sprintf(queries[0], revoke(u))
				} else {
					queries[len(queries)-1] = fmt.Sprintf(c.block, revoke(u))
				}
			}
			for _, q := range queries {
				if _, failed = conn.Exec(ctx, q); failed != nil {
					break
				}
			}
			if !refused(failed) {
				t.Errorf("a revoke with a %s: %v", c.name, failed)
			}
			_, _ = conn.Exec(ctx, `ROLLBACK`)
			if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
				t.Fatalf("after a revoke refused: %v", err)
			}
		})
	}
	// Set immediate before or after the revoke, by name, in a block, in a savepoint released, twice
	// or in one rolled back, the revoke's transaction commits, held open past every commit record
	// it wrote before, and AsOf counts the revoke from its commit; so does one in a session whose
	// temporary table has a deferrable trigger that is disabled.
	for _, c := range []struct {
		name          string
		before, after []string
	}{
		{name: "immediate after", after: []string{`SET CONSTRAINTS ALL IMMEDIATE`}},
		{name: "immediate by name", after: []string{`SET CONSTRAINTS rbac_history_committed IMMEDIATE`}},
		{name: "immediate before", before: []string{`SET CONSTRAINTS ALL IMMEDIATE`}},
		{name: "immediate in a block", after: []string{`DO $$ BEGIN SET CONSTRAINTS ALL IMMEDIATE; END $$`}},
		{name: "immediate twice", after: []string{`SET CONSTRAINTS ALL IMMEDIATE`, `SET CONSTRAINTS ALL IMMEDIATE`}},
		{name: "immediate then deferred", after: []string{`SET CONSTRAINTS ALL IMMEDIATE`, `SET CONSTRAINTS ALL DEFERRED`}},
		{name: "immediate in a savepoint released", after: []string{`SAVEPOINT early`, `SET CONSTRAINTS ALL IMMEDIATE`, `RELEASE SAVEPOINT early`}},
		{name: "immediate in a savepoint rolled back", after: []string{`SAVEPOINT early`, `SET CONSTRAINTS ALL IMMEDIATE`, `ROLLBACK TO SAVEPOINT early`}},
		{name: "immediate before and after", before: []string{`SET CONSTRAINTS ALL IMMEDIATE`}, after: []string{`SET CONSTRAINTS ALL IMMEDIATE`}},
		// A temporary table's deferrable trigger that is disabled fires nothing as the commit does.
		{name: "disabled temporary trigger", before: []string{
			`CREATE TEMP TABLE held (a int)`,
			`CREATE FUNCTION pg_temp.held() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`,
			`CREATE CONSTRAINT TRIGGER held AFTER INSERT ON held DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pg_temp.held()`,
			`ALTER TABLE held DISABLE TRIGGER held`,
		}, after: []string{`INSERT INTO held VALUES (1)`}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			u := h.as(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
			conn := connect(t)
			for _, q := range slices.Concat([]string{`BEGIN`}, c.before, []string{revoke(u)}, c.after) {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			time.Sleep(20 * time.Millisecond)
			mid := dbNow(t, h)
			h.now = mid
			if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
				t.Fatalf("a check while the revoke is uncommitted: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
			if _, err := conn.Exec(ctx, `COMMIT`); err != nil {
				t.Fatal(err)
			}
			after := dbNow(t, h)
			for at, held := range map[time.Time]bool{mid: true, after: false} {
				err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) })
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					t.Fatal(err)
				}
				if (err == nil) != held {
					t.Errorf("as of %v, u's login: %v", at, err)
				}
			}
		})
	}
}

// A batch that holds a cursor across the transactions of a procedure or a DO block, and changes the
// package's tables in them, commits as the refusal's hint says: with the cursor declared before the
// block, in a transaction of its own, and fetched from by its name; closed before the change's
// transaction commits; or as a FOR loop over a query, which PL/pgSQL runs to its end as each COMMIT
// begins, before any trigger fires.
func TestABatchHoldingACursorCommitsAsTheHintSays(t *testing.T) {
	h := setup(t)
	for _, c := range []struct {
		name  string
		batch []string
	}{
		{name: "declared before the block", batch: []string{
			`DECLARE batch CURSOR WITH HOLD FOR SELECT g FROM generate_series(1, 3) g`,
			`DO $$ DECLARE c refcursor := 'batch'; g int; BEGIN LOOP FETCH c INTO g; EXIT WHEN NOT FOUND;
				INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'batched' || g); COMMIT; END LOOP; END $$`,
			`CLOSE batch`,
		}},
		{name: "closed first", batch: []string{
			`DO $$ DECLARE g int; BEGIN FOR g IN 1..3 LOOP EXECUTE 'DECLARE batch CURSOR WITH HOLD FOR SELECT 1'; COMMIT; EXECUTE 'CLOSE batch';
				INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'batched' || g); COMMIT; END LOOP; END $$`,
		}},
		{name: "a FOR loop", batch: []string{
			`DO $$ DECLARE g int; BEGIN FOR g IN SELECT generate_series(1, 3) LOOP
				INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'batched' || g); COMMIT; END LOOP; END $$`,
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
			if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_memberships WHERE principal_id LIKE 'batched%'`); err != nil {
				t.Fatal(err)
			}
			var from uint64
			if err := h.pool.QueryRow(ctx, `SELECT pg_current_xact_id()::text::bigint`).Scan(&from); err != nil {
				t.Fatal(err)
			}
			for _, q := range c.batch {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			var commits int
			if err := h.pool.QueryRow(ctx, `SELECT count(DISTINCT c.txid) FROM rbac_history m JOIN rbac_history c ON c.txid = m.txid AND c.entity = 'commit'
				WHERE m.entity = 'membership' AND m.op = 'create' AND m.key LIKE 'user:batched%' AND m.txid > $1::bigint::text::xid8`, from).Scan(&commits); err != nil || commits != 3 {
				t.Errorf("the batch's three changes have %d commit records, %v", commits, err)
			}
		})
	}
}

// A query string of several statements, as the simple protocol sends one, is a block too: each of
// its statements began as it did, and each of its transactions with them, so a transaction of it
// that changes the package's tables, after one of it that declared a cursor WITH HOLD and
// committed, is refused as one with a cursor declared in it, which nothing tells it from. The
// refusal names such a query string, and its hint says how one commits: with the cursor declared
// in a query string of its own, as it then does.
func TestAQueryStringHoldingACursorCommitsAsTheHintSays(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	exec := func(sql string) error {
		_, err := conn.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol)
		return err
	}
	const (
		declare = `BEGIN; DECLARE batch CURSOR WITH HOLD FOR SELECT 1; COMMIT;`
		change  = `BEGIN; INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'batched'); COMMIT;`
	)
	err = exec(declare + ` ` + change)
	if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "0A000" ||
		!strings.Contains(pgErr.Message, "query string") || !strings.Contains(pgErr.Hint, "query string of its own") {
		t.Fatalf("a change after a transaction of its query string that declared a cursor WITH HOLD: %v", err)
	}
	for _, sql := range []string{`CLOSE batch`, declare, change, `CLOSE batch`} {
		if err := exec(sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var commits int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history m JOIN rbac_history c ON c.txid = m.txid AND c.entity = 'commit'
		WHERE m.entity = 'membership' AND m.key = 'user:batched'`).Scan(&commits); err != nil || commits != 1 {
		t.Errorf("the change has %d commit records, %v", commits, err)
	}
}

// The commit record's trigger fires as a transaction commits once for each record it wrote, and the
// event of each but the last only looks for a later one: first among the next 32 ids, where the
// records a statement writes are, one after another, unless more than 32 sessions write history at
// once, and only then among all of the transaction's later records, which reads every entry after
// the record's on its index page. So a commit of thousands of records one id apart adds at most three
// quarters of what it adds where they are 40 apart, where it reads both, each the least of several
// commits made one after the other, so the server's load moves them alike. The read of all of them
// alone, as 0027's trigger made it, adds as much to either.
func TestACommitLooksForALaterRecordAmongTheNextIdsFirst(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	const n, rounds = 5000, 5
	conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	exec := func(sql string) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	commits := map[string][]time.Duration{}
	for i := range rounds {
		for _, c := range []struct {
			name    string
			apart   int
			trigger string
		}{
			{"one apart", 1, "ENABLE ALWAYS"},
			{"40 apart", 40, "ENABLE ALWAYS"},
			{"none", 1, "DISABLE"},
		} {
			exec(`ALTER TABLE rbac_history ` + c.trigger + ` TRIGGER rbac_history_committed`)
			exec(`BEGIN`)
			exec(fmt.Sprintf(`INSERT INTO rbac_history (id, effective_at, tenant, entity, key, op, bytes) OVERRIDING SYSTEM VALUE
				SELECT l.id + 1 + g * %d, now(), 't1', 'membership', '%s %d ' || g, 'create', 0
				FROM (SELECT coalesce(max(id), 0) AS id FROM rbac_history) l, generate_series(0, %d) g`, c.apart, c.name, i, n-1))
			// Past them, for the commit record's id.
			exec(`SELECT setval(pg_get_serial_sequence('rbac_history', 'id'), (SELECT max(id) FROM rbac_history))`)
			start := time.Now()
			exec(`COMMIT`)
			commits[c.name] = append(commits[c.name], time.Since(start))
		}
	}
	exec(`ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed`)
	added := func(name string) time.Duration { return (slices.Min(commits[name]) - slices.Min(commits["none"])) / n }
	near, far := added("one apart"), added("40 apart")
	t.Logf("a commit of %d records adds %v a record where they are one id apart, %v where 40", n, near, far)
	if near > far*3/4 {
		t.Errorf("a commit of records one id apart adds %v for each, more than three quarters of the %v of records 40 apart", near, far)
	}
}

// A commit that empties a session's temporary table (ON COMMIT DELETE ROWS) takes its lock, and
// that of its TOAST table, after history records the commit: another session, of the same role,
// that holds either, by LOCK or by preparing a statement that names the TOAST table, which needs
// no privilege, would hold the commit back past its record, so AsOf would count a revoke from a
// time every check still allowed what it revoked. The commit gives up the wait instead, and the
// revoke with it.
func TestACommitWaitsForNoLockPastItsRecord(t *testing.T) {
	h := setup(t)
	for _, hold := range []string{"table", "toast"} {
		t.Run(hold, func(t *testing.T) {
			ctx := t.Context()
			u := h.as(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
			var conns [2]*pgx.Conn
			for i := range conns {
				conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
				conns[i] = conn
			}
			committer, holder := conns[0], conns[1]
			if _, err := committer.Exec(ctx, `CREATE TEMP TABLE held (a int, b text) ON COMMIT DELETE ROWS`); err != nil {
				t.Fatal(err)
			}
			var table, toast string
			if err := committer.QueryRow(ctx, `SELECT pg_my_temp_schema()::regnamespace::text || '.held', t.oid::regclass::text
				FROM pg_class c JOIN pg_class t ON t.oid = c.reltoastrelid WHERE c.oid = 'pg_temp.held'::regclass`).Scan(&table, &toast); err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{`BEGIN`, `INSERT INTO held VALUES (1, 'x')`, `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u'`} {
				if _, err := committer.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			lock := map[string]string{"table": `LOCK TABLE ` + table + ` IN ACCESS SHARE MODE`, "toast": `PREPARE held AS SELECT * FROM ` + toast}[hold]
			for _, q := range []string{`BEGIN`, lock} {
				if _, err := holder.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			defer func() { _, _ = holder.Exec(context.WithoutCancel(ctx), `ROLLBACK`) }()
			wait, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, err := committer.Exec(wait, `COMMIT`)
			if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Fatalf("a commit whose temporary table another session holds: %v", err)
			}
			if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
				t.Errorf("after a revoke that waited: %v", err)
			}
		})
	}
}

// A change made in a savepoint that is released, as one rolled back, stores the top-level
// transaction's id (pg_current_xact_id(), the txid column's default), so the transaction's commit
// record, keyed by that id, dates it: a revoke in a released savepoint and one at the top level
// share one id and one commit record, and AsOf counts both from that commit, not before. A change
// in a savepoint rolled back is gone, records and all.
func TestAsOfCountsASubtransactionsChangeFromTheTopLevelCommit(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u, v, w := h.as(t, "u"), h.as(t, "v"), h.as(t, "w")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "v"),
		grant(cluster.Scope(), "cluster.login", rbac.User, "w"))
	revoke := func(id string) string {
		return `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:` + id + `'`
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// u at the top level, v in a savepoint released, w in a savepoint rolled back.
	for _, q := range []string{
		revoke("u"),
		`SAVEPOINT kept`, revoke("v"), `RELEASE SAVEPOINT kept`,
		`SAVEPOINT gone`, revoke("w"), `ROLLBACK TO SAVEPOINT gone`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	time.Sleep(40 * time.Millisecond)
	mid := dbNow(t, h)
	h.now = mid
	for _, c := range []struct {
		s    rbac.Subject
		held bool
	}{{u, true}, {v, true}, {w, true}} {
		if err := h.authz.Authorize(ctx, c.s, login, cluster); (err == nil) != c.held {
			t.Fatalf("a check of %s while the revokes are uncommitted: %v", c.s.Principal.ID, err)
		}
	}
	time.Sleep(40 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// The top-level and the released savepoint's revokes share one txid, that txid has a commit
	// record, and the rolled-back savepoint's revoke left no record.
	var txids, commits, gone int
	if err := h.pool.QueryRow(ctx, `SELECT count(DISTINCT txid) FROM rbac_history
		WHERE entity = 'grant' AND op = 'delete' AND principal IN ('user:u', 'user:v')`).Scan(&txids); err != nil || txids != 1 {
		t.Fatalf("the two revokes span %d txids, %v", txids, err)
	}
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE entity = 'commit'
		AND txid = (SELECT txid FROM rbac_history WHERE entity = 'grant' AND op = 'delete' AND principal = 'user:v')`).Scan(&commits); err != nil || commits != 1 {
		t.Fatalf("the released savepoint's revoke shares %d commit records with the top level, %v", commits, err)
	}
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history
		WHERE entity = 'grant' AND op = 'delete' AND principal = 'user:w'`).Scan(&gone); err != nil || gone != 0 {
		t.Fatalf("the rolled-back savepoint's revoke left %d records, %v", gone, err)
	}
	for at, held := range map[time.Time]map[string]bool{
		mid:         {"u": true, "v": true, "w": true},
		dbNow(t, h): {"u": false, "v": false, "w": true},
	} {
		if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			for _, s := range []rbac.Subject{u, v, w} {
				err := a.Authorize(ctx, s, login, cluster)
				if err != nil && !errors.Is(err, rbac.ErrDenied) {
					return err
				}
				if (err == nil) != held[s.Principal.ID] {
					t.Errorf("as of %v, %s's login: %v", at, s.Principal.ID, err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// restoreRows writes rows into h's history as a logical dump restored by a superuser would: the
// commit trigger off, so it records no commit of its own, each row with the cluster and txid it
// carried. It is how a restore, not the application's role, makes the rows a test of one needs.
func restoreRows(t *testing.T, h *harness, rows ...string) {
	t.Helper()
	ctx := t.Context()
	queries := append([]string{`ALTER TABLE rbac_history DISABLE TRIGGER rbac_history_committed`}, rows...)
	queries = append(queries, `ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed`)
	for _, q := range queries {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// otherCluster returns a system_identifier that is not tx's cluster's, as a dump from another
// cluster carries.
func otherCluster(t *testing.T, h *harness) (ours, theirs string) {
	t.Helper()
	if err := h.pool.QueryRow(t.Context(), `SELECT system_identifier::text FROM pg_control_system()`).Scan(&ours); err != nil {
		t.Fatal(err)
	}
	theirs = "1"
	if theirs == ours {
		theirs = "2"
	}
	return ours, theirs
}

// fakeGrant is SQL inserting the creation of user restored's grant, its row copied from user tmpl's
// grant, as of at in cluster clu with txid.
func fakeGrant(at, clu, txid string) string {
	return fmt.Sprintf(`INSERT INTO rbac_history (effective_at, txid, cluster, tenant, entity, key, op, principal, role, scope, after, bytes)
		SELECT timestamptz '%s', '%s'::xid8, '%s', tenant, entity, md5('restored-grant')::uuid::text, 'create', 'user:restored', role, scope,
		  after || jsonb_build_object('id', md5('restored-grant')::uuid::text, 'principal', 'user:restored', 'principal_id', 'restored'), bytes
		FROM rbac_history WHERE entity = 'grant' AND principal = 'user:tmpl'`, at, txid, clu)
}

// fakeCommit is SQL inserting a commit record of txid in cluster clu, dated at.
func fakeCommit(at, clu, txid string) string {
	return fmt.Sprintf(`INSERT INTO rbac_history (effective_at, txid, cluster, tenant, entity, key, op, bytes)
		VALUES (timestamptz '%s', '%s'::xid8, '%s', '', 'commit', '', 'commit', 0)`, at, txid, clu)
}

// A change restored from another cluster, whose txid the new cluster later gives a transaction of
// its own, must be dated by its own cluster's commit record, not the colliding one: AsOf matches a
// version to a commit record of the version's own cluster. Without that, the later transaction's
// commit, picked by max(effective_at), dates the restored grant, and it reads as not yet in force.
func TestAsOfDatesARestoredChangeWithinItsCluster(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	ours, theirs := otherCluster(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "tmpl"))
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	mid := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
	restoreRows(t, h,
		// A grant restored from another cluster, committed there long ago, keyed by txid 500.
		fakeGrant(old.Format("2006-01-02 15:04:05"), theirs, "500"),
		fakeCommit(old.Add(time.Second).Format("2006-01-02 15:04:05"), theirs, "500"),
		// This cluster later gives txid 500 to a transaction that commits after mid: a collision.
		fakeCommit("2020-01-01 00:00:00", ours, "500"),
	)
	// As of mid, the restored grant was in force in its own cluster, so it reads as held.
	if err := h.authz.AsOf(ctx, "t1", mid, func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("restored")}})
		if err == nil && len(grants) != 1 {
			t.Errorf("as of %v, a restored grant dated by a colliding txid reads as %+v", mid, grants)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A version of a row whose transaction wrote a later one dated by a time hasn't counted by then
// where the later one hasn't, as their commit is the same: but a restored version and a later one
// of this cluster that share a txid are of two transactions. Taken for one, the restored grant
// read as superseded by a version of the same row a transaction of this cluster held open, while
// it was, and as of then the row read as no grant at all. And the commit record, reading every
// record of the txid as its transaction's, refused that transaction's commit, as the restored one
// names another cluster.
func TestAsOfTellsATransactionApartFromAnotherClustersOfTheSameTxid(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	_, theirs := otherCluster(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "tmpl"))
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var txid string
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&txid); err != nil {
		t.Fatal(err)
	}
	// A grant restored from another cluster, committed there long ago, whose txid this cluster
	// gives the transaction that, held open past mid, writes the same row anew.
	restoreRows(t, h,
		fakeGrant(old.Format("2006-01-02 15:04:05"), theirs, txid),
		fakeCommit(old.Add(time.Second).Format("2006-01-02 15:04:05"), theirs, txid),
	)
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (id, tenant, scope_type, scope_id, principal_kind, principal_id, role, note)
		VALUES (md5('restored-grant')::uuid, 't1', 'cluster', 'c1', 'user', 'restored', 'cluster.login', 'anew')`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	mid := dbNow(t, h)
	time.Sleep(20 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.AsOf(ctx, "t1", mid, func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("restored")}})
		if err == nil && (len(grants) != 1 || grants[0].Note == "anew") {
			t.Errorf("as of %v, a restored grant, a change of which a transaction sharing its txid held open: %+v", mid, grants)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// A read as of a time counts none of its own transaction's changes, which haven't committed, but a
// change a restore carried from another cluster, of a txid this cluster has since given the
// reading transaction, committed there: taken for the reader's own, the restored grant read as
// never made.
func TestAsOfCountsAnotherClustersChangeOfItsOwnTxid(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	_, theirs := otherCluster(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "tmpl"))
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var txid string
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&txid); err != nil {
		t.Fatal(err)
	}
	restoreRows(t, h,
		fakeGrant(old.Format("2006-01-02 15:04:05"), theirs, txid),
		fakeCommit(old.Add(time.Second).Format("2006-01-02 15:04:05"), theirs, txid),
	)
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		grants, err := a.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("restored")}})
		if err == nil && len(grants) != 1 {
			t.Errorf("as of now, read in a transaction of the txid of a restored grant of another cluster: %+v", grants)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// History stamps each record with the cluster that wrote it, which it reads once a transaction and
// keeps in a setting, rbac.cluster, that any session can set as well: a revoke stamped with another
// cluster than its commit record would count from its own date, before it committed, as a restored
// change whose commit records are gone does, and AsOf of a moment while it was held open would read
// it as in force. The commit record checks every record of its transaction against the cluster the
// server names, so a transaction that set it commits nothing, whenever it set it.
func TestACommitRefusesRecordsStampedWithAnotherCluster(t *testing.T) {
	h := setup(t)
	_, theirs := otherCluster(t, h)
	set := func(local bool, cluster string) string {
		return fmt.Sprintf(`SELECT set_config('rbac.cluster', '%s', %t)`, cluster, local)
	}
	revoke := `DELETE FROM rbac_grants WHERE tenant = 't1' AND principal = 'user:u'`
	grantW := `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'w', 'cluster.login')`
	for _, c := range []struct {
		name    string
		queries []string
	}{
		{name: "set for the revoke alone", queries: []string{set(true, theirs), revoke, set(true, "")}},
		{name: "set for the transaction", queries: []string{set(true, theirs), revoke}},
		{name: "set for the session", queries: []string{set(false, theirs), revoke}},
		{name: "set in a savepoint released", queries: []string{`SAVEPOINT s`, set(true, theirs), revoke, `RELEASE SAVEPOINT s`, set(true, "")}},
		{name: "set after an early commit record", queries: []string{
			revoke, `SET CONSTRAINTS ALL IMMEDIATE`, set(true, theirs), grantW, set(true, ""),
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			u, w := h.as(t, "u"), h.as(t, "w")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
			conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
			for _, q := range slices.Concat([]string{`BEGIN`}, c.queries) {
				if _, err := conn.Exec(ctx, q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			time.Sleep(20 * time.Millisecond)
			mid := dbNow(t, h)
			h.now = mid
			time.Sleep(20 * time.Millisecond)
			_, err = conn.Exec(ctx, `COMMIT`)
			if pgErr := (*pgconn.PgError)(nil); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				// What it would have let through: the revoke, uncommitted as of mid, read as in force.
				held := h.authz.AsOf(ctx, "t1", mid, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) })
				t.Fatalf("a commit of records stamped with another cluster: %v; as of while it was held open, u's login: %v", err, held)
			}
			if err := h.authz.Authorize(ctx, u, login, cluster); err != nil {
				t.Errorf("after the commit was refused, u's login: %v", err)
			}
			if err := h.authz.Authorize(ctx, w, login, cluster); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("after the commit was refused, w's login: %v", err)
			}
		})
	}
}

// Versions of a row dated alike, as every write of a DO block, a function or a query string of
// several statements is, cost a read as of a time a few pages each, as versions dated apart do:
// tested for a later one in history's index of an entity's versions, which ordered those of one
// date by their places, oldest first, each read every one before it, so 4,000 of a membership from
// one block made a check read 743,745 pages of history, and 4,000 written apart 12,877.
func TestAsOfReadsVersionsDatedAlikeInAFewPagesEach(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u", "g")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "g"))
	const n = 2000
	if _, err := h.pool.Exec(ctx, fmt.Sprintf(`DO $$ BEGIN FOR i IN 1..%d LOOP
		UPDATE rbac_memberships SET note = i::text WHERE tenant = 't1' AND principal = 'user:u'; END LOOP; END $$`, n)); err != nil {
		t.Fatal(err)
	}
	var dates int
	if err := h.pool.QueryRow(ctx, `SELECT count(DISTINCT effective_at) FROM rbac_history WHERE entity = 'membership' AND key = 'user:u'`).Scan(&dates); err != nil || dates > 2 {
		t.Fatalf("the membership's versions are of %d dates, %v", dates, err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pages int64
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		start := historyPages(ctx, t, tx)
		err := a.Authorize(ctx, u, login, cluster)
		pages = historyPages(ctx, t, tx) - start
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if pages > 10*n {
		t.Errorf("a check as of now read %d pages of history beside %d versions of its subject's membership dated alike", pages, n)
	}
}

// As of a time, a check reads its subject's places in groups by their principal, a list of its
// groups too, and a list another principal's eligibilities by it, however history's statistics
// count them and however a session plans: by statistics from before the tenant's places and
// eligibilities were written, as autovacuum leaves them until a tenth of history is new, a plan read
// every one in the tenant by history's index of an entity's versions instead, so beside 3,000
// others' places a check of a subject in one group read 3,098 pages of history, and 65 by fresh
// statistics. A list of a group's members looks each one's membership up by its key: hashed, by
// such statistics, the test read every membership in the tenant, 15,848 pages, and 113 by fresh.
func TestAsOfReadsByPrincipalWhateverHistorysStatisticsCount(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	ctx := t.Context()
	u1 := h.as(t, "u1", "g1")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "g1"))
	exec := func(q string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	// Autovacuum would analyze history as it grows.
	exec(`ALTER TABLE rbac_history SET (autovacuum_enabled = off)`)
	// History large before it is analyzed, so what is written after is under a tenth of it.
	exec(`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 'zz', 'cluster', 'x' || i, 'user', 'o' || i, 'cluster.login' FROM generate_series(1, 100000) i`)
	exec(`ANALYZE rbac_history`)
	reads := map[string]func(a *rbac.Authorizer) error{
		"Authorize": func(a *rbac.Authorizer) error { return a.Authorize(ctx, u1, login, cluster) },
		"GroupsOf":  func(a *rbac.Authorizer) error { return second(a.GroupsOf(ctx, "t1", u1.Principal)) },
		"Members":   func(a *rbac.Authorizer) error { return second(a.Members(ctx, "t1", "g1")) },
		"Eligibilities": func(a *rbac.Authorizer) error {
			return second(a.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{u1.Principal}}))
		},
	}
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for _, mode := range []string{"auto", "force_generic_plan", "force_custom_plan"} {
			for what, f := range reads {
				func() {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
					if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, mode); err != nil {
						t.Fatal(err)
					}
					if err := h.authz.WithTx(tx).AsOf(ctx, "t1", time.Now(), func(a *rbac.Authorizer) error {
						start := historyPages(ctx, t, tx)
						err := f(a)
						pages[mode+" "+what] = historyPages(ctx, t, tx) - start
						return err
					}); err != nil {
						t.Fatalf("%s %s: %v", mode, what, err)
					}
				}()
			}
		}
		return pages
	}
	// Others' places in t1's groups, and their eligibilities, a few percent of history.
	exec(`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) SELECT 't1', 'user', 'o' || i FROM generate_series(1, 3000) i`)
	exec(`INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'og' || i FROM generate_series(1, 300) i`)
	exec(`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) SELECT 't1', 'og' || (i % 300 + 1), 'user', 'o' || i FROM generate_series(1, 3000) i`)
	exec(`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
		SELECT 't1', 'cluster', 'e' || i, 'user', 'o' || i, 'cluster.sudo', 3600 FROM generate_series(1, 300) i`)
	stale := read()
	exec(`ANALYZE rbac_history`)
	for what, analyzed := range read() {
		if stale[what] > analyzed*3/2+deeper {
			t.Errorf("as of a time, %s read %d pages of history by statistics from before 3,000 others' places and 300 eligibilities were written, and %d once it was analyzed", what, stale[what], analyzed)
		}
	}
}

// sqlState is the SQLSTATE of the PostgreSQL error err holds, or empty.
func sqlState(err error) string {
	if pg := (*pgconn.PgError)(nil); errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

// viewsOf is the schema of AsOf's views beside the schema of h's pool's connections, quoted.
func viewsOf(t *testing.T, h *harness) string {
	t.Helper()
	var views string
	if err := h.pool.QueryRow(t.Context(), `SELECT quote_ident(current_schema() || '_as_of')`).Scan(&views); err != nil {
		t.Fatal(err)
	}
	return views
}

// Each of AsOf's views, which migrating makes, reads history as AsOf has, by the SQL PruneHistory
// keeps the versions it reads by (byTime): changed there and not in a migration that makes the
// views again, it reads otherwise, and this fails. Every table of the package's but history and
// rbac_migrations has one.
func TestAsOfViewsReadHistoryAsPruningKeepsIt(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT current_schema()::text, t.relname::text, array_agg(a.attname::text ORDER BY a.attnum)
		FROM pg_class t JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE t.relnamespace = current_schema()::regnamespace AND t.relkind = 'r' AND t.relname NOT IN ('rbac_history', 'rbac_migrations', 'rbac_expired')
		GROUP BY t.relname ORDER BY t.relname`)
	if err != nil {
		t.Fatal(err)
	}
	type table struct {
		Schema, Name string
		Columns      []string
	}
	tables, err := pgx.CollectRows(rows, pgx.RowToStructByPos[table])
	if err != nil || len(tables) != 7 {
		t.Fatalf("the package's tables: %+v, %v", tables, err)
	}
	views := viewsOf(t, h)
	for _, tb := range tables {
		want := rbac.AsOfView(tb.Schema, tb.Name, tb.Columns)
		if want == "" {
			t.Errorf("%s is read by no view of history", tb.Name)
			continue
		}
		if _, err := tx.Exec(ctx, `CREATE TEMP VIEW `+tb.Name+` AS `+want); err != nil {
			t.Fatal(err)
		}
		var made, built string
		if err := tx.QueryRow(ctx, `SELECT pg_get_viewdef(($1 || '.' || $2)::regclass), pg_get_viewdef(('pg_temp.' || $2)::regclass)`,
			views, tb.Name).Scan(&made, &built); err != nil {
			t.Fatal(err)
		}
		if made != built {
			t.Errorf("the view of %s reads\n%s\nnot, as byTime reads history,\n%s", tb.Name, made, built)
		}
	}
}

// AsOf's views read history with the rights of whoever reads them, never with their owner's, the
// role that migrated, who may read all of it: a role that may read no history reads none through
// them, and one that a row security policy on history shows one tenant's alone reads only that
// tenant's, whatever tenant it sets them to read. They read history alone: in a session that never
// set what they read by, they fail, and once a read as of a time has run in it, they read nothing or
// fail, as with an empty cluster, never the tables.
func TestAsOfViewsReadWithTheReadersRights(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t2', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	at := dbNow(t, h)
	views := viewsOf(t, h)
	var invoker, owned int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE 'security_invoker=true' = ANY(reloptions)), count(*) FILTER (WHERE relowner = current_user::regrole)
		FROM pg_class WHERE relnamespace = $1::regnamespace AND relkind = 'v'`, views).Scan(&invoker, &owned); err != nil || invoker != 7 || owned != 7 {
		t.Fatalf("of 7 views, %d read with their reader's rights and %d are the migrating role's: %v", invoker, owned, err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// u's grants the views give, in a savepoint, as role where one is named, with nothing set for them
	// to read by, or set to read tenant as of at.
	grants := func(role, tenant string) (n int64, err error) {
		err = pgx.BeginFunc(ctx, tx, func(s pgx.Tx) error {
			if tenant != "" {
				if _, err := s.Exec(ctx, `SELECT set_config('rbac.as_of_tenant', $1, true),
					set_config('rbac.as_of', to_char($2::timestamptz AT TIME ZONE INTERVAL '00:00', 'YYYY-MM-DD HH24:MI:SS.US TZH BC'), true),
					set_config('rbac.as_of_cluster', (pg_control_system()).system_identifier::text, true)`, tenant, at); err != nil {
					return err
				}
			}
			if role != "" {
				if _, err := s.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
					return err
				}
			}
			return s.QueryRow(ctx, `SELECT count(*) FROM `+views+`.rbac_grants WHERE principal = 'user:u'`).Scan(&n)
		})
		return n, err
	}
	if n, err := grants("", ""); sqlState(err) != "42704" {
		t.Errorf("never set in the session, the views read %d of u's grants: %v", n, err)
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if n, err := grants("", ""); n != 0 || err != nil && sqlState(err) != "22P02" {
		t.Errorf("once a read as of a time has run in the session, the views read %d of u's grants, the tables 2: %v", n, err)
	}
	for _, tenant := range []string{"t1", "t2"} {
		if n, err := grants("", tenant); err != nil || n != 1 {
			t.Errorf("as the role that migrated, the views read %d of u's grants in %s: %v", n, tenant, err)
		}
	}
	reader, schema := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + `, ` + views + ` TO ` + reader,
		`GRANT SELECT ON ALL TABLES IN SCHEMA ` + views + ` TO ` + reader,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := grants(reader, "t1"); sqlState(err) != "42501" {
		t.Errorf("a role that may read no history reads it through the views: %v", err)
	}
	for _, sql := range []string{
		`GRANT SELECT ON rbac_history TO ` + reader,
		`ALTER TABLE rbac_history ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY t1 ON rbac_history FOR SELECT TO ` + reader + ` USING (tenant IN ('t1', ''))`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	for tenant, want := range map[string]int64{"t1": 1, "t2": 0} {
		if n, err := grants(reader, tenant); err != nil || n != want {
			t.Errorf("a role shown t1's history alone reads %d of u's grants in %s through the views, not %d: %v", n, tenant, want, err)
		}
	}
}

// A statement of AsOf's read that leaves the search_path set otherwise, or what its views read the
// tenant, the time or the cluster by, has the statements after it read another tenant or time, or
// the tables as they are now, so AsOf fails once read returns, the host's query and a hook's alike;
// one that a savepoint of its own sets and rolls back leaves AsOf's read as it was.
func TestAsOfFailsWhereItsReadSetsWhatItReadsBy(t *testing.T) {
	var hook string
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "sets", Deny: func(ctx context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			if hook == "" {
				return false, nil
			}
			_, err := q.Exec(ctx, hook)
			return false, err
		}}}
	})
	ctx := t.Context()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	for _, set := range []string{
		`SELECT set_config('search_path', current_schema() || ', pg_temp', true)`,
		`RESET search_path`,
		`RESET ALL`,
		`SELECT set_config('rbac.as_of_tenant', 't2', true)`,
		`SELECT set_config('rbac.as_of', '2000-01-01 00:00:00.000000 +00 AD', true)`,
		`SELECT set_config('rbac.as_of_cluster', '1', false)`,
	} {
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, by := range []string{"the host", "a hook"} {
			err := pgx.BeginFunc(ctx, tx, func(host pgx.Tx) error {
				return h.authz.WithTx(host).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
					if by == "a hook" {
						hook = set
						defer func() { hook = "" }()
					} else if _, err := host.Exec(ctx, set); err != nil {
						return err
					}
					// As a review records what each check answers, which stands only where AsOf
					// returns nil.
					_ = a.Authorize(ctx, owner, login, cluster)
					return nil
				})
			})
			if !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("a read in which %s ran %s: %v", by, set, err)
			}
		}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if err := pgx.BeginFunc(ctx, tx, func(s pgx.Tx) error {
				_, err := s.Exec(ctx, set)
				return errors.Join(err, errRolledBack)
			}); !errors.Is(err, errRolledBack) {
				return err
			}
			return a.Authorize(ctx, owner, login, cluster)
		}); err != nil {
			t.Errorf("a read that ran %s in a savepoint it rolled back: %v", set, err)
		}
		_ = tx.Rollback(ctx)
	}
}

var errRolledBack = errors.New("rolled back")

// AsOf reads its views first, and then the session's own tables before any schema's, as a
// search_path that doesn't name pg_temp reads them: one that names it, however written, is refused,
// as AsOf would read the session's tables before the package's, where the search_path names it
// after the package's schema, and where it names it before, the current schema is the session's.
func TestAsOfReadsTheSessionsTablesFirstAsTheSearchPathDoes(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT quote_ident(current_schema())`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for path, refused := range map[string]bool{
		schema:                             false,
		`"$user", nowhere,` + schema:       false,
		schema + `, "PG_TEMP"`:             false,
		`pg_temp, ` + schema:               true,
		`nowhere,pg_temp ,` + schema:       true,
		`"$user", ` + schema + `, pg_temp`: true,
		schema + `, "pg_temp"`:             true,
		schema + `,PG_TEMP`:                true,
	} {
		err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('search_path', $1, true)`, path); err != nil {
				return err
			}
			return h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) })
		})
		if refused && !errors.Is(err, rbac.ErrInvalid) || !refused && err != nil {
			t.Errorf("as of when u held its login, with the search_path %s: %v", path, err)
		}
	}
}

// AsOf reads each of the package's tables by its view, which migrating makes: where one is missing,
// or the schema of them is, or the role reading has no USAGE on it, which the search_path then
// leaves out, it refuses, rather than read that table as it is now. Made again, as a migration that
// changes a table makes them, having dropped the view of a column it drops or retypes, rbac_grants's
// too, they are read again, in the schema the views left stand in.
func TestAsOfReadsNoTableWithoutItsView(t *testing.T) {
	h, guardian := guarded(t)
	ctx := t.Context()
	u := h.as(t, "u")
	at := dbNow(t, h)
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{u.Principal}, Permissions: []rbac.Permission{root}}); err != nil {
		t.Fatal(err)
	}
	views := viewsOf(t, h)
	read := func() error {
		return h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			if denies, err := a.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()}); err != nil || len(denies) != 0 {
				return fmt.Errorf("as of before the deny, Denies = %+v, %w", denies, err)
			}
			return nil
		})
	}
	for _, drop := range []string{`DROP VIEW ` + views + `.rbac_denies`, `DROP VIEW ` + views + `.rbac_grants`, `DROP SCHEMA ` + views + ` CASCADE`} {
		if _, err := h.pool.Exec(ctx, drop); err != nil {
			t.Fatal(err)
		}
		if err := read(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("after %s: %v", drop, err)
		}
		if _, err := h.pool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
			t.Fatalf("making the views again after %s: %v", drop, err)
		}
		if err := read(); err != nil {
			t.Errorf("with the views made again after %s: %v", drop, err)
		}
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	reader, schema := role(t, tx)
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + reader,
		`GRANT SELECT ON ALL TABLES IN SCHEMA ` + pgx.Identifier{schema}.Sanitize() + `, ` + views + ` TO ` + reader,
		`SET LOCAL ROLE ` + reader,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error { return nil }); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("as a role with no USAGE on the views' schema: %v", err)
	}
}

// AsOf's read takes no transaction id, on a transaction of its own or a host's that has taken none,
// so History and Export read a change that commits while it runs, as they read no record of a
// transaction that took its id after one still running.
func TestAsOfHoldsNoExportBack(t *testing.T) {
	var held []*string
	h := setup(t, func(c *rbac.Config) {
		c.Constraints = []rbac.Constraint{{Name: "xid", Deny: func(ctx context.Context, q rbac.DB, _ rbac.ConstraintInput) (bool, error) {
			var xid *string
			err := q.QueryRow(ctx, `SELECT pg_current_xact_id_if_assigned()::text`).Scan(&xid)
			held = append(held, xid)
			return false, err
		}}}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	owner := h.as(t, "owner")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Exported to the end, as of now.
	checkpoint := rbac.Checkpoint{}
	for {
		records, next, err := h.authz.Export(ctx, checkpoint, rbac.MaxHistory, key)
		if err != nil {
			t.Fatal(err)
		}
		if checkpoint = next; len(records) == 0 {
			break
		}
	}
	at := dbNow(t, h)
	for i, onHosts := range []bool{false, true} {
		reading, release := make(chan error, 1), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			read := func(a *rbac.Authorizer) error {
				held = nil
				err := a.Authorize(ctx, owner, login, cluster)
				if err == nil && (len(held) == 0 || held[0] != nil) {
					err = fmt.Errorf("a check in the read ran in transaction %v", held)
				}
				reading <- err
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if !onHosts {
				done <- h.authz.AsOf(ctx, "t1", at, read)
				return
			}
			done <- pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error { return h.authz.WithTx(tx).AsOf(ctx, "t1", at, read) })
		}()
		select {
		case err := <-reading:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		// A change committed while the read runs, which History reads once every transaction in the
		// cluster older than it has ended, as other sessions sharing it can hold one for a while.
		principal := fmt.Sprint("u", i)
		h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, principal))
		for exported := false; !exported; {
			got, next, err := h.authz.Export(ctx, checkpoint, rbac.MaxHistory, key)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, exported = next, slices.ContainsFunc(got, func(r rbac.Record) bool { return r.Principal.ID == principal })
			if len(got) > 0 {
				continue
			}
			select {
			case <-time.After(10 * time.Millisecond):
			case <-ctx.Done():
				t.Fatalf("on the host's transaction %t, a change committed while AsOf read wasn't exported while it read: %v", onHosts, ctx.Err())
			}
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

// AsOf names the schema of its views first on its search_path, where a function, operator or type
// is found before the package's or the session's and called as whoever reads: it refuses that
// schema where another role may create in it, where it holds more than its owner's views, as a
// function made there that would be called in place of rbac_group_members, a type or another
// role's view, or where it is another role's than the package's tables', as each can come to be
// since migrating checked it. Its default privileges hold no object, and are read past.
func TestAsOfRefusesAViewsSchemaOthersCanMakeObjectsIn(t *testing.T) {
	h := setup(t)
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	views := viewsOf(t, h)
	for _, c := range []struct {
		what    string
		made    func(other string) []string
		refused bool
	}{
		{"CREATE granted to another role", func(other string) []string {
			return []string{`GRANT CREATE ON SCHEMA ` + views + ` TO ` + other}
		}, true},
		{"a function called in place of rbac_group_members", func(string) []string {
			return []string{`CREATE FUNCTION ` + views + `.rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
				RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE sql AS $$ SELECT 'ops', 'user:planted', false $$`}
		}, true},
		{"a type", func(string) []string { return []string{`CREATE TYPE ` + views + `.planted AS (a int)`} }, true},
		{"another role's view", func(other string) []string {
			return []string{
				`GRANT USAGE, CREATE ON SCHEMA ` + views + ` TO ` + other, `SET LOCAL ROLE ` + other,
				`CREATE VIEW ` + views + `.planted AS SELECT 1 AS a`, `RESET ROLE`, `REVOKE CREATE ON SCHEMA ` + views + ` FROM ` + other,
			}
		}, true},
		{"another role's schema", func(other string) []string { return []string{`ALTER SCHEMA ` + views + ` OWNER TO ` + other} }, true},
		{"default privileges", func(other string) []string {
			return []string{`ALTER DEFAULT PRIVILEGES IN SCHEMA ` + views + ` GRANT SELECT ON TABLES TO ` + other}
		}, false},
	} {
		t.Run(c.what, func(t *testing.T) {
			ctx := t.Context()
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			other, _ := role(t, tx)
			for _, sql := range c.made(other) {
				if _, err := tx.Exec(ctx, sql); err != nil {
					t.Fatalf("%s: %v", sql, err)
				}
			}
			read := false
			err = h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
				read = true
				return a.Authorize(ctx, owner, login, cluster)
			})
			if c.refused && (!errors.Is(err, rbac.ErrInvalid) || read) || !c.refused && err != nil {
				t.Errorf("with %s in the views' schema, AsOf read %t: %v", c.what, read, err)
			}
		})
	}
}

// A statement looks a name up by the catalog as it is, at any isolation, not by its transaction's
// snapshot, so what another session makes in the views' schema, or drops from it, as AsOf reads
// takes effect at the read's next statement: a function made there in place of rbac_group_members
// is called, and a table whose view is dropped is read as it is now. AsOf fails once read returns,
// whether it reads on a transaction of its own, which is REPEATABLE READ, so that a query of the
// catalog in it reads past what was made since, or under WithTx at READ COMMITTED or REPEATABLE
// READ.
func TestAsOfFailsWhereItsViewsSchemaChangesAsItReads(t *testing.T) {
	h := setup(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h.groups(t, "ops")
	u := h.as(t, "u")
	h.as(t, "planted")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "ops"), grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	views := viewsOf(t, h)
	exec := func(sql string) error {
		_, err := h.pool.Exec(ctx, sql)
		return err
	}
	planted := func(a *rbac.Authorizer) (bool, error) {
		if err := exec(`CREATE FUNCTION ` + views + `.rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
			RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE sql AS $$ SELECT 'ops', 'user:planted', false $$`); err != nil {
			return false, err
		}
		hs, err := a.Holders(ctx, login, cluster)
		return slices.Contains(holderPrincipals(hs), identity("planted")), err
	}
	// As of then, u held login itself, which it no longer does.
	dropped := func(a *rbac.Authorizer) (bool, error) {
		if err := exec(`DROP VIEW ` + views + `.rbac_grants`); err != nil {
			return false, err
		}
		err := a.Authorize(ctx, u, login, cluster)
		return errors.Is(err, rbac.ErrDenied), nil
	}
	for _, c := range []struct {
		what   string
		on     pgx.TxIsoLevel
		during func(*rbac.Authorizer) (bool, error)
	}{
		{"a function made in place of rbac_group_members, on its own transaction", "", planted},
		{"a function made in place of rbac_group_members, under a host's transaction at READ COMMITTED", pgx.ReadCommitted, planted},
		{"rbac_grants's view dropped, under a host's transaction at REPEATABLE READ", pgx.RepeatableRead, dropped},
	} {
		t.Run(c.what, func(t *testing.T) {
			t.Cleanup(func() {
				for _, sql := range []string{`DROP FUNCTION IF EXISTS ` + views + `.rbac_group_members`, `SELECT rbac_as_of_views()`} {
					if _, err := h.pool.Exec(context.WithoutCancel(ctx), sql); err != nil {
						t.Errorf("%s: %v", sql, err)
					}
				}
			})
			changed := false
			read := func(a *rbac.Authorizer) error {
				var err error
				changed, err = c.during(a)
				return err
			}
			var err error
			if c.on == "" {
				err = h.authz.AsOf(ctx, "t1", at, read)
			} else {
				err = pgx.BeginTxFunc(ctx, h.pool, pgx.TxOptions{IsoLevel: c.on}, func(tx pgx.Tx) error {
					return h.authz.WithTx(tx).AsOf(ctx, "t1", at, read)
				})
			}
			if !changed {
				t.Errorf("a read with %s read as before: %v", c.what, err)
			}
			if !errors.Is(err, rbac.ErrInvalid) {
				t.Errorf("a read with %s: %v", c.what, err)
			}
		})
	}
}

// AsOf's views stand in for the package's tables only while the role reading has USAGE on their
// schema, which a search_path leaves out otherwise, reading the tables as they are now: a read
// during which another session revokes it, or that leaves the session's role one without it, as a
// SET ROLE can, fails AsOf once it returns, as one that leaves the search_path set otherwise does.
func TestAsOfFailsWhereItsReadLeavesItsViewsOffTheSearchPath(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	views := viewsOf(t, h)
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT quote_ident(current_schema())`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// A role of the test's own, which another session revokes from as the read runs.
	reader := pgx.Identifier{"rbac_test_" + strings.ToLower(rand.Text())}.Sanitize()
	exec := func(sql string) {
		t.Helper()
		if _, err := h.pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`CREATE ROLE ` + reader)
	t.Cleanup(func() {
		for _, sql := range []string{`DROP OWNED BY ` + reader, `DROP ROLE ` + reader} {
			if _, err := h.pool.Exec(context.WithoutCancel(ctx), sql); err != nil {
				t.Errorf("%s: %v", sql, err)
			}
		}
	})
	exec(`GRANT USAGE ON SCHEMA ` + schema + `, ` + views + ` TO ` + reader)
	exec(`GRANT SELECT ON ALL TABLES IN SCHEMA ` + schema + `, ` + views + ` TO ` + reader)
	for _, c := range []struct {
		what, as string
		during   func(host pgx.Tx) error
	}{
		{"another session revokes USAGE on the views' schema", reader, func(pgx.Tx) error {
			_, err := h.pool.Exec(ctx, `REVOKE USAGE ON SCHEMA `+views+` FROM `+reader)
			return err
		}},
		{"the host sets the role to one without it", "", func(host pgx.Tx) error {
			_, err := host.Exec(ctx, `SET LOCAL ROLE `+reader)
			return err
		}},
	} {
		err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if c.as != "" {
				if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+c.as); err != nil {
					return err
				}
			}
			return h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
				if err := c.during(tx); err != nil {
					return err
				}
				// As a review records what each check answers, which stands only where AsOf returns
				// nil: read as the tables are now, u holds no login.
				_ = a.Authorize(ctx, u, login, cluster)
				return nil
			})
		})
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a read in which %s: %v", c.what, err)
		}
	}
}

// AsOf under WithTx reads in a savepoint of the host's transaction, which it makes READ ONLY and
// rolls back whether read returns, fails, panics or its context ends: whatever the host's
// transaction is, READ COMMITTED, REPEATABLE READ, SERIALIZABLE, READ ONLY or SERIALIZABLE READ
// ONLY DEFERRABLE, each setting is as it was, the search_path, the role, AsOf's own and the
// package's, JIT and the planner's among them, no transaction id is taken, and one that may write
// writes.
func TestAsOfLeavesTheHostsSettingsAsTheyWere(t *testing.T) {
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"))
	// A SERIALIZABLE READ ONLY DEFERRABLE transaction waits for the serializable ones running on the
	// server to end.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	owner := h.as(t, "owner")
	at := dbNow(t, h)
	// Once before, so each variable a read sets is one the session has.
	if err := h.authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, owner, login, cluster) }); err != nil {
		t.Fatal(err)
	}
	settings := func(tx pgx.Tx) []string {
		t.Helper()
		var s []string
		if err := tx.QueryRow(ctx, `SELECT array_agg(name || '=' || setting ORDER BY name) || ARRAY[
			  'rbac.as_of_tenant=' || current_setting('rbac.as_of_tenant'), 'rbac.as_of=' || current_setting('rbac.as_of'),
			  'rbac.as_of_cluster=' || current_setting('rbac.as_of_cluster'), 'rbac.jit=' || coalesce(current_setting('rbac.jit', true), 'unset'),
			  'rbac.enable_seqscan=' || coalesce(current_setting('rbac.enable_seqscan', true), 'unset'),
			  'rbac.enable_sort=' || coalesce(current_setting('rbac.enable_sort', true), 'unset'),
			  'current_user=' || current_user, 'current_schema=' || current_schema(), 'rbac_grants=' || 'rbac_grants'::regclass::text,
			  'xid=' || coalesce(pg_current_xact_id_if_assigned()::text, 'none')]
			FROM pg_settings`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	failed := errors.New("read failed")
	for _, mode := range []pgx.TxOptions{
		{IsoLevel: pgx.ReadCommitted},
		{IsoLevel: pgx.RepeatableRead},
		{IsoLevel: pgx.Serializable},
		{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly, DeferrableMode: pgx.Deferrable},
	} {
		for _, end := range []string{"returns", "fails", "panics", "ends its context"} {
			func() {
				tx, err := h.pool.BeginTx(ctx, mode)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
				// The host's own, AsOf's settings too, as a session that set them itself has them.
				if _, err := tx.Exec(ctx, `SELECT set_config('search_path', current_setting('search_path') || ', public', true),
					set_config('plan_cache_mode', 'force_generic_plan', true), set_config('jit', 'on', true),
					set_config('enable_seqscan', 'off', true), set_config('rbac.as_of_tenant', 'host', true),
					set_config('rbac.as_of', 'host', true), set_config('rbac.as_of_cluster', 'host', true)`); err != nil {
					t.Fatal(err)
				}
				before := settings(tx)
				readCtx, cancelRead := context.WithCancel(ctx)
				defer cancelRead()
				func() {
					defer func() { _ = recover() }()
					err := h.authz.WithTx(tx).AsOf(readCtx, "t1", at, func(a *rbac.Authorizer) error {
						if err := a.Authorize(readCtx, owner, login, cluster); err != nil {
							return err
						}
						switch end {
						case "fails":
							return failed
						case "panics":
							panic(failed)
						case "ends its context":
							cancelRead()
						}
						return nil
					})
					if want := map[string]error{"fails": failed}[end]; !errors.Is(err, want) {
						t.Errorf("in a host's transaction %+v, a read that %s: %v", mode, end, err)
					}
				}()
				if after := settings(tx); !slices.Equal(after, before) {
					var changed []string
					for _, s := range after {
						if !slices.Contains(before, s) {
							changed = append(changed, s)
						}
					}
					t.Errorf("in a host's transaction %+v, after a read that %s, %v", mode, end, changed)
				}
				_, err = tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', 'c1', 'user', 'w', 'cluster.login')`)
				if mode.AccessMode == pgx.ReadOnly && sqlState(err) != "25006" || mode.AccessMode != pgx.ReadOnly && err != nil {
					t.Errorf("in a host's transaction %+v, a write after a read that %s: %v", mode, end, err)
				}
			}()
		}
	}
}

// AsOf finds its views by the history they read, whatever either schema is named: renamed, the
// package's schema and the views' are read on, and the views made again, as a later migration
// makes them, stand where they did, not in a schema named after the package's new name.
func TestAsOfReadsItsViewsWhateverEitherSchemaIsNamed(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	if err := h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	rename := func(from, to string) error {
		_, err := h.pool.Exec(context.WithoutCancel(ctx), `ALTER SCHEMA `+pgx.Identifier{from}.Sanitize()+` RENAME TO `+pgx.Identifier{to}.Sanitize())
		return err
	}
	renamed := map[string]string{schema: schema + "_renamed", schema + "_as_of": schema + "_views"}
	for from, to := range renamed {
		if err := rename(from, to); err != nil {
			t.Fatal(err)
		}
		// Before the pool's cleanup drops both by their names.
		t.Cleanup(func() {
			if err := rename(to, from); err != nil {
				t.Error(err)
			}
		})
	}
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('search_path', quote_ident($1), true)`, renamed[schema]); err != nil {
			return err
		}
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) }); err != nil {
			return fmt.Errorf("as of when u held its login, with both schemas renamed: %w", err)
		}
		if _, err := tx.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
			return err
		}
		var views []string
		if err := tx.QueryRow(ctx, `SELECT array_agg(DISTINCT n.nspname::text) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind = 'v' AND c.relname = 'rbac_grants' AND n.nspname IN ($1, $2, $3)`,
			renamed[schema+"_as_of"], renamed[schema]+"_as_of", schema+"_as_of").Scan(&views); err != nil {
			return err
		}
		if want := []string{renamed[schema+"_as_of"]}; !slices.Equal(views, want) {
			return fmt.Errorf("made again, the views stand in %v, not %v", views, want)
		}
		return nil
	}); err != nil {
		t.Error(err)
	}
}

// AsOf's views stand in a schema named as the package's with _as_of after, which PostgreSQL cuts to
// 63 bytes: beside a package's schema named in 57, migrating makes them in a schema named so, and
// one named in more is refused before anything is made, by migrating, or by rbac_as_of_views where
// the views are gone after a rename to such a name, which AsOf reads by while they stand; AsOf,
// finding none, says to rename it. Named in 58 to 62 bytes, the views stood in a schema named
// otherwise, and in 63, their schema was the package's own, which migrating refused as holding
// more than the views.
func TestAsOfsViewsStandBesideNoSchemaNamedTooLongForTheirs(t *testing.T) {
	ctx := t.Context()
	super, err := pgx.Connect(ctx, pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.WithoutCancel(ctx)) })
	quoted := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	exec := func(t *testing.T, sql string) {
		t.Helper()
		if _, err := super.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// dropping drops, once t ends, the schema name and the one its views' would be, as PostgreSQL
	// cuts that name.
	dropping := func(t *testing.T, name string) {
		t.Helper()
		drop := []string{quoted(name)}
		if views := (name + "_as_of")[:min(len(name)+len("_as_of"), 63)]; views != name {
			drop = append(drop, quoted(views))
		}
		t.Cleanup(func() {
			if _, err := super.Exec(context.WithoutCancel(ctx), `DROP SCHEMA IF EXISTS `+strings.Join(drop, ", ")+` CASCADE`); err != nil {
				t.Error(err)
			}
		})
	}
	// schema makes a schema named in n bytes, and returns its name and a pool on it.
	schema := func(t *testing.T, n int) (string, *pgxpool.Pool) {
		t.Helper()
		name := "rbac_" + strings.ToLower(rand.Text())
		name += strings.Repeat("x", n-len(name))
		exec(t, `CREATE SCHEMA `+quoted(name))
		dropping(t, name)
		return name, superuserOn(t, quoted(name))
	}
	// schemas are the schemas named from prefix.
	schemas := func(t *testing.T, prefix string) []string {
		t.Helper()
		var names []string
		if err := super.QueryRow(ctx, `SELECT coalesce(array_agg(nspname::text ORDER BY nspname), '{}') FROM pg_namespace
			WHERE starts_with(nspname::text, $1)`, prefix).Scan(&names); err != nil {
			t.Fatal(err)
		}
		return names
	}
	const rename = "rename it to a name of at most 57 bytes"

	t.Run("57 bytes", func(t *testing.T) {
		ctx := t.Context()
		name, pool := schema(t, 57)
		h := setupOn(t, pool)
		owner := h.as(t, "owner")
		at := dbNow(t, h)
		reads := func(authz *rbac.Authorizer) error {
			return authz.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, owner, login, cluster) })
		}
		var stand bool
		if err := super.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = 'rbac_grants' AND c.relkind = 'v')`, name+"_as_of").Scan(&stand); err != nil || !stand {
			t.Fatalf("the views stand in %s: %t, %v", name+"_as_of", stand, err)
		}
		if err := reads(h.authz); err != nil {
			t.Fatalf("as of when owner held its role: %v", err)
		}
		// Renamed to 58 bytes, the package's schema is read by its views as they stand.
		longer := name + "y"
		dropping(t, longer)
		exec(t, `ALTER SCHEMA `+quoted(name)+` RENAME TO `+quoted(longer))
		long := superuserOn(t, quoted(longer))
		authz, err := rbac.New(long, h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := reads(authz); err != nil {
			t.Errorf("as of when owner held its role, with the package's schema renamed to 58 bytes: %v", err)
		}
		// Gone, they aren't made again beside it, and AsOf says to rename it.
		exec(t, `DROP SCHEMA `+quoted(name+"_as_of")+` CASCADE`)
		if _, err := long.Exec(ctx, `SELECT rbac_as_of_views()`); sqlState(err) != "42622" {
			t.Errorf("making the views again beside a schema named in 58 bytes: %v", err)
		}
		if made := schemas(t, name); !slices.Equal(made, []string{longer}) {
			t.Errorf("making the views again beside a schema named in 58 bytes left schemas %v", made)
		}
		if err := reads(authz); !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), rename) {
			t.Errorf("as of a time, with no views beside a schema named in 58 bytes: %v", err)
		}
		// Renamed back, they are made again in the schema named after it.
		exec(t, `ALTER SCHEMA `+quoted(longer)+` RENAME TO `+quoted(name))
		if _, err := pool.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
			t.Fatal(err)
		}
		if err := reads(h.authz); err != nil {
			t.Errorf("as of when owner held its role, with the views made again: %v", err)
		}
	})

	_, version := madeViews(t)
	for _, n := range []int{58, 63} {
		t.Run(fmt.Sprint(n, " bytes"), func(t *testing.T) {
			ctx := t.Context()
			name, pool := schema(t, n)
			if err := rbac.Migrate(ctx, pool); sqlState(err) != "42622" {
				t.Fatalf("migrating a schema named in %d bytes: %v", n, err)
			}
			if v := migratedTo(t, pool); v != version-1 {
				t.Errorf("migrated to %d", v)
			}
			if made := schemas(t, name); !slices.Equal(made, []string{name}) {
				t.Errorf("migrating a schema named in %d bytes left schemas %v", n, made)
			}
			authz, err := rbac.New(pool, rbac.Config{
				Catalog: catalog, ContainerTypes: []string{"org", "workspace"},
				ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			err = authz.AsOf(ctx, "t1", time.Now(), func(*rbac.Authorizer) error { return nil })
			if !errors.Is(err, rbac.ErrInvalid) || !strings.Contains(err.Error(), rename) {
				t.Errorf("as of a time, beside a schema named in %d bytes: %v", n, err)
			}
		})
	}
}

// AsOf finds its views among those of the role owning the package's tables, as migrating finds
// them among the role's that migrates, outside every session's temporary schema: a view of history
// named as one of the tables, made in its temporary schema by another session, as any role with
// TEMPORARY that may read history can, or by the session reading, or another role's in a schema of
// its own, stood beside them, and every read as of a time in the database was refused while it
// stood, as was making the views again.
func TestAsOfFindsItsViewsWhateverViewsOfHistoryOthersMake(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	u := h.as(t, "u")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "u"))
	at := dbNow(t, h)
	var schema string
	if err := h.pool.QueryRow(ctx, `SELECT quote_ident(current_schema())`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	views := viewsOf(t, h)
	over := `CREATE TEMPORARY VIEW rbac_grants AS SELECT id FROM ` + schema + `.rbac_history`
	for _, c := range []struct {
		what string
		made func(t *testing.T, tx pgx.Tx) []string
	}{
		{"another session's temporary view", func(t *testing.T, _ pgx.Tx) []string {
			t.Helper()
			other, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Close(context.WithoutCancel(ctx)) })
			if _, err := other.Exec(ctx, over); err != nil {
				t.Fatal(err)
			}
			return nil
		}},
		{"the reading session's temporary view", func(*testing.T, pgx.Tx) []string { return []string{over} }},
		{"another role's view in a schema of its own", func(t *testing.T, tx pgx.Tx) []string {
			t.Helper()
			other, _ := role(t, tx)
			planted := pgx.Identifier{"planted_" + strings.ToLower(rand.Text())}.Sanitize()
			return []string{
				`CREATE SCHEMA ` + planted + ` AUTHORIZATION ` + other,
				`GRANT USAGE ON SCHEMA ` + schema + ` TO ` + other, `GRANT SELECT ON ` + schema + `.rbac_history TO ` + other,
				`SET LOCAL ROLE ` + other, `CREATE VIEW ` + planted + `.rbac_grants AS SELECT id FROM ` + schema + `.rbac_history`, `RESET ROLE`,
			}
		}},
	} {
		t.Run(c.what, func(t *testing.T) {
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
			for _, sql := range c.made(t, tx) {
				if _, err := tx.Exec(ctx, sql); err != nil {
					t.Fatalf("%s: %v", sql, err)
				}
			}
			if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error { return a.Authorize(ctx, u, login, cluster) }); err != nil {
				t.Errorf("as of when u held its login, beside %s: %v", c.what, err)
			}
			if _, err := tx.Exec(ctx, `SELECT rbac_as_of_views()`); err != nil {
				t.Errorf("making the views again beside %s: %v", c.what, err)
			}
			var stand bool
			if err := tx.QueryRow(ctx, `SELECT to_regclass($1 || '.rbac_grants') IS NOT NULL`, views).Scan(&stand); err != nil || !stand {
				t.Errorf("made again beside %s, the views stand in %s: %t, %v", c.what, views, stand, err)
			}
		})
	}
}
