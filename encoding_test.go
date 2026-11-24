package rbac_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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

// latin1 is an Authorizer like h's on a pool whose sessions set client_encoding to LATIN1 as they
// connect, as a host's AfterConnect can: pgx sends text as UTF-8 all the same, and doesn't check
// the setting again, so PostgreSQL converts what it is sent, "josé" into "josÃ©".
func latin1(t *testing.T, h *harness) (*rbac.Authorizer, *pgxpool.Pool) {
	t.Helper()
	cfg := h.pool.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SET client_encoding = 'LATIN1'`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	a, err := rbac.New(pool, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a, pool
}

// The public holds login on the org, and guardian sets denies: a deny naming josé, which a session
// converting the id would store or look up as another, is all that keeps josé out.
func accented(t *testing.T) (h *harness, jose, guardian rbac.Subject) {
	t.Helper()
	open := rbac.RoleDefinition{ID: "cluster.open", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}, Public: true}
	h, guardian = guarded(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), open) })
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.open", rbac.Public, ""))
	return h, h.as(t, "josé"), guardian
}

// storedDeny checks that the deny on the cluster names josé, which keeps it out, and that history
// records it for the reason given, as a session in UTF8 reads them.
func storedDeny(t *testing.T, h *harness, jose rbac.Subject) {
	t.Helper()
	var stored []string
	if err := h.pool.QueryRow(t.Context(), `SELECT coalesce(array_agg(p), '{}') FROM rbac_denies, unnest(principals) p`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored, []string{"user:josé"}) {
		t.Errorf("the deny names %q, not user:josé", stored)
	}
	if allowed(t, h, jose, login, cluster) {
		t.Error("josé may log in to the cluster the deny denies it")
	}
	// Another session's open transaction can hold the record back from History a while.
	var records []rbac.Record
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var err error
		if records, _, err = h.authz.History(t.Context(), rbac.Cursor{}, rbac.MaxHistory); err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(records, func(r rbac.Record) bool { return r.Entity == "deny" }) || time.Now().After(deadline) {
			break
		}
	}
	found := false
	for _, r := range records {
		if r.Entity != "deny" {
			continue
		}
		found = true
		if r.Reason != "café" || !strings.Contains(string(r.After), `"user:josé"`) {
			t.Errorf("history records the deny %s for %q, not naming user:josé for café", r.After, r.Reason)
		}
	}
	if !found {
		t.Error("history records no deny")
	}
}

func TestAChangeOnASessionInAnotherClientEncodingStoresWhatItWasGiven(t *testing.T) {
	h, jose, guardian := accented(t)
	la, _ := latin1(t, h)
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Reason: "café"})
	if err := la.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	storedDeny(t, h, jose)
}

// Under WithTx the change sets the encoding in its savepoint and puts the host's back.
func TestAChangeInAHostsTransactionInAnotherClientEncodingStoresWhatItWasGiven(t *testing.T) {
	h, jose, guardian := accented(t)
	la, pool := latin1(t, h)
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Reason: "café"})
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := la.WithTx(tx).SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
			return err
		}
		var encoding string
		if err := tx.QueryRow(ctx, `SELECT current_setting('client_encoding')`).Scan(&encoding); err != nil {
			return err
		}
		if encoding != "LATIN1" {
			t.Errorf("after the change the host's transaction is in %s, not LATIN1", encoding)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	storedDeny(t, h, jose)
	// And where the change fails, its savepoint rolled back puts it back too.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		err := la.WithTx(tx).SetDeny(ctx, jose, cluster, rbac.Deny{ID: "e", Principals: []rbac.Principal{guardian.Principal}, Permissions: []rbac.Permission{login}})
		if !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("josé, who may set no deny, set one: %v", err)
		}
		var encoding string
		if err := tx.QueryRow(ctx, `SELECT current_setting('client_encoding')`).Scan(&encoding); err != nil {
			return err
		}
		if encoding != "LATIN1" {
			t.Errorf("after the refused change the host's transaction is in %s, not LATIN1", encoding)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAReadOnASessionInAnotherClientEncodingFindsWhatItsKeysName(t *testing.T) {
	h, jose, guardian := accented(t)
	ctx := t.Context()
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	la, _ := latin1(t, h)
	if err := la.Authorize(ctx, jose, login, cluster); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("on a LATIN1 session, josé may log in to the cluster the deny denies it: %v", err)
	}
	reach, err := la.Reachable(ctx, jose, login, "t1", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(reach.Except, cluster.Scope()) {
		t.Errorf("on a LATIN1 session, Reachable excepts %v, not the denied cluster", reach.Except)
	}
	ds, err := la.Denies(ctx, "t1", []rbac.Scope{cluster.Scope()})
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || !slices.Equal(ds[0].Principals, []rbac.Principal{jose.Principal}) {
		t.Errorf("on a LATIN1 session, Denies lists %+v, not the deny naming josé", ds)
	}
}

func TestHistoryAndAsOfOnASessionInAnotherClientEncodingReadWhatIsStored(t *testing.T) {
	h, jose, guardian := accented(t)
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Reason: "café"})
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	la, _ := latin1(t, h)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Exported on a session in UTF8 first, which also waits for the deny's record to be readable.
	want, checkpoints := exportAll(t, h, key)
	utf8 := checkpoints[len(checkpoints)-1]
	got, _, err := la.History(ctx, rbac.Cursor{}, rbac.MaxHistory)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("on a LATIN1 session, History reads %d records, not %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Principal != want[i].Principal || got[i].Actor != want[i].Actor || got[i].Reason != want[i].Reason || string(got[i].After) != string(want[i].After) {
			t.Errorf("on a LATIN1 session, History reads %+v, not %+v", got[i], want[i])
		}
	}
	lh := *h
	lh.authz = la
	records, checkpoints := exportAll(t, &lh, key)
	last := checkpoints[len(checkpoints)-1]
	if err := rbac.VerifyChain(rbac.Genesis(last.Cursor.Generation), records, last, key.Public()); err != nil {
		t.Errorf("an export on a LATIN1 session: %v", err)
	}
	if last.Hash != utf8.Hash || last.Count != utf8.Count {
		t.Errorf("an export on a LATIN1 session chains %d records to %x, where one on a UTF8 session chains %d to %x", last.Count, last.Hash, utf8.Count, utf8.Hash)
	}
	if err := la.AsOf(t.Context(), "t1", time.Now(), func(a *rbac.Authorizer) error {
		if err := a.Authorize(ctx, jose, login, cluster); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("as of now, on a LATIN1 session, josé may log in to the cluster the deny denies it: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// AsOf's reads of history's views run outside a batch, in the encoding its transaction set: a read
// that sets another, as the host's statement on its transaction under WithTx can, has the reads
// after it look josé up converted and miss the deny, so AsOf fails as the read returns.
func TestAnAsOfReadThatSetsAnotherClientEncodingFails(t *testing.T) {
	h, jose, guardian := accented(t)
	ctx := t.Context()
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{`SET LOCAL client_encoding = 'LATIN1'`, `SET client_encoding = 'LATIN1'`} {
		err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			return h.authz.WithTx(tx).AsOf(ctx, "t1", time.Now(), func(a *rbac.Authorizer) error {
				if _, err := tx.Exec(ctx, set); err != nil {
					return err
				}
				_ = a.Authorize(ctx, jose, login, cluster)
				return nil
			})
		})
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("a read ran %s, and AsOf returned %v, not ErrInvalid", set, err)
		}
	}
}

// Filter's condition runs in the host's session, whose arguments PostgreSQL converts: in another
// encoding than UTF8 it keeps no row.
func TestFiltersConditionInAnotherClientEncodingKeepsNoRow(t *testing.T) {
	h, jose, guardian := accented(t)
	ctx := t.Context()
	hostTable(t, h)
	if err := h.authz.SetDeny(ctx, guardian, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{jose.Principal}, Permissions: []rbac.Permission{login}}); err != nil {
		t.Fatal(err)
	}
	_, pool := latin1(t, h)
	for name, p := range map[string]*pgxpool.Pool{"UTF8": h.pool, "LATIN1": pool} {
		pred, err := h.authz.Filter(ctx, jose, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := p.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		kept, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"c0"}
		if name == "LATIN1" {
			want = nil
		}
		if !slices.Equal(kept, want) {
			t.Errorf("on a %s session the condition keeps %q, not %q", name, kept, want)
		}
	}
}

// A schema whose name isn't ASCII, migrated and read as of a time on a LATIN1 session: Migrate
// finds it by its name, and AsOf checks its views' schema by it once the read has rolled back.
func TestASchemaNamedInAnotherClientEncodingMigratesAndIsReadAsOfATime(t *testing.T) {
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	name := "tést_" + strings.ToLower(rand.Text())
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(ctx)) })
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "DROP SCHEMA IF EXISTS "+pgtest.WithViews(name)+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", name, err)
		}
	})
	cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{name}.Sanitize()
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, `SET client_encoding = 'LATIN1'`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// It migrates the pool.
	h := harnessOn(t, pool)
	var tables int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname = $1`, name).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables == 0 {
		t.Fatalf("Migrate on a LATIN1 session made no table in %s", name)
	}
	if err := h.authz.AsOf(ctx, "t1", time.Now(), func(a *rbac.Authorizer) error {
		if err := a.Authorize(ctx, rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "josé"}}, login, cluster); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("as of now, josé, who holds nothing: %v", err)
		}
		return nil
	}); err != nil {
		t.Errorf("AsOf on a LATIN1 session in %s: %v", name, err)
	}
}

// reencoding is a host's wrapper around a pool whose transactions set client_encoding to WIN1252
// before each statement, as one putting a connection's settings back before each might: pgx sends
// text as UTF-8 all the same, so PostgreSQL converts what a statement outside a batch is sent,
// "josé" into "josÃ©", fails on text holding a byte WIN1252 has no character for, and sends back
// what it reads in WIN1252. It has no BeginTx, so the package begins its transactions by Begin.
type reencoding struct{ pool *pgxpool.Pool }

func (d reencoding) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return d.pool.Exec(ctx, sql, args...)
}

func (d reencoding) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return d.pool.Query(ctx, sql, args...)
}

func (d reencoding) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return d.pool.QueryRow(ctx, sql, args...)
}

func (d reencoding) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return reencodingTx{tx}, nil
}

type reencodingTx struct{ pgx.Tx }

const win1252 = `SET LOCAL client_encoding = 'WIN1252'`

func (tx reencodingTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if _, err := tx.Tx.Exec(ctx, win1252); err != nil {
		return pgconn.CommandTag{}, err
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func (tx reencodingTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if _, err := tx.Tx.Exec(ctx, win1252); err != nil {
		return nil, err
	}
	return tx.Tx.Query(ctx, sql, args...)
}

func (tx reencodingTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if _, err := tx.Tx.Exec(ctx, win1252); err != nil {
		return failedRow{err}
	}
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func (tx reencodingTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	// Failing, it aborts the transaction, which fails the batch.
	_, _ = tx.Tx.Exec(ctx, win1252)
	return tx.Tx.SendBatch(ctx, b)
}

func (tx reencodingTx) Begin(ctx context.Context) (pgx.Tx, error) {
	inner, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return reencodingTx{inner}, nil
}

type failedRow struct{ err error }

func (r failedRow) Scan(...any) error { return r.err }

// reencoded is an Authorizer like h's on a reencoding wrapper around h's pool.
func reencoded(t *testing.T, h *harness) *rbac.Authorizer {
	t.Helper()
	a, err := rbac.New(reencoding{h.pool}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A change's statements each set UTF8 themselves, so one recording who made it and SetRole's
// write store what they were given, and History reads it so, through a wrapper setting another
// encoding before each statement.
func TestAChangeThroughAWrapperSettingAnotherClientEncodingRecordsWhatItWasGiven(t *testing.T) {
	h := setup(t)
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Reason: "für", Request: "réq"})
	root := rbac.TenantRoot("t1")
	h.seed(t, grant(root, "tenant.roles", rbac.User, "josé"), grant(root, "cluster.admin", rbac.User, "josé"))
	jose := h.as(t, "josé")
	wa := reencoded(t, h)
	r := rbac.RoleDefinition{ID: "custom.cafe", Name: "café", Description: "naïve", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := wa.SetRole(ctx, jose, "t1", r); err != nil {
		t.Fatal(err)
	}
	var name, description string
	if err := h.pool.QueryRow(ctx, `SELECT name, description FROM rbac_roles WHERE tenant = 't1' AND id = 'custom.cafe'`).Scan(&name, &description); err != nil {
		t.Fatal(err)
	}
	if name != r.Name || description != r.Description {
		t.Errorf("SetRole stored name %q description %q, not %q %q", name, description, r.Name, r.Description)
	}
	if err := wa.Apply(ctx, jose, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("bob")}}}); err != nil {
		t.Fatal(err)
	}
	var actor, reason, request string
	if err := h.pool.QueryRow(ctx, `SELECT actor, reason, request FROM rbac_history
		WHERE tenant = 't1' AND entity = 'grant' AND principal = 'user:bob'`).Scan(&actor, &reason, &request); err != nil {
		t.Fatal(err)
	}
	if actor != "user:josé" || reason != "für" || request != "réq" {
		t.Errorf("history recorded the grant by %q for %q in %q, not by user:josé for für in réq", actor, reason, request)
	}
	// Another session's open transaction can hold the record back from History a while.
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		records, _, err := wa.History(wait, rbac.Cursor{}, rbac.MaxHistory)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(records, func(r rbac.Record) bool { return r.Entity == "grant" && r.Principal == identity("bob") })
		if i >= 0 {
			if got := records[i]; got.Actor != jose.Principal || got.Reason != "für" || got.Request != "réq" {
				t.Errorf("History read the grant by %+v for %q in %q, not by user:josé for für in réq", got.Actor, got.Reason, got.Request)
			}
			if j := slices.IndexFunc(records, func(r rbac.Record) bool { return r.Entity == "role" }); j < 0 || !strings.Contains(string(records[j].After), `"café"`) {
				t.Errorf("History read no record of the role named café")
			}
			return
		}
		select {
		case <-wait.Done():
			t.Fatal("History read no record of the grant")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Grants differing only in their conditions have the conditions hashed as stored, in UTF8,
// through a wrapper setting another encoding before each statement: in WIN1252, which has no
// character for byte 0x81, "с" (U+0441, d1 81) failed the change.
func TestConditionsHashedThroughAWrapperSettingAnotherClientEncodingAreThoseStored(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	admin := h.as(t, "admin")
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "admin"))
	wa := reencoded(t, h)
	conditions := []string{`resource.id == "с1"`, `resource.id == "с2"`}
	change := rbac.Change{}
	for _, c := range conditions {
		change.Grant = append(change.Grant, rbac.Binding{Role: "cluster.login", Principal: identity("bob"), Condition: rbac.Condition{Expression: c}})
	}
	if err := wa.Apply(ctx, admin, cluster, change); err != nil {
		t.Fatal(err)
	}
	var stored []string
	if err := h.pool.QueryRow(ctx, `SELECT array_agg(condition ORDER BY condition) FROM rbac_grants WHERE tenant = 't1' AND principal_id = 'bob'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored, conditions) {
		t.Errorf("the grants stored conditions %q, not %q", stored, conditions)
	}
}

// accentedSchema is a pool whose sessions' search_path names only a new schema named "tést_…", and
// that schema's name, with mode for its statements, as many name a schema in their own language.
func accentedSchema(t *testing.T, mode pgx.QueryExecMode) (*pgxpool.Pool, string) {
	t.Helper()
	ctx := t.Context()
	cfg, err := pgxpool.ParseConfig(pgtest.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	name := "tést_" + strings.ToLower(rand.Text())
	conn, err := pgx.ConnectConfig(ctx, cfg.ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.WithoutCancel(ctx)) })
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), "DROP SCHEMA IF EXISTS "+pgtest.WithViews(name)+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", name, err)
		}
	})
	cfg.ConnConfig.RuntimeParams["search_path"] = pgx.Identifier{name}.Sanitize()
	cfg.ConnConfig.DefaultQueryExecMode = mode
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, name
}

// A change, or a migration, through a wrapper setting another encoding before each statement
// takes the locks a session in UTF8 takes for the same tables, named by a schema's name in UTF-8:
// in WIN1252, "tést_…" read as other bytes keyed other locks, so a process behind the wrapper and
// one without never waited for each other, and in one process the second failed on the first's
// name, which isn't UTF-8.
func TestLocksThroughAWrapperSettingAnotherClientEncodingAreAPlainSessions(t *testing.T) {
	ctx := t.Context()
	pool, _ := accentedSchema(t, pgx.QueryExecModeCacheStatement)
	h := harnessOn(t, pool)
	root := rbac.TenantRoot("t1")
	h.seed(t, grant(root, "tenant.roles", rbac.User, "admin"), grant(root, "cluster.admin", rbac.User, "admin"))
	admin := h.as(t, "admin")
	wa := reencoded(t, h)
	waits := func(what string, held func(pgx.Tx) error, then func(context.Context) error) {
		t.Helper()
		host, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = host.Rollback(context.WithoutCancel(ctx)) }()
		if err := held(reencodingTx{host}); err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := then(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s while the wrapper's held its locks: %v, not waiting for them", what, err)
		}
	}
	r := rbac.RoleDefinition{ID: "custom.x", Name: "x", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	waits("a plain session's Apply", func(tx pgx.Tx) error { return wa.WithTx(tx).SetRole(ctx, admin, "t1", r) }, func(ctx context.Context) error {
		return h.authz.Apply(ctx, admin, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("bob")}}})
	})
	waits("a plain session's Migrate", func(tx pgx.Tx) error { return rbac.Migrate(ctx, tx) }, func(ctx context.Context) error {
		return rbac.Migrate(ctx, pool)
	})
}

// History through a wrapper setting another encoding before each statement reads a schema named
// "tést_…" in every query mode: its read of records, in a batch that sets UTF8, named the schema
// as read in WIN1252, which pgx's modes but one parse in UTF8, after the batch set it.
func TestHistoryThroughAWrapperSettingAnotherClientEncodingReadsAnAccentedSchemaInEveryMode(t *testing.T) {
	for _, mode := range []pgx.QueryExecMode{pgx.QueryExecModeCacheStatement, pgx.QueryExecModeCacheDescribe, pgx.QueryExecModeDescribeExec, pgx.QueryExecModeExec} {
		t.Run(mode.String(), func(t *testing.T) {
			pool, _ := accentedSchema(t, mode)
			h := harnessOn(t, pool)
			if _, _, err := reencoded(t, h).History(t.Context(), rbac.Cursor{}, rbac.MaxHistory); err != nil {
				t.Errorf("History: %v", err)
			}
		})
	}
}
