package rbac_test

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/parallelworks/rbac"
)

// drain reads n records of history from cursor, as an exporter would, moves cursor past them, and
// checks nothing follows. A transaction running anywhere in the cluster, as another run's of these
// tests, holds them back until it ends.
func drain(t *testing.T, h *harness, cursor *rbac.Cursor, n int) []rbac.Record {
	t.Helper()
	var all []rbac.Record
	for deadline := time.Now().Add(10 * time.Second); len(all) < n; {
		got, next, err := h.authz.History(t.Context(), *cursor, min(2, n-len(all)))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("read %d of %d records: %+v", len(all), n, all)
			}
			time.Sleep(10 * time.Millisecond)
		}
		all, *cursor = append(all, got...), next
	}
	if more, _, err := h.authz.History(t.Context(), *cursor, 1); err != nil || len(more) != 0 {
		t.Fatalf("read past %d records: %+v, %v", n, more, err)
	}
	return all
}

func principals(records []rbac.Record) []rbac.Principal {
	ps := make([]rbac.Principal, len(records))
	for i, r := range records {
		ps[i] = r.Principal
	}
	return ps
}

func TestHistorySkipsNoTransactionThatCommitsLate(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	late, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = late.Rollback(ctx) }()
	const insert = `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', $1, 'cluster.login')`
	if _, err := late.Exec(ctx, insert, "late"); err != nil {
		t.Fatal(err)
	}
	// A transaction begun after it commits first; reading it now would move the cursor past the
	// first one's record, which commits after.
	if _, err := h.pool.Exec(ctx, insert, "early"); err != nil {
		t.Fatal(err)
	}
	if got, _, err := h.authz.History(ctx, cursor, 10); err != nil || len(got) != 0 {
		t.Fatalf("read past a transaction still running: %+v, %v", got, err)
	}
	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 2)
	if want := []rbac.Principal{{Kind: rbac.User, ID: "late"}, {Kind: rbac.User, ID: "early"}}; !slices.Equal(principals(got), want) {
		t.Fatalf("History = %+v, want %v", got, want)
	}
}

func TestHistoryRecordsEveryWrite(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// Written around the package, as by hand: recorded, with who wrote it in the database.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET note = 'why' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_grants WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 3)
	for i, op := range []string{"create", "update", "delete"} {
		r := got[i]
		if r.Op != op || r.Entity != "grant" || r.Tenant != "t1" || r.Principal != (rbac.Principal{Kind: rbac.User, ID: "u"}) ||
			r.Role != "cluster.login" || r.Scope != cluster.Scope() || r.Actor != (rbac.Principal{}) || r.DBUser == "" || r.Key != got[0].Key {
			t.Errorf("%s: %+v", op, r)
		}
		if (r.Before == nil) != (op == "create") || (r.After == nil) != (op == "delete") {
			t.Errorf("%s: before %s, after %s", op, r.Before, r.After)
		}
	}
	// History is appended to only, and a table it records is deleted from, never truncated, so
	// nothing changes it unrecorded.
	for _, sql := range []string{
		`UPDATE rbac_history SET actor = 'user:x'`, `DELETE FROM rbac_history`, `TRUNCATE rbac_history`, `TRUNCATE rbac_grants`,
	} {
		if _, err := h.pool.Exec(ctx, sql); err == nil {
			t.Errorf("%s: allowed", sql)
		}
	}
}

// The change's context says whether a delete is an expiry, and nothing more about what was done.
func TestHistoryRecordsADeleteAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	// `expired` expires after it is made, as its statement runs, and before it is deleted.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'create', 'cluster.login', NULL),
		  ('t1', 'cluster', 'c1', 'user', 'early', 'cluster.login', now() + interval '1 hour'),
		  ('t1', 'cluster', 'c1', 'user', 'expired', 'cluster.login', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	// Whoever sets the context can call a delete an expiry, which only one of a row that expired is.
	for id, op := range map[string]string{"create": "create", "early": "expire", "expired": "expire"} {
		if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('rbac.change', json_build_object('op', $1::text)::text, true)`, op); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `DELETE FROM rbac_grants WHERE principal_id = $1`, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := drain(t, h, &cursor, 6)
	ops := map[string]rbac.Record{}
	for _, r := range got[3:] {
		ops[r.Principal.ID] = r
	}
	if ops["create"].Op != "delete" || ops["early"].Op != "delete" || ops["expired"].Op != "expire" ||
		!ops["expired"].EffectiveAt.Equal(ops["expired"].ExpiresAt) {
		t.Fatalf("History = %+v", got[3:])
	}
}

// An expiry is dated when its row expired, but never before the row's last change, which can have
// moved its expiry back to before it: the grant was held until then.
func TestHistoryDatesNoExpiryBeforeItsRowsLastChange(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'standing', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		for _, sql := range []string{
			`UPDATE rbac_grants SET expires_at = '2000-01-01' WHERE principal_id = 'standing'`,
			`SELECT set_config('rbac.change', '{"op": "expire"}', true)`,
			`DELETE FROM rbac_grants WHERE principal_id = 'standing'`,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 3)
	if got[2].Op != "expire" || !got[2].EffectiveAt.Equal(got[1].EffectiveAt) {
		t.Fatalf("History = %+v", got)
	}
}

// rbac_record runs as its owner, so an overload of what it calls, made in its schema by any role
// that may create there, can't stand in for pg_catalog's.
func TestHistoryRecordsRowsWhateverItsSchemaHolds(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	for _, sql := range []string{
		`CREATE FUNCTION to_jsonb(rbac_grants) RETURNS jsonb LANGUAGE sql
			AS $$ SELECT pg_catalog.to_jsonb($1) || '{"principal": "user:forged"}' $$`,
		`CREATE FUNCTION jsonb_build_array(text, text, text) RETURNS jsonb LANGUAGE sql AS $$ SELECT '["forged"]'::jsonb $$`,
	} {
		if _, err := h.pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	// A connection of its own, which hasn't planned rbac_record before the overloads were made.
	conn, err := pgx.ConnectConfig(ctx, h.pool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	for _, sql := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'real', 'cluster.login')`,
		`INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'g')`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'g', 'user', 'real')`,
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var forged int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE principal = 'user:forged' OR key LIKE '%forged%'`).Scan(&forged); err != nil || forged != 0 {
		t.Fatalf("recorded %d forged, %v", forged, err)
	}
}

// History is written by its triggers alone: a role that may write the package's tables but not
// history still records what it writes, a session's own table named as history's takes none of
// it, and no one may attach the function that writes it to a table of their own.
func TestHistoryIsWrittenByItsTriggersAlone(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var public bool
	if err := h.pool.QueryRow(ctx, `SELECT has_function_privilege('public', 'rbac_record()', 'EXECUTE')`).Scan(&public); err != nil || public {
		t.Fatalf("anyone may attach rbac_record to a table: %v, %v", public, err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var schema string
	if err := tx.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	// A role made and dropped with tx, as roles are the cluster's.
	writer := pgx.Identifier{"rbac_test_" + strings.ToLower(rand.Text())}.Sanitize()
	if _, err := tx.Exec(ctx, `CREATE ROLE `+writer); err != nil {
		if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "42501" {
			t.Skip("the test database's role can't create roles")
		}
		t.Fatal(err)
	}
	for _, sql := range []string{
		`GRANT USAGE ON SCHEMA ` + pgx.Identifier{schema}.Sanitize() + ` TO ` + writer,
		`GRANT INSERT ON rbac_grants TO ` + writer,
		// pg_temp comes first in a search_path that doesn't name it.
		`CREATE TEMP TABLE rbac_history (LIKE rbac_history INCLUDING ALL)`,
		`SET LOCAL ROLE ` + writer,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role) VALUES ('t1', 'cluster', 'c1', 'user', 'writer', 'cluster.login')`,
		`RESET ROLE`,
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{schema, "rbac_history"}.Sanitize()+` WHERE principal = 'user:writer'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recorded %d, %v", n, err)
	}
}

func TestHistoryKeysTellMembersApart(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_groups (tenant, id) VALUES ('t1', 'a'), ('t1', 'a user:b')`); err != nil {
		t.Fatal(err)
	}
	// Joined with spaces, each member's group, principal and source would be `a user:b user:c `.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		VALUES ('t1', 'a user:b', 'user', 'c'), ('t1', 'a', 'user', 'b user:c')`); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor, 4)
	if got[2].Entity != "member" || got[2].Key == got[3].Key {
		t.Fatalf("History = %+v", got[2:])
	}
}

func TestHistoryRefusesACursorItCantFollow(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	if cursor.Generation == "" || cursor.RecordedAt.IsZero() {
		t.Fatalf("cursor = %+v", cursor)
	}
	// Read on with the cursor it gave, or one a read that found nothing gave.
	for _, c := range []rbac.Cursor{cursor, {Generation: cursor.Generation}} {
		if _, _, err := h.authz.History(ctx, c, 1); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	// Refused one another generation gave, as before a failover, and one whose last record this
	// database doesn't hold, as after a restore that started no generation: either may number
	// records past what this one kept anew.
	old := cursor
	old.Generation = "1/1"
	if _, _, err := h.authz.History(ctx, old, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a cursor of another generation: %v", err)
	}
	lost := cursor
	lost.RecordedAt = lost.RecordedAt.Add(time.Microsecond)
	if _, _, err := h.authz.History(ctx, lost, 1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a cursor of a record the database doesn't hold: %v", err)
	}
	if _, _, err := h.authz.History(ctx, rbac.Cursor{}, rbac.MaxHistory+1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("too many: %v", err)
	}
}

// A pool's connections can reach different servers, as an old primary and the new one after a
// failover: History checks the cursor on the server it reads, which here doesn't hold its record.
func TestHistoryChecksTheCursorWhereItReads(t *testing.T) {
	h, other := setup(t), setup(t)
	var cursor rbac.Cursor
	drain(t, h, &cursor, 1)
	authz, err := rbac.New(servers{DB: other.pool, alone: h.pool}, rbac.Config{
		ValidateGrant: func(context.Context, rbac.DB, rbac.GrantInput) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := authz.History(t.Context(), cursor, 10); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("History = %+v, %v", got, err)
	}
}

// servers runs a query of one row outside a transaction on alone, and everything else on DB.
type servers struct {
	rbac.DB
	alone rbac.DB
}

func (s servers) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return s.alone.QueryRow(ctx, sql, args...)
}

func TestHistoryRecordsAReplicasWrites(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// A session in replica mode, as a subscription's apply worker is, fires only triggers enabled
	// always.
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'cluster', 'c1', 'user', 'replicated', 'cluster.login')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM rbac_history WHERE principal = 'user:replicated' AND op = 'create'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("recorded %d, %v", n, err)
	}
	// Nor does replica mode let history be changed.
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM rbac_history`)
		return err
	}); err == nil {
		t.Fatal("deleted history in replica mode")
	}
}

// recorded is a change's context as history recorded it.
type recorded struct{ actor, onBehalfOf, how, request, reason, op string }

// recordedSince reads the records after *last directly, in id order, and moves *last past them:
// each change has committed, and History would wait on transactions other sessions hold open.
func recordedSince(t *testing.T, h *harness, last *int64) []recorded {
	t.Helper()
	rows, err := h.pool.Query(t.Context(), `SELECT id, actor, on_behalf_of, how, request, reason, op FROM rbac_history
		WHERE id > $1 ORDER BY id`, *last)
	if err != nil {
		t.Fatal(err)
	}
	var got []recorded
	var r recorded
	if _, err := pgx.ForEachRow(rows, []any{last, &r.actor, &r.onBehalfOf, &r.how, &r.request, &r.reason, &r.op}, func() error {
		got = append(got, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestHistoryRecordsWhoMadeEachChangeAndHow(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), guardRole, groupMembers)
		c.PrincipalKinds = []rbac.PrincipalKind{"service_account"}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	h.seed(t, grant(cluster.Scope(), "guard", rbac.User, "owner"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "groups"))
	owner, groups, u := h.as(t, "owner"), h.as(t, "groups"), h.as(t, "u")
	h.join(t, "v", "w")
	// One that expired before the clock, which DeleteExpired removes, and grants in t2, w's of which
	// DeletePrincipalEverywhere removes and the rest DeleteTenant.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'workspace', 'w1', 'user', 'gone', 'cluster.login', $1)`, h.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.Import(ctx, host, "t2", []rbac.Grant{
		grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "w"), grant(rbac.TenantRoot("t2"), "cluster.login", rbac.User, "y"),
	}); err != nil {
		t.Fatal(err)
	}
	var last int64
	recordedSince(t, h, &last)
	boss := identity("boss")
	login := rbac.Binding{Role: "cluster.login", Principal: identity("v")}
	custom := rbac.RoleDefinition{ID: "custom.view", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	sudo := rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}
	for _, step := range []struct {
		how   string
		actor rbac.Principal
		do    func(ctx context.Context) error
	}{
		{"SetMemberships", host, func(ctx context.Context) error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("x")}})
		}},
		{"ImportGroups", host, func(ctx context.Context) error {
			return h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}})
		}},
		{"SetGroup", groups.Principal, func(ctx context.Context) error {
			return h.authz.SetGroup(ctx, groups, "t1", rbac.GroupDefinition{ID: "devs"})
		}},
		{"ImportMembers", host, func(ctx context.Context) error {
			return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("v")}})
		}},
		{"ChangeMembers", groups.Principal, func(ctx context.Context) error {
			return h.authz.ChangeMembers(ctx, groups, "t1", []rbac.Member{{Group: "devs", Principal: identity("v")}}, nil)
		}},
		{"DeleteMembers", host, func(ctx context.Context) error {
			return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("v")}})
		}},
		{"Apply", owner.Principal, func(ctx context.Context) error {
			return h.authz.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{login}})
		}},
		{"Import", host, func(ctx context.Context) error {
			return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"DeleteGrants", host, func(ctx context.Context) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(workspace.Scope(), "cluster.login", rbac.User, "v")})
		}},
		{"SetRole", admin.Principal, func(ctx context.Context) error { return h.authz.SetRole(ctx, admin, "t1", custom) }},
		{"DeleteRole", admin.Principal, func(ctx context.Context) error { return h.authz.DeleteRole(ctx, admin, "t1", custom.ID) }},
		{"SetDeny", owner.Principal, func(ctx context.Context) error {
			return h.authz.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{identity("x")}, Permissions: []rbac.Permission{root}})
		}},
		{"DeleteDeny", owner.Principal, func(ctx context.Context) error { return h.authz.DeleteDeny(ctx, owner, cluster, "d") }},
		{"SetEligibility", owner.Principal, func(ctx context.Context) error { return h.authz.SetEligibility(ctx, owner, cluster, sudo) }},
		{"Activate", u.Principal, func(ctx context.Context) error {
			_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"})
			return err
		}},
		{"Deactivate", u.Principal, func(ctx context.Context) error { return h.authz.Deactivate(ctx, u, cluster, "cluster.sudo") }},
		{"DeleteEligibility", owner.Principal, func(ctx context.Context) error {
			return h.authz.DeleteEligibility(ctx, owner, cluster, "cluster.sudo", u.Principal)
		}},
		{"DeleteGroup", groups.Principal, func(ctx context.Context) error { return h.authz.DeleteGroup(ctx, groups, "t1", "devs") }},
		{"DeleteGroups", host, func(ctx context.Context) error { return h.authz.DeleteGroups(ctx, host, "t1", []string{"ops"}) }},
		{"DeleteScopes", host, func(ctx context.Context) error {
			return h.authz.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope()})
		}},
		{"DeletePrincipal", host, func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("x")) }},
		{"DeletePrincipalEverywhere", host, func(ctx context.Context) error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, identity("w"))
		}},
		{"DeleteTenant", host, func(ctx context.Context) error { return h.authz.DeleteTenant(ctx, host, "t2") }},
	} {
		audit := rbac.Audit{OnBehalfOf: boss, Request: "req-" + step.how, Reason: "because"}
		if err := step.do(rbac.WithAudit(ctx, audit)); err != nil {
			t.Fatalf("%s: %v", step.how, err)
		}
		got := recordedSince(t, h, &last)
		if len(got) == 0 {
			t.Errorf("%s recorded nothing", step.how)
		}
		want := recorded{actor: "user:" + step.actor.ID, onBehalfOf: "user:boss", how: step.how, request: audit.Request, reason: "because"}
		for _, r := range got {
			if r.op = ""; r != want {
				t.Errorf("%s recorded %+v, want %+v", step.how, r, want)
			}
		}
	}
	// An expiry is no one's, and is recorded as one.
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{how: "DeleteExpired", op: "expire"}) {
		t.Fatalf("DeleteExpired recorded %+v", got)
	}
}

func TestAHostsOwnWritesAreNotRecordedAsAChangesUnderWithTx(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).Import(rbac.WithAudit(ctx, rbac.Audit{Request: "req-1"}), host, "t1",
		[]rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := recordedSince(t, h, &last)
	if len(got) != 2 || got[0].how != "Import" || got[0].request != "req-1" || got[1] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAChangeRefusesWhatItCantRecord(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	g := []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}
	for name, a := range map[string]rbac.Audit{
		"on behalf of a group": {OnBehalfOf: rbac.Principal{Kind: rbac.Group, ID: "ops"}},
		"a long request":       {Request: strings.Repeat("r", rbac.MaxRequest+1)},
		"a long reason":        {Reason: strings.Repeat("r", rbac.MaxNote+1)},
		"a NUL":                {Request: "a\x00b"},
	} {
		if err := h.authz.Import(rbac.WithAudit(ctx, a), host, "t1", g); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
