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
		{"DeleteScope", host, func(ctx context.Context) error { return h.authz.DeleteScope(ctx, host, "t1", rbac.TenantRoot("t1")) }},
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
		// JSON would record it as someone else, with U+FFFD for the byte.
		"on behalf of an id that isn't UTF-8": {OnBehalfOf: identity("a\xffb")},
		"a long request":                      {Request: strings.Repeat("r", rbac.MaxRequest+1)},
		"a long reason":                       {Reason: strings.Repeat("r", rbac.MaxNote+1)},
		"a NUL":                               {Request: "a\x00b"},
	} {
		if err := h.authz.Import(rbac.WithAudit(ctx, a), host, "t1", g); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := h.authz.DeleteExpired(rbac.WithAudit(ctx, a)); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("DeleteExpired, %s: %v", name, err)
		}
	}
	// DeleteGrants stores nothing that names its actor, so history alone would take it, as someone else.
	if err := h.authz.DeleteGrants(ctx, identity("h\xff"), "t1", g); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("an actor whose id isn't UTF-8: %v", err)
	}
}

// What OnChange writes is its host's: through the package, as the call it makes; by hand, as no
// one's. Neither is recorded as the change it is told of, and a call it makes ends no context
// that change still writes with.
func TestHistoryRecordsOnChangesWritesAsItsOwn(t *testing.T) {
	var h *harness
	h = setup(t, func(c *rbac.Config) {
		c.OnChange = func(ctx context.Context, tx pgx.Tx, e rbac.ChangeEvent) error {
			switch e.Tenant {
			case "t1":
				_, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					VALUES ('t1', 'cluster', 'c1', 'user', 'by-hook', 'cluster.login')`)
				return err
			case "t2":
				return h.authz.WithTx(tx).Import(ctx, host, "t9", []rbac.Grant{grant(rbac.TenantRoot("t9"), "cluster.login", rbac.User, "z")})
			}
			return nil
		}
	})
	ctx := t.Context()
	// w's grants in t2 and t3, which DeletePrincipalEverywhere removes in one transaction, telling
	// OnChange of t2's first.
	for _, tenant := range []string{"t2", "t3"} {
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ($1, 'cluster', 'c1', 'user', 'w', 'cluster.login')`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var last int64
	recordedSince(t, h, &last)
	if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 2 || got[0] != (recorded{actor: "user:host", how: "Import", op: "create"}) ||
		got[1] != (recorded{op: "create"}) {
		t.Errorf("Import recorded %+v", got)
	}
	if err := h.authz.DeletePrincipalEverywhere(ctx, host, identity("w")); err != nil {
		t.Fatal(err)
	}
	removal := recorded{actor: "user:host", how: "DeletePrincipalEverywhere", op: "delete"}
	if got := recordedSince(t, h, &last); len(got) != 3 || got[0] != removal || got[1] != removal ||
		got[2] != (recorded{actor: "user:host", how: "Import", op: "create"}) {
		t.Errorf("DeletePrincipalEverywhere recorded %+v", got)
	}
}

// A change that fails under WithTx leaves nothing in the host's transaction, though its context is
// done: neither what it wrote nor its context for history, which would record the host's own
// writes as the change's.
func TestAFailedChangeLeavesNothingInTheHostsTransaction(t *testing.T) {
	var cancel context.CancelFunc
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error {
			cancel()
			return context.Canceled
		}
	})
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	call, c := context.WithCancel(ctx)
	cancel = c
	if err := h.authz.WithTx(tx).Import(call, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAnExpiryInAnOlderTransactionIsRecordedAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A host's transaction begun before the grant expires, which DeleteExpired, under it, removes.
	if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'brief', 'cluster.login', clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	h.now = time.Now().Add(time.Second)
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var op string
	if err := h.pool.QueryRow(ctx, `SELECT op FROM rbac_history WHERE principal = 'user:brief' AND after IS NULL`).Scan(&op); err != nil || op != "expire" {
		t.Fatalf("op = %q, %v", op, err)
	}
}

// A change under WithTx that runs past a savepoint's bound still ends its savepoint: the bound
// runs from when the change is done, so a slow one neither fails once written nor leaves its
// writes in the host's transaction once refused.
func TestASlowChangeUnderWithTxEndsItsSavepoint(t *testing.T) {
	rbac.SetSavepointEnd(t, 200*time.Millisecond)
	errRefused := errors.New("refused")
	var refuse bool
	h := setup(t, func(c *rbac.Config) {
		c.OnChange = func(context.Context, pgx.Tx, rbac.ChangeEvent) error {
			time.Sleep(400 * time.Millisecond)
			if refuse {
				return errRefused
			}
			return nil
		}
	})
	ctx := t.Context()
	for _, id := range []string{"kept", "refused"} {
		refuse = id == "refused"
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, id)})
		if want := map[bool]error{true: errRefused}[refuse]; !errors.Is(err, want) {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: %v", id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := h.pool.Query(ctx, `SELECT principal_id FROM rbac_grants WHERE principal_id IN ('kept', 'refused')`)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(held, []string{"kept"}) {
		t.Fatalf("held %v, %v", held, err)
	}
}

// hostTx is a host's own handle on its transaction, as one that traces its queries is: a DB, but
// not a pgx.Tx.
type hostTx struct{ tx pgx.Tx }

func (h hostTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return h.tx.Exec(ctx, sql, args...)
}

func (h hostTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return h.tx.Query(ctx, sql, args...)
}

func (h hostTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return h.tx.QueryRow(ctx, sql, args...)
}

func (h hostTx) Begin(ctx context.Context) (pgx.Tx, error) { return h.tx.Begin(ctx) }

// A change on a DB that begins only savepoints, though not a pgx.Tx, ends its context with it, so
// the host's own writes after it aren't recorded as the change's.
func TestAChangeInAHostsTransactionEndsItsContext(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.OnChange = nil })
	ctx := t.Context()
	var last int64
	recordedSince(t, h, &last)
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	authz, err := rbac.New(hostTx{tx}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "u")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		VALUES ('t1', 'cluster', 'c1', 'user', 'by-hand', 'cluster.login')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 2 || got[0] != (recorded{actor: "user:host", how: "Import", op: "create"}) ||
		got[1] != (recorded{op: "create"}) {
		t.Fatalf("recorded %+v", got)
	}
}

// The host's clock can run ahead of the database's, which history records an expiry by: what
// DeleteExpired removes has expired by both, so it is recorded as an expiry.
func TestAnExpiryAheadOfTheDatabasesClockIsRecordedAsOne(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.now = time.Now().Add(time.Hour)
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, expires_at)
		VALUES ('t1', 'cluster', 'c1', 'user', 'past', 'cluster.login', clock_timestamp() - interval '1 second'),
		  ('t1', 'cluster', 'c1', 'user', 'soon', 'cluster.login', clock_timestamp() + interval '30 minutes')`); err != nil {
		t.Fatal(err)
	}
	var last int64
	recordedSince(t, h, &last)
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if got := recordedSince(t, h, &last); len(got) != 1 || got[0] != (recorded{how: "DeleteExpired", op: "expire"}) {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAnUpdateThatMovesARowIsRecordedAsItsEndAndStart(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.as(t, "u", "ops")
	var last int64
	recordedSince(t, h, &last)
	// By hand, as a write around the package can: Activate moves only an activation that ended.
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_members SET source = 'sync' WHERE principal = 'user:u'`); err != nil {
		t.Fatal(err)
	}
	got := recordedSince(t, h, &last)
	if len(got) != 2 || got[0].op != "delete" || got[1].op != "create" {
		t.Fatalf("recorded %+v", got)
	}
	rows, err := h.pool.Query(ctx, `SELECT key FROM rbac_history WHERE entity = 'member' AND id > $1 - 2 ORDER BY id`, last)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("keys = %v, %v", keys, err)
	}
}

// Activating again once an activation has ended moves its grant to a new id: the ended one is
// recorded as the expiry it was, when it expired, not as a revoke by whoever activated again.
func TestAnActivationMadeAnewRecordsTheEndedOneAsItsExpiry(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// On the database's clock, which dates an expiry no earlier than the change before it, so the
	// activation ends after it is made, and ends by both clocks before it is made anew.
	h.now = time.Now()
	activate := rbac.Activation{Role: "cluster.sudo", Duration: 250 * time.Millisecond, Justification: "INC-1"}
	first, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `SELECT pg_sleep(extract(epoch FROM $1 - clock_timestamp()))`, first.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	h.now = first.ExpiresAt
	again, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil || again.ID == first.ID {
		t.Fatalf("activated anew %+v, %v", again, err)
	}
	rows, err := h.pool.Query(ctx, `SELECT key || ' ' || op FROM rbac_history WHERE entity = 'grant' AND key IN ($1, $2) ORDER BY id`,
		first.ID, again.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if want := []string{first.ID + " create", first.ID + " expire", again.ID + " create"}; err != nil || !slices.Equal(got, want) {
		t.Fatalf("recorded %v, %v, want %v", got, err, want)
	}
	var expired time.Time
	if err := h.pool.QueryRow(ctx, `SELECT effective_at FROM rbac_history WHERE entity = 'grant' AND key = $1 AND op = 'expire'`,
		first.ID).Scan(&expired); err != nil || !expired.Equal(first.ExpiresAt) {
		t.Fatalf("expired at %v, %v, want %v", expired, err, first.ExpiresAt)
	}
}

// The host's clock can run ahead of the database's, which history records an expiry by: an
// activation ended by Config.Now alone is extended, not made anew, so the one before isn't recorded
// as revoked by whoever activated again.
func TestAnActivationEndedAheadOfTheDatabasesClockIsExtended(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	owner, u := h.as(t, "owner"), h.as(t, "u")
	if err := h.authz.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.now = time.Now().Add(time.Hour)
	activate := rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}
	first, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Minute)
	again, err := h.authz.Activate(ctx, u, cluster, activate)
	if err != nil || again.ID != first.ID {
		t.Fatalf("activated %+v, %v, want %s extended", again, err, first.ID)
	}
	rows, err := h.pool.Query(ctx, `SELECT op FROM rbac_history WHERE entity = 'grant' AND key = $1 ORDER BY id`, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(got, []string{"create", "update"}) {
		t.Fatalf("recorded %v, %v", got, err)
	}
}

func TestEveryRefusedChangeIsReported(t *testing.T) {
	var refused []rbac.Refusal
	h := setup(t, func(c *rbac.Config) {
		c.OnRefused = func(_ context.Context, r rbac.Refusal) { refused = append(refused, r) }
	})
	ctx := rbac.WithAudit(t.Context(), rbac.Audit{Request: "req-1"})
	actor := h.as(t, "actor")
	none := rbac.Resource{}
	// Each refused as invalid, for want of a tenant or a resource.
	for _, c := range []struct {
		how string
		do  func() error
	}{
		{"Apply", func() error { return h.authz.Apply(ctx, actor, none, rbac.Change{}) }},
		{"Import", func() error { return h.authz.Import(ctx, host, "", nil) }},
		{"DeleteGrants", func() error { return h.authz.DeleteGrants(ctx, host, "", nil) }},
		{"DeleteScope", func() error { return h.authz.DeleteScope(ctx, host, "", cluster.Scope()) }},
		{"DeleteScopes", func() error { return h.authz.DeleteScopes(ctx, host, "", []rbac.Scope{cluster.Scope()}) }},
		{"DeletePrincipal", func() error { return h.authz.DeletePrincipal(ctx, host, "", actor.Principal) }},
		{"DeletePrincipalEverywhere", func() error {
			return h.authz.DeletePrincipalEverywhere(ctx, host, rbac.TenantMembers("t1"))
		}},
		{"DeleteTenant", func() error { return h.authz.DeleteTenant(ctx, host, "") }},
		{"DeleteExpired", func() error {
			_, err := h.authz.DeleteExpired(rbac.WithAudit(ctx, rbac.Audit{OnBehalfOf: rbac.TenantMembers("t1")}))
			return err
		}},
		{"SetMemberships", func() error { return h.authz.SetMemberships(ctx, host, "", nil) }},
		{"SetGroup", func() error { return h.authz.SetGroup(ctx, actor, "", rbac.GroupDefinition{}) }},
		{"ImportGroups", func() error { return h.authz.ImportGroups(ctx, host, "", nil) }},
		{"DeleteGroup", func() error { return h.authz.DeleteGroup(ctx, actor, "", "g") }},
		{"DeleteGroups", func() error { return h.authz.DeleteGroups(ctx, host, "", []string{"g"}) }},
		{"ImportMembers", func() error { return h.authz.ImportMembers(ctx, host, "", nil) }},
		{"ChangeMembers", func() error { return h.authz.ChangeMembers(ctx, actor, "", nil, nil) }},
		{"DeleteMembers", func() error { return h.authz.DeleteMembers(ctx, host, "", nil) }},
		{"SetRole", func() error { return h.authz.SetRole(ctx, actor, "", rbac.RoleDefinition{}) }},
		{"DeleteRole", func() error { return h.authz.DeleteRole(ctx, actor, "", "custom.x") }},
		{"SetDeny", func() error { return h.authz.SetDeny(ctx, actor, none, rbac.Deny{}) }},
		{"DeleteDeny", func() error { return h.authz.DeleteDeny(ctx, actor, none, "d") }},
		{"SetEligibility", func() error { return h.authz.SetEligibility(ctx, actor, none, rbac.Eligibility{}) }},
		{"DeleteEligibility", func() error { return h.authz.DeleteEligibility(ctx, actor, none, "cluster.sudo", actor.Principal) }},
		{"Activate", func() error {
			_, err := h.authz.Activate(ctx, actor, none, rbac.Activation{})
			return err
		}},
		{"Deactivate", func() error { return h.authz.Deactivate(ctx, actor, none, "cluster.sudo") }},
	} {
		refused = nil
		if err := c.do(); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("%s: %v", c.how, err)
			continue
		}
		if len(refused) != 1 || refused[0].How != c.how || !errors.Is(refused[0].Err, rbac.ErrInvalid) || refused[0].At.IsZero() {
			t.Errorf("%s reported %+v", c.how, refused)
		}
	}
	// One denied is too, with its actor and the host's audit; one made isn't.
	refused = nil
	grant := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: actor.Principal}}}
	if err := h.authz.Apply(ctx, actor, cluster, grant); !errors.Is(err, rbac.ErrDenied) {
		t.Fatal(err)
	}
	if len(refused) != 1 || refused[0].Actor != actor.Principal || refused[0].Tenant != "t1" || refused[0].Audit.Request != "req-1" ||
		!errors.Is(refused[0].Err, rbac.ErrDenied) {
		t.Fatalf("reported %+v", refused)
	}
	refused = nil
	owner := h.as(t, "owner")
	if err := h.authz.Apply(ctx, owner, cluster, grant); err != nil || len(refused) != 0 {
		t.Fatalf("a change made: %v, reported %+v", err, refused)
	}
	// Nor is one that failed for another reason, as the host's lookup failing.
	unreachable := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: rbac.Principal{Kind: rbac.User, ID: "unreachable"}}}}
	if err := h.authz.Apply(ctx, owner, cluster, unreachable); !errors.Is(err, errLookup) || len(refused) != 0 {
		t.Fatalf("a change failed: %v, reported %+v", err, refused)
	}
}

func TestAChangeAsOfATimeIsNotReportedRefused(t *testing.T) {
	var refused []rbac.Refusal
	h := setup(t, func(c *rbac.Config) {
		c.OnRefused = func(_ context.Context, r rbac.Refusal) { refused = append(refused, r) }
	})
	ctx := t.Context()
	owner, actor := h.as(t, "owner"), h.as(t, "actor")
	grant := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: actor.Principal}}}
	// Refused as reading the past, whether the actor could make it then or not: no actor's attempt.
	if err := h.authz.AsOf(ctx, "t1", dbNow(t, h), func(a *rbac.Authorizer) error {
		if err := a.Apply(ctx, owner, cluster, grant); !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("Apply by the owner: %v", err)
		}
		if err := a.Apply(ctx, actor, cluster, grant); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("Apply by another: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(refused) != 0 {
		t.Fatalf("reported %+v", refused)
	}
}
