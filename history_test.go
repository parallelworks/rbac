package rbac_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/parallelworks/rbac"
)

// drain reads history from cursor to its end, as an exporter would, and moves cursor there.
func drain(t *testing.T, h *harness, cursor *rbac.Cursor) []rbac.Record {
	t.Helper()
	var all []rbac.Record
	for {
		got, next, err := h.authz.History(t.Context(), *cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			return all
		}
		all, *cursor = append(all, got...), next
	}
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
	drain(t, h, &cursor)
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
	if got := drain(t, h, &cursor); len(got) != 0 {
		t.Fatalf("read past a transaction still running: %+v", got)
	}
	if err := late.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	got := drain(t, h, &cursor)
	if want := []rbac.Principal{{Kind: rbac.User, ID: "late"}, {Kind: rbac.User, ID: "early"}}; !slices.Equal(principals(got), want) {
		t.Fatalf("History = %+v, want %v", got, want)
	}
}

func TestHistoryRecordsEveryWrite(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	var cursor rbac.Cursor
	drain(t, h, &cursor)
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
	got := drain(t, h, &cursor)
	if len(got) != 3 {
		t.Fatalf("History = %+v", got)
	}
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

func TestHistoryRefusesACursorFromAnotherDatabase(t *testing.T) {
	h := setup(t)
	if _, _, err := h.authz.History(t.Context(), rbac.Cursor{TxID: 1 << 62}, 10); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("a cursor past every transaction: %v", err)
	}
	if _, _, err := h.authz.History(t.Context(), rbac.Cursor{}, rbac.MaxHistory+1); !errors.Is(err, rbac.ErrInvalid) {
		t.Fatalf("too many: %v", err)
	}
}
