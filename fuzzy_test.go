package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
)

// Any role may set gin_fuzzy_search_limit, as a host's session can for its own text searches, and
// past it a GIN index's scan returns a random part of the rows it matches: the package finds the
// denies, exemptions and approvers naming a key by such indexes, live and as of a time.

// fuzzy is an Authorizer like h's on a pool of h's schema whose sessions set gin_fuzzy_search_limit
// to 1, and that pool.
func fuzzy(t *testing.T, h *harness) (*rbac.Authorizer, *pgxpool.Pool) {
	t.Helper()
	cfg := h.pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["gin_fuzzy_search_limit"] = "1"
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

// deniedClusters makes u a member of t1 granted login on the org o1, and stores the clusters c1 to c203 under it, in the
// host's table clusters too, a deny of login on each of the first 200 naming u and exempting the
// group ops, and an eligibility of v on each that ops and boss approve; it returns a time after.
func deniedClusters(t *testing.T, h *harness) time.Time {
	t.Helper()
	h.join(t, "u")
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.User, "u"))
	for _, sql := range []string{
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 SELECT 't1', 'cluster', 'c' || i, 'd', '{user:u}', '{group:ops}', '{cluster:login}' FROM generate_series(1, 200) i`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 SELECT 't1', 'cluster', 'c' || i, 'user', 'v', 'cluster.sudo', 3600, '{group:ops,user:boss}' FROM generate_series(1, 200) i`,
		`CREATE TABLE clusters (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL)`,
		`INSERT INTO clusters SELECT 't1', 'c' || i, ARRAY['cluster:c' || i, 'org:o1', 'tenant:t1'] FROM generate_series(1, 203) i`,
		`ANALYZE rbac_denies, rbac_eligibilities, rbac_history, clusters`,
	} {
		if _, err := h.pool.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return dbNow(t, h)
}

// onCluster is the cluster ci under the org o1.
func onCluster(i int) rbac.Resource {
	return rbac.Resource{Tenant: "t1", Type: "cluster", ID: fmt.Sprintf("c%d", i), Ancestors: []rbac.Scope{{Type: "org", ID: "o1"}}}
}

// filtered is the ids of the host's clusters that a's Filter condition for s to log in keeps, in q's
// query.
func filtered(ctx context.Context, t *testing.T, a *rbac.Authorizer, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, s rbac.Subject,
) []string {
	t.Helper()
	pred, err := a.Filter(ctx, s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.Query(ctx, `SELECT id FROM clusters WHERE `+pred.SQL+` ORDER BY id`, pred.Args...)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// The host's query of a Filter condition runs in its own session, which the package doesn't set: on
// one that limits GIN scans it keeps no row, as it would find only some of the denies, and kept 198
// of 200 clusters denied to the subject. As of a time, AsOf's transaction reads every row, so the
// query keeps what it keeps on any session.
func TestFiltersConditionKeepsNoRowWhereTheSessionLimitsGINScans(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := deniedClusters(t, h)
	fa, fuzzyPool := fuzzy(t, h)
	u := h.as(t, "u")
	want := []string{"c201", "c202", "c203"}
	if got := filtered(ctx, t, h.authz, h.pool, u); !slices.Equal(got, want) {
		t.Fatalf("on a plain session, kept %v", got)
	}
	if got := filtered(ctx, t, fa, fuzzyPool, u); len(got) != 0 {
		t.Errorf("on a session limiting GIN scans, kept %d: %v", len(got), got)
	}
	tx, err := fuzzyPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fa.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if got := filtered(ctx, t, a, tx, u); !slices.Equal(got, want) {
			t.Errorf("as of a time, on a session limiting GIN scans, kept %d: %v", len(got), got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Reachable lists every deny naming the subject among its exceptions, live and as of a time, on a
// session that limits GIN scans: such a session found one of 200 live, and none as of a time.
func TestReachableReadsEveryDenyWhereTheSessionLimitsGINScans(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := deniedClusters(t, h)
	fa, _ := fuzzy(t, h)
	u := h.as(t, "u")
	except := func(a *rbac.Authorizer) int {
		t.Helper()
		reach, err := a.Reachable(ctx, u, login, "t1", "cluster")
		if err != nil {
			t.Fatal(err)
		}
		return len(reach.Except)
	}
	if n := except(fa); n != 200 {
		t.Errorf("live: %d of the 200 denied clusters excepted", n)
	}
	if err := fa.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		if n := except(a); n != 200 {
			t.Errorf("as of a time: %d of the 200 denied clusters excepted", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Deleting a group takes it out of the denies exempting it and the eligibilities it approves, which
// it finds by the keys they name, on a session that limits GIN scans too: there 200 of 200 denies
// kept exempting it, and a later group of its id, which u joined, made u exempt from them. And
// DeleteGroup refuses it, as a deny exempts it, where it let it go and left 197.
func TestDeletingAGroupTakesItOutOfEveryDenyAndApprovalWhereTheSessionLimitsGINScans(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "ops")
	deniedClusters(t, h)
	fa, _ := fuzzy(t, h)
	if err := fa.DeleteGroup(ctx, h.as(t, "groups"), "t1", "ops"); !errors.Is(err, rbac.ErrInvalid) {
		t.Errorf("DeleteGroup of a group 200 denies exempt: %v", err)
	}
	if err := fa.DeletePrincipal(ctx, host, "t1", groupOf("ops")); err != nil {
		t.Fatal(err)
	}
	var exempting, approving int
	if err := h.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM rbac_denies WHERE 'group:ops' = ANY(exempt)),
		(SELECT count(*) FROM rbac_eligibilities WHERE 'group:ops' = ANY(approvers) OR approvers <> '{user:boss}')`).Scan(&exempting, &approving); err != nil {
		t.Fatal(err)
	}
	if exempting != 0 || approving != 0 {
		t.Errorf("of 200, %d denies still exempt the deleted group and %d eligibilities still have it approve", exempting, approving)
	}
	h.groups(t, "ops")
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	u, allowed := h.as(t, "u", "ops"), 0
	for i := 1; i <= 200; i++ {
		if h.authz.Authorize(ctx, u, login, onCluster(i)) == nil {
			allowed++
		}
	}
	if allowed != 0 {
		t.Errorf("u, in a later group ops, allowed on %d of the 200 clusters denied to it", allowed)
	}
}

// Adding a member to a group the denies on its path exempt lifts them, which needs the power to set
// them, read by the keys the denies exempt, on a session that limits GIN scans too: there a manager
// of members who holds no such power added u, which 200 denies bound, to a group they exempt, or
// was refused as a conflict, as the reads before and under the change's locks differed.
func TestAddingAMemberToAGroupDeniesExemptNeedsTheirPowerWhereTheSessionLimitsGINScans(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "ops")
	deniedClusters(t, h)
	// The denies alone, so a refusal is theirs.
	if _, err := h.pool.Exec(ctx, `DELETE FROM rbac_eligibilities`); err != nil {
		t.Fatal(err)
	}
	fa, _ := fuzzy(t, h)
	ops := rbac.Member{Group: "ops", Principal: identity("u")}
	manager := h.as(t, "manager")
	// Each time, as the denies such a session reads differ from one statement to the next.
	for range 10 {
		if err := fa.ChangeMembers(ctx, manager, "t1", []rbac.Member{ops}, nil); !errors.Is(err, rbac.ErrDenied) ||
			!strings.Contains(err.Error(), "cluster:deny") {
			t.Fatalf("adding u to a group 200 denies binding it exempt: %v", err)
		}
	}
}

// AsOf refuses a read one of whose statements set gin_fuzzy_search_limit, as those after it would
// find only some of the denies naming a key by history's GIN index.
func TestAsOfRefusesAReadThatLimitsGINScans(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	at := dbNow(t, h)
	if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
		err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(*rbac.Authorizer) error {
			_, err := tx.Exec(ctx, `SET LOCAL gin_fuzzy_search_limit = 1`)
			return err
		})
		if !errors.Is(err, rbac.ErrInvalid) {
			t.Errorf("AsOf whose read limited GIN scans: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Every call answers on a session that limits GIN scans as on a plain one: each read, live and as of
// a time, and each change, which it accepts or refuses alike and with which it writes the same, in a
// transaction rolled back. So a statement of the package's reading part of what a GIN index finds
// fails it, wherever it is.
func TestEveryCallAnswersAlikeWhereTheSessionLimitsGINScans(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "ops", "crew")
	h.seed(t, grant(rbac.Scope{Type: "org", ID: "o1"}, "cluster.login", rbac.Group, "crew"))
	// Beside the denies naming u, 200 naming crew that exempt w.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		SELECT 't1', 'cluster', 'c' || i, 'e', '{group:crew}', '{user:w}', '{cluster:*}' FROM generate_series(1, 200) i`); err != nil {
		t.Fatal(err)
	}
	subjects := []rbac.Subject{h.as(t, "x", "crew"), h.as(t, "w", "crew"), h.as(t, "v")}
	manager, groups := h.as(t, "manager"), h.as(t, "groups")
	h.join(t, "y")
	at := deniedClusters(t, h)
	subjects = append(subjects, h.as(t, "u"))
	fa, fuzzyPool := fuzzy(t, h)
	reads := func(a *rbac.Authorizer) []string {
		t.Helper()
		var out []string
		answer := func(what string, v any, err error) { out = append(out, fmt.Sprintf("%s: %+v, %v", what, v, err)) }
		for _, s := range subjects {
			who := s.Principal.ID
			for _, i := range []int{1, 200, 201} {
				answer(fmt.Sprintf("Authorize %s on c%d", who, i), nil, a.Authorize(ctx, s, login, onCluster(i)))
				d, err := a.Explain(ctx, s, login, onCluster(i))
				answer(fmt.Sprintf("Explain %s on c%d", who, i), []any{d.Allowed, d.DeniedBy, len(d.Grants)}, err)
				ps, err := a.Permissions(ctx, s, onCluster(i))
				answer(fmt.Sprintf("Permissions %s on c%d", who, i), ps, err)
			}
			reach, err := a.Reachable(ctx, s, login, "t1", "cluster")
			answer("Reachable "+who, reach, err)
			pred, err := a.Filter(ctx, s, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
			answer("Filter "+who, pred, err)
			answer("Filter's query "+who, filtered(ctx, t, a, h.pool, s), nil)
		}
		for _, i := range []int{1, 201} {
			holders, err := a.Holders(ctx, login, onCluster(i))
			answer(fmt.Sprintf("Holders on c%d", i), holders, err)
		}
		roles, err := a.Grantable(ctx, manager, onCluster(1))
		var ids []rbac.Role
		for _, r := range roles {
			ids = append(ids, r.ID)
		}
		answer("Grantable", ids, err)
		denies, err := a.Denies(ctx, "t1", []rbac.Scope{onCluster(1).Scope()})
		answer("Denies", len(denies), err)
		eligible, err := a.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("v")}})
		answer("Eligibilities", len(eligible), err)
		return out
	}
	alike := func(what string, plain, limited []string) {
		t.Helper()
		if len(plain) != len(limited) {
			t.Fatalf("%s: %d answers on a plain session, %d where it limits GIN scans", what, len(plain), len(limited))
		}
		for i := range plain {
			if plain[i] != limited[i] {
				t.Errorf("%s:\n  plain:   %.400s\n  limited: %.400s", what, plain[i], limited[i])
			}
		}
	}
	alike("live", reads(h.authz), reads(fa))
	asOf := func(a *rbac.Authorizer) []string {
		t.Helper()
		var out []string
		if err := a.AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			out = reads(a)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	alike("as of a time", asOf(h.authz), asOf(fa))
	history := func(a *rbac.Authorizer) []string {
		t.Helper()
		records, _, err := a.History(ctx, rbac.Cursor{}, 5000)
		return []string{fmt.Sprintf("%d records, %v", len(records), err), fmt.Sprintf("%+v", records)}
	}
	alike("History", history(h.authz), history(fa))
	ops, crew := rbac.Member{Group: "ops", Principal: identity("u")}, rbac.Member{Group: "crew", Principal: identity("w")}
	changes := []struct {
		name string
		run  func(a *rbac.Authorizer) error
	}{
		{"ChangeMembers adding u to ops", func(a *rbac.Authorizer) error {
			return a.ChangeMembers(ctx, manager, "t1", []rbac.Member{ops}, nil)
		}},
		{"ChangeMembers adding y to ops and taking w out of crew", func(a *rbac.Authorizer) error {
			return a.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "ops", Principal: identity("y")}}, []rbac.Member{crew})
		}},
		{"ImportMembers adding u to ops", func(a *rbac.Authorizer) error { return a.ImportMembers(ctx, host, "t1", []rbac.Member{ops}) }},
		{"DeleteGroup ops", func(a *rbac.Authorizer) error { return a.DeleteGroup(ctx, groups, "t1", "ops") }},
		{"DeleteGroups ops and crew", func(a *rbac.Authorizer) error { return a.DeleteGroups(ctx, host, "t1", []string{"ops", "crew"}) }},
		{"DeletePrincipal ops", func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", groupOf("ops")) }},
		{"DeletePrincipal crew", func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", groupOf("crew")) }},
		{"DeletePrincipal u", func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", identity("u")) }},
		{"DeletePrincipalEverywhere w", func(a *rbac.Authorizer) error { return a.DeletePrincipalEverywhere(ctx, host, identity("w")) }},
		{"DeleteMembers w from crew", func(a *rbac.Authorizer) error { return a.DeleteMembers(ctx, host, "t1", []rbac.Member{crew}) }},
	}
	for _, c := range changes {
		change := func(a *rbac.Authorizer, pool *pgxpool.Pool) []string {
			t.Helper()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			h.events = nil
			out := []string{fmt.Sprint(c.run(a.WithTx(tx)))}
			for _, e := range h.events {
				out = append(out, changed(e))
			}
			var denies, eligibilities, members, limit *string
			if err := tx.QueryRow(ctx, `SELECT
				(SELECT string_agg(concat_ws(' ', scope_id, id, principals, exempt), ', ' ORDER BY scope_id, id) FROM rbac_denies),
				(SELECT string_agg(concat_ws(' ', scope_id, principal, approvers), ', ' ORDER BY scope_id, principal) FROM rbac_eligibilities),
				(SELECT string_agg(concat_ws(' ', group_id, principal), ', ' ORDER BY group_id, principal) FROM rbac_members),
				current_setting('gin_fuzzy_search_limit')`).Scan(&denies, &eligibilities, &members, &limit); err != nil {
				t.Fatal(err)
			}
			// The host's transaction goes on with its own setting.
			if want := pool.Config().ConnConfig.RuntimeParams["gin_fuzzy_search_limit"]; want != "" && *limit != want {
				t.Errorf("%s: left the host's transaction with gin_fuzzy_search_limit %s", c.name, *limit)
			}
			return append(out, fmt.Sprintf("denies: %v", deref(denies)), fmt.Sprintf("eligibilities: %v", deref(eligibilities)),
				fmt.Sprintf("members: %v", deref(members)))
		}
		alike(c.name, change(h.authz, h.pool), change(fa, fuzzyPool))
	}
}

// changed is what e changed, by how many of each.
func changed(e rbac.ChangeEvent) string {
	v := reflect.ValueOf(e)
	var counts []string
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.Slice && f.Len() > 0 {
			counts = append(counts, fmt.Sprintf("%s %d", v.Type().Field(i).Name, f.Len()))
		}
	}
	return strings.Join(counts, ", ")
}

// deref is what s points to, or nil.
func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
