package pgtest

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A template is filled once however many tests ask for it, until it is dropped.
func TestATemplateIsFilledOnce(t *testing.T) {
	fills := 0
	fill := func(ctx context.Context, pool *pgxpool.Pool) error {
		fills++
		_, err := pool.Exec(ctx, `CREATE TABLE filled (n int)`)
		return err
	}
	first := Template(t, "once", fill)
	t.Cleanup(func() {
		if err := DropTemplates(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	})
	if again := Template(t, "once", fill); again != first || fills != 1 {
		t.Errorf("asked for again, the template was %s, then %s, filled %d times", first, again, fills)
	}
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, URL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `SELECT FROM `+first+`.filled`); err != nil {
		t.Fatal(err)
	}
	if err := DropTemplates(ctx); err != nil {
		t.Fatal(err)
	}
	var left bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_namespace WHERE quote_ident(nspname) = $1)`, first).Scan(&left); err != nil || left {
		t.Errorf("a dropped template's schema is left: %v, %v", left, err)
	}
}

// A test that can't run is skipped, but in CI it fails.
func TestSkipFailsInCI(t *testing.T) {
	if os.Getenv("PGTEST_SKIP_CHILD") != "" {
		Skip(t, "autovacuum is off")
		return
	}
	for _, ci := range []string{"", "true"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSkipFailsInCI$", "-test.v")
		cmd.Env = append(os.Environ(), "PGTEST_SKIP_CHILD=1", "CI="+ci)
		out, err := cmd.CombinedOutput()
		failed, skipped := err != nil, strings.Contains(string(out), "--- SKIP: TestSkipFailsInCI")
		if failed != (ci != "") || skipped == (ci != "") {
			t.Errorf("CI=%q: failed %t, skipped %t:\n%s", ci, failed, skipped, out)
		}
	}
}

// Without the database's URL, a test is skipped, but in CI it fails.
func TestURLFailsWithoutTheDatabaseInCI(t *testing.T) {
	if os.Getenv("PGTEST_URL_CHILD") != "" {
		URL(t)
		return
	}
	for _, ci := range []string{"", "true"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestURLFailsWithoutTheDatabaseInCI$")
		cmd.Env = append(os.Environ(), "PGTEST_URL_CHILD=1", URLEnv+"=", "CI="+ci)
		out, err := cmd.CombinedOutput()
		if failed := err != nil; failed != (ci != "") {
			t.Errorf("CI=%q: failed %t, want %t:\n%s", ci, failed, ci != "", out)
		}
	}
}
