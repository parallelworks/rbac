package pgtest

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseShard(t *testing.T) {
	for spec, want := range map[string][2]int{"1/1": {1, 1}, "3/4": {3, 4}, "4/4": {4, 4}} {
		if index, count, err := parseShard(spec); err != nil || [2]int{index, count} != want {
			t.Errorf("parseShard(%q) = %d, %d, %v", spec, index, count, err)
		}
	}
	for _, spec := range []string{"", "1", "0/4", "5/4", "1/0", "-1/4", "a/4", "1/b", "1/4/2", " 1/4"} {
		if index, count, err := parseShard(spec); err == nil {
			t.Errorf("parseShard(%q) = %d, %d, not an error", spec, index, count)
		}
	}
}

// The tests timed are placed longest first, each in the shard with the least so far, so a few long
// ones are spread apart and the rest fill in around them; the others are placed by their names.
func TestShardsBalanceTheTimesOfTheirTests(t *testing.T) {
	timings := map[string]float64{"TestA": 8, "TestB": 7, "TestC": 6, "TestD": 5, "TestE": 4, "TestF": 3, "TestG": 2, "TestH": 1}
	s := newShards(2, timings)
	loads := make([]float64, 2)
	for test, seconds := range timings {
		loads[s.of(test)-1] += seconds
	}
	if !slices.Equal(loads, []float64{18, 18}) {
		t.Errorf("shards of %v take %v seconds", timings, loads)
	}
	// Heavy-tailed, as the package's tests are: a few take a minute and most a moment.
	timings = map[string]float64{}
	for i := range 600 {
		timings[fmt.Sprintf("Test%d", i)] = 60 / float64(1+i*i%97)
	}
	total, longest := 0.0, 0.0
	for _, seconds := range timings {
		total, longest = total+seconds, max(longest, seconds)
	}
	for count := 1; count <= 8; count++ {
		s := newShards(count, timings)
		loads := make([]float64, count)
		for test, seconds := range timings {
			loads[s.of(test)-1] += seconds
		}
		if most := slices.Max(loads); most > max(total/float64(count), longest)*4/3 {
			t.Errorf("of %d shards of %.0f seconds, the longest takes %.0f", count, total, most)
		}
	}
}

func TestShardsPlaceEveryTestInOneOfThem(t *testing.T) {
	timed := newShards(4, map[string]float64{"TestA": 3, "TestB": 2})
	untimed := newShards(4, nil)
	shards := map[int]bool{}
	for i := range 1000 {
		test := fmt.Sprintf("TestUntimed%d", i)
		in := timed.of(test)
		if in < 1 || in > 4 || in != untimed.of(test) || in != newShards(4, nil).of(test) {
			t.Fatalf("%s is in shard %d, and %d untimed", test, in, untimed.of(test))
		}
		shards[in] = true
	}
	if len(shards) != 4 {
		t.Errorf("1000 tests are in only shards %v of 4", slices.Sorted(maps.Keys(shards)))
	}
}

func TestReadTimingsTakesEachTopLevelTestsLongestRun(t *testing.T) {
	long := strings.Repeat("x", 1<<20)
	output := strings.Join([]string{
		`# github.com/parallelworks/rbac`,
		`{"Action":"start","Package":"github.com/parallelworks/rbac"}`,
		`{"Action":"run","Package":"github.com/parallelworks/rbac","Test":"TestA"}`,
		`{"Action":"output","Package":"github.com/parallelworks/rbac","Test":"TestA","Output":"` + long + `\n"}`,
		`{"Action":"pass","Package":"github.com/parallelworks/rbac","Test":"TestA/sub","Elapsed":9}`,
		`{"Action":"pass","Package":"github.com/parallelworks/rbac","Test":"TestA","Elapsed":4.5}`,
		`{"Action":"skip","Package":"github.com/parallelworks/rbac","Test":"TestB","Elapsed":0}`,
		`{"Action":"pass","Package":"github.com/parallelworks/rbac","Test":"TestB","Elapsed":2}`,
		`{"Action":"pass","Package":"github.com/parallelworks/rbac","Test":"TestB","Elapsed":0.1}`,
		`{"Action":"fail","Package":"github.com/parallelworks/rbac","Test":"TestC","Elapsed":1}`,
		`{"Action":"skip","Package":"github.com/parallelworks/rbac","Test":"TestD","Elapsed":0}`,
		`{"Action":"pass","Package":"github.com/parallelworks/rbac","Elapsed":30}`,
	}, "\n")
	got, err := readTimings(strings.NewReader(output))
	if want := map[string]float64{"TestA": 4.5, "TestB": 2, "TestC": 1}; err != nil || !maps.Equal(got, want) {
		t.Errorf("readTimings = %v, %v, want %v", got, err, want)
	}
}

// URL skips a test, and each of its subtests, in every shard but its own: by its time where the
// timings name it, and by its name where they don't.
func TestURLSkipsTestsInOtherShards(t *testing.T) {
	t.Setenv(URLEnv, "postgres://localhost/unused")
	const count = 3
	hashed := newShards(count, nil).of(t.Name())
	timings := map[string]float64{t.Name(): 10}
	timed := 1
	if hashed == timed {
		timings["TestLonger"], timed = 20, 2
	}
	file := filepath.Join(t.TempDir(), "timings.json")
	var lines []string
	for test, seconds := range timings {
		lines = append(lines, fmt.Sprintf(`{"Action":"pass","Test":%q,"Elapsed":%v}`, test, seconds))
	}
	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		by, timings string
		in          int
	}{{"name", "", hashed}, {"time", file, timed}} {
		t.Setenv(TimingsEnv, c.timings)
		for index := 1; index <= count; index++ {
			t.Setenv(ShardEnv, fmt.Sprintf("%d/%d", index, count))
			reached := false
			t.Run(fmt.Sprintf("shard %d by %s", index, c.by), func(t *testing.T) {
				URL(t)
				reached = true
			})
			if reached != (index == c.in) {
				t.Errorf("placed by %s, shard %d of %d ran the test: %v; it is in shard %d", c.by, index, count, reached, c.in)
			}
		}
	}
}

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
