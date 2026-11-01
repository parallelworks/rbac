package main

import (
	"bytes"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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
// ones are spread apart and the rest fill in around them.
func TestShardsBalanceTheTimesOfTheirTests(t *testing.T) {
	timings := map[string]float64{"TestA": 8, "TestB": 7, "TestC": 6, "TestD": 5, "TestE": 4, "TestF": 3, "TestG": 2, "TestH": 1}
	in := place(slices.Sorted(maps.Keys(timings)), timings, 2)
	loads := make([]float64, 2)
	for test, seconds := range timings {
		loads[in[test]-1] += seconds
	}
	if !slices.Equal(loads, []float64{18, 18}) {
		t.Errorf("shards of %v take %v seconds", timings, loads)
	}
	// Heavy-tailed, as the package's tests are: a few take a minute and most a moment.
	timings = map[string]float64{}
	for i := range 600 {
		timings[fmt.Sprintf("Test%d", i)] = 60 / float64(1+i*i%97)
	}
	names := slices.Sorted(maps.Keys(timings))
	total, longest := 0.0, 0.0
	for _, seconds := range timings {
		total, longest = total+seconds, max(longest, seconds)
	}
	for count := 1; count <= 8; count++ {
		in := place(names, timings, count)
		loads := make([]float64, count)
		for test, seconds := range timings {
			loads[in[test]-1] += seconds
		}
		if most := slices.Max(loads); most > max(total/float64(count), longest)*4/3 {
			t.Errorf("of %d shards of %.0f seconds, the longest takes %.0f", count, total, most)
		}
	}
}

// Each test is in one shard, those the timings don't time by their names alone, wherever the
// timings place others, and timings of tests no longer listed place nothing.
func TestShardsPlaceEveryTestInOneOfThem(t *testing.T) {
	var names []string
	for i := range 1000 {
		names = append(names, fmt.Sprintf("TestUntimed%d", i))
	}
	untimed := place(names, nil, 4)
	timed := place(append([]string{"TestA", "TestB"}, names...), map[string]float64{"TestA": 3, "TestB": 2, "TestGone": 100}, 4)
	shards := map[int]bool{}
	for _, name := range names {
		in := timed[name]
		if in < 1 || in > 4 || in != untimed[name] {
			t.Fatalf("%s is in shard %d, and %d untimed", name, in, untimed[name])
		}
		shards[in] = true
	}
	if len(shards) != 4 {
		t.Errorf("1000 tests are in only shards %v of 4", slices.Sorted(maps.Keys(shards)))
	}
	if timed["TestA"] != 1 || timed["TestB"] != 2 || len(timed) != 1002 {
		t.Errorf("a test no longer listed took a shard's time: TestA is in shard %d, TestB in %d, of %d placed", timed["TestA"], timed["TestB"], len(timed))
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

// go test -list names a test by go test's own rule, of any letters, digits and underscores, and a
// line of its output that names neither a test nor its package fails the read: a test of a name the
// rule passed over would run in no shard, unseen.
func TestReadListTakesEveryNameGoTestGivesATest(t *testing.T) {
	list := func(lines ...string) string {
		output := []string{`# example.com/p`, `{"Action":"build-output","ImportPath":"example.com/p","Output":"# example.com/p\n"}`}
		for _, line := range lines {
			output = append(output, fmt.Sprintf(`{"Action":"output","Package":"example.com/p","Output":%q}`, line+"\n"))
		}
		return strings.Join(output, "\n")
	}
	names := []string{"Test", "TestA", "Test_a", "TestCafé", "TestΣum", "Test٣", "FuzzΔ", "Example", "ExampleA_ünicode"}
	listed, err := readList(strings.NewReader(list(slices.Concat(names, []string{
		"Benchmark", "BenchmarkΣ", "ok  \texample.com/p\t0.01s", "?   \texample.com/q\t[no test files]", "program not built with -cover", "",
	})...)))
	want := map[test]bool{}
	for _, name := range names {
		want[test{"example.com/p", name}] = true
	}
	if err != nil || !maps.Equal(listed, want) {
		t.Errorf("readList = %v, %v, want %v", listed, err, want)
	}
	for _, line := range []string{"hello from TestMain", "Testé", "Test-a", "FAIL\texample.com/p [build failed]"} {
		if _, err := readList(strings.NewReader(list("TestA", line))); err == nil {
			t.Errorf("readList read a list printing %q", line)
		}
	}
}

// A pattern selects the top-level tests it names, and no other, however one's name begins or ends
// another's.
func TestAPatternSelectsTheTestsItNamesAlone(t *testing.T) {
	for _, names := range [][]string{nil, {"TestA"}, {"TestA", "TestB_c", "FuzzD", "ExampleE"}} {
		re := regexp.MustCompile(pattern(names))
		for _, name := range []string{"TestA", "TestAB", "XTestA", "TestB_c", "TestB", "FuzzD", "ExampleE"} {
			if re.MatchString(name) != slices.Contains(names, name) {
				t.Errorf("the pattern of %q, %s, matches %q: %t", names, re, name, !slices.Contains(names, name))
			}
		}
	}
}

// Each shard runs its top-level tests whole, and no others: a test whose own body reads what its
// subtests did runs once, with them, and passes, where a shard that ran it while skipping them
// fails it.
func TestEachShardRunsItsTestsWholeAndNoOthers(t *testing.T) {
	ctx := t.Context()
	const count = 3
	pkgs := []string{"./testdata/aggregate"}
	list, err := exec.CommandContext(ctx, "go", append([]string{"test", "-json", "-list", "."}, pkgs...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{}
	for index := 1; index <= count; index++ {
		run, _, err := selection(ctx, index, count, "", pkgs)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "go", append([]string{"test", "-json", "-count=1", "-run", run}, pkgs...)...)
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("shard %d of %d, -run %s: %v\n%s%s", index, count, run, err, stderr.Bytes(), out.Bytes())
		}
		dir := fmt.Sprintf("test-results-%d/", index)
		fsys[dir+"shard"] = &fstest.MapFile{Data: fmt.Appendf(nil, "%d/%d", index, count)}
		fsys[dir+"test-list.json"] = &fstest.MapFile{Data: list}
		fsys[dir+"test-results.json"] = &fstest.MapFile{Data: out.Bytes()}
	}
	read, err := readShards(fsys)
	if err != nil {
		t.Fatal(err)
	}
	problems, summary := check(read)
	if len(problems) > 0 {
		t.Fatalf("the shards ran: %q", problems)
	}
	const want = "the 3 shards ran each of the 6 tests go test -list names once"
	if !strings.Contains(summary, want) {
		t.Errorf("summary %q, want %q", summary, want)
	}
	// Its subtests too ran once each, where it did.
	var subtests []string
	for _, s := range read {
		if err := events(bytes.NewReader(fsys[s.dir+"/test-results.json"].Data), func(e event) {
			if strings.HasPrefix(e.Test, "TestParentOfSubtests/") && e.Action == "pass" {
				subtests = append(subtests, e.Test)
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	if slices.Sort(subtests); !slices.Equal(subtests, []string{"TestParentOfSubtests/0", "TestParentOfSubtests/1", "TestParentOfSubtests/2"}) {
		t.Errorf("between the shards, the parent's subtests that passed were %q", subtests)
	}
}
