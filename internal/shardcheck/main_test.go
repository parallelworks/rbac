package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const pkg = "example.com/p"

// ran is a test's go test -json events where it ran and passed.
func ran(name string) []string {
	return []string{
		fmt.Sprintf(`{"Action":"run","Package":%q,"Test":%q}`, pkg, name),
		fmt.Sprintf(`{"Action":"pass","Package":%q,"Test":%q,"Elapsed":0.1}`, pkg, name),
	}
}

// skippedAs is a test's events where pgtest.URL skipped it as the inth of count shards'.
func skippedAs(name string, in, count int) []string {
	top, _, _ := strings.Cut(name, "/")
	return []string{
		fmt.Sprintf(`{"Action":"run","Package":%q,"Test":%q}`, pkg, name),
		fmt.Sprintf(`{"Action":"output","Package":%q,"Test":%q,"Output":"    p_test.go:9: %s is in shard %d of %d\n"}`, pkg, name, top, in, count),
		fmt.Sprintf(`{"Action":"output","Package":%q,"Test":%q,"Output":"--- SKIP: %s (0.00s)\n","OutputType":"frame"}`, pkg, name, name),
		fmt.Sprintf(`{"Action":"skip","Package":%q,"Test":%q,"Elapsed":0}`, pkg, name),
	}
}

// shards is the directory the gate reads, of a shard for each of runs, with every top-level test
// any of them ran listed in each.
func shards(t *testing.T, runs ...[][]string) fstest.MapFS {
	t.Helper()
	var listed []string
	for _, run := range runs {
		for _, events := range run {
			for _, e := range events {
				if name, ok := strings.CutPrefix(e, `{"Action":"run","Package":"`+pkg+`","Test":"`); ok {
					if name = strings.TrimSuffix(name, `"}`); !strings.Contains(name, "/") && !slices.Contains(listed, name) {
						listed = append(listed, name)
					}
				}
			}
		}
	}
	list := []string{`# example.com/p`}
	for _, name := range listed {
		list = append(list, fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"%s\n"}`, pkg, name))
	}
	list = append(list,
		fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"BenchmarkNotRun\n"}`, pkg),
		fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"ok  \t%s\t0.01s\n"}`, pkg, pkg))
	fsys := fstest.MapFS{}
	for i, run := range runs {
		dir := fmt.Sprintf("test-results-%d/", i+1)
		fsys[dir+"shard"] = &fstest.MapFile{Data: fmt.Appendf(nil, "%d/%d\n", i+1, len(runs))}
		fsys[dir+"test-results.json"] = &fstest.MapFile{Data: []byte(strings.Join(slices.Concat(run...), "\n"))}
		fsys[dir+"test-list.json"] = &fstest.MapFile{Data: []byte(strings.Join(list, "\n"))}
	}
	return fsys
}

func problemsOf(t *testing.T, fsys fstest.MapFS) []string {
	t.Helper()
	read, err := readShards(fsys)
	if err != nil {
		t.Fatal(err)
	}
	problems, _ := check(read)
	return problems
}

// wantProblem fails t unless one of problems holds each of want.
func wantProblem(t *testing.T, problems []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, w) }) {
			t.Errorf("no problem says %q: %q", w, problems)
		}
	}
}

// Shards that each ran their own tests and skipped the others' ran every test between them: a test
// of the database in one, as its top-level test's shard, and one of none in each. A test of
// pgtest.URL skips its subtests as shards it makes up, whatever shard runs it.
func TestShardsThatRanEachTestOnceArePassed(t *testing.T) {
	fsys := shards(t,
		[][]string{
			ran("TestDatabase"), skippedAs("TestOther", 2, 2), ran("TestPure"),
			ran("TestSubtests"), skippedAs("TestSubtests/database", 2, 2), ran("TestSubtests/pure"),
			ran("TestURL"), skippedAs("TestURL/shard_2_of_3", 1, 3), ran("TestURL/shard_1_of_3"),
			skippedAs("TestURL/shard_2_of_2", 1, 2), ran("TestURL/shard_1_of_2"),
		},
		[][]string{
			skippedAs("TestDatabase", 1, 2), ran("TestOther"), ran("TestPure"),
			ran("TestSubtests"), ran("TestSubtests/database"), ran("TestSubtests/pure"),
			ran("TestURL"), skippedAs("TestURL/shard_2_of_3", 1, 3), ran("TestURL/shard_1_of_3"),
			skippedAs("TestURL/shard_2_of_2", 1, 2), ran("TestURL/shard_1_of_2"),
		},
	)
	read, err := readShards(fsys)
	if err != nil {
		t.Fatal(err)
	}
	problems, summary := check(read)
	if len(problems) > 0 {
		t.Errorf("shards that ran each test once: %q", problems)
	}
	if want := "of the 5 tests go test -list names, 4 ran in one of the 2 shards and 1 in each"; !strings.Contains(summary, want) {
		t.Errorf("summary %q, want %q", summary, want)
	}
}

// Shards that read different timings each skip as another's a test that one places with them.
func TestATestEveryShardSkipsAsAnothersRanInNone(t *testing.T) {
	wantProblem(t, problemsOf(t, shards(t,
		[][]string{ran("TestKept"), skippedAs("TestLost", 2, 2), ran("TestSubtests"), skippedAs("TestSubtests/lost", 2, 2)},
		[][]string{skippedAs("TestKept", 1, 2), skippedAs("TestLost", 1, 2), ran("TestSubtests"), skippedAs("TestSubtests/lost", 1, 2)},
	)), "TestLost ran in no shard", "TestSubtests/lost ran in no shard")
}

func TestATestTwoShardsRunAsTheirOwnIsFound(t *testing.T) {
	wantProblem(t, problemsOf(t, shards(t,
		[][]string{ran("TestTwice"), skippedAs("TestPlaced", 3, 3)},
		[][]string{ran("TestTwice"), skippedAs("TestPlaced", 1, 3)},
		[][]string{skippedAs("TestTwice", 1, 3), ran("TestPlaced")},
	)), "TestTwice ran in shards [1 2], and shards [3] skipped it as shard 1's", "TestPlaced: shards [1 2] skipped it as shards [1 3]'s")
}

func TestAShardThatDidntReportIsFound(t *testing.T) {
	fsys := shards(t, [][]string{ran("TestA"), skippedAs("TestB", 2, 3)}, [][]string{skippedAs("TestA", 1, 3), ran("TestB")})
	fsys["test-results-1/shard"] = &fstest.MapFile{Data: []byte("1/3\n")}
	fsys["test-results-2/shard"] = &fstest.MapFile{Data: []byte("2/3\n")}
	wantProblem(t, problemsOf(t, fsys), "shard 3 of 3 didn't report")
	fsys["test-results-2/shard"] = &fstest.MapFile{Data: []byte("1/3\n")}
	wantProblem(t, problemsOf(t, fsys), "test-results-1 and test-results-2 are both shard 1 of 3")
	fsys["test-results-2/shard"] = &fstest.MapFile{Data: []byte("2/2\n")}
	wantProblem(t, problemsOf(t, fsys), "test-results-2 is shard 2 of 2, and test-results-1 of 3")
	fsys["test-results-2/shard"] = &fstest.MapFile{Data: []byte("3/2\n")}
	if _, err := readShards(fsys); err == nil {
		t.Error("a shard 3 of 2 was read")
	}
}

// Every test go test -list names ends in each shard, as each runs the whole of each package, and
// none it doesn't name runs.
func TestEveryTestListedEndsInEveryShard(t *testing.T) {
	fsys := shards(t,
		[][]string{ran("TestA"), skippedAs("TestB", 2, 2), ran("TestCut")},
		[][]string{skippedAs("TestA", 1, 2), ran("TestB")},
	)
	wantProblem(t, problemsOf(t, fsys), "TestCut didn't run in shard 2")
	fsys["test-results-1/test-list.json"] = &fstest.MapFile{Data: []byte(`{"Action":"output","Package":"example.com/p","Output":"TestA\n"}
{"Action":"output","Package":"example.com/p","Output":"TestB\n"}`)}
	wantProblem(t, problemsOf(t, fsys), "TestCut ran, and go test -list doesn't name it", "TestCut: go test -list names it in shard 2, not in shard 1")
}

// Where no shard skipped a test as another's, each ran every test, or none, as where none was
// given the database or pgtest.URL's message no longer reads as the check expects.
func TestShardsThatSkippedNothingAsAnothersAreFound(t *testing.T) {
	wantProblem(t, problemsOf(t, shards(t,
		[][]string{ran("TestA"), ran("TestB")},
		[][]string{ran("TestA"), ran("TestB")},
	)), "no shard skipped a test as another's")
	if problems := problemsOf(t, shards(t, [][]string{ran("TestA"), ran("TestB")})); len(problems) > 0 {
		t.Errorf("a single shard: %q", problems)
	}
}
