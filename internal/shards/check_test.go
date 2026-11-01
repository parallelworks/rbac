package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const pkg = "example.com/p"

// ran is the go test -json output of a run of the tests named, which end as action.
func ran(action string, names ...string) []string {
	var events []string
	for _, name := range names {
		events = append(events,
			fmt.Sprintf(`{"Action":"run","Package":%q,"Test":%q}`, pkg, name),
			fmt.Sprintf(`{"Action":"output","Package":%q,"Test":%q,"Output":"=== RUN   %s\n"}`, pkg, name, name),
			fmt.Sprintf(`{"Action":%q,"Package":%q,"Test":%q,"Elapsed":0.1}`, action, pkg, name))
	}
	return events
}

// listOf is go test -json -list output naming the tests.
func listOf(names ...string) string {
	list := []string{`# example.com/p`}
	for _, name := range names {
		list = append(list, fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"%s\n"}`, pkg, name))
	}
	list = append(list,
		fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"BenchmarkNotRun\n"}`, pkg),
		fmt.Sprintf(`{"Action":"output","Package":%q,"Output":"ok  \t%s\t0.01s\n"}`, pkg, pkg))
	return strings.Join(list, "\n")
}

// shards is the directory the go job checks, of a shard for each of runs, each listing listed.
func shards(listed []string, runs ...[]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for i, run := range runs {
		dir := fmt.Sprintf("test-results-%d/", i+1)
		fsys[dir+"shard"] = &fstest.MapFile{Data: fmt.Appendf(nil, "%d/%d\n", i+1, len(runs))}
		fsys[dir+"test-results.json"] = &fstest.MapFile{Data: []byte(strings.Join(run, "\n"))}
		fsys[dir+"test-list.json"] = &fstest.MapFile{Data: []byte(listOf(listed...))}
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

// Shards that between them ran each test once pass, a subtest that skipped among them, and a shard
// that ran none.
func TestShardsThatRanEachTestOnceArePassed(t *testing.T) {
	fsys := shards([]string{"TestA", "TestB", "TestC"},
		slices.Concat(ran("pass", "TestA"), ran("skip", "TestA/sub"), ran("pass", "TestB")),
		ran("fail", "TestC"),
		nil,
	)
	read, err := readShards(fsys)
	if err != nil {
		t.Fatal(err)
	}
	problems, summary := check(read)
	if len(problems) > 0 {
		t.Errorf("shards that ran each test once: %q", problems)
	}
	if want := "the 3 shards ran each of the 3 tests go test -list names once, 2, 1, 0 of them"; !strings.Contains(summary, want) {
		t.Errorf("summary %q, want %q", summary, want)
	}
}

// A top-level test that skipped tested nothing, though it ran: in CI, where the check runs, nothing
// should keep a test from running.
func TestATestThatSkippedIsFound(t *testing.T) {
	wantProblem(t, problemsOf(t, shards([]string{"TestA", "TestB"},
		ran("pass", "TestA"), ran("skip", "TestB"),
	)), "example.com/p TestB skipped in shard 2")
}

func TestATestNoShardRanIsFound(t *testing.T) {
	wantProblem(t, problemsOf(t, shards([]string{"TestA", "TestB", "TestLost"},
		ran("pass", "TestA"), ran("pass", "TestB"),
	)), "example.com/p TestLost ran in no shard")
}

func TestATestTwoShardsRanIsFound(t *testing.T) {
	wantProblem(t, problemsOf(t, shards([]string{"TestA", "TestTwice"},
		ran("pass", "TestA", "TestTwice"), ran("pass", "TestTwice"), nil,
	)), "example.com/p TestTwice ran in shards [1 2]")
}

func TestAShardThatDidntReportIsFound(t *testing.T) {
	fsys := shards([]string{"TestA", "TestB"}, ran("pass", "TestA"), ran("pass", "TestB"))
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

// The shards list the same tests, and run none the list doesn't name.
func TestTheShardsRunWhatTheirListsName(t *testing.T) {
	fsys := shards([]string{"TestA", "TestB"}, ran("pass", "TestA", "TestUnlisted"), ran("pass", "TestB"))
	wantProblem(t, problemsOf(t, fsys), "example.com/p TestUnlisted ran in shards [1], and go test -list doesn't name it")
	fsys["test-results-2/test-list.json"] = &fstest.MapFile{Data: []byte(listOf("TestA", "TestB", "TestC"))}
	wantProblem(t, problemsOf(t, fsys), "example.com/p TestC: go test -list names it in shard 2, not in shard 1")
	fsys["test-results-2/test-list.json"] = &fstest.MapFile{Data: []byte(listOf("TestA"))}
	wantProblem(t, problemsOf(t, fsys), "example.com/p TestB: go test -list names it in shard 1, not in shard 2")
}
