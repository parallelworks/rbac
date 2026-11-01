// Command shardcheck checks that CI's test shards ran every test between them: a test that shards
// skipped as another's ran in just that one, which each of them names, and every test go test
// -list names ended in every shard, run or skipped. Shards that read different timings, or count
// the shards differently, place some tests apart, and those run in no shard or in two, while go
// test passes a test every shard skips.
//
// Its argument is a directory holding one directory for each shard, with "shard", as
// RBAC_TEST_SHARD names it, "test-results.json", the go test -json output of its tests, and
// "test-list.json", that of go test -json -list.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shardcheck dir")
		os.Exit(2)
	}
	shards, err := readShards(os.DirFS(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "shardcheck:", err)
		os.Exit(1)
	}
	problems, summary := check(shards)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "shardcheck:", p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Println(summary)
}

type test struct{ pkg, name string }

func (t test) String() string { return t.pkg + " " + t.name }

func (t test) topLevel() bool { return !strings.Contains(t.name, "/") }

// outcome is how a test ended in one shard: pass, fail or skip, or "" where it didn't run there,
// and, where pgtest.URL skipped it as another shard's, that shard.
type outcome struct {
	action string
	in     int
}

func (o outcome) reached() bool { return o.action != "" && o.in == 0 }

type shard struct {
	dir          string
	index, count int
	ran          map[test]outcome
	listed       map[test]bool
}

func readShards(fsys fs.FS) ([]shard, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var shards []shard
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s, err := readShard(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		shards = append(shards, s)
	}
	if len(shards) == 0 {
		return nil, errors.New("no shards")
	}
	return shards, nil
}

func readShard(fsys fs.FS, dir string) (shard, error) {
	s := shard{dir: dir}
	spec, err := fs.ReadFile(fsys, dir+"/shard")
	if err != nil {
		return s, err
	}
	if s.index, s.count, err = parseShard(strings.TrimSpace(string(spec))); err != nil {
		return s, err
	}
	results, err := fsys.Open(dir + "/test-results.json")
	if err != nil {
		return s, err
	}
	defer func() { _ = results.Close() }()
	if s.ran, err = readResults(results, s.index, s.count); err != nil {
		return s, err
	}
	list, err := fsys.Open(dir + "/test-list.json")
	if err != nil {
		return s, err
	}
	defer func() { _ = list.Close() }()
	s.listed, err = readList(list)
	return s, err
}

// parseShard reads "i/n", the ith of n shards, counting from 1, as pgtest does.
func parseShard(spec string) (index, count int, err error) {
	i, n, ok := strings.Cut(spec, "/")
	index, errIndex := strconv.Atoi(i)
	count, errCount := strconv.Atoi(n)
	if !ok || errIndex != nil || errCount != nil || count < 1 || index < 1 || index > count {
		return 0, 0, fmt.Errorf("shard %q: want i/n, the ith of n shards, counting from 1", spec)
	}
	return index, count, nil
}

type event struct {
	Action, Package, Test, Output string
}

// The message pgtest.URL skips a test with, naming its top-level test, the shard it is in and how
// many there are.
var skipMessage = regexp.MustCompile(`(\S+) is in shard (\d+) of (\d+)$`)

// readResults reads how each test ended in the ith of n shards from its go test -json output. A
// skip is another shard's only where pgtest.URL's message names n shards and another than the ith,
// as a test of URL itself skips its subtests for shards that aren't CI's.
func readResults(r io.Reader, index, count int) (map[test]outcome, error) {
	ran := map[test]outcome{}
	err := events(r, func(e event) {
		if e.Test == "" {
			return
		}
		t := test{e.Package, e.Test}
		o := ran[t]
		switch e.Action {
		case "pass", "fail", "skip":
			o.action = e.Action
		case "output":
			top, _, _ := strings.Cut(e.Test, "/")
			m := skipMessage.FindStringSubmatch(strings.TrimSpace(e.Output))
			if m == nil || m[1] != top {
				return
			}
			in, errIn := strconv.Atoi(m[2])
			n, errN := strconv.Atoi(m[3])
			if errIn != nil || errN != nil || n != count || in == index || in < 1 || in > count {
				return
			}
			o.in = in
		default:
			return
		}
		ran[t] = o
	})
	for t, o := range ran {
		if o.action != "skip" && o.in != 0 {
			o.in = 0
			ran[t] = o
		}
	}
	return ran, err
}

// The names go test -list prints. It lists benchmarks too, which run only with -bench.
var listedName = regexp.MustCompile(`^(Test|Fuzz|Example)\w*$`)

// readList reads the top-level tests of each package from go test -json -list output.
func readList(r io.Reader) (map[test]bool, error) {
	listed := map[test]bool{}
	err := events(r, func(e event) {
		if name := strings.TrimSpace(e.Output); e.Action == "output" && listedName.MatchString(name) {
			listed[test{e.Package, name}] = true
		}
	})
	return listed, err
}

// events calls f with each event of go test -json output, passing over lines that aren't one.
func events(r io.Reader, f func(event)) error {
	lines := bufio.NewReader(r)
	for {
		line, err := lines.ReadBytes('\n')
		var e event
		if json.Unmarshal(line, &e) == nil {
			f(e)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// check is what is wrong with what the shards ran between them, and else a line saying what they
// ran. A test one shard skipped as another's ran in exactly that one, which every other skipping it
// names: it is placed by its top-level test, which every shard places alike.
func check(shards []shard) (problems []string, summary string) {
	count := shards[0].count
	by := make([]*shard, count+1)
	for i := range shards {
		s := &shards[i]
		switch {
		case s.count != count:
			problems = append(problems, fmt.Sprintf("%s is shard %d of %d, and %s of %d", s.dir, s.index, s.count, shards[0].dir, count))
		case by[s.index] != nil:
			problems = append(problems, fmt.Sprintf("%s and %s are both shard %d of %d", by[s.index].dir, s.dir, s.index, count))
		default:
			by[s.index] = s
		}
	}
	for i := 1; i <= count; i++ {
		if by[i] == nil {
			problems = append(problems, fmt.Sprintf("shard %d of %d didn't report", i, count))
		}
	}
	if len(problems) > 0 {
		return problems, ""
	}

	listed := by[1].listed
	ends := map[test][]outcome{}
	for t := range listed {
		ends[t] = make([]outcome, count+1)
	}
	for _, s := range by[1:] {
		for t := range s.listed {
			if !listed[t] {
				problems = append(problems, fmt.Sprintf("%s: go test -list names it in shard %d, not in shard 1", t, s.index))
			}
		}
		for t := range listed {
			if !s.listed[t] {
				problems = append(problems, fmt.Sprintf("%s: go test -list names it in shard 1, not in shard %d", t, s.index))
			}
		}
		for t, o := range s.ran {
			if ends[t] == nil {
				ends[t] = make([]outcome, count+1)
			}
			ends[t][s.index] = o
		}
	}

	once := map[test]bool{}
	for t, end := range ends {
		var in, ran, skipped []int
		for i, o := range end[1:] {
			switch {
			case o.in != 0:
				skipped = append(skipped, i+1)
				if !slices.Contains(in, o.in) {
					in = append(in, o.in)
				}
			case o.reached():
				ran = append(ran, i+1)
			case t.topLevel() && listed[t]:
				problems = append(problems, fmt.Sprintf("%s didn't run in shard %d", t, i+1))
			}
		}
		if t.topLevel() && !listed[t] && (len(ran) > 0 || len(skipped) > 0) {
			problems = append(problems, fmt.Sprintf("%s ran, and go test -list doesn't name it", t))
		}
		if len(in) == 0 {
			continue
		}
		top, _, _ := strings.Cut(t.name, "/")
		once[test{t.pkg, top}] = true
		slices.Sort(in)
		switch {
		case len(ran) == 0:
			problems = append(problems, fmt.Sprintf("%s ran in no shard: shards %v skipped it as shard %v's", t, skipped, in))
		case len(in) > 1:
			problems = append(problems, fmt.Sprintf("%s: shards %v skipped it as shards %v's, and it ran in shards %v", t, skipped, in, ran))
		case len(ran) > 1 || ran[0] != in[0]:
			problems = append(problems, fmt.Sprintf("%s ran in shards %v, and shards %v skipped it as shard %d's", t, ran, skipped, in[0]))
		}
	}
	if count > 1 && len(once) == 0 {
		problems = append(problems, fmt.Sprintf("no shard skipped a test as another's, so each of the %d ran every test or none: has pgtest.URL's message changed?", count))
	}
	slices.Sort(problems)
	return problems, fmt.Sprintf("shardcheck: of the %d tests go test -list names, %d ran in one of the %d shards and %d in each",
		len(listed), len(once), count, len(listed)-len(once))
}
