package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// checkMain is shards check.
func checkMain(args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}
	shards, err := readShards(os.DirFS(args[0]))
	if err != nil {
		return err
	}
	problems, summary := check(shards)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "shards:", p)
	}
	if len(problems) > 0 {
		return fmt.Errorf("the shards didn't run each test once: %d problems", len(problems))
	}
	fmt.Println(summary)
	return nil
}

type shard struct {
	dir          string
	index, count int
	// ran holds how each top-level test ended where it ran: pass, fail or skip.
	ran    map[test]string
	listed map[test]bool
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
	s := shard{dir: dir, ran: map[test]string{}}
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
	if err := events(results, func(e event) {
		if t := (test{e.Package, e.Test}); e.Test != "" && t.topLevel() && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip") {
			s.ran[t] = e.Action
		}
	}); err != nil {
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

// check is what is wrong with what the shards ran between them, a top-level test that skipped too,
// and else a line saying what they ran. A shard runs its top-level tests whole, subtests and all,
// so each subtest runs once where its top-level test does.
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
	ranIn := map[test][]int{}
	ran := make([]int, count+1)
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
		for t, action := range s.ran {
			ranIn[t] = append(ranIn[t], s.index)
			ran[s.index]++
			// A skip tests nothing, and CI is where every test can run: one that can't fails there,
			// as pgtest.Skip has it, rather than pass the run unseen.
			if action == "skip" {
				problems = append(problems, fmt.Sprintf("%s skipped in shard %d", t, s.index))
			}
		}
	}
	for t := range listed {
		if in := ranIn[t]; len(in) == 0 {
			problems = append(problems, fmt.Sprintf("%s ran in no shard", t))
		} else if len(in) > 1 {
			slices.Sort(in)
			problems = append(problems, fmt.Sprintf("%s ran in shards %v", t, in))
		}
	}
	for t, in := range ranIn {
		if !listed[t] {
			slices.Sort(in)
			problems = append(problems, fmt.Sprintf("%s ran in shards %v, and go test -list doesn't name it", t, in))
		}
	}
	slices.Sort(problems)
	each := make([]string, count)
	for i, n := range ran[1:] {
		each[i] = fmt.Sprint(n)
	}
	return problems, fmt.Sprintf("shards: the %d shards ran each of the %d tests go test -list names once, %s of them",
		count, len(listed), strings.Join(each, ", "))
}
