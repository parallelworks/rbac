package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"maps"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// selectMain is shards select.
func selectMain(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("select", flag.ContinueOnError)
	spec := flags.String("shard", "", "the shard to select, as i/n, the ith of n")
	timings := flags.String("timings", "", "a file of go test -json output whose times balance the shards")
	if err := flags.Parse(args); err != nil {
		return err
	}
	index, count, err := parseShard(*spec)
	if err != nil {
		return err
	}
	run, summary, err := selection(ctx, index, count, *timings, flags.Args())
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, summary)
	fmt.Println(run)
	return nil
}

// selection is the go test -run pattern of the ith of count shards' top-level tests, of those go
// test -list names with args, placed by the times in timings, a file, if any; and a line saying what
// it selected.
func selection(ctx context.Context, index, count int, timings string, args []string) (run, summary string, err error) {
	times, err := timingsOf(timings)
	if err != nil {
		return "", "", err
	}
	names, err := listNames(ctx, args)
	if err != nil {
		return "", "", err
	}
	in := place(names, times, count)
	var selected []string
	var timed, total float64
	untimed := 0
	for _, name := range names {
		seconds, ok := times[name]
		total += seconds
		if in[name] != index {
			continue
		}
		selected = append(selected, name)
		timed += seconds
		if !ok {
			untimed++
		}
	}
	return pattern(selected), fmt.Sprintf("shards: shard %d of %d runs %d of the %d tests, %.0f of their %.0f seconds timed, and %d untimed",
		index, count, len(selected), len(names), timed, total, untimed), nil
}

// listNames is the top-level tests' names that go test -list names with args, its flags and
// packages, in order, each once: tests of the same name in two packages are placed together.
func listNames(ctx context.Context, args []string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", append([]string{"test", "-json", "-list", "."}, args...)...) //nolint:gosec // make test passes its own flags and packages
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	listed, err := readList(out)
	if err := errors.Join(err, cmd.Wait()); err != nil {
		return nil, fmt.Errorf("go test -list: %w", err)
	}
	names := map[string]bool{}
	for t := range listed {
		names[t.name] = true
	}
	if len(names) == 0 {
		return nil, errors.New("go test -list names no tests")
	}
	return slices.Sorted(maps.Keys(names)), nil
}

func timingsOf(file string) (map[string]float64, error) {
	if file == "" {
		return nil, nil
	}
	f, err := os.Open(file) //nolint:gosec // the person running the tests names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readTimings(f)
}

// readTimings reads the seconds each top-level test took from go test -json output, by its name:
// the longest of its runs, where the output is of several, as of every shard of a run.
func readTimings(r io.Reader) (map[string]float64, error) {
	times := map[string]float64{}
	err := events(r, func(e event) {
		if e.Test != "" && !strings.Contains(e.Test, "/") && (e.Action == "pass" || e.Action == "fail") {
			times[e.Test] = max(times[e.Test], e.Elapsed)
		}
	})
	return times, err
}

// place puts each of names in one of count shards, numbered from 1. Those times holds go longest
// first, each in the shard with the least time so far, which leaves the longest shard at most a
// third longer than the least it could be, where a hash leaves the few tests that take a minute
// wherever it happens to put them; the rest go by a hash of their names.
func place(names []string, times map[string]float64, count int) map[string]int {
	timed := slices.DeleteFunc(slices.Clone(names), func(name string) bool {
		_, ok := times[name]
		return !ok
	})
	slices.SortFunc(timed, func(a, b string) int {
		return cmp.Or(cmp.Compare(times[b], times[a]), strings.Compare(a, b))
	})
	loads := make([]float64, count)
	in := make(map[string]int, len(names))
	for _, name := range timed {
		least := 0
		for i := range loads {
			if loads[i] < loads[least] {
				least = i
			}
		}
		loads[least] += times[name]
		in[name] = least + 1
	}
	for _, name := range names {
		if _, ok := in[name]; !ok {
			h := fnv.New64a()
			_, _ = h.Write([]byte(name))
			in[name] = int(h.Sum64()%uint64(count)) + 1 //nolint:gosec // count is positive, so neither conversion overflows
		}
	}
	return in
}

// pattern is the go test -run pattern of the top-level tests named, and of none where none are.
func pattern(names []string) string {
	if len(names) == 0 {
		return "^$"
	}
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}
