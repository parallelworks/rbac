// Command shards splits the tests into shards, as CI runs them, and checks that the shards ran every
// test between them, each once.
//
//	shards select -shard i/n [-timings file] [-- go test flags and packages]
//
// prints the -run pattern of the top-level tests of the ith of n shards, of those go test -list
// names with the flags and packages given. It places them longest first, by the times of the go test
// -json output timings names, each in the shard with the least time so far, and a test it doesn't
// time by a hash of its name. So shards given the same tests and timings place each test in one of
// them, and a test runs, subtests and all, where it is placed and nowhere else.
//
//	shards check dir
//
// checks the shards' results: dir holds a directory for each, with "shard", its i/n, "test-list.json",
// the go test -json -list output of every test, and "test-results.json", the go test -json output of
// its run. It fails unless the shards are numbered 1 to n, once each, list the same tests, and
// between them ran each listed test once, in a single shard, without skipping it, and ran nothing
// else. Both fail where go test -list prints a line that names neither a test nor its package.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
)

const usage = `usage: shards select -shard i/n [-timings file] [-- go test flags and packages]
       shards check dir`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "shards:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if len(os.Args) < 2 {
		return errors.New(usage)
	}
	switch os.Args[1] {
	case "select":
		return selectMain(ctx, os.Args[2:])
	case "check":
		return checkMain(os.Args[2:])
	default:
		return errors.New(usage)
	}
}

// test is a top-level test, or a subtest, of a package.
type test struct{ pkg, name string }

func (t test) String() string { return t.pkg + " " + t.name }

func (t test) topLevel() bool { return !strings.Contains(t.name, "/") }

// parseShard reads "i/n", the ith of n shards, counting from 1.
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
	Elapsed                       float64
}

// events calls f with each event of go test -json output, passing over lines that aren't one, such
// as a build's.
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

// The names go test -list prints, by go test's own rule for them: a prefix, then nothing or the rest
// of an identifier, of any letters, digits and underscores, whose first isn't a lowercase letter.
// go test -run selects tests, fuzz tests and examples; benchmarks run only with -bench.
var (
	listedName    = regexp.MustCompile(`^(Test|Fuzz|Example)` + nameRest)
	benchmarkName = regexp.MustCompile(`^Benchmark` + nameRest)
	// What go test -list prints of a package, not of a test: how it ended, that it has no test
	// files, or, of one without statements, that it isn't built with -cover.
	packageLine = regexp.MustCompile(`^(ok  \t|\?   \t|program not built with -cover$)`)
)

const nameRest = `([\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{Nd}_][\pL\p{Nd}_]*)?$`

// readList reads the top-level tests of each package from go test -json -list output. A line of
// its output that is neither a name nor one of a package's fails it, so a test of a name the rule
// doesn't foresee is never left out of every shard.
func readList(r io.Reader) (map[test]bool, error) {
	listed := map[test]bool{}
	var unknown []string
	err := events(r, func(e event) {
		if e.Action != "output" {
			return
		}
		switch name := strings.TrimSpace(e.Output); {
		case listedName.MatchString(name):
			listed[test{e.Package, name}] = true
		case name != "" && !benchmarkName.MatchString(name) && !packageLine.MatchString(name):
			unknown = append(unknown, fmt.Sprintf("%s: %q", e.Package, name))
		}
	})
	if err == nil && len(unknown) > 0 {
		err = fmt.Errorf("go test -list printed lines that name no test: %s", strings.Join(unknown, ", "))
	}
	return listed, err
}
