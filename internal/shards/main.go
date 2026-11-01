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
// between them ran each listed test once, in a single shard, and ran nothing else.
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

// The names go test -list prints that go test -run selects: it lists benchmarks too, which run
// only with -bench.
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
