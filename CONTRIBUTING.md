# Contributing to rbac

- Every change goes through a pull request against `canary`. PR titles follow
  [Conventional Commits](https://www.conventionalcommits.org) (`feat: ...`, `fix: ...`); PRs are
  squash-merged, so the title becomes the commit and the changelog entry.
- `make check` must pass: module tidiness, golangci-lint, govulncheck, and the tests, which run
  with the race detector in FIPS mode. Set `RBAC_TEST_DATABASE_URL` to a PostgreSQL database the
  tests may create schemas in; without it, the tests that need one are skipped.

## Tests in CI

`make test` runs every test in one run. CI runs tidiness, lint and govulncheck once, in a job of
their own, and splits the tests into shards, each a job with a PostgreSQL of its own. Each shard
runs its own top-level tests, of every package, whole, subtests and all, and no others: `go run
./internal/shards select` places every test `go test -list` names, and `make test` runs the shard's
with `go test -run`. So a test whose own body reads what its subtests did runs as it does unsharded.

- `make test SHARD=2/4` runs the second of four shards. With `TIMINGS=results.json`, a file of
  `go test -json` output, the shards are balanced by its times as CI balances them; without it, each
  test is placed by a hash of its name. Tests of the same name in two packages are placed together.
- CI balances its shards by the times of the latest passing run of the branch, or else of canary:
  longest first, each test in the shard with the least time so far, so that the few tests of a
  minute are spread apart. A test no run has timed yet, such as a new one, is placed by its name
  until one does. Every shard restores the same timings, which the `plan` job names, so they place
  each test alike. Each shard's `go test -json` output is its job's `test-results-N` artifact.
- The `go` job, which branch protection requires, passes once the checks, the audit of the
  workflows (`actions`) and every shard have, and `go run ./internal/shards check` finds that the
  shards ran each test `go test -list` names once between them, none of them skipped, and nothing
  else, which it writes in the job's summary. It runs in a cancelled run too, and fails it, as a
  required job its `if` skips counts as passed.
  `select` and `check` read a test's name by go test's own rule, any letters and digits, and fail on
  a line of `go test -list` that names neither a test nor its package, so no test runs in no shard.
- Each job has a 20-minute timeout. When a shard's Test step nears half of that, add a shard to the
  matrix in `.github/workflows/ci.yml`; nothing else names their number.
- The tests that wait for VACUUM to mark rows visible to all skip where another session's snapshot
  keeps it from doing so, as on a database other runs share, but fail in CI (where `CI` is true), as
  there only the run's own sessions hold snapshots.
- A test that can't run where it is, as without autovacuum or a role that may create roles, skips
  with `pgtest.Skip`, which fails it in CI, where every test can run, and so the `go` job fails on
  a top-level test that skipped. The test that migrates beside an autovacuum worker waits two of
  `autovacuum_naptime` and 30 seconds for one, which in CI has come within a minute; a shorter
  naptime there has autovacuum analyze a crowded copy before its test reads that nothing had.
- The coverage each shard prints counts only the statements its own tests reach, so it reads low.
  The `go` job merges every shard's profile into the whole suite's, as `make test` prints it.
- `crowded` copies its tenants from a schema each test process fills once, as writing their 46,000
  rows through history's trigger takes seconds and copying them a moment, and the copy is laid out
  as writing them was. `pgtest.Template` and `pgtest.Copy` do the same for any fixture slow to write.

## Releasing

release-please keeps a release PR open (`chore: release x.y.z`), built from merged PR titles.
Merging it tags the module. Don't bump versions or push tags by hand.
