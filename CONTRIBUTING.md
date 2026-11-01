# Contributing to rbac

- Every change goes through a pull request against `canary`. PR titles follow
  [Conventional Commits](https://www.conventionalcommits.org) (`feat: ...`, `fix: ...`); PRs are
  squash-merged, so the title becomes the commit and the changelog entry.
- `make check` must pass: module tidiness, golangci-lint, govulncheck, and the tests, which run
  with the race detector in FIPS mode. Set `RBAC_TEST_DATABASE_URL` to a PostgreSQL database the
  tests may create schemas in; without it, the tests that need one are skipped.

## Tests in CI

`make test` runs every test in one run. CI runs tidiness, lint and govulncheck once, in a job of
their own, and splits the tests that need the database into shards, each a job with a PostgreSQL of
its own. A test is in its top-level test's shard: `pgtest.URL`, which every test that needs the
database passes through, skips it in the others. Tests that need no database take seconds and run in
every shard.

- `make test SHARD=2/4` runs the second of four shards. With `TIMINGS=results.json`, a file of
  `go test -json` output, the shards are balanced by its times as CI balances them; without it, each
  test is placed by a hash of its name.
- CI balances its shards by the times of the latest passing run of the branch, or else of canary:
  longest first, each test in the shard with the least time so far, so that the few tests of a
  minute are spread apart. A test no run has timed yet, such as a new one, is placed by its name
  until one does. Each shard's `go test -json` output is its job's `test-results-N` artifact.
- The `go` job, which branch protection requires, passes once the checks and every shard have, and
  `internal/shardcheck` finds that the shards ran every test `go test -list` names between them:
  each test the others skipped as one shard's ran in that one alone. It runs in a cancelled run too,
  and fails it, as a required job its `if` skips counts as passed.
- Each job has a 20-minute timeout. When a shard's Test step nears half of that, add a shard to the
  matrix in `.github/workflows/ci.yml`; nothing else names their number.
- The coverage each shard prints counts only the statements its own tests reach, so it reads low.
  The `go` job merges every shard's profile into the whole suite's, as `make test` prints it.
- `crowded` copies its tenants from a schema each test process fills once, as writing their 46,000
  rows through history's trigger takes seconds and copying them a moment, and the copy is laid out
  as writing them was. `pgtest.Template` and `pgtest.Copy` do the same for any fixture slow to write.

## Releasing

release-please keeps a release PR open (`chore: release x.y.z`), built from merged PR titles.
Merging it tags the module. Don't bump versions or push tags by hand.
