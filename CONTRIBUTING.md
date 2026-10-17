# Contributing to rbac

- Every change goes through a pull request against `canary`. PR titles follow
  [Conventional Commits](https://www.conventionalcommits.org) (`feat: ...`, `fix: ...`); PRs are
  squash-merged, so the title becomes the commit and the changelog entry.
- `make check` must pass: module tidiness, golangci-lint, govulncheck, and the tests, which run
  with the race detector in FIPS mode. Set `RBAC_TEST_DATABASE_URL` to a PostgreSQL database the
  tests may create schemas in; without it, the tests that need one are skipped.

## Releasing

release-please keeps a release PR open (`chore: release x.y.z`), built from merged PR titles.
Merging it tags the module. Don't bump versions or push tags by hand.
