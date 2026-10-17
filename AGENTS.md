# rbac

Role-based access control on PostgreSQL, as a Go library. The repository is public.

- It is a general library: it names no company, product or application, holds no product logic, and has no secrets, hostnames or infrastructure details.
- Never name other products in code, docs, commits or PR text. Describe the behavior instead.
- FIPS 140-3: no cryptography outside the Go standard library `crypto/*`. Tests run with `GODEBUG=fips140=only`.
- Tests run against PostgreSQL: set `RBAC_TEST_DATABASE_URL` to a database they may create schemas in. A test calls the package's own functions, and a check comes with a test that fails without it.
- Once released, exported names and what is stored (role ids, permissions, principal kinds, tables and columns) are contract: never rename one, and change storage only through a new migration.
- Comments explain why, not what. PR titles follow Conventional Commits; PRs target `canary` and are squash-merged.
- Write American English in code, comments, docs, commits and PRs: color, center, behavior, canceled, canceling.

`make check` runs every linter and test.
