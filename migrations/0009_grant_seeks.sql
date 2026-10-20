-- A check, a list and a revoke look up their principals' grants on a few scopes, which
-- rbac_grants_key seeks. A connection's cached statement moves to a generic plan, which costs every
-- index by the table's averages: where most scopes and principals hold a grant or two, one that
-- leads to a scope or to a principal alone looks as cheap, and reads every grant on a tenant's busy
-- scope, or every grant of a group granted on thousands of resources. Each leads to both, so
-- whichever a plan picks seeks the same grants, and holds the rest of what a check reads, so its
-- read stays an index-only scan: plans pick these, narrower than the key, over it, and without
-- those columns would read each grant's row.
--
-- Each is dropped before its replacement is built, so the migration takes the table's strongest
-- lock before any other: built first, the replacement's lock would stop a change that has read
-- grants from writing while the drop waits for that change to end. Reads and writes of the table
-- wait until the migration commits.

-- Who has access to a scope, and deleting a scope's grants. The scope first, so a search's range
-- of a type's scopes spans every tenant, which no plan mistakes for a few grants.
DROP INDEX rbac_grants_scope;
CREATE INDEX rbac_grants_scope ON rbac_grants (scope, tenant, principal) INCLUDE (role, id, expires_at, conditional);

-- What an identity or group holds in every tenant, and deleting it everywhere: its tenants in
-- order, from the index alone.
DROP INDEX rbac_grants_principal;
CREATE INDEX rbac_grants_principal ON rbac_grants (principal, tenant, scope) INCLUDE (role, id, expires_at, conditional);
