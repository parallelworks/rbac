-- A change to a group's members reads the eligibilities the groups it reaches approve, and the
-- denies that name or exempt them, by those groups' keys in the arrays approvers, principals and
-- exempt. No btree seeks a key in an array, so it read every eligibility and deny in the tenant;
-- and once a connection's cached statement moves to a generic plan, which costs a read by the
-- tenant as the tables' average, a few rows, it reads them by the tenant over any other index. A
-- GIN index on an array alone would read the rows naming the key in every tenant, as a group's id
-- can name a group in each, and the plan would still pick the read by the tenant over it.
--
-- So each is indexed as rbac_tenant_keys gives it, each key prefixed by its tenant, and a read asks
-- for the tenant's keys alone, with no condition on the tenant an index on it could serve. The
-- tenant goes first with its length, as it may hold any text, so the keys of two tenants never
-- meet. Its body is parsed now, and names pg_catalog's functions and operators, so neither a later
-- overload nor a search_path changes what it gives, which the indexes rest on.
--
-- Without fastupdate, a write adds its keys to an index as it is made, rather than to a list every
-- read scans until a vacuum merges it, which grows with the writes. Writes to the two tables wait
-- while the indexes are built, until the migration commits.
CREATE FUNCTION rbac_tenant_keys(tenant text, keys text[]) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN ARRAY(SELECT pg_catalog.length(tenant)::text OPERATOR(pg_catalog.||) ':' OPERATOR(pg_catalog.||) tenant
        OPERATOR(pg_catalog.||) k FROM pg_catalog.unnest(keys) AS k);

CREATE INDEX rbac_eligibilities_approvers ON rbac_eligibilities USING gin (rbac_tenant_keys(tenant, approvers)) WITH (fastupdate = off);
CREATE INDEX rbac_denies_principals ON rbac_denies USING gin (rbac_tenant_keys(tenant, principals)) WITH (fastupdate = off);
CREATE INDEX rbac_denies_exempt ON rbac_denies USING gin (rbac_tenant_keys(tenant, exempt)) WITH (fastupdate = off);
