-- Filter, Reachable and Holders read which custom roles the public's and the tenant's members'
-- grants on the scopes they search name. rbac_grants_principal finds those grants with every other
-- grant of theirs there, of built-in roles too, which the tenant's members can hold on thousands of
-- resources; and rbac_grants_custom_role leads to the tenant alone, which a generic plan costs as an
-- average tenant's few grants, so it read every grant of a custom role in the tenant. This one
-- holds only grants of custom roles and leads to a principal, a tenant and a scope, so a search
-- seeks just those of the principal on a scope or a range of a type's, from the index alone, and no
-- plan finds them cheaper through the tenant. Building it keeps writes to rbac_grants waiting until
-- the migration commits, though reads go on.
CREATE INDEX rbac_grants_custom_principal ON rbac_grants (principal, tenant, scope) INCLUDE (role) WHERE role LIKE 'custom.%';

-- As of a time, a search reads its subject's grants, and the public's and the tenant's members', on
-- scopes of the types it lists, and a check its subject's on its resource's path, but history's index
-- of a principal's versions held no scope: a plan read every version of a principal's grants, of
-- other types too, once for each type, or by history's index of scopes every version of every grant
-- on a type's scopes in the tenant, the members' too. This one leads to the principal, then to its
-- entity, its scope's type and its scope, so a plan seeks a principal's versions of a type or on a
-- scope, and it serves what the one it replaces did, which led to the same three columns. A search
-- names a type as a scope's text up to its colon, an equality: a range of a type's scopes whose
-- bounds are another table's, as a search's types are, a plan counts as a few rows, so where it
-- counts a principal's versions as many, as in a history of a few principals, it took the index of
-- scopes. It is dropped before its replacement is built, so the migration takes history's strongest
-- lock before any other, as 0009 does the grants': reads of history, and every change, each of which
-- writes history, wait until the migration commits, and a transaction that read history and then
-- writes a grant deadlocks with it. Building it reads all of history; the analysis after it gives a
-- plan the statistics of the types, which autovacuum would take long after migrating.
DROP INDEX rbac_history_principal;
CREATE INDEX rbac_history_principal ON rbac_history (tenant, principal, entity, (split_part(scope, ':', 1)), scope, effective_at DESC)
    WHERE principal IS NOT NULL;
ANALYZE rbac_history;
