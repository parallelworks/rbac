-- As of a time, a statement reads history by the rows it names through an index leading to the
-- tenant, or every version of an entity in the tenant. The planner counted a tenant's versions of an
-- entity as history's rows times the tenant's share of them times the entity's: in a history of many
-- tenants, a tenant of hundreds of custom roles holds a small share of every record and its roles a
-- small share of every tenant's, so it counted them as a row. Reading them all looked as cheap as
-- seeking the few a check names, and a plan read them all again for each version it found, which for
-- 200 roles was about 20,000 pages. Statistics of the two columns together count each pair common
-- enough to matter as it is.
CREATE STATISTICS rbac_history_tenant_entity (mcv) ON tenant, entity FROM rbac_history;

-- As of a time, a list of the grants or the eligibilities on a scope read every version of every
-- one in the tenant: history had an index by scope for denies alone. This one finds an entity's
-- versions on a scope. Denies keep theirs, which holds no grant: in this one, every grant's version
-- would deepen each lookup of a scope's denies, which a check makes for each scope on its path.
-- Building it reads all of history, and every write to the package's tables, each of which writes
-- history, waits until the migration commits.
CREATE INDEX rbac_history_scope ON rbac_history (tenant, entity, scope, effective_at DESC) WHERE entity IN ('grant', 'eligibility');

-- As of a time, Filter and Reachable find the denies naming their subject by the keys they name,
-- as rbac_denies_principals finds them now, but history held those keys in each version's record
-- alone, so they read every version of every deny in the tenant. This index holds them as that
-- one does, and AsOf reads a deny's keys by the same expression, which a plan matches to it.
-- rbac_text_array is the strings of a JSON array; its body, as rbac_tenant_keys', is parsed now and
-- names pg_catalog's functions and operators.
CREATE FUNCTION rbac_text_array(a jsonb) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN ARRAY(SELECT e FROM pg_catalog.jsonb_array_elements_text(
        CASE WHEN pg_catalog.jsonb_typeof(a) OPERATOR(pg_catalog.=) 'array' THEN a END) AS e);

CREATE INDEX rbac_history_deny_principals ON rbac_history
    USING gin (rbac_tenant_keys(tenant, rbac_text_array(after -> 'principals') COLLATE "C")) WITH (fastupdate = off)
    WHERE entity = 'deny';
