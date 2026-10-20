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
