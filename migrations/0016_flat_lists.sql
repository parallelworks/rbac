-- A list is a text array, which PostgreSQL holds in up to six dimensions and from any subscript.
-- Every read of one took its elements in order whatever its shape, as ANY, an overlap, unnest,
-- rbac_tenant_keys and a scan into Go do, but AsOf's of a deny's keys; and 0013's checks read a
-- list as JSON in lax mode, which takes an array's arrays as their elements. So a write around the
-- package with the application's rights could store a deny naming '{{user:u}}', which checks took
-- to bind u, but rbac_text_array, reading it from history, took the inner array as one key, the
-- text of its JSON: as of any time from then, the deny bound no one, and checks allowed u.
--
-- So rbac_text_array takes an array's arrays as their elements too, as deep as an array's
-- dimensions go: in lax mode, a [*] past an element's own depth takes it as it is, so a record's
-- other values, which history's owner can write, read as their text as before. History's index of
-- the keys denies name, built on it, is rebuilt where a record holds such an array: only those
-- records' keys change, and rebuilding reads all of history.
--
-- And the tables hold each list as history gives it back: in one dimension, from 1, or empty, which
-- has none. A row holding one in another shape is rewritten so, its elements in order, as every
-- read but that one took them, which history records as Migrate's change; then each list is
-- checked, which reads each table once more. The tables are locked first, history last, as 0013
-- locks them, but history only against writes, which every change to a table makes: reads of
-- history go on.
LOCK TABLE rbac_roles, rbac_denies, rbac_eligibilities IN ACCESS EXCLUSIVE MODE;
LOCK TABLE rbac_history IN SHARE ROW EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION rbac_text_array(a jsonb) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN ARRAY(SELECT e OPERATOR(pg_catalog.#>>) '{}' FROM pg_catalog.jsonb_path_query(
        CASE WHEN pg_catalog.jsonb_typeof(a) OPERATOR(pg_catalog.=) 'array' THEN a END, 'lax $[*][*][*][*][*][*]') AS e);

DO $$ BEGIN
    IF EXISTS (SELECT FROM rbac_history h WHERE h.entity = 'deny' AND h.after @? 'strict $.principals[*] ? (@.type() == "array")') THEN
        REINDEX INDEX rbac_history_deny_principals;
    END IF;
END $$;

SELECT set_config('rbac.change', '{"how": "Migrate"}', true);
UPDATE rbac_roles SET
    permissions = ARRAY(SELECT e FROM pg_catalog.unnest(permissions) WITH ORDINALITY AS t(e, i) ORDER BY i),
    resource_types = ARRAY(SELECT e FROM pg_catalog.unnest(resource_types) WITH ORDINALITY AS t(e, i) ORDER BY i),
    grantable_roles = ARRAY(SELECT e FROM pg_catalog.unnest(grantable_roles) WITH ORDINALITY AS t(e, i) ORDER BY i)
    WHERE NOT ((pg_catalog.cardinality(permissions) = 0 OR pg_catalog.array_ndims(permissions) = 1 AND pg_catalog.array_lower(permissions, 1) = 1)
      AND (pg_catalog.cardinality(resource_types) = 0 OR pg_catalog.array_ndims(resource_types) = 1 AND pg_catalog.array_lower(resource_types, 1) = 1)
      AND (pg_catalog.cardinality(grantable_roles) = 0 OR pg_catalog.array_ndims(grantable_roles) = 1 AND pg_catalog.array_lower(grantable_roles, 1) = 1));
UPDATE rbac_denies SET
    principals = ARRAY(SELECT e FROM pg_catalog.unnest(principals) WITH ORDINALITY AS t(e, i) ORDER BY i),
    exempt = ARRAY(SELECT e FROM pg_catalog.unnest(exempt) WITH ORDINALITY AS t(e, i) ORDER BY i),
    permissions = ARRAY(SELECT e FROM pg_catalog.unnest(permissions) WITH ORDINALITY AS t(e, i) ORDER BY i)
    WHERE NOT ((pg_catalog.cardinality(principals) = 0 OR pg_catalog.array_ndims(principals) = 1 AND pg_catalog.array_lower(principals, 1) = 1)
      AND (pg_catalog.cardinality(exempt) = 0 OR pg_catalog.array_ndims(exempt) = 1 AND pg_catalog.array_lower(exempt, 1) = 1)
      AND (pg_catalog.cardinality(permissions) = 0 OR pg_catalog.array_ndims(permissions) = 1 AND pg_catalog.array_lower(permissions, 1) = 1));
UPDATE rbac_eligibilities SET
    approvers = ARRAY(SELECT e FROM pg_catalog.unnest(approvers) WITH ORDINALITY AS t(e, i) ORDER BY i)
    WHERE NOT (pg_catalog.cardinality(approvers) = 0 OR pg_catalog.array_ndims(approvers) = 1 AND pg_catalog.array_lower(approvers, 1) = 1);
SELECT set_config('rbac.change', '', true);

ALTER TABLE rbac_roles
    ADD CONSTRAINT rbac_roles_permissions_flat CHECK (pg_catalog.cardinality(permissions) = 0
        OR pg_catalog.array_ndims(permissions) = 1 AND pg_catalog.array_lower(permissions, 1) = 1),
    ADD CONSTRAINT rbac_roles_resource_types_flat CHECK (pg_catalog.cardinality(resource_types) = 0
        OR pg_catalog.array_ndims(resource_types) = 1 AND pg_catalog.array_lower(resource_types, 1) = 1),
    ADD CONSTRAINT rbac_roles_grantable_roles_flat CHECK (pg_catalog.cardinality(grantable_roles) = 0
        OR pg_catalog.array_ndims(grantable_roles) = 1 AND pg_catalog.array_lower(grantable_roles, 1) = 1);
ALTER TABLE rbac_denies
    ADD CONSTRAINT rbac_denies_principals_flat CHECK (pg_catalog.cardinality(principals) = 0
        OR pg_catalog.array_ndims(principals) = 1 AND pg_catalog.array_lower(principals, 1) = 1),
    ADD CONSTRAINT rbac_denies_exempt_flat CHECK (pg_catalog.cardinality(exempt) = 0
        OR pg_catalog.array_ndims(exempt) = 1 AND pg_catalog.array_lower(exempt, 1) = 1),
    ADD CONSTRAINT rbac_denies_permissions_flat CHECK (pg_catalog.cardinality(permissions) = 0
        OR pg_catalog.array_ndims(permissions) = 1 AND pg_catalog.array_lower(permissions, 1) = 1);
ALTER TABLE rbac_eligibilities
    ADD CONSTRAINT rbac_eligibilities_approvers_flat CHECK (pg_catalog.cardinality(approvers) = 0
        OR pg_catalog.array_ndims(approvers) = 1 AND pg_catalog.array_lower(approvers, 1) = 1);
