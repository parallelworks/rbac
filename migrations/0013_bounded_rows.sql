-- The package bounds every row it writes, but the tables bounded only some of what a role that may
-- write them, as the application's, can store: an actor's key, an id, a role and a custom role's
-- lists held any text. rbac_record writes each row into history as JSON, whose text, a control
-- character taking six bytes, PostgreSQL can't return past 1 GB, so one such row, built on the
-- server at no cost on the wire, stopped every History and Export call from then on. Each is
-- bounded here as the package bounds what it writes, so nothing it writes is refused: an id to
-- MaxID bytes; an actor's key, none or `kind:id`, to a kind's name and an id, as 0012 bounds an
-- activation's principal; a role to a role's id; and a list to its number of elements and each
-- one's form. A check can't count an element's bytes without a function of the package's own, which
-- every role writing the table would need EXECUTE on, so it counts its characters, to MaxID, and
-- refuses a NULL.
--
-- The package never wrote a row these refuse, so none is rewritten: a row written around it that
-- one refuses stops the migration, which names the table, the check and a query that finds the row.
-- Each is added unchecked, then checked on its own, so a row one refuses is reported with the
-- check's own condition; a check left unchecked before, as 0012's on a column every row held null
-- in, stays so. Writes to the tables wait until migrating commits.
DO $$
DECLARE
    unchecked oid[] := ARRAY(SELECT k.oid FROM pg_catalog.pg_constraint k
        WHERE k.connamespace = pg_catalog.current_schema()::regnamespace AND NOT k.convalidated);
    c record;
BEGIN
    ALTER TABLE rbac_grants
        DROP CONSTRAINT rbac_grants_tenant_check,
        ADD CONSTRAINT rbac_grants_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_grants_scope_id_check CHECK (pg_catalog.octet_length(scope_id) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_grants_principal_id_check CHECK (pg_catalog.octet_length(principal_id) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_grants_role_check CHECK (role ~ '^[a-z][a-z0-9._-]{0,127}$') NOT VALID,
        ADD CONSTRAINT rbac_grants_approved_by_check CHECK (approved_by = '' OR approved_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(approved_by, pg_catalog.strpos(approved_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_grants_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_grants_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    -- A custom role gives at most MaxRoleEntries permissions, is for at most as many types, and
    -- lists at most MaxGrantableRoles roles.
    ALTER TABLE rbac_roles
        DROP CONSTRAINT rbac_roles_tenant_check,
        ADD CONSTRAINT rbac_roles_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        DROP CONSTRAINT rbac_roles_permissions_check,
        ADD CONSTRAINT rbac_roles_permissions_check CHECK (pg_catalog.cardinality(permissions) BETWEEN 1 AND 1000
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(permissions),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9_-]{0,62}:[a-z][a-z0-9_-]{0,62}$"))')) NOT VALID,
        DROP CONSTRAINT rbac_roles_resource_types_check,
        ADD CONSTRAINT rbac_roles_resource_types_check CHECK (pg_catalog.cardinality(resource_types) BETWEEN 1 AND 1000
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(resource_types),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9_-]{0,62}$"))')) NOT VALID,
        ADD CONSTRAINT rbac_roles_grantable_roles_check CHECK (pg_catalog.cardinality(grantable_roles) <= 64
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(grantable_roles),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9._-]{0,127}$"))')) NOT VALID,
        ADD CONSTRAINT rbac_roles_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    -- A deny names principals by key, the public's with no id.
    ALTER TABLE rbac_denies
        DROP CONSTRAINT rbac_denies_tenant_check,
        ADD CONSTRAINT rbac_denies_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_denies_scope_id_check CHECK (pg_catalog.octet_length(scope_id) <= 512) NOT VALID,
        DROP CONSTRAINT rbac_denies_principals_check,
        ADD CONSTRAINT rbac_denies_principals_check CHECK (pg_catalog.cardinality(principals) BETWEEN 1 AND 256
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(principals),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9_-]{0,62}:(.{0,128}){0,4}$" flag "s"))')) NOT VALID,
        DROP CONSTRAINT rbac_denies_exempt_check,
        ADD CONSTRAINT rbac_denies_exempt_check CHECK (pg_catalog.cardinality(exempt) <= 256
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(exempt),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9_-]{0,62}:(.{0,128}){0,4}$" flag "s"))')) NOT VALID,
        ADD CONSTRAINT rbac_denies_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_denies_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    ALTER TABLE rbac_eligibilities
        DROP CONSTRAINT rbac_eligibilities_tenant_check,
        ADD CONSTRAINT rbac_eligibilities_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_eligibilities_scope_id_check CHECK (pg_catalog.octet_length(scope_id) <= 512) NOT VALID,
        DROP CONSTRAINT rbac_eligibilities_principal_id_check,
        ADD CONSTRAINT rbac_eligibilities_principal_id_check CHECK (principal_id <> '' AND pg_catalog.octet_length(principal_id) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_eligibilities_role_check CHECK (role ~ '^[a-z][a-z0-9._-]{0,127}$') NOT VALID,
        DROP CONSTRAINT rbac_eligibilities_approvers_check,
        ADD CONSTRAINT rbac_eligibilities_approvers_check CHECK (pg_catalog.cardinality(approvers) <= 16
            AND NOT pg_catalog.jsonb_path_exists(pg_catalog.to_jsonb(approvers),
              '$[*] ? (@.type() != "string" || !(@ like_regex "^[a-z][a-z0-9_-]{0,62}:(.{0,128}){0,4}$" flag "s"))')) NOT VALID,
        ADD CONSTRAINT rbac_eligibilities_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    ALTER TABLE rbac_memberships
        DROP CONSTRAINT rbac_memberships_tenant_check,
        ADD CONSTRAINT rbac_memberships_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        DROP CONSTRAINT rbac_memberships_principal_id_check,
        ADD CONSTRAINT rbac_memberships_principal_id_check CHECK (principal_id <> '' AND pg_catalog.octet_length(principal_id) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_memberships_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_memberships_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    ALTER TABLE rbac_groups
        DROP CONSTRAINT rbac_groups_tenant_check,
        ADD CONSTRAINT rbac_groups_tenant_check CHECK (tenant <> '' AND pg_catalog.octet_length(tenant) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_groups_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_groups_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    -- A member's tenant and group are its group's.
    ALTER TABLE rbac_members
        DROP CONSTRAINT rbac_members_principal_id_check,
        ADD CONSTRAINT rbac_members_principal_id_check CHECK (principal_id <> '' AND pg_catalog.octet_length(principal_id) <= 512) NOT VALID,
        ADD CONSTRAINT rbac_members_created_by_check CHECK (created_by = '' OR created_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(created_by, pg_catalog.strpos(created_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID,
        ADD CONSTRAINT rbac_members_updated_by_check CHECK (updated_by = '' OR updated_by ~ '^[a-z][a-z0-9_-]{0,62}:'
            AND pg_catalog.octet_length(pg_catalog.substr(updated_by, pg_catalog.strpos(updated_by, ':') + 1)) BETWEEN 1 AND 512) NOT VALID;

    FOR c IN SELECT k.conrelid::regclass AS tab, k.conname, pg_catalog.pg_get_expr(k.conbin, k.conrelid) AS cond
        FROM pg_catalog.pg_constraint k
        WHERE k.connamespace = pg_catalog.current_schema()::regnamespace AND NOT k.convalidated AND k.oid <> ALL (unchecked)
        ORDER BY k.conname
    LOOP
        BEGIN
            EXECUTE pg_catalog.format('ALTER TABLE %s VALIDATE CONSTRAINT %I', c.tab, c.conname);
        EXCEPTION WHEN check_violation THEN
            RAISE EXCEPTION '% holds a row the package never writes, which % refuses: find it with SELECT * FROM % WHERE NOT (%), correct or delete it, and migrate again',
                c.tab, c.conname, c.tab, c.cond USING ERRCODE = 'check_violation';
        END;
    END LOOP;
END $$;
