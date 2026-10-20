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

-- How many bytes a record's rows take as JSON text, which History bounds a read by without reading
-- them: a read of as many of the largest records the package writes, a deny's changes, would hold
-- gigabytes. Null for one written before, or by PruneHistory, which History counts by its rows. A
-- column added with no default rewrites no record.
ALTER TABLE rbac_history ADD COLUMN bytes integer;

-- History returns each record whole, and PostgreSQL returns no text past 1 GB, so one record past
-- it stops every read of history from there. The tables bound what they hold, but a change's
-- context is the writing session's to set, and a column a later migration adds could go unbounded:
-- a row of more than 1 MiB as jsonb, or a context of more than 1 MiB, is refused, which fails its
-- write. The largest row the package writes, a deny naming and exempting as many of the longest
-- keys as it may, is about a third of that, and a context a few kilobytes. A row already stored was
-- bounded when it was written, so a change that removes one is never refused here.
CREATE OR REPLACE FUNCTION rbac_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
<<rbac_record>>
DECLARE
    was    jsonb := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE pg_catalog.to_jsonb(OLD) END;
    is_now jsonb := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE pg_catalog.to_jsonb(NEW) END;
    r      jsonb := coalesce(is_now, was);
    -- The row's expiry as the tables bound it, as migrating rewrites it: a grant migrating deletes,
    -- merged into another, holds one they refuse, which JSON or a time.Time can't write.
    expiry timestamptz := CASE WHEN (r->>'expires_at')::timestamptz = 'infinity' THEN NULL
                   WHEN (r->>'expires_at')::timestamptz > '9999-12-30 23:59:59.999999+00' THEN '9999-12-30 23:59:59.999999+00'
                   WHEN (r->>'expires_at')::timestamptz <= '0001-01-01 00:00:00+00' THEN timestamptz 'epoch'
                   ELSE (r->>'expires_at')::timestamptz END;
    -- Parsed only within the bound, which the record checks first.
    said   text  := current_setting('rbac.change', true);
    change jsonb := CASE WHEN pg_catalog.octet_length(said) > 1048576 THEN NULL ELSE coalesce(nullif(said, '')::jsonb, '{}') END;
    -- The context says only whether a delete is an expiry, and only a row that has expired is one,
    -- so whoever sets it can't record a revoke as anything else.
    op     text  := CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update'
                   WHEN 'DELETE' THEN CASE WHEN change->>'op' = 'expire' AND (was->>'expires_at')::timestamptz <= statement_timestamp()
                     THEN 'expire' ELSE 'delete' END END;
    entity text  := CASE TG_TABLE_NAME WHEN 'rbac_grants' THEN 'grant' WHEN 'rbac_roles' THEN 'role'
                   WHEN 'rbac_denies' THEN 'deny' WHEN 'rbac_eligibilities' THEN 'eligibility'
                   WHEN 'rbac_memberships' THEN 'membership' WHEN 'rbac_groups' THEN 'group' WHEN 'rbac_members' THEN 'member' END;
    key    text  := CASE entity WHEN 'deny' THEN (r->>'scope') || ' ' || (r->>'id') WHEN 'membership' THEN r->>'principal'
                   WHEN 'member' THEN pg_catalog.jsonb_build_array(r->>'group_id', r->>'principal', r->>'source')::text
                   ELSE r->>'id' END;
    was_key text := CASE entity WHEN 'deny' THEN (was->>'scope') || ' ' || (was->>'id') WHEN 'membership' THEN was->>'principal'
                   WHEN 'member' THEN pg_catalog.jsonb_build_array(was->>'group_id', was->>'principal', was->>'source')::text
                   ELSE was->>'id' END;
    ended  boolean;
BEGIN
    IF pg_catalog.pg_column_size(is_now) > 1048576 OR pg_catalog.octet_length(said) > 1048576 THEN
        RAISE EXCEPTION 'history records no row or change of more than 1 MiB: this % row is % bytes and its change %',
            TG_TABLE_NAME, pg_catalog.pg_column_size(is_now), pg_catalog.octet_length(said) USING ERRCODE = 'program_limit_exceeded';
    END IF;
    -- An update that moves a row to another key or tenant ends it under the old one, which would
    -- otherwise read as live for good, and starts it under the new.
    IF TG_OP = 'UPDATE' AND (was_key IS DISTINCT FROM key OR was->>'tenant' IS DISTINCT FROM is_now->>'tenant') THEN
        -- An update revokes nothing, so a row it moves that had expired ended with its expiry, as an
        -- activation Activate makes anew did, rather than by the change that moved it.
        ended := (was->>'expires_at')::timestamptz <= statement_timestamp();
        INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
          before, after, bytes, actor, on_behalf_of, how, request, reason)
        VALUES (
          greatest(CASE WHEN ended THEN (was->>'expires_at')::timestamptz ELSE statement_timestamp() END,
            (SELECT max(h.effective_at) FROM rbac_history h
             WHERE h.tenant = was->>'tenant' AND h.entity = rbac_record.entity AND h.key = was_key)),
          was->>'tenant', entity, was_key, CASE WHEN ended THEN 'expire' ELSE 'delete' END, was->>'principal',
          CASE entity WHEN 'role' THEN was->>'id' ELSE was->>'role' END,
          was->>'scope',
          CASE entity WHEN 'group' THEN was->>'id' WHEN 'member' THEN was->>'group_id' END,
          (was->>'expires_at')::timestamptz, was, NULL, pg_catalog.octet_length(was::text),
          coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
          coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
        op := 'create';
        was := NULL;
    END IF;
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
      before, after, bytes, actor, on_behalf_of, how, request, reason)
    VALUES (
      -- A change took effect with its statement, and an expiry when it expired, but neither before
      -- the row's last record: a change can have moved its expiry back to before then. The last a
      -- write's snapshot holds: at READ COMMITTED, as the package changes the tables, this query
      -- takes one once the write has waited for another's lock on the row, but at REPEATABLE READ
      -- or SERIALIZABLE the transaction's is older, so a write that waited is dated before the
      -- change it waited for. Write around the package at READ COMMITTED.
      greatest(CASE WHEN op = 'expire' THEN expiry ELSE statement_timestamp() END,
        (SELECT max(h.effective_at) FROM rbac_history h
         WHERE h.tenant = r->>'tenant' AND h.entity = rbac_record.entity AND h.key = rbac_record.key)),
      r->>'tenant', entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      expiry, was, is_now, coalesce(pg_catalog.octet_length(was::text), 0) + coalesce(pg_catalog.octet_length(is_now::text), 0),
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
    RETURN NULL;
END $$;


-- Replacing a function resets its settings: its definer's rights read only this schema again, and
-- it writes a row's times as JSON in UTC.
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_record() SET search_path = %I, pg_temp SET TimeZone = ''UTC''', current_schema());
END $$;
