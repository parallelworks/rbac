-- rbac_record set its variables as it declared them, before its body refused a search_path that
-- can't name the schema of the table it fires on, and one of them read the row's last record from
-- history: where history's role has no USAGE on the schema, or the schema is named $user, it read a
-- session's own table named as history's in pg_temp, as history's role, before the row was refused.
-- Whatever that table runs, as a row security policy or a function in a view, ran with history's
-- rights, and what a rollback doesn't undo stayed: setting history's id sequence back, as the
-- application's role could, numbered later records below earlier ones, so AsOf read a row as it was
-- before its last changes, and setting it to its end failed every later write. Now it sets nothing
-- but its search_path before it refuses, so it reads no table, and calls no function or operator
-- but pg_catalog's, by a search_path it hasn't checked: where a schema is named as history's role,
-- which $user then names, an operator there of types pg_catalog has none of exactly, as ->> of
-- jsonb and jsonb for a jsonb and a literal, is chosen over pg_catalog's.
--
-- No other function of the package's runs as a role other than its caller, and none that sets its
-- search_path reads or calls anything by it before it knows it: rbac_history_pruned declares only
-- the search_path it sets too, and refuses before it reads history; rbac_history_append_only reads
-- pg_catalog alone, naming each operator. rbac_no_truncate reads and calls nothing; rbac_tenant_keys,
-- rbac_text_array and rbac_changes_grants were parsed as they were made and name pg_catalog's
-- functions and operators; and rbac_group_members reads the tables by its caller's search_path, with
-- its caller's rights, as the caller's statement does.
--
-- Replacing a function keeps its owner and who may execute it, but not its settings, so each is set
-- here, as 0017, 0018 and 0023 set them. It takes no lock on the tables: changes go on as it is
-- applied, each recorded as before until migrating commits.
CREATE OR REPLACE FUNCTION rbac_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' SET plan_cache_mode = force_generic_plan SET enable_seqscan = off AS $$
<<rbac_record>>
DECLARE
    -- Alone, as every statement below finds history, and what it calls, by it.
    here   text := pg_catalog.set_config('search_path', pg_catalog.quote_ident(TG_TABLE_SCHEMA) || ', pg_temp', true);
    was    jsonb;
    is_now jsonb;
    r      jsonb;
    expiry timestamptz;
    said   text;
    change jsonb;
    entity text;
    key    text;
    was_key text;
    at     timestamptz;
    last   timestamptz;
    op     text;
    was_last timestamptz;
    ended  boolean;
BEGIN
    -- A search_path reads $user, however it is quoted, as a role's name, and leaves out a schema
    -- the role has no USAGE on, so history would be found in pg_temp: refused before anything it
    -- names is read or called. The = it compares two names by is pg_catalog's, which has one of
    -- exactly their type, and comes first in a search_path that doesn't name it.
    IF pg_catalog.current_schema() IS DISTINCT FROM TG_TABLE_SCHEMA THEN
        RAISE EXCEPTION 'history is not found in schema %: no search_path names a schema called $user, nor one % has no USAGE on',
            TG_TABLE_SCHEMA, current_user USING ERRCODE = 'invalid_schema_name';
    END IF;
    was := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE pg_catalog.to_jsonb(OLD) END;
    is_now := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE pg_catalog.to_jsonb(NEW) END;
    r := coalesce(is_now, was);
    -- The row's expiry as the tables bound it, as migrating rewrites it: a grant migrating deletes,
    -- merged into another, holds one they refuse, which JSON or a time.Time can't write.
    expiry := CASE WHEN (r->>'expires_at')::timestamptz = 'infinity' THEN NULL
              WHEN (r->>'expires_at')::timestamptz > '9999-12-30 23:59:59.999999+00' THEN '9999-12-30 23:59:59.999999+00'
              WHEN (r->>'expires_at')::timestamptz <= '0001-01-01 00:00:00+00' THEN timestamptz 'epoch'
              ELSE (r->>'expires_at')::timestamptz END;
    -- Parsed only within the bound, which the record checks first.
    said := current_setting('rbac.change', true);
    change := CASE WHEN pg_catalog.octet_length(said) > 1048576 THEN NULL ELSE coalesce(nullif(said, '')::jsonb, '{}') END;
    entity := CASE TG_TABLE_NAME WHEN 'rbac_grants' THEN 'grant' WHEN 'rbac_roles' THEN 'role'
              WHEN 'rbac_denies' THEN 'deny' WHEN 'rbac_eligibilities' THEN 'eligibility'
              WHEN 'rbac_memberships' THEN 'membership' WHEN 'rbac_groups' THEN 'group' WHEN 'rbac_members' THEN 'member' END;
    key := CASE entity WHEN 'deny' THEN (r->>'scope') || ' ' || (r->>'id') WHEN 'membership' THEN r->>'principal'
           WHEN 'member' THEN pg_catalog.jsonb_build_array(r->>'group_id', r->>'principal', r->>'source')::text
           ELSE r->>'id' END;
    was_key := CASE entity WHEN 'deny' THEN (was->>'scope') || ' ' || (was->>'id') WHEN 'membership' THEN was->>'principal'
               WHEN 'member' THEN pg_catalog.jsonb_build_array(was->>'group_id', was->>'principal', was->>'source')::text
               ELSE was->>'id' END;
    -- When the change took effect, but for an expiry: when its statement began, or its transaction,
    -- where that began later, and never before the row's last record, as a change can have moved
    -- its expiry back to before then. The last a write's snapshot holds: at READ COMMITTED, as the
    -- package changes the tables, this query takes one once the write has waited for another's
    -- lock on the row, but at REPEATABLE READ or SERIALIZABLE the transaction's is older, so a
    -- write that waited is dated before the change it waited for. Write around the package at READ
    -- COMMITTED.
    at := greatest(statement_timestamp(), transaction_timestamp());
    last := (SELECT max(h.effective_at) FROM rbac_history h
             WHERE h.tenant = r->>'tenant' AND h.entity = rbac_record.entity AND h.key = rbac_record.key);
    -- The context says only whether a delete is an expiry, and only a row that has expired by when
    -- the delete took effect is one, so whoever sets it can't record a revoke as anything else.
    op := CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update'
          WHEN 'DELETE' THEN CASE WHEN change->>'op' = 'expire' AND (was->>'expires_at')::timestamptz <= greatest(at, last)
            THEN 'expire' ELSE 'delete' END END;
    IF pg_catalog.pg_column_size(is_now) > 1048576 OR pg_catalog.octet_length(said) > 1048576 THEN
        RAISE EXCEPTION 'history records no row or change of more than 1 MiB: this % row is % bytes and its change %',
            TG_TABLE_NAME, pg_catalog.pg_column_size(is_now), pg_catalog.octet_length(said) USING ERRCODE = 'program_limit_exceeded';
    END IF;
    -- An update that moves a row to another key or tenant ends it under the old one, which would
    -- otherwise read as live for good, and starts it under the new.
    IF TG_OP = 'UPDATE' AND (was_key IS DISTINCT FROM key OR was->>'tenant' IS DISTINCT FROM is_now->>'tenant') THEN
        was_last := (SELECT max(h.effective_at) FROM rbac_history h
                     WHERE h.tenant = was->>'tenant' AND h.entity = rbac_record.entity AND h.key = was_key);
        -- An update revokes nothing, so a row it moves that had expired ended with its expiry, as an
        -- activation Activate makes anew did, rather than by the change that moved it.
        ended := (was->>'expires_at')::timestamptz <= greatest(at, was_last);
        INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
          before, after, bytes, actor, on_behalf_of, how, request, reason)
        VALUES (
          greatest(CASE WHEN ended THEN (was->>'expires_at')::timestamptz ELSE at END, was_last),
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
      greatest(CASE WHEN op = 'expire' THEN expiry ELSE at END, last),
      r->>'tenant', entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      expiry, was, is_now, coalesce(pg_catalog.octet_length(was::text), 0) + coalesce(pg_catalog.octet_length(is_now::text), 0),
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
    RETURN NULL;
END $$;
