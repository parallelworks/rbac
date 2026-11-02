-- rbac_record and rbac_history_pruned found history by the name the schema had when they were made,
-- which their search_path held, with pg_temp after it. Renamed, the schema answered to that name no
-- more, so they found history in pg_temp: a session that made a table of its own named rbac_history
-- there took the records of the changes it wrote after, which history never held, and one with the
-- rights of history's owner that recorded a prune there could delete any record of history's, which
-- the trigger let through though History counts no such prune. A schema made under the old name, as
-- for another installation, would have taken them all as its own history's. Each now sets its
-- search_path, for its own run alone, as a function's SET clause puts the caller's back once it
-- returns, to the schema of the table it fires on, and then pg_temp: history beside that table is
-- found before any table of pg_temp's, whatever the schema is named, and no name it was made under
-- is kept to go stale. Setting it costs each row recorded about 0.7 microseconds, as measured on a
-- trigger of the same settings that reads a table by name, of the 70 to 100 rbac_record takes.
-- Where that search_path can't name the schema, history would be found in pg_temp, so each refuses
-- the row: a search_path reads $user, however it is quoted, as a role's name, and leaves out a
-- schema the role has no USAGE on, as history's role has none where a host left that grant out.
-- Checking costs a row about 0.2 microseconds more.
--
-- No other function of the package's reads a table by a name of its own: rbac_group_members reads
-- the tables by its caller's search_path, as the caller's statement does, so that under AsOf it
-- reads the views; rbac_history_append_only reads pg_catalog alone, and the rest no table.
-- Replacing a function keeps its owner and who may execute it, but not its settings, so each is
-- set here. Neither takes a lock on the tables: changes go on as it is applied, each recorded as
-- the function was until migrating commits.
CREATE OR REPLACE FUNCTION rbac_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp SET TimeZone = 'UTC' SET plan_cache_mode = force_generic_plan SET enable_seqscan = off AS $$
<<rbac_record>>
DECLARE
    -- First, as every statement below finds history by it.
    here   text  := pg_catalog.set_config('search_path', pg_catalog.quote_ident(TG_TABLE_SCHEMA) || ', pg_temp', true);
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
    entity text  := CASE TG_TABLE_NAME WHEN 'rbac_grants' THEN 'grant' WHEN 'rbac_roles' THEN 'role'
                   WHEN 'rbac_denies' THEN 'deny' WHEN 'rbac_eligibilities' THEN 'eligibility'
                   WHEN 'rbac_memberships' THEN 'membership' WHEN 'rbac_groups' THEN 'group' WHEN 'rbac_members' THEN 'member' END;
    key    text  := CASE entity WHEN 'deny' THEN (r->>'scope') || ' ' || (r->>'id') WHEN 'membership' THEN r->>'principal'
                   WHEN 'member' THEN pg_catalog.jsonb_build_array(r->>'group_id', r->>'principal', r->>'source')::text
                   ELSE r->>'id' END;
    was_key text := CASE entity WHEN 'deny' THEN (was->>'scope') || ' ' || (was->>'id') WHEN 'membership' THEN was->>'principal'
                   WHEN 'member' THEN pg_catalog.jsonb_build_array(was->>'group_id', was->>'principal', was->>'source')::text
                   ELSE was->>'id' END;
    -- When the change took effect, but for an expiry: when its statement began, or its transaction,
    -- where that began later, and never before the row's last record, as a change can have moved
    -- its expiry back to before then. The last a write's snapshot holds: at READ COMMITTED, as the
    -- package changes the tables, this query takes one once the write has waited for another's
    -- lock on the row, but at REPEATABLE READ or SERIALIZABLE the transaction's is older, so a
    -- write that waited is dated before the change it waited for. Write around the package at READ
    -- COMMITTED.
    at     timestamptz := greatest(statement_timestamp(), transaction_timestamp());
    last   timestamptz := (SELECT max(h.effective_at) FROM rbac_history h
                   WHERE h.tenant = r->>'tenant' AND h.entity = rbac_record.entity AND h.key = rbac_record.key);
    -- The context says only whether a delete is an expiry, and only a row that has expired by when
    -- the delete took effect is one, so whoever sets it can't record a revoke as anything else.
    op     text  := CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update'
                   WHEN 'DELETE' THEN CASE WHEN change->>'op' = 'expire' AND (was->>'expires_at')::timestamptz <= greatest(at, last)
                     THEN 'expire' ELSE 'delete' END END;
    was_last timestamptz;
    ended  boolean;
BEGIN
    -- A search_path reads $user, however it is quoted, as a role's name, and leaves out a schema
    -- the role has no USAGE on, so history would be found in pg_temp: refused before any record.
    IF pg_catalog.current_schema() IS DISTINCT FROM TG_TABLE_SCHEMA THEN
        RAISE EXCEPTION 'history is not found in schema %: no search_path names a schema called $user, nor one % has no USAGE on',
            TG_TABLE_SCHEMA, current_user USING ERRCODE = 'invalid_schema_name';
    END IF;
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

CREATE OR REPLACE FUNCTION rbac_history_pruned() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    -- First, as the statement below finds history by it: the table it fires on.
    here text := pg_catalog.set_config('search_path', pg_catalog.quote_ident(TG_TABLE_SCHEMA) || ', pg_temp', true);
BEGIN
    -- As rbac_record refuses, or a prune recorded in pg_temp would let the delete through.
    IF pg_catalog.current_schema() IS DISTINCT FROM TG_TABLE_SCHEMA THEN
        RAISE EXCEPTION 'history is not found in schema %: no search_path names a schema called $user, nor one % has no USAGE on',
            TG_TABLE_SCHEMA, current_user USING ERRCODE = 'invalid_schema_name';
    END IF;
    IF OLD.txid < pg_catalog.pg_current_xact_id() AND EXISTS (SELECT FROM rbac_history p
        WHERE p.entity = 'history' AND p.txid = pg_catalog.pg_current_xact_id() AND p.op = 'prune'
          AND (OLD.txid, OLD.id) <= ((coalesce(p.after->'last', p.after->'through')->>'txid')::pg_catalog.xid8,
                                     (coalesce(p.after->'last', p.after->'through')->>'id')::bigint)) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'rbac_history record % is deleted by no prune its transaction records: prune history with PruneHistory', OLD.id
        USING ERRCODE = 'insufficient_privilege';
END $$;
