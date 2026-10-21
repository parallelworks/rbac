-- A change was dated by when its statement began, which in a procedure or a DO block that commits as
-- it goes is when the block began, though each COMMIT there ends its transaction and starts another.
-- So a session of a role that may write the tables, as the application's, could revoke a grant in a
-- block's later transaction dated before a time when the grant gave access and every transaction
-- then running, the block's own included, had ended: AsOf of that time, read before the revoke,
-- allowed, and read after, denied. A change is dated by when its statement began, or its
-- transaction, where that began later, as one a block starts does, so no change is dated before the
-- transaction that made it began; and like an expiry, never before its row's last record. Outside a
-- procedure a transaction begins with its first statement, so nothing else is dated otherwise. A
-- delete is an expiry, and a row an update moves ended with its expiry, only where the row had
-- expired by that same time.
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

-- Replacing a function resets its settings: its definer's rights read only this schema again, and
-- it writes a row's times as JSON in UTC.
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_record() SET search_path = %I, pg_temp SET TimeZone = ''UTC''', current_schema());
END $$;
