-- An expiry is a row that had expired by the statement that deletes it. The transaction's start,
-- which 0003 read, can be long before it, as under a host's transaction, and earlier than the
-- clock DeleteExpired picks expired rows by, so a row that expired since was recorded as deleted.
-- And an update that changes a row's key, as a write around the package can, is recorded as the
-- end of the row under its old key and its start under the new.
CREATE OR REPLACE FUNCTION rbac_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
<<rbac_record>>
DECLARE
    was    jsonb := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE pg_catalog.to_jsonb(OLD) END;
    is_now jsonb := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE pg_catalog.to_jsonb(NEW) END;
    r      jsonb := coalesce(is_now, was);
    change jsonb := coalesce(nullif(current_setting('rbac.change', true), '')::jsonb, '{}');
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
BEGIN
    -- An update that moves a row to another key or tenant ends it under the old one, which would
    -- otherwise read as live for good, and starts it under the new.
    IF TG_OP = 'UPDATE' AND (was_key IS DISTINCT FROM key OR was->>'tenant' IS DISTINCT FROM is_now->>'tenant') THEN
        INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
          before, after, actor, on_behalf_of, how, request, reason)
        VALUES (now(), was->>'tenant', entity, was_key, 'delete', was->>'principal',
          CASE entity WHEN 'role' THEN was->>'id' ELSE was->>'role' END,
          was->>'scope',
          CASE entity WHEN 'group' THEN was->>'id' WHEN 'member' THEN was->>'group_id' END,
          (was->>'expires_at')::timestamptz, was, NULL,
          coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
          coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
        op := 'create';
        was := NULL;
    END IF;
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
      before, after, actor, on_behalf_of, how, request, reason)
    VALUES (
      -- An expiry took effect when it expired, but no earlier than the entity's last change, which
      -- can have moved its expiry back to before then.
      CASE WHEN op = 'expire' THEN greatest((r->>'expires_at')::timestamptz,
          (SELECT max(h.effective_at) FROM rbac_history h
           WHERE h.tenant = r->>'tenant' AND h.entity = rbac_record.entity AND h.key = rbac_record.key))
        ELSE now() END,
      r->>'tenant', entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      (r->>'expires_at')::timestamptz, was, is_now,
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
    RETURN NULL;
END $$;


-- Replacing a function resets its settings: its definer's rights read only this schema again.
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_record() SET search_path = %I, pg_temp', current_schema());
END $$;
