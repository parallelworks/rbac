-- A row's record, as 0006 wrote it, but for an expiry at the first instant of year 1, which a
-- time.Time holds as its zero, read as none: the tables refuse it from here, as one before it, and
-- it is recorded as the epoch, as migrating rewrites it.
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
    ended  boolean;
BEGIN
    -- An update that moves a row to another key or tenant ends it under the old one, which would
    -- otherwise read as live for good, and starts it under the new.
    IF TG_OP = 'UPDATE' AND (was_key IS DISTINCT FROM key OR was->>'tenant' IS DISTINCT FROM is_now->>'tenant') THEN
        -- An update revokes nothing, so a row it moves that had expired ended with its expiry, as an
        -- activation Activate makes anew did, rather than by the change that moved it.
        ended := (was->>'expires_at')::timestamptz <= statement_timestamp();
        INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
          before, after, actor, on_behalf_of, how, request, reason)
        VALUES (
          greatest(CASE WHEN ended THEN (was->>'expires_at')::timestamptz ELSE statement_timestamp() END,
            (SELECT max(h.effective_at) FROM rbac_history h
             WHERE h.tenant = was->>'tenant' AND h.entity = rbac_record.entity AND h.key = was_key)),
          was->>'tenant', entity, was_key, CASE WHEN ended THEN 'expire' ELSE 'delete' END, was->>'principal',
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
      expiry, was, is_now,
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
    RETURN NULL;
END $$;

-- Replacing a function resets its settings: its definer's rights read only this schema again, and
-- it writes a row's times as JSON in UTC.
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_record() SET search_path = %I, pg_temp SET TimeZone = ''UTC''', current_schema());
END $$;

-- A row written before history was installed, as by a host that applied the first migrations on
-- their own, has no record, so AsOf would read it as never written. Each row with none is recorded
-- as it is, its baseline, as rbac_record records a row: dated when it was created, or a role, which
-- keeps no such time, when it last changed, but never after now, and its times as JSON in UTC.
-- Writes to the tables wait until migrating commits, and those in flight end first: a change that
-- committed after the baseline read its row, with a record numbered before the baseline, would be
-- superseded by it, and AsOf would read the row as it was before the change.
LOCK TABLE rbac_grants, rbac_roles, rbac_denies, rbac_eligibilities, rbac_memberships, rbac_groups, rbac_members IN SHARE MODE;
DO $$
DECLARE
    zone text := current_setting('TimeZone');
BEGIN
    PERFORM set_config('TimeZone', 'UTC', true);
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at, after, how)
    SELECT least(b.at, statement_timestamp()), b.r->>'tenant', b.entity, b.key, 'baseline', b.r->>'principal',
      CASE b.entity WHEN 'role' THEN b.r->>'id' ELSE b.r->>'role' END,
      b.r->>'scope',
      CASE b.entity WHEN 'group' THEN b.r->>'id' WHEN 'member' THEN b.r->>'group_id' END,
      CASE WHEN (b.r->>'expires_at')::timestamptz = 'infinity' THEN NULL
        WHEN (b.r->>'expires_at')::timestamptz > '9999-12-30 23:59:59.999999+00' THEN '9999-12-30 23:59:59.999999+00'
        WHEN (b.r->>'expires_at')::timestamptz <= '0001-01-01 00:00:00+00' THEN timestamptz 'epoch'
        ELSE (b.r->>'expires_at')::timestamptz END,
      b.r, 'Migrate'
    FROM (
      SELECT e.entity, e.r, e.at,
        CASE e.entity WHEN 'deny' THEN (e.r->>'scope') || ' ' || (e.r->>'id') WHEN 'membership' THEN e.r->>'principal'
          WHEN 'member' THEN pg_catalog.jsonb_build_array(e.r->>'group_id', e.r->>'principal', e.r->>'source')::text
          ELSE e.r->>'id' END AS key
      FROM (
        SELECT 'grant' AS entity, pg_catalog.to_jsonb(t) AS r, t.created_at AS at FROM rbac_grants t
        UNION ALL SELECT 'role', pg_catalog.to_jsonb(t), t.updated_at FROM rbac_roles t
        UNION ALL SELECT 'deny', pg_catalog.to_jsonb(t), t.created_at FROM rbac_denies t
        UNION ALL SELECT 'eligibility', pg_catalog.to_jsonb(t), t.created_at FROM rbac_eligibilities t
        UNION ALL SELECT 'membership', pg_catalog.to_jsonb(t), t.created_at FROM rbac_memberships t
        UNION ALL SELECT 'group', pg_catalog.to_jsonb(t), t.created_at FROM rbac_groups t
        UNION ALL SELECT 'member', pg_catalog.to_jsonb(t), t.created_at FROM rbac_members t
      ) e
    ) b
    WHERE NOT EXISTS (SELECT FROM rbac_history h WHERE h.tenant = b.r->>'tenant' AND h.entity = b.entity AND h.key = b.key)
    ORDER BY 1, b.entity, b.key;
    PERFORM set_config('TimeZone', zone, true);
END $$;

-- An expiry at the first instant of year 1 is a time.Time's zero, which a Record reads as none.
-- Those stored are kept as 0006 kept one before it, as expired by any clock, at the epoch, and of
-- grants that differ only in an expiry the rewrite makes one, the one already at the epoch stays,
-- the other going as its expiry.
SELECT set_config('rbac.change', '{"how": "Migrate", "op": "expire"}', true);
DELETE FROM rbac_grants g
    WHERE g.expires_at <= '0001-01-01 00:00:00+00'
      AND EXISTS (SELECT FROM rbac_grants o
        WHERE (o.tenant, o.principal, o.scope, o.role, o.source, o.condition) = (g.tenant, g.principal, g.scope, g.role, g.source, g.condition)
          AND o.expires_at = 'epoch');
SELECT set_config('rbac.change', '{"how": "Migrate"}', true);
UPDATE rbac_grants SET expires_at = 'epoch' WHERE expires_at <= '0001-01-01 00:00:00+00';
UPDATE rbac_eligibilities SET expires_at = 'epoch' WHERE expires_at <= '0001-01-01 00:00:00+00';
UPDATE rbac_memberships SET expires_at = 'epoch' WHERE expires_at <= '0001-01-01 00:00:00+00';
UPDATE rbac_members SET expires_at = 'epoch' WHERE expires_at <= '0001-01-01 00:00:00+00';
SELECT set_config('rbac.change', '', true);
ALTER TABLE rbac_grants DROP CONSTRAINT rbac_grants_expires_at_check, ADD CONSTRAINT rbac_grants_expires_at_check
    CHECK (expires_at > '0001-01-01 00:00:00+00' AND expires_at <= '9999-12-30 23:59:59.999999+00');
ALTER TABLE rbac_eligibilities DROP CONSTRAINT rbac_eligibilities_expires_at_check, ADD CONSTRAINT rbac_eligibilities_expires_at_check
    CHECK (expires_at > '0001-01-01 00:00:00+00' AND expires_at <= '9999-12-30 23:59:59.999999+00');
ALTER TABLE rbac_memberships DROP CONSTRAINT rbac_memberships_expires_at_check, ADD CONSTRAINT rbac_memberships_expires_at_check
    CHECK (expires_at > '0001-01-01 00:00:00+00' AND expires_at <= '9999-12-30 23:59:59.999999+00');
ALTER TABLE rbac_members DROP CONSTRAINT rbac_members_expires_at_check, ADD CONSTRAINT rbac_members_expires_at_check
    CHECK (expires_at > '0001-01-01 00:00:00+00' AND expires_at <= '9999-12-30 23:59:59.999999+00');
