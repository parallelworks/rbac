-- A create, update or delete was dated by its transaction's start, which under a host's transaction
-- can be long before it, and before another transaction's change to the row since: a revoke of a
-- grant made after its transaction began was dated before the grant, which AsOf then read as never
-- held. It is dated by its statement, and like an expiry, no earlier than the row's last record: a
-- statement that waited for another's lock on the row began before that one changed it.
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
      -- the row's last record: a change can have moved its expiry back to before then.
      greatest(CASE WHEN op = 'expire' THEN (r->>'expires_at')::timestamptz ELSE statement_timestamp() END,
        (SELECT max(h.effective_at) FROM rbac_history h
         WHERE h.tenant = r->>'tenant' AND h.entity = rbac_record.entity AND h.key = rbac_record.key)),
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

-- When a record was written, as Record.RecordedAt says, rather than when its transaction began.
ALTER TABLE rbac_history ALTER COLUMN recorded_at SET DEFAULT clock_timestamp();

-- An expiry of infinity or -infinity, which a role that may write the tables could store, is one a
-- time.Time can't hold, so History failed on its record, and every export stopped there; and one
-- outside the years 1 to 9999 is one JSON and RFC 3339 can't, so an export that writes either
-- stopped there too. Those stored are kept as what they meant: one at infinity never expires, one
-- past 9999 expires at its end, and one at -infinity or before year 1 has, by any clock: dated by
-- the migration, it would read as held to a host whose clock is behind.
SELECT set_config('rbac.change', '{"how": "Migrate"}', true);
UPDATE rbac_grants SET expires_at = CASE WHEN expires_at = 'infinity' THEN NULL
    WHEN expires_at > '9999-12-31 23:59:59.999999+00' THEN '9999-12-31 23:59:59.999999+00' ELSE timestamptz 'epoch' END
    WHERE expires_at NOT BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00';
UPDATE rbac_eligibilities SET expires_at = CASE WHEN expires_at = 'infinity' THEN NULL
    WHEN expires_at > '9999-12-31 23:59:59.999999+00' THEN '9999-12-31 23:59:59.999999+00' ELSE timestamptz 'epoch' END
    WHERE expires_at NOT BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00';
UPDATE rbac_memberships SET expires_at = CASE WHEN expires_at = 'infinity' THEN NULL
    WHEN expires_at > '9999-12-31 23:59:59.999999+00' THEN '9999-12-31 23:59:59.999999+00' ELSE timestamptz 'epoch' END
    WHERE expires_at NOT BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00';
UPDATE rbac_members SET expires_at = CASE WHEN expires_at = 'infinity' THEN NULL
    WHEN expires_at > '9999-12-31 23:59:59.999999+00' THEN '9999-12-31 23:59:59.999999+00' ELSE timestamptz 'epoch' END
    WHERE expires_at NOT BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00';
SELECT set_config('rbac.change', '', true);
ALTER TABLE rbac_grants ADD CONSTRAINT rbac_grants_expires_at_check
    CHECK (expires_at BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00');
ALTER TABLE rbac_eligibilities ADD CONSTRAINT rbac_eligibilities_expires_at_check
    CHECK (expires_at BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00');
ALTER TABLE rbac_memberships ADD CONSTRAINT rbac_memberships_expires_at_check
    CHECK (expires_at BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00');
ALTER TABLE rbac_members ADD CONSTRAINT rbac_members_expires_at_check
    CHECK (expires_at BETWEEN '0001-01-01 00:00:00+00' AND '9999-12-31 23:59:59.999999+00');

-- As of a time, a group's members and the denies on a scope are read by the rows a statement
-- names, as a subject's grants are by principal, not all of the tenant's. Only those records have
-- entries, so writes of grants pay nothing for them.
CREATE INDEX rbac_history_group ON rbac_history (tenant, group_id, entity, effective_at DESC) WHERE group_id IS NOT NULL;
CREATE INDEX rbac_history_deny ON rbac_history (tenant, scope, effective_at DESC) WHERE entity = 'deny';

-- The trigger runs as whoever deletes, and read its operators on their search_path: a role granted
-- DELETE on history, with a schema of its own first there, could make an = that finds a table it
-- owns as history, and delete it with rbac.prune set. It reads only pg_catalog, by name.
CREATE OR REPLACE FUNCTION rbac_history_append_only() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP OPERATOR(pg_catalog.=) 'DELETE' AND pg_catalog.current_setting('rbac.prune', true) OPERATOR(pg_catalog.=) 'on'
        AND pg_catalog.pg_has_role(current_user, (SELECT c.relowner FROM pg_catalog.pg_class c
          WHERE c.oid OPERATOR(pg_catalog.=) TG_RELID), 'USAGE') THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'rbac_history is append only' USING ERRCODE = 'insufficient_privilege';
END $$;
