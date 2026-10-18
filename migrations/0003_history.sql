-- Every change to the package's tables, as it was made. Triggers write it, so a write that
-- bypasses the package is recorded too, as the database role that made it; nothing changes or
-- removes it.
CREATE TABLE rbac_history (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The transaction that made it, which History orders by: an id or a time is taken before its
    -- transaction commits, so one can commit after a later one.
    txid         xid8        NOT NULL DEFAULT pg_current_xact_id(),
    recorded_at  timestamptz NOT NULL DEFAULT now(),
    -- When it took effect: when it was made, or for an expiry, when it expired.
    effective_at timestamptz NOT NULL,
    tenant       text        COLLATE "C" NOT NULL,
    entity       text        COLLATE "C" NOT NULL
                             CHECK (entity IN ('grant', 'role', 'deny', 'eligibility', 'membership', 'group', 'member')),
    -- The entity's key in its tenant: a grant's or eligibility's id, a role's or group's id, a deny's
    -- scope and id, a membership's principal, a member's group, principal and source.
    key          text        COLLATE "C" NOT NULL,
    op           text        COLLATE "C" NOT NULL CHECK (op IN ('create', 'update', 'delete', 'expire', 'baseline')),
    principal    text        COLLATE "C",
    role         text        COLLATE "C",
    scope        text        COLLATE "C",
    group_id     text        COLLATE "C",
    expires_at   timestamptz,
    -- The row as it was and as it is, each null where there is none.
    before       jsonb,
    after        jsonb,
    -- Who made it through the package and how, on whose behalf, and the host's request and reason:
    -- empty for a write that bypassed it.
    actor        text        NOT NULL DEFAULT '',
    on_behalf_of text        NOT NULL DEFAULT '',
    how          text        NOT NULL DEFAULT '',
    request      text        NOT NULL DEFAULT '',
    reason       text        NOT NULL DEFAULT '',
    -- The database role whose session made it.
    db_user      text        NOT NULL DEFAULT session_user
);

-- History's cursor.
CREATE INDEX rbac_history_txid ON rbac_history (txid, id);
-- An entity's versions, latest first, as of a time.
CREATE INDEX rbac_history_entity ON rbac_history (tenant, entity, key, effective_at DESC);
-- What a principal held, and who held a role on a scope, as of a time.
CREATE INDEX rbac_history_principal ON rbac_history (tenant, principal, entity, effective_at DESC) WHERE principal IS NOT NULL;
CREATE INDEX rbac_history_role ON rbac_history (tenant, role, scope, effective_at DESC) WHERE role IS NOT NULL;

-- Records a change to a row, with the change's context the package sets for its transaction
-- (rbac.change). A definer's rights, so a role that may write the package's tables but not
-- history still records what it writes.
CREATE FUNCTION rbac_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    was    jsonb := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END;
    is_now jsonb := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END;
    r      jsonb := coalesce(is_now, was);
    change jsonb := coalesce(nullif(current_setting('rbac.change', true), '')::jsonb, '{}');
    op     text  := CASE TG_OP WHEN 'INSERT' THEN 'create' WHEN 'UPDATE' THEN 'update'
                   ELSE coalesce(change->>'op', 'delete') END;
    entity text;
    key    text;
BEGIN
    CASE TG_TABLE_NAME
    WHEN 'rbac_grants' THEN entity := 'grant'; key := r->>'id';
    WHEN 'rbac_roles' THEN entity := 'role'; key := r->>'id';
    WHEN 'rbac_denies' THEN entity := 'deny'; key := (r->>'scope') || ' ' || (r->>'id');
    WHEN 'rbac_eligibilities' THEN entity := 'eligibility'; key := r->>'id';
    WHEN 'rbac_memberships' THEN entity := 'membership'; key := r->>'principal';
    WHEN 'rbac_groups' THEN entity := 'group'; key := r->>'id';
    WHEN 'rbac_members' THEN entity := 'member'; key := (r->>'group_id') || ' ' || (r->>'principal') || ' ' || (r->>'source');
    END CASE;
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
      before, after, actor, on_behalf_of, how, request, reason)
    VALUES (
      -- An expiry took effect when it expired; a row removed with an expired membership, now.
      CASE WHEN op = 'expire' THEN least(coalesce((r->>'expires_at')::timestamptz, now()), now()) ELSE now() END,
      r->>'tenant', entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      (r->>'expires_at')::timestamptz, was, is_now,
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''));
    RETURN NULL;
END $$;

-- Its definer's rights read only this schema, and pg_temp last, so no one's objects stand in for
-- its own.
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_record() SET search_path = %I, pg_temp', current_schema());
END $$;

CREATE TRIGGER rbac_grants_history AFTER INSERT OR UPDATE OR DELETE ON rbac_grants
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_roles_history AFTER INSERT OR UPDATE OR DELETE ON rbac_roles
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_denies_history AFTER INSERT OR UPDATE OR DELETE ON rbac_denies
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_eligibilities_history AFTER INSERT OR UPDATE OR DELETE ON rbac_eligibilities
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_memberships_history AFTER INSERT OR UPDATE OR DELETE ON rbac_memberships
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_groups_history AFTER INSERT OR UPDATE OR DELETE ON rbac_groups
    FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_members_history AFTER INSERT OR UPDATE OR DELETE ON rbac_members
    FOR EACH ROW EXECUTE FUNCTION rbac_record();

-- A truncate fires no row's trigger, so it would change the tables unrecorded: deleting records it.
CREATE FUNCTION rbac_no_truncate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is recorded in rbac_history: delete from it rather than truncate it', TG_TABLE_NAME
        USING ERRCODE = 'feature_not_supported';
END $$;
CREATE TRIGGER rbac_grants_no_truncate BEFORE TRUNCATE ON rbac_grants FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_roles_no_truncate BEFORE TRUNCATE ON rbac_roles FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_denies_no_truncate BEFORE TRUNCATE ON rbac_denies FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_eligibilities_no_truncate BEFORE TRUNCATE ON rbac_eligibilities FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_memberships_no_truncate BEFORE TRUNCATE ON rbac_memberships FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_groups_no_truncate BEFORE TRUNCATE ON rbac_groups FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
CREATE TRIGGER rbac_members_no_truncate BEFORE TRUNCATE ON rbac_members FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();

-- History is appended to, never changed or removed.
CREATE FUNCTION rbac_history_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'rbac_history is append only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER rbac_history_append_only BEFORE UPDATE OR DELETE ON rbac_history
    FOR EACH ROW EXECUTE FUNCTION rbac_history_append_only();
CREATE TRIGGER rbac_history_no_truncate BEFORE TRUNCATE ON rbac_history
    FOR EACH STATEMENT EXECUTE FUNCTION rbac_history_append_only();
