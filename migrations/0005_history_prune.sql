-- A prune of history is recorded in it, as entity history and op prune. One statement, which
-- checks both constraints in one scan of history, as every write to the package's tables waits.
ALTER TABLE rbac_history DROP CONSTRAINT rbac_history_entity_check,
    ADD CONSTRAINT rbac_history_entity_check
        CHECK (entity IN ('grant', 'role', 'deny', 'eligibility', 'membership', 'group', 'member', 'history')),
    DROP CONSTRAINT rbac_history_op_check,
    ADD CONSTRAINT rbac_history_op_check CHECK (op IN ('create', 'update', 'delete', 'expire', 'baseline', 'prune'));

-- History is appended to, never changed, and removed only by PruneHistory, which sets rbac.prune
-- for its transaction, as a role with the rights of history's owner: that role can disable this
-- trigger anyway, so this keeps its delete deliberate. Any role can set rbac.prune, so one only
-- granted DELETE on history stays refused, as it was.
CREATE OR REPLACE FUNCTION rbac_history_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_catalog.current_setting('rbac.prune', true) = 'on'
        AND pg_catalog.pg_has_role(current_user, (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID), 'USAGE') THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'rbac_history is append only' USING ERRCODE = 'insufficient_privilege';
END $$;
