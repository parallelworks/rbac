-- rbac_history_committed ran rbac_record as each record's event fired at the commit, with the four
-- settings and the start rbac_record needs to record a change: on a test server, a commit of 20,000
-- records took about 12.5 microseconds a record more than with the trigger disabled, 250 ms in all,
-- against 1, a fifth of the 64 microseconds writing a membership took, and at a million some 12
-- seconds more of COMMIT, which a statement_timeout can end. Of those, about 9 were its read of
-- history for a later record of the transaction, which reads every entry after the record's on its
-- index page, a few hundred. It now runs a function of its own, rbac_history_commit, set as its path
-- needs: its search_path, which it checks before it reads a table, and a generic plan with
-- sequential scans off, as rbac_record's, for its reads of history; no TimeZone, as nothing it does
-- reads or writes a time as text. And it looks for a later record among the next 32 ids first, as
-- the records a statement writes take ids one after another, or nearly, where other sessions write
-- too: about 8 microseconds a record, 160 ms for 20,000. Where none of those is the transaction's,
-- as where more than 32 sessions write history at once, record by record, it reads both, about 15.5.
-- The read stays: nothing else tells the event of the transaction's last record, which writes the
-- commit record, from the others, but what a session can set, as a setting, which would let it skip
-- the commit record and have AsOf count a revoke it held open from before it committed; and it
-- passes over an event only for a later record it found. Each check it made stays as it was, but for
-- what its refusal of a cursor says, below.
--
-- A cursor WITH HOLD that a procedure or a DO block declared in an earlier transaction, which that
-- transaction's commit ran to its end, is refused as one declared in this one, which this commit
-- would run after the commit record: a cursor's creation time is when the statement that declared it
-- began, the CALL or the block, before every transaction of it, so the two hold the same. Nothing
-- else tells them apart, against a session that can choose: the cursors open at the transaction's
-- first record, or a time that record took, would take one declared in this transaction before its
-- first change for an earlier one, and the catalog doesn't show whether a cursor has run. So the
-- hint says how such a batch commits: declare the cursor before the block, in a transaction of its
-- own, and fetch from it in the block by its name, or close it before a transaction that changes the
-- tables commits. A FOR loop over a query, which PL/pgSQL runs to its end as each COMMIT in it
-- begins, before any trigger fires, and doesn't declare WITH HOLD, is not refused.
--
-- What runs after the commit record includes writing the transaction's NOTIFY payloads to the
-- notification queue, which PostgreSQL does after the deferred triggers, and which no SQL can see
-- beforehand: about 1.6 ms a MB on a test server, 260 ms for 160 MB, and some 13 seconds at the
-- default queue of 8 GB. Any role can NOTIFY, which takes no privilege, so revoking EXECUTE on
-- pg_notify bounds nothing; lock_timeout doesn't, as it isn't a lock wait. Only the queue's size
-- does, max_notify_queue_pages from PostgreSQL 17 on: a commit whose payloads overflow it fails, and
-- its changes with it.
--
-- The function is made by the role migrating, so it gives it to rbac_record's owner, history's role
-- where the README's roles are set up, where the role migrating may: as a superuser, or as a member
-- of history's role where that role may create in the schema. Otherwise it stays the migrating
-- role's, which has the rights of history's owner, so the commit record is written all the same, and
-- is to be given to history's role after migrating, as rbac_record is. Only its trigger calls it, so no
-- role may execute it, as none may rbac_history_pruned. rbac_record keeps its path for a commit
-- record, which no trigger reaches from here on.
--
-- Replacing the trigger locks history against reads and writes until migrating commits, so every
-- change, as each writes history, and every read of history, as AsOf and an export, waits for it,
-- and a transaction under way as it starts that made a change can make it give way.
CREATE FUNCTION rbac_history_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp SET plan_cache_mode = force_generic_plan SET enable_seqscan = off AS $$
DECLARE
    -- Alone, as every statement below finds history by it.
    here       text := pg_catalog.set_config('search_path', pg_catalog.quote_ident(TG_TABLE_SCHEMA) || ', pg_temp', true);
    cluster_id bigint;
    inserted   numeric;
    top        numeric;
    mine       boolean;
    at         timestamptz;
BEGIN
    -- As rbac_record refuses, before anything it names is read or called.
    IF pg_catalog.current_schema() IS DISTINCT FROM TG_TABLE_SCHEMA THEN
        RAISE EXCEPTION 'history is not found in schema %: no search_path names a schema called $user, nor one % has no USAGE on',
            TG_TABLE_SCHEMA, current_user USING ERRCODE = 'invalid_schema_name';
    END IF;
    -- A commit record. One dated -infinity, which no read counts a change from, holds an event to
    -- record the commit again (below), as the last record of its transaction does.
    IF NEW.entity = 'commit' AND NEW.effective_at <> '-infinity' THEN
        -- Fired a level deeper than the commit fires it: constraints were set immediate, so the
        -- transaction goes on past this record, as long as its session likes. Its commit is
        -- recorded again as it commits, by the event of a record of its own, which is deferred again
        -- for it, whatever the session set: AsOf counts a change from its transaction's latest
        -- commit record.
        IF pg_catalog.pg_trigger_depth() > 1 THEN
            EXECUTE pg_catalog.format('SET CONSTRAINTS %I.rbac_history_committed DEFERRED', TG_TABLE_SCHEMA);
            INSERT INTO rbac_history (effective_at, tenant, entity, key, op, bytes, cluster)
            VALUES ('-infinity', '', 'commit', '', 'commit', 0, (pg_catalog.pg_control_system()).system_identifier);
        -- What commits after it waits for no lock for long: a lock another session takes on a
        -- temporary table the commit empties (ON COMMIT DELETE ROWS), or on its TOAST table, which
        -- any session can take by preparing a statement that names it, would hold the commit, and
        -- what others see, back for as long as that session likes. Not set among the function's
        -- settings, which it would put back as it returns.
        ELSIF (SELECT s.setting::bigint FROM pg_catalog.pg_settings s WHERE s.name = 'lock_timeout') NOT BETWEEN 1 AND 100 THEN
            PERFORM pg_catalog.set_config('lock_timeout', '100ms', true);
        END IF;
        RETURN NULL;
    END IF;
    -- The event of the transaction's last record writes it, after every other event of its records
    -- fired. A later record is looked for among the next 32 ids first, as a search of all the
    -- transaction's later ones reads every entry after the record's on its index page, and then
    -- among all of them. A prune's record dates nothing AsOf reads, so a transaction that wrote only
    -- those, as PruneHistory's own, writes none.
    IF EXISTS (SELECT FROM rbac_history h WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.id > NEW.id AND h.id <= NEW.id + 32) THEN
        RETURN NULL;
    END IF;
    IF EXISTS (SELECT FROM rbac_history h WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.id > NEW.id)
        OR NEW.entity = 'history' AND NOT EXISTS (SELECT FROM rbac_history h
          WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.entity NOT IN ('history', 'commit')) THEN
        RETURN NULL;
    END IF;
    -- A cursor's creation time is when the statement that declared it began, which in a procedure or
    -- a DO block that commits is when the CALL or the block began, before the transaction it is
    -- declared in, and before every other: one it declared in an earlier transaction is refused too.
    IF EXISTS (SELECT FROM pg_catalog.pg_cursors c WHERE c.is_holdable
        AND c.creation_time >= LEAST(pg_catalog.statement_timestamp(), pg_catalog.transaction_timestamp())) THEN
        RAISE EXCEPTION 'a transaction that changes the package''s tables commits with no cursor WITH HOLD open that it, or the procedure or DO block it runs in, declared: committing can run one after history dates the changes'
            USING ERRCODE = 'feature_not_supported',
            HINT = 'Declare it without HOLD, or in a transaction of its own before the procedure or DO block, which can fetch from it by its name; or close it before a transaction that changes the tables commits.';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_trigger t ON t.tgrelid = d.objid
        WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
          AND d.refobjid = pg_catalog.pg_my_temp_schema() AND t.tgdeferrable AND t.tgenabled <> 'D') THEN
        RAISE EXCEPTION 'a session with a deferrable trigger on a temporary table commits no change to the package''s tables: committing fires it after history dates the changes'
            USING ERRCODE = 'feature_not_supported', HINT = 'Drop or disable the trigger, or make it NOT DEFERRABLE.';
    END IF;
    -- Every record of the transaction that rbac_record stamped holds the cluster the server names,
    -- read here from the server, as the setting it stamped them from can be any a session set. Of
    -- the txid's records, those this transaction wrote, or one of its subtransactions, are those
    -- whose xmin, read as a full id no earlier than the transaction's own, is in progress: one a
    -- restore carried from another cluster, of a txid this cluster has since given the transaction,
    -- an earlier transaction wrote. An earlier transaction's, so read, is an id not given yet, which
    -- pg_xact_status refuses, unless 2^32 or more have been given since it.
    cluster_id := (pg_catalog.pg_control_system()).system_identifier;
    top := pg_catalog.pg_current_xact_id()::text::numeric;
    FOR inserted IN SELECT h.xmin::text::numeric FROM rbac_history h
        WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.cluster <> cluster_id LOOP
        BEGIN
            mine := pg_catalog.pg_xact_status((top + ((inserted - top % 4294967296) % 4294967296 + 4294967296) % 4294967296)
                ::text::pg_catalog.xid8) = 'in progress';
        EXCEPTION WHEN invalid_parameter_value THEN
            mine := false;
        END;
        IF mine THEN
            RAISE EXCEPTION 'a transaction that changes the package''s tables sets no rbac.cluster: history stamps each record with the cluster that wrote it, which AsOf dates it by'
                USING ERRCODE = 'insufficient_privilege', HINT = 'Reset rbac.cluster.';
        END IF;
    END LOOP;
    at := pg_catalog.clock_timestamp();
    INSERT INTO rbac_history (recorded_at, effective_at, tenant, entity, key, op, bytes, cluster)
    VALUES (at, at, '', 'commit', '', 'commit', 0, cluster_id);
    RETURN NULL;
END $$;
REVOKE EXECUTE ON FUNCTION rbac_history_commit() FROM PUBLIC;

DO $$
DECLARE
    owner pg_catalog.regrole := (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid = 'rbac_record()'::pg_catalog.regprocedure);
BEGIN
    IF owner <> (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid = 'rbac_history_commit()'::pg_catalog.regprocedure) THEN
        BEGIN
            EXECUTE pg_catalog.format('ALTER FUNCTION rbac_history_commit() OWNER TO %s', owner);
        EXCEPTION WHEN insufficient_privilege THEN
            NULL;
        END;
    END IF;
END $$;

DROP TRIGGER rbac_history_committed ON rbac_history;
CREATE CONSTRAINT TRIGGER rbac_history_committed AFTER INSERT ON rbac_history
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rbac_history_commit();
-- In every session, as history's other triggers fire.
ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed;
