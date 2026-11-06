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
-- its changes with it (SQLSTATE 54000). The queue holds what any listener in the cluster has yet to
-- read, and any role may LISTEN, so a small one fills while one lags, as one in a long transaction
-- does, and every commit that notifies fails until it catches up or ends.
--
-- The function writes history as its owner, so it is given to rbac_record's owner, history's role
-- where the README's roles are set up, not left to the role migrating, which makes it and owns the
-- package's tables too: whatever a session could have it run would run with those rights as well.
-- Giving it takes a role migrating that may SET ROLE to the new owner, and the new owner's CREATE on
-- the schema: where history's role has none, the role migrating grants it for this transaction alone
-- where it may, as the schema's owner can, and revokes it once the function is given. Where it can't
-- be given, migrating fails, saying what to change, rather than leave it to another role. Only its
-- trigger calls it, so no role but its owner may execute it, as none may rbac_history_pruned: a grant
-- the schema's default privileges gave it as it was made is revoked too, as a role holding one could
-- attach it to a table of its own in pg_temp, whose triggers would then run as its owner.
--
-- rbac_record is replaced without its path for a commit record, which no trigger reaches from here
-- on, so no copy of the commit record's checks is left to fall behind the one that runs.
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
    here    pg_catalog.text := pg_catalog.current_schema();
    fn      pg_catalog.regprocedure := pg_catalog.format('%I.rbac_history_commit()', here);
    owner   pg_catalog.regrole := (SELECT p.proowner FROM pg_catalog.pg_proc p
                                   WHERE p.oid = pg_catalog.format('%I.rbac_record()', here)::pg_catalog.regprocedure);
    grantee pg_catalog.regrole;
    lent    boolean := false;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(p.proacl) a
        WHERE p.oid = fn AND a.grantee <> 0 AND a.grantee <> p.proowner LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %s CASCADE', fn, grantee);
    END LOOP;
    IF owner <> (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid = fn) THEN
        IF NOT pg_catalog.has_schema_privilege(owner, here, 'CREATE')
            AND pg_catalog.has_schema_privilege(here, 'CREATE WITH GRANT OPTION')
            AND NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
            EXECUTE pg_catalog.format('GRANT CREATE ON SCHEMA %I TO %s', here, owner);
            lent := true;
        END IF;
        BEGIN
            EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO %s', fn, owner);
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE EXCEPTION 'rbac_history_commit, which writes history as its owner, can''t be given to %, which owns rbac_record: % may not SET ROLE to it, or it has no CREATE on schema %',
                owner, current_user, here USING ERRCODE = 'insufficient_privilege',
                HINT = pg_catalog.format('Grant %s CREATE on schema %I, or migrate as a superuser, and migrate again.', owner, here);
        END;
        IF lent THEN
            EXECUTE pg_catalog.format('REVOKE CREATE ON SCHEMA %I FROM %s', here, owner);
        END IF;
    END IF;
END $$;

DROP TRIGGER rbac_history_committed ON rbac_history;
CREATE CONSTRAINT TRIGGER rbac_history_committed AFTER INSERT ON rbac_history
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rbac_history_commit();
-- In every session, as history's other triggers fire.
ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed;

-- As 0027 wrote it, without its path for a commit record. Replacing it keeps its owner and who may
-- execute it, but not its settings, so they are set here, as 0027 set them. It takes no lock on the
-- tables.
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
    cluster_id bigint;
BEGIN
    -- A search_path reads $user, however it is quoted, as a role's name, and leaves out a schema
    -- the role has no USAGE on, so history would be found in pg_temp: refused before anything it
    -- names is read or called. The = it compares two names by is pg_catalog's, which has one of
    -- exactly their type, and comes first in a search_path that doesn't name it.
    IF pg_catalog.current_schema() IS DISTINCT FROM TG_TABLE_SCHEMA THEN
        RAISE EXCEPTION 'history is not found in schema %: no search_path names a schema called $user, nor one % has no USAGE on',
            TG_TABLE_SCHEMA, current_user USING ERRCODE = 'invalid_schema_name';
    END IF;
    -- The cluster writing the record, stamped on every one so AsOf trusts a commit record's dating
    -- only within the cluster that wrote it. Read once a transaction and held in a local setting, as
    -- one statement writes many records, and reading the server's control file for each made 8,000
    -- grants in one statement a seventh slower: only pg_catalog is read, after the schema is
    -- checked. A session can set the setting too, so the commit record checks every record its
    -- transaction wrote against the server's.
    cluster_id := nullif(pg_catalog.current_setting('rbac.cluster', true), '')::bigint;
    IF cluster_id IS NULL THEN
        cluster_id := (pg_catalog.pg_control_system()).system_identifier;
        PERFORM pg_catalog.set_config('rbac.cluster', cluster_id::text, true);
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
    -- COMMITTED. AsOf counts it from no earlier than its transaction's commit record.
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
          before, after, bytes, actor, on_behalf_of, how, request, reason, cluster)
        VALUES (
          greatest(CASE WHEN ended THEN (was->>'expires_at')::timestamptz ELSE at END, was_last),
          was->>'tenant', entity, was_key, CASE WHEN ended THEN 'expire' ELSE 'delete' END, was->>'principal',
          CASE entity WHEN 'role' THEN was->>'id' ELSE was->>'role' END,
          was->>'scope',
          CASE entity WHEN 'group' THEN was->>'id' WHEN 'member' THEN was->>'group_id' END,
          (was->>'expires_at')::timestamptz, was, NULL, pg_catalog.octet_length(was::text),
          coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
          coalesce(change->>'request', ''), coalesce(change->>'reason', ''), cluster_id);
        op := 'create';
        was := NULL;
    END IF;
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
      before, after, bytes, actor, on_behalf_of, how, request, reason, cluster)
    VALUES (
      greatest(CASE WHEN op = 'expire' THEN expiry ELSE at END, last),
      r->>'tenant', entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      expiry, was, is_now, coalesce(pg_catalog.octet_length(was::text), 0) + coalesce(pg_catalog.octet_length(is_now::text), 0),
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''), cluster_id);
    RETURN NULL;
END $$;
