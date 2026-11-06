-- A change was dated by when its statement began, or its transaction where that began later, but no
-- other session sees it until its transaction commits, which a host's transaction, or the hook the
-- package's own runs before it commits (Config.OnChange), can put off as long as it likes: a revoke
-- still uncommitted read, as of a time while it was, as already in force, so once it committed, AsOf
-- of that time denied what every check then allowed, and a grant so read allowed what each denied.
-- Each transaction that changes the package's tables now records when it commits: a commit record,
-- of entity and op commit in no tenant, dated by the clock as it is written, which AsOf counts each
-- of the transaction's changes from and History returns with each of its records
-- (Record.CommittedAt). A record's own date is as it was, and those already written keep theirs: a
-- transaction that committed before this migration has no commit record, and its changes count from
-- their dates. One that only prunes writes none, as no read counts a prune from it.
--
-- A constraint trigger deferred to the commit writes it, rbac_record, which history's role owns and
-- writes history as, fired by each record the transaction writes, of which the last, by id, writes
-- it: so it is dated after every other event of the transaction's records fired. Any session may
-- fire deferred triggers early, with SET CONSTRAINTS ... IMMEDIATE, and then stay open: the commit
-- record's own event then fires at the end of the statement that wrote it, inside the trigger that
-- wrote it, a level deeper than the commit fires it, after. So there it defers the trigger again, by
-- name, and writes a record dated -infinity, which no read counts a change from, whose event writes
-- the transaction's commit record anew as it commits, as the last record's does: AsOf counts a
-- change from its transaction's latest commit record, and a host's transaction may set its own
-- constraints immediate. A session's own code can still run as it commits, once the commit record
-- is written, and put off what others see: a cursor WITH HOLD declared in the transaction, which
-- commit runs to its end, and a deferrable trigger on a temporary table, whose events fire after
-- those before them; so the last record's event refuses both, and a transaction with either can't
-- commit having changed the package's tables. A cursor's creation time is when the statement that
-- declared it began, which for one a procedure or a DO block declares in a later transaction, after
-- it commits, is before that transaction began. And as the commit empties a session's temporary
-- tables made ON COMMIT DELETE ROWS, it locks each, and its TOAST table, which another session of
-- the role can hold, the TOAST table by preparing a statement that names it, for as long as it
-- likes: so the commit record's event, at the commit, has the rest of it wait for no lock past
-- 100 ms. What runs after it is then the package's, the host's, as its own deferred triggers and
-- constraints of statements after the transaction's last change to the tables, and the commit's: the
-- session's temporary tables emptied or dropped, about half a millisecond each, and synchronous
-- replication, which waits before others see it, as long as synchronous_standby_names and the
-- session's synchronous_commit make it. A transaction prepared for two-phase commit fires its
-- deferred triggers as it is prepared, so its changes count from then, not from COMMIT PREPARED: keep
-- max_prepared_transactions at 0.
--
-- AsOf tested each version of a row for a later one, and PruneHistory each for a later one by its
-- time, in history's index of an entity's versions, by date: versions dated alike, as every write
-- of a DO block, a function or a query string of several statements is, read in the order of their
-- places, oldest first, so each read every one before it. 4,000 versions of a membership from one
-- block made a check as of a time read 743,745 pages of history, and 4,000 written apart 12,877;
-- pruning 6,001 from one block took 1.6 seconds, and 6,001 apart 0.16. The index now orders a row's
-- versions of one date by id, latest first, beside each one's transaction. As since 0006 none is
-- dated before the version before it, a version is tested by the row's latest dated by then after
-- it, and where that one's transaction committed later, by reading on from it in the index's order
-- until the first counted by then; where that finds none and the version is from before history
-- recorded commits, which a release before 0006 can have dated before a version written earlier,
-- also as it was, against the row's versions dated by then from the latest, which now reads the one
-- written last first.
--
-- And it holds the versions of grants, eligibilities and places in groups only for a read that
-- names their key, as the test for a later one does, and a prune's: PostgreSQL proves a partial
-- index's predicate from a query's conditions, not from the column's NOT NULL. As of a time, those
-- are read by their principal, scope, role or group, by history's indexes leading to each, but by
-- statistics that counted the tenant's rows of the entity as a few, as autovacuum leaves them until
-- a tenth of history is new, a plan read every one in the tenant by this index instead: beside
-- 3,000 others' places, a check of a subject in one group read 3,098 pages of history, and 65 by
-- fresh statistics, and a list of another's eligibilities read all 300 in the tenant. History's
-- index of scopes holds them only for a read that names a scope, for the same reason. Every read of
-- them by those columns now seeks them, whatever the statistics.
--
-- History is locked first, in the strongest mode the migration takes, as 0019 locks it: every change
-- waits until migrating commits, as each writes history, and every read of history too, as AsOf and
-- an export do; building each index reads all of history. Migrate applies a migration in a
-- transaction, which CREATE INDEX CONCURRENTLY can't run in.
LOCK TABLE rbac_history IN ACCESS EXCLUSIVE MODE;

DROP INDEX rbac_history_entity;
CREATE INDEX rbac_history_entity ON rbac_history (tenant, entity, key, effective_at DESC, id DESC) INCLUDE (txid)
    WHERE key IS NOT NULL OR entity NOT IN ('grant', 'eligibility', 'member');
DROP INDEX rbac_history_scope;
CREATE INDEX rbac_history_scope ON rbac_history (tenant, entity, scope, effective_at DESC)
    WHERE entity IN ('grant', 'eligibility') AND scope IS NOT NULL;

-- A transaction's commit records, the latest of which dates it.
CREATE INDEX rbac_history_commits ON rbac_history (txid) INCLUDE (effective_at) WHERE entity = 'commit';

-- The checks are wider than those they replace, which held every record, so neither reads history.
ALTER TABLE rbac_history DROP CONSTRAINT rbac_history_entity_check,
    ADD CONSTRAINT rbac_history_entity_check
        CHECK (entity IN ('grant', 'role', 'deny', 'eligibility', 'membership', 'group', 'member', 'history', 'commit')) NOT VALID,
    DROP CONSTRAINT rbac_history_op_check,
    ADD CONSTRAINT rbac_history_op_check CHECK (op IN ('create', 'update', 'delete', 'expire', 'baseline', 'prune', 'commit')) NOT VALID;

-- As 0024 wrote it, with the commit record. Replacing it keeps its owner and who may execute it,
-- but not its settings, so they are set here.
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
    -- A record history wrote, as rbac_history_committed fires it as its transaction commits.
    IF TG_TABLE_NAME = 'rbac_history' THEN
        -- A commit record. One dated -infinity, which no read counts a change from, holds an event
        -- to record the commit again (below), as the last record of its transaction does.
        IF NEW.entity = 'commit' AND NEW.effective_at <> '-infinity' THEN
            -- Fired a level deeper than the commit fires it: constraints were set immediate, so the
            -- transaction goes on past this record, as long as its session likes. Its commit is
            -- recorded again as it commits, by the event of a record of its own, which is deferred
            -- again for it, whatever the session set: AsOf counts a change from its transaction's
            -- latest commit record.
            IF pg_catalog.pg_trigger_depth() > 1 THEN
                EXECUTE pg_catalog.format('SET CONSTRAINTS %I.rbac_history_committed DEFERRED', TG_TABLE_SCHEMA);
                INSERT INTO rbac_history (effective_at, tenant, entity, key, op, bytes)
                VALUES ('-infinity', '', 'commit', pg_catalog.pg_current_xact_id()::text, 'commit', 0);
            -- What commits after it waits for no lock for long: a lock another session takes on a
            -- temporary table the commit empties (ON COMMIT DELETE ROWS), or on its TOAST table,
            -- which any session can take by preparing a statement that names it, would hold the
            -- commit, and what others see, back for as long as that session likes.
            ELSIF (SELECT s.setting::bigint FROM pg_catalog.pg_settings s WHERE s.name = 'lock_timeout') NOT BETWEEN 1 AND 100 THEN
                PERFORM pg_catalog.set_config('lock_timeout', '100ms', true);
            END IF;
            RETURN NULL;
        END IF;
        -- The event of the transaction's last record writes it, after every other event of its
        -- records fired. A prune's record dates nothing AsOf reads, so a transaction that wrote only
        -- those, as PruneHistory's own, writes none.
        IF EXISTS (SELECT FROM rbac_history h WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.id > NEW.id)
            OR NEW.entity = 'history' AND NOT EXISTS (SELECT FROM rbac_history h
              WHERE h.txid = pg_catalog.pg_current_xact_id() AND h.entity NOT IN ('history', 'commit')) THEN
            RETURN NULL;
        END IF;
        -- A cursor's creation time is when the statement that declared it began, which in a
        -- procedure or a DO block that commits is when the CALL or the block began, before the
        -- transaction it is declared in.
        IF EXISTS (SELECT FROM pg_catalog.pg_cursors c WHERE c.is_holdable
            AND c.creation_time >= LEAST(pg_catalog.statement_timestamp(), pg_catalog.transaction_timestamp())) THEN
            RAISE EXCEPTION 'a transaction that changes the package''s tables declares no cursor WITH HOLD: committing runs it after history dates the changes'
                USING ERRCODE = 'feature_not_supported', HINT = 'Declare it in a transaction of its own, or without HOLD.';
        END IF;
        IF EXISTS (SELECT FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_trigger t ON t.tgrelid = d.objid
            WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass
              AND d.refobjid = pg_catalog.pg_my_temp_schema() AND t.tgdeferrable AND t.tgenabled <> 'D') THEN
            RAISE EXCEPTION 'a session with a deferrable trigger on a temporary table commits no change to the package''s tables: committing fires it after history dates the changes'
                USING ERRCODE = 'feature_not_supported', HINT = 'Drop or disable the trigger, or make it NOT DEFERRABLE.';
        END IF;
        at := pg_catalog.clock_timestamp();
        INSERT INTO rbac_history (recorded_at, effective_at, tenant, entity, key, op, bytes)
        VALUES (at, at, '', 'commit', pg_catalog.pg_current_xact_id()::text, 'commit', 0);
        RETURN NULL;
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

CREATE CONSTRAINT TRIGGER rbac_history_committed AFTER INSERT ON rbac_history
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rbac_record();
-- In every session, as history's other triggers fire.
ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_committed;
