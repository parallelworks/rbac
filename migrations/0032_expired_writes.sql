-- Every check and change decided no earlier than the latest time in rbac_expired, with no bound,
-- and every role holding INSERT, UPDATE or DELETE on rbac_grants, as the README's application role
-- does, held the same on it, which history didn't record: one row of a time far ahead, written
-- around the package, had every later call of every host decide then, for good, so a deny binding a
-- subject through a place ending before then lifted, and a condition reading request.time met,
-- while AsOf of the same moment, which doesn't read the table, still read the deny, and nothing
-- recorded the write. DeleteExpired never removed it, as it deletes only times no later than its
-- own. Deleting a time, unrecorded too, moved the latest back, and a read by an earlier clock could
-- again find a place a deny binds by removed and one a power comes through still there. Each read
-- now takes the latest time no later than the database's clock as it reads it, which takes nothing
-- from a time DeleteExpired recorded, as below no write records one past the clock as its statement
-- began, before it commits and so before a snapshot that sees it is taken. And here:
--
-- History records every write to the table, as it does to the package's other tables: rbac_record
-- records its rows as the entity 'expired', in no tenant, keyed by an id each row is given here, as
-- the other tables' rows are keyed by theirs, and the record's row holds its time, so the chain
-- covers it as every other field. Not by the time: two rows can hold one, as two runs can each add
-- it and bringing several back to the clock below gives them one, and a prune would take the delete
-- of one for the end of both, and delete every record of the one still there. A row there before is
-- recorded as migrating finds it, its baseline, dated at its time, as it was written no earlier, or
-- at the clock where that is earlier; one past the clock is then brought back to it, recorded as an
-- update, from its time to the clock's, so neither the row nor the bound it broke is lost to an
-- auditor. Widening history's check of entities reads no record, but locks history against reads
-- and writes until migrating commits, as 0027's did: every change, as each writes history, waits
-- for it, and every read of history, as AsOf and an export.
--
-- A trigger refuses a time past the database's clock as its statement began, whoever writes it, as
-- a check can't read the clock. It reads no table, so it runs as whoever writes, its search_path
-- pinned to pg_catalog, and no role but its owner may execute it, as the schema's default
-- privileges can grant it to one as it is made. Only a role that may disable the table's triggers
-- can write past it, or the database's clock going back leave such a time there, which every read
-- bounds all the same.
--
-- No role but the table's owner may write it, nor hold TRIGGER on it: a trigger runs as whoever
-- writes the table, which below is its owner. INSERT and UPDATE on its column are taken too, from a
-- role holding them there alone, which a revoke from the roles holding the table's passes over, and
-- every privilege on its id's sequence, which the schema's default privileges can grant as the id
-- is added: setval could have each later row take an id a row holds, or none, failing every run. A
-- trigger already there, as a role holding TRIGGER could have made, whose function a role other
-- than the owner or a superuser owns, is refused before anything writes the table: it would run
-- that role's code as the owner, from the update below on, whenever a role writes through
-- rbac_expired_through. DeleteExpired records a time through rbac_expired_through, which deletes
-- the times no later than its own, passing over those another run is deleting, and adds its own, as
-- the table's owner, so the latest only moves on, and never past the clock. Its body is SQL bound
-- as it is made, to the table in this schema and to pg_catalog's operators, so no name a session
-- resolves, no search_path and nothing it makes in pg_temp changes what it writes, and renaming the
-- schema leaves it naming the table; its search_path is pinned all the same. It is given to the
-- table's owner where another role migrates, and each role that held INSERT on the table or its
-- column, as 0030 granted it, may execute it in its place, so a deployment that gave its roles
-- their privileges before migrating runs DeleteExpired after it with no step of its own; no other
-- role may, whatever the schema's default privileges grant. Code before this writes the table
-- itself, so its DeleteExpired fails on such a role, which may no longer (SQLSTATE 42501); its
-- checks and changes, which only read it, run as before.
--
-- Adding the id locks the table against reads and writes until migrating commits: every write
-- waits for it, so none goes unrecorded between the baseline and the triggers, and so does every
-- check and change, as each reads the table. The table is locked before history: a batch of
-- DeleteExpired of the code before this locks the table as its statement begins and writes history
-- only as it ends, as the triggers recording what it removes fire, and a change reads the table
-- before it writes, so taking history first would deadlock with either in flight. A host's
-- transaction that changed the tables before it reads or writes this one takes history first, and
-- gives way to migrating, or migrating to it, by lock_timeout.

-- As 0029 wrote it, recording rbac_expired's rows too. Replacing it keeps its owner and who may
-- execute it, but not its settings, so they are set here, as 0029 set them. It takes no lock on the
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
              WHEN 'rbac_memberships' THEN 'membership' WHEN 'rbac_groups' THEN 'group' WHEN 'rbac_members' THEN 'member'
              WHEN 'rbac_expired' THEN 'expired' END;
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
             WHERE h.tenant = coalesce(r->>'tenant', '') AND h.entity = rbac_record.entity AND h.key = rbac_record.key);
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
                     WHERE h.tenant = coalesce(was->>'tenant', '') AND h.entity = rbac_record.entity AND h.key = was_key);
        -- An update revokes nothing, so a row it moves that had expired ended with its expiry, as an
        -- activation Activate makes anew did, rather than by the change that moved it.
        ended := (was->>'expires_at')::timestamptz <= greatest(at, was_last);
        INSERT INTO rbac_history (effective_at, tenant, entity, key, op, principal, role, scope, group_id, expires_at,
          before, after, bytes, actor, on_behalf_of, how, request, reason, cluster)
        VALUES (
          greatest(CASE WHEN ended THEN (was->>'expires_at')::timestamptz ELSE at END, was_last),
          coalesce(was->>'tenant', ''), entity, was_key, CASE WHEN ended THEN 'expire' ELSE 'delete' END, was->>'principal',
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
      coalesce(r->>'tenant', ''), entity, key, op, r->>'principal',
      CASE entity WHEN 'role' THEN r->>'id' ELSE r->>'role' END,
      r->>'scope',
      CASE entity WHEN 'group' THEN r->>'id' WHEN 'member' THEN r->>'group_id' END,
      expiry, was, is_now, coalesce(pg_catalog.octet_length(was::text), 0) + coalesce(pg_catalog.octet_length(is_now::text), 0),
      coalesce(change->>'actor', ''), coalesce(change->>'on_behalf_of', ''), coalesce(change->>'how', ''),
      coalesce(change->>'request', ''), coalesce(change->>'reason', ''), cluster_id);
    RETURN NULL;
END $$;

-- Locking the table against reads and writes, before history (see above).
ALTER TABLE rbac_expired ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY;

ALTER TABLE rbac_history DROP CONSTRAINT rbac_history_entity_check,
    ADD CONSTRAINT rbac_history_entity_check
        CHECK (entity IN ('grant', 'role', 'deny', 'eligibility', 'membership', 'group', 'member', 'history', 'commit', 'expired')) NOT VALID;

-- Before anything writes the table as its owner, as the update below does.
DO $$
DECLARE
    expired pg_catalog.regclass := (pg_catalog.quote_ident(pg_catalog.current_schema()) || '.rbac_expired')::pg_catalog.regclass;
    planted pg_catalog.text;
BEGIN
    SELECT pg_catalog.string_agg(pg_catalog.format('trigger %I runs %s, which %s owns', t.tgname, t.tgfoid::pg_catalog.regprocedure,
            p.proowner::pg_catalog.regrole), '; ' ORDER BY t.tgname)
        INTO planted
        FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
        WHERE t.tgrelid = expired AND NOT t.tgisinternal
          AND p.proowner <> (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = expired)
          AND NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.oid = p.proowner);
    IF planted IS NOT NULL THEN
        RAISE EXCEPTION 'rbac_expired has a trigger whose function neither the table''s owner nor a superuser owns, which would run as the table''s owner whenever rbac_expired_through writes it: %', planted
            USING ERRCODE = 'insufficient_privilege', HINT = 'Drop the trigger, revoke TRIGGER on rbac_expired from that role, and migrate again.';
    END IF;
END $$;

-- Written as rbac_record writes a record, its time as JSON in UTC, as TimeZone is set back to the
-- session's after: on a host's transaction it would stay set until that transaction ends.
DO $$
DECLARE
    zone text := pg_catalog.current_setting('TimeZone');
BEGIN
    PERFORM pg_catalog.set_config('TimeZone', 'UTC', true);
    INSERT INTO rbac_history (effective_at, tenant, entity, key, op, after, bytes, how, cluster)
    SELECT least(e.until, pg_catalog.statement_timestamp()), '', 'expired', pg_catalog.to_jsonb(e)->>'id', 'baseline',
      pg_catalog.to_jsonb(e), pg_catalog.octet_length(pg_catalog.to_jsonb(e)::text), 'Migrate',
      (pg_catalog.pg_control_system()).system_identifier
    FROM rbac_expired e ORDER BY e.id;
    PERFORM pg_catalog.set_config('TimeZone', zone, true);
END $$;

CREATE FUNCTION rbac_expired_until() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.until > pg_catalog.statement_timestamp() THEN
        RAISE EXCEPTION 'rbac_expired records no time past the database''s clock: % is after %', NEW.until, pg_catalog.statement_timestamp()
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER rbac_expired_until BEFORE INSERT OR UPDATE ON rbac_expired FOR EACH ROW EXECUTE FUNCTION rbac_expired_until();
CREATE TRIGGER rbac_expired_history AFTER INSERT OR UPDATE OR DELETE ON rbac_expired FOR EACH ROW EXECUTE FUNCTION rbac_record();
CREATE TRIGGER rbac_expired_no_truncate BEFORE TRUNCATE ON rbac_expired FOR EACH STATEMENT EXECUTE FUNCTION rbac_no_truncate();
-- In every session, as the other tables' triggers fire.
ALTER TABLE rbac_expired ENABLE ALWAYS TRIGGER rbac_expired_until, ENABLE ALWAYS TRIGGER rbac_expired_history,
    ENABLE ALWAYS TRIGGER rbac_expired_no_truncate;

SELECT pg_catalog.set_config('rbac.change', '{"how": "Migrate"}', true);
UPDATE rbac_expired SET until = pg_catalog.statement_timestamp() WHERE until > pg_catalog.statement_timestamp();
SELECT pg_catalog.set_config('rbac.change', '', true);

CREATE FUNCTION rbac_expired_through(through timestamptz) RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
BEGIN ATOMIC
    DELETE FROM rbac_expired WHERE id = ANY (ARRAY(SELECT id FROM rbac_expired WHERE until <= through FOR UPDATE SKIP LOCKED));
    INSERT INTO rbac_expired (until) VALUES (through);
END;

-- Named by the schema, so no table or function of the session's own stands in for one.
DO $$
DECLARE
    here    pg_catalog.text := pg_catalog.quote_ident(pg_catalog.current_schema());
    expired pg_catalog.regclass := (here || '.rbac_expired')::pg_catalog.regclass;
    through pg_catalog.regprocedure := (here || '.rbac_expired_through(timestamptz)')::pg_catalog.regprocedure;
    refusing pg_catalog.regprocedure := (here || '.rbac_expired_until()')::pg_catalog.regprocedure;
    owner   pg_catalog.oid := (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = expired);
    ids     pg_catalog.regclass := pg_catalog.pg_get_serial_sequence(here || '.rbac_expired', 'id')::pg_catalog.regclass;
    g       record;
BEGIN
    IF owner <> (SELECT p.proowner FROM pg_catalog.pg_proc p WHERE p.oid = through) THEN
        EXECUTE pg_catalog.format('ALTER FUNCTION %s OWNER TO %s', through, owner::pg_catalog.regrole);
    END IF;
    FOR g IN SELECT DISTINCT p.oid::pg_catalog.regprocedure AS fn,
            CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::pg_catalog.regrole::pg_catalog.text END AS grantee
        FROM pg_catalog.pg_proc p, pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
        WHERE p.oid IN (through, refusing) AND a.grantee <> p.proowner ORDER BY 1, 2 LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM %s CASCADE', g.fn, g.grantee);
    END LOOP;
    -- The table's and its column's: a revoke of the table's takes the column's with it.
    FOR g IN SELECT DISTINCT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::pg_catalog.regrole::pg_catalog.text END AS grantee
        FROM (SELECT c.relacl AS acl FROM pg_catalog.pg_class c WHERE c.oid = expired
              UNION ALL SELECT t.attacl FROM pg_catalog.pg_attribute t WHERE t.attrelid = expired AND t.attnum > 0) l,
          pg_catalog.aclexplode(l.acl) a
        WHERE a.privilege_type = 'INSERT' AND a.grantee <> owner ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION %s TO %s', through, g.grantee);
    END LOOP;
    FOR g IN SELECT DISTINCT a.privilege_type AS privilege,
            CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::pg_catalog.regrole::pg_catalog.text END AS grantee
        FROM (SELECT c.relacl AS acl FROM pg_catalog.pg_class c WHERE c.oid = expired
              UNION ALL SELECT t.attacl FROM pg_catalog.pg_attribute t WHERE t.attrelid = expired AND t.attnum > 0) l,
          pg_catalog.aclexplode(l.acl) a
        WHERE a.privilege_type <> 'SELECT' AND a.grantee <> owner ORDER BY 2, 1 LOOP
        EXECUTE pg_catalog.format('REVOKE %s ON %s FROM %s CASCADE', g.privilege, expired, g.grantee);
    END LOOP;
    -- The id's sequence, which the schema's default privileges can grant a role as it is made.
    FOR g IN SELECT DISTINCT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::pg_catalog.regrole::pg_catalog.text END AS grantee
        FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a
        WHERE c.oid = ids AND a.grantee <> owner ORDER BY 1 LOOP
        EXECUTE pg_catalog.format('REVOKE ALL ON SEQUENCE %s FROM %s CASCADE', ids, g.grantee);
    END LOOP;
END $$;
