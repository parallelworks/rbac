-- AsOf's views tested each version for a later one of its row by the row's key, naming its entity,
-- and a plan could read that through history's partial index of an entity's versions by scope, of
-- denies (rbac_history_deny), or of grants and eligibilities (rbac_history_scope), by the tenant
-- and the time alone, every scope skipped, testing the key of each entry: so each deny a statement
-- read cost it every later version of the tenant's denies, on every scope. Beside 3,000 denies on
-- volumes naming a group and 3,000 naming the public, with history analyzed, Reachable as of a time
-- read 18 million pages of history, 4.4 s, against 377 before the denies; a host's query of
-- Filter's condition 36 million; and Denies of one volume 6,875 to list 2. Each such test names a
-- later version's entity now as the version's own, as PruneHistory's (byTime) do, from which no
-- partial index's predicate naming an entity can be proven, so neither of those indexes serves it,
-- and history's index of an entity's versions, which leads to the key, does: the versions it reads,
-- and so what the views give, are the same. Not by naming the row's scope, which the key of a deny
-- holds already, but which a grant or an eligibility moved in place, as by hand, changes under its
-- key: its version before the move would read as its last at the scope it left. The views are made
-- again here, which waits for a read as of a time under way, as one after waits for the migration;
-- it takes no lock a check, a change or a read of history waits for.
--
-- rbac_as_of_views found the views made before as any named as one of the package's tables that
-- read history, in any schema, and AsOf found them so: a view another session made over history in
-- its temporary schema, as any session of a role that may read history and has TEMPORARY can, or
-- another role's in a schema of its own, stood beside them, so AsOf refused every read in the
-- database, and rbac_as_of_views to make the views again (42P06), until it was gone. It looks for
-- them now among the views of the role migrating, which makes them, and AsOf among those of the
-- role owning the package's tables, which it requires their schema's owner to be, each outside
-- every session's temporary schema; and each checks the schema it finds as before.
--
-- rbac_history_commit refuses a transaction with a cursor WITH HOLD open that its procedure or DO
-- block declared in an earlier transaction: a cursor's creation time is the block's, and nothing
-- tells it from one this transaction declared, which this commit would run after the commit record.
-- A query string of several statements, as the simple protocol sends one, is such a block too: each
-- statement of it began as the string did, and each of its transactions with them, so a transaction
-- after one of the string that declared a cursor and committed, which ran it to its end, is refused
-- alike, and nothing tells the two apart either. So the check stays as it was, and only what its
-- refusal says changes: it names such a query string, and its hint how one commits, with the cursor
-- declared in a query string of its own. Every other check stays as 0029 made it, as do its
-- settings, given again here, and its owner and who may execute it, which replacing it keeps.
--
-- After the deferred triggers, and so after the commit record, PostgreSQL runs every loaded
-- extension's pre-commit callbacks, and postgres_fdw commits each remote transaction the local one
-- opened there: a remote COMMIT waits for what the remote server has it wait for, as a remote
-- deferred foreign key's check for a row another session holds there, which lock_timeout, the local
-- session's, doesn't bound, and in a test held a commit 1.5 s past its record. PostgreSQL 18's
-- postgres_fdw_get_connections() tells which of the session's connections the transaction used, but
-- rbac_history_commit doesn't refuse one that used any: no check of postgres_fdw's sees another
-- extension's callbacks, as another foreign-data wrapper's that commits its own remote
-- transactions, nor a connection a deferred trigger of the host's opens after the commit record's
-- event; and a role that may create in the extension's schema can make a call of the function
-- ambiguous, failing every commit, as revoking it would. So the README's roles give the
-- application's role no USAGE on any foreign-data wrapper or foreign server, no privilege on a
-- foreign table, nor pg_read_all_data, which reads every one, and no privilege on a view or a
-- function that reaches one as its owner, through the owner's user mapping.
CREATE OR REPLACE FUNCTION rbac_history_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
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
    -- declared in, and before every other, and in a query string of several statements when the
    -- string began, as each of its statements and transactions did: one it declared in an earlier
    -- transaction is refused too.
    IF EXISTS (SELECT FROM pg_catalog.pg_cursors c WHERE c.is_holdable
        AND c.creation_time >= LEAST(pg_catalog.statement_timestamp(), pg_catalog.transaction_timestamp())) THEN
        RAISE EXCEPTION 'a transaction that changes the package''s tables commits with no cursor WITH HOLD open that it, or the procedure, DO block or query string of several statements it runs in, declared: committing can run one after history dates the changes'
            USING ERRCODE = 'feature_not_supported',
            HINT = 'Declare it without HOLD; or in a transaction of its own, sent as a query string of its own, before the procedure, DO block or query string, which can fetch from it by its name; or close it before a transaction that changes the tables commits.';
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

CREATE OR REPLACE FUNCTION rbac_as_of_views() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    here     pg_catalog.text := pg_catalog.current_schema();
    history  pg_catalog.text := pg_catalog.format('%I.rbac_history', pg_catalog.current_schema());
    me       pg_catalog.oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER);
    tables   CONSTANT pg_catalog.text[] := '{rbac_grants,rbac_roles,rbac_denies,rbac_eligibilities,rbac_memberships,rbac_groups,rbac_members}';
    -- As AsOf sets them: the time is written in UTC with its era and read back by the format it was
    -- written in, whatever the reader's DateStyle and TimeZone.
    at       CONSTANT pg_catalog.text := $q$pg_catalog.to_timestamp(pg_catalog.current_setting('rbac.as_of'), 'YYYY-MM-DD HH24:MI:SS.US TZH BC')$q$;
    tenant   CONSTANT pg_catalog.text := $q$pg_catalog.current_setting('rbac.as_of_tenant')$q$;
    cluster  CONSTANT pg_catalog.text := $q$pg_catalog.current_setting('rbac.as_of_cluster')::pg_catalog.int8$q$;
    -- Of history, %1$s, the versions of the entity %2$L in the tenant %5$s that are each one's row's
    -- last counted by the time %3$s, by the cluster %4$s reading them: byTime's later, writtenLater
    -- and byCommit, each naming a later version's entity as h's own, as PruneHistory's do (above).
    last     CONSTANT pg_catalog.text := $q$h.tenant = %5$s AND h.entity = %2$L
          AND h.op NOT IN ('delete', 'expire') AND h.effective_at <= %3$s
          AND (h.txid, h.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
          AND CASE WHEN (SELECT CASE WHEN l.id > h.id AND ((l.txid = h.txid AND l.cluster IS NOT DISTINCT FROM h.cluster) OR (l.txid, l.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = l.txid
                AND c.cluster IS NOT DISTINCT FROM l.cluster),
              l.effective_at) <= %3$s) THEN l.id
            ELSE (SELECT n.id FROM %1$s n WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key AND n.id > h.id
              AND n.effective_at <= %3$s AND ((n.txid = h.txid AND n.cluster IS NOT DISTINCT FROM h.cluster) OR (n.txid, n.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = n.txid
                AND c.cluster IS NOT DISTINCT FROM n.cluster),
              n.effective_at) <= %3$s)
                AND (n.effective_at, n.id) > (h.effective_at, h.id)
              ORDER BY n.effective_at, n.id LIMIT 1) END
            FROM (SELECT n.id, n.txid, n.effective_at, n.cluster FROM %1$s n
              WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key AND n.effective_at <= %3$s
                AND (n.effective_at, n.id) > (h.effective_at, h.id)
              ORDER BY n.effective_at DESC, n.id DESC LIMIT 1) l) IS NOT NULL THEN false
            ELSE (SELECT CASE WHEN c.at IS NULL THEN NOT EXISTS (SELECT FROM %1$s n WHERE n.tenant = h.tenant AND n.entity = h.entity AND n.key = h.key AND n.id > h.id
              AND n.effective_at <= %3$s AND ((n.txid = h.txid AND n.cluster IS NOT DISTINCT FROM h.cluster) OR (n.txid, n.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = n.txid
                AND c.cluster IS NOT DISTINCT FROM n.cluster),
              n.effective_at) <= %3$s)) ELSE c.at <= %3$s END
            FROM (SELECT max(c.effective_at) AS at FROM %1$s c WHERE c.entity = 'commit' AND c.txid = h.txid
              AND c.cluster IS NOT DISTINCT FROM h.cluster) c) END$q$;
    -- Whether h counts by the time: byTime's counts.
    counts   CONSTANT pg_catalog.text := $q$h.effective_at <= %3$s AND (h.txid, h.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = h.txid
                AND c.cluster IS NOT DISTINCT FROM h.cluster),
              h.effective_at) <= %3$s$q$;
    named    pg_catalog.text;
    made     pg_catalog.oid[];
    views    pg_catalog.oid;
    e        record;
    selected pg_catalog.text;
    reader   pg_catalog.text;
BEGIN
    -- Those made before, whatever their schema and the package's are named now: the role's, outside
    -- every session's temporary schema (above).
    made := ARRAY(SELECT DISTINCT v.relnamespace FROM pg_catalog.pg_depend d
        JOIN pg_catalog.pg_rewrite w ON w.oid = d.objid
        JOIN pg_catalog.pg_class v ON v.oid = w.ev_class
        WHERE d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
          AND d.refobjid = history::pg_catalog.regclass AND v.relkind = 'v' AND v.relname = ANY (tables)
          AND v.relowner = me AND NOT pg_catalog.pg_is_other_temp_schema(v.relnamespace)
          AND v.relnamespace <> pg_catalog.pg_my_temp_schema());
    IF pg_catalog.cardinality(made) > 1 THEN
        RAISE EXCEPTION 'views named as the package''s tables read % in several schemas: %', history, made::pg_catalog.regnamespace[]
            USING ERRCODE = 'duplicate_schema';
    END IF;
    views := made[1];
    IF views IS NULL THEN
        IF pg_catalog.octet_length(here) > 57 THEN
            RAISE EXCEPTION 'schema % is named in % bytes, too many for the schema of AsOf''s views, named as it with _as_of after, in at most 63',
                here, pg_catalog.octet_length(here)
                USING ERRCODE = 'name_too_long', HINT = 'Rename it to a name of at most 57 bytes, and set the search_path to that.';
        END IF;
        named := here || '_as_of';
        views := pg_catalog.to_regnamespace(pg_catalog.quote_ident(named));
        IF views IS NULL THEN
            BEGIN
                EXECUTE pg_catalog.format('CREATE SCHEMA %I', named);
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE EXCEPTION 'the role % may not make schema % for AsOf''s views, which takes CREATE on the database', CURRENT_USER, named
                    USING ERRCODE = 'insufficient_privilege',
                    HINT = pg_catalog.format('Have a superuser run CREATE SCHEMA %I AUTHORIZATION %I, and migrate again.', named, CURRENT_USER);
            END;
            views := pg_catalog.to_regnamespace(pg_catalog.quote_ident(named));
        END IF;
    END IF;
    -- Made here, made for the role or made by an earlier migration, it is checked alike: where the
    -- views are made already, it holds them, the role's, and nothing else.
    IF (SELECT n.nspowner FROM pg_catalog.pg_namespace n WHERE n.oid = views) <> me
        OR EXISTS (SELECT FROM pg_catalog.aclexplode((SELECT n.nspacl FROM pg_catalog.pg_namespace n WHERE n.oid = views)) a
                   WHERE a.privilege_type = 'CREATE' AND a.grantee <> me)
        OR EXISTS (SELECT FROM pg_catalog.pg_depend d
                   WHERE d.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND d.refobjid = views
                     AND d.classid <> 'pg_catalog.pg_default_acl'::pg_catalog.regclass
                     AND NOT (made[1] IS NOT NULL AND d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                       AND d.objid IN (SELECT v.oid FROM pg_catalog.pg_class v
                         WHERE v.relnamespace = views AND v.relkind = 'v' AND v.relowner = me AND v.relname = ANY (tables)))) THEN
        RAISE EXCEPTION 'schema % is not one to make AsOf''s views in: it holds something other than them, is another role''s than %, or another may create in it',
            views::pg_catalog.regnamespace, CURRENT_USER
            USING ERRCODE = 'invalid_schema_definition',
            HINT = 'Make it empty, AUTHORIZATION the role that migrates, with CREATE granted to no other, as by that role''s default privileges.';
    END IF;
    FOR e IN SELECT * FROM (VALUES
        ('rbac_grants', 'grant', '{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}'),
        ('rbac_roles', 'role', '{"tenant": "tenant", "id": "key"}'),
        ('rbac_denies', 'deny', '{"tenant": "tenant", "scope": "scope"}'),
        ('rbac_eligibilities', 'eligibility', '{"tenant": "tenant", "principal": "principal", "role": "role", "scope": "scope"}'),
        ('rbac_memberships', 'membership', '{"tenant": "tenant", "principal": "key"}'),
        ('rbac_groups', 'group', '{"tenant": "tenant", "id": "key"}'),
        ('rbac_members', 'member', '{"tenant": "tenant", "group_id": "group_id", "principal": "principal"}')
    ) AS t(name, entity, copied) LOOP
        -- Each column as its row's version holds it, or as history copied it beside the version.
        selected := (SELECT pg_catalog.string_agg(CASE
                WHEN e.name = 'rbac_denies' AND a.attname = 'principals'
                    THEN pg_catalog.format($q$%I.rbac_text_array(h.after -> 'principals') COLLATE "C" AS principals$q$, here)
                WHEN a.attname = 'expires_at'
                    THEN $q$CASE r.expires_at WHEN 'infinity' THEN NULL WHEN '-infinity' THEN pg_catalog.timestamptz 'epoch' ELSE r.expires_at END AS expires_at$q$
                WHEN e.copied::pg_catalog.jsonb ? a.attname
                    THEN pg_catalog.format('h.%I AS %I', e.copied::pg_catalog.jsonb ->> a.attname, a.attname)
                ELSE pg_catalog.format('r.%I', a.attname) END, ', ' ORDER BY a.attnum)
            FROM pg_catalog.pg_attribute a
            WHERE a.attrelid = pg_catalog.format('%I.%I', here, e.name)::pg_catalog.regclass AND a.attnum > 0 AND NOT a.attisdropped);
        EXECUTE pg_catalog.format('CREATE OR REPLACE VIEW %s.%I WITH (security_invoker = true) AS ', views::pg_catalog.regnamespace, e.name)
            || pg_catalog.format(CASE WHEN e.entity = 'role' THEN
                $q$SELECT %6$s FROM (SELECT DISTINCT ON (h.key) h.* FROM %1$s h
                    WHERE h.tenant = %5$s AND h.entity = %2$L AND $q$ || counts || $q$
                    ORDER BY h.key, h.id DESC) h, LATERAL pg_catalog.jsonb_populate_record(NULL::%7$s, h.after) r
                WHERE h.op NOT IN ('delete', 'expire')$q$
            ELSE
                $q$SELECT %6$s FROM %1$s h, LATERAL pg_catalog.jsonb_populate_record(NULL::%7$s, h.after) r
                WHERE $q$ || last
            END, history, e.entity, at, cluster, tenant, selected, pg_catalog.format('%I.%I', here, e.name));
    END LOOP;
    -- Whoever may read history may read it through the views, as the role migrating, their owner,
    -- does already: one that may also use the package's schema, without which it reads no history,
    -- as the views name history by its oid, and USAGE isn't asked of a name never looked up.
    FOR reader IN SELECT DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident(r.rolname) END
        FROM pg_catalog.aclexplode((SELECT c.relacl FROM pg_catalog.pg_class c WHERE c.oid = history::pg_catalog.regclass)) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE a.privilege_type = 'SELECT' AND a.grantee <> me
          AND CASE WHEN a.grantee = 0
            THEN EXISTS (SELECT FROM pg_catalog.aclexplode((SELECT n.nspacl FROM pg_catalog.pg_namespace n WHERE n.nspname = here)) s
                         WHERE s.grantee = 0 AND s.privilege_type = 'USAGE')
            ELSE pg_catalog.has_schema_privilege(a.grantee, (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname = here), 'USAGE') END LOOP
        EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %s TO %s', views::pg_catalog.regnamespace, reader);
        EXECUTE pg_catalog.format('GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s', views::pg_catalog.regnamespace, reader);
    END LOOP;
END $$;

SELECT rbac_as_of_views();
