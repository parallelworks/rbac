-- AsOf stood temporary views of history in for the package's tables, made in each read's own
-- transaction, so a role that ran it needed TEMPORARY on the database: commit dating (0027) checks
-- a session's temporary objects only as its commit record is written, so the README's roles revoke
-- TEMPORARY from PUBLIC, and the application's role could not both run AsOf and be left without it.
-- And making them took a transaction id, which held every History and Export in the cluster back
-- for as long as the read ran, and under WithTx until the host's transaction ended.
--
-- The views are now made here, once, in a schema of their own beside the package's, named as it
-- with _as_of after, each named as the table it stands in for. AsOf names that schema first on its
-- transaction's search_path, which takes no transaction id and makes no object, so it reads in a
-- transaction or savepoint it makes READ ONLY, as a role without TEMPORARY: every statement of its
-- read, the package's, a hook's or the host's, and rbac_group_members's, which reads by its
-- caller's search_path, reads a table by its name as it was then.
--
-- Each view reads the tenant, the time and the cluster AsOf sets for its transaction
-- (rbac.as_of_tenant, rbac.as_of, rbac.as_of_cluster), as the temporary views did, so no value is
-- spliced into its definition. A session can set them too, and read through the views as of any
-- time and tenant, but only what it may read of history itself: they read with the rights of
-- whoever reads them (security_invoker), so history's privileges, and any row security policy on
-- it, are the reader's, never those of the views' owner, the role that migrated, which may read
-- every row. They read history alone, never the tables: in a session that never set them they fail,
-- and with them empty, as outside AsOf once a session has run it, they read nothing, as every row
-- of the tables names a tenant, or fail, as an empty cluster is no number. Each tested for empty,
-- as by NULLIF, every statement over them was planned a hundredth slower.
--
-- A role's id is its key, which history's index of an entity's versions seeks with its tenant: its
-- role column is indexed beside every grant and eligibility of the role, and a plan that counts the
-- tenant's roles as a few reads them all rather than seek that index. So are a membership's
-- principal and a group's id: by its principal or group column, which history indexes beside the
-- entity, a plan by statistics that count the tenant's memberships or groups as a few read every
-- one of them by the entity to find one. A grant, an eligibility and a place in a group are read by
-- columns other than their key, as their principal, and that index holds their versions only for a
-- read that names their key, as history's index of scopes holds them only for one that names a
-- scope: so by whichever of history's indexes leading to those columns a plan reads them, it seeks
-- them. The keys a deny names are read by the expression history's index on them reads them by
-- (0015). A version recorded before the tables refused an infinite expiry reads as migrating
-- rewrote its row.
--
-- Each table is the last version of each of its rows counted by the time, none where that was a
-- delete or an expiry, as AsOf has read it since 0027: a version counts from its date, or its
-- transaction's commit record where that is later, and is its row's last unless a later one, by id,
-- counts by then, which a subquery the planner can't make a join of reads by the row's key in
-- history's index of an entity's versions, a few pages for each version whatever history's
-- statistics. PruneHistory keeps the versions those views read, by the same SQL (byTime), which a
-- test holds them to. Custom roles are read by their ids, or all at once, as Grantable reads them:
-- their view takes each one's newest version counted by then, which a condition on the key reaches
-- into, so each is read once.
--
-- rbac_as_of_views makes or remakes the views from the tables' columns as they are, granting each
-- role that may read history the views and their schema, so a later migration that changes a table
-- calls it once it has, as its owner, and drops a view first where it drops or retypes a column the
-- view gives. Here it makes the schema too, which takes CREATE on the database: where the role
-- migrating hasn't it, a superuser or the database's owner makes the schema first, empty,
-- AUTHORIZATION that role, and it is taken as it is. One that holds anything, is another role's, or
-- in which another may create, is refused: AsOf names it first on the search_path, so a function
-- made there would be called in place of the package's, as whoever runs AsOf. Neither takes a lock
-- that a check, a change or a read of history waits for.
CREATE FUNCTION rbac_as_of_views() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    here     pg_catalog.text := pg_catalog.current_schema();
    history  pg_catalog.text := pg_catalog.format('%I.rbac_history', pg_catalog.current_schema());
    me       pg_catalog.oid := (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER);
    -- As AsOf sets them: the time is written in UTC with its era and read back by the format it was
    -- written in, whatever the reader's DateStyle and TimeZone.
    at       CONSTANT pg_catalog.text := $q$pg_catalog.to_timestamp(pg_catalog.current_setting('rbac.as_of'), 'YYYY-MM-DD HH24:MI:SS.US TZH BC')$q$;
    tenant   CONSTANT pg_catalog.text := $q$pg_catalog.current_setting('rbac.as_of_tenant')$q$;
    cluster  CONSTANT pg_catalog.text := $q$pg_catalog.current_setting('rbac.as_of_cluster')::pg_catalog.int8$q$;
    -- Of history, %1$s, the versions of the entity %2$L in the tenant %5$s that are each one's row's
    -- last counted by the time %3$s, by the cluster %4$s reading them: byTime's later, writtenLater
    -- and byCommit.
    last     CONSTANT pg_catalog.text := $q$h.tenant = %5$s AND h.entity = %2$L
          AND h.op NOT IN ('delete', 'expire') AND h.effective_at <= %3$s
          AND (h.txid, h.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
          AND CASE WHEN (SELECT CASE WHEN l.id > h.id AND ((l.txid = h.txid AND l.cluster IS NOT DISTINCT FROM h.cluster) OR (l.txid, l.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = l.txid
                AND c.cluster IS NOT DISTINCT FROM l.cluster),
              l.effective_at) <= %3$s) THEN l.id
            ELSE (SELECT n.id FROM %1$s n WHERE n.tenant = h.tenant AND n.entity = %2$L AND n.key = h.key AND n.id > h.id
              AND n.effective_at <= %3$s AND ((n.txid = h.txid AND n.cluster IS NOT DISTINCT FROM h.cluster) OR (n.txid, n.cluster) IS DISTINCT FROM (pg_catalog.pg_current_xact_id_if_assigned(), %4$s)
            AND coalesce((SELECT max(c.effective_at) FROM %1$s c WHERE c.entity = 'commit' AND c.txid = n.txid
                AND c.cluster IS NOT DISTINCT FROM n.cluster),
              n.effective_at) <= %3$s)
                AND (n.effective_at, n.id) > (h.effective_at, h.id)
              ORDER BY n.effective_at, n.id LIMIT 1) END
            FROM (SELECT n.id, n.txid, n.effective_at, n.cluster FROM %1$s n
              WHERE n.tenant = h.tenant AND n.entity = %2$L AND n.key = h.key AND n.effective_at <= %3$s
                AND (n.effective_at, n.id) > (h.effective_at, h.id)
              ORDER BY n.effective_at DESC, n.id DESC LIMIT 1) l) IS NOT NULL THEN false
            ELSE (SELECT CASE WHEN c.at IS NULL THEN NOT EXISTS (SELECT FROM %1$s n WHERE n.tenant = h.tenant AND n.entity = %2$L AND n.key = h.key AND n.id > h.id
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
    -- Those made before, whatever their schema and the package's are named now.
    made := ARRAY(SELECT DISTINCT v.relnamespace FROM pg_catalog.pg_depend d
        JOIN pg_catalog.pg_rewrite w ON w.oid = d.objid
        JOIN pg_catalog.pg_class v ON v.oid = w.ev_class
        WHERE d.classid = 'pg_catalog.pg_rewrite'::pg_catalog.regclass AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
          AND d.refobjid = history::pg_catalog.regclass AND v.relkind = 'v' AND v.relname = 'rbac_grants');
    IF pg_catalog.cardinality(made) > 1 THEN
        RAISE EXCEPTION 'views named rbac_grants read % in several schemas: %', history, made::pg_catalog.regnamespace[]
            USING ERRCODE = 'duplicate_schema';
    END IF;
    views := made[1];
    IF views IS NULL THEN
        named := here || '_as_of';
        views := pg_catalog.to_regnamespace(pg_catalog.quote_ident(named));
        IF views IS NULL THEN
            BEGIN
                EXECUTE pg_catalog.format('CREATE SCHEMA %I', named);
            EXCEPTION WHEN insufficient_privilege THEN
                RAISE EXCEPTION 'the role % may not make schema % for AsOf''s views, which takes CREATE on the database', CURRENT_USER, named
                    USING ERRCODE = 'insufficient_privilege',
                    HINT = pg_catalog.format('Have a superuser or the database''s owner run CREATE SCHEMA %I AUTHORIZATION %I, and migrate again.', named, CURRENT_USER);
            END;
            views := pg_catalog.to_regnamespace(pg_catalog.quote_ident(named));
        ELSIF (SELECT n.nspowner FROM pg_catalog.pg_namespace n WHERE n.oid = views) <> me
            OR EXISTS (SELECT FROM pg_catalog.pg_depend d WHERE d.refclassid = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND d.refobjid = views)
            OR EXISTS (SELECT FROM pg_catalog.aclexplode((SELECT n.nspacl FROM pg_catalog.pg_namespace n WHERE n.oid = views)) a
                       WHERE a.privilege_type = 'CREATE' AND a.grantee <> me) THEN
            RAISE EXCEPTION 'schema % is not one to make AsOf''s views in: it holds something, is another role''s than %, or another may create in it', named, CURRENT_USER
                USING ERRCODE = 'invalid_schema_definition',
                HINT = 'Make it empty, AUTHORIZATION the role that migrates, with CREATE granted to no other.';
        END IF;
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
    -- does already.
    FOR reader IN SELECT DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident(r.rolname) END
        FROM pg_catalog.aclexplode((SELECT c.relacl FROM pg_catalog.pg_class c WHERE c.oid = history::pg_catalog.regclass)) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE a.privilege_type = 'SELECT' AND a.grantee <> me LOOP
        EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %s TO %s', views::pg_catalog.regnamespace, reader);
        EXECUTE pg_catalog.format('GRANT SELECT ON ALL TABLES IN SCHEMA %s TO %s', views::pg_catalog.regnamespace, reader);
    END LOOP;
END $$;
-- Only the role migrating, which owns it, calls it.
REVOKE EXECUTE ON FUNCTION rbac_as_of_views() FROM PUBLIC;

SELECT rbac_as_of_views();
