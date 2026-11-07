-- rbac_group_members runs the statements of a check, a list and a change that reach the members of
-- groups, each of which now plans its reads with sequential scans off, so the members' tables are
-- read by key however small they were when a session planned the calling statement; and a function
-- takes its caller's settings. Its first statement, reading the groups' places, needs them off too:
-- planned by statistics from when rbac_members was nearly empty, which count a group's places as
-- the whole table's, it read every place in the table, 20 pages and 284 beside 20,000 others'. So it
-- sets them off for itself, by its SET clause, which PostgreSQL puts back as it returns, and reads
-- each group's places on its own, in the primary key's order, which only the index leading to the
-- group gives, so a plan can't read them by an index leading to the tenant alone; and each group
-- once however often it is named, as reading them by = ANY of the groups did. Its second, joining
-- the members to their memberships, is planned for the members' number: as a join to the table, many
-- were each looked up on its own with sequential scans off, 20,179 pages of memberships that fill
-- 856 for a group of 20,000. So it reads the members' memberships by their keys, as = ANY of them,
-- which a plan for many reads through a bitmap of an index leading to the principal, each page once,
-- and hashes with the members: 633 pages for a group of 20,000 beside 20,000 other tenants'
-- memberships. Not by setting them on for that statement: a function runs in parallel mode
-- where its calling statement does, as one with a Gather anywhere in its plan does, and there a
-- setting changes only by a SET clause, so set_config failed the call. Replacing it keeps its owner
-- and who may execute it, and takes no lock on the tables.
CREATE OR REPLACE FUNCTION rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
    RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE plpgsql STABLE PARALLEL RESTRICTED
    SET enable_seqscan = off AS $$
DECLARE
    places CONSTANT text := ' FROM (SELECT DISTINCT id COLLATE "C" AS id FROM unnest($2::text[]) AS u(id)) g CROSS JOIN LATERAL (
          SELECT p.group_id, p.principal FROM rbac_members p
          WHERE p.tenant = $1 AND p.group_id = g.id AND p.principal NOT LIKE ''group:%''
            AND (p.expires_at IS NULL OR p.expires_at > $3) AND ($4 IS NULL OR p.principal = ANY ($4))
          ORDER BY p.principal, p.source) m';
    ids  text[];
    keys text[];
BEGIN
    -- Planning the query costs more than finding no groups.
    IF coalesce(cardinality(groups), 0) = 0 THEN
        RETURN;
    END IF;
    IF standing IS NOT TRUE THEN
        RETURN QUERY EXECUTE 'SELECT m.group_id::text, m.principal::text, NULL::boolean' || places
            USING tenant, groups, at, principals;
        RETURN;
    END IF;
    EXECUTE 'SELECT array_agg(m.group_id), array_agg(m.principal)' || places
        INTO ids, keys USING tenant, groups, at, principals;
    RETURN QUERY EXECUTE 'SELECT u.g, u.p, s.guest FROM unnest($2::text[], $3::text[]) AS u(g, p)
        JOIN (SELECT principal, guest FROM rbac_memberships WHERE tenant = $1 AND principal = ANY ($3::text[])
          AND NOT suspended AND (expires_at IS NULL OR expires_at > $4) OFFSET 0) s ON s.principal = u.p COLLATE "C"'
        USING tenant, ids, keys, at;
END $$;
