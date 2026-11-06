-- rbac_group_members runs the statements of a check, a list and a change that reach the members of
-- groups, each of which now plans its reads with sequential scans off, so the members' tables are
-- read by key however small they were when a session planned the calling statement; and a function
-- takes its caller's settings. Its first statement, reading the groups' places, needs them off too:
-- planned by statistics from when rbac_members was nearly empty, which count a group's places as
-- the whole table's, it read every place in the table, 20 pages and 284 beside 20,000 others'. Its
-- second, joining the members to their memberships, needs them on: planned for the members'
-- number, many are read with the tenant's memberships, which with sequential scans off became a
-- lookup each, 20,179 pages of memberships that fill 856 for a group of 20,000. So it sets them off
-- for itself, which PostgreSQL puts back as it returns, reads each group's places on its own, in the
-- primary key's order, which only the index leading to the group gives, so a plan can't read them
-- by an index leading to the tenant alone, and turns them on for the join. Replacing it keeps its
-- owner and who may execute it, and takes no lock on the tables.
CREATE OR REPLACE FUNCTION rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
    RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE plpgsql STABLE PARALLEL RESTRICTED
    SET enable_seqscan = off AS $$
DECLARE
    places CONSTANT text := ' FROM unnest($2::text[]) AS g(id) CROSS JOIN LATERAL (
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
    PERFORM set_config('enable_seqscan', 'on', true);
    RETURN QUERY EXECUTE 'SELECT u.g, u.p, s.guest FROM unnest($2::text[], $3::text[]) AS u(g, p)
        JOIN rbac_memberships s ON s.tenant = $1 AND s.principal = u.p COLLATE "C"
          AND NOT s.suspended AND (s.expires_at IS NULL OR s.expires_at > $4)'
        USING tenant, ids, keys, at;
END $$;
