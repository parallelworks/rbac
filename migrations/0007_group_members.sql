-- The identities in a tenant's groups, in force at a time: only those in principals, unless it is
-- null, and with standing, only those whose membership of the tenant is in force and not suspended,
-- with whether each is a guest. A statement expanding groups learns which it reaches only as it
-- runs, so a join to the members is planned for groups of the average size: in a tenant with one
-- large group, finding a small one's members read all of its. Here the query is planned once the
-- groups are known, with their values, for each one's own size, as is the join to the memberships,
-- which the calling statement would plan for the thousand rows it counts a function as. Stable, so
-- it reads the calling statement's snapshot, and by the caller's search_path, so under AsOf it
-- reads the members as of the time; restricted to a parallel plan's leader, which alone can read
-- AsOf's temporary views, so the rest of the calling statement can still run in parallel.
CREATE FUNCTION rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
    RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE plpgsql STABLE PARALLEL RESTRICTED AS $$
BEGIN
    -- Planning the query costs more than finding no groups.
    IF cardinality(groups) > 0 THEN
        RETURN QUERY EXECUTE 'SELECT m.group_id::text, m.principal::text, ' || CASE WHEN standing
            THEN 's.guest FROM rbac_members m JOIN rbac_memberships s ON s.tenant = m.tenant AND s.principal = m.principal
              AND NOT s.suspended AND (s.expires_at IS NULL OR s.expires_at > $3)'
            ELSE 'NULL::boolean FROM rbac_members m' END || '
            WHERE m.tenant = $1 AND m.group_id = ANY ($2) AND m.principal NOT LIKE ''group:%''
              AND (m.expires_at IS NULL OR m.expires_at > $3) AND ($4 IS NULL OR m.principal = ANY ($4))'
            USING tenant, groups, at, principals;
    END IF;
END $$;
