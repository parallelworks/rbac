-- The identities in a tenant's groups, in force at a time. A statement expanding groups learns
-- which it reaches only as it runs, so a join to the members is planned for groups of the average
-- size: in a tenant with one large group, finding a small one's members read all of its. Here the
-- query is planned once the groups are known, with their values, for each one's own size. Stable,
-- so it reads the calling statement's snapshot, and by the caller's search_path, so under AsOf it
-- reads the members as of the time.
CREATE FUNCTION rbac_group_members(tenant text, groups text[], at timestamptz)
    RETURNS TABLE (group_id text, principal text) LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN QUERY EXECUTE 'SELECT group_id::text, principal::text FROM rbac_members
        WHERE tenant = $1 AND group_id = ANY ($2) AND principal NOT LIKE ''group:%''
          AND (expires_at IS NULL OR expires_at > $3)' USING tenant, groups, at;
END $$;
