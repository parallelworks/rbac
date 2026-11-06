-- DeleteExpired removes what has ended in transactions of its own, places in groups before
-- memberships, passing over a row a change holds, by its own clock. A change reads its clock, and
-- then what its actor acts by in one statement, which DeleteExpired, by a later clock, can commit
-- some of its removals before: the place in a group a deny binds the actor by, which ended later,
-- gone, and the membership or place its power comes through, which ended sooner, still there, a
-- state no moment held, by which the actor acted by the power and escaped the deny. Each run now
-- records the time it deletes by here before it deletes anything, and a read of an actor or a
-- subject decides no earlier than the latest it sees: every row any run it sees removed or passed
-- over has ended by then. A run adds its own row and deletes those no later, passing over one
-- another run is deleting, so runs never wait for each other and the latest stays. No tenant's:
-- a run removes what has ended in every tenant. History doesn't record it, and AsOf doesn't read
-- it: as of a time, a read decides at that time.
CREATE TABLE rbac_expired (
    until timestamptz NOT NULL CHECK (isfinite(until))
);

-- Every check and change reads the latest by it.
CREATE INDEX rbac_expired_until ON rbac_expired (until);

-- Every check reads it and DeleteExpired writes it, so each role holding SELECT, INSERT, UPDATE or
-- DELETE on rbac_grants, as the README's application role does, is given the same on it: a
-- deployment that gave its roles their privileges on the tables before migrating runs the code
-- after it with no step of its own, where otherwise every check would fail until one. The role
-- migrating owns it. Named by the schema, so no table of the session's own stands in for either.
DO $$
DECLARE
    here     pg_catalog.text := pg_catalog.quote_ident(pg_catalog.current_schema());
    expired  pg_catalog.regclass := (here || '.rbac_expired')::pg_catalog.regclass;
    g        record;
BEGIN
    FOR g IN SELECT DISTINCT a.privilege_type AS privilege,
            CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident(r.rolname) END AS grantee
        FROM pg_catalog.aclexplode((SELECT c.relacl FROM pg_catalog.pg_class c WHERE c.oid = (here || '.rbac_grants')::pg_catalog.regclass)) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = a.grantee
        WHERE a.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
          AND a.grantee <> (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = expired)
        ORDER BY 2, 1 LOOP
        EXECUTE pg_catalog.format('GRANT %s ON %s TO %s', g.privilege, expired, g.grantee);
    END LOOP;
END $$;
