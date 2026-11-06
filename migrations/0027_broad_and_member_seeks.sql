-- Filter, Reachable and Holders read which custom roles the public's and the tenant's members'
-- grants on the scopes they search name, through rbac_grants_custom_principal, but its predicate
-- was rbac_grants_custom_role's, which the search named, so a plan could read them through that
-- index instead, which leads to the tenant alone. By statistics from before the tenant granted
-- custom roles to its users, as autovacuum leaves them until a tenth of rbac_grants is new, or with
-- none, as after a restore, the planner counts the tenant's grants of custom roles as a few, and
-- every plan, generic or for its arguments, read them all, to anyone, once for each broad key and
-- scope or type: 40,000 pages beside 5,000 grants of custom roles to users, and 33 by fresh
-- statistics. This one holds the same grants, as a range of the C collation, in which every custom
-- role's id sorts from `custom.` to just before `custom/`, and a search names that range and no
-- LIKE, which the range doesn't imply: so rbac_grants_custom_role serves no plan of it, whatever
-- the statistics, and the indexes left each lead to the principal or the scope with the tenant, of
-- which this one, holding the fewest of the grants they reach, costs least. A test of the tenant
-- that index can't take as a condition would still leave it a whole scan for its predicate, which
-- such statistics count as cheap too: every tenant's grants of custom roles.
--
-- Dropped before its replacement is built, as 0009 does, so the migration takes the table's
-- strongest lock before any other: built first, the replacement's lock would stop a change that has
-- read grants from writing while the drop waits for that change to end. Reads and writes of
-- rbac_grants wait until the migration commits.
DROP INDEX rbac_grants_custom_principal;
CREATE INDEX rbac_grants_custom_principal ON rbac_grants (principal, tenant, scope) INCLUDE (role)
    WHERE role >= 'custom.' AND role < 'custom/';

-- rbac_group_members joined the members of its groups to their memberships in one statement, but
-- the planner counts a group's members by the tenant's selectivity and the group id's apart, as if
-- neither told anything of the other: where other tenants use a group's id too, as each can name
-- its own admins, a large tenant's group of one is counted as a thousand or more, and the join
-- hashed the memberships, every tenant's: Holders of a role such a group held read 457 pages of
-- them beside 20,000 other members of the tenant, and 15 beside none. Looking each member's up on
-- its own, by its key, read a group of 20,000 in 80,000 pages of memberships that fill 900. So the
-- members are read first, and then joined to their memberships by a statement planned for them,
-- whose number the planner counts exactly in the arrays it is given: a few are looked up by their
-- keys, and many read with the tenant's memberships. Both statements read the calling statement's
-- snapshot, as the function is stable. Replacing it keeps its owner and who may execute it; it has
-- no settings, and takes no lock on the tables.
CREATE OR REPLACE FUNCTION rbac_group_members(tenant text, groups text[], at timestamptz, principals text[], standing boolean)
    RETURNS TABLE (group_id text, principal text, guest boolean) LANGUAGE plpgsql STABLE PARALLEL RESTRICTED AS $$
DECLARE
    ids  text[];
    keys text[];
BEGIN
    -- Planning the query costs more than finding no groups.
    IF coalesce(cardinality(groups), 0) = 0 THEN
        RETURN;
    END IF;
    EXECUTE 'SELECT array_agg(m.group_id), array_agg(m.principal) FROM rbac_members m
        WHERE m.tenant = $1 AND m.group_id = ANY ($2) AND m.principal NOT LIKE ''group:%''
          AND (m.expires_at IS NULL OR m.expires_at > $3) AND ($4 IS NULL OR m.principal = ANY ($4))'
        INTO ids, keys USING tenant, groups, at, principals;
    IF standing IS NOT TRUE THEN
        RETURN QUERY SELECT u.g, u.p, NULL::boolean FROM unnest(ids, keys) AS u(g, p);
        RETURN;
    END IF;
    RETURN QUERY EXECUTE 'SELECT u.g, u.p, s.guest FROM unnest($2::text[], $3::text[]) AS u(g, p)
        JOIN rbac_memberships s ON s.tenant = $1 AND s.principal = u.p COLLATE "C"
          AND NOT s.suspended AND (s.expires_at IS NULL OR s.expires_at > $4)'
        USING tenant, ids, keys, at;
END $$;
