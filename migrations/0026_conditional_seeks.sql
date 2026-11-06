-- A conditional grant to a group, the tenant's members or the public is bounded with the conditions
-- of the conditional grants to them on its scope, and an identity's with those of its own there,
-- which a change reads under the scope's lock before it writes and again after. The scope's index
-- holds whether each grant is conditional, but not its condition or source, so every grant to a
-- group on the scope was read from the table to find the conditional ones: with 80,000
-- unconditional grants to groups on a tenant, a conditional grant to one more took 39 ms, against
-- 7 ms unconditional. This index holds conditional grants alone, by scope, tenant and principal, so
-- the read finds those of a scope by key, whatever else is granted there.
--
-- A group's eligibility with a requirement is bounded with the requirements of the groups'
-- eligibilities for its role on its scope, which the scope's index found among every eligibility
-- there, of any role, each read from the table. This one holds the eligibilities with a requirement
-- alone, by scope, role, tenant and principal: an order no other index of them begins with, so the
-- read seeks it by a row comparison of those columns that no other index can seek, whatever the
-- statistics count.
--
-- The eligibilities' is built first, as changes that write both tables write eligibilities first,
-- as deleting a scope does. Building each keeps writes to its table waiting until the migration
-- commits, though reads go on.
CREATE INDEX rbac_eligibilities_requires ON rbac_eligibilities (scope, role, tenant, principal) WHERE requires <> '';

CREATE INDEX rbac_grants_conditional ON rbac_grants (scope, tenant, principal) WHERE conditional;
