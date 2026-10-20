-- A change adding places in groups counts, under its locks, the groups each principal it adds is
-- in, those from each source the host owns apart (MaxGroupsOfPrincipal). The index on the
-- principal held each place's group and end but not its source, so the count read every place's
-- row of the table, one page for each. With the source too, it reads the index alone, as checks do.
--
-- Dropped before its replacement is built, as 0009 does, so the migration takes the table's
-- strongest lock before any other: built first, the replacement's lock would stop a change that has
-- read places from writing while the drop waits for that change to end, a deadlock that fails the
-- migration or the change. Reads and writes of the table wait until the migration commits.
DROP INDEX rbac_members_principal;
CREATE INDEX rbac_members_principal ON rbac_members (tenant, principal) INCLUDE (group_id, expires_at, source);
