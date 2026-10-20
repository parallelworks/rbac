-- A change adding places in groups counts, under its locks, the groups each principal it adds is
-- in, those from each source the host owns apart (MaxGroupsOfPrincipal). The index on the
-- principal held each place's group and end but not its source, so the count read every place's
-- row of the table, one page for each. With the source too, it reads the index alone, as checks do.
--
-- Built beside the index it replaces, which serves checks until then: writes to the table wait while
-- it is built, and every read only for the swap, until the migration commits.
CREATE INDEX rbac_members_principal_sources ON rbac_members (tenant, principal) INCLUDE (group_id, expires_at, source);
DROP INDEX rbac_members_principal;
ALTER INDEX rbac_members_principal_sources RENAME TO rbac_members_principal;
