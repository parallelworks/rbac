-- A change to a group's members, and DeleteGroup, ask which types of scope a deny binding the actor
-- removes the power to change grants on, as `<type>:grant` or `<type>:*`, wherever in the tenant it
-- is: only on a scope of one can a deny on its path stop the change taking access away there, and
-- only for such a scope is the host asked about it. Found through rbac_denies_principals, the read
-- took every deny naming a key the actor is bound by, the tenant's members and the public too,
-- whatever it removed, so a change beside thousands of denies of root to the members, each on a
-- resource of its own, read them all, before its transaction and again under its locks. This index
-- holds, by the keys they name as rbac_denies_principals holds them, only the denies that remove a
-- power to change grants, so the read finds those alone.
--
-- rbac_changes_grants reports whether a deny's permissions hold such a power. A permission is
-- `type:verb` or `type:*`, as rbac_denies_permissions_deniable checks, so its verb is what follows
-- its colon. Its body, as rbac_tenant_keys', is parsed now and names pg_catalog's functions and
-- operators, so neither a later overload nor a search_path changes what it gives, which the index
-- rests on. Every role writing denies calls it, as it calls rbac_tenant_keys, which every role may
-- unless it is revoked. Writes to the denies wait while the index is built, until the migration
-- commits, though reads go on.
CREATE FUNCTION rbac_changes_grants(permissions text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN EXISTS (SELECT FROM pg_catalog.unnest(permissions) AS p
        WHERE pg_catalog.split_part(p, ':', 2) OPERATOR(pg_catalog.=) ANY ('{grant,*}'::pg_catalog.text[]));

CREATE INDEX rbac_denies_grants ON rbac_denies USING gin (rbac_tenant_keys(tenant, principals)) WITH (fastupdate = off)
    WHERE rbac_changes_grants(permissions);
