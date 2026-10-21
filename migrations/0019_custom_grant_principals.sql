-- Filter, Reachable and Holders read which custom roles the public's and the tenant's members'
-- grants on the scopes they search name. rbac_grants_principal finds those grants with every other
-- grant of theirs there, of built-in roles too, which the tenant's members can hold on thousands of
-- resources; and rbac_grants_custom_role leads to the tenant alone, which a generic plan costs as an
-- average tenant's few grants, so it read every grant of a custom role in the tenant. This one
-- holds only grants of custom roles and leads to a principal, a tenant and a scope, so a search
-- seeks just those of the principal on a scope or a range of a type's, from the index alone, and no
-- plan finds them cheaper through the tenant. Building it keeps writes to rbac_grants waiting until
-- the migration commits, though reads go on.
CREATE INDEX rbac_grants_custom_principal ON rbac_grants (principal, tenant, scope) INCLUDE (role) WHERE role LIKE 'custom.%';
