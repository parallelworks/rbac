-- Role grants: one role to one principal on a resource, a container or the tenant.
CREATE TABLE rbac_grants (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant                text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type            text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id              text        COLLATE "C" NOT NULL,
    -- The host declares its kinds besides user, group, members and public.
    principal_kind        text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'),
    principal_id          text        COLLATE "C" NOT NULL,
    role                  text        COLLATE "C" NOT NULL,
    -- Where it comes from: empty when made directly, `activation` when activated from an
    -- eligibility, or a name the host gives the grants it manages.
    source                text        COLLATE "C" NOT NULL DEFAULT '' CHECK (source ~ '^([a-z][a-z0-9._:/-]{0,62})?$'),
    expires_at            timestamptz,
    -- A grant's condition, in CEL; empty for none.
    condition_title       text        NOT NULL DEFAULT '' CHECK (length(condition_title) <= 128),
    condition_description text        NOT NULL DEFAULT '' CHECK (length(condition_description) <= 2048),
    condition             text        COLLATE "C" NOT NULL DEFAULT '' CHECK (length(condition) <= 2048),
    -- Why a grant was made; an activated grant's justification.
    note                  text        NOT NULL DEFAULT '' CHECK (length(note) <= 2048),
    -- Principals as `kind:id`: who approved an activation that needed it, empty for none; who made
    -- the grant, and who last changed its note.
    approved_by           text        NOT NULL DEFAULT '',
    created_by            text        NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            text        NOT NULL DEFAULT '',
    updated_at            timestamptz NOT NULL DEFAULT now(),
    -- Keys as `type:id`; a type can't contain ':', so they are unambiguous.
    scope                 text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    principal             text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    conditional           boolean     GENERATED ALWAYS AS (condition <> '') STORED,
    -- The public has no id, and a tenant's members have the tenant's.
    CHECK ((principal_kind = 'public') = (principal_id = '')),
    CHECK (principal_kind <> 'members' OR principal_id = tenant),
    -- The tenant's own scope has the tenant's id.
    CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant))
);

-- A grant is one role to one principal on one scope, from one source, until one time, under one
-- condition: granting the same again changes only its note, and a grant that differs in any of
-- these is another beside it, so granting never narrows what a principal holds. The condition
-- counts by its length and hash, as an index entry can't hold a long one. Checks are an
-- index-only scan on this: principals and scopes as arrays, with expiry, and whether a grant has
-- a condition, which a check reads by id only when no unconditional grant allows.
CREATE UNIQUE INDEX rbac_grants_key ON rbac_grants
    (tenant, principal, scope, role, source, coalesce(expires_at, 'infinity'), length(condition), hashtextextended(condition, 0))
    INCLUDE (id, expires_at, conditional);

-- A principal holds one activation of a role on a scope, which activating again extends, so an
-- eligible principal can't add rows without bound.
CREATE UNIQUE INDEX rbac_grants_activation ON rbac_grants (tenant, principal, scope, role) WHERE source = 'activation';

-- Who has access to a scope, and deleting a scope's grants.
CREATE INDEX rbac_grants_scope ON rbac_grants (tenant, scope);

-- What an identity or group holds in every tenant, and deleting it everywhere: its tenants in
-- order, from the index alone.
CREATE INDEX rbac_grants_principal ON rbac_grants (principal, tenant);

-- DeleteExpired, across tenants, without reading the grants that never expire.
CREATE INDEX rbac_grants_expires ON rbac_grants (expires_at) WHERE expires_at IS NOT NULL;

-- Deleting a custom role finds its grants without reading the tenant's every grant; built-in
-- roles are never deleted, so their grants needn't pay for the index.
CREATE INDEX rbac_grants_custom_role ON rbac_grants (tenant, role) WHERE role LIKE 'custom.%';

-- A tenant's own roles, beside the built-in catalog. Grants name them by id like any role.
CREATE TABLE rbac_roles (
    tenant          text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    id              text        COLLATE "C" NOT NULL CHECK (id ~ '^custom\.[a-z0-9._-]{1,121}$'),
    name            text        NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    description     text        NOT NULL DEFAULT '' CHECK (length(description) <= 2048),
    permissions     text[]      COLLATE "C" NOT NULL CHECK (cardinality(permissions) > 0),
    resource_types  text[]      COLLATE "C" NOT NULL CHECK (cardinality(resource_types) > 0),
    privileged      boolean     NOT NULL DEFAULT false,
    public          boolean     NOT NULL DEFAULT false,
    grantable_roles text[]      COLLATE "C" NOT NULL DEFAULT '{}',
    -- The actor's principal as `kind:id`.
    updated_by      text        NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);

-- Deny policies: on a scope and everything under it, they remove permissions from principals,
-- whatever their grants give.
CREATE TABLE rbac_denies (
    tenant                text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type            text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id              text        COLLATE "C" NOT NULL CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    id                    text        COLLATE "C" NOT NULL CHECK (id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
    name                  text        NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    -- Principals as `kind:id`; `public:` is everyone, `members:<tenant>` every member.
    principals            text[]      COLLATE "C" NOT NULL CHECK (cardinality(principals) BETWEEN 1 AND 256),
    exempt                text[]      COLLATE "C" NOT NULL DEFAULT '{}' CHECK (cardinality(exempt) <= 256),
    -- `type:verb`, or `type:*` for every permission on a type.
    permissions           text[]      COLLATE "C" NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 256),
    condition_title       text        NOT NULL DEFAULT '' CHECK (length(condition_title) <= 128),
    condition_description text        NOT NULL DEFAULT '' CHECK (length(condition_description) <= 2048),
    condition             text        NOT NULL DEFAULT '' CHECK (length(condition) <= 4096),
    created_by            text        NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            text        NOT NULL DEFAULT '',
    updated_at            timestamptz NOT NULL DEFAULT now(),
    scope                 text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    PRIMARY KEY (tenant, scope_type, scope_id, id)
);

-- A check reads the denies on a resource's path; a search, those on scopes of some types.
CREATE INDEX rbac_denies_scope ON rbac_denies (tenant, scope);

-- Roles a principal may activate on a scope for a while, rather than hold standing.
CREATE TABLE rbac_eligibilities (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant         text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type     text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id       text        COLLATE "C" NOT NULL CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    -- An identity or a group: the tenant's members and the public activate nothing.
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'
                                                        AND principal_kind NOT IN ('members', 'public')),
    principal_id   text        COLLATE "C" NOT NULL CHECK (principal_id <> ''),
    role           text        COLLATE "C" NOT NULL,
    -- The longest activation, at most a year.
    max_seconds    bigint      NOT NULL CHECK (max_seconds BETWEEN 1 AND 31622400),
    expires_at     timestamptz,
    -- What activating needs, in CEL; empty for nothing more.
    requires       text        NOT NULL DEFAULT '' CHECK (length(requires) <= 2048),
    -- Who approves each activation, identities or groups as `kind:id`; empty for no one.
    approvers      text[]      COLLATE "C" NOT NULL DEFAULT '{}' CHECK (cardinality(approvers) <= 16),
    note           text        NOT NULL DEFAULT '' CHECK (length(note) <= 2048),
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    scope          text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    principal      text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    CONSTRAINT rbac_eligibilities_key UNIQUE (tenant, principal, scope, role)
);

-- Who may activate on a scope, and deleting a scope's eligibilities.
CREATE INDEX rbac_eligibilities_scope ON rbac_eligibilities (tenant, scope);
-- An identity's or group's eligibilities in every tenant, and deleting them everywhere.
CREATE INDEX rbac_eligibilities_principal ON rbac_eligibilities (principal, tenant);
-- DeleteExpired, without reading the eligibilities that never expire.
CREATE INDEX rbac_eligibilities_expires ON rbac_eligibilities (expires_at) WHERE expires_at IS NOT NULL;
-- Deleting a custom role, which locks its tenant, finds its eligibilities without reading the
-- tenant's every one.
CREATE INDEX rbac_eligibilities_custom_role ON rbac_eligibilities (tenant, role) WHERE role LIKE 'custom.%';
