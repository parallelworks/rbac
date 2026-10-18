-- An identity's membership of a tenant: as a member, or as a guest, who holds what it is granted
-- there and nothing granted to the tenant's members; a suspended one holds nothing until it is
-- lifted.
CREATE TABLE rbac_memberships (
    tenant         text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    -- An identity: a user or a kind the host declares, never a group, the members or the public.
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'
                                                        AND principal_kind NOT IN ('group', 'members', 'public')),
    principal_id   text        COLLATE "C" NOT NULL CHECK (principal_id <> ''),
    guest          boolean     NOT NULL DEFAULT false,
    suspended      boolean     NOT NULL DEFAULT false,
    source         text        COLLATE "C" NOT NULL DEFAULT '' CHECK (source ~ '^([a-z][a-z0-9._:/-]{0,62})?$'),
    expires_at     timestamptz,
    note           text        NOT NULL DEFAULT '' CHECK (length(note) <= 2048),
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     text        NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now(),
    principal      text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    PRIMARY KEY (tenant, principal)
);

-- An identity's tenants, and removing it from every one.
CREATE INDEX rbac_memberships_principal ON rbac_memberships (principal, tenant);
-- DeleteExpired, without reading the memberships that never expire.
CREATE INDEX rbac_memberships_expires ON rbac_memberships (expires_at) WHERE expires_at IS NOT NULL;

-- A tenant's groups of identities and other groups; `group:<id>` names one only in its tenant.
CREATE TABLE rbac_groups (
    tenant      text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    id          text        COLLATE "C" NOT NULL CHECK (id <> '' AND length(id) <= 128),
    name        text        NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    description text        NOT NULL DEFAULT '' CHECK (length(description) <= 2048),
    -- Empty when made directly, or the host's, such as a directory it syncs from.
    source      text        COLLATE "C" NOT NULL DEFAULT '' CHECK (source ~ '^([a-z][a-z0-9._:/-]{0,62})?$'),
    -- Set when it is created, and never after: only a privileged group holds a privileged role,
    -- and only identities are its members.
    privileged  boolean     NOT NULL DEFAULT false,
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);

-- Who is in a group, from a source: an identity, or another of the tenant's groups.
CREATE TABLE rbac_members (
    tenant         text        COLLATE "C" NOT NULL,
    group_id       text        COLLATE "C" NOT NULL,
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'
                                                        AND principal_kind NOT IN ('members', 'public')),
    principal_id   text        COLLATE "C" NOT NULL CHECK (principal_id <> ''),
    source         text        COLLATE "C" NOT NULL DEFAULT '' CHECK (source ~ '^([a-z][a-z0-9._:/-]{0,62})?$'),
    expires_at     timestamptz,
    note           text        NOT NULL DEFAULT '' CHECK (length(note) <= 2048),
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     text        NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now(),
    principal      text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    PRIMARY KEY (tenant, group_id, principal, source),
    FOREIGN KEY (tenant, group_id) REFERENCES rbac_groups (tenant, id) ON DELETE CASCADE,
    CHECK (principal_kind <> 'group' OR principal_id <> group_id)
);

-- A check resolves an identity's groups, and the groups they are in, from this alone.
CREATE INDEX rbac_members_principal ON rbac_members (tenant, principal) INCLUDE (group_id, expires_at);
-- An identity's or group's tenants, and removing it from every one, without reading every tenant's.
CREATE INDEX rbac_members_tenants ON rbac_members (principal, tenant);
-- DeleteExpired, without reading the memberships that never expire.
CREATE INDEX rbac_members_expires ON rbac_members (expires_at) WHERE expires_at IS NOT NULL;
