-- +goose Up
CREATE TABLE rbac_grants (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant         text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type     text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id       text        COLLATE "C" NOT NULL,
    -- The host declares its kinds besides user, group, tenant and public.
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'),
    principal_id   text        COLLATE "C" NOT NULL,
    role           text        COLLATE "C" NOT NULL,
    expires_at     timestamptz,
    -- The actor's principal as `kind:id`; empty for a grant Import stored.
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Keys as `type:id`; a type can't contain ':', so they are unambiguous.
    scope          text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    principal      text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    -- The public has no id, and a tenant's members have the tenant's.
    CHECK ((principal_kind = 'public') = (principal_id = '')),
    CHECK (principal_kind <> 'tenant' OR principal_id = tenant),
    -- The tenant's own scope has the tenant's id.
    CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    -- Checks are an index-only scan on this: principals and scopes as arrays, expiry included.
    CONSTRAINT rbac_grants_key UNIQUE (tenant, principal, scope, role) INCLUDE (expires_at)
);

-- Who has access to a scope, and deleting a scope's grants.
CREATE INDEX rbac_grants_scope ON rbac_grants (tenant, scope);

-- What an identity or group holds in every tenant, and deleting it everywhere.
CREATE INDEX rbac_grants_principal ON rbac_grants (principal);

-- DeleteExpired, across tenants, without reading the grants that never expire.
CREATE INDEX rbac_grants_expires ON rbac_grants (expires_at) WHERE expires_at IS NOT NULL;

-- +goose Down
DROP TABLE rbac_grants;
