-- +goose Up
CREATE TABLE rbac_grants (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant         text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type     text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]*$'),
    scope_id       text        COLLATE "C" NOT NULL,
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind IN ('user', 'group', 'everyone')),
    principal_id   text        COLLATE "C" NOT NULL,
    role           text        COLLATE "C" NOT NULL,
    expires_at     timestamptz,
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Keys as `type:id`; a type can't contain ':', so they are unambiguous.
    scope          text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    principal      text        COLLATE "C" GENERATED ALWAYS AS (principal_kind || ':' || principal_id) STORED,
    CHECK ((principal_kind = 'everyone') = (principal_id = '')),
    -- The tenant's own scope has the tenant's id.
    CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    -- Checks are an index-only scan on this: principals and scopes as arrays, expiry included.
    CONSTRAINT rbac_grants_key UNIQUE (tenant, principal, scope, role) INCLUDE (expires_at)
);

-- Who has access to a scope, and deleting a scope's grants.
CREATE INDEX rbac_grants_scope ON rbac_grants (tenant, scope);

-- DeleteExpired, across tenants, without reading the grants that never expire.
CREATE INDEX rbac_grants_expires ON rbac_grants (expires_at) WHERE expires_at IS NOT NULL;

-- +goose Down
DROP TABLE rbac_grants;
