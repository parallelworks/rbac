-- +goose Up
-- Why a grant was made; an activated grant's justification.
ALTER TABLE rbac_grants ADD COLUMN note text NOT NULL DEFAULT '' CHECK (length(note) <= 2048);

-- Roles a principal may activate on a scope for a while, rather than hold standing.
CREATE TABLE rbac_eligibilities (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant         text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type     text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id       text        COLLATE "C" NOT NULL CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    -- An identity or a group: the tenant's members and the public activate nothing.
    principal_kind text        COLLATE "C" NOT NULL CHECK (principal_kind ~ '^[a-z][a-z0-9_-]{0,62}$'
                                                        AND principal_kind NOT IN ('tenant', 'public')),
    principal_id   text        COLLATE "C" NOT NULL CHECK (principal_id <> ''),
    role           text        COLLATE "C" NOT NULL,
    -- The longest activation, at most a year.
    max_seconds    bigint      NOT NULL CHECK (max_seconds BETWEEN 1 AND 31622400),
    expires_at     timestamptz,
    -- What activating needs, in CEL; empty for nothing more.
    requires       text        NOT NULL DEFAULT '' CHECK (length(requires) <= 2048),
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

-- +goose Down
DROP TABLE rbac_eligibilities;
ALTER TABLE rbac_grants DROP COLUMN note;
