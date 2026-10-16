-- +goose Up
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

-- Deleting a custom role finds its grants without reading the tenant's every grant; built-in
-- roles are never deleted, so their grants needn't pay for the index.
CREATE INDEX rbac_grants_custom_role ON rbac_grants (tenant, role) WHERE role LIKE 'custom.%';

-- +goose Down
DROP INDEX rbac_grants_custom_role;
DROP TABLE rbac_roles;
