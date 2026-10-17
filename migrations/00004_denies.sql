-- +goose Up
-- Deny policies: on a scope and everything under it, they remove permissions from principals,
-- whatever their grants give.
CREATE TABLE rbac_denies (
    tenant      text        COLLATE "C" NOT NULL CHECK (tenant <> ''),
    scope_type  text        COLLATE "C" NOT NULL CHECK (scope_type ~ '^[a-z][a-z0-9_-]{0,62}$'),
    scope_id    text        COLLATE "C" NOT NULL CHECK (scope_id <> '' AND (scope_type <> 'tenant' OR scope_id = tenant)),
    id          text        COLLATE "C" NOT NULL CHECK (id ~ '^[a-z0-9][a-z0-9._-]{0,127}$'),
    name        text        NOT NULL DEFAULT '' CHECK (length(name) <= 128),
    -- Principals as `kind:id`; `public:` is everyone, `tenant:<id>` every member.
    principals  text[]      COLLATE "C" NOT NULL CHECK (cardinality(principals) BETWEEN 1 AND 256),
    exempt      text[]      COLLATE "C" NOT NULL DEFAULT '{}' CHECK (cardinality(exempt) <= 256),
    -- `type:verb`, or `type:*` for every permission on a type.
    permissions text[]      COLLATE "C" NOT NULL CHECK (cardinality(permissions) BETWEEN 1 AND 256),
    condition_title       text NOT NULL DEFAULT '' CHECK (length(condition_title) <= 128),
    condition_description text NOT NULL DEFAULT '' CHECK (length(condition_description) <= 2048),
    condition   text        NOT NULL DEFAULT '' CHECK (length(condition) <= 4096),
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text        NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    scope       text        COLLATE "C" GENERATED ALWAYS AS (scope_type || ':' || scope_id) STORED,
    PRIMARY KEY (tenant, scope_type, scope_id, id)
);

-- A check reads the denies on a resource's path; a search, those on scopes of some types.
CREATE INDEX rbac_denies_scope ON rbac_denies (tenant, scope);

-- +goose Down
DROP TABLE rbac_denies;
