-- +goose Up
-- A grant's condition, in CEL; empty for none.
ALTER TABLE rbac_grants
    ADD COLUMN condition_title       text    NOT NULL DEFAULT '' CHECK (length(condition_title) <= 128),
    ADD COLUMN condition_description text    NOT NULL DEFAULT '' CHECK (length(condition_description) <= 2048),
    ADD COLUMN condition             text    NOT NULL DEFAULT '' CHECK (length(condition) <= 2048),
    ADD COLUMN conditional           boolean GENERATED ALWAYS AS (condition <> '') STORED;

-- Checks stay an index-only scan: the key says whether a grant has a condition, and a check
-- reads the condition only when no unconditional grant allows.
ALTER TABLE rbac_grants DROP CONSTRAINT rbac_grants_key,
    ADD CONSTRAINT rbac_grants_key UNIQUE (tenant, principal, scope, role) INCLUDE (expires_at, conditional);

-- +goose Down
-- Without its condition a conditional grant would give its role everywhere.
DELETE FROM rbac_grants WHERE conditional;
ALTER TABLE rbac_grants DROP CONSTRAINT rbac_grants_key,
    ADD CONSTRAINT rbac_grants_key UNIQUE (tenant, principal, scope, role) INCLUDE (expires_at);
ALTER TABLE rbac_grants DROP COLUMN conditional, DROP COLUMN condition, DROP COLUMN condition_description,
    DROP COLUMN condition_title;
