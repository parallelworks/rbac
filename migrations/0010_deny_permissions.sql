-- A deny lists `type:verb` or `type:*`, and never a `:deny` permission, which no deny removes:
-- checks read no deny for one, so a row written around the package listing one, or text that is no
-- permission, would bind no one or, matched as it was, remove the power to lift it. Each element is
-- checked on its own: NULL reads as empty, which no permission is. The package never stored such a
-- row, so none is rewritten.
ALTER TABLE rbac_denies ADD CONSTRAINT rbac_denies_permissions_deniable CHECK (
    pg_catalog.array_to_string(permissions, ',', '')
        ~ '^[a-z][a-z0-9_-]{0,62}:([a-z][a-z0-9_-]{0,62}|\*)(,[a-z][a-z0-9_-]{0,62}:([a-z][a-z0-9_-]{0,62}|\*))*$'
    AND ',' || pg_catalog.array_to_string(permissions, ',', '') || ',' NOT LIKE '%:deny,%');
