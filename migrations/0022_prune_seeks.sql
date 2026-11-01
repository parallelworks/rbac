-- History found the prunes that can have deleted records after a cursor by where each is recorded,
-- through rbac_history_prunes: those after the cursor, or for a cursor behind its export's Horizon,
-- from the Horizon on. A prune is recorded after what it deletes, but a prune through the cursor of
-- the export furthest behind deletes only what that export has read, and is recorded after it all
-- the same: so while an export fell behind, or caught up from the start, each of its reads, twice,
-- and each window of a prune through its cursor, read every prune recorded since, each from
-- history's rows, though none of them had deleted anything it hadn't read. This index holds each
-- prune by the last record it deleted, or for one recorded before 0020, the cursor it went through,
-- and then its transaction, so History finds the prunes that reached past a cursor, which for an
-- export that has read past its Horizon are only those that refuse it, and tests their transactions
-- among the index's own entries. Only prunes have entries, so other writes pay nothing for it.
--
-- Building it reads all of history, and keeps every change waiting until migrating commits, as each
-- writes history; reads of history go on. It fails on a prune's record whose last record or cursor
-- holds a txid or id that isn't one, which only history's owner could have written, by hand; once
-- it is built, history refuses such a record as it is written.
CREATE INDEX rbac_history_prune_lasts ON rbac_history (
    ((coalesce(after->'last', after->'through')->>'txid')::pg_catalog.xid8),
    ((coalesce(after->'last', after->'through')->>'id')::bigint),
    txid) WHERE entity = 'history' AND op = 'prune';
