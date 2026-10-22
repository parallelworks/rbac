-- History refused a cursor only where its own record was gone. A prune through one export's cursor
-- deletes records another export, further behind, hasn't read, and keeps that one's last record
-- where no later version supersedes it: that export went on past the records deleted with no
-- error, and its chain vouched for history with them missing. A prune now records the last record
-- it deleted in History's order, and History refuses a cursor before the last a prune recorded after
-- it deleted. A prune's record is never pruned, so with history's ids, this index finds the prunes
-- recorded after a cursor, which are few or none, among all of history; only prunes have entries,
-- so other writes pay nothing for it.
--
-- A prune's record is written in the transaction that deletes, so it follows what that deletes in
-- History's order, and a cursor past it is past them too, only where the transaction took its id
-- after theirs: one that had taken it first, as a host's can, would be recorded before a record it
-- deletes, where a cursor already past the prune's record would never meet it. So a delete from
-- history, which the append-only trigger lets only a role with the rights of history's owner make,
-- is refused as its transaction commits unless the record is of an earlier transaction and a prune
-- that transaction records reaches it: by the last record it deleted, or for a prune recorded
-- before this migration, the cursor it went through. A delete by hand, as by a host's script, then
-- shows to an export from before it, rather than leave a gap no record shows. It is checked at
-- commit, as PruneHistory of a release before this one records its prune in a statement after its
-- delete; or in a transaction that sets constraints immediate, at the end of the statement, which
-- sees what its WITH clauses wrote, as PruneHistory's statement records its prune.
--
-- History is locked first, in the strongest mode the migration takes, so a lock it holds is never
-- raised while a change waits behind it. Every change waits until migrating commits, as each writes
-- history, and building the index reads all of history; reads of history go on.
LOCK TABLE rbac_history IN SHARE ROW EXCLUSIVE MODE;

CREATE INDEX rbac_history_prunes ON rbac_history (txid, id) WHERE entity = 'history';

-- It runs as whoever deletes, a role with the rights of history's owner, and reads only this
-- schema, and pg_temp last, so a session's own table named as history's stands in for none of it.
CREATE FUNCTION rbac_history_pruned() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.txid < pg_catalog.pg_current_xact_id() AND EXISTS (SELECT FROM rbac_history p
        WHERE p.entity = 'history' AND p.txid = pg_catalog.pg_current_xact_id() AND p.op = 'prune'
          AND (OLD.txid, OLD.id) <= ((coalesce(p.after->'last', p.after->'through')->>'txid')::pg_catalog.xid8,
                                     (coalesce(p.after->'last', p.after->'through')->>'id')::bigint)) THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'rbac_history record % is deleted by no prune its transaction records: prune history with PruneHistory', OLD.id
        USING ERRCODE = 'insufficient_privilege';
END $$;
DO $$ BEGIN
    EXECUTE format('ALTER FUNCTION rbac_history_pruned() SET search_path = %I, pg_temp', current_schema());
END $$;
-- Only its trigger calls it.
REVOKE EXECUTE ON FUNCTION rbac_history_pruned() FROM PUBLIC;

CREATE CONSTRAINT TRIGGER rbac_history_pruned AFTER DELETE ON rbac_history
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rbac_history_pruned();
-- In every session, as history's other triggers fire.
ALTER TABLE rbac_history ENABLE ALWAYS TRIGGER rbac_history_pruned;
