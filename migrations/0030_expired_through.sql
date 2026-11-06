-- DeleteExpired removes what has ended in transactions of its own, places in groups before
-- memberships, passing over a row a change holds, by its own clock. A change reads its clock, and
-- then what its actor acts by in one statement, which DeleteExpired, by a later clock, can commit
-- some of its removals before: the place in a group a deny binds the actor by, which ended later,
-- gone, and the membership or place its power comes through, which ended sooner, still there, a
-- state no moment held, by which the actor acted by the power and escaped the deny. Each run now
-- records the time it deletes by here before it deletes anything, and a read of an actor or a
-- subject decides no earlier than the latest it sees: every row any run it sees removed or passed
-- over has ended by then. A run adds its own row and deletes those no later, passing over one
-- another run is deleting, so runs never wait for each other and the latest stays. No tenant's:
-- a run removes what has ended in every tenant. History doesn't record it, and AsOf doesn't read
-- it: as of a time, a read decides at that time.
CREATE TABLE rbac_expired (
    until timestamptz NOT NULL CHECK (isfinite(until))
);

-- Every check and change reads the latest by it.
CREATE INDEX rbac_expired_until ON rbac_expired (until);
