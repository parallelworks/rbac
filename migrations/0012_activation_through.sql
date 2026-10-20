-- An activation rests on its holder reaching the principal of the eligibility it was made through:
-- the holder's own identity, while it is a member or guest of the tenant, or a group it is in.
-- Activate records that principal's key and the eligibility's id, and a change ending a membership
-- or a place in a group sooner, or removing it, cuts an activation resting on it short to the latest
-- end of the paths left to that principal, or ends it. Worked out again from every eligibility the
-- holder reaches, as before, one whose requirement or approval it never met would count as allowing
-- the activation, and another's MaxDuration would cut short one made through this one. Null on other
-- grants. Deleting the eligibility leaves both, as it leaves its activations to their own ends. A
-- column added with no default rewrites no row.
ALTER TABLE rbac_grants ADD COLUMN activated_through text COLLATE "C", ADD COLUMN eligibility_id bigint;

-- An activation in force is recorded as made through the one eligibility for its role on its scope,
-- of those stored, whose principal its holder reaches now, by its membership in force, suspended
-- too, and the places in groups in force from it, as a change reads the paths an activation rests
-- on. Where it reaches the principals of several, which made it can't be told; where it reaches
-- none, as once the eligibility it was made through is deleted, nothing says what it rested on.
-- Those record neither, as do those that code from before this migration activates while a host
-- upgrades, and the first change that ends or removes a membership or place of their holder's ends
-- them, rather than leave one through a path it may not have rested on: activating again records
-- the eligibility. The package has had no release, so only a developer's database holds any, and
-- none lasts past a year.
SELECT set_config('rbac.change', '{"how": "Migrate"}', true);
WITH RECURSIVE activations AS (
    SELECT id, tenant, principal, scope, role FROM rbac_grants WHERE source = 'activation' AND expires_at > now()
), reaching(tenant, holder, k) AS (
    SELECT a.tenant, a.principal, a.principal FROM activations a
    JOIN rbac_memberships s ON s.tenant = a.tenant AND s.principal = a.principal AND (s.expires_at IS NULL OR s.expires_at > now())
    UNION
    SELECT r.tenant, r.holder, ('group:' || m.group_id) COLLATE "C" FROM reaching r
    JOIN rbac_members m ON m.tenant = r.tenant AND m.principal = r.k AND (m.expires_at IS NULL OR m.expires_at > now())
), made AS (
    SELECT a.id, min(e.principal) AS through, min(e.id) AS eligibility FROM activations a
    JOIN reaching r ON r.tenant = a.tenant AND r.holder = a.principal
    JOIN rbac_eligibilities e ON e.tenant = a.tenant AND e.scope = a.scope AND e.role = a.role AND e.principal = r.k
    GROUP BY a.id HAVING count(*) = 1
)
UPDATE rbac_grants g SET activated_through = m.through, eligibility_id = m.eligibility FROM made m WHERE g.id = m.id;
SELECT set_config('rbac.change', '', true);
