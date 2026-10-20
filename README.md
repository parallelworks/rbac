# rbac

Role-based access control on PostgreSQL, as a Go library: roles granted on resources, the
containers above them or a whole tenant, with custom roles, conditions, deny policies and
just-in-time access, in the shape of cloud IAM.

```sh
go get github.com/parallelworks/rbac
```

It needs Go 1.26 or later and is tested on PostgreSQL 18. It runs in FIPS 140-3 mode: it uses no
cryptography outside the Go standard library.

[Architecture](docs/architecture.md) maps how it works, with diagrams of its data, checks, changes,
lists and history.

## The model

A role is a set of `type:verb` permissions, such as `cluster:login`, built into the application's
catalog or defined by a tenant. A grant gives one role to a principal on a scope, and applies to
everything under it: a resource, a container above resources (any depth, any names), or the
tenant. A principal is a user, another kind of identity the application declares (a service
account), a group, every member of the tenant, or the public, signed in or not.

The application keeps identities, resources and their hierarchy, and passes them in: a `Subject`
is the identity asking, and a `Resource` carries its ancestors. The package keeps the grants and
its own policies, and which identities are members or guests of each tenant and in each of its
groups, so a check, a list and an access review all read membership from one place, and
nothing it holds goes stale when a resource moves.

```go
authz, err := rbac.New(pool, rbac.Config{
	Catalog:        roles, // []rbac.RoleDefinition, built into the application
	ContainerTypes: []string{"org", "workspace"},
	PrincipalKinds: []rbac.PrincipalKind{"service_account"},
	ValidateGrant:  policy.MayGrant, // required: who may hold what in a tenant
	OnChange:       audit.Record,    // runs in the change's transaction
})

subject := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: userID}}
cluster := rbac.Resource{Tenant: tenant, Type: "cluster", ID: id,
	Ancestors: []rbac.Scope{{Type: "workspace", ID: ws}, {Type: "org", ID: org}}}
if err := authz.Authorize(ctx, subject, "cluster:login", cluster); err != nil {
	return err // matches rbac.ErrDenied; any error means no
}
```

## Grants

- **One grant, or several:** a grant is one role to one principal on one scope, from one source,
  until one time, under one condition. Granting the same again changes only its note and its
  condition's title and description; one that differs in any of these stands beside the others,
  so granting never narrows what a principal holds. Each has an `ID`, who made it and when, and
  who last changed it.
- **Changes:** `Apply` grants and revokes on one scope in one transaction. A revoke removes a
  role's grants to a principal from a source, or with an `ID`, still naming the role, one grant;
  revoking and granting a role at once replaces its grants, keeping those granted again as they
  are.
- **Sources:** a host that manages some grants itself, such as those it syncs from a directory,
  grants them from a `Source` of its own and revokes only those. Listed in `Config.Sources`, only
  the host changes them: `Apply` refuses to grant or revoke from one, and the host writes them with
  `Import` and removes them with `DeleteGrants`.
- **Who may:** the actor needs `<type>:grant` on the scope. Through a role with `GrantableRoles` it
  may grant and revoke only those roles, without holding them; through any other, it may grant a
  role whose every permission it holds, for every type the grant reaches, and revoke any. A
  role's power to change grants counts as part of what it gives, so a limited grant permission
  can't mint an unlimited one. `Grantable` lists the roles a subject may grant, unconditionally and
  for good, for an access screen.
- **Until when:** what the actor hands on it holds until the grant ends. What it holds only through
  grants that end, such as an activation, or through a membership or a place in a group that ends,
  it grants ending no later than the last of them, and never as an eligibility, a custom role's
  definition or a place in a group that outlasts it, so access approved for an hour stays an
  hour's. A grant outlives the actor's power to change grants, though: a power held for an hour
  grants for good what the actor holds for good, and the roles a role it holds lists, which it
  needn't hold. Put expiries on roles that list none.
- **Creators:** nothing is owned. The host gives whoever creates a resource a role on it with
  `Import`, as an actor it names, in the same transaction through `WithTx`.

## Lists

Store each resource's `authz.Path(resource)`, its own key first and then its containers' and the
tenant's, in a `text[]` column with a GIN index. `Filter` returns a condition for the host's own
query, which reads the grants in the same statement as the rows, so sorting and pagination work and
nothing changes between deciding and reading. A condition holds for the query it was built for: it
fixes the time, the subject's label holding and what the constraints answered, so build one for each
query. It compares the tenant and keys byte for byte, as `Authorize` does, whatever the columns'
collation, in which their indexes still serve. The subject's grants are matched through the path's
index, whose cost for each row it finds grows with their number. Past a few on resources of the
listed type, or past 128 on containers and the tenant, as one holding a grant on everything it
created does, each of a row's keys is looked up among them instead, so a row costs a few lookups
however many it holds; no index serves that, so the query then reads every row of the tenant its
other conditions keep. Denies, on resources and containers alike, are looked up so whatever their
number, and of those naming the subject or its groups only theirs are read; denies naming the
public or the tenant's members are read by type while the listed types hold few denies, and
otherwise every one in the tenant is. `Reachable` returns the same as scopes, for resources kept in
another store. Both search one tenant, and count only unconditional grants: `Reach.Conditional`
names the scopes conditional ones reach, to check one by one.

## Policies

- **Custom roles:** a tenant defines its own with `SetRole`, ids starting `custom.`, from the
  permissions and types the built-in roles use. Defining one needs `rbac.DefineRoles` on the tenant
  and everything the role gives across it. Redefining one so that its grants give more asks
  `ValidateGrant` about each grant and eligibility it widens, as the role will be, and the host
  refusing one refuses the redefinition, as is one giving more label values where a condition of its
  grants on the tenant reading the action would then cost a check more than it may spend; an actor a
  label of a scope its grants are on, as `Config.ResourceOf` gives it, refuses can neither redefine
  nor delete it. `DeleteRole` removes one with its grants; `Roles` lists the built-in and custom
  roles a scope type takes. Custom roles follow the catalog: one gives only what the catalog still
  has, and is privileged when it gives what only privileged roles do, or changes access.
- **Labels on data:** a mandatory layer above every grant. A host declares label dimensions
  (`Config.Labels`), each `Ordered` (a level), `AllOf` (compartments) or `AnyOf` (releasable to
  these partners), and a resource carries its label (`Resource.Labels`), stored with it as its path
  is. A subject holds a dimension's values as permissions, `dimension:value`, which roles for the
  tenant give, so groups, eligibilities, expiry, conditions, denies on the tenant and history all
  apply to them. Every check decides them, and the powers to release, on the tenant with no
  attributes or label, whatever tenant it is passed, as a check of a labeled resource reads them: a
  condition of theirs reads the tenant's type and id alone, so one reading `resource.attributes`
  gives nothing and a deny's applies, and a constraint is asked about that bare tenant, so one
  deciding them by the tenant's state reads it through its `q`. `Authorize`, `Explain`,
  `Permissions`, `Holders` and `Grantable` allow nothing of a labeled resource unless what the
  subject holds satisfies the label, whatever its grants give, nor do `Apply`, `SetEligibility` and
  `DeleteEligibility` change its grants, nor `SetDeny` and `DeleteDeny` its denies, nor `SetRole`
  and `DeleteRole` the grants of a role on it, nor `ChangeMembers` the members of a labeled group,
  or of one holding access or exempt from a deny on a labeled scope, nor `SetGroup` and
  `DeleteGroup` a labeled group or the groups of a labeled tenant, each reading the actor's values
  again under the change's locks; `Explain` names the dimension that failed. `Filter` tests a
  `text[]` label column (`Columns.Labels`), which needs no index, as the path's drives the query;
  `Reachable` returns the holding, and `Holding` with `Satisfies` checks data points in a feed
  without reading the database.
- **Writing labeled data:** data read under one label is written under another only if
  `Holding.MayWrite` allows it: the writer satisfies the label it read, and the new one is at
  least as restrictive in every dimension (a level as high, every compartment kept, partners
  narrowed or kept), so data never moves to a looser label by being copied. Data from several
  sources takes a label `MayWrite` allows from each, and where their partners share none, only a
  release writes it. Loosening a label is a release:
  `Holding.MayRelease` allows it in the dimensions whose power to release the subject holds
  (`ReleasePermission(dimension)` on the tenant), for data it can read. A role giving it is
  `Privileged`, so the tenant's members never hold it, and no value is named `release`.
- **Exclusive values:** a dimension marked `Exclusive` names parties with a conflict of interest,
  whose values are held one at a time. A change that leaves an identity able to hold two, through
  any grant or eligibility on the tenant and under any condition, directly, through its groups, as
  one of the tenant's members or the public, or by its own grants before it joins, is refused with
  `ErrInvalid`; denies don't count, and removing a grant, an eligibility, a membership or a place in
  a group, or suspending a membership, is never refused. Where a dimension is exclusive, a tenant's
  changes run in turn, so two can't each give one value. The check reads every identity a change
  reaches, so a grant to the tenant's members or the public reads every member. A subject whose
  grants could give it two anyway, as after a catalog change, holds none of them, whatever the
  request, a constraint or a deny removes: checks and searches of its labels and of the values
  themselves refuse it, and it can't hand them on. A change reaching it is refused until a removal
  leaves it one; `Conflicts` lists them. A role giving two of them is refused. An `Ordered`
  dimension's higher values include the lower, so it isn't exclusive, and in an `AllOf` one a label
  naming two is one no one can read, as data that joins two parties is.
- **Conditions:** a grant can carry a CEL expression over the subject's, the resource's and the
  request's attributes (`Subject.Attributes`, `Resource.Attributes`, `rbac.WithRequest`), the time
  and the action. It gives its role only where the expression holds; one that fails is false.
  `Config.Attributes` declares the attributes and their types, so a condition reading one
  misnamed, or as another type, is refused when stored, and one stored under other declarations
  fails where it no longer passes them. Each condition runs within the most evaluating it can
  cost, which its literals and types bound: little for comparing what a request passes with
  literals, and all a condition may for reading the size of, or looping over, a list the request
  passes. Cost is bounded per check too, for each scope on its path, and the conditions a check
  reads together are bounded where they are stored: an identity's grants' on a scope, those of a
  scope's grants to groups, the tenant's members and the public, each the tenant's and those from
  each source the host owns apart, a scope's denies', and the requirements of groups'
  eligibilities for a role on a scope. Each holds hundreds of comparisons with literals, or three
  of the longest conditions that read a list or loop, and a change adding a condition past one is
  refused as invalid. So a check evaluates every condition it reads, and a grant made beside
  another, as by someone who can't revoke it, never changes what that one decides. A change adding
  no condition isn't refused, so what was stored past a bound before there were bounds can be
  rewritten in place, as by a restore over the rows still stored, though not restored where they
  are gone, and a check may not reach all of it: it evaluates the cheapest first within its budget. To hand a permission on, the actor holds it unconditionally or
  under the same condition, one that doesn't read the subject: that one decides for each holder,
  so the actor's holding says nothing of another's.
- **Deny policies:** `SetDeny` puts a deny on a scope: under it, it removes permissions
  (`type:verb`, or `type:*` for a type's every one) from the principals it names, those it exempts
  aside, whatever their grants give. It names and exempts principals a grant could name, so not
  one of a kind the host doesn't declare. It exempts identities and groups, or from a deny naming
  the public the tenant's members, to bind only those who aren't; never the public, which would
  exempt everyone, nor one it names. A conditional one denies where its condition holds or can't
  be evaluated. Setting one needs `rbac.DenyPermission(type)` there, which no deny removes, so
  whoever holds it on a scope above can always lift a deny set below. `Filter`, `Reachable` and
  `Holders` honor denies.
- **Just-in-time access:** `SetEligibility` lets a principal, an identity or a group's members,
  activate a role on a scope for up to a maximum duration and no later than the eligibility, the
  activator's membership of the tenant, or its place in the group that makes it eligible ends,
  perhaps only where a condition holds, such as a second factor, and perhaps only once one of its
  `Approvers` approves. Setting one needs what granting the role for good does, so no activation
  can make its holder eligible on looser terms. `Activate` gives the activator a grant of its own from
  `rbac.SourceActivation`, beside any it holds, with its justification and approver. It holds
  one activation of a role on a scope, recording the request its end rests on: activating again
  until later replaces it, one ending no later changes nothing, and once it has ended, activating
  again makes a new grant. `Deactivate` ends it early. An activation records the eligibility it
  was made through, of those that allow it the one whose path from the activator lasts longest,
  by its own membership or its places in groups, and its own of those lasting alike and needing
  approval alike, and rests on its holder being that one's principal or in its group: a change
  that ends the membership or a place on the way sooner, or removes it, as by leaving the group,
  cuts the activation short to the latest end of the paths left, or ends it if none is left
  (`ChangeEvent.Shortened` and `Revoked`), whatever another eligibility would allow. Setting the
  eligibility again or deleting it bounds only the activations made from then on, and leaves
  those made to their ends, or to their holders leaving its group.
- **Host policy:** `Config.ValidateGrant` is asked about every grant with the role, the principal,
  the actor and how it is made, so the host decides who may hold what: members only, no
  privileged roles for service accounts or guests. `Config.Constraints` remove permissions above
  anything a tenant grants or denies, seeing copies of the subject and the resource, such as
  freezing changes under a container. What one removes from an actor the actor can't hand on, but for a
  role a role it holds lists in `GrantableRoles`, which it grants without holding. The host is
  asked before a change takes its locks, so a change is tried again (`rbac.ErrConflict`) when the
  memberships its answers rest on, of an identity it grants to or of a group's members, changed
  in between, or a group a change to members reaches was nested in another. A change to a group
  member's own membership takes that member's lock alone, so one committing after the change reads
  them again isn't seen: a host whose policy rests on a group's members checks the group's grants
  when it changes a membership, as `SetMemberships` says.

## Principals

- **Members and guests:** an identity holds what it is granted in a tenant only while it is a
  member or guest of it (`SetMemberships`), and nothing while its membership is suspended. A guest,
  such as one from another tenant, holds what it is granted there and nothing granted to the
  tenant's members. Leaving a tenant (`DeletePrincipal`) removes what the identity held there,
  its exemptions from denies and its place among approvers too; `DeletePrincipalEverywhere` removes
  a deleted identity from every tenant.
- **Groups:** a group is its tenant's (`SetGroup`, `ImportGroups`), and `group:<id>` names it only
  there. Its members are identities that are members or guests of the tenant, and other groups of
  the tenant, at most `rbac.MaxGroupDepth` deep (`ImportMembers`), each from a source, perhaps
  until a time. Every check, list and deny reads an identity's groups, through those they are in,
  as they are stored now: `Authorize` and `Filter` in the same statement as its grants and denies,
  and `Explain`, `Reachable` and `Holders` in one snapshot of the database, but under `WithTx` at
  READ COMMITTED, where each statement reads its own.
  A suspended identity holds only what the public does, and stays bound by a deny naming its
  groups or the tenant's members, though no group of its exempts it from one: suspending it lifts
  nothing. When the host takes a group over (`ImportGroups` from one of `Config.Sources`), the
  members a tenant put in it, from no source of the host's, leave it.
- **Changing members is granting:** a group's members hold what it and the groups it is in hold,
  so `ChangeMembers`, with `rbac.GroupMembers` on the group and its label, checks a change to its members as the
  changes to access it makes, each as `Apply` or `SetDeny` checks one on its scope. An added member
  gains the grants and eligibilities of the group and the groups it is in, those the same change
  nests it in too, which the actor must be able to grant it, until its place ends, and an
  eligibility for good, and `ValidateGrant` is asked about each as the member's
  (`rbac.ViaMembership`); it approves what the group approves, which the actor must be able to set;
  and it is exempt from the denies the group is exempt from, as a removed member is from those
  naming it, which the actor must be able to set. A place made to end sooner gains nothing: it is a
  removal then, checked as one now. So whoever manages a group that holds, approves and is in no
  deny changes its members freely, and one holding a role only if they could grant that role
  themselves. `Config.ResourceOf` gives the package the tenant, which `SetGroup` and `DeleteGroup`
  check `rbac.ManageGroups` on, and the groups, which `ChangeMembers` checks `rbac.GroupMembers`
  on and `SetGroup` and `DeleteGroup` the label of, each with its constraints and label, and the
  containers, label and attributes of the scopes a group's access is on; a host without it
  declares no labels and resource attributes as none, and for access below the tenant, no
  containers. For a scope the host no longer has, as a resource deleted without `DeleteScopes`, it
  returns `rbac.ErrNotFound`, or an error wrapping it: a change that only takes access away there,
  as a member leaving a group with access on it or `DeleteRole` deleting a role granted on it,
  reads it as unlabeled, and any other change fails with the error.
- **Privileged roles:** a role the catalog marks `Privileged`, or one that changes access, is
  privileged: it is never granted to the tenant's members, and gives nothing through them, as
  after a catalog change.
- **Public access:** the zero `Subject` is anonymous and holds only what is granted to the public.
  Only a role marked `Public` can be granted to the public, and a grant to the public gives
  nothing once its role no longer is.
- **Broad grants:** a grant to a tenant's members (`rbac.TenantMembers`) or the public never gives
  a privileged role, nor any permission that changes access, so changing access always takes a
  named identity or group.

## Why

`Explain` names the grants that allow, or the deny, the constraint or the label's dimension that
denied, or for a value of an exclusive dimension the subject holds none of, that dimension;
`Permissions` lists what a subject may do; `Holders` lists who may, for an access review: each
identity, through its own grants and its groups', and the tenant's members and the public as one
holder each, marking those that hold only under a condition or that a deny or constraint may bind. A
`DeniedError`'s message names only the permission, so an error shown to a user shows no policy; its
fields say why.

## History

Every change to the package's tables is recorded in `rbac_history`: the row as it was and as it
became, when, and the database role that wrote it. A change through the package records its
actor and the call that made it (`Record.How`), and what the host attaches with `rbac.WithAudit`:
on whose behalf it was made, the request and the reason. An expiry `DeleteExpired` removes is
recorded as one, made by no one. Triggers write it, so a write that bypasses the package is
recorded too, as no one's. That context is what the session that wrote it says; the database role
is what the database knows. A row written before history was installed, as by a host that applied
the first migrations on their own, is recorded by migrating as it found it, its `baseline`, dated
when it was created, or a role when it last changed. Nothing updates or truncates history, only
`PruneHistory` deletes from it, and the package's tables can be deleted from but not truncated.
`History` reads it in order, to export it to storage of the host's own: a transaction that commits
after a later one is read after it, never skipped, and a record can be read twice, so dedupe on
`Record.ID` and `RecordedAt`: a restore can give another record the ID of one it lost. Any
transaction still running in the database cluster, in any of its databases, holds `History` back
until it ends. A time a record holds as PostgreSQL's infinity, which the tables refuse but an older
record can hold, reads as an instant just past either end of PostgreSQL's range, as `Record` says,
so `History` reads on past it. `History` reads the primary, and fails on a replica. A generation
(`Cursor.Generation`) names the cluster, and the database and schema history is in, so no two
installations in a cluster share one. A failover or a recovery to a point in time starts a new one,
and a restore that starts none, as from a disk snapshot, loses what came after it: either can number
again what the last one numbered past what it kept. `History` refuses a cursor from another
generation, or whose last record the database no longer holds, and history is exported again from
the start, kept apart from the last export. Move history with physical backups and replicas; a
logical dump restored into another cluster numbers its transactions anew.

A change refused, as `ErrDenied` or `ErrInvalid`, writes nothing, so history doesn't record it:
`Config.OnRefused` is told of each, with its actor, the call and the host's audit, to record the
failed attempt on a connection of the host's own, which keeps it when a host transaction the
change was made in (`WithTx`) rolls back.

`Export(ctx, from, limit, signer)` reads as `History` does and chains what it reads onto `from`,
a `Checkpoint`: a SHA-256 hash chain over every record of the generation in order, signed by the
host's `crypto.Signer`, such as a key in a key management service. Keep the records and each
checkpoint where they can't be rewritten, as write-once storage. `VerifyChain` then shows that the
records between two checkpoints are those history held, none dropped, changed or reordered, which
a database's superuser couldn't forge past the last checkpoint stored. A checkpoint vouches for
the records before it, not after: an audit verifies a generation from its `Genesis` to the latest
checkpoint kept, and checks that checkpoint's `At` is as recent as the host exports, since
`Export` signs one on every call, even one that reads nothing, so records dropped from the end
leave the latest checkpoint old. A generation exported from the start again, as after `History`
refuses a cursor, is chained anew: compare it with the last export, whose records are what
history held up to its last checkpoint, since a superuser who deletes a cursor's record makes
`History` refuse it. Keep the records so they read back as they were: times to the microsecond,
and each row as JSON text, not parsed into a store's own form, which can reorder its keys.

`AsOf(ctx, tenant, at, read)` reads a tenant as it was at a time, from its history: every check,
list and search the read makes answers as it would have then, with the catalog as it is now, as for
an access review of a past date. A change counts from when the statement that made it began, but
never before its row's change before it, as the writer's snapshot holds it: at READ COMMITTED, as
the package changes the tables, a statement that waited for another's lock on the row reads the
change it waited for, but at REPEATABLE READ or SERIALIZABLE its transaction's snapshot is older,
and it is dated before that change. Write around the package at READ COMMITTED. `AsOf` makes no
change: one tried is no actor's attempt, and `Config.OnRefused` isn't told of it. A statement
reads the history of the rows it names, as a check does its subject's grants, groups and the
denies on its resource's path, and `Holders` the members of the groups it lists, not the whole
tenant's. It orders a row's changes by their ids in `rbac_history`, which sessions take out of
order once that table's id sequence caches more than one, so `AsOf` refuses that.

`rbac.PruneHistory(ctx, db, before, through)` deletes what an export has read past (`through`, its
cursor) and later records supersede: of each row, the last version at or before `before` stays, so
`AsOf` answers as it did for any time from then on, and refuses an earlier one, and a row that had
ended by then goes, once no version before its end stays. One call deletes at most `rbac.MaxPrune`
records: call it again while it deletes as many, and each goes on from where the last stopped. A
prune that deletes records is recorded in history; one that deletes none changes nothing, and is
not. Run it on a connection of the administrator's role below, which has the rights of history's
owner, as the application's hasn't, and keep what the host's audit retention requires: the federal
floor is at least a year.

A role that owns a table can change it whatever its triggers say, and a schema's owner can drop
any table in it. So that the application's database role can't rewrite history or write around
it, that role is no superuser, nor a member of `pg_write_all_data` or `pg_create_subscription`,
through which it could write `rbac_history` itself, and before PostgreSQL 16 has no `CREATEROLE`,
with which it could make itself a member of any role but a superuser, such as those or the roles
below; and:

1. `Migrate` runs as an administrator's role the application's isn't a member of, with only the
   package's schema in its search_path, so that role owns the package's tables: their owner can
   disable the triggers that record them. A later migration can change history too, so the
   administrator's role keeps both owners' rights.
2. A role of history's own, which the administrator's role is a member of and the application's
   isn't, owns `rbac_history` and the function `rbac_record`: transfer them to it after migrating.
   It needs `USAGE` on the schema, since every write to the package's tables runs `rbac_record`
   as it, and `CREATE` there to be given them, unless a superuser gives them.
3. The application's role has `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the package's tables
   but `rbac_history` and `rbac_migrations`, and on any a later migration adds, `EXECUTE` on the
   functions `rbac_group_members` and `rbac_tenant_keys`, which every role has unless it is
   revoked, and only `SELECT` on `rbac_history`, with no `UPDATE` on its id sequence, which a
   grant on all the schema's sequences can give: `setval` could number a change below the one
   before it, and `AsOf` would read the row as it was before the change. Never `TRIGGER`, which
   `ALL` includes: a trigger runs its function as whoever writes the table, and one on
   `rbac_history` can drop each record, as history's owner.
4. The application's role can make no schema and create in none: it neither owns the database nor
   has `CREATE` on it, which `CREATE SCHEMA` needs and only the owner has by default, and it
   creates in no schema it owns, as `public` is when that role owns the database, nor in `public`
   before PostgreSQL 15, where every role can. `Migrate` calls functions by name, and an overload
   made in the package's schema would run in its place, as the administrator's role; and the
   package's schema is a session's current one, the first on its search_path, which a session can
   set, so one that named first a schema the role made, or can create in, would read a table made
   there as history: a generation of its own, which an export starts from `Genesis`, and `Export`
   would sign what it holds. `History` and `Export` can't tell that table from history's own,
   which the application's role owns where these roles aren't set up, so they don't refuse it.

The application's role may create temporary tables, as `AsOf` needs, and a session reads its own
tables and types before any schema's of the same name until it ends, which in a pool can be long
after the call that made one. One named as a package's table stands in for it in that session,
whose checks are the application's own to make; `History`, `Export` and `PruneHistory`, and
`AsOf`'s checks of history, name history's table by the package's schema and their types by
pg_catalog's, so none stands in for them, and refuse a search_path that names pg_temp first.

## Running it

- **Tables:** `rbac.Migrate` creates them, prefixed `rbac_`, in the connection's current schema,
  in a database whose encoding is UTF8, and records what it applied in `rbac_migrations`. It never
  runs by itself; a host with a migration tool of its own can apply `rbac.Migrations()` instead.
  On a host's transaction it refuses any isolation but READ COMMITTED: a stricter one's snapshot
  would miss the writes it waits for.
  A migration that rebuilds an index, as `0009_grant_seeks` rebuilds two of `rbac_grants`, locks
  the table until it commits, so checks, lists and changes wait for the rebuild; one that builds
  an index, as `0011_tenant_keys` builds three on `rbac_eligibilities` and `rbac_denies`, keeps
  writes to the table waiting until it commits, though reads go on: on a large table, migrate when
  that wait is acceptable. Code from before `0012_activation_through` must not run beside code
  after it: an activation it extends keeps the eligibility recorded before, and can outlast the one
  it was extended through. Stop the replicas running it before migrating.
- **Transactions:** a change runs in its own transaction at READ COMMITTED, or under `WithTx` in
  the host's, which must be READ COMMITTED too. A change refused for a race, such as a deadlock
  between host transactions, matches `rbac.ErrConflict`: try it again. Changes to the same rows
  wait for each other by locks named for the schema holding the tables, so sessions reaching them
  through different search_paths still do.
- **What the host passes:** a check reads grants, memberships and groups as they are; only compiled
  conditions are cached. Read a resource's ancestors and attributes from where they are stored,
  never from request input, no earlier than the content they protect, and from the primary. A
  deny is only as complete as the ancestors passed.
- **Ids:** an id names its identity, group or resource for good. Never reuse one, or a new
  resource or account inherits the grants of the one before it. Delete a resource's grants with
  `DeleteScopes` in the transaction that deletes it, in one call with every scope under it too,
  which holds a bounded number of locks however many it removes, and rewrite the stored paths
  below a container when it moves.
- **Permissions:** a check or search of a permission, or a resource type, the host doesn't have
  is refused as `rbac.ErrInvalid`, as a typo, not denied, as is a change on a scope of such a
  type, a removal too (`Deactivate`, `DeleteScopes`, `DeleteGrants`), which would otherwise
  succeed having removed nothing. They are what the catalog's roles give and are for, or with
  `Config.Permissions` every permission the host checks, which a catalog an operator configures
  can leave out of every role: then it is denied like any other. To retire a type, keep one of its
  permissions there until its scopes are deleted; `DeletePrincipal` and `DeleteTenant` remove
  grants on any type.
- **Limits:** a change takes at most `rbac.MaxBindings` bindings; a principal holds a role on a
  scope at most `rbac.MaxGrantsPerRole` times, and is in a group at most `rbac.MaxPlacesInGroup`
  times, by source, from each source the host owns apart; a scope holds at most `rbac.MaxDenies`
  denies; a tenant has at most `rbac.MaxCustomRoles` custom roles; an id is at most `rbac.MaxID`
  bytes. The others are exported beside them. Lists have no limit or cursor, so what one returns
  grows with what it lists: `Memberships` of a whole tenant with its members and guests, `Groups`
  with its groups, `Members` with a group's members, `Holders` with who holds the permission,
  `Grants` and `Eligibilities` on the tenant's scope with what is granted there, `Reach.Scopes`
  with the scopes a subject's grants are on, and `Conflicts` with the identities in conflict. In a
  large tenant, ask for less: `Memberships` of named principals, `Grants` of one principal.
- **Expiry:** expired grants give nothing at once; `DeleteExpired` clears them a batch at a time,
  to run on a schedule, passing over what a change holds until the next run.

## Development

`make check` runs every linter and test. The tests need a PostgreSQL database they may create
schemas in, named by `RBAC_TEST_DATABASE_URL`; without it they are skipped. See
[CONTRIBUTING.md](CONTRIBUTING.md).
