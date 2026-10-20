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
  can't mint an unlimited one. `Grantable` lists the roles a subject may grant, for an access
  screen. A grant outlives the actor's own access: put expiries on roles that can't change grants.
- **Creators:** nothing is owned. The host gives whoever creates a resource a role on it with
  `Import`, as an actor it names, in the same transaction through `WithTx`.

## Lists

Store each resource's `authz.Path(resource)`, its own key first and then its containers' and the
tenant's, in a `text[]` column with a GIN index. `Filter` returns a condition for the host's own
query, which reads the grants in the same statement as the rows, so sorting and pagination work and
nothing changes between deciding and reading. It compares the tenant and keys byte for byte, as
`Authorize` does, whatever the columns' collation, in which their indexes still serve. A subject's
grants on resources of the listed type are looked up by each row's own key, so one holding a grant
on everything it created lists as fast as one holding a few. `Reachable` returns the same as
scopes, for resources kept in another store. Both search one tenant, and count only unconditional
grants: `Reach.Conditional` names the scopes conditional ones reach, to check one by one.

## Policies

- **Custom roles:** a tenant defines its own with `SetRole`, ids starting `custom.`, from the
  permissions and types the built-in roles use. Defining one needs `rbac.DefineRoles` on the
  tenant and everything the role gives across it. Redefining one so that its grants give more
  asks `ValidateGrant` about each grant and eligibility it widens, as the role will be, and the
  host refusing one refuses the redefinition; an actor a label of a scope its grants are on, as
  `Config.ResourceOf` gives it, refuses can neither redefine nor delete it. `DeleteRole` removes
  one with its grants; `Roles` lists the built-in and custom roles a scope type takes. Custom
  roles follow the catalog: one gives only what the catalog still has, and is privileged when it
  gives what only privileged roles do, or changes access.
- **Labels on data:** a mandatory layer above every grant. A host declares label dimensions
  (`Config.Labels`), each `Ordered` (a level), `AllOf` (compartments) or `AnyOf` (releasable to
  these partners), and a resource carries its label (`Resource.Labels`), stored with it as its
  path is. A subject holds a dimension's values as permissions, `dimension:value`, which roles for
  the tenant give, so groups, eligibilities, expiry, conditions, denies on the tenant and history
  all apply to them. `Authorize`, `Explain`, `Permissions`, `Holders` and `Grantable` allow
  nothing of a labeled resource unless what the subject holds satisfies the label, whatever its
  grants give, nor do `Apply`, `SetEligibility` and `DeleteEligibility` change its grants, nor
  `SetDeny` and `DeleteDeny` its denies; `Explain` names the dimension that failed. `Filter`
  tests a `text[]` label column (`Columns.Labels`), `Reachable` returns the holding, and `Holding`
  with `Satisfies` checks data points in a feed without reading the database.
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
  misnamed, or as another type, is refused when stored. Cost is bounded per condition and per
  check, and a check evaluates the cheapest first, so what it decides doesn't rest on ids; a
  scope's conditional denies are bounded together, so a check always evaluates them. To hand a
  permission on, the actor holds it unconditionally or under the same condition, one that doesn't
  read the subject: that one decides for each holder, so the actor's holding says nothing of
  another's.
- **Deny policies:** `SetDeny` puts a deny on a scope: under it, it removes permissions
  (`type:verb`, or `type:*` for a type's every one) from the principals it names, those it exempts
  aside, whatever their grants give. It exempts identities and groups, or from a deny naming the
  public the tenant's members, to bind only those who aren't; never the public, which would
  exempt everyone, nor one it names. A conditional one denies where its condition holds or can't
  be evaluated. Setting one needs `rbac.DenyPermission(type)` there, which no deny removes, so
  whoever holds it on a scope above can always lift a deny set below. `Filter`, `Reachable` and
  `Holders` honor denies.
- **Just-in-time access:** `SetEligibility` lets a principal, an identity or a group's members,
  activate a role on a scope for up to a maximum duration and no later than the eligibility, the
  activator's membership of the tenant, or its place in the group that makes it eligible ends,
  perhaps only where a condition holds, such as a second factor, and perhaps only once one of its
  `Approvers` approves. `Activate` gives the activator a grant of its own from
  `rbac.SourceActivation`, beside any it holds, with its justification and approver. It holds
  one activation of a role on a scope, recording the request its end rests on: activating again
  until later replaces it, one ending no later changes nothing, and once it has ended, activating
  again makes a new grant. `Deactivate` ends it early.
- **Host policy:** `Config.ValidateGrant` is asked about every grant with the role, the principal,
  the actor and how it is made, so the host decides who may hold what: members only, no
  privileged roles for service accounts or guests. `Config.Constraints` remove permissions above
  anything a tenant grants or denies, seeing the subject and the resource, such as freezing
  changes under a container. What one removes from an actor the actor can't hand on, but for a
  role a role it holds lists in `GrantableRoles`, which it grants without holding. The host is
  asked before a change takes its locks, so a change is tried again (`rbac.ErrConflict`) when the
  memberships its answers rest on, of an identity it grants to or of a group's members, changed
  in between. A change to a group member's own membership takes that member's lock alone, so one
  committing after the change reads them again isn't seen: a host whose policy rests on a group's
  members checks the group's grants when it changes a membership, as `SetMemberships` says.

## Principals

- **Members and guests:** an identity holds what it is granted in a tenant only while it is a
  member or guest of it (`SetMemberships`), and nothing while its membership is suspended. A guest,
  such as one from another tenant, holds what it is granted there and nothing granted to the
  tenant's members. Leaving a tenant (`DeletePrincipal`) removes what the identity held there;
  `DeletePrincipalEverywhere` removes a deleted identity from every tenant.
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
  gains the group's grants and eligibilities, which the actor must be able to grant it, and
  `ValidateGrant` is asked about each as the member's (`rbac.ViaMembership`); it approves what the
  group approves, which the actor must be able to set; and it is exempt from the denies the group
  is exempt from, as a removed member, or one whose membership is made to end sooner, is from
  those naming it, which the actor must be able to set. So whoever manages a group that holds,
  approves and is in no deny changes its members freely, and one holding a role only if they could
  grant that role themselves. `Config.ResourceOf` gives the package the containers, label and
  attributes of the scopes a group's access is on; a host without it declares no labels and
  resource attributes as none, and for access below the tenant, no containers.
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

`Explain` names the grants that allow, or the deny or constraint that denied; `Permissions` lists
what a subject may do; `Holders` lists who may, for an access review: each identity, through its own
grants and its groups', and the tenant's members and the public as one holder each, marking those
that hold only under a condition or that a deny or constraint may bind. A `DeniedError`'s message
names only the permission, so an error shown to a user shows no policy; its fields say why.

## History

Every change to the package's tables is recorded in `rbac_history`: the row as it was and as it
became, when, and the database role that wrote it. A change through the package records its
actor and the call that made it (`Record.How`), and what the host attaches with `rbac.WithAudit`:
on whose behalf it was made, the request and the reason. An expiry `DeleteExpired` removes is
recorded as one, made by no one. Triggers write it, so a write that bypasses the package is
recorded too, as no one's. That context is what the session that wrote it says; the database role
is what the database knows. Nothing updates or truncates it, only `PruneHistory` deletes from it,
and the package's tables can be deleted from but not truncated. `History` reads it in order, to
export it to storage of the host's own: a transaction that commits after a later one is read
after it, never skipped, and a record can be read twice, so dedupe on `Record.ID` and
`RecordedAt`: a restore can give another record the ID of one it lost. Any transaction still
running in the database cluster, in any of its databases, holds `History` back until it ends.
A time a record holds as PostgreSQL's infinity, which the tables refuse but an older record can
hold, reads as an instant just past either end of PostgreSQL's range, as `Record` says, so
`History` reads on past it. `History` reads the primary, and fails on a replica. A generation
(`Cursor.Generation`) names the cluster, and the database and schema history is in, so no two
installations in a cluster share one. A failover or a recovery to a point in time starts a new
one, and a restore that starts none, as from a disk snapshot, loses what came after it: either
can number again what the last one numbered past what it kept.
`History` refuses a cursor from another generation, or whose last record the database no longer
holds, and history is exported again from the start, kept apart from the last export. Move
history with physical backups and replicas; a logical dump restored into another cluster numbers
its transactions anew.

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
never before its row's change before it, and none can be made through it: one tried is no actor's
attempt, and `Config.OnRefused` isn't told of it. A statement reads the history of the rows it
names, as a check does its subject's grants, groups and the denies on its resource's path, and
`Holders` the members of the groups it lists, not the whole tenant's. It orders a row's changes by
their ids in `rbac_history`, which sessions take out of order once that table's id sequence caches
more than one, so `AsOf` refuses that.

`rbac.PruneHistory(ctx, db, before, through)` deletes what an export has read past (`through`, its
cursor) and later records supersede: of each row, the last version at or before `before` stays, so
`AsOf` answers as it did for any time from then on, and refuses an earlier one, and a row that had
ended by then goes, once no version before its end stays. One call deletes at most `rbac.MaxPrune`
records: call it again while it deletes as many, and each goes on from where the last stopped. The
prune is recorded in history. Run it on a connection of the administrator's role below, which has
the rights of history's owner, as the application's hasn't, and keep what the host's audit retention
requires: the federal floor is at least a year.

A role that owns a table can change it whatever its triggers say, and a schema's owner can drop
any table in it. So that the application's database role can't rewrite history or write around
it, that role is no superuser, nor a member of `pg_write_all_data` or `pg_create_subscription`,
through which it could write `rbac_history` itself; and:

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
   function `rbac_group_members`, which every role has unless it is revoked, and only `SELECT`
   on `rbac_history`, with no `UPDATE` on its id sequence, which a grant on all the schema's
   sequences can give: `setval` could number a change below the one before it, and `AsOf` would
   read the row as it was before the change. Never `TRIGGER`, which `ALL` includes: a trigger
   runs its function as whoever writes the table, and one on `rbac_history` can drop each record,
   as history's owner.
4. The schema isn't the application's role's, as `public` is when that role owns the database,
   and that role can't create in it, as every role can in `public` before PostgreSQL 15:
   `Migrate` calls functions by name, and an overload made there would run in its place, as the
   administrator's role.

## Running it

- **Tables:** `rbac.Migrate` creates them, prefixed `rbac_`, in the connection's current schema,
  in a database whose encoding is UTF8, and records what it applied in `rbac_migrations`. It never
  runs by itself; a host with a migration tool of its own can apply `rbac.Migrations()` instead.
- **Transactions:** a change runs in its own transaction at READ COMMITTED, or under `WithTx` in
  the host's, which must be READ COMMITTED too. A change refused for a race, such as a deadlock
  between host transactions, matches `rbac.ErrConflict`: try it again.
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
  type. They are what the catalog's roles give and are for, or with `Config.Permissions` every
  permission the host checks, which a catalog an operator configures can leave out of every role:
  then it is denied like any other.
- **Limits:** a change takes at most `rbac.MaxBindings` bindings; a principal holds a role on a
  scope at most `rbac.MaxGrantsPerRole` times, from each source the host owns apart; a scope holds
  at most `rbac.MaxDenies` denies; a tenant has at most `rbac.MaxCustomRoles` custom roles; an id
  is at most `rbac.MaxID` bytes. The others are exported beside them.
- **Expiry:** expired grants give nothing at once; `DeleteExpired` clears them a batch at a time,
  to run on a schedule.

## Development

`make check` runs every linter and test. The tests need a PostgreSQL database they may create
schemas in, named by `RBAC_TEST_DATABASE_URL`; without it they are skipped. See
[CONTRIBUTING.md](CONTRIBUTING.md).
